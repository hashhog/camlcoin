(* Wallet - HD key management, UTXO tracking, and transaction signing

   This module provides wallet functionality:
   - BIP-32/84 HD key derivation from seed
   - Key generation and storage
   - Address derivation (P2WPKH native SegWit)
   - UTXO tracking for wallet addresses
   - Branch-and-Bound coin selection with greedy fallback
   - Transaction creation and signing (BIP-143 SegWit sighash)
   - Fee bumping via RBF (BIP-125)
   - Wallet persistence to JSON *)

let log_src = Logs.Src.create "WALLET" ~doc:"Wallet"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

(* FIX-70 / W120 BUG-2: Core's CWallet default for wallet-created inputs.
   Reference: bitcoin-core/src/wallet/wallet.h
     static constexpr uint32_t MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;
   Wallet-created transactions opt into BIP-125 RBF by default since
   Bitcoin Core v23 (m_signal_rbf=true).  Any input with
   nSequence <= 0xFFFFFFFD signals replaceability per BIP-125.
   Use 0xFFFFFFFE only when nLockTime enforcement is needed but RBF
   signaling is not (coinbase, explicit non-replaceable opt-out). *)
let max_bip125_rbf_sequence : int32 = 0xFFFFFFFDl

(* CSPRNG helper: read 8 bytes from /dev/urandom and return a non-negative
   integer in [0, max).  Never falls back to OCaml stdlib Random — same
   pattern used in peer_manager.ml/sync.ml/p2p.ml throughout camlcoin.
   Mirrors Bitcoin Core's FastRandomContext::randrange() sourced from
   GetStrongRandBytes() → /dev/urandom.  Called for all privacy-sensitive
   decisions: coin shuffle order, change output position, anti-fee-sniping
   trigger.  `max` must be > 0. *)
let csprng_int_range (max_exclusive : int) : int =
  assert (max_exclusive > 0);
  let buf = Bytes.create 8 in
  let ic = open_in_bin "/dev/urandom" in
  really_input ic buf 0 8;
  close_in ic;
  (* Interpret as a little-endian unsigned 63-bit integer (drop sign bit) to
     stay within OCaml's native int range on 64-bit systems, then mod. *)
  let b i = Int64.of_int (Char.code (Bytes.get buf i)) in
  let ( lsl ) = Int64.shift_left in
  let ( lor ) = Int64.logor in
  let raw =
    (b 0) lor ((b 1) lsl 8) lor ((b 2) lsl 16) lor ((b 3) lsl 24)
    lor ((b 4) lsl 32) lor ((b 5) lsl 40) lor ((b 6) lsl 48) lor ((b 7) lsl 56)
  in
  (* Mask to 62 bits to guarantee non-negative after Int64.to_int *)
  let masked = Int64.logand raw 0x3FFFFFFFFFFFFFFFL in
  Int64.to_int masked mod max_exclusive

(* Insert an item at a random position in a list (for output order privacy) *)
let insert_at_random lst item =
  let n = List.length lst in
  let pos = csprng_int_range (n + 1) in
  let rec aux i acc = function
    | [] -> List.rev (item :: acc)
    | x :: xs ->
      if i = pos then List.rev_append (item :: acc) (x :: xs)
      else aux (i + 1) (x :: acc) xs
  in aux 0 [] lst

(* ============================================================================
   Secp256k1 Helpers (shared with Crypto module)

   All secp256k1 operations route through the vendored libsecp256k1 via thin
   C stubs in lib/schnorr_stubs.c. The opam secp256k1-internal binding has
   been removed so there is exactly one secp256k1 implementation in-binary.
   ============================================================================ *)

(* BIP-32 add_tweak for child key derivation: vendored libsecp256k1's
   secp256k1_ec_seckey_tweak_add (private side) and secp256k1_ec_pubkey_tweak_add
   (public side / xpub-rooted derivation). *)
external ec_seckey_tweak_add_raw : Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_ec_seckey_tweak_add"

external ec_pubkey_tweak_add_raw : Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_ec_pubkey_tweak_add"

let cstruct_to_bigstring cs =
  let len = Cstruct.length cs in
  let bs = Bigstring.create len in
  for i = 0 to len - 1 do
    Bigstring.set bs i (Char.chr (Cstruct.get_uint8 cs i))
  done;
  bs

let bigstring_to_cstruct bs =
  let len = Bigstring.length bs in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.set_uint8 cs i (Char.code (Bigstring.get bs i))
  done;
  cs

(* ============================================================================
   BIP-32 HD Key Derivation Types and Functions (Gap 16)
   ============================================================================ *)

type extended_key = {
  key : Cstruct.t;          (* 32-byte private key *)
  chain_code : Cstruct.t;   (* 32-byte chain code *)
  depth : int;
  parent_fingerprint : int32;
  child_index : int32;
}

(* HMAC-SHA512 using digestif *)
let hmac_sha512 ~key data =
  let module H = Digestif.SHA512 in
  H.hmac_string ~key:(Cstruct.to_string key) (Cstruct.to_string data)
  |> H.to_raw_string |> Cstruct.of_string

(* Derive master key from seed (BIP-32) *)
let derive_master_key (seed : Cstruct.t) : extended_key =
  let key_str = Cstruct.of_string "Bitcoin seed" in
  let i = hmac_sha512 ~key:key_str seed in
  let il = Cstruct.sub i 0 32 in
  let ir = Cstruct.sub i 32 32 in
  { key = il;
    chain_code = ir;
    depth = 0;
    parent_fingerprint = 0l;
    child_index = 0l }

(* Compute fingerprint of an extended key (first 4 bytes of hash160 of pubkey).
   Accepts either a 32-byte private extkey (derive pubkey) or a 33-byte
   compressed-pubkey extkey (use as-is). *)
let fingerprint_of_key (ek : extended_key) : int32 =
  let pubkey =
    if Cstruct.length ek.key = 32 then
      Crypto.derive_public_key ~compressed:true ek.key
    else
      ek.key
  in
  let h = Crypto.hash160 pubkey in
  (* Read first 4 bytes as big-endian int32 *)
  Cstruct.BE.get_uint32 h 0

(* Write int32 as 4 big-endian bytes *)
let int32_to_bytes (v : int32) : Cstruct.t =
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 buf 0 v;
  buf

(* Hardened index threshold *)
let hardened_offset = 0x80000000l

(* Derive a child key (BIP-32).

   Handles both private (xprv-rooted, 32-byte key) and public (xpub-rooted,
   33-byte compressed key) parents:
     private: child_sk = parent_sk + IL  (mod n) via ec_seckey_tweak_add
     public:  child_pk = parent_pk + IL*G via ec_pubkey_tweak_add
   Hardened derivation requires the private key, so it errors out for xpub
   parents. *)
let derive_child_key (parent : extended_key) (index : int32) : (extended_key, string) result =
  let parent_is_private = Cstruct.length parent.key = 32 in
  let parent_pubkey () =
    if parent_is_private then
      Crypto.derive_public_key ~compressed:true parent.key
    else
      parent.key
  in
  (* BIP-32 hardened indices are 0x80000000..0xFFFFFFFF.  The signed
     Int32.compare misclassifies any unsigned value with bit 31 set as
     "less than 0x80000000" (which itself is -2^31 signed), so use
     Int32.unsigned_compare to get the BIP-32-correct ordering. *)
  let is_hardened = Int32.unsigned_compare index hardened_offset >= 0 in
  if is_hardened && not parent_is_private then
    Error "BIP-32: hardened derivation requires private key (xprv)"
  else
    let data =
      if is_hardened then
        (* Hardened: HMAC-SHA512(chain_code, 0x00 || sk || index_be) *)
        Cstruct.concat [
          Cstruct.of_string "\x00";
          parent.key;
          int32_to_bytes index
        ]
      else
        (* Normal: HMAC-SHA512(chain_code, parent_pubkey || index_be) *)
        Cstruct.concat [
          parent_pubkey ();
          int32_to_bytes index
        ]
    in
    let i = hmac_sha512 ~key:parent.chain_code data in
    let il = Cstruct.sub i 0 32 in
    let ir = Cstruct.sub i 32 32 in
    (* Child key = parent_key (+) il via libsecp256k1's tweak_add.
       For private keys: secp256k1_ec_seckey_tweak_add (mod-n scalar add).
       For public keys:  secp256k1_ec_pubkey_tweak_add (point add tweak*G). *)
    try
      let parent_bs = cstruct_to_bigstring parent.key in
      let tweak_bs = cstruct_to_bigstring il in
      let child_key_bs =
        if parent_is_private
        then ec_seckey_tweak_add_raw parent_bs tweak_bs
        else ec_pubkey_tweak_add_raw parent_bs tweak_bs
      in
      let child_key = bigstring_to_cstruct child_key_bs in
      let fp = fingerprint_of_key parent in
      Ok { key = child_key;
        chain_code = ir;
        depth = parent.depth + 1;
        parent_fingerprint = fp;
        child_index = index }
    with _ ->
      Error "BIP-32: invalid child key derived"

(* Derive a hardened child *)
let derive_hardened (parent : extended_key) (index : int) : (extended_key, string) result =
  derive_child_key parent (Int32.add hardened_offset (Int32.of_int index))

(* Derive a normal (non-hardened) child *)
let derive_normal (parent : extended_key) (index : int) : (extended_key, string) result =
  derive_child_key parent (Int32.of_int index)

(* Derive BIP-84 receive key: m/84'/0'/0'/0/n *)
let derive_bip84_receive (master : extended_key) (n : int) : (Cstruct.t, string) result =
  let open Result in
  let ( >>= ) = bind in
  derive_hardened master 84 >>= fun purpose ->
  derive_hardened purpose 0 >>= fun coin_type ->
  derive_hardened coin_type 0 >>= fun account ->
  derive_normal account 0 >>= fun change ->
  derive_normal change n >>= fun child ->
  Ok child.key

(* Derive BIP-84 change key: m/84'/0'/0'/1/n *)
let derive_bip84_change (master : extended_key) (n : int) : (Cstruct.t, string) result =
  let open Result in
  let ( >>= ) = bind in
  derive_hardened master 84 >>= fun purpose ->
  derive_hardened purpose 0 >>= fun coin_type ->
  derive_hardened coin_type 0 >>= fun account ->
  derive_normal account 1 >>= fun change ->
  derive_normal change n >>= fun child ->
  Ok child.key

(* Derive BIP-44 receive key: m/44'/0'/0'/0/n (P2PKH) *)
let derive_bip44_receive (master : extended_key) (n : int) : (Cstruct.t, string) result =
  let open Result in
  let ( >>= ) = bind in
  derive_hardened master 44 >>= fun purpose ->
  derive_hardened purpose 0 >>= fun coin_type ->
  derive_hardened coin_type 0 >>= fun account ->
  derive_normal account 0 >>= fun change ->
  derive_normal change n >>= fun child ->
  Ok child.key

(* Derive BIP-44 change key: m/44'/0'/0'/1/n (P2PKH) *)
let derive_bip44_change (master : extended_key) (n : int) : (Cstruct.t, string) result =
  let open Result in
  let ( >>= ) = bind in
  derive_hardened master 44 >>= fun purpose ->
  derive_hardened purpose 0 >>= fun coin_type ->
  derive_hardened coin_type 0 >>= fun account ->
  derive_normal account 1 >>= fun change ->
  derive_normal change n >>= fun child ->
  Ok child.key

(* Derive BIP-86 receive key: m/86'/0'/0'/0/n (P2TR) *)
let derive_bip86_receive (master : extended_key) (n : int) : (Cstruct.t, string) result =
  let open Result in
  let ( >>= ) = bind in
  derive_hardened master 86 >>= fun purpose ->
  derive_hardened purpose 0 >>= fun coin_type ->
  derive_hardened coin_type 0 >>= fun account ->
  derive_normal account 0 >>= fun change ->
  derive_normal change n >>= fun child ->
  Ok child.key

(* Derive BIP-86 change key: m/86'/0'/0'/1/n (P2TR) *)
let derive_bip86_change (master : extended_key) (n : int) : (Cstruct.t, string) result =
  let open Result in
  let ( >>= ) = bind in
  derive_hardened master 86 >>= fun purpose ->
  derive_hardened purpose 0 >>= fun coin_type ->
  derive_hardened coin_type 0 >>= fun account ->
  derive_normal account 1 >>= fun change ->
  derive_normal change n >>= fun child ->
  Ok child.key

(* ============================================================================
   Extended Key Serialization (xpub/xprv)
   ============================================================================ *)

(* Serialize extended private key to xprv Base58Check string *)
let serialize_xprv (ek : extended_key) : string =
  let buf = Cstruct.create 78 in
  (* Version: mainnet xprv = 0x0488ADE4 *)
  Cstruct.BE.set_uint32 buf 0 0x0488ADE4l;
  (* Depth *)
  Cstruct.set_uint8 buf 4 ek.depth;
  (* Parent fingerprint *)
  Cstruct.BE.set_uint32 buf 5 ek.parent_fingerprint;
  (* Child index *)
  Cstruct.BE.set_uint32 buf 9 ek.child_index;
  (* Chain code *)
  Cstruct.blit ek.chain_code 0 buf 13 32;
  (* 0x00 prefix + private key *)
  Cstruct.set_uint8 buf 45 0x00;
  Cstruct.blit ek.key 0 buf 46 32;
  Address.base58check_encode buf

(* Serialize extended public key to xpub Base58Check string *)
let serialize_xpub (ek : extended_key) : string =
  let buf = Cstruct.create 78 in
  (* Version: mainnet xpub = 0x0488B21E *)
  Cstruct.BE.set_uint32 buf 0 0x0488B21El;
  (* Depth *)
  Cstruct.set_uint8 buf 4 ek.depth;
  (* Parent fingerprint *)
  Cstruct.BE.set_uint32 buf 5 ek.parent_fingerprint;
  (* Child index *)
  Cstruct.BE.set_uint32 buf 9 ek.child_index;
  (* Chain code *)
  Cstruct.blit ek.chain_code 0 buf 13 32;
  (* Compressed public key — accept either a 32-byte private extkey
     (derive pubkey) or a 33-byte compressed-pubkey extkey (use as-is). *)
  let pubkey =
    if Cstruct.length ek.key = 32 then
      Crypto.derive_public_key ~compressed:true ek.key
    else
      ek.key
  in
  Cstruct.blit pubkey 0 buf 45 33;
  Address.base58check_encode buf

(* Deserialize a Base58Check-encoded extended key (xprv/xpub/tprv/tpub) *)
let deserialize_extended_key (s : string) : (extended_key * bool, string) result =
  match Address.base58check_decode s with
  | Error e -> Error e
  | Ok payload ->
    if Cstruct.length payload <> 78 then
      Error "deserialize_extended_key: payload must be 78 bytes"
    else
      let version = Cstruct.BE.get_uint32 payload 0 in
      let is_private = match version with
        | v when v = 0x0488ADE4l -> true   (* xprv *)
        | v when v = 0x04358394l -> true   (* tprv *)
        | v when v = 0x0488B21El -> false  (* xpub *)
        | v when v = 0x043587CFl -> false  (* tpub *)
        | _ -> failwith "deserialize_extended_key: unknown version"
      in
      let depth = Cstruct.get_uint8 payload 4 in
      let parent_fingerprint = Cstruct.BE.get_uint32 payload 5 in
      let child_index = Cstruct.BE.get_uint32 payload 9 in
      let chain_code = Cstruct.sub payload 13 32 in
      let key =
        if is_private then
          (* Skip 0x00 prefix byte *)
          Cstruct.sub payload 46 32
        else
          Cstruct.sub payload 45 33
      in
      Ok ({ key; chain_code; depth; parent_fingerprint; child_index }, is_private)

(* ============================================================================
   Wallet Types
   ============================================================================ *)

(* Address type for key derivation *)
type address_type = P2PKH | P2WPKH | P2TR

(* A keypair for signing *)
type key_pair = {
  private_key : Crypto.private_key;
  public_key : Crypto.public_key;
  address : Address.address;
  addr_type : address_type;
}

(* UTXO tracked by wallet *)
type wallet_utxo = {
  outpoint : Types.outpoint;
  utxo : Utxo.utxo_entry;
  key_index : int;
  confirmed : bool;
}

(* Transaction history entry.

   Mirrors a single Bitcoin Core wallet "category" row as emitted by
   listtransactions / gettransaction (wallet/rpc/transactions.cpp
   ListTransactions): one entry per wallet-relevant credit (a receive /
   coinbase-generate) or debit (a send), carrying the per-output/input vout, the
   net amount, the fee (sends only), and the confirming block coordinates.

   [hist_category] distinguishes the four Core categories.  Coinbase credits are
   recorded as [`Generate]; whether listtransactions reports them as "generate"
   (mature) or "immature" is decided dynamically at RPC time from the live
   confirmation count + coinbase maturity, exactly like Core's
   IsTxImmatureCoinBase check — so a stored entry never goes stale as the chain
   advances. *)
type tx_history_entry = {
  hist_txid : string;
  hist_category : [`Send | `Receive | `Generate];
  hist_amount : int64;
  (* Stored as a POSITIVE magnitude in satoshis; the RPC layer applies Core's
     sign convention (negative for [`Send]). *)
  hist_fee : int64;       (* positive magnitude; sends only, else 0 *)
  hist_address : string;
  hist_vout : int;        (* the credited output index, or spent-input vout *)
  hist_is_coinbase : bool;(* surfaces Core's "generated" boolean *)
  hist_confirmations : int;
  hist_block_hash : string;
  hist_block_height : int;
  hist_timestamp : float;
}

(* Wallet lock state: tracks whether private keys are accessible *)
type lock_state =
  | Locked
  | Unlocked of { master_key : Cstruct.t; expires : float }

(* Wallet encryption state *)
type encryption_state = {
  mutable encrypted : bool;
  mutable salt : Cstruct.t option;
  mutable iv : Cstruct.t option;
  (* Encrypted master key (for encrypted wallets only) *)
  mutable encrypted_master_key : Cstruct.t option;
  (* Current lock state *)
  mutable lock_state : lock_state;
  (* Encrypted private keys: address -> encrypted key ciphertext *)
  mutable encrypted_keys : (string, Cstruct.t) Hashtbl.t;
}

(* Wallet state *)
type t = {
  mutable keys : key_pair list;
  mutable utxos : wallet_utxo list;
  mutable next_key_index : int;
  mutable balance_confirmed : int64;
  mutable balance_unconfirmed : int64;
  network : [`Mainnet | `Testnet | `Regtest];
  db_path : string;
  mutable master_key : extended_key option;
  mutable receive_index : int;
  mutable change_index : int;
  (* Separate indices for each address type *)
  mutable bip44_receive_index : int;  (* m/44'/0'/0'/0/n - P2PKH *)
  mutable bip44_change_index : int;   (* m/44'/0'/0'/1/n - P2PKH *)
  mutable bip86_receive_index : int;  (* m/86'/0'/0'/0/n - P2TR *)
  mutable bip86_change_index : int;   (* m/86'/0'/0'/1/n - P2TR *)
  sent_transactions : (string, Types.transaction) Hashtbl.t;
  mutable tx_history : tx_history_entry list;
  mutable encryption : encryption_state;
  (* lockunspent: outpoint -> persistent flag (true = written to disk) *)
  locked_coins : (string * int32, bool) Hashtbl.t;
}

(* ============================================================================
   Wallet Creation
   ============================================================================ *)

(* Create a new empty wallet *)
let create ~(network : [`Mainnet | `Testnet | `Regtest])
    ~(db_path : string) : t =
  { keys = [];
    utxos = [];
    next_key_index = 0;
    balance_confirmed = 0L;
    balance_unconfirmed = 0L;
    network;
    db_path;
    master_key = None;
    receive_index = 0;
    change_index = 0;
    bip44_receive_index = 0;
    bip44_change_index = 0;
    bip86_receive_index = 0;
    bip86_change_index = 0;
    sent_transactions = Hashtbl.create 16;
    tx_history = [];
    encryption = {
      encrypted = false;
      salt = None;
      iv = None;
      encrypted_master_key = None;
      lock_state = Unlocked { master_key = Cstruct.empty; expires = infinity };
      encrypted_keys = Hashtbl.create 16;
    };
    locked_coins = Hashtbl.create 16;
  }

(* ============================================================================
   HD Wallet Initialization
   ============================================================================ *)

(* Initialize wallet from a BIP-32 seed *)
let init_from_seed (w : t) (seed : Cstruct.t) : unit =
  let master = derive_master_key seed in
  w.master_key <- Some master;
  w.receive_index <- 0;
  w.change_index <- 0

(* Initialize wallet from a BIP-39 mnemonic phrase *)
let init_from_mnemonic (w : t) (mnemonic : string) ?(passphrase = "") () : unit =
  if not (Bip39.validate_mnemonic mnemonic) then
    failwith "Invalid BIP-39 mnemonic"
  else
    let seed = Bip39.mnemonic_to_seed ~mnemonic ~passphrase () in
    init_from_seed w seed

(* Restore the wallet's HD master seed from a known value (seed-only recovery).
   Mirrors Bitcoin Core's sethdseed (CWallet::SetHDSeed + keypool flush):
   the master key is replaced and every derivation index is reset to 0 so
   that re-deriving addresses with [generate_key*] reproduces the exact same
   sequence the original wallet produced. The already-derived [keys] list is
   cleared (Core's "newkeypool" flush) — recovery re-derives from index 0.
   Reference: bitcoin-core/src/wallet/rpc/backup.cpp sethdseed.

   The chain-derived ledger (UTXO set, both balance buckets, and on-chain
   history) is ALSO reset: a wallet restored from a seed has no tracked funds
   until it walks the chain (rescanblockchain / scantxoutset). Mirrors Core,
   where SetHDSeed on a fresh wallet leaves an empty CWallet::mapWallet until a
   rescan re-derives the credits/debits from the blocks. Without this, getbalance
   would report stale coins from the pre-reseed key set before any rescan ran. *)
let set_hd_seed (w : t) (seed : Cstruct.t) : unit =
  let master = derive_master_key seed in
  w.master_key <- Some master;
  w.keys <- [];
  w.next_key_index <- 0;
  w.receive_index <- 0;
  w.change_index <- 0;
  w.bip44_receive_index <- 0;
  w.bip44_change_index <- 0;
  w.bip86_receive_index <- 0;
  w.bip86_change_index <- 0;
  (* Fresh-wallet ledger reset: re-deriving keys does not re-derive funds. *)
  w.utxos <- [];
  w.balance_confirmed <- 0L;
  w.balance_unconfirmed <- 0L;
  w.tx_history <- []

(* ============================================================================
   Key Management
   ============================================================================ *)

(* Helper: find index of element in list *)
let list_find_index (pred : 'a -> bool) (lst : 'a list) : int option =
  let rec aux i = function
    | [] -> None
    | x :: xs -> if pred x then Some i else aux (i + 1) xs
  in
  aux 0 lst

(* Generate a new keypair with specified address type.
   If master_key is set, derive via appropriate BIP path; otherwise use random. *)
let generate_key_typed (w : t) (addr_type : address_type) : key_pair =
  let derivation_fn, get_index, set_index, addr_constructor = match addr_type with
    | P2PKH ->
      (derive_bip44_receive, (fun () -> w.bip44_receive_index),
       (fun idx -> w.bip44_receive_index <- idx + 1), Address.P2PKH)
    | P2WPKH ->
      (derive_bip84_receive, (fun () -> w.receive_index),
       (fun idx -> w.receive_index <- idx + 1), Address.P2WPKH)
    | P2TR ->
      (derive_bip86_receive, (fun () -> w.bip86_receive_index),
       (fun idx -> w.bip86_receive_index <- idx + 1), Address.P2TR)
  in
  let private_key = match w.master_key with
    | Some master ->
      let rec try_derive idx =
        match derivation_fn master idx with
        | Ok pk ->
          set_index idx;
          pk
        | Error _ ->
          try_derive (idx + 1)
      in
      try_derive (get_index ())
    | None ->
      Crypto.generate_private_key ()
  in
  let public_key = Crypto.derive_public_key ~compressed:true private_key in
  let address = match addr_type with
    | P2TR ->
      (* P2TR uses x-only pubkey for address *)
      let xonly = Crypto.derive_xonly_pubkey private_key in
      Address.of_pubkey ~network:w.network addr_constructor xonly
    | _ ->
      Address.of_pubkey ~network:w.network addr_constructor public_key
  in
  let kp = { private_key; public_key; address; addr_type } in
  w.keys <- w.keys @ [kp];
  w.next_key_index <- w.next_key_index + 1;
  kp

(* Generate a new keypair (default: P2WPKH/BIP-84).
   If master_key is set, derive via BIP-84; otherwise use random generation. *)
let generate_key (w : t) : key_pair =
  generate_key_typed w P2WPKH

(* Generate a change key with specified address type *)
let generate_change_key_typed (w : t) (addr_type : address_type) : key_pair =
  let derivation_fn, get_index, set_index, addr_constructor = match addr_type with
    | P2PKH ->
      (derive_bip44_change, (fun () -> w.bip44_change_index),
       (fun idx -> w.bip44_change_index <- idx + 1), Address.P2PKH)
    | P2WPKH ->
      (derive_bip84_change, (fun () -> w.change_index),
       (fun idx -> w.change_index <- idx + 1), Address.P2WPKH)
    | P2TR ->
      (derive_bip86_change, (fun () -> w.bip86_change_index),
       (fun idx -> w.bip86_change_index <- idx + 1), Address.P2TR)
  in
  let private_key = match w.master_key with
    | Some master ->
      let rec try_derive idx =
        match derivation_fn master idx with
        | Ok pk ->
          set_index idx;
          pk
        | Error _ ->
          try_derive (idx + 1)
      in
      try_derive (get_index ())
    | None ->
      Crypto.generate_private_key ()
  in
  let public_key = Crypto.derive_public_key ~compressed:true private_key in
  let address = match addr_type with
    | P2TR ->
      let xonly = Crypto.derive_xonly_pubkey private_key in
      Address.of_pubkey ~network:w.network addr_constructor xonly
    | _ ->
      Address.of_pubkey ~network:w.network addr_constructor public_key
  in
  let kp = { private_key; public_key; address; addr_type } in
  w.keys <- w.keys @ [kp];
  w.next_key_index <- w.next_key_index + 1;
  kp

(* Generate a change key (default: P2WPKH/BIP-84).
   If master_key is set, derive via BIP-84 change path; otherwise random. *)
let generate_change_key (w : t) : key_pair =
  generate_change_key_typed w P2WPKH

(* Get a new receiving address with specified type *)
let get_new_address_typed (w : t) (addr_type : address_type) : string =
  let kp = generate_key_typed w addr_type in
  Address.address_to_string kp.address

(* Get a new receiving address (default: P2WPKH) *)
let get_new_address (w : t) : string =
  let kp = generate_key w in
  Address.address_to_string kp.address

(* Get all addresses in the wallet *)
let get_all_addresses (w : t) : string list =
  List.map (fun kp -> Address.address_to_string kp.address) w.keys

(* Check if a script_pubkey belongs to this wallet *)
let is_mine (w : t) (script_pubkey : Cstruct.t)
    : key_pair option =
  let template = Script.classify_script script_pubkey in
  match template with
  | Script.P2WPKH_script hash ->
    List.find_opt (fun kp ->
      let kp_hash = Crypto.hash160 kp.public_key in
      Cstruct.equal kp_hash hash
    ) w.keys
  | Script.P2PKH_script hash ->
    List.find_opt (fun kp ->
      let kp_hash = Crypto.hash160 kp.public_key in
      Cstruct.equal kp_hash hash
    ) w.keys
  | Script.P2TR_script xonly_hash ->
    List.find_opt (fun kp ->
      let xonly = Crypto.derive_xonly_pubkey kp.private_key in
      Cstruct.equal xonly xonly_hash
    ) w.keys
  | _ -> None

(* Find keypair by address string *)
let find_by_address (w : t) (addr_str : string) : key_pair option =
  List.find_opt (fun kp ->
    Address.address_to_string kp.address = addr_str
  ) w.keys

(* Find keypair by pubkey hash *)
let find_by_pubkey_hash (w : t) (pkh : Types.hash160) : key_pair option =
  List.find_opt (fun kp ->
    Cstruct.equal (Crypto.hash160 kp.public_key) pkh
  ) w.keys

(* ============================================================================
   Import/Export
   ============================================================================ *)

(* Import a private key in WIF format *)
let import_wif (w : t) ?(addr_type = P2WPKH) (wif : string) : (key_pair, string) result =
  match Address.wif_decode wif with
  | Error e -> Error e
  | Ok (private_key, _compressed, _network) ->
    let public_key = Crypto.derive_public_key ~compressed:true private_key in
    let address_constructor = match addr_type with
      | P2PKH -> Address.P2PKH
      | P2WPKH -> Address.P2WPKH
      | P2TR -> Address.P2TR
    in
    let address = match addr_type with
      | P2TR ->
        let xonly = Crypto.derive_xonly_pubkey private_key in
        Address.of_pubkey ~network:w.network address_constructor xonly
      | _ ->
        Address.of_pubkey ~network:w.network address_constructor public_key
    in
    let kp = { private_key; public_key; address; addr_type } in
    w.keys <- w.keys @ [kp];
    w.next_key_index <- w.next_key_index + 1;
    Ok kp

(* Export a keypair to WIF format *)
let export_wif (w : t) (addr_str : string) : string option =
  match find_by_address w addr_str with
  | None -> None
  | Some kp ->
    Some (Address.wif_encode ~compressed:true ~network:w.network kp.private_key)

(* ============================================================================
   UTXO Scanning and Balance Tracking
   ============================================================================ *)

(* Convert Cstruct to hex string — forward declaration needed by scan_block *)
let cstruct_to_hex (cs : Cstruct.t) : string =
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Scan a block for wallet-relevant transactions *)
let scan_block (w : t) (block : Types.block) (height : int) : unit =
  let block_hash = Crypto.compute_block_hash block.header in
  (* Display (reversed) byte order for the user-facing block hash + txids, so
     listtransactions / gettransaction return the SAME hashes as every other RPC
     (getbestblockhash, sendtoaddress, getrawmempool, ...).  [txid_hex] stays in
     internal order purely as the [sent_transactions] Hashtbl key (which is
     keyed by the internal-order hex throughout the wallet). *)
  let block_hash_hex = Types.hash256_to_hex_display block_hash in
  let block_timestamp = Int32.to_float block.header.timestamp in
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    let txid_hex = cstruct_to_hex txid in
    let txid_display = Types.hash256_to_hex_display txid in

    (* Check outputs for our addresses *)
    List.iteri (fun vout out ->
      match is_mine w out.Types.script_pubkey with
      | Some kp ->
        (* Find key index *)
        let key_index =
          match list_find_index (fun k -> k == kp) w.keys with
          | Some idx -> idx
          | None -> 0
        in
        (* Check if this is a coinbase transaction *)
        let is_coinbase =
          List.length tx.Types.inputs = 1 &&
          Cstruct.equal
            (List.hd tx.Types.inputs).previous_output.txid
            Types.zero_hash
        in
        let vout32 = Int32.of_int vout in
        (* Idempotency: if this outpoint is already tracked (e.g. it was first
           seen unconfirmed via [scan_transaction] when [sendtoaddress]
           accepted the change output to mempool, or the same block is
           re-scanned), do NOT double-credit. Instead promote the existing
           entry to confirmed at this height so [select_coins] (which filters on
           [confirmed]) and the confirmation count are correct, and adjust the
           confirmed/unconfirmed balance split. Mirrors Core's
           CWallet::AddToWallet upsert-by-{txid,vout}. *)
        let existing =
          List.find_opt (fun u ->
            Cstruct.equal u.outpoint.txid txid && u.outpoint.vout = vout32)
            w.utxos
        in
        (match existing with
         | Some prev ->
           if not prev.confirmed then begin
             (* Promote unconfirmed -> confirmed; move value across the split. *)
             w.balance_unconfirmed <-
               Int64.sub w.balance_unconfirmed prev.utxo.Utxo.value;
             w.balance_confirmed <-
               Int64.add w.balance_confirmed prev.utxo.Utxo.value;
             w.utxos <- List.map (fun u ->
               if Cstruct.equal u.outpoint.txid txid && u.outpoint.vout = vout32
               then { u with
                      confirmed = true;
                      utxo = { u.utxo with Utxo.height; is_coinbase } }
               else u) w.utxos
           end
           (* already confirmed: same block re-scanned -> no-op (idempotent). *)
         | None ->
        let wutxo = {
          outpoint = { txid; vout = vout32 };
          utxo = {
            Utxo.value = out.Types.value;
            script_pubkey = out.Types.script_pubkey;
            height;
            is_coinbase;
          };
          key_index;
          confirmed = true;
        } in
        w.utxos <- wutxo :: w.utxos;
        w.balance_confirmed <- Int64.add w.balance_confirmed out.Types.value);
        (* Record a credit history entry, deduped by {txid,vout} so a re-scanned
           block does not duplicate it.  A coinbase credit is [`Generate]
           (listtransactions reports "generate"/"immature" dynamically from the
           live maturity); a non-coinbase credit to an output of a tx the wallet
           itself sent is the wallet's OWN change — Core's CachedTxGetAmounts
           classifies change out of listReceived, so we skip recording a
           standalone receive row for it (the [`Send] row already accounts for
           the spend).  Every other non-coinbase credit is a [`Receive]. *)
        let already_logged =
          List.exists (fun h ->
            h.hist_txid = txid_display && h.hist_vout = vout
            && (match h.hist_category with `Send -> false | _ -> true))
            w.tx_history
        in
        let is_own_send = Hashtbl.mem w.sent_transactions txid_hex in
        if (not already_logged) && (is_coinbase || not is_own_send) then begin
          let hist_entry = {
            hist_txid = txid_display;
            hist_category = (if is_coinbase then `Generate else `Receive);
            hist_amount = out.Types.value;
            hist_fee = 0L;
            hist_address = Address.address_to_string kp.address;
            hist_vout = vout;
            hist_is_coinbase = is_coinbase;
            hist_confirmations = 1;
            hist_block_hash = block_hash_hex;
            hist_block_height = height;
            hist_timestamp = block_timestamp;
          } in
          w.tx_history <- hist_entry :: w.tx_history
        end
      | None -> ()
    ) tx.Types.outputs;

    (* If this tx is one the wallet itself sent, its unconfirmed [`Send] history
       row (recorded at create_transaction time with the correct destination,
       negative-magnitude amount and fee) is now confirmed at this block.
       Promote it in place — set the confirming block coordinates — mirroring
       Core's CWallet::transactionAddedToMempool -> blockConnected state
       transition.  This is how a send appears as confirmed in listtransactions:
       the spent input UTXO was already removed from [w.utxos] at sendtoaddress
       time (scan_transaction / CommitTransaction-style), so the input-scan below
       can no longer find it; the promotion here is the authoritative path. *)
    if Hashtbl.mem w.sent_transactions txid_hex then
      w.tx_history <- List.map (fun h ->
        if h.hist_txid = txid_display && h.hist_category = `Send
           && h.hist_block_height = 0
        then { h with
               hist_block_hash = block_hash_hex;
               hist_block_height = height;
               hist_timestamp = block_timestamp;
               hist_confirmations = 1 }
        else h) w.tx_history;

    (* Check inputs for spent UTXOs *)
    List.iter (fun inp ->
      let prev = inp.Types.previous_output in
      let spent = List.filter (fun wutxo ->
        Cstruct.equal wutxo.outpoint.txid prev.txid &&
        wutxo.outpoint.vout = prev.vout
      ) w.utxos in
      List.iter (fun wutxo ->
        w.utxos <- List.filter (fun u -> not (Cstruct.equal u.outpoint.txid wutxo.outpoint.txid && u.outpoint.vout = wutxo.outpoint.vout)) w.utxos;
        (* Debit from the matching balance bucket: a spent input may have been
           tracked unconfirmed (a mempool change output we credited earlier),
           in which case it never contributed to balance_confirmed. *)
        if wutxo.confirmed then
          w.balance_confirmed <-
            Int64.sub w.balance_confirmed wutxo.utxo.Utxo.value
        else
          w.balance_unconfirmed <-
            Int64.sub w.balance_unconfirmed wutxo.utxo.Utxo.value;
        (* Record a send history entry ONLY for a spend the wallet did not
           itself originate (a tx not in [sent_transactions]).  The wallet's own
           sends are surfaced by promoting their pre-recorded [`Send] row above
           (with the real destination + fee), so emitting another row here would
           double-list them with the wrong address (our own input addr) and a
           wrong amount (the whole spent UTXO rather than the value that left the
           wallet). *)
        if not (Hashtbl.mem w.sent_transactions txid_hex) then begin
          let kp_opt = is_mine w wutxo.utxo.Utxo.script_pubkey in
          let addr_str = match kp_opt with
            | Some kp -> Address.address_to_string kp.address
            | None -> ""
          in
          let hist_entry = {
            hist_txid = txid_display;
            hist_category = `Send;
            hist_amount = wutxo.utxo.Utxo.value;
            hist_fee = 0L;
            hist_address = addr_str;
            hist_vout = Int32.to_int wutxo.outpoint.vout;
            hist_is_coinbase = false;
            hist_confirmations = 1;
            hist_block_hash = block_hash_hex;
            hist_block_height = height;
            hist_timestamp = block_timestamp;
          } in
          w.tx_history <- hist_entry :: w.tx_history
        end
      ) spent
    ) tx.Types.inputs
  ) block.transactions

(* Reverse [scan_block] for a block being disconnected on a reorg (mirrors
   Bitcoin Core CWallet::blockDisconnected).  Removes the credits this block
   created so the ledger does not over-count coins that no longer exist on the
   active chain.  Note: like beamchain's unscan, this does NOT restore coins
   the disconnected block SPENT — camlcoin has no per-spend undo in the wallet
   ledger; the authoritative recovery path (rescan / scantxoutset) rebuilds the
   set.  Best-effort, keeps the spendable set from drifting upward. *)
let unscan_block (w : t) (block : Types.block) (_height : int) : unit =
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    List.iteri (fun vout out ->
      match is_mine w out.Types.script_pubkey with
      | Some _ ->
        let vout32 = Int32.of_int vout in
        let removed =
          List.find_opt (fun u ->
            Cstruct.equal u.outpoint.txid txid && u.outpoint.vout = vout32)
            w.utxos
        in
        (match removed with
         | Some u ->
           w.utxos <- List.filter (fun x ->
             not (Cstruct.equal x.outpoint.txid txid && x.outpoint.vout = vout32))
             w.utxos;
           if u.confirmed then
             w.balance_confirmed <-
               Int64.sub w.balance_confirmed u.utxo.Utxo.value
           else
             w.balance_unconfirmed <-
               Int64.sub w.balance_unconfirmed u.utxo.Utxo.value
         | None -> ())
      | None -> ()
    ) tx.Types.outputs
  ) block.transactions

(* Scan a single transaction (for mempool tracking) *)
let scan_transaction (w : t) (tx : Types.transaction) : unit =
  let txid = Crypto.compute_txid tx in

  (* Check outputs for our addresses *)
  List.iteri (fun vout out ->
    match is_mine w out.Types.script_pubkey with
    | Some kp ->
      let key_index =
        match list_find_index (fun k -> k == kp) w.keys with
        | Some idx -> idx
        | None -> 0
      in
      let is_coinbase = false in (* Mempool txs are never coinbase *)
      let wutxo = {
        outpoint = { txid; vout = Int32.of_int vout };
        utxo = {
          Utxo.value = out.Types.value;
          script_pubkey = out.Types.script_pubkey;
          height = 0;  (* Unconfirmed *)
          is_coinbase;
        };
        key_index;
        confirmed = false;
      } in
      w.utxos <- wutxo :: w.utxos;
      w.balance_unconfirmed <- Int64.add w.balance_unconfirmed out.Types.value
    | None -> ()
  ) tx.Types.outputs;

  (* Check inputs for spent UTXOs *)
  List.iter (fun inp ->
    let prev = inp.Types.previous_output in
    let spent = List.filter (fun wutxo ->
      Cstruct.equal wutxo.outpoint.txid prev.txid &&
      wutxo.outpoint.vout = prev.vout
    ) w.utxos in
    List.iter (fun wutxo ->
      w.utxos <- List.filter (fun u -> not (Cstruct.equal u.outpoint.txid wutxo.outpoint.txid && u.outpoint.vout = wutxo.outpoint.vout)) w.utxos;
      if wutxo.confirmed then
        w.balance_confirmed <- Int64.sub w.balance_confirmed wutxo.utxo.Utxo.value
      else
        w.balance_unconfirmed <- Int64.sub w.balance_unconfirmed wutxo.utxo.Utxo.value
    ) spent
  ) tx.Types.inputs

(* Is a tracked UTXO spendable at the given chain tip height?  Applies Bitcoin
   Core's coinbase-maturity rule: a coinbase output created at height H is
   spendable once it has [coinbase_maturity] (=100) confirmations, i.e. once
   [tip_height - H >= 100] (validation.cpp CheckInputs:
   premature_spend_of_coinbase / consensus/tx_verify.cpp).  Non-coinbase coins
   are spendable as soon as they are confirmed.  Unconfirmed coins are never
   selected for spending (Core's default min-conf is 1). *)
let is_spendable_at (wutxo : wallet_utxo) (tip_height : int) : bool =
  wutxo.confirmed &&
  (if wutxo.utxo.Utxo.is_coinbase then
     tip_height - wutxo.utxo.Utxo.height >= Consensus.coinbase_maturity
   else true)

(* The wallet's spendable UTXOs at the given chain tip (maturity-filtered).
   This is the set coin-selection runs over and getbalance counts. *)
let get_spendable_utxos (w : t) (tip_height : int) : wallet_utxo list =
  List.filter (fun u -> is_spendable_at u tip_height) w.utxos

(* Spendable (mature, confirmed) balance at the given chain tip, in satoshis.
   This is what Core's getbalance reports: immature coinbase is EXCLUDED. *)
let get_spendable_balance (w : t) (tip_height : int) : int64 =
  List.fold_left (fun acc u -> Int64.add acc u.utxo.Utxo.value)
    0L (get_spendable_utxos w tip_height)

(* Get confirmed and unconfirmed balance *)
let get_balance (w : t) : (int64 * int64) =
  (w.balance_confirmed, w.balance_unconfirmed)

(* Recalculate balance from UTXOs *)
let recalculate_balance (w : t) : unit =
  w.balance_confirmed <- 0L;
  w.balance_unconfirmed <- 0L;
  List.iter (fun wutxo ->
    if wutxo.confirmed then
      w.balance_confirmed <- Int64.add w.balance_confirmed wutxo.utxo.Utxo.value
    else
      w.balance_unconfirmed <- Int64.add w.balance_unconfirmed wutxo.utxo.Utxo.value
  ) w.utxos

(* ============================================================================
   Coin Selection
   ============================================================================ *)

type coin_selection = {
  selected : wallet_utxo list;
  total_input : int64;
  change : int64;
}

(* Estimate transaction weight for fee calculation *)
let estimate_tx_weight (n_inputs : int) (n_outputs : int) : int =
  (* P2WPKH transaction weight estimation:
     - Base: 10 vbytes (version, locktime, etc.)
     - Per input: ~68 vbytes (outpoint, sequence, empty script_sig)
       + witness data (~110 weight units for signature + pubkey)
     - Per output: ~31 vbytes (value + P2WPKH script)

     Weight = base*4 + inputs*(68*4 + 110) + outputs*31*4 *)
  let base_weight = 10 * 4 in
  let input_weight = n_inputs * (68 * 4 + 110) in  (* ~382 per input *)
  let output_weight = n_outputs * 31 * 4 in        (* 124 per output *)
  base_weight + input_weight + output_weight

(* Fisher-Yates shuffle for random permutation — uses CSPRNG for privacy.
   Coin selection order must be unpredictable to prevent UTXO fingerprinting. *)
let shuffle_list (lst : 'a list) : 'a list =
  let arr = Array.of_list lst in
  let n = Array.length arr in
  for i = n - 1 downto 1 do
    let j = csprng_int_range (i + 1) in
    let tmp = arr.(i) in
    arr.(i) <- arr.(j);
    arr.(j) <- tmp
  done;
  Array.to_list arr

(* Single Random Draw (SRD) coin selection.
   Shuffles UTXOs and selects until target is reached.
   Based on Bitcoin Core's SelectCoinsSRD. *)
let select_coins_srd (utxos : wallet_utxo list) (target : int64)
    : wallet_utxo list option =
  if List.length utxos = 0 then None
  else begin
    (* Shuffle the UTXOs *)
    let shuffled = shuffle_list utxos in
    let selected = ref [] in
    let total = ref 0L in
    (* Select UTXOs until we reach target *)
    List.iter (fun wutxo ->
      if Int64.compare !total target < 0 then begin
        selected := wutxo :: !selected;
        total := Int64.add !total wutxo.utxo.Utxo.value
      end
    ) shuffled;
    if Int64.compare !total target >= 0 then
      Some (List.rev !selected)
    else
      None
  end

(* Estimated input spending cost in vbytes for P2WPKH *)
let p2wpkh_input_vbytes = 68

(* Branch and Bound coin selection (Gap 17).
   Attempts to find an exact-match selection avoiding change outputs.
   Uses effective values (actual value minus input spending cost) for
   selection, but returns UTXOs with their actual values.
   Returns None if no suitable selection is found within iteration limit. *)
let select_coins_bnb (utxos : wallet_utxo list) (target : int64)
    (cost_of_change : int64) ~(fee_rate : float) : wallet_utxo list option =
  let input_cost = Int64.of_float (fee_rate *. float_of_int p2wpkh_input_vbytes) in
  (* Filter out UTXOs with non-positive effective value *)
  let with_eff = List.filter_map (fun u ->
    let eff = Int64.sub u.utxo.Utxo.value input_cost in
    if Int64.compare eff 0L > 0 then Some (u, eff) else None
  ) utxos in
  (* Sort by effective value descending *)
  let sorted = List.sort (fun (_, ea) (_, eb) ->
    Int64.compare eb ea
  ) with_eff in
  let arr = Array.of_list sorted in
  let n = Array.length arr in
  if n = 0 then None
  else begin
    let max_iterations = 100_000 in
    let iterations = ref 0 in
    let best = ref None in
    let upper = Int64.add target cost_of_change in

    (* Precompute suffix sums of effective values *)
    let suffix = Array.make (n + 1) 0L in
    for i = n - 1 downto 0 do
      let (_, eff) = arr.(i) in
      suffix.(i) <- Int64.add suffix.(i + 1) eff
    done;

    (* DFS with backtracking using effective values *)
    let rec search idx current_sum selection =
      if !iterations >= max_iterations then ()
      else begin
        incr iterations;
        if Int64.compare current_sum target >= 0 &&
           Int64.compare current_sum upper <= 0 then
          best := Some (List.rev selection)
        else if idx >= n then ()
        else if Int64.compare current_sum upper > 0 then ()
        else if Int64.compare (Int64.add current_sum suffix.(idx)) target < 0 then ()
        else begin
          let (utxo, eff) = arr.(idx) in
          search (idx + 1) (Int64.add current_sum eff) (utxo :: selection);
          if !best = None then
            search (idx + 1) current_sum selection
        end
      end
    in
    search 0 0L [];
    !best
  end

(* Select coins to meet target amount, trying BnB first then greedy fallback *)
let select_coins (w : t) (target : int64) (fee_rate : float)
    ?tip_height () : (coin_selection, string) result =
  (* Sort by value descending *)
  let available = List.sort (fun a b ->
    Int64.compare b.utxo.Utxo.value a.utxo.Utxo.value
  ) w.utxos in

  (* Only confirmed coins are spendable; when the chain tip height is known,
     also exclude immature coinbase (Core's premature_spend_of_coinbase rule).
     Without a tip height (no chain yet) fall back to the confirmed filter. *)
  let available = match tip_height with
    | Some h -> List.filter (fun u -> is_spendable_at u h) available
    | None -> List.filter (fun u -> u.confirmed) available
  in

  (* Estimate fee for a typical transaction (start with 1 input, 2 outputs) *)
  let estimated_tx_weight = estimate_tx_weight 1 2 in
  let estimated_fee = Int64.of_float
    (fee_rate *. float_of_int estimated_tx_weight /. 4.0) in
  let target_with_fee = Int64.add target estimated_fee in

  (* Cost of change: ~34 bytes for change output + ~68 bytes for spending it *)
  let cost_of_change = Int64.of_float
    (fee_rate *. float_of_int (34 + 68) /. 1.0) in

  (* Try BnB first for exact-match selection (no change output) *)
  match select_coins_bnb available target_with_fee cost_of_change ~fee_rate with
  | Some selected ->
    let total_input = List.fold_left (fun acc u ->
      Int64.add acc u.utxo.Utxo.value
    ) 0L selected in
    let n_inputs = List.length selected in
    (* Recalculate fee with actual input count, 1 output (no change) *)
    let actual_weight = estimate_tx_weight n_inputs 1 in
    let actual_fee = Int64.of_float
      (fee_rate *. float_of_int actual_weight /. 4.0) in
    let change = Int64.sub total_input (Int64.add target actual_fee) in
    Ok {
      selected;
      total_input;
      change;
    }
  | None ->
    (* Fall back to Single Random Draw (SRD) *)
    match select_coins_srd available target_with_fee with
    | Some selected ->
      let total_input = List.fold_left (fun acc u ->
        Int64.add acc u.utxo.Utxo.value
      ) 0L selected in
      let n_inputs = List.length selected in
      let actual_weight = estimate_tx_weight n_inputs 2 in
      let actual_fee = Int64.of_float
        (fee_rate *. float_of_int actual_weight /. 4.0) in
      let change = Int64.sub total_input (Int64.add target actual_fee) in
      Ok {
        selected;
        total_input;
        change;
      }
    | None ->
      let total_available = List.fold_left (fun acc u ->
        Int64.add acc u.utxo.Utxo.value
      ) 0L available in
      Error (Printf.sprintf
        "Insufficient funds: have %Ld satoshis, need %Ld"
        total_available target_with_fee)

(* Primary coin selection interface: BnB with SRD fallback.
   As specified: try_bnb target fee_rate utxos |> Option.value ~default:(srd target fee_rate utxos) *)
let coin_select ~target ~fee_rate (utxos : wallet_utxo list) : wallet_utxo list option =
  let available = List.filter (fun u -> u.confirmed) utxos in
  let estimated_tx_weight = estimate_tx_weight 1 2 in
  let estimated_fee = Int64.of_float
    (fee_rate *. float_of_int estimated_tx_weight /. 4.0) in
  let target_with_fee = Int64.add target estimated_fee in
  let cost_of_change = Int64.of_float
    (fee_rate *. float_of_int (34 + 68) /. 1.0) in
  match select_coins_bnb available target_with_fee cost_of_change ~fee_rate with
  | Some selected -> Some selected
  | None -> select_coins_srd available target_with_fee

(* ============================================================================
   Transaction Creation and Signing
   ============================================================================ *)

(* Dust threshold: outputs below this are non-economical *)
let dust_threshold = 546L

(* Build a P2WPKH script_pubkey from pubkey hash *)
let build_p2wpkh_script (hash : Types.hash160) : Cstruct.t =
  let s = Cstruct.create 22 in
  Cstruct.set_uint8 s 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 s 1 0x14;  (* push 20 bytes *)
  Cstruct.blit hash 0 s 2 20;
  s

(* Build a P2PKH script_pubkey from pubkey hash *)
let build_p2pkh_script (hash : Types.hash160) : Cstruct.t =
  let s = Cstruct.create 25 in
  Cstruct.set_uint8 s 0 0x76;   (* OP_DUP *)
  Cstruct.set_uint8 s 1 0xa9;   (* OP_HASH160 *)
  Cstruct.set_uint8 s 2 0x14;   (* push 20 bytes *)
  Cstruct.blit hash 0 s 3 20;
  Cstruct.set_uint8 s 23 0x88;  (* OP_EQUALVERIFY *)
  Cstruct.set_uint8 s 24 0xac;  (* OP_CHECKSIG *)
  s

(* Build a P2TR script_pubkey from x-only pubkey *)
let build_p2tr_script (hash : Types.hash256) : Cstruct.t =
  let s = Cstruct.create 34 in
  Cstruct.set_uint8 s 0 0x51;  (* OP_1 *)
  Cstruct.set_uint8 s 1 0x20;  (* push 32 bytes *)
  Cstruct.blit hash 0 s 2 32;
  s

(* Build a change script matching the destination script type for privacy *)
let build_change_script (dest_script : Cstruct.t) (change_pubkey : Cstruct.t) : Cstruct.t =
  match Script.classify_script dest_script with
  | Script.P2TR_script _ ->
    (* P2TR change: extract x-only key (strip 0x02 or 0x03 prefix) then
       compute the tweaked output key for key-path-only spending *)
    let xonly = Cstruct.sub change_pubkey 1 32 in
    let output_key = Crypto.compute_taproot_output_key xonly None in
    build_p2tr_script output_key
  | Script.P2PKH_script _ ->
    let change_hash = Crypto.hash160 change_pubkey in
    build_p2pkh_script change_hash
  | _ ->
    (* Default to P2WPKH for P2WPKH, P2WSH, and other types *)
    let change_hash = Crypto.hash160 change_pubkey in
    build_p2wpkh_script change_hash

(* ============================================================================
   Phase-2 segwit-v0 wrap signers (W28 — single-key + multisig P2WSH /
   P2SH-P2WPKH / P2SH-P2WSH).  Pure functions; no wallet state.

   References (Bitcoin Core):
   - script/sign.cpp::ProduceSignature  — top-level dispatcher
   - script/interpreter.cpp::SignatureHashV0  — BIP-143 sighash
   - The witnessScript serves as scriptCode for BIP-143 unconditionally
     for P2WSH (and P2SH-wrapped P2WSH) per BIP-143 spec.
   ============================================================================ *)

(* Encode an OP_PUSH for arbitrary-length payload.  Wraps with the
   correct opcode (direct push <0x4c, OP_PUSHDATA1/2/4) so the resulting
   bytes are a single push operation in script-execution semantics. *)
let push_data (payload : Cstruct.t) : Cstruct.t =
  let len = Cstruct.length payload in
  let prefix =
    if len < 0x4c then
      let b = Cstruct.create 1 in
      Cstruct.set_uint8 b 0 len; b
    else if len <= 0xff then
      let b = Cstruct.create 2 in
      Cstruct.set_uint8 b 0 0x4c;
      Cstruct.set_uint8 b 1 len; b
    else if len <= 0xffff then
      let b = Cstruct.create 3 in
      Cstruct.set_uint8 b 0 0x4d;
      Cstruct.set_uint8 b 1 (len land 0xff);
      Cstruct.set_uint8 b 2 ((len lsr 8) land 0xff); b
    else
      let b = Cstruct.create 5 in
      Cstruct.set_uint8 b 0 0x4e;
      Cstruct.set_uint8 b 1 (len land 0xff);
      Cstruct.set_uint8 b 2 ((len lsr 8) land 0xff);
      Cstruct.set_uint8 b 3 ((len lsr 16) land 0xff);
      Cstruct.set_uint8 b 4 ((len lsr 24) land 0xff); b
  in
  Cstruct.concat [prefix; payload]

(* Extract the (sorted-as-they-appear) list of compressed pubkeys from a
   bare OP_CHECKMULTISIG witnessScript:
     OP_M <pk1> <pk2> ... <pkN> OP_N OP_CHECKMULTISIG
   Returns None for any other script template.  Used to determine M (the
   required-signature count) and the canonical pubkey ordering — the
   witness must place sigs in pubkey-listed order, with an OP_0 dummy
   preceding the sigs to absorb the historical CHECKMULTISIG off-by-one. *)
let parse_multisig_witness_script (ws : Cstruct.t)
    : (int * int * Cstruct.t list) option =
  let len = Cstruct.length ws in
  if len < 4 then None
  else
    let last = Cstruct.get_uint8 ws (len - 1) in
    if last <> 0xae then None  (* OP_CHECKMULTISIG *)
    else
      let m_op = Cstruct.get_uint8 ws 0 in
      let n_op = Cstruct.get_uint8 ws (len - 2) in
      (* OP_1..OP_16 = 0x51..0x60 *)
      if m_op < 0x51 || m_op > 0x60 || n_op < 0x51 || n_op > 0x60 then None
      else
        let m = m_op - 0x50 in
        let n = n_op - 0x50 in
        if m > n || m = 0 then None
        else
          let pks = ref [] in
          let pos = ref 1 in
          let ok = ref true in
          for _ = 1 to n do
            if !ok && !pos < len - 2 then begin
              let push_len = Cstruct.get_uint8 ws !pos in
              if (push_len = 33 || push_len = 65)
                 && !pos + 1 + push_len <= len - 2 then begin
                pks := Cstruct.sub ws (!pos + 1) push_len :: !pks;
                pos := !pos + 1 + push_len
              end else ok := false
            end else ok := false
          done;
          if !ok && !pos = len - 2 && List.length !pks = n
          then Some (m, n, List.rev !pks)
          else None

(* BIP-143 P2WSH signer.  Caller supplies the witnessScript (which doubles
   as scriptCode for the sighash), the input value, the sighash type,
   and a list of signing keys.  For a 1-key OP_CHECKSIG witnessScript
   sign_keys must contain exactly that key.  For an M-of-N OP_CHECKMULTISIG
   witnessScript sign_keys must contain at least M keys whose pubkeys
   appear in the witnessScript; the witness is assembled with an OP_0
   dummy plus M sigs placed in pubkey-listed order (CHECKMULTISIG semantics).

   Returns the (input, witness) pair; the input is unchanged because
   segwit inputs leave script_sig empty. *)
let sign_input_p2wsh
    ~(tx : Types.transaction)
    ~(input_idx : int)
    ~(witness_script : Cstruct.t)
    ~(value : int64)
    ~(sign_keys : (Crypto.private_key * Crypto.public_key) list)
    ~(hash_type : int)
    : Types.tx_in * Types.tx_witness =
  let sighash =
    Script.compute_sighash_segwit tx input_idx witness_script value hash_type
  in
  let ht_byte = Cstruct.create 1 in
  Cstruct.set_uint8 ht_byte 0 hash_type;
  let inp = List.nth tx.inputs input_idx in
  let stack =
    match parse_multisig_witness_script witness_script with
    | Some (m, _n, pks) ->
      (* Order the M sigs by the witnessScript's pubkey order. *)
      let sigs_in_order = List.filter_map (fun pk ->
        match List.find_opt (fun (_sk, our_pk) ->
          Cstruct.equal our_pk pk
        ) sign_keys with
        | None -> None
        | Some (sk, _) ->
          let der = Crypto.sign sk sighash in
          Some (Cstruct.concat [der; ht_byte])
      ) pks in
      if List.length sigs_in_order < m then
        failwith (Printf.sprintf
          "sign_input_p2wsh: have %d matching keys, need %d"
          (List.length sigs_in_order) m);
      (* Truncate to M (Core verifies exactly M sigs; extras are stack
         garbage). *)
      let take_m =
        let rec aux n l = match n, l with
          | 0, _ | _, [] -> []
          | n, x :: rest -> x :: aux (n - 1) rest
        in aux m sigs_in_order
      in
      (Cstruct.create 0) :: take_m  (* OP_0 dummy + M sigs *)
    | None ->
      (* Single-key path: assume the witnessScript ends OP_CHECKSIG and
         our one signing key is the consumer.  Caller is responsible for
         passing the correct key. *)
      (match sign_keys with
       | [(sk, _pk)] ->
         let der = Crypto.sign sk sighash in
         [Cstruct.concat [der; ht_byte]]
       | [] -> failwith "sign_input_p2wsh: no signing keys"
       | _ ->
         failwith
           "sign_input_p2wsh: single-key path requires exactly one key")
  in
  let witness_items = stack @ [witness_script] in
  (inp, { Types.items = witness_items })

(* P2SH-P2WPKH wrap.  scriptSig = push(redeemScript), where
   redeemScript = OP_0 <hash160(pubkey)>.  BIP-143 sighash uses the
   implied P2PKH scriptCode ( OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY
   OP_CHECKSIG ).  Witness = [sig||hashtype, pubkey]. *)
let sign_input_p2sh_p2wpkh
    ~(tx : Types.transaction)
    ~(input_idx : int)
    ~(privkey : Crypto.private_key)
    ~(pubkey : Crypto.public_key)
    ~(value : int64)
    ~(hash_type : int)
    : Types.tx_in * Types.tx_witness =
  let pkh = Crypto.hash160 pubkey in
  (* redeemScript = OP_0 <20-byte pkh> (= 22 bytes total) *)
  let redeem_script = build_p2wpkh_script pkh in
  (* BIP-143 scriptCode for P2WPKH: OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY
     OP_CHECKSIG (= the legacy P2PKH script).  See BIP-143 spec. *)
  let script_code = build_p2pkh_script pkh in
  let sighash =
    Script.compute_sighash_segwit tx input_idx script_code value hash_type
  in
  let der = Crypto.sign privkey sighash in
  let ht_byte = Cstruct.create 1 in
  Cstruct.set_uint8 ht_byte 0 hash_type;
  let sig_with_hashtype = Cstruct.concat [der; ht_byte] in
  let script_sig = push_data redeem_script in
  let inp = List.nth tx.inputs input_idx in
  ({ inp with Types.script_sig },
   { Types.items = [sig_with_hashtype; pubkey] })

(* P2SH-P2WSH wrap.  scriptSig = push(redeemScript) where
   redeemScript = OP_0 <SHA256(witnessScript)>.  Witness identical to
   bare P2WSH.  BIP-143 sighash uses witnessScript as scriptCode. *)
let sign_input_p2sh_p2wsh
    ~(tx : Types.transaction)
    ~(input_idx : int)
    ~(witness_script : Cstruct.t)
    ~(value : int64)
    ~(sign_keys : (Crypto.private_key * Crypto.public_key) list)
    ~(hash_type : int)
    : Types.tx_in * Types.tx_witness =
  let ws_hash = Crypto.sha256 witness_script in
  (* redeemScript = OP_0 <32-byte sha256> (= 34 bytes total) *)
  let redeem_script = Cstruct.create 34 in
  Cstruct.set_uint8 redeem_script 0 0x00;
  Cstruct.set_uint8 redeem_script 1 0x20;
  Cstruct.blit ws_hash 0 redeem_script 2 32;
  let (_inp_unused, witness) =
    sign_input_p2wsh ~tx ~input_idx ~witness_script ~value ~sign_keys ~hash_type
  in
  let script_sig = push_data redeem_script in
  let inp = List.nth tx.inputs input_idx in
  ({ inp with Types.script_sig }, witness)

(* Helper: detect a P2SH scriptPubKey that wraps a P2WPKH whose pubkey
   the wallet owns.  Returns the matching keypair on success.  Used by
   the dispatcher below to route otherwise-unowned P2SH inputs through
   the new P2SH-P2WPKH signer. *)
let is_mine_p2sh_p2wpkh (w : t) (script_pubkey : Cstruct.t)
    : key_pair option =
  match Script.classify_script script_pubkey with
  | Script.P2SH_script script_hash ->
    List.find_opt (fun kp ->
      let pkh = Crypto.hash160 kp.public_key in
      let redeem = build_p2wpkh_script pkh in
      Cstruct.equal (Crypto.hash160 redeem) script_hash
    ) w.keys
  | _ -> None

(* Sign a transaction's inputs given the selected UTXOs *)
let sign_transaction_inputs (w : t) (tx : Types.transaction)
    (input_utxos : wallet_utxo list) : Types.transaction =
  let signed_inputs_and_witnesses = List.mapi (fun i wutxo ->
    let kp_opt = is_mine w wutxo.utxo.Utxo.script_pubkey in
    let kp = match kp_opt with
      | Some kp -> Some kp
      | None ->
        (* Phase-2 W28: also accept P2SH-P2WPKH wraps of an owned key. *)
        is_mine_p2sh_p2wpkh w wutxo.utxo.Utxo.script_pubkey
    in
    let kp = match kp with
      | Some kp -> kp
      | None -> failwith "Cannot find key for input"
    in
    let inp = List.nth tx.inputs i in
    let script_type = Script.classify_script wutxo.utxo.Utxo.script_pubkey in
    match script_type with
    | Script.P2TR_script _ ->
      (* Taproot key-path spend with BIP-341 tweaked key *)
      let prevouts = List.map (fun wu ->
        (wu.utxo.Utxo.value, wu.utxo.Utxo.script_pubkey)
      ) input_utxos in
      let sighash = Script.compute_sighash_taproot tx i prevouts 0x00 () in
      let xonly_pk = Crypto.derive_xonly_pubkey kp.private_key in
      let tweak = Crypto.compute_taptweak_keypath xonly_pk in
      let sig_bytes = Crypto.schnorr_sign_tweaked ~privkey:kp.private_key ~tweak ~msg:sighash in
      (* SIGHASH_DEFAULT (0x00): no suffix byte *)
      (inp, { Types.items = [sig_bytes] })
    | Script.P2WPKH_script _ ->
      (* BIP-143 SegWit signing *)
      let pubkey_hash = Crypto.hash160 kp.public_key in
      let script_code = build_p2pkh_script pubkey_hash in
      let sighash = Script.compute_sighash_segwit
        tx i script_code wutxo.utxo.Utxo.value
        Script.sighash_all in
      let signature = Crypto.sign kp.private_key sighash in
      let sig_with_hashtype = Cstruct.concat [
        signature; Cstruct.of_string "\x01"
      ] in
      (inp, { Types.items = [sig_with_hashtype; kp.public_key] })
    | Script.P2PKH_script _ ->
      (* Legacy P2PKH signing *)
      let script_code = wutxo.utxo.Utxo.script_pubkey in
      let sighash = Script.compute_sighash_legacy tx i script_code
        Script.sighash_all in
      let signature = Crypto.sign kp.private_key sighash in
      let sig_with_hashtype = Cstruct.concat [
        signature; Cstruct.of_string "\x01"
      ] in
      (* Build scriptSig: <sig_with_hashtype> <pubkey> *)
      let sig_len = Cstruct.length sig_with_hashtype in
      let pub_len = Cstruct.length kp.public_key in
      let script_sig = Cstruct.create (1 + sig_len + 1 + pub_len) in
      Cstruct.set_uint8 script_sig 0 sig_len;
      Cstruct.blit sig_with_hashtype 0 script_sig 1 sig_len;
      Cstruct.set_uint8 script_sig (1 + sig_len) pub_len;
      Cstruct.blit kp.public_key 0 script_sig (1 + sig_len + 1) pub_len;
      ({ inp with Types.script_sig }, { Types.items = [] })
    | Script.P2SH_script _ ->
      (* W28: only the P2SH-P2WPKH-of-owned-key shape is dispatchable
         here; the wallet does not store witnessScripts so bare P2SH
         multisig and P2SH-P2WSH require external context (RPC prevtxs
         array — not yet wired into this code path). *)
      sign_input_p2sh_p2wpkh
        ~tx ~input_idx:i
        ~privkey:kp.private_key
        ~pubkey:kp.public_key
        ~value:wutxo.utxo.Utxo.value
        ~hash_type:Script.sighash_all
    | _ ->
      failwith "sign_transaction_inputs: unsupported script type"
  ) input_utxos in
  let inputs = List.map fst signed_inputs_and_witnesses in
  let witnesses = List.map snd signed_inputs_and_witnesses in
  { tx with inputs; witnesses }

(* ============================================================================
   PSBT processing — the Signer + Updater role per BIP-174.

   Walks a PSBT input by input, fills witness_utxo / bip32 derivation data
   the wallet knows, and (when sign=true) creates a partial signature for
   every input the wallet has the key for.  Mirrors Bitcoin Core's
   CWallet::FillPSBT (src/wallet/scriptpubkeyman.cpp::FillPSBT +
   src/script/sign.cpp::SignPSBTInput).

   Inputs:
     w           wallet (must be unlocked when sign=true)
     psbt        the PSBT to update
     sign        if true, produce partial sigs / tap_key_sig
     sighash     sighash type to use when the input has none (default 0x01
                 for legacy/segwit, 0x00 SIGHASH_DEFAULT for taproot)
     bip32derivs if true, attach bip32_derivation records for the wallet
                 keys we touched
     finalize    [unused at the Wallet layer — RPC handler walks
                 Psbt.finalize_input_* after this returns]

   Returns (psbt', complete) where complete=true iff every input is either
   already-finalized or has enough partial sigs to be finalized for its
   script type.

   Reference: bitcoin-core/src/wallet/rpc/spend.cpp::walletprocesspsbt;
              src/wallet/scriptpubkeyman.cpp::FillPSBT. *)
let process_psbt
    (w : t)
    (psbt : Psbt.psbt)
    ~(sign : bool)
    ~(sighash : int)
    ~(bip32derivs : bool)
    : Psbt.psbt * bool =
  let tx = psbt.Psbt.tx in
  (* Collect the per-input UTXO (for value + scriptPubKey).  Prefer the
     witness_utxo when present (BIP-174 says it's authoritative for segwit
     inputs); otherwise project the non_witness_utxo's vout. *)
  let prevout_at (inp : Psbt.psbt_input) (tx_in : Types.tx_in)
      : Types.tx_out option =
    match inp.witness_utxo with
    | Some o -> Some o
    | None ->
      match inp.non_witness_utxo with
      | Some prev_tx ->
        let vout_idx = Int32.to_int tx_in.previous_output.vout in
        (try Some (List.nth prev_tx.outputs vout_idx)
         with _ -> None)
      | None -> None
  in
  (* Compute the master fingerprint once (or 0 if no master key — same as
     Core when the wallet has no HD seed). *)
  let fingerprint = match w.master_key with
    | Some mk -> fingerprint_of_key mk
    | None -> 0l
  in
  let make_derivation (pubkey : Cstruct.t) : Psbt.bip32_derivation =
    { pubkey;
      origin = { fingerprint; path = [] };
    }
  in
  (* Look up the wallet's owning keypair (if any) for a given scriptPubKey.
     Reuses [is_mine] for P2WPKH/P2PKH/P2TR, and [is_mine_p2sh_p2wpkh] for
     the P2SH-P2WPKH wrap case. *)
  let wallet_kp_for (script_pubkey : Cstruct.t) : key_pair option =
    match is_mine w script_pubkey with
    | Some kp -> Some kp
    | None -> is_mine_p2sh_p2wpkh w script_pubkey
  in
  (* Try to derive the scriptPubKey under which the input is claimed —
     either the direct prevout SPK, or, for P2SH-P2WPKH, the wrapped P2WPKH
     program from the redeem_script.  For sighash computation we need the
     "scriptCode" appropriate to the spend path. *)
  let process_one (i : int) (inp : Psbt.psbt_input) : Psbt.psbt_input * bool =
    let tx_in = List.nth tx.inputs i in
    (* If the input is already finalized, leave it alone. *)
    if Psbt.is_input_finalized inp then (inp, true)
    else
      match prevout_at inp tx_in with
      | None ->
        (* No UTXO info — can't sign and can't finalize. *)
        (inp, false)
      | Some utxo_out ->
        let value = utxo_out.value in
        let spk = utxo_out.script_pubkey in
        match wallet_kp_for spk with
        | None ->
          (* Not the wallet's input.  Still attach the witness_utxo we
             derived so downstream tooling has it.  Cannot sign. *)
          let inp = match inp.witness_utxo with
            | Some _ -> inp
            | None -> { inp with witness_utxo = Some utxo_out }
          in
          (inp, false)
        | Some kp ->
          let script_type = Script.classify_script spk in
          (* Resolve the effective sighash byte.  PSBT may override via
             inp.sighash_type; otherwise use the caller-supplied default.
             Taproot defaults to SIGHASH_DEFAULT (0x00) per BIP-341. *)
          let is_taproot = match script_type with
            | Script.P2TR_script _ -> true
            | _ -> false
          in
          let hash_type =
            match inp.sighash_type with
            | Some s -> Int32.to_int s
            | None ->
              if is_taproot then 0x00 else sighash
          in
          (* Build the bip32 derivation record (best-effort: path empty
             when wallet doesn't track per-key derivation path). *)
          let inp =
            if bip32derivs then begin
              if is_taproot then
                let xonly = Crypto.derive_xonly_pubkey kp.private_key in
                let tap_d : Psbt.tap_bip32_derivation = {
                  xonly_pubkey = xonly;
                  leaf_hashes = [];
                  origin = { fingerprint; path = [] };
                } in
                let exists = List.exists (fun (d : Psbt.tap_bip32_derivation) ->
                  Cstruct.equal d.xonly_pubkey xonly
                ) inp.tap_bip32_derivations in
                if exists then inp
                else { inp with
                  tap_bip32_derivations =
                    tap_d :: inp.tap_bip32_derivations }
              else
                let d = make_derivation kp.public_key in
                let exists = List.exists (fun (d2 : Psbt.bip32_derivation) ->
                  Cstruct.equal d2.pubkey kp.public_key
                ) inp.bip32_derivations in
                if exists then inp
                else { inp with
                  bip32_derivations = d :: inp.bip32_derivations }
            end else inp
          in
          (* Ensure witness_utxo is present (segwit) — Core fills this when
             the wallet learns the prevout. *)
          let inp = match inp.witness_utxo with
            | Some _ -> inp
            | None ->
              (* P2PKH is legacy: non_witness_utxo is what it needs.  For
                 segwit shapes (P2WPKH, P2TR, P2SH-P2WPKH, P2WSH) attach
                 witness_utxo. *)
              (match script_type with
               | Script.P2PKH_script _ -> inp
               | _ -> { inp with witness_utxo = Some utxo_out })
          in
          (* Sign it. *)
          if not sign then
            (* Updater-only path: no partial sig produced.  "complete" is
               false because we didn't sign. *)
            (inp, false)
          else begin
            match script_type with
            | Script.P2WPKH_script pkh ->
              (* BIP-143: scriptCode = OP_DUP OP_HASH160 <pkh>
                 OP_EQUALVERIFY OP_CHECKSIG. *)
              let script_code = build_p2pkh_script pkh in
              let h =
                Script.compute_sighash_segwit
                  tx i script_code value hash_type
              in
              let der = Crypto.sign kp.private_key h in
              let ht = Cstruct.create 1 in
              Cstruct.set_uint8 ht 0 hash_type;
              let sig_with_ht = Cstruct.concat [der; ht] in
              let ps : Psbt.partial_sig = {
                pubkey = kp.public_key;
                signature = sig_with_ht;
              } in
              let exists = List.exists (fun (p : Psbt.partial_sig) ->
                Cstruct.equal p.pubkey kp.public_key
              ) inp.partial_sigs in
              let inp =
                if exists then inp
                else { inp with partial_sigs = ps :: inp.partial_sigs }
              in
              (inp, true)
            | Script.P2PKH_script _ ->
              (* Legacy: sighash over the scriptPubKey itself. *)
              let h =
                Script.compute_sighash_legacy tx i spk hash_type
              in
              let der = Crypto.sign kp.private_key h in
              let ht = Cstruct.create 1 in
              Cstruct.set_uint8 ht 0 hash_type;
              let sig_with_ht = Cstruct.concat [der; ht] in
              let ps : Psbt.partial_sig = {
                pubkey = kp.public_key;
                signature = sig_with_ht;
              } in
              let exists = List.exists (fun (p : Psbt.partial_sig) ->
                Cstruct.equal p.pubkey kp.public_key
              ) inp.partial_sigs in
              let inp =
                if exists then inp
                else { inp with partial_sigs = ps :: inp.partial_sigs }
              in
              (inp, true)
            | Script.P2TR_script _ ->
              (* BIP-341 key-path spend.  Sign the tweaked key with
                 SIGHASH_DEFAULT (0x00) by default. *)
              (* Build the prevouts array required for the taproot sighash —
                 must cover every input.  Use whatever utxo info each input
                 already carries; abort signing this input if any is
                 missing. *)
              let prevouts =
                List.mapi (fun j ti ->
                  let inp_j = List.nth psbt.inputs j in
                  prevout_at inp_j ti
                ) tx.inputs
              in
              if List.exists Option.is_none prevouts then
                (inp, false)
              else
                let prevs = List.map (fun o ->
                  let o = Option.get o in
                  (o.Types.value, o.Types.script_pubkey)
                ) prevouts in
                let h =
                  Script.compute_sighash_taproot tx i prevs hash_type ()
                in
                let xonly_pk = Crypto.derive_xonly_pubkey kp.private_key in
                let tweak =
                  Crypto.compute_taptweak_keypath xonly_pk
                in
                let raw_sig =
                  Crypto.schnorr_sign_tweaked
                    ~privkey:kp.private_key ~tweak ~msg:h
                in
                (* SIGHASH_DEFAULT → bare 64-byte signature; non-default
                   appends the hashtype byte to make 65. *)
                let sig_bytes =
                  if hash_type = 0x00 then raw_sig
                  else
                    let ht = Cstruct.create 1 in
                    Cstruct.set_uint8 ht 0 hash_type;
                    Cstruct.concat [raw_sig; ht]
                in
                let inp = { inp with tap_key_sig = Some sig_bytes } in
                (inp, true)
            | Script.P2SH_script _ ->
              (* Currently only the P2SH-P2WPKH-wrap shape is signable
                 here (same restriction as sign_transaction_inputs).  We
                 inject the redeem_script (OP_0 <pkh>) and sign as
                 P2WPKH per BIP-143. *)
              let pkh = Crypto.hash160 kp.public_key in
              let redeem = build_p2wpkh_script pkh in
              let inp =
                match inp.redeem_script with
                | Some _ -> inp
                | None -> { inp with redeem_script = Some redeem }
              in
              let script_code = build_p2pkh_script pkh in
              let h =
                Script.compute_sighash_segwit
                  tx i script_code value hash_type
              in
              let der = Crypto.sign kp.private_key h in
              let ht = Cstruct.create 1 in
              Cstruct.set_uint8 ht 0 hash_type;
              let sig_with_ht = Cstruct.concat [der; ht] in
              let ps : Psbt.partial_sig = {
                pubkey = kp.public_key;
                signature = sig_with_ht;
              } in
              let exists = List.exists (fun (p : Psbt.partial_sig) ->
                Cstruct.equal p.pubkey kp.public_key
              ) inp.partial_sigs in
              let inp =
                if exists then inp
                else { inp with partial_sigs = ps :: inp.partial_sigs }
              in
              (inp, true)
            | _ ->
              (* Unsupported script type for wallet PSBT signer.  Leave
                 the input untouched; complete=false. *)
              (inp, false)
          end
  in
  let processed =
    List.mapi process_one psbt.inputs
  in
  let new_inputs = List.map fst processed in
  let all_signable = List.for_all snd processed in
  ({ psbt with inputs = new_inputs }, all_signable)

(* Build output script from an address *)
let build_output_script (dest_addr : Address.address) : Cstruct.t =
  match dest_addr.Address.addr_type with
  | Address.P2WPKH -> build_p2wpkh_script dest_addr.Address.hash
  | Address.P2PKH -> build_p2pkh_script dest_addr.Address.hash
  | Address.P2TR -> build_p2tr_script dest_addr.Address.hash
  | Address.P2WSH ->
    let s = Cstruct.create 34 in
    Cstruct.set_uint8 s 0 0x00;  (* OP_0 *)
    Cstruct.set_uint8 s 1 0x20;  (* push 32 bytes *)
    Cstruct.blit dest_addr.Address.hash 0 s 2 32;
    s
  | Address.P2SH ->
    let s = Cstruct.create 23 in
    Cstruct.set_uint8 s 0 0xa9;  (* OP_HASH160 *)
    Cstruct.set_uint8 s 1 0x14;  (* push 20 bytes *)
    Cstruct.blit dest_addr.Address.hash 0 s 2 20;
    Cstruct.set_uint8 s 22 0x87; (* OP_EQUAL *)
    s
  | Address.WitnessUnknown v ->
    let hash_len = Cstruct.length dest_addr.Address.hash in
    let s = Cstruct.create (2 + hash_len) in
    Cstruct.set_uint8 s 0 (0x50 + v);  (* OP_v = OP_1 + (v-1) for witness version v *)
    Cstruct.set_uint8 s 1 hash_len;    (* push N bytes *)
    Cstruct.blit dest_addr.Address.hash 0 s 2 hash_len;
    s

(* Create and sign a transaction *)
let create_transaction (w : t) ~(dest_address : string)
    ~(amount : int64) ~(fee_rate : float)
    ?tip_height
    () : (Types.transaction, string) result =

  (* Parse destination address *)
  match Address.address_of_string dest_address with
  | Error e -> Error e
  | Ok dest_addr ->
    (* Select coins (maturity-aware when the tip height is known) *)
    match select_coins w amount fee_rate ?tip_height () with
    | Error e -> Error e
    | Ok selection ->
      let dest_script = build_output_script dest_addr in

      (* Build outputs *)
      let outputs = ref [
        { Types.value = amount; script_pubkey = dest_script }
      ] in

      (* Add change output if significant *)
      if selection.change > dust_threshold then begin
        let change_kp = generate_change_key w in
        let change_script = build_change_script dest_script change_kp.public_key in
        let change_output = { Types.value = selection.change; script_pubkey = change_script } in
        outputs := insert_at_random !outputs change_output
      end;

      (* Build unsigned transaction inputs.
         FIX-70 / W120 BUG-2: default nSequence = MAX_BIP125_RBF_SEQUENCE
         (0xFFFFFFFD) so the created tx opts into BIP-125 RBF, matching
         Core CWallet since v23.  Previously 0xFFFFFFFE made every
         wallet-created tx unreplaceable and broke bump_fee's BIP-125
         rule 1 enforcement on mempools that require ancestor signaling. *)
      let inputs = List.map (fun wutxo ->
        { Types.previous_output = wutxo.outpoint;
          script_sig = Cstruct.create 0;  (* Empty for segwit *)
          sequence = max_bip125_rbf_sequence; }
      ) selection.selected in

      (* Anti-fee-sniping locktime — use CSPRNG for the 10% trigger.
         csprng_int_range 10 = 0 triggers with ~10% probability, matching
         Core's CWallet::CreateTransactionInternal random trigger. *)
      let locktime = match tip_height with
        | Some h ->
          if csprng_int_range 10 = 0 then Int32.of_int (max 0 (h - 1))
          else Int32.of_int h
        | None -> 0l
      in

      (* Create unsigned transaction *)
      let tx : Types.transaction = {
        version = 2l;
        inputs;
        outputs = !outputs;
        witnesses = [];
        locktime;
      } in

      (* Sign *)
      let signed_tx = sign_transaction_inputs w tx selection.selected in

      (* Track sent transaction for fee bumping *)
      let txid = Crypto.compute_txid signed_tx in
      let txid_hex = cstruct_to_hex txid in
      Hashtbl.replace w.sent_transactions txid_hex signed_tx;

      (* Record send history entry *)
      let total_input = List.fold_left (fun acc u ->
        Int64.add acc u.utxo.Utxo.value
      ) 0L selection.selected in
      let total_output = List.fold_left (fun acc out ->
        Int64.add acc out.Types.value
      ) 0L signed_tx.Types.outputs in
      let fee = Int64.sub total_input total_output in
      (* The destination output index (change may have been inserted at a random
         position, so it is not necessarily 0). *)
      let dest_vout =
        match list_find_index (fun out ->
          Cstruct.equal out.Types.script_pubkey dest_script) signed_tx.Types.outputs
        with Some i -> i | None -> 0
      in
      let hist_entry = {
        hist_txid = Types.hash256_to_hex_display txid;
        hist_category = `Send;
        hist_amount = amount;
        hist_fee = fee;
        hist_address = dest_address;
        hist_vout = dest_vout;
        hist_is_coinbase = false;
        hist_confirmations = 0;
        hist_block_hash = "";
        hist_block_height = 0;
        hist_timestamp = Unix.gettimeofday ();
      } in
      w.tx_history <- hist_entry :: w.tx_history;

      Ok signed_tx

(* Create a transaction with multiple outputs *)
let create_transaction_multi (w : t)
    ~(outputs : (string * int64) list) ~(fee_rate : float)
    ?tip_height
    () : (Types.transaction, string) result =

  (* Calculate total amount needed *)
  let total_amount = List.fold_left (fun acc (_, amt) ->
    Int64.add acc amt
  ) 0L outputs in

  (* Parse all destination addresses and build scripts *)
  let parsed_outputs = List.map (fun (addr_str, amount) ->
    match Address.address_of_string addr_str with
    | Error e -> failwith e
    | Ok dest_addr ->
      let script = build_output_script dest_addr in
      { Types.value = amount; script_pubkey = script }
  ) outputs in

  (* Select coins (maturity-aware when the tip height is known) *)
  match select_coins w total_amount fee_rate ?tip_height () with
  | Error e -> Error e
  | Ok selection ->
    (* Build all outputs including change *)
    let tx_outputs = ref parsed_outputs in

    if selection.change > dust_threshold then begin
      let change_kp = generate_change_key w in
      let dest_script = (List.hd parsed_outputs).Types.script_pubkey in
      let change_script = build_change_script dest_script change_kp.public_key in
      let change_output = { Types.value = selection.change; script_pubkey = change_script } in
      tx_outputs := insert_at_random !tx_outputs change_output
    end;

    (* Anti-fee-sniping locktime — use CSPRNG for the 10% trigger. *)
    let locktime = match tip_height with
      | Some h ->
        if csprng_int_range 10 = 0 then Int32.of_int (max 0 (h - 1))
        else Int32.of_int h
      | None -> 0l
    in

    (* Build and sign transaction.
       FIX-70 / W120 BUG-2: default nSequence = MAX_BIP125_RBF_SEQUENCE
       (0xFFFFFFFD) — opts into BIP-125 RBF.  See create_transaction. *)
    let inputs = List.map (fun wutxo ->
      { Types.previous_output = wutxo.outpoint;
        script_sig = Cstruct.create 0;
        sequence = max_bip125_rbf_sequence; }
    ) selection.selected in

    let tx : Types.transaction = {
      version = 2l;
      inputs;
      outputs = !tx_outputs;
      witnesses = [];
      locktime;
    } in

    let signed_tx = sign_transaction_inputs w tx selection.selected in

    (* Track for fee bumping *)
    let txid = Crypto.compute_txid signed_tx in
    let txid_hex = cstruct_to_hex txid in
    Hashtbl.replace w.sent_transactions txid_hex signed_tx;

    (* Record send history entries for each output *)
    let total_input = List.fold_left (fun acc u ->
      Int64.add acc u.utxo.Utxo.value
    ) 0L selection.selected in
    let total_output = List.fold_left (fun acc out ->
      Int64.add acc out.Types.value
    ) 0L signed_tx.Types.outputs in
    let fee = Int64.sub total_input total_output in
    List.iter (fun (addr_str, amt) ->
      (* Locate this destination output's index in the signed tx (change may
         have been inserted at a random position). *)
      let dest_vout =
        match Address.address_of_string addr_str with
        | Ok dest_addr ->
          let script = build_output_script dest_addr in
          (match list_find_index (fun out ->
             Cstruct.equal out.Types.script_pubkey script
             && out.Types.value = amt) signed_tx.Types.outputs
           with Some i -> i | None -> 0)
        | Error _ -> 0
      in
      let hist_entry = {
        hist_txid = Types.hash256_to_hex_display txid;
        hist_category = `Send;
        hist_amount = amt;
        hist_fee = fee;
        hist_address = addr_str;
        hist_vout = dest_vout;
        hist_is_coinbase = false;
        hist_confirmations = 0;
        hist_block_hash = "";
        hist_block_height = 0;
        hist_timestamp = Unix.gettimeofday ();
      } in
      w.tx_history <- hist_entry :: w.tx_history
    ) outputs;

    Ok signed_tx

(* ============================================================================
   Fee Bumping (RBF) - Gap 18
   ============================================================================ *)

(* Bump fee on a previously sent transaction via RBF (BIP-125).
   Finds the original tx, computes the new required fee, reduces the change
   output or adds more inputs as needed, sets nSequence for RBF signaling,
   and re-signs. *)
let bump_fee (w : t) ~(txid : Types.hash256) ~(new_fee_rate : float)
    : (Types.transaction, string) result =
  let txid_hex = cstruct_to_hex txid in
  match Hashtbl.find_opt w.sent_transactions txid_hex with
  | None -> Error "Transaction not found in wallet history"
  | Some orig_tx ->
    (* Compute original total input value by looking up from the parent
       transactions' outputs rather than the wallet's UTXO set (which
       no longer contains the spent UTXOs). *)
    let orig_input_total = List.fold_left (fun acc inp ->
      let prev = inp.Types.previous_output in
      let prev_txid_hex = cstruct_to_hex prev.txid in
      let vout = Int32.to_int prev.vout in
      let value =
        match Hashtbl.find_opt w.sent_transactions prev_txid_hex with
        | Some parent_tx ->
          if vout < List.length parent_tx.Types.outputs then
            (List.nth parent_tx.Types.outputs vout).Types.value
          else 0L
        | None ->
          (* Fall back to wallet UTXO set for non-wallet-sent inputs *)
          List.fold_left (fun v wutxo ->
            if Cstruct.equal wutxo.outpoint.txid prev.txid &&
               wutxo.outpoint.vout = prev.vout then
              wutxo.utxo.Utxo.value
            else v
          ) 0L w.utxos
      in
      Int64.add acc value
    ) 0L orig_tx.Types.inputs in

    let orig_output_total = List.fold_left (fun acc out ->
      Int64.add acc out.Types.value
    ) 0L orig_tx.Types.outputs in

    let orig_input_value = orig_input_total in

    let n_inputs = List.length orig_tx.inputs in
    let n_outputs = List.length orig_tx.outputs in
    let new_weight = estimate_tx_weight n_inputs n_outputs in
    let new_fee = Int64.of_float
      (new_fee_rate *. float_of_int new_weight /. 4.0) in
    let old_fee = Int64.sub orig_input_value orig_output_total in

    if Int64.compare new_fee old_fee <= 0 then
      Error "New fee rate does not result in higher fee"
    else begin
      let fee_increase = Int64.sub new_fee old_fee in

      (* Find change output: last output that belongs to us *)
      let change_idx = ref (-1) in
      List.iteri (fun i out ->
        match is_mine w out.Types.script_pubkey with
        | Some _ -> change_idx := i
        | None -> ()
      ) orig_tx.outputs;

      let new_outputs, extra_inputs_needed =
        if !change_idx >= 0 then begin
          let change_out = List.nth orig_tx.outputs !change_idx in
          let new_change_value = Int64.sub change_out.Types.value fee_increase in
          if Int64.compare new_change_value dust_threshold > 0 then begin
            (* Reduce change output *)
            let new_outs = List.mapi (fun i out ->
              if i = !change_idx then
                { out with Types.value = new_change_value }
              else out
            ) orig_tx.outputs in
            (new_outs, 0L)
          end else if Int64.compare new_change_value 0L >= 0 then begin
            (* Remove change output entirely (too small) *)
            let new_outs = List.filteri (fun i _ -> i <> !change_idx) orig_tx.outputs in
            (new_outs, 0L)
          end else begin
            (* Change is insufficient, need more inputs *)
            let deficit = Int64.neg new_change_value in
            let new_outs = List.filteri (fun i _ -> i <> !change_idx) orig_tx.outputs in
            (new_outs, deficit)
          end
        end else begin
          (* No change output, need additional inputs *)
          (orig_tx.outputs, fee_increase)
        end
      in

      (* Collect existing input outpoints to avoid duplication *)
      let existing_outpoints = List.map (fun inp ->
        (inp.Types.previous_output.txid, inp.Types.previous_output.vout)
      ) orig_tx.inputs in

      let is_existing_input txid_cs vout =
        List.exists (fun (t, v) ->
          Cstruct.equal t txid_cs && v = vout
        ) existing_outpoints
      in

      (* Add more inputs if needed *)
      let extra_inputs = ref [] in
      let extra_utxos = ref [] in
      let extra_total = ref 0L in
      if Int64.compare extra_inputs_needed 0L > 0 then begin
        let available = List.filter (fun u ->
          u.confirmed &&
          not (is_existing_input u.outpoint.txid u.outpoint.vout)
        ) w.utxos in
        let sorted = List.sort (fun a b ->
          Int64.compare b.utxo.Utxo.value a.utxo.Utxo.value
        ) available in
        List.iter (fun wutxo ->
          if Int64.compare !extra_total extra_inputs_needed < 0 then begin
            extra_inputs := { Types.previous_output = wutxo.outpoint;
                              script_sig = Cstruct.create 0;
                              sequence = 0xFFFFFFFDl } :: !extra_inputs;
            extra_utxos := wutxo :: !extra_utxos;
            extra_total := Int64.add !extra_total wutxo.utxo.Utxo.value
          end
        ) sorted
      end;

      if Int64.compare extra_inputs_needed 0L > 0 &&
         Int64.compare !extra_total extra_inputs_needed < 0 then
        Error "Insufficient funds to bump fee"
      else begin
        (* Set nSequence to 0xFFFFFFFD on all original inputs for RBF signaling *)
        let rbf_inputs = List.map (fun inp ->
          { inp with Types.sequence = 0xFFFFFFFDl }
        ) orig_tx.inputs in

        let all_inputs = rbf_inputs @ List.rev !extra_inputs in

        (* If we added extra inputs and have surplus, add change output *)
        let final_outputs =
          if Int64.compare !extra_total extra_inputs_needed > 0 then begin
            let surplus = Int64.sub !extra_total extra_inputs_needed in
            if Int64.compare surplus dust_threshold > 0 then begin
              let change_kp = generate_change_key w in
              let dest_script = (List.hd new_outputs).Types.script_pubkey in
              let change_script = build_change_script dest_script change_kp.public_key in
              insert_at_random new_outputs { Types.value = surplus; script_pubkey = change_script }
            end else
              new_outputs
          end else
            new_outputs
        in

        (* Build the replacement transaction *)
        let new_tx : Types.transaction = {
          version = orig_tx.version;
          inputs = all_inputs;
          outputs = final_outputs;
          witnesses = [];
          locktime = orig_tx.locktime;
        } in

        (* Reconstruct the full UTXO list for signing.
           For original inputs, look up values from the parent tx's outputs
           since the UTXOs are already spent from the wallet. *)
        let orig_utxos = List.filter_map (fun inp ->
          let prev = inp.Types.previous_output in
          let prev_txid_hex = cstruct_to_hex prev.txid in
          let vout = Int32.to_int prev.vout in
          match Hashtbl.find_opt w.sent_transactions prev_txid_hex with
          | Some parent_tx when vout < List.length parent_tx.Types.outputs ->
            let out = List.nth parent_tx.Types.outputs vout in
            Some {
              outpoint = prev;
              utxo = {
                Utxo.value = out.Types.value;
                script_pubkey = out.Types.script_pubkey;
                height = 0;
                is_coinbase = false;
              };
              key_index = 0;
              confirmed = true;
            }
          | _ ->
            List.find_opt (fun wutxo ->
              Cstruct.equal wutxo.outpoint.txid prev.txid &&
              wutxo.outpoint.vout = prev.vout
            ) w.utxos
        ) orig_tx.inputs in

        let all_utxos = orig_utxos @ List.rev !extra_utxos in

        if List.length all_utxos <> List.length all_inputs then
          Error "Cannot find all input UTXOs for re-signing"
        else begin
          let signed_tx = sign_transaction_inputs w new_tx all_utxos in

          (* Update sent_transactions: remove old, add new *)
          Hashtbl.remove w.sent_transactions txid_hex;
          let new_txid = Crypto.compute_txid signed_tx in
          let new_txid_hex = cstruct_to_hex new_txid in
          Hashtbl.replace w.sent_transactions new_txid_hex signed_tx;

          Ok signed_tx
        end
      end
    end

(* Update confirmation counts based on current chain height *)
let update_confirmations (w : t) (current_height : int) : unit =
  w.tx_history <- List.map (fun entry ->
    if entry.hist_block_height > 0 then
      { entry with hist_confirmations = current_height - entry.hist_block_height + 1 }
    else entry
  ) w.tx_history

(* ============================================================================
   Wallet Encryption (AES-256-CBC)
   ============================================================================ *)

(* Default number of key derivation rounds (matches Bitcoin Core) *)
let pbkdf2_iterations = 25000

(* Derive encryption key + IV from passphrase using PBKDF2-HMAC-SHA512.
   Uses Bitcoin Core's derivation method: SHA512 iterations produce 64 bytes,
   first 32 bytes are the AES-256 key, next 16 bytes are the IV. *)
let derive_key_and_iv (passphrase : string) (salt : Cstruct.t) : Cstruct.t * Cstruct.t =
  let iterations = pbkdf2_iterations in
  let salt_str = Cstruct.to_string salt in
  (* PBKDF2-HMAC-SHA512: produces 64 bytes in one block *)
  let hmac_sha512_str ~key data =
    Digestif.SHA512.hmac_string ~key data
    |> Digestif.SHA512.to_raw_string
  in
  (* Salt with block number (only 1 block needed for 64-byte output) *)
  let salt_with_block =
    let s = Bytes.create (String.length salt_str + 4) in
    Bytes.blit_string salt_str 0 s 0 (String.length salt_str);
    Bytes.set s (String.length salt_str) '\000';
    Bytes.set s (String.length salt_str + 1) '\000';
    Bytes.set s (String.length salt_str + 2) '\000';
    Bytes.set s (String.length salt_str + 3) '\001';
    Bytes.to_string s
  in
  let u = ref (hmac_sha512_str ~key:passphrase salt_with_block) in
  let result = Bytes.of_string !u in
  for _ = 2 to iterations do
    u := hmac_sha512_str ~key:passphrase !u;
    for j = 0 to 63 do
      let b = Char.code (Bytes.get result j) lxor Char.code (String.get !u j) in
      Bytes.set result j (Char.chr b)
    done
  done;
  let full = Cstruct.of_string (Bytes.to_string result) in
  let key = Cstruct.sub full 0 32 in  (* AES-256 key: 32 bytes *)
  let iv = Cstruct.sub full 32 16 in   (* AES-CBC IV: 16 bytes *)
  (key, iv)

(* Legacy derive_aes_key for backward compatibility *)
let derive_aes_key (passphrase : string) (salt : Cstruct.t) : Cstruct.t =
  let (key, _iv) = derive_key_and_iv passphrase salt in
  key

(* Generate a random salt for key derivation *)
let generate_salt () : Cstruct.t =
  let salt = Cstruct.create 16 in
  let fd = Unix.openfile "/dev/urandom" [Unix.O_RDONLY] 0 in
  let bytes = Bytes.create 16 in
  let _ = Unix.read fd bytes 0 16 in
  Unix.close fd;
  Cstruct.blit_from_bytes bytes 0 salt 0 16;
  salt

(* Generate a random IV for AES-CBC *)
let generate_iv () : Cstruct.t =
  let iv = Cstruct.create 16 in
  let fd = Unix.openfile "/dev/urandom" [Unix.O_RDONLY] 0 in
  let bytes = Bytes.create 16 in
  let _ = Unix.read fd bytes 0 16 in
  Unix.close fd;
  Cstruct.blit_from_bytes bytes 0 iv 0 16;
  iv

(* Pad data to AES block size (16 bytes) using PKCS7 padding *)
let pkcs7_pad (data : Cstruct.t) : Cstruct.t =
  let block_size = 16 in
  let len = Cstruct.length data in
  let pad_len = block_size - (len mod block_size) in
  let padded = Cstruct.create (len + pad_len) in
  Cstruct.blit data 0 padded 0 len;
  for i = 0 to pad_len - 1 do
    Cstruct.set_uint8 padded (len + i) pad_len
  done;
  padded

(* Remove PKCS7 padding *)
let pkcs7_unpad (data : Cstruct.t) : Cstruct.t option =
  let len = Cstruct.length data in
  if len = 0 || len mod 16 <> 0 then None
  else begin
    let pad_len = Cstruct.get_uint8 data (len - 1) in
    if pad_len = 0 || pad_len > 16 then None
    else if pad_len > len then None
    else begin
      (* Verify padding *)
      let valid = ref true in
      for i = 0 to pad_len - 1 do
        if Cstruct.get_uint8 data (len - 1 - i) <> pad_len then
          valid := false
      done;
      if !valid then
        Some (Cstruct.sub data 0 (len - pad_len))
      else
        None
    end
  end

(* Encrypt data with AES-256-CBC *)
let aes_256_cbc_encrypt ~(key : Cstruct.t) ~(iv : Cstruct.t) (plaintext : Cstruct.t) : Cstruct.t =
  let padded = pkcs7_pad plaintext in
  let cipher = Mirage_crypto.AES.CBC.of_secret (Cstruct.to_string key) in
  let iv_str = Cstruct.to_string iv in
  Cstruct.of_string (Mirage_crypto.AES.CBC.encrypt ~key:cipher ~iv:iv_str (Cstruct.to_string padded))

(* Decrypt data with AES-256-CBC *)
let aes_256_cbc_decrypt ~(key : Cstruct.t) ~(iv : Cstruct.t) (ciphertext : Cstruct.t) : Cstruct.t option =
  if Cstruct.length ciphertext = 0 || Cstruct.length ciphertext mod 16 <> 0 then
    None
  else begin
    let cipher = Mirage_crypto.AES.CBC.of_secret (Cstruct.to_string key) in
    let iv_str = Cstruct.to_string iv in
    let decrypted = Mirage_crypto.AES.CBC.decrypt ~key:cipher ~iv:iv_str (Cstruct.to_string ciphertext) in
    pkcs7_unpad (Cstruct.of_string decrypted)
  end

(* ============================================================================
   Wallet Passphrase Lock/Unlock
   ============================================================================ *)

(* Check if wallet is locked *)
let is_locked (w : t) : bool =
  match w.encryption.lock_state with
  | Locked -> true
  | Unlocked { expires; _ } ->
    let now = Unix.gettimeofday () in
    if now >= expires then begin
      (* Expired, transition to locked state *)
      w.encryption.lock_state <- Locked;
      true
    end else
      false

(* Check if wallet is encrypted *)
let is_encrypted (w : t) : bool =
  w.encryption.encrypted

(* Generate a random master key for encryption *)
let generate_master_key () : Cstruct.t =
  let key = Cstruct.create 32 in
  let fd = Unix.openfile "/dev/urandom" [Unix.O_RDONLY] 0 in
  let bytes = Bytes.create 32 in
  let _ = Unix.read fd bytes 0 32 in
  Unix.close fd;
  Cstruct.blit_from_bytes bytes 0 key 0 32;
  key

(* Encrypt a private key with the master key.
   Uses pubkey hash as IV per Bitcoin Core's approach. *)
let encrypt_private_key ~(master_key : Cstruct.t) (kp : key_pair) : Cstruct.t =
  let pubkey_hash = Crypto.sha256d kp.public_key in
  let iv = Cstruct.sub pubkey_hash 0 16 in
  aes_256_cbc_encrypt ~key:master_key ~iv kp.private_key

(* Decrypt a private key with the master key *)
let decrypt_private_key ~(master_key : Cstruct.t) ~(public_key : Cstruct.t)
    (encrypted : Cstruct.t) : Cstruct.t option =
  let pubkey_hash = Crypto.sha256d public_key in
  let iv = Cstruct.sub pubkey_hash 0 16 in
  aes_256_cbc_decrypt ~key:master_key ~iv encrypted

(* Encrypt the wallet with a passphrase.
   This encrypts all private keys and stores the encrypted master key. *)
let encrypt_wallet (w : t) ~(passphrase : string) : (unit, string) result =
  if w.encryption.encrypted then
    Error "Wallet is already encrypted"
  else if String.length passphrase = 0 then
    Error "Passphrase cannot be empty"
  else begin
    (* Generate salt and master key *)
    let salt = generate_salt () in
    let master_key = generate_master_key () in

    (* Derive encryption key from passphrase *)
    let (derived_key, derived_iv) = derive_key_and_iv passphrase salt in

    (* Encrypt each private key with the master key *)
    List.iter (fun kp ->
      let encrypted = encrypt_private_key ~master_key kp in
      let addr_str = Address.address_to_string kp.address in
      Hashtbl.replace w.encryption.encrypted_keys addr_str encrypted
    ) w.keys;

    (* Encrypt the master key with the derived key *)
    let encrypted_master = aes_256_cbc_encrypt ~key:derived_key ~iv:derived_iv master_key in

    (* Update encryption state *)
    w.encryption.encrypted <- true;
    w.encryption.salt <- Some salt;
    w.encryption.iv <- Some derived_iv;
    w.encryption.encrypted_master_key <- Some encrypted_master;
    w.encryption.lock_state <- Locked;

    (* Clear unencrypted private keys from memory (for security, replace with zeroes) *)
    List.iter (fun kp ->
      for i = 0 to Cstruct.length kp.private_key - 1 do
        Cstruct.set_uint8 kp.private_key i 0
      done
    ) w.keys;

    Ok ()
  end

(* Unlock the wallet with a passphrase for a specified timeout (seconds).
   Private keys become accessible until the timeout expires. *)
let wallet_passphrase (w : t) ~(passphrase : string) ~(timeout : float)
    : (unit, string) result =
  if not w.encryption.encrypted then
    Error "Wallet is not encrypted"
  else begin
    match w.encryption.salt, w.encryption.encrypted_master_key with
    | Some salt, Some encrypted_master ->
      (* Derive key from passphrase *)
      let (derived_key, derived_iv) = derive_key_and_iv passphrase salt in

      (* Try to decrypt master key *)
      (match aes_256_cbc_decrypt ~key:derived_key ~iv:derived_iv encrypted_master with
       | Some master_key ->
         (* Verify the master key by decrypting one private key *)
         let valid = List.length w.keys = 0 ||
           let kp = List.hd w.keys in
           let addr_str = Address.address_to_string kp.address in
           match Hashtbl.find_opt w.encryption.encrypted_keys addr_str with
           | Some encrypted ->
             (match decrypt_private_key ~master_key ~public_key:kp.public_key encrypted with
              | Some decrypted ->
                (* Verify by deriving pubkey and comparing *)
                let derived_pub = Crypto.derive_public_key ~compressed:true decrypted in
                Cstruct.equal derived_pub kp.public_key
              | None -> false)
           | None -> true  (* No encrypted key stored, assume valid *)
         in
         if valid then begin
           (* Decrypt all private keys and restore them *)
           List.iter (fun kp ->
             let addr_str = Address.address_to_string kp.address in
             match Hashtbl.find_opt w.encryption.encrypted_keys addr_str with
             | Some encrypted ->
               (match decrypt_private_key ~master_key ~public_key:kp.public_key encrypted with
                | Some decrypted ->
                  Cstruct.blit decrypted 0 kp.private_key 0 32
                | None -> ())
             | None -> ()
           ) w.keys;

           (* Set unlock state with expiration *)
           let expires = Unix.gettimeofday () +. timeout in
           w.encryption.lock_state <- Unlocked { master_key; expires };
           Ok ()
         end else
           Error "Error: The wallet passphrase entered was incorrect"
       | None ->
         Error "Error: The wallet passphrase entered was incorrect")
    | _ ->
      Error "Wallet encryption data is missing"
  end

(* Lock the wallet immediately *)
let wallet_lock (w : t) : unit =
  (* Clear private keys from memory *)
  if w.encryption.encrypted then begin
    List.iter (fun kp ->
      for i = 0 to Cstruct.length kp.private_key - 1 do
        Cstruct.set_uint8 kp.private_key i 0
      done
    ) w.keys
  end;
  w.encryption.lock_state <- Locked

(* Change the wallet passphrase *)
let wallet_passphrase_change (w : t) ~(old_passphrase : string)
    ~(new_passphrase : string) : (unit, string) result =
  if not w.encryption.encrypted then
    Error "Wallet is not encrypted"
  else if String.length new_passphrase = 0 then
    Error "New passphrase cannot be empty"
  else begin
    (* First unlock with old passphrase *)
    match wallet_passphrase w ~passphrase:old_passphrase ~timeout:60.0 with
    | Error e -> Error e
    | Ok () ->
      (* Get current master key *)
      match w.encryption.lock_state with
      | Locked -> Error "Failed to unlock wallet"
      | Unlocked { master_key; _ } ->
        (* Generate new salt and derive new key *)
        let new_salt = generate_salt () in
        let (new_derived_key, new_derived_iv) = derive_key_and_iv new_passphrase new_salt in

        (* Re-encrypt master key with new passphrase *)
        let new_encrypted_master = aes_256_cbc_encrypt
          ~key:new_derived_key ~iv:new_derived_iv master_key in

        (* Update encryption state *)
        w.encryption.salt <- Some new_salt;
        w.encryption.iv <- Some new_derived_iv;
        w.encryption.encrypted_master_key <- Some new_encrypted_master;

        (* Lock the wallet *)
        wallet_lock w;
        Ok ()
  end

(* Get time remaining until wallet locks (0 if locked) *)
let wallet_unlock_remaining (w : t) : float =
  match w.encryption.lock_state with
  | Locked -> 0.0
  | Unlocked { expires; _ } ->
    let now = Unix.gettimeofday () in
    max 0.0 (expires -. now)

(* ============================================================================
   Wallet Persistence
   ============================================================================ *)

(* Convert hex string to Cstruct *)
let hex_to_cstruct (s : string) : Cstruct.t =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* Convert address_type to string *)
let addr_type_to_string = function
  | P2PKH -> "p2pkh"
  | P2WPKH -> "p2wpkh"
  | P2TR -> "p2tr"

(* Convert string to address_type *)
let addr_type_of_string = function
  | "p2pkh" -> P2PKH
  | "p2tr" -> P2TR
  | _ -> P2WPKH  (* default *)

(* Save wallet to file (unencrypted) *)
let save (w : t) : unit =
  let keys_json = List.map (fun kp ->
    `Assoc [
      ("private_key", `String (cstruct_to_hex kp.private_key));
      ("address", `String (Address.address_to_string kp.address));
      ("addr_type", `String (addr_type_to_string kp.addr_type));
    ]
  ) w.keys in

  let utxos_json = List.map (fun wutxo ->
    `Assoc [
      ("txid", `String (cstruct_to_hex wutxo.outpoint.txid));
      ("vout", `Int (Int32.to_int wutxo.outpoint.vout));
      ("value", `String (Int64.to_string wutxo.utxo.Utxo.value));
      ("script_pubkey", `String (cstruct_to_hex wutxo.utxo.Utxo.script_pubkey));
      ("height", `Int wutxo.utxo.Utxo.height);
      ("is_coinbase", `Bool wutxo.utxo.Utxo.is_coinbase);
      ("key_index", `Int wutxo.key_index);
      ("confirmed", `Bool wutxo.confirmed);
    ]
  ) w.utxos in

  let history_json = List.map (fun h ->
    `Assoc [
      ("txid", `String h.hist_txid);
      ("category", `String (match h.hist_category with
        | `Send -> "send" | `Generate -> "generate" | `Receive -> "receive"));
      ("amount", `String (Int64.to_string h.hist_amount));
      ("fee", `String (Int64.to_string h.hist_fee));
      ("address", `String h.hist_address);
      ("vout", `Int h.hist_vout);
      ("is_coinbase", `Bool h.hist_is_coinbase);
      ("confirmations", `Int h.hist_confirmations);
      ("blockhash", `String h.hist_block_hash);
      ("blockheight", `Int h.hist_block_height);
      ("time", `Float h.hist_timestamp);
    ]
  ) w.tx_history in

  let network_str = match w.network with
    | `Mainnet -> "mainnet"
    | `Testnet -> "testnet"
    | `Regtest -> "regtest"
  in

  let json = `Assoc [
    ("network", `String network_str);
    ("keys", `List keys_json);
    ("utxos", `List utxos_json);
    ("next_key_index", `Int w.next_key_index);
    ("balance_confirmed", `String (Int64.to_string w.balance_confirmed));
    ("balance_unconfirmed", `String (Int64.to_string w.balance_unconfirmed));
    ("bip44_receive_index", `Int w.bip44_receive_index);
    ("bip44_change_index", `Int w.bip44_change_index);
    ("bip86_receive_index", `Int w.bip86_receive_index);
    ("bip86_change_index", `Int w.bip86_change_index);
    ("tx_history", `List history_json);
  ] in

  let oc = open_out w.db_path in
  output_string oc (Yojson.Safe.to_string json);
  close_out oc

(* Save wallet to file with AES-256-CBC encryption *)
let save_encrypted (w : t) ~(passphrase : string) : unit =
  let keys_json = List.map (fun kp ->
    `Assoc [
      ("private_key", `String (cstruct_to_hex kp.private_key));
      ("address", `String (Address.address_to_string kp.address));
      ("addr_type", `String (addr_type_to_string kp.addr_type));
    ]
  ) w.keys in

  let utxos_json = List.map (fun wutxo ->
    `Assoc [
      ("txid", `String (cstruct_to_hex wutxo.outpoint.txid));
      ("vout", `Int (Int32.to_int wutxo.outpoint.vout));
      ("value", `String (Int64.to_string wutxo.utxo.Utxo.value));
      ("script_pubkey", `String (cstruct_to_hex wutxo.utxo.Utxo.script_pubkey));
      ("height", `Int wutxo.utxo.Utxo.height);
      ("is_coinbase", `Bool wutxo.utxo.Utxo.is_coinbase);
      ("key_index", `Int wutxo.key_index);
      ("confirmed", `Bool wutxo.confirmed);
    ]
  ) w.utxos in

  let history_json = List.map (fun h ->
    `Assoc [
      ("txid", `String h.hist_txid);
      ("category", `String (match h.hist_category with
        | `Send -> "send" | `Generate -> "generate" | `Receive -> "receive"));
      ("amount", `String (Int64.to_string h.hist_amount));
      ("fee", `String (Int64.to_string h.hist_fee));
      ("address", `String h.hist_address);
      ("vout", `Int h.hist_vout);
      ("is_coinbase", `Bool h.hist_is_coinbase);
      ("confirmations", `Int h.hist_confirmations);
      ("blockhash", `String h.hist_block_hash);
      ("blockheight", `Int h.hist_block_height);
      ("time", `Float h.hist_timestamp);
    ]
  ) w.tx_history in

  let network_str = match w.network with
    | `Mainnet -> "mainnet"
    | `Testnet -> "testnet"
    | `Regtest -> "regtest"
  in

  let json = `Assoc [
    ("network", `String network_str);
    ("keys", `List keys_json);
    ("utxos", `List utxos_json);
    ("next_key_index", `Int w.next_key_index);
    ("balance_confirmed", `String (Int64.to_string w.balance_confirmed));
    ("balance_unconfirmed", `String (Int64.to_string w.balance_unconfirmed));
    ("bip44_receive_index", `Int w.bip44_receive_index);
    ("bip44_change_index", `Int w.bip44_change_index);
    ("bip86_receive_index", `Int w.bip86_receive_index);
    ("bip86_change_index", `Int w.bip86_change_index);
    ("tx_history", `List history_json);
  ] in

  (* Encrypt the JSON content *)
  let salt = generate_salt () in
  let iv = generate_iv () in
  let key = derive_aes_key passphrase salt in
  let plaintext = Cstruct.of_string (Yojson.Safe.to_string json) in
  let ciphertext = aes_256_cbc_encrypt ~key ~iv plaintext in

  (* Store encrypted wallet with salt and IV prepended *)
  let header = `Assoc [
    ("encrypted", `Bool true);
    ("salt", `String (cstruct_to_hex salt));
    ("iv", `String (cstruct_to_hex iv));
    ("data", `String (cstruct_to_hex ciphertext));
  ] in

  let oc = open_out w.db_path in
  output_string oc (Yojson.Safe.to_string header);
  close_out oc;

  (* Update encryption state *)
  w.encryption.encrypted <- true;
  w.encryption.salt <- Some salt;
  w.encryption.iv <- Some iv

(* Load wallet data from JSON into wallet *)
let load_wallet_json (w : t) (network : [`Mainnet | `Testnet | `Regtest]) (json : Yojson.Safe.t) : unit =
  match json with
  | `Assoc fields ->
    (* Load keys *)
    (match List.assoc_opt "keys" fields with
     | Some (`List keys) ->
       List.iter (fun k ->
         match k with
         | `Assoc kf ->
           (match List.assoc_opt "private_key" kf with
            | Some (`String hex) ->
              let private_key = hex_to_cstruct hex in
              let public_key = Crypto.derive_public_key
                ~compressed:true private_key in
              let addr_type = match List.assoc_opt "addr_type" kf with
                | Some (`String s) -> addr_type_of_string s
                | _ -> P2WPKH
              in
              let addr_constructor = match addr_type with
                | P2PKH -> Address.P2PKH
                | P2WPKH -> Address.P2WPKH
                | P2TR -> Address.P2TR
              in
              let address = match addr_type with
                | P2TR ->
                  let xonly = Crypto.derive_xonly_pubkey private_key in
                  Address.of_pubkey ~network addr_constructor xonly
                | _ ->
                  Address.of_pubkey ~network addr_constructor public_key
              in
              w.keys <- w.keys @ [{ private_key; public_key; address; addr_type }]
            | _ -> ())
         | _ -> ()
       ) keys
     | _ -> ());

    (* Load UTXOs *)
    (match List.assoc_opt "utxos" fields with
     | Some (`List utxos) ->
       List.iter (fun u ->
         match u with
         | `Assoc uf ->
           let txid = match List.assoc_opt "txid" uf with
             | Some (`String h) -> hex_to_cstruct h
             | _ -> Types.zero_hash
           in
           let vout = match List.assoc_opt "vout" uf with
             | Some (`Int v) -> Int32.of_int v
             | _ -> 0l
           in
           let value = match List.assoc_opt "value" uf with
             | Some (`String v) -> Int64.of_string v
             | _ -> 0L
           in
           let script_pubkey = match List.assoc_opt "script_pubkey" uf with
             | Some (`String h) -> hex_to_cstruct h
             | _ -> Cstruct.create 0
           in
           let height = match List.assoc_opt "height" uf with
             | Some (`Int h) -> h
             | _ -> 0
           in
           let is_coinbase = match List.assoc_opt "is_coinbase" uf with
             | Some (`Bool b) -> b
             | _ -> false
           in
           let key_index = match List.assoc_opt "key_index" uf with
             | Some (`Int i) -> i
             | _ -> 0
           in
           let confirmed = match List.assoc_opt "confirmed" uf with
             | Some (`Bool b) -> b
             | _ -> true
           in
           let wutxo = {
             outpoint = { txid; vout };
             utxo = { Utxo.value; script_pubkey; height; is_coinbase };
             key_index;
             confirmed;
           } in
           w.utxos <- w.utxos @ [wutxo]
         | _ -> ()
       ) utxos
     | _ -> ());

    (* Load index fields *)
    (match List.assoc_opt "next_key_index" fields with
     | Some (`Int n) -> w.next_key_index <- n | _ -> ());
    (match List.assoc_opt "balance_confirmed" fields with
     | Some (`String v) -> w.balance_confirmed <- Int64.of_string v | _ -> ());
    (match List.assoc_opt "balance_unconfirmed" fields with
     | Some (`String v) -> w.balance_unconfirmed <- Int64.of_string v | _ -> ());
    (match List.assoc_opt "bip44_receive_index" fields with
     | Some (`Int n) -> w.bip44_receive_index <- n | _ -> ());
    (match List.assoc_opt "bip44_change_index" fields with
     | Some (`Int n) -> w.bip44_change_index <- n | _ -> ());
    (match List.assoc_opt "bip86_receive_index" fields with
     | Some (`Int n) -> w.bip86_receive_index <- n | _ -> ());
    (match List.assoc_opt "bip86_change_index" fields with
     | Some (`Int n) -> w.bip86_change_index <- n | _ -> ());

    (* Load transaction history *)
    (match List.assoc_opt "tx_history" fields with
     | Some (`List entries) ->
       List.iter (fun entry ->
         match entry with
         | `Assoc ef ->
           let hist_txid = match List.assoc_opt "txid" ef with
             | Some (`String s) -> s | _ -> "" in
           let hist_category = match List.assoc_opt "category" ef with
             | Some (`String "send") -> `Send
             | Some (`String "generate") -> `Generate
             | _ -> `Receive in
           let hist_amount = match List.assoc_opt "amount" ef with
             | Some (`String s) -> Int64.of_string s | _ -> 0L in
           let hist_fee = match List.assoc_opt "fee" ef with
             | Some (`String s) -> Int64.of_string s | _ -> 0L in
           let hist_address = match List.assoc_opt "address" ef with
             | Some (`String s) -> s | _ -> "" in
           let hist_vout = match List.assoc_opt "vout" ef with
             | Some (`Int n) -> n | _ -> 0 in
           let hist_is_coinbase = match List.assoc_opt "is_coinbase" ef with
             | Some (`Bool b) -> b
             | _ -> (hist_category = `Generate) in
           let hist_confirmations = match List.assoc_opt "confirmations" ef with
             | Some (`Int n) -> n | _ -> 0 in
           let hist_block_hash = match List.assoc_opt "blockhash" ef with
             | Some (`String s) -> s | _ -> "" in
           let hist_block_height = match List.assoc_opt "blockheight" ef with
             | Some (`Int n) -> n | _ -> 0 in
           let hist_timestamp = match List.assoc_opt "time" ef with
             | Some (`Float f) -> f
             | Some (`Int n) -> float_of_int n
             | _ -> 0.0 in
           let h = {
             hist_txid; hist_category; hist_amount; hist_fee;
             hist_address; hist_vout; hist_is_coinbase;
             hist_confirmations; hist_block_hash;
             hist_block_height; hist_timestamp;
           } in
           w.tx_history <- w.tx_history @ [h]
         | _ -> ()
       ) entries
     | _ -> ())
  | _ -> ()

(* Load wallet from file (unencrypted) *)
let load ~(network : [`Mainnet | `Testnet | `Regtest])
    ~(db_path : string) : t =
  if Sys.file_exists db_path then begin
    let ic = open_in db_path in
    let len = in_channel_length ic in
    let data = really_input_string ic len in
    close_in ic;

    let json = Yojson.Safe.from_string data in
    let w = create ~network ~db_path in
    load_wallet_json w network json;
    w
  end else
    create ~network ~db_path

(* Load wallet from encrypted file *)
let load_encrypted ~(network : [`Mainnet | `Testnet | `Regtest])
    ~(db_path : string) ~(passphrase : string) : (t, string) result =
  if not (Sys.file_exists db_path) then
    Error "Wallet file does not exist"
  else begin
    let ic = open_in db_path in
    let len = in_channel_length ic in
    let data = really_input_string ic len in
    close_in ic;

    let json = Yojson.Safe.from_string data in
    match json with
    | `Assoc fields ->
      (match List.assoc_opt "encrypted" fields with
       | Some (`Bool true) ->
         (* Encrypted wallet: extract salt, IV, and ciphertext *)
         let salt = match List.assoc_opt "salt" fields with
           | Some (`String h) -> hex_to_cstruct h
           | _ -> failwith "Missing salt"
         in
         let iv = match List.assoc_opt "iv" fields with
           | Some (`String h) -> hex_to_cstruct h
           | _ -> failwith "Missing IV"
         in
         let ciphertext = match List.assoc_opt "data" fields with
           | Some (`String h) -> hex_to_cstruct h
           | _ -> failwith "Missing encrypted data"
         in
         (* Derive key and decrypt *)
         let key = derive_aes_key passphrase salt in
         (match aes_256_cbc_decrypt ~key ~iv ciphertext with
          | Some plaintext ->
            let decrypted_json = Yojson.Safe.from_string (Cstruct.to_string plaintext) in
            let w = create ~network ~db_path in
            w.encryption.encrypted <- true;
            w.encryption.salt <- Some salt;
            w.encryption.iv <- Some iv;
            load_wallet_json w network decrypted_json;
            Ok w
          | None ->
            Error "Decryption failed: incorrect passphrase or corrupted data")
       | _ ->
         (* Unencrypted wallet, just load it *)
         let w = create ~network ~db_path in
         load_wallet_json w network json;
         Ok w)
    | _ -> Error "Invalid wallet file format"
  end

(* ============================================================================
   Wallet Info
   ============================================================================ *)

(* Sign a message hash with a specific keypair *)
let sign_hash (kp : key_pair) (hash : Types.hash256) : Crypto.signature =
  Crypto.sign kp.private_key hash

(* Check if wallet can sign for a pubkey hash *)
let can_sign (w : t) (pkh : Types.hash160) : bool =
  Option.is_some (find_by_pubkey_hash w pkh)

(* Get the number of keys in the wallet *)
let key_count (w : t) : int =
  List.length w.keys

(* Get the number of UTXOs in the wallet *)
let utxo_count (w : t) : int =
  List.length w.utxos

(* Check if wallet is empty *)
let is_empty (w : t) : bool =
  w.keys = []

(* Get list of UTXOs *)
let get_utxos (w : t) : wallet_utxo list =
  w.utxos

(* Clear UTXOs (for rescanning) *)
let clear_utxos (w : t) : unit =
  w.utxos <- [];
  w.balance_confirmed <- 0L;
  w.balance_unconfirmed <- 0L

(* Reset the wallet's chain-derived ledger ahead of a from-scratch rescan
   (rescanblockchain with start_height = 0).  Clears the UTXO set, both balance
   buckets, and the on-chain history rows so re-applying [scan_block] over the
   block range rebuilds the ledger without double-counting.  Mirrors Bitcoin
   Core's CWallet::ScanForWalletTransactions(fUpdate=true) over the full chain,
   which re-derives every wallet credit/debit from the blocks themselves.

   The [sent_transactions] table is intentionally preserved: it records txs the
   wallet itself originated (with their real destination / fee), and [scan_block]
   re-promotes their pre-recorded [`Send] history rows as it re-walks the range.
   A wallet restored from seed alone (the recovery -> rescan path) has an empty
   [sent_transactions] table, so this is a no-op for that case. *)
let clear_for_rescan (w : t) : unit =
  w.utxos <- [];
  w.balance_confirmed <- 0L;
  w.balance_unconfirmed <- 0L;
  w.tx_history <- []

(* ============================================================================
   Locked coins (lockunspent / listlockunspent)
   Mirrors Bitcoin Core CWallet::{LockCoin,UnlockCoin,IsLockedCoin,
   ListLockedCoins,UnlockAllCoins} (src/wallet/wallet.cpp).  In-memory locks
   are dropped on process exit (Core wipes m_setLockedCoins for unwritten
   entries on restart); we have no on-disk lockset yet, so persistent=true
   currently behaves like persistent=false but is accepted for API parity.
   ============================================================================ *)

(* Internal key: txid hex (32 bytes raw -> 64 hex chars) + vout.  We use the
   raw byte string (not display-reversed) so the encoding is canonical. *)
let outpoint_key (op : Types.outpoint) : string * int32 =
  (Cstruct.to_string op.Types.txid, op.Types.vout)

(* Lock a coin.  Returns false if already locked AND we're not upgrading from
   in-memory to persistent.  Matches Core's behaviour where re-locking with
   persistent=true upgrades the entry. *)
let lock_coin (w : t) (op : Types.outpoint) ~(persistent : bool) : bool =
  let k = outpoint_key op in
  (match Hashtbl.find_opt w.locked_coins k with
   | Some existing_persistent when existing_persistent || not persistent ->
     (* Already locked with at-least the requested persistence: nothing to do
        except return success (Core's LockCoin always returns true in this
        path; the caller already filtered duplicates). *)
     ()
   | _ ->
     Hashtbl.replace w.locked_coins k persistent);
  true

let unlock_coin (w : t) (op : Types.outpoint) : bool =
  let k = outpoint_key op in
  Hashtbl.remove w.locked_coins k;
  true

let is_locked_coin (w : t) (op : Types.outpoint) : bool =
  Hashtbl.mem w.locked_coins (outpoint_key op)

let unlock_all_coins (w : t) : bool =
  Hashtbl.clear w.locked_coins;
  true

let list_locked_coins (w : t) : Types.outpoint list =
  Hashtbl.fold (fun (txid_str, vout) _persistent acc ->
    let op = { Types.txid = Cstruct.of_string txid_str; vout } in
    op :: acc
  ) w.locked_coins []

(* ============================================================================
   Legacy Interface (for backward compatibility)
   ============================================================================ *)

type keypair = key_pair

(* Create wallet with network config (legacy interface) *)
let create_legacy (network : Consensus.network_config) : t =
  let net = match network.Consensus.name with
    | "mainnet" -> `Mainnet
    | "testnet" -> `Testnet
    | _ -> `Regtest
  in
  create ~network:net ~db_path:""

(* Get addresses (legacy interface) *)
let get_addresses (w : t) : string list =
  get_all_addresses w

(* ============================================================================
   Multi-Wallet Manager
   ============================================================================ *)

(* Wallet creation options *)
type wallet_options = {
  disable_private_keys : bool;
  blank : bool;
  passphrase : string option;
  avoid_reuse : bool;
  descriptors : bool;
  load_on_startup : bool option;
}

let default_wallet_options = {
  disable_private_keys = false;
  blank = false;
  passphrase = None;
  avoid_reuse = false;
  descriptors = true;
  load_on_startup = None;
}

(* Wallet manager state *)
type wallet_manager = {
  wallets : (string, t) Hashtbl.t;
  mutable wallets_dir : string;
  network : [`Mainnet | `Testnet | `Regtest];
}

(* Create a new wallet manager *)
let create_wallet_manager ~(wallets_dir : string) ~(network : [`Mainnet | `Testnet | `Regtest]) : wallet_manager =
  if not (Sys.file_exists wallets_dir) then
    Unix.mkdir wallets_dir 0o755;
  { wallets = Hashtbl.create 16;
    wallets_dir;
    network }

(* Get wallet file path from name *)
let wallet_path (wm : wallet_manager) (name : string) : string =
  if name = "" then
    Filename.concat wm.wallets_dir "wallet.dat"
  else
    Filename.concat wm.wallets_dir name

(* Flush wallet state to disk.
   For encrypted wallets, only save when unlocked (keys are accessible)
   to avoid writing zeroed-out private keys. *)
let flush (w : t) : unit =
  if w.db_path <> "" then
    if w.encryption.encrypted then begin
      match w.encryption.lock_state with
      | Unlocked { master_key; _ } when Cstruct.length master_key > 0 ->
        save w
      | _ ->
        ()
    end else
      save w

(* Load a wallet by name *)
let load_wallet (wm : wallet_manager) (name : string) : (t, string) result =
  let path = wallet_path wm name in
  if Hashtbl.mem wm.wallets name then
    Error (Printf.sprintf "Wallet \"%s\" is already loaded" name)
  else if not (Sys.file_exists path) then
    Error (Printf.sprintf "Wallet \"%s\" not found at %s" name path)
  else begin
    let wallet = load ~network:wm.network ~db_path:path in
    Hashtbl.replace wm.wallets name wallet;
    Ok wallet
  end

(* Load an encrypted wallet by name with passphrase *)
let load_wallet_encrypted (wm : wallet_manager) (name : string) ~(passphrase : string)
    : (t, string) result =
  let path = wallet_path wm name in
  if Hashtbl.mem wm.wallets name then
    Error (Printf.sprintf "Wallet \"%s\" is already loaded" name)
  else if not (Sys.file_exists path) then
    Error (Printf.sprintf "Wallet \"%s\" not found at %s" name path)
  else
    match load_encrypted ~network:wm.network ~db_path:path ~passphrase with
    | Ok wallet ->
      Hashtbl.replace wm.wallets name wallet;
      Ok wallet
    | Error e -> Error e

(* Unload a wallet by name *)
let unload_wallet (wm : wallet_manager) (name : string) : (unit, string) result =
  match Hashtbl.find_opt wm.wallets name with
  | None ->
    Error (Printf.sprintf "Wallet \"%s\" is not loaded" name)
  | Some wallet ->
    flush wallet;
    Hashtbl.remove wm.wallets name;
    Ok ()

(* Create a new wallet *)
let create_wallet (wm : wallet_manager) (name : string) ?(options = default_wallet_options) ()
    : (t, string) result =
  let path = wallet_path wm name in
  if Hashtbl.mem wm.wallets name then
    Error (Printf.sprintf "Wallet \"%s\" is already loaded" name)
  else if Sys.file_exists path then
    Error (Printf.sprintf "Wallet \"%s\" already exists" name)
  else begin
    let wallet = create ~network:wm.network ~db_path:path in
    (* Initialize with HD seed unless blank *)
    if not options.blank && not options.disable_private_keys then begin
      let mnemonic = Bip39.generate_mnemonic ~strength:128 () in
      init_from_mnemonic wallet mnemonic ()
    end;
    (* Save to disk *)
    (match options.passphrase with
     | Some pass when pass <> "" -> save_encrypted wallet ~passphrase:pass
     | _ -> save wallet);
    (* Register in manager *)
    Hashtbl.replace wm.wallets name wallet;
    Ok wallet
  end

(* Get a wallet by name *)
let get_wallet (wm : wallet_manager) (name : string) : t option =
  Hashtbl.find_opt wm.wallets name

(* Get the default wallet (empty name) *)
let get_default_wallet (wm : wallet_manager) : t option =
  Hashtbl.find_opt wm.wallets ""

(* List all loaded wallet names *)
let list_wallets (wm : wallet_manager) : string list =
  Hashtbl.fold (fun name _ acc -> name :: acc) wm.wallets []

(* Check if a wallet is loaded *)
let is_wallet_loaded (wm : wallet_manager) (name : string) : bool =
  Hashtbl.mem wm.wallets name

(* Get wallet info as JSON-like structure *)
type wallet_info = {
  wallet_name : string;
  wallet_version : int;
  format : string;
  tx_count : int;
  keypoolsize : int;
  balance : float;
  unconfirmed_balance : float;
  immature_balance : float;
  private_keys_enabled : bool;
  avoid_reuse : bool;
  scanning : bool;
  descriptors : bool;
  external_signer : bool;
}

let get_wallet_info (name : string) (w : t) : wallet_info =
  let confirmed, unconfirmed = get_balance w in
  { wallet_name = name;
    wallet_version = 169900;  (* Bitcoin Core 0.16.99 format *)
    format = "sqlite";
    tx_count = List.length w.tx_history;
    keypoolsize = List.length w.keys;
    balance = Int64.to_float confirmed /. 100_000_000.0;
    unconfirmed_balance = Int64.to_float unconfirmed /. 100_000_000.0;
    immature_balance = 0.0;  (* TODO: track immature coinbase *)
    (* Private keys enabled if wallet has master key or any non-empty private keys *)
    private_keys_enabled = (Option.is_some w.master_key) ||
      (w.keys <> [] && not (List.for_all (fun kp -> Cstruct.length kp.private_key = 0) w.keys));
    avoid_reuse = false;
    scanning = false;
    descriptors = true;
    external_signer = false;
  }

(* Shutdown wallet manager, flushing all wallets *)
let shutdown_wallet_manager (wm : wallet_manager) : unit =
  Hashtbl.iter (fun _name wallet -> flush wallet) wm.wallets;
  Hashtbl.clear wm.wallets

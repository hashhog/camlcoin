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

(* Insert an item at a random position in a list (for output order privacy) *)
let insert_at_random lst item =
  let n = List.length lst in
  let pos = Random.int (n + 1) in
  let rec aux i acc = function
    | [] -> List.rev (item :: acc)
    | x :: xs ->
      if i = pos then List.rev_append (item :: acc) (x :: xs)
      else aux (i + 1) (x :: acc) xs
  in aux 0 [] lst

(* ============================================================================
   Secp256k1 Helpers (shared with Crypto module)
   ============================================================================ *)

module Secp = Libsecp256k1.External

let secp_ctx = Secp.Context.create ~sign:true ~verify:true ()

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

(* Compute fingerprint of an extended key (first 4 bytes of hash160 of pubkey) *)
let fingerprint_of_key (ek : extended_key) : int32 =
  let pubkey = Crypto.derive_public_key ~compressed:true ek.key in
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

(* Derive a child key (BIP-32) *)
let derive_child_key (parent : extended_key) (index : int32) : (extended_key, string) result =
  let data =
    if Int32.compare index hardened_offset >= 0 then begin
      (* Hardened derivation: HMAC-SHA512(chain_code, 0x00 || key || index_be) *)
      Cstruct.concat [
        Cstruct.of_string "\x00";
        parent.key;
        int32_to_bytes index
      ]
    end else begin
      (* Normal derivation: HMAC-SHA512(chain_code, pubkey || index_be) *)
      let pubkey = Crypto.derive_public_key ~compressed:true parent.key in
      Cstruct.concat [
        pubkey;
        int32_to_bytes index
      ]
    end
  in
  let i = hmac_sha512 ~key:parent.chain_code data in
  let il = Cstruct.sub i 0 32 in
  let ir = Cstruct.sub i 32 32 in
  (* Child key = (parent_key + il) mod curve order.
     Use libsecp256k1's add_tweak which handles the mod order arithmetic. *)
  try
    let parent_sk_bs = cstruct_to_bigstring parent.key in
    let parent_sk = Secp.Key.read_sk_exn secp_ctx parent_sk_bs in
    let tweak_bs = cstruct_to_bigstring il in
    let child_sk = Secp.Key.add_tweak secp_ctx parent_sk tweak_bs in
    let child_key_bs = Secp.Key.to_bytes secp_ctx child_sk in
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
  (* Compressed public key *)
  let pubkey = Crypto.derive_public_key ~compressed:true ek.key in
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

(* Transaction history entry *)
type tx_history_entry = {
  hist_txid : string;
  hist_category : [`Send | `Receive];
  hist_amount : int64;
  hist_fee : int64;
  hist_address : string;
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
    } }

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
  let block_hash_hex = cstruct_to_hex block_hash in
  let block_timestamp = Int32.to_float block.header.timestamp in
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    let txid_hex = cstruct_to_hex txid in

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
        let wutxo = {
          outpoint = { txid; vout = Int32.of_int vout };
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
        w.balance_confirmed <- Int64.add w.balance_confirmed out.Types.value;
        (* Record receive history entry *)
        let hist_entry = {
          hist_txid = txid_hex;
          hist_category = `Receive;
          hist_amount = out.Types.value;
          hist_fee = 0L;
          hist_address = Address.address_to_string kp.address;
          hist_confirmations = 1;
          hist_block_hash = block_hash_hex;
          hist_block_height = height;
          hist_timestamp = block_timestamp;
        } in
        w.tx_history <- hist_entry :: w.tx_history
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
        w.balance_confirmed <-
          Int64.sub w.balance_confirmed wutxo.utxo.Utxo.value;
        (* Record send history entry *)
        let kp_opt = is_mine w wutxo.utxo.Utxo.script_pubkey in
        let addr_str = match kp_opt with
          | Some kp -> Address.address_to_string kp.address
          | None -> ""
        in
        let hist_entry = {
          hist_txid = txid_hex;
          hist_category = `Send;
          hist_amount = wutxo.utxo.Utxo.value;
          hist_fee = 0L;
          hist_address = addr_str;
          hist_confirmations = 1;
          hist_block_hash = block_hash_hex;
          hist_block_height = height;
          hist_timestamp = block_timestamp;
        } in
        w.tx_history <- hist_entry :: w.tx_history
      ) spent
    ) tx.Types.inputs
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

(* Fisher-Yates shuffle for random permutation *)
let shuffle_list (lst : 'a list) : 'a list =
  let arr = Array.of_list lst in
  let n = Array.length arr in
  for i = n - 1 downto 1 do
    let j = Random.int (i + 1) in
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

(* Branch and Bound coin selection (Gap 17).
   Attempts to find an exact-match selection avoiding change outputs.
   Returns None if no suitable selection is found within iteration limit. *)
let select_coins_bnb (utxos : wallet_utxo list) (target : int64)
    (cost_of_change : int64) : wallet_utxo list option =
  (* Sort UTXOs by effective value descending *)
  let sorted = List.sort (fun a b ->
    Int64.compare b.utxo.Utxo.value a.utxo.Utxo.value
  ) utxos in
  let arr = Array.of_list sorted in
  let n = Array.length arr in
  if n = 0 then None
  else begin
    let max_iterations = 100_000 in
    let iterations = ref 0 in
    let best = ref None in
    let upper = Int64.add target cost_of_change in

    (* Precompute suffix sums: suffix.(i) = sum of values from index i to n-1 *)
    let suffix = Array.make (n + 1) 0L in
    for i = n - 1 downto 0 do
      suffix.(i) <- Int64.add suffix.(i + 1) arr.(i).utxo.Utxo.value
    done;

    (* DFS with backtracking *)
    let rec search idx current_sum selection =
      if !iterations >= max_iterations then ()
      else begin
        incr iterations;
        (* Check if current sum is in acceptable range *)
        if Int64.compare current_sum target >= 0 &&
           Int64.compare current_sum upper <= 0 then
          best := Some (List.rev selection)
        else if idx >= n then
          ()  (* No more UTXOs to consider *)
        else if Int64.compare current_sum upper > 0 then
          ()  (* Exceeded upper bound, prune *)
        else if Int64.compare (Int64.add current_sum suffix.(idx)) target < 0 then
          ()  (* Even taking all remaining can't reach target, prune *)
        else begin
          (* Include current UTXO *)
          let value = arr.(idx).utxo.Utxo.value in
          search (idx + 1) (Int64.add current_sum value)
            (arr.(idx) :: selection);
          (* Exclude current UTXO (only if we haven't found a solution) *)
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
    : (coin_selection, string) result =
  (* Sort by value descending *)
  let available = List.sort (fun a b ->
    Int64.compare b.utxo.Utxo.value a.utxo.Utxo.value
  ) w.utxos in

  (* Filter only confirmed UTXOs for safety *)
  let available = List.filter (fun u -> u.confirmed) available in

  (* Estimate fee for a typical transaction (start with 1 input, 2 outputs) *)
  let estimated_tx_weight = estimate_tx_weight 1 2 in
  let estimated_fee = Int64.of_float
    (fee_rate *. float_of_int estimated_tx_weight /. 4.0) in
  let target_with_fee = Int64.add target estimated_fee in

  (* Cost of change: ~34 bytes for change output + ~68 bytes for spending it *)
  let cost_of_change = Int64.of_float
    (fee_rate *. float_of_int (34 + 68) /. 1.0) in

  (* Try BnB first for exact-match selection (no change output) *)
  match select_coins_bnb available target_with_fee cost_of_change with
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
  match select_coins_bnb available target_with_fee cost_of_change with
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
    (* P2TR change: use x-only pubkey (drop first byte of compressed key) *)
    let xonly = Cstruct.sub change_pubkey 1 32 in
    build_p2tr_script xonly
  | Script.P2PKH_script _ ->
    let change_hash = Crypto.hash160 change_pubkey in
    build_p2pkh_script change_hash
  | _ ->
    (* Default to P2WPKH for P2WPKH, P2WSH, and other types *)
    let change_hash = Crypto.hash160 change_pubkey in
    build_p2wpkh_script change_hash

(* Sign a transaction's inputs given the selected UTXOs *)
let sign_transaction_inputs (w : t) (tx : Types.transaction)
    (input_utxos : wallet_utxo list) : Types.transaction =
  let signed_inputs_and_witnesses = List.mapi (fun i wutxo ->
    let kp = match is_mine w wutxo.utxo.Utxo.script_pubkey with
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
    | _ ->
      failwith "sign_transaction_inputs: unsupported script type"
  ) input_utxos in
  let inputs = List.map fst signed_inputs_and_witnesses in
  let witnesses = List.map snd signed_inputs_and_witnesses in
  { tx with inputs; witnesses }

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
    (* Select coins *)
    match select_coins w amount fee_rate with
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

      (* Build unsigned transaction inputs *)
      let inputs = List.map (fun wutxo ->
        { Types.previous_output = wutxo.outpoint;
          script_sig = Cstruct.create 0;  (* Empty for segwit *)
          sequence = 0xFFFFFFFEl; }
      ) selection.selected in

      (* Anti-fee-sniping locktime *)
      let locktime = match tip_height with
        | Some h ->
          if Random.int 10 = 0 then Int32.of_int (max 0 (h - 1))
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
      let hist_entry = {
        hist_txid = txid_hex;
        hist_category = `Send;
        hist_amount = amount;
        hist_fee = fee;
        hist_address = dest_address;
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

  (* Select coins *)
  match select_coins w total_amount fee_rate with
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

    (* Anti-fee-sniping locktime *)
    let locktime = match tip_height with
      | Some h ->
        if Random.int 10 = 0 then Int32.of_int (max 0 (h - 1))
        else Int32.of_int h
      | None -> 0l
    in

    (* Build and sign transaction *)
    let inputs = List.map (fun wutxo ->
      { Types.previous_output = wutxo.outpoint;
        script_sig = Cstruct.create 0;
        sequence = 0xFFFFFFFEl; }
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
      let hist_entry = {
        hist_txid = txid_hex;
        hist_category = `Send;
        hist_amount = amt;
        hist_fee = fee;
        hist_address = addr_str;
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
    (* Compute original total input value by looking up UTXOs *)
    let orig_input_total = List.fold_left (fun acc inp ->
      let prev = inp.Types.previous_output in
      (* Look for the UTXO in our wallet or use 0 if spent *)
      let value = List.fold_left (fun v wutxo ->
        if Cstruct.equal wutxo.outpoint.txid prev.txid &&
           wutxo.outpoint.vout = prev.vout then
          wutxo.utxo.Utxo.value
        else v
      ) 0L w.utxos in
      (* If not in current UTXOs, the original tx must track it.
         Compute from outputs + original fee *)
      Int64.add acc value
    ) 0L orig_tx.Types.inputs in

    let orig_output_total = List.fold_left (fun acc out ->
      Int64.add acc out.Types.value
    ) 0L orig_tx.Types.outputs in

    (* If we couldn't find the inputs (already spent by original tx), compute
       original fee from output structure. We need to reconstruct input value. *)
    let orig_input_value =
      if orig_input_total = 0L then
        (* Estimate: we can't know exact input value without full UTXO set.
           Use output total + estimated old fee *)
        let old_weight = estimate_tx_weight
          (List.length orig_tx.inputs) (List.length orig_tx.outputs) in
        let old_est_fee = Int64.of_float (1.0 *. float_of_int old_weight /. 4.0) in
        Int64.add orig_output_total old_est_fee
      else
        orig_input_total
    in

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
           For original inputs, find UTXOs from wallet. *)
        let orig_utxos = List.filter_map (fun inp ->
          let prev = inp.Types.previous_output in
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
      ("category", `String (match h.hist_category with `Send -> "send" | `Receive -> "receive"));
      ("amount", `String (Int64.to_string h.hist_amount));
      ("fee", `String (Int64.to_string h.hist_fee));
      ("address", `String h.hist_address);
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
      ("category", `String (match h.hist_category with `Send -> "send" | `Receive -> "receive"));
      ("amount", `String (Int64.to_string h.hist_amount));
      ("fee", `String (Int64.to_string h.hist_fee));
      ("address", `String h.hist_address);
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
             | Some (`String "send") -> `Send | _ -> `Receive in
           let hist_amount = match List.assoc_opt "amount" ef with
             | Some (`String s) -> Int64.of_string s | _ -> 0L in
           let hist_fee = match List.assoc_opt "fee" ef with
             | Some (`String s) -> Int64.of_string s | _ -> 0L in
           let hist_address = match List.assoc_opt "address" ef with
             | Some (`String s) -> s | _ -> "" in
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
             hist_address; hist_confirmations; hist_block_hash;
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

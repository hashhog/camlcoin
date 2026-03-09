(* Wallet - HD key management and transaction signing

   This module provides basic wallet functionality:
   - Key generation and storage
   - Address derivation
   - UTXO tracking for wallet addresses
   - Transaction creation and signing

   NOTE: This is a minimal implementation. A full wallet would include:
   - BIP-32/39/44 HD key derivation
   - Encrypted key storage
   - Watch-only addresses
   - Multi-signature support *)

(* ============================================================================
   Wallet Types
   ============================================================================ *)

(* A keypair for signing *)
type keypair = {
  privkey : Crypto.private_key;
  pubkey : Crypto.public_key;
  pubkey_hash : Types.hash160;
  address : string;
}

(* Wallet state *)
type t = {
  mutable keys : keypair list;
  mutable current_index : int;
  network : Consensus.network_config;
}

(* ============================================================================
   Wallet Creation
   ============================================================================ *)

(* Create a new empty wallet *)
let create (network : Consensus.network_config) : t =
  { keys = [];
    current_index = 0;
    network }

(* ============================================================================
   Key Management
   ============================================================================ *)

(* Generate a new keypair and add to wallet *)
let generate_key (wallet : t) : keypair =
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key privkey in
  let pubkey_hash = Crypto.hash160 pubkey in
  let address = Address.encode_p2pkh wallet.network.pubkey_address_prefix pubkey_hash in
  let kp = { privkey; pubkey; pubkey_hash; address } in
  wallet.keys <- kp :: wallet.keys;
  wallet.current_index <- wallet.current_index + 1;
  kp

(* Get a new receiving address *)
let get_new_address (wallet : t) : string =
  let kp = generate_key wallet in
  kp.address

(* Get all addresses in the wallet *)
let get_addresses (wallet : t) : string list =
  List.map (fun kp -> kp.address) wallet.keys

(* Find keypair by address *)
let find_by_address (wallet : t) (address : string) : keypair option =
  List.find_opt (fun kp -> kp.address = address) wallet.keys

(* Find keypair by pubkey hash *)
let find_by_pubkey_hash (wallet : t) (pkh : Types.hash160) : keypair option =
  List.find_opt (fun kp -> Cstruct.equal kp.pubkey_hash pkh) wallet.keys

(* ============================================================================
   Import/Export
   ============================================================================ *)

(* Import a private key in WIF format *)
let import_wif (wallet : t) (wif : string) : (keypair, string) result =
  match Address.decode_wif wif with
  | Error e -> Error e
  | Ok (privkey, _compressed) ->
    let pubkey = Crypto.derive_public_key privkey in
    let pubkey_hash = Crypto.hash160 pubkey in
    let address = Address.encode_p2pkh wallet.network.pubkey_address_prefix pubkey_hash in
    let kp = { privkey; pubkey; pubkey_hash; address } in
    wallet.keys <- kp :: wallet.keys;
    Ok kp

(* Export a keypair to WIF format *)
let export_wif (wallet : t) (address : string) : string option =
  match find_by_address wallet address with
  | None -> None
  | Some kp ->
    Some (Address.encode_wif wallet.network.wif_prefix kp.privkey ~compressed:true)

(* ============================================================================
   Signing
   ============================================================================ *)

(* Sign a message hash with a specific keypair *)
let sign_hash (kp : keypair) (hash : Types.hash256) : Crypto.signature =
  Crypto.sign kp.privkey hash

(* Check if wallet can sign for a pubkey hash *)
let can_sign (wallet : t) (pkh : Types.hash160) : bool =
  Option.is_some (find_by_pubkey_hash wallet pkh)

(* ============================================================================
   Wallet Info
   ============================================================================ *)

(* Get the number of keys in the wallet *)
let key_count (wallet : t) : int =
  List.length wallet.keys

(* Check if wallet is empty *)
let is_empty (wallet : t) : bool =
  wallet.keys = []

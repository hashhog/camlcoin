(* Wallet - HD key management, UTXO tracking, and transaction signing

   This module provides wallet functionality:
   - Key generation and storage
   - Address derivation (P2WPKH native SegWit)
   - UTXO tracking for wallet addresses
   - Coin selection and transaction creation
   - Transaction signing (BIP-143 SegWit sighash)
   - Wallet persistence to JSON

   NOTE: This is a minimal implementation. A full wallet would include:
   - BIP-32/39/44 HD key derivation from mnemonic
   - Encrypted key storage
   - Watch-only addresses
   - Multi-signature support *)

(* ============================================================================
   Wallet Types
   ============================================================================ *)

(* A keypair for signing *)
type key_pair = {
  private_key : Crypto.private_key;
  public_key : Crypto.public_key;
  address : Address.address;
}

(* UTXO tracked by wallet *)
type wallet_utxo = {
  outpoint : Types.outpoint;
  utxo : Utxo.utxo_entry;
  key_index : int;
  confirmed : bool;
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
    db_path }

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

(* Generate a new keypair and add to wallet *)
let generate_key (w : t) : key_pair =
  let private_key = Crypto.generate_private_key () in
  let public_key = Crypto.derive_public_key ~compressed:true private_key in
  let address = Address.of_pubkey ~network:w.network Address.P2WPKH public_key in
  let kp = { private_key; public_key; address } in
  w.keys <- w.keys @ [kp];
  w.next_key_index <- w.next_key_index + 1;
  kp

(* Get a new receiving address *)
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
let import_wif (w : t) (wif : string) : (key_pair, string) result =
  match Address.wif_decode wif with
  | Error e -> Error e
  | Ok (private_key, _compressed, _network) ->
    let public_key = Crypto.derive_public_key ~compressed:true private_key in
    let address = Address.of_pubkey ~network:w.network Address.P2WPKH public_key in
    let kp = { private_key; public_key; address } in
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

(* Scan a block for wallet-relevant transactions *)
let scan_block (w : t) (block : Types.block) (height : int) : unit =
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in

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
        w.balance_confirmed <- Int64.add w.balance_confirmed out.Types.value
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
        w.utxos <- List.filter (fun u -> u != wutxo) w.utxos;
        w.balance_confirmed <-
          Int64.sub w.balance_confirmed wutxo.utxo.Utxo.value
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
      w.utxos <- List.filter (fun u -> u != wutxo) w.utxos;
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

(* Select coins to meet target amount using greedy largest-first *)
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

  (* Greedy selection: pick largest UTXOs first *)
  let selected = ref [] in
  let total = ref 0L in

  List.iter (fun wutxo ->
    if Int64.compare !total target_with_fee < 0 then begin
      selected := wutxo :: !selected;
      total := Int64.add !total wutxo.utxo.Utxo.value
    end
  ) available;

  if Int64.compare !total target_with_fee < 0 then
    Error (Printf.sprintf
      "Insufficient funds: have %Ld satoshis, need %Ld"
      !total target_with_fee)
  else begin
    (* Recalculate fee with actual number of inputs *)
    let n_inputs = List.length !selected in
    let actual_weight = estimate_tx_weight n_inputs 2 in
    let actual_fee = Int64.of_float
      (fee_rate *. float_of_int actual_weight /. 4.0) in
    let change = Int64.sub !total (Int64.add target actual_fee) in
    Ok {
      selected = List.rev !selected;
      total_input = !total;
      change;
    }
  end

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

(* Create and sign a transaction *)
let create_transaction (w : t) ~(dest_address : string)
    ~(amount : int64) ~(fee_rate : float)
    : (Types.transaction, string) result =

  (* Parse destination address *)
  match Address.address_of_string dest_address with
  | Error e -> Error e
  | Ok dest_addr ->
    (* Select coins *)
    match select_coins w amount fee_rate with
    | Error e -> Error e
    | Ok selection ->
      (* Build destination output script *)
      let dest_script = match dest_addr.Address.addr_type with
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
      in

      (* Build outputs *)
      let outputs = ref [
        { Types.value = amount; script_pubkey = dest_script }
      ] in

      (* Add change output if significant *)
      if selection.change > dust_threshold then begin
        let change_kp = generate_key w in
        let change_hash = Crypto.hash160 change_kp.public_key in
        let change_script = build_p2wpkh_script change_hash in
        outputs := !outputs @ [
          { Types.value = selection.change; script_pubkey = change_script }
        ]
      end;

      (* Build unsigned transaction inputs *)
      let inputs = List.map (fun wutxo ->
        { Types.previous_output = wutxo.outpoint;
          script_sig = Cstruct.create 0;  (* Empty for segwit *)
          sequence = 0xFFFFFFFEl; }
      ) selection.selected in

      (* Create unsigned transaction *)
      let tx : Types.transaction = {
        version = 2l;
        inputs;
        outputs = !outputs;
        witnesses = [];
        locktime = 0l;
      } in

      (* Sign each input (BIP-143 segwit sighash for P2WPKH) *)
      let witnesses = List.mapi (fun i wutxo ->
        (* Find the key for this input *)
        let kp = match is_mine w wutxo.utxo.Utxo.script_pubkey with
          | Some kp -> kp
          | None -> failwith "Cannot find key for input"
        in

        (* Build implicit P2PKH script code for BIP-143 *)
        let pubkey_hash = Crypto.hash160 kp.public_key in
        let script_code = build_p2pkh_script pubkey_hash in

        (* Compute BIP-143 sighash *)
        let sighash = Script.compute_sighash_segwit
          tx i script_code wutxo.utxo.Utxo.value
          Script.sighash_all in

        (* Sign *)
        let signature = Crypto.sign kp.private_key sighash in

        (* Append SIGHASH_ALL byte *)
        let sig_with_hashtype = Cstruct.concat [
          signature;
          Cstruct.of_string "\x01"
        ] in

        (* Witness: [signature, pubkey] *)
        { Types.items = [sig_with_hashtype; kp.public_key] }
      ) selection.selected in

      Ok { tx with witnesses }

(* Create a transaction with multiple outputs *)
let create_transaction_multi (w : t)
    ~(outputs : (string * int64) list) ~(fee_rate : float)
    : (Types.transaction, string) result =

  (* Calculate total amount needed *)
  let total_amount = List.fold_left (fun acc (_, amt) ->
    Int64.add acc amt
  ) 0L outputs in

  (* Parse all destination addresses and build scripts *)
  let parsed_outputs = List.map (fun (addr_str, amount) ->
    match Address.address_of_string addr_str with
    | Error e -> failwith e
    | Ok dest_addr ->
      let script = match dest_addr.Address.addr_type with
        | Address.P2WPKH -> build_p2wpkh_script dest_addr.Address.hash
        | Address.P2PKH -> build_p2pkh_script dest_addr.Address.hash
        | Address.P2TR -> build_p2tr_script dest_addr.Address.hash
        | Address.P2WSH ->
          let s = Cstruct.create 34 in
          Cstruct.set_uint8 s 0 0x00;
          Cstruct.set_uint8 s 1 0x20;
          Cstruct.blit dest_addr.Address.hash 0 s 2 32;
          s
        | Address.P2SH ->
          let s = Cstruct.create 23 in
          Cstruct.set_uint8 s 0 0xa9;
          Cstruct.set_uint8 s 1 0x14;
          Cstruct.blit dest_addr.Address.hash 0 s 2 20;
          Cstruct.set_uint8 s 22 0x87;
          s
      in
      { Types.value = amount; script_pubkey = script }
  ) outputs in

  (* Select coins *)
  match select_coins w total_amount fee_rate with
  | Error e -> Error e
  | Ok selection ->
    (* Build all outputs including change *)
    let tx_outputs = ref parsed_outputs in

    if selection.change > dust_threshold then begin
      let change_kp = generate_key w in
      let change_hash = Crypto.hash160 change_kp.public_key in
      let change_script = build_p2wpkh_script change_hash in
      tx_outputs := !tx_outputs @ [
        { Types.value = selection.change; script_pubkey = change_script }
      ]
    end;

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
      locktime = 0l;
    } in

    let witnesses = List.mapi (fun i wutxo ->
      let kp = match is_mine w wutxo.utxo.Utxo.script_pubkey with
        | Some kp -> kp
        | None -> failwith "Cannot find key for input"
      in
      let pubkey_hash = Crypto.hash160 kp.public_key in
      let script_code = build_p2pkh_script pubkey_hash in
      let sighash = Script.compute_sighash_segwit
        tx i script_code wutxo.utxo.Utxo.value Script.sighash_all in
      let signature = Crypto.sign kp.private_key sighash in
      let sig_with_hashtype = Cstruct.concat [
        signature; Cstruct.of_string "\x01"
      ] in
      { Types.items = [sig_with_hashtype; kp.public_key] }
    ) selection.selected in

    Ok { tx with witnesses }

(* ============================================================================
   Wallet Persistence
   ============================================================================ *)

(* Convert Cstruct to hex string *)
let cstruct_to_hex (cs : Cstruct.t) : string =
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Convert hex string to Cstruct *)
let hex_to_cstruct (s : string) : Cstruct.t =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* Save wallet to file *)
let save (w : t) : unit =
  let keys_json = List.map (fun kp ->
    `Assoc [
      ("private_key", `String (cstruct_to_hex kp.private_key));
      ("address", `String (Address.address_to_string kp.address));
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
  ] in

  let oc = open_out w.db_path in
  output_string oc (Yojson.Safe.to_string json);
  close_out oc

(* Load wallet from file *)
let load ~(network : [`Mainnet | `Testnet | `Regtest])
    ~(db_path : string) : t =
  if Sys.file_exists db_path then begin
    let ic = open_in db_path in
    let len = in_channel_length ic in
    let data = really_input_string ic len in
    close_in ic;

    let json = Yojson.Safe.from_string data in
    let w = create ~network ~db_path in

    (match json with
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
                 let address = Address.of_pubkey
                   ~network Address.P2WPKH public_key in
                 w.keys <- w.keys @ [{ private_key; public_key; address }]
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

       (* Load other fields *)
       (match List.assoc_opt "next_key_index" fields with
        | Some (`Int n) -> w.next_key_index <- n
        | _ -> ());
       (match List.assoc_opt "balance_confirmed" fields with
        | Some (`String v) -> w.balance_confirmed <- Int64.of_string v
        | _ -> ());
       (match List.assoc_opt "balance_unconfirmed" fields with
        | Some (`String v) -> w.balance_unconfirmed <- Int64.of_string v
        | _ -> ())
     | _ -> ());
    w
  end else
    create ~network ~db_path

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

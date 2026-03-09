(* Tests for wallet functionality *)

open Camlcoin

(* Helper to convert hex string to Cstruct *)
let hex_to_cstruct s =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* ============================================================================
   Wallet Creation Tests
   ============================================================================ *)

let test_create_wallet () =
  let w = Wallet.create ~network:`Regtest ~db_path:"/tmp/test_wallet.json" in
  Alcotest.(check bool) "wallet is empty" true (Wallet.is_empty w);
  Alcotest.(check int) "no keys" 0 (Wallet.key_count w);
  Alcotest.(check int) "no utxos" 0 (Wallet.utxo_count w);
  let (confirmed, unconfirmed) = Wallet.get_balance w in
  Alcotest.(check int64) "confirmed balance" 0L confirmed;
  Alcotest.(check int64) "unconfirmed balance" 0L unconfirmed

(* ============================================================================
   Key Management Tests
   ============================================================================ *)

let test_generate_key () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  Alcotest.(check bool) "wallet not empty" false (Wallet.is_empty w);
  Alcotest.(check int) "one key" 1 (Wallet.key_count w);
  (* Verify key has correct components *)
  Alcotest.(check int) "private key 32 bytes" 32 (Cstruct.length kp.Wallet.private_key);
  Alcotest.(check int) "public key 33 bytes" 33 (Cstruct.length kp.Wallet.public_key);
  (* Compressed pubkey starts with 02 or 03 *)
  let prefix = Cstruct.get_uint8 kp.public_key 0 in
  Alcotest.(check bool) "compressed pubkey prefix" true (prefix = 0x02 || prefix = 0x03)

let test_get_new_address () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let addr = Wallet.get_new_address w in
  (* Regtest P2WPKH addresses start with "bcrt1q" *)
  Alcotest.(check bool) "regtest bech32 prefix" true (String.sub addr 0 5 = "bcrt1");
  Alcotest.(check int) "one key after address" 1 (Wallet.key_count w)

let test_get_new_address_mainnet () =
  let w = Wallet.create ~network:`Mainnet ~db_path:"" in
  let addr = Wallet.get_new_address w in
  (* Mainnet P2WPKH addresses start with "bc1q" *)
  Alcotest.(check bool) "mainnet bech32 prefix" true (String.sub addr 0 3 = "bc1")

let test_get_new_address_testnet () =
  let w = Wallet.create ~network:`Testnet ~db_path:"" in
  let addr = Wallet.get_new_address w in
  (* Testnet P2WPKH addresses start with "tb1q" *)
  Alcotest.(check bool) "testnet bech32 prefix" true (String.sub addr 0 3 = "tb1")

let test_get_all_addresses () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let _ = Wallet.get_new_address w in
  let _ = Wallet.get_new_address w in
  let _ = Wallet.get_new_address w in
  let addrs = Wallet.get_all_addresses w in
  Alcotest.(check int) "three addresses" 3 (List.length addrs);
  (* All should be unique *)
  let unique = List.sort_uniq String.compare addrs in
  Alcotest.(check int) "all unique" 3 (List.length unique)

let test_find_by_address () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let addr = Wallet.get_new_address w in
  let found = Wallet.find_by_address w addr in
  Alcotest.(check bool) "found key" true (Option.is_some found);
  let not_found = Wallet.find_by_address w "bcrt1qnotexist" in
  Alcotest.(check bool) "not found" true (Option.is_none not_found)

let test_find_by_pubkey_hash () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  let found = Wallet.find_by_pubkey_hash w pkh in
  Alcotest.(check bool) "found by pkh" true (Option.is_some found)

(* ============================================================================
   WIF Import/Export Tests
   ============================================================================ *)

let test_export_wif () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let addr = Wallet.get_new_address w in
  let wif_opt = Wallet.export_wif w addr in
  Alcotest.(check bool) "got wif" true (Option.is_some wif_opt);
  let wif = Option.get wif_opt in
  (* Regtest WIF starts with c (compressed) *)
  Alcotest.(check bool) "wif prefix" true (wif.[0] = 'c')

let test_import_wif () =
  (* Create wallet and export a key *)
  let w1 = Wallet.create ~network:`Regtest ~db_path:"" in
  let addr1 = Wallet.get_new_address w1 in
  let wif = Option.get (Wallet.export_wif w1 addr1) in
  (* Import into new wallet *)
  let w2 = Wallet.create ~network:`Regtest ~db_path:"" in
  match Wallet.import_wif w2 wif with
  | Error e -> Alcotest.fail ("import failed: " ^ e)
  | Ok kp ->
    (* Should have same public key *)
    let kp1 = Option.get (Wallet.find_by_address w1 addr1) in
    Alcotest.(check bool) "same pubkey" true
      (Cstruct.equal kp.Wallet.public_key kp1.Wallet.public_key)

(* ============================================================================
   is_mine Tests
   ============================================================================ *)

let test_is_mine_p2wpkh () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  (* Build P2WPKH script: OP_0 <20 bytes> *)
  let script = Cstruct.create 22 in
  Cstruct.set_uint8 script 0 0x00;
  Cstruct.set_uint8 script 1 0x14;
  Cstruct.blit pkh 0 script 2 20;
  let result = Wallet.is_mine w script in
  Alcotest.(check bool) "is_mine returns Some" true (Option.is_some result)

let test_is_mine_p2pkh () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  (* Build P2PKH script: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG *)
  let script = Cstruct.create 25 in
  Cstruct.set_uint8 script 0 0x76;
  Cstruct.set_uint8 script 1 0xa9;
  Cstruct.set_uint8 script 2 0x14;
  Cstruct.blit pkh 0 script 3 20;
  Cstruct.set_uint8 script 23 0x88;
  Cstruct.set_uint8 script 24 0xac;
  let result = Wallet.is_mine w script in
  Alcotest.(check bool) "is_mine P2PKH" true (Option.is_some result)

let test_is_mine_unknown () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let _ = Wallet.generate_key w in
  (* Random script *)
  let script = Cstruct.of_string "random script" in
  let result = Wallet.is_mine w script in
  Alcotest.(check bool) "is_mine unknown" true (Option.is_none result)

(* ============================================================================
   UTXO Scanning Tests
   ============================================================================ *)

(* Helper to create a simple P2WPKH script *)
let make_p2wpkh_script (pkh : Cstruct.t) : Cstruct.t =
  let script = Cstruct.create 22 in
  Cstruct.set_uint8 script 0 0x00;
  Cstruct.set_uint8 script 1 0x14;
  Cstruct.blit pkh 0 script 2 20;
  script

(* Helper to create a mock transaction *)
let make_mock_tx ~(outputs : Types.tx_out list)
    ~(is_coinbase : bool) : Types.transaction =
  let inputs = if is_coinbase then
    [{ Types.previous_output = { txid = Types.zero_hash; vout = 0xFFFFFFFFl };
       script_sig = Cstruct.of_string "coinbase";
       sequence = 0xFFFFFFFFl }]
  else
    [{ Types.previous_output = {
         txid = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000001";
         vout = 0l };
       script_sig = Cstruct.create 0;
       sequence = 0xFFFFFFFEl }]
  in
  { Types.version = 2l;
    inputs;
    outputs;
    witnesses = [];
    locktime = 0l }

let test_scan_block_add_utxo () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  let script = make_p2wpkh_script pkh in
  let output = { Types.value = 100_000L; script_pubkey = script } in
  let tx = make_mock_tx ~outputs:[output] ~is_coinbase:true in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0l;
      nonce = 0l
    };
    transactions = [tx]
  } in
  Wallet.scan_block w block 1;
  Alcotest.(check int) "one utxo" 1 (Wallet.utxo_count w);
  let (confirmed, _) = Wallet.get_balance w in
  Alcotest.(check int64) "balance 100000" 100_000L confirmed

let test_scan_block_skip_others () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let _ = Wallet.generate_key w in
  (* Output to different address *)
  let other_pkh = hex_to_cstruct "0000000000000000000000000000000000000000" in
  let script = make_p2wpkh_script other_pkh in
  let output = { Types.value = 100_000L; script_pubkey = script } in
  let tx = make_mock_tx ~outputs:[output] ~is_coinbase:true in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0l;
      nonce = 0l
    };
    transactions = [tx]
  } in
  Wallet.scan_block w block 1;
  Alcotest.(check int) "no utxos" 0 (Wallet.utxo_count w);
  let (confirmed, _) = Wallet.get_balance w in
  Alcotest.(check int64) "balance 0" 0L confirmed

let test_recalculate_balance () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  let script = make_p2wpkh_script pkh in
  let output = { Types.value = 50_000L; script_pubkey = script } in
  let tx = make_mock_tx ~outputs:[output] ~is_coinbase:true in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0l;
      nonce = 0l
    };
    transactions = [tx]
  } in
  Wallet.scan_block w block 1;
  (* Mess up the balance *)
  let w_copy = w in
  let _ = w_copy.balance_confirmed <- 0L in
  Wallet.recalculate_balance w;
  let (confirmed, _) = Wallet.get_balance w in
  Alcotest.(check int64) "recalculated balance" 50_000L confirmed

(* ============================================================================
   Coin Selection Tests
   ============================================================================ *)

let test_coin_selection_simple () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  let script = make_p2wpkh_script pkh in
  (* Add a UTXO *)
  let output = { Types.value = 100_000L; script_pubkey = script } in
  let tx = make_mock_tx ~outputs:[output] ~is_coinbase:true in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0l;
      nonce = 0l
    };
    transactions = [tx]
  } in
  Wallet.scan_block w block 100; (* Height 100 for coinbase maturity *)
  (* Select coins for 10000 sats *)
  match Wallet.select_coins w 10_000L 1.0 with
  | Error e -> Alcotest.fail ("selection failed: " ^ e)
  | Ok sel ->
    Alcotest.(check int) "one input selected" 1 (List.length sel.selected);
    Alcotest.(check int64) "total input" 100_000L sel.total_input;
    Alcotest.(check bool) "has change" true (sel.change > 0L)

let test_coin_selection_insufficient () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  let script = make_p2wpkh_script pkh in
  (* Add a small UTXO *)
  let output = { Types.value = 1_000L; script_pubkey = script } in
  let tx = make_mock_tx ~outputs:[output] ~is_coinbase:true in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0l;
      nonce = 0l
    };
    transactions = [tx]
  } in
  Wallet.scan_block w block 100;
  (* Try to select for more than we have *)
  match Wallet.select_coins w 1_000_000L 1.0 with
  | Ok _ -> Alcotest.fail "should have failed"
  | Error e ->
    Alcotest.(check bool) "insufficient funds error" true
      (String.length e > 0)

(* ============================================================================
   Transaction Creation Tests
   ============================================================================ *)

let test_create_transaction () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  let script = make_p2wpkh_script pkh in
  (* Add funds *)
  let output = { Types.value = 1_000_000L; script_pubkey = script } in
  let tx = make_mock_tx ~outputs:[output] ~is_coinbase:true in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0l;
      nonce = 0l
    };
    transactions = [tx]
  } in
  Wallet.scan_block w block 100;
  (* Create transaction to another address *)
  let dest_addr = Wallet.get_new_address w in
  match Wallet.create_transaction w ~dest_address:dest_addr ~amount:100_000L ~fee_rate:1.0 with
  | Error e -> Alcotest.fail ("tx creation failed: " ^ e)
  | Ok created_tx ->
    Alcotest.(check int) "has inputs" 1 (List.length created_tx.inputs);
    Alcotest.(check bool) "has outputs" true (List.length created_tx.outputs >= 1);
    Alcotest.(check bool) "has witnesses" true (List.length created_tx.witnesses = 1);
    (* Witness should have 2 items: signature and pubkey *)
    let witness = List.hd created_tx.witnesses in
    Alcotest.(check int) "witness items" 2 (List.length witness.items)

let test_create_transaction_invalid_address () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.Wallet.public_key in
  let script = make_p2wpkh_script pkh in
  let output = { Types.value = 1_000_000L; script_pubkey = script } in
  let tx = make_mock_tx ~outputs:[output] ~is_coinbase:true in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0l;
      nonce = 0l
    };
    transactions = [tx]
  } in
  Wallet.scan_block w block 100;
  (* Try invalid address *)
  match Wallet.create_transaction w ~dest_address:"invalid" ~amount:100_000L ~fee_rate:1.0 with
  | Ok _ -> Alcotest.fail "should have failed"
  | Error _ -> ()

(* ============================================================================
   Wallet Persistence Tests
   ============================================================================ *)

let test_save_load_empty () =
  let path = "/tmp/test_wallet_empty.json" in
  (* Clean up *)
  if Sys.file_exists path then Sys.remove path;
  let w1 = Wallet.create ~network:`Regtest ~db_path:path in
  Wallet.save w1;
  let w2 = Wallet.load ~network:`Regtest ~db_path:path in
  Alcotest.(check bool) "loaded is empty" true (Wallet.is_empty w2);
  Sys.remove path

let test_save_load_with_keys () =
  let path = "/tmp/test_wallet_keys.json" in
  if Sys.file_exists path then Sys.remove path;
  let w1 = Wallet.create ~network:`Regtest ~db_path:path in
  let addr1 = Wallet.get_new_address w1 in
  let addr2 = Wallet.get_new_address w1 in
  Wallet.save w1;
  let w2 = Wallet.load ~network:`Regtest ~db_path:path in
  Alcotest.(check int) "loaded 2 keys" 2 (Wallet.key_count w2);
  let addrs = Wallet.get_all_addresses w2 in
  Alcotest.(check bool) "addr1 present" true (List.mem addr1 addrs);
  Alcotest.(check bool) "addr2 present" true (List.mem addr2 addrs);
  Sys.remove path

let test_load_nonexistent () =
  let path = "/tmp/test_wallet_nonexistent.json" in
  if Sys.file_exists path then Sys.remove path;
  let w = Wallet.load ~network:`Regtest ~db_path:path in
  Alcotest.(check bool) "new wallet is empty" true (Wallet.is_empty w)

(* ============================================================================
   Test Suite
   ============================================================================ *)

let creation_tests = [
  Alcotest.test_case "create wallet" `Quick test_create_wallet;
]

let key_management_tests = [
  Alcotest.test_case "generate key" `Quick test_generate_key;
  Alcotest.test_case "get new address" `Quick test_get_new_address;
  Alcotest.test_case "mainnet address" `Quick test_get_new_address_mainnet;
  Alcotest.test_case "testnet address" `Quick test_get_new_address_testnet;
  Alcotest.test_case "get all addresses" `Quick test_get_all_addresses;
  Alcotest.test_case "find by address" `Quick test_find_by_address;
  Alcotest.test_case "find by pubkey hash" `Quick test_find_by_pubkey_hash;
]

let wif_tests = [
  Alcotest.test_case "export wif" `Quick test_export_wif;
  Alcotest.test_case "import wif" `Quick test_import_wif;
]

let is_mine_tests = [
  Alcotest.test_case "is_mine P2WPKH" `Quick test_is_mine_p2wpkh;
  Alcotest.test_case "is_mine P2PKH" `Quick test_is_mine_p2pkh;
  Alcotest.test_case "is_mine unknown" `Quick test_is_mine_unknown;
]

let utxo_tests = [
  Alcotest.test_case "scan block add utxo" `Quick test_scan_block_add_utxo;
  Alcotest.test_case "scan block skip others" `Quick test_scan_block_skip_others;
  Alcotest.test_case "recalculate balance" `Quick test_recalculate_balance;
]

let coin_selection_tests = [
  Alcotest.test_case "simple selection" `Quick test_coin_selection_simple;
  Alcotest.test_case "insufficient funds" `Quick test_coin_selection_insufficient;
]

let tx_creation_tests = [
  Alcotest.test_case "create transaction" `Quick test_create_transaction;
  Alcotest.test_case "invalid address" `Quick test_create_transaction_invalid_address;
]

let persistence_tests = [
  Alcotest.test_case "save load empty" `Quick test_save_load_empty;
  Alcotest.test_case "save load with keys" `Quick test_save_load_with_keys;
  Alcotest.test_case "load nonexistent" `Quick test_load_nonexistent;
]

let () = Alcotest.run "test_wallet" [
  ("creation", creation_tests);
  ("key_management", key_management_tests);
  ("wif", wif_tests);
  ("is_mine", is_mine_tests);
  ("utxo", utxo_tests);
  ("coin_selection", coin_selection_tests);
  ("tx_creation", tx_creation_tests);
  ("persistence", persistence_tests);
]

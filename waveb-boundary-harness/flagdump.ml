let names = [
  ("P2SH",       Camlcoin.Consensus.script_verify_p2sh);
  ("DERSIG",     Camlcoin.Consensus.script_verify_dersig);
  ("NULLDUMMY",  Camlcoin.Consensus.script_verify_nulldummy);
  ("CLTV",       Camlcoin.Consensus.script_verify_checklocktimeverify);
  ("CSV",        Camlcoin.Consensus.script_verify_checksequenceverify);
  ("WITNESS",    Camlcoin.Consensus.script_verify_witness);
  ("TAPROOT",    Camlcoin.Consensus.script_verify_taproot);
]
let show f =
  let s = List.filter_map (fun (n,b) -> if f land b <> 0 then Some n else None) names in
  Printf.sprintf "0x%x [%s]" f (String.concat "|" s)

let open_c = Camlcoin.Consensus.get_block_script_flags
let h = Camlcoin.Types.hash256_of_hex
let z = Camlcoin.Types.zero_hash

let () =
  let bip16 = h "229c4fac88bab194eb08f1a528cc308ded2397f4f4eb6e75dc02000000000000" in
  let tap   = h "ad95e3a15ee5ffd585c5e81d44b56a981e842d5bc3140f000000000000000000" in
  let tn3   = h "05b132a4f74a8799a57a4202d0eeb09612cc08d295401f007c4530dd00000000" in
  let m = Camlcoin.Consensus.mainnet and t3 = Camlcoin.Consensus.testnet in
  Printf.printf "-- Core-expected values (Wave B fixture) --\n";
  Printf.printf "mainnet 170060 exception-hash : %s   (Core: 0x0)\n" (show (open_c ~block_hash:bip16 170060 m));
  Printf.printf "mainnet 692261 exception-hash : %s   (Core: 0xe15)\n" (show (open_c ~block_hash:tap 692261 m));
  Printf.printf "testnet3 514   exception-hash : %s   (Core: 0x0)\n" (show (open_c ~block_hash:tn3 514 t3));
  Printf.printf "\n-- no-exception controls at the same heights --\n";
  Printf.printf "mainnet 170060 zero-hash      : %s\n" (show (open_c ~block_hash:z 170060 m));
  Printf.printf "mainnet 692261 zero-hash      : %s\n" (show (open_c ~block_hash:z 692261 m));
  Printf.printf "testnet3 514   zero-hash      : %s\n" (show (open_c ~block_hash:z 514 t3));
  Printf.printf "\n-- replace-then-OR discriminator: exception hash at a LATER height --\n";
  Printf.printf "mainnet 800000 bip16-hash     : %s   (Core: 0x614)\n" (show (open_c ~block_hash:bip16 800000 m));
  Printf.printf "mainnet 800000 taproot-hash   : %s   (Core: 0xe15)\n" (show (open_c ~block_hash:tap 800000 m));
  Printf.printf "mainnet 800000 zero-hash      : %s   (Core: 0x20e15)\n" (show (open_c ~block_hash:z 800000 m));
  Printf.printf "\n-- base trio unconditional at every height --\n";
  List.iter (fun ht ->
    Printf.printf "mainnet %-8d zero-hash    : %s\n" ht (show (open_c ~block_hash:z ht m)))
    [0; 1; 170059; 170061; 481823; 709631];
  Printf.printf "\n-- byte-order negative control (display-order hashes must NOT fire) --\n";
  let rev s = let n = String.length s / 2 in
    String.concat "" (List.init n (fun i -> String.sub s ((n-1-i)*2) 2)) in
  let d16 = h (rev "229c4fac88bab194eb08f1a528cc308ded2397f4f4eb6e75dc02000000000000") in
  let dtp = h (rev "ad95e3a15ee5ffd585c5e81d44b56a981e842d5bc3140f000000000000000000") in
  Printf.printf "mainnet 800000 REVERSED bip16 : %s (must equal zero-hash)\n" (show (open_c ~block_hash:d16 800000 m));
  Printf.printf "mainnet 800000 REVERSED tap   : %s (must equal zero-hash)\n" (show (open_c ~block_hash:dtp 800000 m));
  Printf.printf "\n-- hash producer round-trip (internal LE order) --\n";
  Printf.printf "hash256_to_hex_display(table key 692261) = %s\n"
    (Camlcoin.Types.hash256_to_hex_display tap);
  Printf.printf "hash256_to_hex_display(table key 170060) = %s\n"
    (Camlcoin.Types.hash256_to_hex_display bip16)

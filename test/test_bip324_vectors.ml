(* BIP-324 ElligatorSwift / ECDH test vectors.

   Validates camlcoin's libsecp256k1 ellswift FFI (compute_ellswift_pubkey
   and compute_ecdh_secret in lib/p2p.ml) against the canonical test
   vectors shipped with libsecp256k1 itself
   (vendor/secp256k1/src/modules/ellswift/tests_impl.h, table
   `ellswift_xdh_tests_bip324`, 7 entries).

   For each vector we feed (priv_ours, ellswift_theirs, ellswift_ours,
   initiating) into compute_ecdh_secret and check the 32-byte output
   matches the expected BIP-324 shared secret byte-for-byte.

   We also exercise compute_ellswift_pubkey end-to-end by generating two
   keypairs locally, ElligatorSwift-encoding both pubkeys, and verifying
   that initiator-side and responder-side ECDH derivations agree. This
   proves that the encoding is decodable and that the party-byte
   handling matches BIP-324. *)

open Camlcoin

let hex_to_cs (h : string) : Cstruct.t =
  let len = String.length h / 2 in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub h (2 * i) 2) in
    Cstruct.set_uint8 cs i byte
  done;
  cs

let cs_to_hex (cs : Cstruct.t) : string =
  let buf = Buffer.create (2 * Cstruct.length cs) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* BIP-324 ECDH test vectors lifted from
   vendor/secp256k1/src/modules/ellswift/tests_impl.h, table
   `ellswift_xdh_tests_bip324`. Order: (priv_ours, ellswift_ours,
   ellswift_theirs, initiating, expected_shared_secret). *)
type bip324_vec = {
  priv_ours : string;
  ellswift_ours : string;
  ellswift_theirs : string;
  initiating : bool;
  shared : string;
}

let vectors : bip324_vec list = [
  { priv_ours       = "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7";
    ellswift_ours   = "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b";
    ellswift_theirs = "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5";
    initiating      = true;
    shared          = "c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592" };
  { priv_ours       = "1f9c581b35231838f0f17cf0c979835baccb7f3abbbb96ffcc318ab71e6e126f";
    ellswift_ours   = "a1855e10e94e00baa23041d916e259f7044e491da6171269694763f018c7e63693d29575dcb464ac816baa1be353ba12e3876cba7628bd0bd8e755e721eb0140";
    ellswift_theirs = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000";
    initiating      = false;
    shared          = "a0138f564f74d0ad70bc337dacc9d0bf1d2349364caf1188a1e6e8ddb3b7b184" };
  { priv_ours       = "0286c41cd30913db0fdff7a64ebda5c8e3e7cef10f2aebc00a7650443cf4c60d";
    ellswift_ours   = "d1ee8a93a01130cbf299249a258f94feb5f469e7d0f2f28f69ee5e9aa8f9b54a60f2c3ff2d023634ec7f4127a96cc11662e402894cf1f694fb9a7eaa5f1d9244";
    ellswift_theirs = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff22d5e441524d571a52b3def126189d3f416890a99d4da6ede2b0cde1760ce2c3f98457ae";
    initiating      = true;
    shared          = "250b93570d411149105ab8cb0bc5079914906306368c23e9d77c2a33265b994c" };
  { priv_ours       = "6c77432d1fda31e9f942f8af44607e10f3ad38a65f8a4bddae823e5eff90dc38";
    ellswift_ours   = "d2685070c1e6376e633e825296634fd461fa9e5bdf2109bcebd735e5a91f3e587c5cb782abb797fbf6bb5074fd1542a474f2a45b673763ec2db7fb99b737bbb9";
    ellswift_theirs = "56bd0c06f10352c3a1a9f4b4c92f6fa2b26df124b57878353c1fc691c51abea77c8817daeeb9fa546b77c8daf79d89b22b0e1b87574ece42371f00237aa9d83a";
    initiating      = false;
    shared          = "1918b741ef5f9d1d7670b050c152b4a4ead2c31be9aecb0681c0cd4324150853" };
  { priv_ours       = "a6ec25127ca1aa4cf16b20084ba1e6516baae4d32422288e9b36d8bddd2de35a";
    ellswift_ours   = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff053d7ecca53e33e185a8b9be4e7699a97c6ff4c795522e5918ab7cd6b6884f67e683f3dc";
    ellswift_theirs = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffa7730be30000000000000000000000000000000000000000000000000000000000000000";
    initiating      = true;
    shared          = "dd210aa6629f20bb328e5d89daa6eb2ac3d1c658a725536ff154f31b536c23b2" };
  { priv_ours       = "0af952659ed76f80f585966b95ab6e6fd68654672827878684c8b547b1b94f5a";
    ellswift_ours   = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc81017fd92fd31637c26c906b42092e11cc0d3afae8d9019d2578af22735ce7bc469c72d";
    ellswift_theirs = "9652d78baefc028cd37a6a92625b8b8f85fde1e4c944ad3f20e198bef8c02f19fffffffffffffffffffffffffffffffffffffffffffffffffffffffff2e91870";
    initiating      = false;
    shared          = "3568f2aea2e14ef4ee4a3c2a8b8d31bc5e3187ba86db10739b4ff8ec92ff6655" };
  { priv_ours       = "f90e080c64b05824c5a24b2501d5aeaf08af3872ee860aa80bdcd430f7b63494";
    ellswift_ours   = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff115173765dc202cf029ad3f15479735d57697af12b0131dd21430d5772e4ef11474d58b9";
    ellswift_theirs = "12a50f3fafea7c1eeada4cf8d33777704b77361453afc83bda91eef349ae044d20126c6200547ea5a6911776c05dee2a7f1a9ba7dfbabbbd273c3ef29ef46e46";
    initiating      = true;
    shared          = "e25461fb0e4c162e18123ecde88342d54d449631e9b75a266fd9260c2bb2f41d" };
]

let test_bip324_xdh_vectors () =
  let n_total = List.length vectors in
  let n_pass = ref 0 in
  List.iteri (fun i v ->
    let priv  = hex_to_cs v.priv_ours in
    let ours  = hex_to_cs v.ellswift_ours in
    let theirs = hex_to_cs v.ellswift_theirs in
    let want_hex = v.shared in
    let got = P2p.compute_ecdh_secret priv theirs ours v.initiating in
    let got_hex = cs_to_hex got in
    Alcotest.(check string)
      (Printf.sprintf "bip324 ellswift_xdh vector %d" i)
      want_hex got_hex;
    if got_hex = want_hex then incr n_pass
  ) vectors;
  Alcotest.(check int) "bip324 vectors all pass" n_total !n_pass

(* compute_ellswift_pubkey: roundtrip / mutual-agreement test.

   We can't pin a single expected encoding for a given seckey because the
   encoding includes 32 bytes of randomness (auxrand). What we *can* check
   is the load-bearing property: both parties derive the same shared
   secret. This exercises:
     - compute_ellswift_pubkey produces an encoding that
       secp256k1_ellswift_decode (used inside ellswift_xdh) accepts;
     - the encoding correctly represents pubkey = privkey * G;
     - initiator/responder party-byte handling agrees with libsecp256k1. *)
let test_bip324_mutual_ecdh () =
  let priv_a = hex_to_cs "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7" in
  let priv_b = hex_to_cs "1f9c581b35231838f0f17cf0c979835baccb7f3abbbb96ffcc318ab71e6e126f" in
  let ell_a = P2p.compute_ellswift_pubkey priv_a in
  let ell_b = P2p.compute_ellswift_pubkey priv_b in
  Alcotest.(check int) "ell_a is 64 bytes" 64 (Cstruct.length ell_a);
  Alcotest.(check int) "ell_b is 64 bytes" 64 (Cstruct.length ell_b);
  (* Initiator (A) computes shared from its own ell_a + peer ell_b *)
  let shared_a = P2p.compute_ecdh_secret priv_a ell_b ell_a true in
  (* Responder (B) computes shared from its own ell_b + peer ell_a *)
  let shared_b = P2p.compute_ecdh_secret priv_b ell_a ell_b false in
  Alcotest.(check int) "shared_a is 32 bytes" 32 (Cstruct.length shared_a);
  Alcotest.(check int) "shared_b is 32 bytes" 32 (Cstruct.length shared_b);
  Alcotest.(check string) "mutual ECDH agrees"
    (cs_to_hex shared_a) (cs_to_hex shared_b)

(* compute_ellswift_pubkey: distinct invocations should produce distinct
   encodings of the same pubkey (because of auxrand). This is the BIP-324
   anti-fingerprinting property — observers can't tell two handshakes
   came from the same identity by comparing transmitted ellswift bytes.

   Note: BIP-324 deliberately mixes the *encodings themselves* into the
   shared-secret hash (`secp256k1_ellswift_xdh_hash_function_bip324`),
   so two different encodings of the same pubkey will produce *different*
   shared secrets — that's by design. We check the encoding-divergence
   property here; the cross-party agreement property is covered by the
   mutual-ECDH test above. *)
let test_bip324_encoding_randomized () =
  let priv = hex_to_cs "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7" in
  let ell_1 = P2p.compute_ellswift_pubkey priv in
  let ell_2 = P2p.compute_ellswift_pubkey priv in
  Alcotest.(check int) "ell_1 is 64 bytes" 64 (Cstruct.length ell_1);
  Alcotest.(check int) "ell_2 is 64 bytes" 64 (Cstruct.length ell_2);
  (* Encodings should differ (auxrand differs across calls) *)
  Alcotest.(check bool) "ellswift encodings differ across calls"
    true (not (Cstruct.equal ell_1 ell_2))

let () =
  let open Alcotest in
  run "BIP324 vectors" [
    "ellswift_xdh", [
      test_case "bip324 xdh vectors (libsecp256k1)" `Quick
        test_bip324_xdh_vectors;
      test_case "bip324 mutual ECDH" `Quick
        test_bip324_mutual_ecdh;
      test_case "bip324 encoding randomized" `Quick
        test_bip324_encoding_randomized;
    ];
  ]

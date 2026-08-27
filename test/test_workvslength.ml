(* #47 chain-selection tier — work-vs-length pure-predicate pins.

   Regtest cannot express work-vs-length end-to-end (every block carries the
   same expected bits), so these tests exercise the comparator arithmetic the
   header-tip selection sites use verbatim:
     Sync.process (:887) / header-tip update (:1482):
       Consensus.work_compare entry.total_work tip.total_work > 0
   over total_work values accumulated with Consensus.work_add from
   Consensus.work_from_compact — i.e. exactly the composition a live fork
   race feeds the predicate.

   The comparator is currently SOUND (work-only; LE 32-byte vectors compared
   most-significant-byte-first, i.e. index 31 downward).  These pins bind it:
   inverting target_compare's byte order (index 0 first) makes the cross-byte
   cases fail (verified during authoring — predicate-inversion A/B), so an
   endianness regression or a height term cannot land silently.

   Work values: weak bits 0x207fffff (regtest limit) -> work 2 (LE byte 0);
   strong bits 0x1a400000 -> target 2^206 -> work 2^50 (LE byte 6).  The
   strong fork's cumulative work lives in a HIGHER byte than the weak fork's,
   so a wrong byte-order compare picks the wrong winner — the pin
   discriminates both a length term and a byte-order break. *)

open Camlcoin

let accumulate_work bits n =
  let w = Consensus.work_from_compact bits in
  let total = ref Consensus.zero_work in
  for _ = 1 to n do
    total := Consensus.work_add !total w
  done;
  !total

let weak_bits = 0x207fffffl (* regtest pow limit: work 2 per block *)
let strong_bits = 0x1a400000l (* target 2^206: work 2^50 per block *)

(* The verbatim is_new_tip predicate from lib/sync.ml (:887/:1482). *)
let is_new_tip ~candidate ~tip = Consensus.work_compare candidate tip > 0

let test_heavier_but_shorter_fork_wins () =
  let light_long = accumulate_work weak_bits 8 in
  let heavy_short = accumulate_work strong_bits 2 in
  Alcotest.(check bool)
    "2-block heavy fork displaces an 8-block light tip" true
    (is_new_tip ~candidate:heavy_short ~tip:light_long)

let test_longer_but_lighter_fork_refused () =
  let light_long = accumulate_work weak_bits 8 in
  let heavy_short = accumulate_work strong_bits 2 in
  Alcotest.(check bool)
    "8-block light fork must NOT displace a 2-block heavy tip" false
    (is_new_tip ~candidate:light_long ~tip:heavy_short);
  (* Equal work must also refuse (first-seen wins — strictly-greater only). *)
  Alcotest.(check bool)
    "equal-work fork must NOT displace the tip (strictly greater required)"
    false
    (is_new_tip ~candidate:heavy_short ~tip:heavy_short)

(* Byte-order pin: work vectors are LE, compared most-significant-byte-first
   (index 31 downward).  mid x1 = 0x0000ffffffffffff (byte0 0xff); strong x2 =
   0x0007fffffffffffe (byte0 0xfe).  A low-byte-first compare sees 0xff > 0xfe
   and wrongly ACCEPTS the 8x-lighter candidate; the correct order refuses it.
   Realistic work values are all-ones patterns, so the earlier scenarios alone
   cannot catch a byte-order break — this pair can. *)
let mid_bits = 0x1b010000l (* target 2^208: work ~2^48 per block *)

let test_byte_order_pin () =
  let mid_one = accumulate_work mid_bits 1 in
  let strong_two = accumulate_work strong_bits 2 in
  Alcotest.(check bool)
    "single ~2^48-work block must NOT displace a ~2^51-work tip" false
    (is_new_tip ~candidate:mid_one ~tip:strong_two);
  Alcotest.(check bool)
    "~2^51-work fork displaces a ~2^48-work tip" true
    (is_new_tip ~candidate:strong_two ~tip:mid_one)

let test_work_scales_with_target_not_block_count () =
  (* Sanity anchor for the fixture itself: one strong block outweighs any
     plausible count of weak blocks (2^50 vs 2*n), so the scenarios above
     are testing WORK dominance, not a knife-edge. *)
  let one_strong = accumulate_work strong_bits 1 in
  let many_weak = accumulate_work weak_bits 10_000 in
  Alcotest.(check bool) "single strong block > 10k weak blocks" true
    (Consensus.work_compare one_strong many_weak > 0)

let () =
  Alcotest.run "workvslength"
    [
      ( "chain-selection work-vs-length (#47)",
        [
          Alcotest.test_case "heavier-but-shorter wins" `Quick
            test_heavier_but_shorter_fork_wins;
          Alcotest.test_case "longer-but-lighter refused" `Quick
            test_longer_but_lighter_fork_refused;
          Alcotest.test_case "work scales with target" `Quick
            test_work_scales_with_target_not_block_count;
          Alcotest.test_case "byte-order pin" `Quick test_byte_order_pin;
        ] );
    ]

(* Database layer using file-based storage (RocksDB fallback) *)

(* Storage module signature *)
module type STORAGE = sig
  type t
  type batch

  val open_db : string -> t
  val close : t -> unit

  val get : t -> string -> string option
  val put : t -> string -> string -> unit
  val delete : t -> string -> unit

  val batch_create : unit -> batch
  val batch_put : batch -> string -> string -> unit
  val batch_delete : batch -> string -> unit
  val batch_write : t -> batch -> unit

  val iter_prefix : t -> string -> (string -> string -> unit) -> unit
end

(* File-based storage implementation for development without RocksDB *)
module FileStorage : STORAGE = struct
  type t = {
    base_dir : string;
    mutable cache : (string, string) Hashtbl.t;
  }

  type batch = (string * [`Put of string | `Delete]) list ref

  let key_to_path t key =
    let hex = Types.hash256_to_hex (Crypto.sha256 (Cstruct.of_string key)) in
    Filename.concat t.base_dir (String.sub hex 0 2)
    |> fun dir -> Filename.concat dir hex

  let open_db path =
    (try Unix.mkdir path 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    { base_dir = path; cache = Hashtbl.create 10000 }

  let close _t = ()

  let get t key =
    match Hashtbl.find_opt t.cache key with
    | Some v -> Some v
    | None ->
      let path = key_to_path t key in
      if Sys.file_exists path then begin
        let ic = open_in_bin path in
        let len = in_channel_length ic in
        let data = really_input_string ic len in
        close_in ic;
        Hashtbl.replace t.cache key data;
        Some data
      end else None

  let put t key value =
    Hashtbl.replace t.cache key value;
    let path = key_to_path t key in
    let dir = Filename.dirname path in
    (try Unix.mkdir dir 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    let oc = open_out_bin path in
    output_string oc value;
    close_out oc

  let delete t key =
    Hashtbl.remove t.cache key;
    let path = key_to_path t key in
    (try Unix.unlink path with Unix.Unix_error _ -> ())

  let batch_create () = ref []
  let batch_put b key value = b := (key, `Put value) :: !b
  let batch_delete b key = b := (key, `Delete) :: !b
  let batch_write t b =
    List.iter (function
      | (key, `Put value) -> put t key value
      | (key, `Delete) -> delete t key
    ) !b

  let iter_prefix t prefix f =
    Hashtbl.iter (fun k v ->
      if String.length k >= String.length prefix &&
         String.sub k 0 (String.length prefix) = prefix then
        f k v
    ) t.cache
end

(* Key prefix constants for namespace separation *)
let prefix_block_header = "h"
let prefix_block_data   = "b"
let prefix_tx           = "t"
let prefix_utxo         = "u"
let prefix_block_height = "n"
let prefix_tx_index     = "x"
let prefix_chain_state  = "s"

(* Higher-level chain database built on top of the storage layer *)
module ChainDB = struct
  type t = { db : FileStorage.t }

  let create path = { db = FileStorage.open_db path }
  let close t = FileStorage.close t.db

  (* Encode height as 4-byte big-endian for lexicographic sorting *)
  let encode_height (h : int) : string =
    let cs = Cstruct.create 4 in
    Cstruct.BE.set_uint32 cs 0 (Int32.of_int h);
    Cstruct.to_string cs

  let decode_height (s : string) : int =
    let cs = Cstruct.of_string s in
    Int32.to_int (Cstruct.BE.get_uint32 cs 0)

  (* Block header storage *)
  let store_block_header t (hash : Types.hash256) (header : Types.block_header) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    let key = prefix_block_header ^ Cstruct.to_string hash in
    FileStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_block_header t (hash : Types.hash256)
      : Types.block_header option =
    let key = prefix_block_header ^ Cstruct.to_string hash in
    match FileStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_block_header r)

  (* Full block storage *)
  let store_block t (hash : Types.hash256) (block : Types.block) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block w block;
    let key = prefix_block_data ^ Cstruct.to_string hash in
    FileStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_block t (hash : Types.hash256) : Types.block option =
    let key = prefix_block_data ^ Cstruct.to_string hash in
    match FileStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_block r)

  (* Height to hash mapping *)
  let set_height_hash t (height : int) (hash : Types.hash256) =
    let key = prefix_block_height ^ encode_height height in
    FileStorage.put t.db key (Cstruct.to_string hash)

  let get_hash_at_height t (height : int) : Types.hash256 option =
    let key = prefix_block_height ^ encode_height height in
    match FileStorage.get t.db key with
    | None -> None
    | Some data -> Some (Cstruct.of_string data)

  (* Transaction storage *)
  let store_transaction t (txid : Types.hash256) (tx : Types.transaction) =
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    let key = prefix_tx ^ Cstruct.to_string txid in
    FileStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_transaction t (txid : Types.hash256) : Types.transaction option =
    let key = prefix_tx ^ Cstruct.to_string txid in
    match FileStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_transaction r)

  (* UTXO storage - keyed by txid + vout for O(1) lookup *)
  let store_utxo t (txid : Types.hash256) (vout : int) (utxo_data : string) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    FileStorage.put t.db key utxo_data

  let get_utxo t (txid : Types.hash256) (vout : int) : string option =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    FileStorage.get t.db key

  let delete_utxo t (txid : Types.hash256) (vout : int) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    FileStorage.delete t.db key

  (* Chain state - tip hash and height *)
  let set_chain_tip t (hash : Types.hash256) (height : int) =
    FileStorage.put t.db
      (prefix_chain_state ^ "tip_hash") (Cstruct.to_string hash);
    FileStorage.put t.db
      (prefix_chain_state ^ "tip_height") (encode_height height)

  let get_chain_tip t : (Types.hash256 * int) option =
    match FileStorage.get t.db (prefix_chain_state ^ "tip_hash"),
          FileStorage.get t.db (prefix_chain_state ^ "tip_height") with
    | Some hash_str, Some height_str ->
      let hash = Cstruct.of_string hash_str in
      let height = decode_height height_str in
      Some (hash, height)
    | _ -> None

  (* Transaction index - map txid to (block_hash, tx_index) *)
  let store_tx_index t (txid : Types.hash256) (block_hash : Types.hash256) (tx_idx : int) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w block_hash;
    Serialize.write_int32_le w (Int32.of_int tx_idx);
    let key = prefix_tx_index ^ Cstruct.to_string txid in
    FileStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_tx_index t (txid : Types.hash256) : (Types.hash256 * int) option =
    let key = prefix_tx_index ^ Cstruct.to_string txid in
    match FileStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      let block_hash = Serialize.read_bytes r 32 in
      let tx_idx = Int32.to_int (Serialize.read_int32_le r) in
      Some (block_hash, tx_idx)

  (* Batch operations for atomic updates *)
  let batch_create () = FileStorage.batch_create ()

  let batch_store_block_header batch (hash : Types.hash256) (header : Types.block_header) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    let key = prefix_block_header ^ Cstruct.to_string hash in
    FileStorage.batch_put batch key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let batch_store_utxo batch (txid : Types.hash256) (vout : int) (utxo_data : string) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    FileStorage.batch_put batch key utxo_data

  let batch_delete_utxo batch (txid : Types.hash256) (vout : int) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    FileStorage.batch_delete batch key

  let batch_set_chain_tip batch (hash : Types.hash256) (height : int) =
    FileStorage.batch_put batch
      (prefix_chain_state ^ "tip_hash") (Cstruct.to_string hash);
    FileStorage.batch_put batch
      (prefix_chain_state ^ "tip_height") (encode_height height)

  let batch_write t batch = FileStorage.batch_write t.db batch

  (* Iterate over all UTXOs *)
  let iter_utxos t f =
    FileStorage.iter_prefix t.db prefix_utxo (fun key value ->
      (* Extract txid and vout from key *)
      let key_data = String.sub key 1 (String.length key - 1) in
      let r = Serialize.reader_of_cstruct (Cstruct.of_string key_data) in
      let txid = Serialize.read_bytes r 32 in
      let vout = Int32.to_int (Serialize.read_int32_le r) in
      f txid vout value
    )

  (* Check if block exists *)
  let has_block t (hash : Types.hash256) : bool =
    let key = prefix_block_data ^ Cstruct.to_string hash in
    Option.is_some (FileStorage.get t.db key)

  let has_block_header t (hash : Types.hash256) : bool =
    let key = prefix_block_header ^ Cstruct.to_string hash in
    Option.is_some (FileStorage.get t.db key)
end

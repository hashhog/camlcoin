type block_header = {
  version : int;
  prev_hash : bytes;
  merkle_root : bytes;
  timestamp : int;
  bits : int;
  nonce : int;
}

#!/usr/bin/env python3
"""
Test script to send getheaders messages to Bitcoin Core and print full hex.
Used for comparing byte-by-byte against camlcoin's wire output.
"""

import socket
import struct
import hashlib
import time
import os

MAINNET_MAGIC = b'\xf9\xbe\xb4\xd9'
PROTOCOL_VERSION = 70016

# Mainnet genesis hash in internal byte order (little-endian)
GENESIS_HASH = bytes.fromhex(
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
)

# Block 2000 hash in internal byte order
BLOCK_2000_HASH = bytes.fromhex(
    "1a95da875f907fb31f13cb3e93e38f01630af6b8b461859d5cd6d5df00000000"
)

ZERO_HASH = b'\x00' * 32


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def make_msg(command: str, payload: bytes) -> bytes:
    """Build a complete Bitcoin P2P message (header + payload)."""
    cmd_bytes = command.encode('ascii')
    cmd_padded = cmd_bytes + b'\x00' * (12 - len(cmd_bytes))
    length = struct.pack('<I', len(payload))
    checksum = sha256d(payload)[:4]
    return MAINNET_MAGIC + cmd_padded + length + checksum + payload


def make_version_msg():
    """Minimal version message for handshake."""
    payload = b''
    payload += struct.pack('<i', PROTOCOL_VERSION)  # version
    payload += struct.pack('<Q', 0)                  # services
    payload += struct.pack('<q', int(time.time()))    # timestamp
    # addr_recv: services(8) + ip(16) + port(2)
    payload += struct.pack('<Q', 0)                  # services
    payload += b'\x00' * 10 + b'\xff\xff' + b'\x7f\x00\x00\x01'  # IPv4-mapped 127.0.0.1
    payload += struct.pack('>H', 8333)               # port (BE)
    # addr_from: services(8) + ip(16) + port(2)
    payload += struct.pack('<Q', 0)
    payload += b'\x00' * 10 + b'\xff\xff' + b'\x7f\x00\x00\x01'
    payload += struct.pack('>H', 0)
    payload += struct.pack('<Q', int.from_bytes(os.urandom(8), 'little'))  # nonce
    payload += b'\x00'                               # user_agent (varint 0)
    payload += struct.pack('<i', 0)                   # start_height
    payload += b'\x01'                               # relay
    return make_msg('version', payload)


def make_getheaders(locator_hashes, hash_stop=ZERO_HASH):
    """Build a getheaders message."""
    payload = struct.pack('<I', PROTOCOL_VERSION)  # version (uint32 LE)
    payload += bytes([len(locator_hashes)])          # varint count
    for h in locator_hashes:
        payload += h
    payload += hash_stop
    return make_msg('getheaders', payload)


def recv_until(sock, n):
    """Receive exactly n bytes."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def read_message(sock):
    """Read one P2P message, return (command, payload)."""
    header = recv_until(sock, 24)
    magic = header[:4]
    if magic != MAINNET_MAGIC:
        raise ValueError(f"Bad magic: {magic.hex()}")
    cmd = header[4:16].rstrip(b'\x00').decode('ascii')
    length = struct.unpack('<I', header[16:20])[0]
    checksum = header[20:24]
    payload = recv_until(sock, length) if length > 0 else b''
    actual_checksum = sha256d(payload)[:4]
    if checksum != actual_checksum:
        raise ValueError(f"Checksum mismatch for {cmd}")
    return cmd, payload


def parse_headers_count(payload):
    """Parse a headers message and return the count."""
    if not payload:
        return 0
    count = payload[0]
    if count < 0xfd:
        return count
    elif count == 0xfd:
        return struct.unpack('<H', payload[1:3])[0]
    elif count == 0xfe:
        return struct.unpack('<I', payload[1:5])[0]
    else:
        return struct.unpack('<Q', payload[1:9])[0]


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    print("Connecting to 127.0.0.1:8333 ...")
    sock.connect(('127.0.0.1', 8333))
    print("Connected.")

    # === Handshake ===
    version_msg = make_version_msg()
    sock.sendall(version_msg)
    print("Sent version.")

    # Read until we get verack (may receive version, wtxidrelay, sendaddrv2, etc first)
    got_verack = False
    got_version = False
    for _ in range(20):
        cmd, payload = read_message(sock)
        print(f"  Received: {cmd} ({len(payload)} bytes)")
        if cmd == 'version':
            got_version = True
            # Send verack
            verack = make_msg('verack', b'')
            sock.sendall(verack)
            print("  Sent verack.")
        elif cmd == 'verack':
            got_verack = True
            break

    if not got_verack:
        print("ERROR: Did not receive verack")
        sock.close()
        return

    print("\n=== Handshake complete ===\n")

    # === First getheaders: locator=[genesis_hash], hash_stop=zeros ===
    msg1 = make_getheaders([GENESIS_HASH])
    print(f"GETHEADERS #1 full hex ({len(msg1)} bytes):")
    print(msg1.hex())
    print()
    sock.sendall(msg1)

    # Wait for response
    for _ in range(20):
        cmd, payload = read_message(sock)
        print(f"  Response: {cmd} ({len(payload)} bytes)")
        if cmd == 'headers':
            count = parse_headers_count(payload)
            print(f"  Headers count: {count}")
            break
        elif cmd in ('ping',):
            # Respond to ping
            pong = make_msg('pong', payload)
            sock.sendall(pong)

    print()

    # === Second getheaders: locator=[block_2000, genesis_hash], hash_stop=zeros ===
    msg2 = make_getheaders([BLOCK_2000_HASH, GENESIS_HASH])
    print(f"GETHEADERS #2 full hex ({len(msg2)} bytes):")
    print(msg2.hex())
    print()
    sock.sendall(msg2)

    # Wait for response
    for _ in range(20):
        cmd, payload = read_message(sock)
        print(f"  Response: {cmd} ({len(payload)} bytes)")
        if cmd == 'headers':
            count = parse_headers_count(payload)
            print(f"  Headers count: {count}")
            break
        elif cmd in ('ping',):
            pong = make_msg('pong', payload)
            sock.sendall(pong)

    sock.close()
    print("\nDone.")


if __name__ == '__main__':
    main()

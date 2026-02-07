#!/usr/bin/env python3
"""
Tron Private Key → Address Derivation

Used to verify that the exposed private key in GemPad's JavaScript bundle
corresponds to a real Tron mainnet wallet with transaction history.

Advisory: CPK-2026-002
Date: 2026-02-07

Dependencies:
    pip install ecdsa pycryptodome

Usage:
    python3 key-derivation.py
"""

import hashlib
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak


def derive_tron_address(private_key_hex: str) -> str:
    """Derive a Tron base58check address from a hex private key."""
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Step 1: Derive the uncompressed public key via secp256k1
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    public_key = sk.get_verifying_key().to_string()  # 64 bytes (x || y)

    # Step 2: Keccak-256 hash of the public key
    k = keccak.new(digest_bits=256)
    k.update(public_key)
    keccak_hash = k.digest()

    # Step 3: Take last 20 bytes, prepend 0x41 (Tron mainnet prefix)
    address_bytes = b'\x41' + keccak_hash[-20:]

    # Step 4: Double SHA-256 for checksum
    h1 = hashlib.sha256(address_bytes).digest()
    h2 = hashlib.sha256(h1).digest()
    checksum = h2[:4]

    # Step 5: Base58 encode (address + checksum)
    addr_with_checksum = address_bytes + checksum
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(addr_with_checksum, 'big')
    result = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        result = alphabet[remainder] + result

    # Handle leading zero bytes
    for byte in addr_with_checksum:
        if byte == 0:
            result = '1' + result
        else:
            break

    return result


def hex_address(private_key_hex: str) -> str:
    """Derive the hex address (used in TronGrid API calls)."""
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    public_key = sk.get_verifying_key().to_string()

    k = keccak.new(digest_bits=256)
    k.update(public_key)
    keccak_hash = k.digest()

    address_bytes = b'\x41' + keccak_hash[-20:]
    return address_bytes.hex()


if __name__ == '__main__':
    # The exposed private key from GemPad's JavaScript bundle
    # Redacted — full key available in evidence/tronweb-initialization.js
    PRIVATE_KEY = "b9205a3a████████████████████████████████████████████d5add12123"

    base58_addr = derive_tron_address(PRIVATE_KEY)
    hex_addr = hex_address(PRIVATE_KEY)

    print(f"Private Key:    {PRIVATE_KEY}")
    print(f"Tron Address:   {base58_addr}")
    print(f"Hex Address:    {hex_addr}")
    print(f"TronScan:       https://tronscan.org/#/address/{base58_addr}")
    print()

    expected = "TQjrBrzXXWRrCXRWZxf6x5xqVrdgJwcXg5"
    if base58_addr == expected:
        print(f"[VERIFIED] Address matches expected: {expected}")
    else:
        print(f"[MISMATCH] Expected {expected}, got {base58_addr}")

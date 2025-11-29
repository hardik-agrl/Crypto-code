# des_implementation.py
# Educational DES implementation (ECB + optional CBC helper)
# NOT FOR PRODUCTION USE.

from typing import List
import math

# --- DES tables (standard) ---
# Initial Permutation (IP)
IP = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
]

# Final Permutation (IP^-1)
FP = [
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
]

# Expansion E (32 -> 48)
E = [
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
]

# S-boxes S1..S8 (each 4x16)
SBOX = [
# S1
[
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
],
# S2
[
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
],
# S3
[
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
],
# S4
[
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
],
# S5
[
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
],
# S6
[
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
],
# S7
[
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
],
# S8
[
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
]
]

# Permutation P (32 -> 32)
P = [
    16,7,20,21,
    29,12,28,17,
    1,15,23,26,
    5,18,31,10,
    2,8,24,14,
    32,27,3,9,
    19,13,30,6,
    22,11,4,25
]

# PC-1 (64 -> 56)
PC1 = [
57,49,41,33,25,17,9,
1,58,50,42,34,26,18,
10,2,59,51,43,35,27,
19,11,3,60,52,44,36,
63,55,47,39,31,23,15,
7,62,54,46,38,30,22,
14,6,61,53,45,37,29,
21,13,5,28,20,12,4
]

# PC-2 (56 -> 48)
PC2 = [
14,17,11,24,1,5,
3,28,15,6,21,10,
23,19,12,4,26,8,
16,7,27,20,13,2,
41,52,31,37,47,55,
30,40,51,45,33,48,
44,49,39,56,34,53,
46,42,50,36,29,32
]

# Left shifts per round
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# --- Bit helpers ---
def permute(block: int, table: List[int], in_bits: int, out_bits: int) -> int:
    """Permute bits of block according to table (1-indexed positions)."""
    out = 0
    for pos in table:
        out = (out << 1) | ((block >> (in_bits - pos)) & 1)
    return out

def left_rotate(val: int, n: int, bits: int) -> int:
    return ((val << n) & ((1 << bits) - 1)) | (val >> (bits - n))

# --- Key schedule ---
def generate_subkeys(key64: bytes) -> List[int]:
    """Given 8-byte key (64 bits, including parity), produce 16 subkeys (48-bit ints)."""
    if len(key64) != 8:
        raise ValueError("Key must be 8 bytes (64 bits).")
    key_int = int.from_bytes(key64, byteorder='big')
    # PC-1: 64 -> 56
    key56 = permute(key_int, PC1, 64, 56)
    # Split to C and D (28 bits each)
    C = (key56 >> 28) & ((1 << 28) - 1)
    D = key56 & ((1 << 28) - 1)
    subkeys = []
    for shift in SHIFTS:
        C = left_rotate(C, shift, 28)
        D = left_rotate(D, shift, 28)
        combined = (C << 28) | D
        # PC-2: 56 -> 48
        k48 = permute(combined, PC2, 56, 48)
        subkeys.append(k48)
    return subkeys  # 16 items

# --- Feistel function ---
def feistel(R: int, subkey: int) -> int:
    """R: 32-bit int. subkey: 48-bit int. Returns 32-bit int."""
    # Expand R (32 -> 48)
    expanded = permute(R, E, 32, 48)
    # XOR with subkey
    x = expanded ^ subkey
    # Split into 8 groups of 6 bits, apply S-boxes
    output = 0
    for i in range(8):
        chunk = (x >> (42 - 6*i)) & 0x3F  # 6 bits
        # row: bits 6 and 1; col: bits 2-5
        row = ((chunk & 0x20) >> 4) | (chunk & 0x01)
        col = (chunk >> 1) & 0x0F
        s_val = SBOX[i][row][col]
        output = (output << 4) | s_val
    # Apply permutation P (32 -> 32)
    return permute(output, P, 32, 32)

# --- Block encrypt/decrypt (ECB single block) ---
def encrypt_block(plain8: bytes, subkeys: List[int]) -> bytes:
    if len(plain8) != 8:
        raise ValueError("Block must be 8 bytes.")
    block = int.from_bytes(plain8, byteorder='big')
    # Initial Permutation
    ip = permute(block, IP, 64, 64)
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF
    # 16 rounds
    for i in range(16):
        newL = R
        newR = L ^ feistel(R, subkeys[i])
        L, R = newL, newR
    # Preoutput (R then L)
    preout = (R << 32) | L
    cipher = permute(preout, FP, 64, 64)
    return cipher.to_bytes(8, byteorder='big')

def decrypt_block(cipher8: bytes, subkeys: List[int]) -> bytes:
    if len(cipher8) != 8:
        raise ValueError("Block must be 8 bytes.")
    block = int.from_bytes(cipher8, byteorder='big')
    ip = permute(block, IP, 64, 64)
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF
    # 16 rounds with subkeys reversed
    for i in range(16):
        newL = R
        newR = L ^ feistel(R, subkeys[15 - i])
        L, R = newL, newR
    preout = (R << 32) | L
    plain = permute(preout, FP, 64, 64)
    return plain.to_bytes(8, byteorder='big')

# --- Padding (PKCS#5/7 style for 8-byte blocks) ---
def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    if pad_len == 0:
        pad_len = 8
    return data + bytes([pad_len]) * pad_len

def unpad_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % 8 != 0:
        raise ValueError("Invalid padded data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")
    return data[:-pad_len]

# --- Higher-level modes: ECB and CBC wrappers ---
def encrypt_ecb(plaintext: bytes, key8: bytes, pad: bool = True) -> bytes:
    subkeys = generate_subkeys(key8)
    if pad:
        plaintext = pad_pkcs7(plaintext)
    out = bytearray()
    for i in range(0, len(plaintext), 8):
        out.extend(encrypt_block(plaintext[i:i+8], subkeys))
    return bytes(out)

def decrypt_ecb(ciphertext: bytes, key8: bytes, unpad: bool = True) -> bytes:
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8.")
    subkeys = generate_subkeys(key8)
    out = bytearray()
    for i in range(0, len(ciphertext), 8):
        out.extend(decrypt_block(ciphertext[i:i+8], subkeys))
    if unpad:
        return unpad_pkcs7(bytes(out))
    return bytes(out)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt_cbc(plaintext: bytes, key8: bytes, iv8: bytes, pad: bool = True) -> bytes:
    if len(iv8) != 8:
        raise ValueError("IV must be 8 bytes.")
    subkeys = generate_subkeys(key8)
    if pad:
        plaintext = pad_pkcs7(plaintext)
    out = bytearray()
    prev = iv8
    for i in range(0, len(plaintext), 8):
        block = xor_bytes(plaintext[i:i+8], prev)
        cipher = encrypt_block(block, subkeys)
        out.extend(cipher)
        prev = cipher
    return bytes(out)

def decrypt_cbc(ciphertext: bytes, key8: bytes, iv8: bytes, unpad: bool = True) -> bytes:
    if len(iv8) != 8 or len(ciphertext) % 8 != 0:
        raise ValueError("Invalid IV or ciphertext length.")
    subkeys = generate_subkeys(key8)
    out = bytearray()
    prev = iv8
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        plain = decrypt_block(block, subkeys)
        plain = xor_bytes(plain, prev)
        out.extend(plain)
        prev = block
    if unpad:
        return unpad_pkcs7(bytes(out))
    return bytes(out)

# --- Example usage ---
if __name__ == "__main__":
    # Example: key must be 8 bytes (64 bits). DES uses parity bits (ignored here).
    key = b"ABCDEFGH"         # 8 bytes sample key
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    msg = b"The quick brown fox jumps over the lazy dog"

    print("Plain:", msg)
    c = encrypt_cbc(msg, key, iv)
    print("Cipher (hex):", c.hex())
    p = decrypt_cbc(c, key, iv)
    print("Decrypted:", p)
    assert p == msg

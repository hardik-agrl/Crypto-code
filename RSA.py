#!/usr/bin/env python3
"""
Simple RSA implementation (educational demo).

- Uses Miller-Rabin for primality testing.
- Generates two random primes of specified bit-length and builds (n,e,d).
- Encrypts/decrypts integer messages and text by splitting into base-256 blocks.
- NOT safe for production: uses naive block handling and no OAEP padding.
"""

import secrets
import math
from typing import Tuple, List

# ----------------- Math helpers -----------------

def is_probable_prime(n: int, k: int = 8) -> bool:
    """Miller-Rabin primality test (probabilistic)."""
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    # write n-1 as d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Generate a prime number of specified bit length."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        # ensure top bit set so number has exactly 'bits' bits; ensure odd
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def egcd(a: int, b: int) -> Tuple[int,int,int]:
    """Extended gcd: returns (g, x, y) such that a*x + b*y = g = gcd(a,b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m. Raises if inverse doesn't exist."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

# ----------------- RSA key generation -----------------

class RSAKeyPair:
    def __init__(self, n:int, e:int, d:int, p:int=None, q:int=None):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

def generate_rsa(bits_per_prime: int = 512, e: int = 65537) -> RSAKeyPair:
    """
    Generate RSA keypair.
    bits_per_prime: bit-length for each prime p and q.
    e: public exponent (default 65537).
    """
    # generate p and q
    p = generate_prime(bits_per_prime)
    q = generate_prime(bits_per_prime)
    while q == p:
        q = generate_prime(bits_per_prime)

    n = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        # rarely, choose a different e
        for cand in range(3, 1 << 16, 2):
            if math.gcd(cand, phi) == 1:
                e = cand
                break

    d = modinv(e, phi)
    return RSAKeyPair(n=n, e=e, d=d, p=p, q=q)

# ----------------- block conversion (text <-> ints) -----------------

def _max_block_bytes(n: int) -> int:
    """Return max number of bytes b such that 256^b < n."""
    b = 1
    while pow(256, b) < n:
        b += 1
    return max(1, b - 1)

def text_to_blocks(msg: str, n: int) -> List[int]:
    """Convert UTF-8 text to list of integer blocks < n."""
    data = msg.encode('utf-8')
    max_bytes = _max_block_bytes(n)
    blocks = []
    for i in range(0, len(data), max_bytes):
        chunk = data[i:i+max_bytes]
        num = 0
        for byte in chunk:
            num = (num << 8) + byte
        blocks.append(num)
    return blocks

def blocks_to_text(blocks: List[int], n: int) -> str:
    """Convert integer blocks back to text (UTF-8)."""
    max_bytes = _max_block_bytes(n)
    out_bytes = bytearray()
    for block in blocks:
        # recover bytes big-endian with padding up to max_bytes
        temp = block
        chunk = bytearray()
        for _ in range(max_bytes):
            chunk.append(temp & 0xFF)
            temp >>= 8
        chunk.reverse()  # big-endian
        # strip leading zero padding that might appear in the first block only
        # but to keep things simple we strip leading zeros globally (works for typical text)
        while chunk and chunk[0] == 0:
            chunk.pop(0)
        out_bytes.extend(chunk)
    return out_bytes.decode('utf-8', errors='ignore')

# ----------------- RSA operations -----------------

def encrypt_int(m: int, pub: RSAKeyPair) -> int:
    if m >= pub.n:
        raise ValueError("message integer >= modulus")
    return pow(m, pub.e, pub.n)

def decrypt_int(c: int, priv: RSAKeyPair) -> int:
    return pow(c, priv.d, priv.n)

def encrypt_text(msg: str, pub: RSAKeyPair) -> List[int]:
    blocks = text_to_blocks(msg, pub.n)
    return [encrypt_int(b, pub) for b in blocks]

def decrypt_text(cipher_blocks: List[int], priv: RSAKeyPair) -> str:
    blocks = [decrypt_int(c, priv) for c in cipher_blocks]
    return blocks_to_text(blocks, priv.n)

# ----------------- Demo -----------------

if __name__ == "__main__":
    import time

    # For quick demo on a laptop, use smaller primes (e.g., 128 bits per prime).
    # For stronger keys use 1024 or 2048 bits per prime (but generation will be slower).
    bits = 256  # change to 512 or 1024 for stronger keys
    print(f"Generating RSA keypair with {bits}-bit primes (this may take a few seconds)...")
    t0 = time.time()
    kp = generate_rsa(bits_per_prime=bits)
    t1 = time.time()
    print(f"Done in {t1-t0:.2f}s")
    print("Public key (n, e):")
    print(" n =", kp.n)
    print(" e =", kp.e)
    print("Private key d (truncated):")
    print(" d =", str(kp.d)[:80] + "..." )

    # integer encrypt/decrypt demo
    m = 12345678901234567890
    c = encrypt_int(m, kp)
    m2 = decrypt_int(c, kp)
    print("\nInteger message demo:")
    print(" m =", m)
    print(" c =", c)
    print(" decrypted =", m2)

    # text encrypt/decrypt demo
    text = "Hello I am hardik. Testing RSA Algorithm"
    print("\nPlaintext:", text)
    cipher_blocks = encrypt_text(text, kp)
    print("Cipher blocks (integers):", cipher_blocks[:6], "..." if len(cipher_blocks)>6 else "")
    recovered = decrypt_text(cipher_blocks, kp)
    print("Recovered text:", recovered)

#!/usr/bin/env python3
"""
rsa_sign.py

Educational RSA signature demo (Python).

- Key generation (Miller-Rabin)
- Sign: SHA-256(message) -> integer -> signature = pow(hash_int, d, n)
- Verify: pow(signature, e, n) == hash_int
- Save/load keys (JSON)
"""

import secrets
import hashlib
import math
import json
import time
from typing import Tuple, Dict

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
    """Generate a prime of exact bit length 'bits'."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1  # ensure high bit and odd
        if is_probable_prime(p):
            return p

def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def modinv(a: int, m: int) -> int:
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
    """Generate RSA keypair. bits_per_prime is the length of p and q each."""
    p = generate_prime(bits_per_prime)
    q = generate_prime(bits_per_prime)
    while q == p:
        q = generate_prime(bits_per_prime)

    n = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        # fallback to find a small coprime e
        for cand in range(3, 1 << 16, 2):
            if math.gcd(cand, phi) == 1:
                e = cand
                break

    d = modinv(e, phi)
    return RSAKeyPair(n=n, e=e, d=d, p=p, q=q)

# ----------------- Signature scheme (educational) -----------------

def sha256_int(data: bytes) -> int:
    """Return integer representation (big-endian) of SHA-256 digest of data."""
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, byteorder='big')

def sign_message(message: bytes, priv: RSAKeyPair) -> int:
    """
    Sign the message:
      s = (SHA256(message) as int)^d mod n
    Returns integer signature.
    """
    h_int = sha256_int(message)
    if h_int >= priv.n:
        # extremely unlikely when n is large vs 256-bit hash, but handle anyway
        h_int = h_int % priv.n
    sig = pow(h_int, priv.d, priv.n)
    return sig

def verify_signature(message: bytes, signature: int, pub: RSAKeyPair) -> bool:
    """
    Verify signature:
      check pow(signature, e, n) == SHA256(message) as int (mod n)
    """
    h_int = sha256_int(message)
    recovered = pow(signature, pub.e, pub.n)
    # In our scheme we do direct equality (mod n). If h_int was reduced modulo n during sign,
    # compare modulo n too.
    return (recovered % pub.n) == (h_int % pub.n)

# ----------------- Key save/load -----------------

def keypair_to_dict(kp: RSAKeyPair) -> Dict:
    return {
        "n": str(kp.n),
        "e": str(kp.e),
        "d": str(kp.d),
        "p": str(kp.p) if kp.p is not None else None,
        "q": str(kp.q) if kp.q is not None else None,
    }

def keypair_from_dict(d: Dict) -> RSAKeyPair:
    return RSAKeyPair(
        n=int(d["n"]),
        e=int(d["e"]),
        d=int(d["d"]),
        p=int(d["p"]) if d.get("p") else None,
        q=int(d["q"]) if d.get("q") else None,
    )

def save_keypair(kp: RSAKeyPair, filename: str) -> None:
    with open(filename, "w") as f:
        json.dump(keypair_to_dict(kp), f)
    print(f"[+] saved keypair to {filename}")

def load_keypair(filename: str) -> RSAKeyPair:
    with open(filename, "r") as f:
        d = json.load(f)
    return keypair_from_dict(d)

# ----------------- Demo -----------------

if __name__ == "__main__":
    print("RSA signature demo (educational). Generating keypair...")
    start = time.time()
    kp = generate_rsa(bits_per_prime=512)  # 512-bit primes -> 1024-bit n (reasonable for demo)
    end = time.time()
    print(f"Generated keys in {end-start:.2f}s")
    print(f"n bit-length: {kp.n.bit_length()} bits")
    print(f"public exponent e = {kp.e}")
    

    # demo message
    message = b"Hello, this is a message to sign."
    print("\nMessage to sign:", message.decode())

    sig = sign_message(message, kp)
    print("Signature (integer, truncated):", str(sig)[:120] + "...")

    ok = verify_signature(message, sig, kp)
    print("Verification result (should be True):", ok)

    # tamper test
    tampered = b"Hello, this is a tampered message."
    ok2 = verify_signature(tampered, sig, kp)
    print("Verification on tampered message (should be False):", ok2)

    # save keys (for demo)
    save_keypair(kp, "rsa_keypair_demo.json")

    # example of loading and verifying with loaded keys
    kp_loaded = load_keypair("rsa_keypair_demo.json")
    print("Loaded key n bit-length:", kp_loaded.n.bit_length())
    print("Verify with loaded key:", verify_signature(message, sig, kp_loaded))

    

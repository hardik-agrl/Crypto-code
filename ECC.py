# ecies_secp256k1.py
# Simple ECIES-like implementation on secp256k1 (educational only).
import os
import hashlib
from typing import Tuple, Optional

# ---------- curve parameters (secp256k1) ----------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---------- basic field and EC ops ----------
Point = Optional[Tuple[int,int]]   # None represents point at infinity

def inv_mod(x: int, p: int = P) -> int:
    """Modular inverse, p prime — uses Fermat's little theorem."""
    return pow(x % p, p - 2, p)

def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x,y = pt
    return (y*y - (x*x*x + A*x + B)) % P == 0

def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1,y1 = p1
    x2,y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 != p2:
        # slope = (y2 - y1)/(x2 - x1)
        s = ((y2 - y1) * inv_mod(x2 - x1)) % P
    else:
        # slope = (3*x1^2 + a) / (2*y1)
        s = ((3 * x1 * x1 + A) * inv_mod(2 * y1)) % P
    xr = (s * s - x1 - x2) % P
    yr = (s * (x1 - xr) - y1) % P
    return (xr, yr)

def scalar_mult(k: int, pt: Point) -> Point:
    """Double-and-add scalar multiplication."""
    if k % N == 0 or pt is None:
        return None
    if k < 0:
        # k * P = -k * (-P)
        return scalar_mult(-k, (pt[0], (-pt[1]) % P))
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

# ---------- serialization helpers ----------
def point_to_bytes(pt: Point) -> bytes:
    """Uncompressed point format: 0x04 || x(32) || y(32)"""
    if pt is None:
        return b'\x00'
    x,y = pt
    xb = x.to_bytes(32, 'big')
    yb = y.to_bytes(32, 'big')
    return b'\x04' + xb + yb

def bytes_to_point(b: bytes) -> Point:
    if b == b'\x00':
        return None
    if len(b) != 65 or b[0] != 4:
        raise ValueError("Invalid uncompressed point encoding")
    x = int.from_bytes(b[1:33], 'big')
    y = int.from_bytes(b[33:65], 'big')
    pt = (x,y)
    if not is_on_curve(pt):
        raise ValueError("Point not on curve")
    return pt

# ---------- key generation ----------
def gen_privkey() -> int:
    """Generate a random private key in [1, N-1]."""
    while True:
        d = int.from_bytes(os.urandom(32), 'big')
        d = d % N
        if 1 <= d < N:
            return d

def priv_to_pub(d: int) -> Point:
    return scalar_mult(d, (Gx, Gy))

# ---------- KDF / keystream ----------
def kdf_shared_secret_to_key(sx: int, sy: int) -> bytes:
    """Derive a symmetric key from ECDH shared point (sx,sy)."""
    s_bytes = sx.to_bytes(32, 'big') + sy.to_bytes(32, 'big')
    return hashlib.sha256(s_bytes).digest()  # 32 bytes key

def keystream(key: bytes, length: int) -> bytes:
    """Expand key into a keystream by repeated SHA256(key || counter)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        ctrb = counter.to_bytes(4, 'big')
        out.extend(hashlib.sha256(key + ctrb).digest())
        counter += 1
    return bytes(out[:length])

# ---------- ECIES-like encrypt/decrypt (stateless, unauthenticated) ----------
def ecies_encrypt(recipient_pub: Point, plaintext: bytes) -> bytes:
    """
    Returns a blob: ephemeral_pub (65 bytes uncompressed) || ciphertext (len plaintext bytes)
    Encryption: generate ephemeral k, compute S = k * recipient_pub, derive key from S, XOR plaintext with keystream.
    """
    # ephemeral key
    k = gen_privkey()
    R = priv_to_pub(k)  # ephemeral public
    S = scalar_mult(k, recipient_pub)  # shared secret
    if S is None:
        raise RuntimeError("Invalid shared secret (point at infinity)")
    key = kdf_shared_secret_to_key(S[0], S[1])
    ks = keystream(key, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    return point_to_bytes(R) + ct

def ecies_decrypt(recipient_priv: int, blob: bytes) -> bytes:
    """
    Expects blob produced by ecies_encrypt.
    Splits ephemeral_pub (65 bytes) and ciphertext and recovers plaintext.
    """
    if len(blob) < 65:
        raise ValueError("Blob too short")
    Rb = blob[:65]
    ct = blob[65:]
    R = bytes_to_point(Rb)
    S = scalar_mult(recipient_priv, R)
    if S is None:
        raise RuntimeError("Invalid shared secret (point at infinity)")
    key = kdf_shared_secret_to_key(S[0], S[1])
    ks = keystream(key, len(ct))
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    return pt

# ---------- example usage ----------
if __name__ == "__main__":
    # Recipient generates key pair
    priv = gen_privkey()
    pub = priv_to_pub(priv)
    print("Receiver priv (hex):", hex(priv))
    print("Receiver pub x:", hex(pub[0]))
    print("Receiver pub y:", hex(pub[1]))

    # Sender encrypts
    msg = b"Hello ECC world! This is a test message."
    blob = ecies_encrypt(pub, msg)
    print("Encrypted blob (hex, truncated):", blob[:40].hex(), "...", "len=", len(blob))

    # Recipient decrypts
    recovered = ecies_decrypt(priv, blob)
    print("Recovered:", recovered)
    assert recovered == msg
    print("Success: plaintext recovered correctly.")

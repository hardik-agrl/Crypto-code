def KSA(key):
    """Key Scheduling Algorithm"""
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S):
    """Pseudo-Random Generation Algorithm"""
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key, plaintext):
    key = [ord(c) for c in key]  
    S = KSA(key)
    keystream = PRGA(S)
    res = []
    for c in plaintext:
        val = ("%02X" % (ord(c) ^ next(keystream)))  
        res.append(val)
    return ''.join(res)

def RC4_decrypt(key, ciphertext_hex):
    key = [ord(c) for c in key]
    S = KSA(key)
    keystream = PRGA(S)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    res = ''.join(chr(b ^ next(keystream)) for b in ciphertext_bytes)
    return res


key = "secretkey"
plaintext = "SRM University AP"

print("Original:", plaintext)
encrypted = RC4(key, plaintext)
print("Encrypted (hex):", encrypted)
decrypted = RC4_decrypt(key, encrypted)
print("Decrypted:", decrypted)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text


def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)  # ECB for simplicity
    padded_text = pad(plaintext).encode('utf-8')
    ciphertext = cipher.encrypt(padded_text)
    return base64.b64encode(ciphertext).decode('utf-8')


def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded_ct = base64.b64decode(ciphertext)
    plaintext = cipher.decrypt(decoded_ct).decode('utf-8').rstrip(' ')
    return plaintext


key = get_random_bytes(16)  
plaintext = "SRM University AP"

print("Original:", plaintext)
encrypted = aes_encrypt(key, plaintext)
print("Encrypted:", encrypted)
decrypted = aes_decrypt(key, encrypted)
print("Decrypted:", decrypted)

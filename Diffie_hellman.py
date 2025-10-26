# Diffie-Hellman Key Exchange Implementation

# Publicly known values (agreed upon by both parties)
# p = prime number, g = primitive root modulo p
p = 23
g = 5

print("Publicly shared values:")
print("Prime number (p):", p)
print("Primitive root (g):", g)

# ---- Client Side ----
a = int(input("\nClient: Enter your private key (a): "))
A = (g ** a) % p     # Client computes g^a mod p
print("Client sends this value to Server (A):", A)

# ---- Server Side ----
b = int(input("\nServer: Enter your private key (b): "))
B = (g ** b) % p     # Server computes g^b mod p
print("Server sends this value to Client (B):", B)

# ---- Shared Secret Calculation ----
# Client computes key = B^a mod p
client_key = (B ** a) % p

# Server computes key = A^b mod p
server_key = (A ** b) % p

print("\nClient's computed shared key:", client_key)
print("Server's computed shared key:", server_key)

if client_key == server_key:
    print("\n Key Exchange Successful! Shared Secret Key =", client_key)
else:
    print("\n Key mismatch! Something went wrong.")

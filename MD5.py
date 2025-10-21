import hashlib

def generate_signature(message):
    """Generate MD5 signature for a given message."""
    md5_hash = hashlib.md5(message.encode())
    return md5_hash.hexdigest()

def authenticate_signature(received_message, received_signature):
    """Verify the authenticity of a message using MD5 hash."""
    calculated_signature = generate_signature(received_message)
    if calculated_signature == received_signature:
        print("✅ Signature is authentic. Message not altered.")
    else:
        print("❌ Signature mismatch! Message may have been tampered.")

# --- Example Usage ---

# Sender side
original_message = "This is a confidential message."
signature = generate_signature(original_message)
print("Generated Signature (MD5):", signature)

# Receiver side
received_message = "This is a confidential message."   # same message
received_signature = signature                          # signature sent by sender

# Authenticate
authenticate_signature(received_message, received_signature)



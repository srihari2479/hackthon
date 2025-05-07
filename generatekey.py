from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()

# Encrypt a message
cipher = Fernet(key)
encrypted_message = cipher.encrypt(b"This is a secret")
print("Encrypted:", encrypted_message)

# Decrypt the message
decrypted_message = cipher.decrypt(encrypted_message)
print("Decrypted:", decrypted_message.decode())

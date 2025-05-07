from cryptography.fernet import Fernet
import os

# Generate a key and write it to a file if it doesn't exist
def load_encryption_key():
    key_path = "key.env"
    if os.path.exists(key_path):
        with open(key_path, "rb") as file:
            key = file.read()
        try:
            Fernet(key)  # Validate key
            print(f"Loaded key from key.env: {key}")  # Debug: Print loaded key
            return key
        except ValueError:
            print("Invalid key format, generating a new key...")
            os.remove(key_path)
    # Generate a new key if it doesn't exist
    key = Fernet.generate_key()
    with open(key_path, "wb") as file:
        file.write(key)
    print(f"Generated new key: {key}")  # Debug: Print generated key
    return key

# Initialize cipher (encryption and decryption)
fernet_key = load_encryption_key()  # Load the encryption key
cipher = Fernet(fernet_key)  # Initialize the cipher object with the key

# Encrypt a message
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

# Decrypt a message
def decrypt_password(encrypted_password):
    try:
        return cipher.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return None

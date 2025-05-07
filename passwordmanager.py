import os  # Add this import at the top of the file
from cryptography.fernet import Fernet
from database import get_db, close_db

# Load the encryption key from the environment variable or file
def load_encryption_key():
    key_path = "key.env"
    
    if os.path.exists(key_path):
        with open(key_path, "rb") as file:
            key = file.read()
        try:
            # Ensure the key is valid (32 bytes base64 URL-safe)
            Fernet(key)  # This will validate the key format
            return key
        except ValueError:
            # If the key is invalid, delete the old key and generate a new one
            print("Invalid key format, generating a new key...")
            os.remove(key_path)  # Remove the invalid key file
            key = Fernet.generate_key()  # Generate a new valid Fernet key
            with open(key_path, "wb") as file:
                file.write(key)
            return key
    else:
        # If the key doesn't exist, generate and save a new one
        key = Fernet.generate_key()
        with open(key_path, "wb") as file:
            file.write(key)
        return key

# Initialize the encryption system (Fernet)
fernet_key = load_encryption_key()
cipher = Fernet(fernet_key)  # This defines the cipher to be used for encryption/decryption

# ✅ Save a password to the database
def save_password(user_id, website, username, password):
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Encrypt the password before saving it
        encrypted_password = cipher.encrypt(password.encode()).decode()
        
        # Insert the new password into the database
        cursor.execute("INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)", 
                       (user_id, website, username, encrypted_password))
        db.commit()

    except Exception as e:
        print(f"Error saving password: {e}")
        raise
    finally:
        cursor.close()
        close_db(db)

# ✅ Get all saved passwords for a specific user
def get_saved_passwords(user_id):
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("SELECT id, website, username, password FROM passwords WHERE user_id = ?", (user_id,))
        passwords = cursor.fetchall()

        # Decrypt the passwords before displaying
        decrypted_passwords = []
        for password in passwords:
            decrypted_password = cipher.decrypt(password[3].encode()).decode()  # Column index 3 holds the encrypted password
            decrypted_passwords.append({
                'id': password[0],
                'website': password[1],
                'username': password[2],
                'password': decrypted_password
            })
        return decrypted_passwords

    except Exception as e:
        print(f"Error fetching saved passwords: {e}")
        raise
    finally:
        cursor.close()
        close_db(db)  

# ✅ Update Password Function
def update_password(password_id, new_password, user_id):
    db = get_db()
    cursor = db.cursor()

    try:
        # Encrypt the new password
        encrypted_password = cipher.encrypt(new_password.encode()).decode()

        cursor.execute("UPDATE passwords SET password = ? WHERE id = ? AND user_id = ?", 
                       (encrypted_password, password_id, user_id))
        db.commit()
        return True
    except Exception as e:
        print(f"Error updating password: {e}")
        db.rollback()
        return False
    finally:
        cursor.close()
        close_db(db)

# ✅ Delete Password Function
def delete_password_entry(password_id, user_id):
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (password_id, user_id))
        db.commit()
        return True
    except Exception as e:
        print(f"Error deleting password: {e}")
        db.rollback()
        return False
    finally:
        cursor.close()
        close_db(db)

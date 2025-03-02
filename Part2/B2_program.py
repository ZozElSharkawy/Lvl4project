import string
import secrets
from cryptography.fernet import Fernet
import hashlib

def get_user_input():
    #Gets domain, username and password from user with validation
        try:
            domain = input("Enter domain (e.g. https://www.example.com): ").strip()
            username = input("Enter username: ").strip()
            while True:
                password = input("Enter password: ").strip()
                strength = evaluate_password(password)
                if strength == "Compliant":
                    break
                print("Password requirements not met:\n" + strength)
            return domain, username, password
        except Exception as e:
            print("Error during input:", e)
            raise
def evaluate_password(password):
    # List to store any password requirement errors
    errors = []
    # Password strength validation 
    if len(password) < 12:
        errors.append("Password must contain at least 12 characters.")
    if not any(char.isupper() for char in password):
        errors.append("Password must contain at least 1 uppercase character.")
    if not any(char.islower() for char in password):
        errors.append("Password must contain at least 1 lowercase character.")
    if not any(char.isdigit() for char in password):
        errors.append("Password must contain at least 1 digit.")
    if not any(char in string.punctuation for char in password):
        errors.append("Password must contain at least 1 special character.")

    return "Compliant" if not errors else "Non-compliant:\n" + "\n".join(errors)

def encrypt_password(password): 
    # Function encrypts password using Fernet symmetric encryption
    try:
        key = Fernet.generate_key()  # Secure random key
        f = Fernet(key)
        encrypted_password = f.encrypt(password.encode())
        return key.decode(), encrypted_password.decode()
    except Exception as e:
        print("Encryption error:", e)
        raise

def hash_password(password):
    # Function creates SHA-256 hash of password
    try:
        return hashlib.sha256(password.encode()).hexdigest()
    except Exception as e:
        print("Hashing error:", e)
        raise

def store_password(domain, username, key, encrypted_pass, pass_hash):
    # Function stores password entry in password file
    try:
        entry = f"{domain}:{username}:{key}:{encrypted_pass}:{pass_hash}\n"
        with open("passwords.txt", "a") as f:
            f.write(entry)
        print("Password stored successfully!")
    except Exception as e:
        print("Error storing password:", e)
        raise

def main():
    try:
    # Get user input
        domain, username, password = get_user_input()
    
    # Encrypt password
        encryption_key, encrypted_password = encrypt_password(password)
    
    # Hash password
        password_hash = hash_password(password)
    
    # Store entry
        store_password(domain, username, encryption_key, encrypted_password, password_hash)
        print("Password stored successfully!")
    except Exception as e:
        print("An unexpected error occurred:", e)

if __name__ == "__main__":
    main()
import hashlib
import secrets
import os

def create_master_key():
    while True:
        master_key = input("Create your master key (minimum 12 characters): ")
        if len(master_key) >= 12: # Check if the key length is at least 12 and meets strength requirements
            if validate_password_strength(master_key):
                return master_key
        print("Password must be at least 12 characters and contain uppercase, lowercase, numbers and special characters")

def validate_password_strength(password): 
    # Function for password strength validation
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return all([has_upper, has_lower, has_digit, has_special])

def hash_master_key(master_key): 
    #Function returns the salt and hash separated by a '$'
    salt = secrets.token_hex(16)
    key_with_salt = (master_key + salt).encode('utf-8')
    hashed_key = hashlib.sha256(key_with_salt).hexdigest()
    return f"{salt}${hashed_key}"

def store_master_key(hashed_key):
    with open("master_key.hash", "w") as file:
        file.write(hashed_key)

def verify_master_key(input_key, stored_hash): 
    #Function compares the computed hash with the stored hash
    salt = stored_hash.split('$')[0]
    key_with_salt = (input_key + salt).encode('utf-8')
    hashed_input = hashlib.sha256(key_with_salt).hexdigest()
    return hashed_input == stored_hash.split('$')[1]


def main():
    if os.path.exists("master_key.hash"):
        print("Master key already exists! Please use your existing master key.")
        return
        
    print("Welcome! Please create your master key.")
    master_key = create_master_key()
    hashed_key = hash_master_key(master_key)
    store_master_key(hashed_key)
    print("Master key created and hashed successfully!")

if __name__ == "__main__":
    main()
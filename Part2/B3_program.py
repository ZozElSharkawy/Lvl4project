import hashlib
import os
import time
from cryptography.fernet import Fernet

# Maximum number of allowed master key attempts
MAX_ATTEMPTS = 3
# Lockout time in seconds after exceeding allowed attempts
LOCKOUT_TIME = 30  # seconds

def verify_master_key():
    """
    Verify the master key by prompting the user and comparing the hashed input with the stored hash.
    
    The stored master key hash file ("master_key.hash") is expected to have the format:
        salt$hashed_master_key
        
    Returns:
      True if authentication is successful, False otherwise.
    """
    if not os.path.exists("master_key.hash"):
        print("Master key hash file not found. Please create your master key first.")
        return False

    # Read the stored salt and hashed master key from the file.
    try:
        with open("master_key.hash", "r") as f:
            stored_data = f.read().strip()
            salt, stored_hash = stored_data.split('$')
    except Exception as e:
        print("Error reading master key hash:", e)
        return False

    attempts = 0
    while attempts < MAX_ATTEMPTS:
        input_key = input("Enter master key: ")
        # Combine the user-provided key with the stored salt and hash it using SHA-256.
        key_with_salt = (input_key + salt).encode('utf-8')
        input_hash = hashlib.sha256(key_with_salt).hexdigest()
        if input_hash == stored_hash:
            # Successful authentication
            return True
        else:
            attempts += 1
            print(f"Invalid master key. {MAX_ATTEMPTS - attempts} attempts remaining.")
    
    # If maximum attempts are exceeded, enforce a lockout.
    print(f"Too many failed attempts. System locked for {LOCKOUT_TIME} seconds.")
    time.sleep(LOCKOUT_TIME)
    return False

def decrypt_password(encrypted_pass, encryption_key):
    """
    Decrypts the encrypted password using Fernet symmetric encryption.
    
    Parameters:
      encrypted_pass: The encrypted password as a string.
      encryption_key: The encryption key (a base64-encoded string) used to encrypt the password.
    
    Returns:
      The decrypted password as a string.
    
    Raises:
      ValueError if decryption fails.
    """
    try:
        # Create a Fernet instance with the provided encryption key.
        f = Fernet(encryption_key.encode())
        # Decrypt the password (Fernet tokens are strings, so encode before decrypting)
        decrypted = f.decrypt(encrypted_pass.encode()).decode()
        return decrypted
    except Exception as e:
        raise ValueError("Error during decryption: " + str(e))

def retrieve_password():
    """
    Retrieve and decrypt the password for a user-requested domain.
    
    Process:
      1. Authenticate the user by prompting for the master key.
      2. If authenticated, prompt for the domain to search.
      3. Open the passwords file ("passwords.txt"), where each line is expected to have the format:
             domain:username:encryption_key:encrypted_password:password_hash
         (Using rsplit with a maxsplit of 4 ensures that any colons in the domain field are handled correctly.)
      4. If the requested domain is found, decrypt the password and display the credentials.
    """
    if not verify_master_key():
        print("Access denied.")
        return
    
    # Prompt for the domain to search (e.g., "https://www.example.com")
    search_domain = input("Enter domain to search: ").strip()

    if not os.path.exists("passwords.txt"):
        print("Passwords file not found.")
        return

    # Open and iterate through each line in the passwords file.
    with open("passwords.txt", "r") as f:
        for line in f:
            # Use rsplit to split the line into 5 parts from the right.
            parts = line.strip().rsplit(':', 4)
            if len(parts) < 5:
                continue  # Skip any malformed lines
            
            # Extract the components:
            # parts[0]: domain (which may include colons, e.g. "https://www.google.com")
            # parts[1]: username
            # parts[2]: encryption key (base64-encoded string)
            # parts[3]: encrypted password (Fernet token)
            # parts[4]: hash of the original password (not used for decryption)
            stored_domain, username, encryption_key, encrypted_pass, pass_hash = parts

            # Check if the stored domain matches the user's search
            if stored_domain == search_domain:
                try:
                    # Decrypt the password using the stored encryption key
                    decrypted_password = decrypt_password(encrypted_pass, encryption_key)
                    print("\nFound credentials:")
                    print(f"Domain:   {stored_domain}")
                    print(f"Username: {username}")
                    print(f"Password: {decrypted_password}")
                    return
                except Exception as e:
                    print("Error decrypting password:", e)
                    return
    print("Domain not found.")

def main():
    """
    Main function to run the password retrieval process.
    """
    retrieve_password()

if __name__ == "__main__":
    main()

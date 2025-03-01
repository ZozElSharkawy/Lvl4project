#!/bin/bash
# password_manager.sh
# Main menu for interacting with the password manager.
# Provides options for adding a new password or retrieving an existing password.
# Assumes that the Python scripts (B2_program.py and B3_program.py) handle
# master key authentication and secure password processing.

echo "Welcome to the Password Manager"
echo "Please choose an option:"
echo "1. Add a new password"
echo "2. Retrieve an existing password"
echo "3. Exit"

read -p "Enter your choice [1-3]: " CHOICE

case $CHOICE in
    1)
        # Call the script to add a new password
        echo "Starting the process to add a new password..."
        python B2_program.py
        STATUS=$?
        if [ $STATUS -eq 0 ]; then
            echo "New password entry added successfully."
        else
            echo "Error: Adding new password failed with exit code $STATUS."
        fi
        ;;
    2)
        # Prompt for domain and call the script to retrieve a password
        read -p "Enter the domain name for which to retrieve the password: " DOMAIN
        echo "Retrieving password for $DOMAIN..."
        python B3_program.py "$DOMAIN"
        STATUS=$?
        if [ $STATUS -eq 0 ]; then
            echo "Password retrieval completed."
        else
            echo "Error: Password retrieval failed with exit code $STATUS."
        fi
        ;;
    3)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

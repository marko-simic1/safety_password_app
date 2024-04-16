# safety_password_app
Project Description
This project consists of three distinct functionalities, separated into three Python scripts, all related to security and data protection.

User Account Management (usermgmt.py): This script allows for adding, changing, deleting user accounts, and checking integrity and security during login. User passwords are encrypted using AES encryption and HMAC for integrity verification.

Simple log in (login.py): This script provides basic mathematical operations after successful user login. This functionality is integrated with the previous user management script to ensure secure access.

Password Management (password_manager.py): This script allows the user to add new passwords for web addresses and securely store them. Passwords are encrypted and stored in a database using AES encryption and HMAC for integrity verification.

# Repository Structure
The repository contains three Python scripts:
- usermgmt.py: Script for managing user accounts.
- login.py: Script for a simple calculator after user login.
- password_manager.py: Script for managing passwords for web addresses.

First, install all required packages listed in the project's requirements.
Each script contains an if __name__ == "__main__": block, meaning each script can be run directly.
Run each script individually according to your project's needs.

# Requirements
This project requires the following:
- Python 3.x
- Installed packages listed in the scripts, such as Crypto, base64, os, sqlite3, hashlib, getpass, hmac, json.

# Usage Instructions
Start by running the usermgmt.py script to add users and manage their accounts.
After adding users, you can run the login.py script to access the calculator.
You can use the password_manager.py script to store and retrieve passwords for web addresses.
Note: Each time you run, the system will prompt you to enter the master password. This password is used for data decryption and ensures data security in the database.

Notes
Make sure to securely store the master password as it is crucial for accessing your data.
It is recommended to regularly check the integrity of the database to ensure the security and integrity of your data.

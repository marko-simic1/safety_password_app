# 🛡️ Safety Password App - Secure Your Digital World 🔒

**Safety Password App** is a comprehensive security solution, designed to manage user accounts, passwords, and provide secure login functionality. This project consists of three distinct Python scripts, each playing a vital role in ensuring data protection and security. Let the magic of cryptography guard your sensitive information!

---

## 🌟 Project Overview

### 1. **User Account Management (`usermgmt.py`)**
   Manage users effortlessly while keeping their data secure. This script handles:
   - Adding, modifying, and deleting user accounts.
   - Enforcing secure logins with password encryption.
   - **AES Encryption** for user passwords.
   - **HMAC** for ensuring the integrity of data.

### 2. **Secure Login with Calculator (`login.py`)**
   Login safely and access basic mathematical operations. This script:
   - Validates user credentials using the `usermgmt.py` system.
   - Grants access to a simple, yet secure calculator interface post-login.
   - Perfect for keeping users engaged while ensuring access control.

### 3. **Password Management (`password_manager.py`)**
   Securely store all your web-based passwords. This script:
   - Allows users to store and retrieve passwords linked to websites.
   - Safeguards passwords with **AES Encryption** and **HMAC**.
   - Saves passwords in a secure database, ensuring data confidentiality.

---

## 🗂️ Repository Structure

Here’s how the repository is structured:

- **`usermgmt.py`**: Manages user accounts and handles secure logins.
- **`login.py`**: Provides secure access to a basic calculator post-login.
- **`password_manager.py`**: Stores and retrieves web passwords securely.

Each script contains a `if __name__ == "__main__":` block, meaning you can run them individually based on what you need.

---

## ⚙️ Requirements

Ensure your environment is set up for security by installing the following:

- **Python 3.x**
- Required Python packages, including:
  - `pycryptodome` for cryptographic functions
  - `base64`, `os`, `sqlite3`, `hashlib`, `getpass`, `hmac`, `json`

Before running, install dependencies with:
```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage Instructions

### 1. **User Account Setup** 🧑‍💻
   Start with user management:
   ```bash
   python3 usermgmt.py
   ```
   Here, you can add new users, delete accounts, and manage user data securely. All passwords will be encrypted before they are stored.

### 2. **Secure Login & Calculator Access** 🔢
   Once users are set up, run the login script:
   ```bash
   python3 login.py
   ```
   After successfully logging in, you’ll have access to basic mathematical operations. No user is left behind, and no data is compromised!

### 3. **Manage Passwords Securely** 🔑
   For managing your web passwords, use the password manager:
   ```bash
   python3 password_manager.py
   ```
   Every time you run the script, the system will ask for the **master password**, which is used to decrypt your stored passwords. Make sure to keep it safe!

---

## 🔐 Important Notes

- **Master Password**: This is the key to unlocking your encrypted data. Make sure it is stored securely.
- **Data Integrity**: Regularly check the integrity of the database to ensure your data remains safe and uncompromised.

---

Embrace the magic of encryption and protect your sensitive information with **Safety Password App**! Stay safe, stay secure. 🌟

---

**📝 License**: This project is licensed under the **University of Zagreb Faculty of Electrical Engineering and Computing**, Laboratory for Robotics and Intelligent Control Systems.

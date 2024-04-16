#using https://docs.python.org/3/library/sqlite3.html & https://www.tutorialspoint.com/python_data_access/python_sqlite_cursor_object.htm
import os
import sqlite3
import hashlib
import getpass
import hmac
import base64
from Crypto.Cipher import AES
import keyring

def check_pw(new_pw):
    return len(new_pw) >= 8 and any(char.isdigit() for char in new_pw)

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(nonce + ciphertext + tag).decode()

def decrypt_data(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data.encode())
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:-16]
    tag = encrypted_data[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data

def generate_secret_key():
    return os.urandom(32)

def load_secret_key():
    try:
        with open('secret_key.key', 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print("**Tajni ključ nije pronađen.")
        return None

def save_secret_key(key):
    with open('secret_key.key', 'wb') as f:
        f.write(key)

def gsalt():
    return os.urandom(32)

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000)

def add(user, pw):
    secret_key = load_secret_key()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT username FROM users WHERE username = ?', (user,))
    existing_user = cursor.fetchone()
    if existing_user:
        print("**Korisnik s tim korisničkim imenom već postoji.")
        conn.close()
        return

    salt = gsalt()
    hashed_pw = hash_pw(pw, salt)
    
    encrypted_pw = encrypt_data(hashed_pw, secret_key)
    
    hmac_hash = hmac.new(secret_key, digestmod='sha256')
    hmac_hash.update(user.encode())
    hmac_hash.update(encrypted_pw.encode())
    
    cursor.execute('INSERT INTO users (username, password, salt, hmac) VALUES (?, ?, ?, ?)', (user, encrypted_pw, salt, hmac_hash.digest()))
    
    conn.commit()
    print("**Korisnik uspiješno dodan.")
    conn.close()

def check(user):
    secret_key = load_secret_key()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('SELECT username, password, salt, force_change, hmac FROM users WHERE username = ?', (user,))

    db_data = cursor.fetchone()
    if db_data:
        if db_data[0] == user:
            conn.close()
            return user, db_data[1], db_data[2], db_data[3], db_data[4]

    conn.close()
    return None

def passwd(user, pw):
    secret_key = load_secret_key()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('SELECT username, password, salt, force_change, hmac FROM users WHERE username = ?', (user,))
    
    db_data = cursor.fetchone()
    if db_data:
        if db_data[0] == user:
            salt = gsalt()
            hashed_pw = hash_pw(pw, salt)
            encrypted_pw = encrypt_data(hashed_pw, secret_key)
        
            hmac_hash = hmac.new(secret_key, digestmod='sha256')
            hmac_hash.update(user.encode())
            hmac_hash.update(encrypted_pw.encode())
        
            cursor.execute('UPDATE users SET password = ?, salt = ?, hmac = ? WHERE username = ?', (encrypted_pw, salt, hmac_hash.digest(), user))
        
            conn.commit()
            conn.close()
            print("**Lozinka korisnika {} uspješno promijenjena.".format(user))
        else:
            print("**Greška prilikom provjere korisničkog imena.")
    else:
        print("**Korisničko ime nije u sustavu.")

def forcepass(user):
    secret_key = load_secret_key()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('UPDATE users SET force_change = 1 WHERE username = ?', (user,))

    conn.commit()
    conn.close()

def dell(user):
    secret_key = load_secret_key()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('DELETE FROM users WHERE username = ?', (user,))

    conn.commit()
    conn.close()

def create_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, salt BLOB, force_change INTEGER DEFAULT 0, hmac BLOB)')
    conn.commit()
    conn.close()

def main():
    create_db()

    if not load_secret_key():
        key = generate_secret_key()
        save_secret_key(key)

    while True:
        secret_key = load_secret_key()  
        print("\n1. Dodaj novog korisnika")
        print("2. Promijeni lozinku korisnika")
        print("3. Forsiraj promjenu lozinke korisnika")
        print("4. Ukloni korisnika")
        print("5. Izlaz")
        
        num = input("\nOdaberi opciju: ")
        
        if num == '1':
            user = input("Unesite korisničko ime: ")
            pw = getpass.getpass("Unesite lozinku: ")
            if check_pw(pw) == False:
                print("**Lozinka mora imati min. 8 znakova i bar jednu znamenku.")
            else:
                add(user, pw)
        
        elif num == '2':
            user = input("Unesite korisničko ime: ")
            user_exists = check(user)
            if user_exists:
                pw = getpass.getpass("Unesite novu lozinku: ")
                if check_pw(pw) == False:
                    print("**Lozinka mora imati min. 8 znakova i bar jednu znamenku.")
                else:
                    passwd(user, pw)
                    print("**Lozinka korisnika {} uspješno promijenjena.".format(user))
            else:
                print("**Korisničko ime nije u sustavu.")
        
        elif num == '3':
            user = input("Unesite korisničko ime: ")
            user_exists = check(user)
            if user_exists:
                forcepass(user)
                print("**Forsirana promjena lozinke za korisnika {}.".format(user))
            else:
                print("**Korisničko ime nije u sustavu.")
        
        elif num == '4':
            user = input("Unesite korisničko ime: ")
            user_exists = check(user)
           
            if user_exists:
                dell(user)
                print("**Korisnik {} uspješno uklonjen.".format(user))
            else:
                print("**Korisničko ime nije u sustavu.")
        
        elif num == '5':
            break
        
        else:
            print("**Krivi odabir!")

if __name__ == "__main__":
    main()

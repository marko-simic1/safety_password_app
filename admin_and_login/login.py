#using https://docs.python.org/3/library/sqlite3.html & https://www.tutorialspoint.com/python_data_access/python_sqlite_cursor_object.htm
import sqlite3
import hashlib
import os
import getpass
import hmac
import base64
from Crypto.Cipher import AES
import keyring

def zbroj(a, b):
    return a + b

def razlika(a, b):
    return a - b

def umnozak(a, b):
    return a * b

def kolicnik(a, b):
    if b == 0:
        return "**Dijeljenje s nulom nije moguće."
    else:
        return a / b

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

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000)

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

def verify_hmac(user, encrypted_pw, secret_key, saved_hmac):
    hmac_hash = hmac.new(secret_key, digestmod='sha256')
    hmac_hash.update(user.encode())
    hmac_hash.update(encrypted_pw.encode())
    
    return hmac_hash.digest() == saved_hmac

def check_pw(new_pw):
    return len(new_pw) >= 8 and any(char.isdigit() for char in new_pw)


def login(user, pw):
    secret_key = load_secret_key()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('SELECT username, password, salt, force_change, hmac FROM users WHERE username = ?', (user,))
    right_pw = False
    db_data = cursor.fetchone()
    
    if db_data:
        stored_user, stored_pw, salt, force_change, hmac_value = db_data
        secret_key = load_secret_key()
        if not secret_key:
            conn.close()
            return False

        if verify_hmac(user, stored_pw, secret_key, hmac_value):
            hashed_pw = hash_pw(pw, salt)
            decrypted_stored_pw = decrypt_data(stored_pw, secret_key)
            
            if hashed_pw == decrypted_stored_pw:
                if force_change == 1:
                    while(right_pw == False):
                        print("**Morate promijeniti lozinku.")
                        new_pw = getpass.getpass("Nova lozinka: ")
                        confirm_new_pw = getpass.getpass("Ponovite novu lozinku: ")
                        if check_pw(new_pw):
                            right_pw = True
                            if new_pw == confirm_new_pw:
                                hashed_new_pw = hash_pw(new_pw, salt)
                                encrypted_new_pw = encrypt_data(hashed_new_pw, secret_key)

                                hmac_hash = hmac.new(secret_key, digestmod='sha256')
                                hmac_hash.update(user.encode())
                                hmac_hash.update(encrypted_new_pw.encode())  # encode the string to bytes

                                cursor.execute('UPDATE users SET password = ?, force_change = 0, hmac = ? WHERE username = ?', (encrypted_new_pw, hmac_hash.digest(), user))
                                conn.commit()
                                print("**Lozinka uspješno promijenjena.")
                            else:
                                print("**Lozinke se ne podudaraju, pokušajte ponovno.")
                        else:
                            print("**Lozinka mora imati min. 8 znakova i bar jednu znamenku.")
                else:
                    print("**Prijava uspješna.")
                    conn.close()
                    return True
            else:
                print("**Korisničko ime ili lozinka netočni.")
        else:
            print("**Korisničko ime ili lozinka netočni.")
    else:
        print("**Korisničko ime ili lozinka netočni.")
        
    conn.close()
    return False

if __name__ == "__main__":
    user = input("Unesite korisničko ime: ")
    pw = getpass.getpass("Unesite lozinku: ")
    
    if login(user, pw):
        print("\nUspješno ste pristupili kalkulatoru :)\n")
        print("Odaberite operaciju:")
        print("1. Zbrajanje")
        print("2. Oduzimanje")
        print("3. Množenje")
        print("4. Dijeljenje")

        operacija = input("Unesite broj operacije (1/2/3/4): ")
        broj1 = float(input("Unesite prvi broj: "))
        broj2 = float(input("Unesite drugi broj: "))

        if operacija == '1':
            print("Zbroj:", zbroj(broj1, broj2))
        elif operacija == '2':
            print("Razlika:", razlika(broj1, broj2))
        elif operacija == '3':
            print("Umnožak:", umnozak(broj1, broj2))
        elif operacija == '4':
            print("Količnik:", kolicnik(broj1, broj2))
        else:
            print("Pogrešan unos operacije.")

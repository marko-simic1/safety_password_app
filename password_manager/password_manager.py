from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import base64
import os
import json
import getpass
import hashlib

DB_FILE = "passwords.db"
MP_FILE = "mp.json"
AES_KEY_SIZE = 32  
HMAC_KEY_SIZE = 32  

def calc_db_hash(file):
    with open(file, "rb") as f:
        file_hash = hashlib.sha256()
        for x in iter(lambda: f.read(8192), b''):
            file_hash.update(x)
    return file_hash.hexdigest()

def db_integrity(file, stored_hash):
    calc_hash = calc_db_hash(file)
    if calc_hash != stored_hash:
        print(f"Pogreška usred provjere integriteta za: {file}!")
        return False
    else:
        return True

def mp_check(mp):
    mp_hash = hashlib.sha256(mp.encode()).hexdigest()

    if os.path.exists(MP_FILE):
        with open(MP_FILE, "r") as f:
            data = json.load(f)
        stored_hash = data["hash"]
        salt = base64.b64decode(data["salt"])

        if stored_hash != mp_hash:
            print("Netočna lozinka!")
            return False, None
    else:
        salt = get_random_bytes(16)
        data = {"hash": mp_hash, "salt": base64.b64encode(salt).decode()}
        with open(MP_FILE, "w") as f:
            json.dump(data, f)

    return True, salt

def derive_keys(mp, salt):
    key = PBKDF2(mp, salt, dkLen=AES_KEY_SIZE + HMAC_KEY_SIZE)
    hmac_key = key[AES_KEY_SIZE:]
    aes_key = key[:AES_KEY_SIZE]
    return aes_key, hmac_key

def compute_hmac(data, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data.encode())
    return h.hexdigest()

def encrypt(txt, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(txt.encode())
    return urlsafe_b64encode(cipher.nonce + ciphertext + tag).decode()

def decrypt(ciphertext, key):
    data = urlsafe_b64decode(ciphertext)
    nonce, ciphertext, tag = data[:16], data[16:-16], data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def add_password(aes_key, hmac_key):
    address = input("Unesite web adresu: ")
    password = getpass.getpass("Unesite lozinku za navedenu adresu: ")

    hashed_address = hashlib.sha256(address.encode()).hexdigest()

    encrypted_password = encrypt(password, aes_key)
    hmac = compute_hmac(hashed_address, hmac_key)

    with open(DB_FILE, "r") as f:
        data = json.load(f)
    data[hashed_address] = {"hmac": hmac, "lozinka": encrypted_password}
    with open(DB_FILE, "w") as f:
        json.dump(data, f)
    print("Lozinka uspiješno spremljena!")

def retrieve_password(aes_key, hmac_key):
    address = input("Unesite web adresu: ")

    hashed_address = hashlib.sha256(address.encode()).hexdigest()

    with open(DB_FILE, "r") as f:
        data = json.load(f)
    if hashed_address in data:
        stored_hmac = data[hashed_address]["hmac"]
        calc_hmac = compute_hmac(hashed_address, hmac_key)
        if stored_hmac == calc_hmac:
            encrypted_password = data[hashed_address]["lozinka"]
            password = decrypt(encrypted_password, aes_key)
            print(f"Lozinka za {address}: {password}")
        else:
            print("Provjera integriteta nije uspjela. Dohvaćanje lozinke odbijeno!")
    else:
        print(f"Ne postoji lozinka za web adresu: {address}")

def initialize_db():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({}, f)

if __name__ == "__main__":

    initialize_db()
    db_hash = calc_db_hash(DB_FILE)

    if not db_integrity(DB_FILE, db_hash):
        print("Baza podataka je kompromitirana!")
        exit(1)

    mp = getpass.getpass("Unesite master lozinku: ")

    valid, salt = mp_check(mp)
    if not valid:
        exit(1)

    aes_key, hmac_key = derive_keys(mp, salt)

    while True:
        print("\nIzaberite jednu od sljedećih opcija:")
        print("1. Dodajte novu lozinku za web adresu")
        print("2. Saznajte lozinku")
        print("3. Izlaz")
        num = input("Odaberite opciju: ")

        if num == "1":
            add_password(aes_key, hmac_key)
        elif num == "2":
            retrieve_password(aes_key, hmac_key)
        elif num == "3":
            break
        else:
            print("Neispravan izbor. Molimo odaberite 1, 2, ili 3.")
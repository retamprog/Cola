## this is the python file for AES-256 based encryption
import os
import json 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

def derive_key(master_pass:str,salt:bytes):
   
    kdf = Argon2id(
            salt = salt,
            length = 32,
            iterations=1,
            lanes = 4,
            memory_cost=64*1024,
            ad=None,
            secret=None
    )
    return kdf.derive(master_pass.encode())

def encrypt_vault(master_pass:str,data:dict):
    salt = os.urandom(16)
    print("this is the salt " ,salt)
    key = derive_key(master_pass,salt)
    nonce = os.urandom(12)
    print("This is the nonce ",nonce)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce,plaintext,None)
    return salt + nonce + ciphertext


def decrypt_vault(master_pass:str,blob:bytes):
    salt = blob[:16]
    nonce = blob[16:28]
    enc_data = blob[28:]
    key = derive_key(master_pass,salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce,enc_data,None)
        return json.loads(plaintext)
    except (InvalidTag,ValueError):
        raise ValueError("wrong password or corrupted vault!!")
        
    

if __name__ == '__main__':
    
   pass
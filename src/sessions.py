'''
Sessions.py - used to create a temp session for caching of master password in the RAM of the device for a short duration of time
like 15mins
'''
import os
from pathlib import Path 
import time
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import hashlib

# session_ttl --> the time till the session is live for 15 mins(900 secs) after that the user will again be prompted to type the passwd for further edit work
SESSION_TTL = 900 
# this function will get the file path for the particular session to be created for that particular time period

def get_bootid():
    with open("/proc/sys/kernel/random/boot_id","r") as f:
        return f.read().strip()
def _session_path():
    uid = os.getuid()
    return Path(f"/run/user/{uid}/.cola_session")

# listen we will use the bootid and uid of the user
def get_session_key():
    boot_id=get_bootid()
    uid = str(os.getuid())
    unhashed_key = (boot_id+uid).encode()
    # here we are going to return our AES key for encryption of the master pass string 
    return hashlib.sha256(unhashed_key).digest()
    
    
    
def session_start(master_pass:str):
    # use the aes key from session_key() function to to enc the master pass string
    # here the plaintext is the master_pass
    key = get_session_key()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce,master_pass.encode(),None)
    ct_data = base64.b64encode(nonce).decode('utf-8')+"."+base64.b64encode(ct).decode('utf-8') # the final data having the nonce . ciphertext data
    
    session_path = _session_path()
    json_data = {
        "data" : ct_data,
        "TTL" : time.time()+SESSION_TTL
    }
    with open(session_path/".cola_session.json","w") as json_file:
        json.dump(json_data,json_file,indent = 4)


def load_session():
    key = get_session_key() # init aes key for decryption

def check_session():
    pass


if __name__=='__main__':
    print(get_session_key())
    
    
        

'''
Sessions.py - used to create a temp session for caching of master password in the RAM of the device for a short duration of time
like 15mins 
For featuring the auto-lock mechanism of the cli application and removing the need to manually type master_pass every single time

'''
from json.decoder import JSONDecodeError
import os
from pathlib import Path 
import time
import base64
import json
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
    return Path(f"/run/user/{uid}/cola.session")

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
    
    session_file = _session_path()
    json_data = {
        "data" : ct_data,
        "expires_at" : time.time()+SESSION_TTL
    }
    
    
    session_file.write_text(json.dumps(json_data))
    session_file.chmod(0o600)
    print("Session created successfully!!!")    

# this fucn is going to be used when we cola add or do any edit work which is going to need the cached passwd
def load_session()->str|None:
    key = get_session_key() # init aes key for decryption
    aes = AESGCM(key)
    json_data={}
    session_file = _session_path()
    if not session_file.exists():
        return None
    try:
        json_data = json.loads(session_file.read_text())
        nonce_str,ct_str = json_data["data"].split(".",1)
        nonce = base64.b64decode(nonce_str.encode('utf-8'))
        ct = base64.b64decode(ct_str.encode('utf-8'))   
        if time.time() > json_data["expires_at"]:
            session_file.unlink()
            return None
        
        master_pass = aes.decrypt(nonce,ct,None).decode()
        return master_pass
    except(KeyError,JSONDecodeError):
        session_file.unlink(missing_ok=True)
        return None
        
# Boolean session file deleter     
def delete_session()->bool:
    session_file = _session_path()
    if session_file.exists():
        session_file.unlink()
        print("Session deleted successfully!!")
        return True
    return False    
    
# session existence checker    
def check_session()->bool:
    return load_session() is not None

if __name__=='__main__':
    pass
    # print(get_session_key())
    # session_start("retam112004")
    # print(session_start("retam112004"))
    # print(load_session())
    # print(delete_session())
    print(check_session())
        

'''
Sessions.py - used to create a temp session for caching of master password in the RAM of the device for a short duration of time
like 15mins 
For featuring the auto-lock mechanism of the cli application and removing the need to manually type master_pass every single time

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
    session_path.mkdir(parents = True,exist_ok=True)
    
    with open(session_path/"cola_session.json","w") as json_file:
        json.dump(json_data,json_file,indent = 4)

    print("Session created successfully!!!")    

# this fucn is going to be used when we cola add or do any edit work which is going to need the cached passwd
def load_session()->str|None:
    key = get_session_key() # init aes key for decryption
    aes = AESGCM(key)
    json_data={}
    try:
        with open(_session_path()/"cola_session.json","r") as f:
            data = f.read()
            json_data = json.loads(data)
    except Exception as e:
        print("The error message : ",e)
      
    nonce_str,ct_str = json_data["data"].split(".",1)
    nonce = base64.b64decode(nonce_str.encode('utf-8'))
    ct = base64.b64decode(ct_str.encode('utf-8'))   
    if time.time() > json_data["TTL"]:
        return None
    
    master_pass = aes.decrypt(nonce,ct,None).decode()
    return master_pass
        
     
def delete_session():
    try:
        json_file_path = _session_path()/"cola_session.json"
        json_file_path.unlink(missing_ok=False)
    except FileNotFoundError:
        print("the session file does not exist !!")
def check_session():
    json_file_path = _session_path()/"cola_session.json"
    if json_file_path.is_file:
        print("the session exists!!")
        return True
    else:
        print("The session does not exist")
        return False


if __name__=='__main__':
    # print(get_session_key())
    # session_start("retam112004")
    print(load_session())
    
        

'''
Sessions.py - used to create a temp session for caching of master password in the RAM of the device for a short duration of time
like 15mins
'''
import os
from pathlib import Path 
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import hashlib

# session_ttl --> the time till the session is live for 15 mins(900 secs) after that the user will again be prompted to type the passwd for further edit work
SESSION_TTL = 900 
# this function will get the file path for the particular session to be created for that particular time period

def get_bootid():
    with open("/proc/sys/kernel/random/boot_id","r") as f:
        return f.read().strip()
def session_path():
    uid = os.getuid()
    return Path(f"/run/user/{uid}/.cola_session")

# listen we will use the bootid and uid of the user
def get_session_key():
    boot_id=get_bootid()
    uid = os.getuid()
    unhashed_key = boot_id+uid
    
    
    
    
def session_start(master_pass:str):
    pass

def load_session():
    pass

def check_session():
    pass


if __name__=='__main__':
    print(get_bootid())
    
    
        

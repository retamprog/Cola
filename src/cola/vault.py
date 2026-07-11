# from doctest import master
# import os

from pathlib import Path
import getpass 
import datetime
from .crypto import decrypt_vault, encrypt_vault

VAULT_PATH = Path.home() / ".cola" / "vault.enc"

# definitely need to change the init_vault function


def init_vault(master_pass: str):
    # VAULT_PATH.parent.mkdir(exist_ok=True)
    # VAULT_PATH.write_bytes(encrypt_vault(master_pass=master_pass,data={}))
    if VAULT_PATH.exists():
       print("the vault already exists !!! unlock it using cola unlock")
    else:
        VAULT_PATH.parent.mkdir(exist_ok=True)
        save_vault(master_pass, {"Owner":getpass.getuser(),"created_on":str(datetime.datetime.now()),"Entries":{}})
        print("vault created successfully using master password!")


def save_vault(master_pass: str, data: dict):
    VAULT_PATH.write_bytes(encrypt_vault(master_pass=master_pass, data=data))


def load_vault(master_pass: str):
    if not VAULT_PATH.exists():
        raise FileNotFoundError(
            "The vault does not exist !! use init cmd to create vault --> cola init"
        )
    
    return decrypt_vault(master_pass=master_pass, blob=VAULT_PATH.read_bytes())
   
# okay need to change this add_entry function for better password management
def add_entry(master_pass: str, name: str, username: str, password: str, url: str = ""):
    try:
        vault = load_vault(
            master_pass=master_pass
        )  # this gives the entire python dict data
    except (FileNotFoundError,ValueError) as e:
        print(e)
        return
    # vault.update({"Name":name,"Username": username, "Password": password, "url": url
    if name not in vault["Entries"]:
        vault["Entries"][name.lower()]=[]
    vault["Entries"][name.lower()].append({"username":username,"password":password,"url":url})
    save_vault(master_pass, vault)

# two parts of the function one is getting the element based on name and other one is username
def get_entry(master_pass: str, name: str,username:str=""):
    # vault = load_vault(master_pass = master_pass)
    try:
        vault =  load_vault(master_pass)
    except (FileNotFoundError,ValueError) as e:
        print(e)
        return
        
    if not username and not name:
        return vault["Entries"]
    try:    
        if username:
            return next((d for d in vault["Entries"][name] if d["username"]==username),None)
        else:
            return vault["Entries"][name]
    except Exception:
        print("Error in name or username please try again!!")
        
    
# now the chance has come to complete this mess of the delete function!!

def delete_entry(master_pass: str, name: str,username:str,vault:dict):
    try:
        if username and name:
            #that means both username and name have been provided
            idx = next((i for i,d in enumerate(vault["Entries"][name]) if d["username"]==username))
            vault["Entries"][name].pop(idx)
        elif name:
            del vault["Entries"][name]
        save_vault(master_pass,vault)    
    except Exception :
        print("Error in username or name!!!")
            

def del_vault():
    try:
        # first deleting the vault.enc file 
        VAULT_PATH.unlink(missing_ok=True)
        # Then deleting the parent directory .cola
        VAULT_PATH.parent.rmdir()
        print("Successfully deleted vault!!")
    except FileNotFoundError:
        print("the vault file does not exist!!")
    except OSError:
        print("The .cola hidden folder could not be deleted!!")
    
        
        
        


if __name__ == "__main__":
    # init_vault("retam")
    # print(load_vault("retam"))
    # add_entry("retam", "gmail", "retamphy2004@gmail.com", "retam112004", "")
    # del_vault()
    # pass
    # print(generate_pass(8,True,"l",False,"retam"))
    # pprint.pprint(load_vault("retam2004"),sort_dicts=False)
    # pass
    get_entry("retam2004","gmail")
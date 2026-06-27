# from doctest import master
import os
from pathlib import Path

from crypto import decrypt_vault, encrypt_vault

VAULT_PATH = Path.home() / ".cola" / "vault.enc"

# definitely need to change the init_vault function


def init_vault(master_pass: str):
    # VAULT_PATH.parent.mkdir(exist_ok=True)
    # VAULT_PATH.write_bytes(encrypt_vault(master_pass=master_pass,data={}))
    if VAULT_PATH.exists():
       print("the vault already exists !!! unlock it using cola unlock")
    else:
        VAULT_PATH.parent.mkdir(exist_ok=True)
        save_vault(master_pass, {})
        print("vault created successfully using master password!")


def save_vault(master_pass: str, data: dict):
    VAULT_PATH.write_bytes(encrypt_vault(master_pass=master_pass, data=data))


def load_vault(master_pass: str):
    if not VAULT_PATH.exists():
        raise FileNotFoundError(
            "The vault does not exist !! use init cmd to create vault --> cola init"
        )
    return decrypt_vault(master_pass=master_pass, blob=VAULT_PATH.read_bytes())


def add_entry(master_pass: str, name: str, username: str, password: str, url: str = ""):
    vault = load_vault(
        master_pass=master_pass
    )  # this gives the entire python dict data
    vault[name.lower()] = {"Username": username, "Password": password, "url": url}
    save_vault(master_pass, vault)


def get_entry(master_pass: str, name: str):
    # vault = load_vault(master_pass = master_pass)
    return load_vault(master_pass).get(name)


def delete_entry(master_pass: str, name: str):
    vault = load_vault(master_pass)
    vault.pop(name)
    save_vault(master_pass, vault)


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
    del_vault()
    # print(generate_pass(8,True,"l",False,"retam"))
    
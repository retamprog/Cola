#!/usr/bin/env python3 
# okay i need to change this ...

import argparse
import string
import secrets
import getpass
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json


BOLD="\033[1m"
UNDERLINE="\033[4m"
RESET="\033[0m"

def create_key(masterpass:str,salt:bytes):
    master_byte=masterpass.encode('utf-8')
    # print(master_byte)
    
    # name_bytes=name.encode('utf-8')

    with open(f"vault.key",'wb') as file:
        file.write(salt)
        print("Key saved for future  uses!!")

    kdf=PBKDF2HMAC(
         algorithm=hashes.SHA256(),
         length=32,
         salt=salt,
         iterations=1_200_000,
    ) 
    key = base64.urlsafe_b64encode(kdf.derive(master_byte))
    return key   
def create_acc():
    new_acc={}
    print("Creating new account:")
    acc_name=input("Acc Name: ")
    user_name=input("User Name: ")
    while True:
        pass_ = getpass.getpass(prompt="Enter password: ")
        check = getpass.getpass(prompt="Re enter password: ")
        if pass_==check:
            print("Account created  and password stored securely!!")
            break
    new_acc={"acc_name":acc_name,"user_name":user_name,"password":pass_}
    data_json=json.dumps(new_acc).encode('utf-8')
    with open("key.key","rb") as file:
        key=file.read()
    f=Fernet(key)
    enc_data=f.encrypt(data_json)
    with open(f"Vault.enc",'ab') as file:
        file.write(enc_data)


def gen_vault():
    while(True):
            master=getpass.getpass(prompt="Enter master password: ")
            if len(master)<8:
                print("Min password length must be 8, please re enter password")
            elif not any(c.isdigit() for c in master):
                print("Password should have 0-9 digits in it..,please re-enter password")
            elif not any(c.isupper() for c in master):
                print("Password should have upppercase letters in it...., please re enter password")       
            else:    
                check=getpass.getpass(prompt="Renter master password: ")
                if master==check:
                    print(f"Vault is being generated encrypted by the master password, from now on open the vault using the master password...")
                    break
                else:
                    print("Please renter password correctly ..., password not matching.")
    salt=os.urandom(16)        
    key=create_key(master,salt)
    create_acc()
    



def main():

    parser=argparse.ArgumentParser(prog="cola",usage=argparse.SUPPRESS,add_help=False,
                                description=f'''
    A password generation and password manager cli app\n    {BOLD}{UNDERLINE}Usage{RESET}:\n    cola [commands] [options]
                                
    {BOLD}{UNDERLINE}Commands{RESET}:
    genpass --> generate new password
    genvault --> generate new vault
    opvault --> open a existing vault
    findacc --> find account details (username: pass)
    modacc --> modify account details.
                                ''', 
                                epilog=f"{BOLD}{UNDERLINE}Examples{RESET}: \ncola genpass -l 8 -Uns --> create a password of length 8 having uppercase letters, digits, special characters",
                                formatter_class=argparse.RawDescriptionHelpFormatter
                                )
    parser.add_argument("-h","--help",action="help",help="shows the help page")
    subparsers = parser.add_subparsers(dest="command",help=argparse.SUPPRESS,metavar="")
    '''
    genpass ---> the password generation cli 
    '''
    genpass = subparsers.add_parser("genpass",help="Generate a new password", description="Generate a new secure password using the secrets module")
    genpass.add_argument("-l","--length",type=int,help="the length of the password",required=True)
    genpass.add_argument("-U","--uppercase",action="store_true",help="include uppercase letters to password")
    genpass.add_argument("-n","--numbers",action="store_true",help="include numbers in the password")
    genpass.add_argument("-s","--spcharac",action="store_true",help="include special characters in password")
    '''
    genvault ---> the vault generation
    '''
    genvault = subparsers.add_parser("genvault",help="generate a new vault",description="Generate a new encrypted file vault for storing passwords and usernames. ")   
    # genvault.add_argument("--name",action="store",help="takes the name of the vault being created",required=True)
    '''
    cracc ---> the account generation
    '''
    cracc=subparsers.add_parser("cracc",help="Create a new account",description="Creates new a new account with new details name,username,password")
    
    spcharac="@#%$*!&^"
    args=parser.parse_args()
    if args.command==None:
        parser.print_help()
        exit(0)
    if args.command=="genpass":
        chars=string.ascii_lowercase
        if args.uppercase==True:
            chars+=string.ascii_uppercase
        if args.numbers==True:
            chars+=string.digits
        if args.spcharac==True:
            chars+=spcharac
        password=''.join([secrets.choice(chars) for _ in range(args.length)])
        print(password)        

    if args.command=="genvault":
        # key=create_key(master,salt)
        # print(key)
        gen_vault()
        exit(0)
    if args.command=="cracc":

        with open("key,key",'rb') as f:
            key=
        create_acc()




if __name__=="__main__":
    main()

# genvault.add_argument()
# parser.add_argument("-gp","--generate_pass",type=)
# parser.add_argument("genpass",action="store_true",help="generates new password")
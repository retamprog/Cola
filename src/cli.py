"""
Cola.cli
the cli application code for accessing the cola app
created using the click module for fast and transparent code.
CLICK - Command line interface creation kit

"""

# import pprint
import json
import secrets
import string
import tempfile
import click
import pwinput
import pyperclip
from click.exceptions import ClickException
import os
import subprocess
from sessions import check_session, delete_session, load_session, session_start
from vault import (
    add_entry,
    decrypt_vault,
    delete_entry,
    encrypt_vault,
    get_entry,
    init_vault,
    load_vault,
    save_vault,
)


@click.group()
def cli():
    pass


# < ---------------------------------Password Generation-------------------------->
@click.command()
@click.option(
    "-l",
    "--length",
    type=click.INT,
    prompt="the length of the password generated",
    help="the length of the password generated",
    default=16,
)
@click.option(
    "-U",
    "--upper",
    is_flag=True,
    help="whether the password should have uppercase letters",
)
@click.option(
    "-s",
    "--spc",
    is_flag=True,
    help="whether the password should have special characters",
)
@click.option(
    "-e",
    "--extra",
    type=click.STRING,
    prompt="any extra string you want to add ?",
    help="extra characters to be taken into account",
    default="",
)
@click.option(
    "-c",
    "--copy",
    type=click.BOOL,
    prompt="want to copy to clipboard",
    help="copy pass to clipboard",
)
def genpass(length: int, upper: bool, spc: bool, extra: str, copy: bool):
    """
    custom random password generation
    """
    pouch = string.digits + string.ascii_lowercase
    if upper:
        pouch += string.ascii_uppercase
    if spc:
        pouch += string.punctuation
    if len(extra) != 0:
        pouch += extra

    output = "".join([secrets.choice(pouch) for _ in range(length)])
    if copy:
        pyperclip.copy(output)
    else:
        click.secho(output, fg="black", bg="white")


# <------------------------Password Management------------------------------------->
"""
I am going to create a masked password prompter so that i will get that asterisk kind off feeling when i type the passwd makes it easy for me and i kind of like it !!!!

"""


# utility function ----->
def masked_prompt(prompt: str):
    return pwinput.pwinput(prompt=prompt)


def get_masterpass():
    # the function to get master pass from the stored session file or to prompt the pass if session expired
    master = load_session()
    if master is None:
        # the session has ended prompt the user for master_pass
        return masked_prompt("Enter the master pass: ")
    return master

def get_editor():
    return os.environ.get("EDITOR","nano")
# ---------------------------------------------------------------------------------------------------------------
@click.command()
def init():
    """Vault initialization command for vault creation"""
    passwd = masked_prompt("Enter the master pass: ")
    confirm = masked_prompt("Renter the pass: ")
    if passwd != confirm:
        raise click.ClickException("Passwords do not match !! please try again.")
    if len(passwd) < 8:
        raise click.ClickException("Password length must be minimum 8 characters. ")

    init_vault(passwd)


@click.command()
def unlock():
    """unlock the vault for a time period to add, edit, del  entries in the vault without repeated master_pass i/p"""
    passwd = masked_prompt("Enter the master pass ")
    # print("hello")
    # after that check it for validity by loading the vault with the pass
    # print(load_vault(passwd))
    try:
        if load_vault(passwd):
            print("hello!!")
            session_start(passwd)
            print("Vault unlocked successfully!!")
    except Exception:
        print("Master pass not correct!!")


@click.command()
def lock():
    """lock the vault manually or it will auto-lock itself out after the session times out"""
    passwd = masked_prompt("Enter the master pass ")
    try:
        if load_vault(passwd):
            delete_session()
            print("Vault locked successfully!!")
    except Exception:
        print("Master pass not correct!!")


@click.command()
@click.option(
    "-n",
    "--name",
    type=click.STRING,
    prompt="The name of the entry",
    help="the name of the entry you are adding to the vault",
)
@click.option(
    "-u",
    "--username",
    type=click.STRING,
    prompt="The username of the entry",
    help="the username of the entry you are adding to the vault",
    default="username",
)
@click.option(
    "--url",
    "-ul",
    type=click.STRING,
    prompt="The url of the entry",
    help="the url of the entry",
    default="",
)
def add(name: str, username: str, url: str):
    """Adding new entries to the vault"""
    # entry pass we will take it from the masked prompt
    passwd = ""
    while True:
        passwd = masked_prompt("Enter the pass for the above entry : ")
        repass = masked_prompt("Renter the pass :")
        if passwd == repass:
            break

    master = get_masterpass()
    add_entry(master, name, username, passwd, url)

## needs finishing and thinking @@@
# # cant seem to figure you out !!!! Fuck you!!!!!!!!!!! 
@click.command(name="edit")
@click.option("-n","--name",type = click.STRING,default="",help="the name of the entry to edit")
@click.option("-u","--username",type=click.STRING,default="",help = "the username of the entry to edit")
def edit_entry(name:str,username:str):
    """Edit entries in the vault"""
    master = get_masterpass()
    # okay for this lets say i get the target dict for editing purposes
    vault = load_vault(master)
    d = get_entry(master,name,username)
    with tempfile.NamedTemporaryFile(mode = "w+",delete=True,suffix='.txt',encoding='utf-8') as fp:
        fp.write(json.dumps(d,indent=4))
        fp.flush() # push the write data from python RAM cache to real disk storage 
        # so that it can be read by external editor
        subprocess.run([get_editor(),fp.name])
        fp.seek(0)
        extracted_data = json.loads(fp.read())
        # print("data extraction completed")
    
    # print(extracted_data)
    
    if not username and not name:
        vault["Entries"]=extracted_data
        save_vault(master,vault)
        return
    elif username:
        index=next((i  for i,d in enumerate(vault["Entries"][name]) if d["username"]==username),None)
        vault["Entries"][name][index]=extracted_data
        save_vault(master,vault)
        return
    else:
        # the username field is empty meaning only name field is given then
        vault["Entries"][name]=extracted_data
        save_vault(master,vault)
        return 
        


@click.command(name="get")
@click.option(
    "-n",
    "--name",
    type=click.STRING,
    default="",
    help="the name of the entry to get info about"
)
@click.option(
    "-u",
    "--username",
    type=click.STRING,
    default="",
    help="the username of the entry to get info about"
)
@click.option("--list", is_flag=True, help="the list of the entries in the vault")
def get(name: str, username: str, list: bool):
    """Get particular entry based on username"""
    master = get_masterpass()
    if list:
        print(json.dumps(load_vault(master), indent=4))
        return 

    if not get_entry(master, name, username):
        print("wrong name or username !!")
        return
    print(json.dumps(get_entry(master, name, username), indent=4))

# might make it multipurpose giving user options as to delete the whole entry name or just particular username entries
@click.command(name="del")
@click.option("-n","--name",help="the name of the entry to be deleted",default="")
def del_entry(name:str,username:str):
    """delete entries in the vault"""
    # okay now you will be created sorry for the late work
    
    


cli.add_command(genpass)
cli.add_command(init)
cli.add_command(lock)
cli.add_command(unlock)
cli.add_command(add)
cli.add_command(edit_entry)
cli.add_command(get)
cli.add_command(del_entry)

if __name__ == "__main__":
    cli()

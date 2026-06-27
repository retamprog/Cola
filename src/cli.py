'''
   Cola.cli
   the cli application code for accessing the cola app
   created using the click module for fast and transparent code.
   CLICK - Command line interface creation kit
   
'''
import click
import secrets
import string
from click.exceptions import ClickException
import pyperclip
import pwinput
from vault import (
    init_vault,encrypt_vault,decrypt_vault,add_entry,
    get_entry,delete_entry
)

@click.group()
def cli():
    pass
# < ---------------------------------Password Generation-------------------------->
@click.command()
@click.option("-l","--length",type=click.INT,prompt="the length of the password generated",help="the length of the password generated",default=16)
@click.option("-U","--upper",is_flag=True,help="whether the password should have uppercase letters")
@click.option("-s","--spc",is_flag=True,help="whether the password should have special characters")
@click.option("-e","--extra",type=click.STRING,prompt="any extra string you want to add ?",help="extra characters to be taken into account",default="")
@click.option("-c","--copy",type=click.BOOL,prompt="want to copy to clipboard",help="copy pass to clipboard")
def genpass(length:int,upper:bool,spc:bool,extra:str,copy:bool):
    '''
      custom random password generation
    '''
    pouch = string.digits+string.ascii_lowercase
    if upper:
        pouch+=string.ascii_uppercase
    if spc:
        pouch+=string.punctuation
    if len(extra)!=0:
        pouch+=extra
        
    output = ''.join([secrets.choice(pouch) for _ in range(length)])
    if copy:
        pyperclip.copy(output)
    else:
        click.secho(output,fg="black",bg="white")
    
#<------------------------Password Management-------------------------------------> 
'''
I am going to create a masked password prompter so that i will get that asterisk kind off feeling when i type the passwd makes it easy for me and i kind of like it !!!!

'''
def masked_prompt(prompt:str):
    return pwinput.pwinput(prompt=prompt)
@click.command()
def init():
    ''' Vault initialization command for vault creation'''
    passwd = masked_prompt("Enter the master pass: ")
    confirm = masked_prompt("Renter the pass: ")
    if passwd!=confirm:
        raise click.ClickException("Passwords do not match !! please try again.")
    if len(passwd) < 8:
        raise click.ClickException("Password length must be minimum 8 characters. ")

    init_vault(passwd)

@click.command()
def add_entry():
    pass


    
    
        

cli.add_command(genpass)
cli.add_command(init)

if __name__=='__main__':
    cli()
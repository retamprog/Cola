#!/usr/bin/env python3
import pyfiglet
import argparse
def welcome_page():
    Header=pyfiglet.figlet_format("COLA",font="ascii12")
    print(Header)
def man_db():
    print('''
         --generate-pass ---> to generate a new pass
         --create-acc ---> create new account with new pass and username 
         --help --> open the help page
         --find-acc --> find which account to see or modify   

''')
    
def generate_pass():
    pass


def main():
    parser=argparse.ArgumentParser()
    # parser.add_argument("-gp","--generate_pass",type=)

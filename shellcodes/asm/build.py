#!/usr/bin/env python
import subprocess
import sys

def main():
    if sys.argv[1] == 'clean':
        clean_up()
        exit()
    
    PAYLOAD = sys.argv[1]
    compiled_asm = compile_asm(PAYLOAD)
    build_pe(PAYLOAD)
    bindata = load_library(compiled_asm)
    shellcode = buffer_python(bindata)
    print shellcode

def clean_up():
    subprocess.Popen('rm -f *.bin *.exe *.c', shell=True)

def compile_asm(PAYLOAD):
    try:
        subprocess.call('nasm -f bin -O3 -o payload.bin %s.asm' % PAYLOAD, shell=True)
        f=open('payload.bin') 
        return f
    except Exception as e:
        print e
        exit()

# load library
def load_library(compiled_asm):
    # to write
    bindata = compiled_asm.read()
    compiled_asm.close()

    print "# Lenth: %s bytes" % len(bindata)
    return bindata

# print out common offsets into the payload data
def offsets():
    # to write
    # could take a while
    ####
    print ""

def build_pe(PAYLOAD):
        subprocess.call('nasm -I inc/ -f bin -o %s.exe win32_template.asm' % PAYLOAD, shell=True)

def buffer_python(bindata):
    # output as shellcode for python

    width = 16
    res = 'shellcode = (\n"'
    count = 0
    for char in bindata:
        if count == width:
            res += '"\n"'
            count = 0
        res += '\\x%s' % char.encode("hex")
        count+=1
    res+= '"\n)'
    return res

main()

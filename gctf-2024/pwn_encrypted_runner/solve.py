from Crypto.Cipher import AES
import subprocess


def helper(cmd, data):
    if cmd == "encrypt":
        data = [ord(c) for c in data]
    else:
        data = list(data)

    while len(data) < 16:
        data.append(0)

    inp = cmd + " " + " ".join("%02x" % c for c in data[:16])
    res = subprocess.check_output("./aes", input=inp.encode())

    return bytes.fromhex(res.decode())


def write_key(key_bit: int):
    key = key_bit.to_bytes(1, "little") + b"\x01" * 15

    with open("key", "bw") as f:
        f.write(key)


# The mappings is the same for each key byte position
mappings = []
for key_bit in range(256):
    write_key(key_bit)

    data = "子" + "A" * 15

    enc_str = helper("encrypt", data)

    out = helper("decrypt", enc_str)

    mappings.append(out[0])

print(mappings)

# RECOVER KEY

out = b'ls \017[\034\203:Q\031z\a\035\252\370\373'
key = bytes()
for val in out:
    key += bytes([mappings.index(val)])

print(key)

# Check make sure
# Expected: Output: ls: cannot access ''$'\017''['$'\034\203'':Q'$'\031''z'$'\a\035\252\370\373': No such file or directory
res = subprocess.run(out, shell=True, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, check=False)
print("Output:", res.stdout.decode())

# We don't know the first three bytes of key
# So we bruteforce first third key byte

text = b'ls 0123456789abc'
encrypted = bytes.fromhex("33f7eca2f2d35e7ed18900b952b27bcf")

i = 0
while i < 256 ** 4 - 1:
    new_key = bytes([i % 256, (i // 256) % 256, i // (256 ** 2)]) + key[3:]
    i += 1
    if i % (256 ** 2) == 0:
        print(i // (256 ** 2))

    aes = AES.new(new_key, AES.MODE_ECB)
    enc_text = aes.encrypt(text)

    if enc_text == encrypted:
        print("FOUND IT")
        print(new_key)

        # new_key = b'N\xa3\x93]\tN\xd1h\x03K(UO\xf8\xaa\xa9'

        aes = AES.new(new_key, AES.MODE_ECB)
        enc_text = aes.encrypt(b"ls ; cat /flag" + b"\x00\x00")
        print(enc_text.hex())

        exit()

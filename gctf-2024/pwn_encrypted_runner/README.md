# Challenge summary
`You won't be able to run anything but ls, echo or date, hahahaha!`

In the challenge, chal.py will only encrypt safe commands (date, echo, ls).
Our goal is to somehow encrypt arbitary commands (and send it to the remote).

# Solution

## Leaking private aes key

If you try encrypting and decrypting characters above 255, you can see this:
```console
$ python3 chal.py
Welcome to encrypted command runner.
What do you want to do?
- encrypt command (e.g. 'encrypt echo test')
- run command (e.g. 'run fefed6ce5359d0e886090575b2f1e0c7')
- exit
encrypt ls 子AA子AA子AA子AA子
Encrypted command: 4e3b832513a430854cf80c64a087f37b

What do you want to do?
- encrypt command (e.g. 'encrypt echo test')
- run command (e.g. 'run fefed6ce5359d0e886090575b2f1e0c7')
- exit
run 4e3b832513a430854cf80c64a087f37b
Output: ls: cannot access 'aAAdAAkAA'$'\021''AA'$'\024': No such file or directory

...
```

`子AA子AA子AA子AA子` has been replaced to `aAAdAAkAA\021AA\024`!

The reason is the following:
```c++
// aes binary
void Cipher(uint *data_buf,long aes_struct)

{
  byte i;
  
  AddRoundKey(0,data_buf,aes_struct); // This is called
  i = 1;
  while( true ) {
    SubBytes(data_buf); // But the first SubBytes() call resets data to \x00
    ShiftRows(data_buf);
    if (i == 10) break;
    MixColumns(data_buf);
    AddRoundKey(i,data_buf,aes_struct);
    i = i + 1;
  }
  AddRoundKey(10,data_buf,aes_struct);
  return;
}
```
After the call of AddRoundKey(...), the first call of SubBytes(...) reset characters above 255 to \x00.
Therefore in decrypting (reverse of encrypting), the extra AddRoundKey(...) call can be used to leak the private aes key.


Now, there is some mathematical relationship (xor 0x52) between the decryption output and the aes key. But at the ctf, I don't really want to spend time thinking about, so I simply bruteforce it.
```python
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
# [82, 83, 80, 81, 86, 87, 84, 85, 90, 91, 88, 89, 94, 95, 92, 93, 66, 67, 64, 65, 70, 71, 68, 69, 74, 75, 72, 73, 78, 79, 76, 77, 114, 115, 112, 113, 118, 119, 116, 117, 122, 123, 120, 121, 126, 127, 124, 125, 98, 99, 96, 97, 102, 103, 100, 101, 106, 107, 104, 105, 110, 111, 108, 109, 18, 19, 16, 17, 22, 23, 20, 21, 26, 27, 24, 25, 30, 31, 28, 29, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 50, 51, 48, 49, 54, 55, 52, 53, 58, 59, 56, 57, 62, 63, 60, 61, 34, 35, 32, 33, 38, 39, 36, 37, 42, 43, 40, 41, 46, 47, 44, 45, 210, 211, 208, 209, 214, 215, 212, 213, 218, 219, 216, 217, 222, 223, 220, 221, 194, 195, 192, 193, 198, 199, 196, 197, 202, 203, 200, 201, 206, 207, 204, 205, 242, 243, 240, 241, 246, 247, 244, 245, 250, 251, 248, 249, 254, 255, 252, 253, 226, 227, 224, 225, 230, 231, 228, 229, 234, 235, 232, 233, 238, 239, 236, 237, 146, 147, 144, 145, 150, 151, 148, 149, 154, 155, 152, 153, 158, 159, 156, 157, 130, 131, 128, 129, 134, 135, 132, 133, 138, 139, 136, 137, 142, 143, 140, 141, 178, 179, 176, 177, 182, 183, 180, 181, 186, 187, 184, 185, 190, 191, 188, 189, 162, 163, 160, 161, 166, 167, 164, 165, 170, 171, 168, 169, 174, 175, 172, 173]
```

##

We can now leak the remote's private key.
By encrypting `ls 子子子子子子子子子子子子子` on the remote, you get `ls \017[\034\203:Q\031z\a\035\252\370\373`. (you can encrypt `ls 子AAAAAAAAAAAA`, `ls A子AAAAAAAAAAA`, ... sequentially to make it easier to read the output)

```console
$ nc encrypted-runner.2024.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to encrypted command runner.
What do you want to do?
- encrypt command (e.g. 'encrypt echo test')
- run command (e.g. 'run fefed6ce5359d0e886090575b2f1e0c7')
- exit
encrypt ls 子子子子子子子子子子子子子
Encrypted command: a75d08c42ca08d8151c5485855c4ed13
What do you want to do?
- encrypt command (e.g. 'encrypt echo test')
- run command (e.g. 'run fefed6ce5359d0e886090575b2f1e0c7')
- exit
run a75d08c42ca08d8151c5485855c4ed13
Output: ls: cannot access ''$'\017''['$'\034\203'':Q'$'\031''z'$'\a\035\252\370\373': No such file or directory

...
```

We can now recover 13 bytes of the private key:

```python
out = b'ls \017[\034\203:Q\031z\a\035\252\370\373'
key = bytes()
for val in out:
    key += bytes([mappings.index(val)])
```

We still don't know the first 3 bytes of the private key, but we can just bruteforce it.

```python
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
        print(new_key) # new_key = b'N\xa3\x93]\tN\xd1h\x03K(UO\xf8\xaa\xa9'

        exit()
```

With that, we leaked the private key! We can now encrypt arbitary commands.

```python
aes = AES.new(new_key, AES.MODE_ECB)
enc_text = aes.encrypt(b"ls ; cat /flag" + b"\x00\x00")
print(enc_text.hex()) # b110678752de46dabf6f9cd87bb4abd3
```

We can send the hash, and get the glorious flag🚩.

```console
$ nc encrypted-runner.2024.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to encrypted command runner.
What do you want to do?
- encrypt command (e.g. 'encrypt echo test')
- run command (e.g. 'run fefed6ce5359d0e886090575b2f1e0c7')
- exit
run b110678752de46dabf6f9cd87bb4abd3
Output: aes
chal.py
key
CTF{hmac_w0uld_h4ve_b33n_bett3r}

...
```
output = [0xb4, 0x31, 0x8e, 0x02, 0xaf, 0x1c, 0x5d, 0x23, 0x98, 0x7d, 0xa3, 0x1e, 0xb0, 0x3c, 0xb3, 0xc4,
          0xa6, 0x06, 0x58, 0x28, 0x19, 0x7d, 0xa3, 0xc0, 0x85, 0x31, 0x68, 0x0a, 0xbc, 0x03, 0x5d, 0x3d, 0x0b]

table1 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76]
table2 = [0x1, 0x3, 0x4, 0x2, 0x6, 0x5]

counter = 0
for i in range(33):
    if i & 1 == 1:  # is odd
        # is not lowercase
        res_a = ((output[i] & 0b11) << 6) | (output[i] >> 2)

        # is lowercase
        res_b = output[i] ^ table1[counter]
    else:  # is even
        # is not lowercase
        b = output[i] ^ table1[counter]
        res_a = ((b & 0b111111) << 2) | (b >> 6)
        
        # is lowercase
        b = (table2[counter] & 0x1f)
        res_b = (((output[i] & ((2 << (8 - b)) - 1)) << b)
                 | (output[i] >> (8 - b))) % 256


    # update counter
    if i & 1 == 1:
        counter = (counter + 1) % 6

    if chr(res_a) in "abcdefghijklmnopqrstuvwxyz0123456789_{}":
        print(chr(res_a), end="")
    else:
        print(chr(res_b), end="")

print()

from pwn import *
from z3 import *
import struct

# The shuffle function in python:
# def shuffle(buf):
#     for _ in range(5):
#         buf = [
#             buf[0] * buf[0] + buf[2] * buf[1],
#             buf[1] * buf[0] + buf[3] * buf[1],
#             buf[0] * buf[2] + buf[2] * buf[3],
#             buf[1] * buf[2] + buf[3] * buf[3],
#         ]
#
#     return sum(buf)
#
# From the shuffle function, we can notice the following:
#
# When a, b are both 0:
#     rand = random.random() * 0.9 + 0.05
#     print(shuffle([0., 0., rand, 1. - rand])) # very close to 0
#
# When one of a, b is 1:
#     rand = random.random() * 0.9 + 0.05
#     print(shuffle([0., 1., rand, 1. - rand])) # very close to 2
#
# When both a, b are 1:
#     rand = random.random() * 0.9 + 0.05
#     print(shuffle([1., 1., rand, 1. - rand])) # very large (~7 orders of magnitude)
#
# Therefore, when calculating mids[i] * mids[j], 6 cases may occur. (00 01 02 11 12 22)
# By feeding the possible cases into z3, we can recover mids.
# After that, recovering flag is trivial.

# --- Read data ---


def read_data():
    elf = ELF("./metronome")

    buf = elf.read(0x4020, (0x208 * 2) * 4)
    select_bits = []
    for i in range(0x208):
        select_bits.append(struct.unpack("<ii", buf[i * 8: (i + 1) * 8]))

    buf = elf.read(0x5060, (0x208 * 0x208 * 2) * 8)
    bounds = []
    for i in range(0x208 * 0x208):
        bounds.append(struct.unpack("<dd", buf[i * 16: (i + 1) * 16]))

    return (select_bits, bounds)


print("Reading data...")
(select_bits, bounds) = read_data()

# --- Part 1 solve ---

solver = Solver()

print("Adding constraints...")

mids = IntVector("mid", 0x208)
for mid in mids:
    solver.add(0 <= mid, mid < 3)

for j in range(0x208):
    for i in range(j, 0x208):
        (low_1, high_1) = bounds[j * 0x208 + i]
        (low_2, high_2) = bounds[i * 0x208 + j]
        (low, high) = (max(low_1, low_2), min(high_1, high_2))

        if high > 100000000000:
            # case 22
            solver.add(mids[i] == 2, mids[j] == 2)
        elif 10 < low and high > 100000:
            # case 12
            solver.add(mids[i] != 0, mids[j] != 0)
        elif low == 0 and high > 100000:
            # case 02
            solver.add(mids[i] != 1, mids[j] != 1)
        elif low != 0:
            # case 11
            solver.add(mids[i] == 1, mids[j] == 1)
        else:
            # case 00 or case 01
            solver.add(mids[i] != 2, mids[j] != 2)

print("Solving part 1...")
# print(solver.check())

# --- Part 2 solve --

input = BoolVector("input", 0x41 * 8)

for i in range(0x208):
    (bit_1, bit_2) = select_bits[i]

    solver.add(If(input[bit_1], 1, 0) + If(input[bit_2], 1, 0) == mids[i])

print("Solving part 2...")
print(solver.check())

model = solver.model()

for i in range(0x41):
    out = 0
    for j in range(8):
        out |= bool(model.eval(input[i * 8 + j])) << j
    print(chr(out), end="")
print()

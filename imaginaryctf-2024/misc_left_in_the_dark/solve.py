from pwn import *
import readchar

# Might want to run in debug mode just in case, `python3 solve.py DEBUG`

wait_secs = 1.25 # Time to wait for bonk response

io = remote("left-in-the-dark.chal.imaginaryctf.org", 1337)
io.recvline_contains(b"WASD to move.")

maze = []
for _ in range(40):
    maze.append([" " for _ in range(40)])

pos = (0, 0)
maze[0][0] = "."
maze[39][39] = "F"


def print_maze():
    print("-" * 42)
    for (x, line) in enumerate(maze):
        print("|", end="")
        for (y, cell) in enumerate(line):
            if pos[0] == x and pos[1] == y:
                print("@", end="")
            else:
                print(cell, end="")
        print("|")
    print("-" * 42)


def get_dir_cell(input_dir):
    if input_dir == "w":
        return (pos[0] - 1, pos[1])
    elif input_dir == "a":
        return (pos[0], pos[1] - 1)
    elif input_dir == "s":
        return (pos[0] + 1, pos[1])
    else:
        return (pos[0], pos[1] + 1)

def is_pos_in_bound(input_pos):
    return input_pos[0] >= 0 and input_pos[0] < 40 and input_pos[1] >= 0 and input_pos[1] < 40

while True:
    print_maze()

    input_dir = readchar.readkey()
    
    if input_dir not in ["w", "a", "s", "d"]:
        print(f"bad direction {input_dir}")
        continue

    io.send(input_dir.encode())

    next_pos = get_dir_cell(input_dir)

    if next_pos[0] == 39 and next_pos[1] == 39:
        break

    # predict (only on empty space)
    if is_pos_in_bound(next_pos) and maze[next_pos[0]][next_pos[1]] == ".":
        print("PREDICT SAFE")

        pos = next_pos
    else:
        # no predict
        if io.recvline(timeout=wait_secs):
            # BONK
            print("WE BONK")

            if is_pos_in_bound(next_pos):
                maze[next_pos[0]][next_pos[1]] = "#"
        else:
            # NO BONK
            print("WE SAFE")

            pos = next_pos

            maze[pos[0]][pos[1]] = "."

io.interactive()

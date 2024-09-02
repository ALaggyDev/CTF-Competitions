import angr
import claripy
import sys

# It takes several minutes to run

project = angr.Project("./chal")

# Setup initial state

state = project.factory.blank_state(addr=0x40c4f4)
state.regs.rbp = state.regs.rsp

inputs = [claripy.BVS(f"input_{i}", 8) for i in range(26)]

for i in range(26):
    addr = state.regs.rsp + 0x274 - i * 0x10
    state.mem[addr].uint32_t = inputs[i].zero_extend(24)

failed_addr = state.regs.rsp + 0x36c
state.mem[failed_addr].uint32_t = 0
print(failed_addr)

# Start simulation

simulation = project.factory.simgr(state)


def should_avoid(state):
    if state.addr == 0x40d717 or state.addr == 0x4082b0:
        return True
    if state.solver.eval(state.mem[failed_addr].uint32_t.resolved == 1):
        return True
    return False


simulation.explore(find=0x40d6f0, avoid=should_avoid)

found = simulation.found[0]

for b in inputs:
    print(chr(found.solver.eval(b)), end="")
print()

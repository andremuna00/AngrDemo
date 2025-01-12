import angr
import monkeyhex

proj = angr.Project('binaries/hello-world')

print("architecture: {0}".format(proj.arch)) 
print("Entry point: {0}".format(proj.entry))
print("Filename: {0}".format(proj.filename))

#--------FACTORY------------------
block = proj.factory.block(proj.entry) # lift a block of code from the program’s entry point
print("Disassembly:")
block.pp() # pretty-print a disassembly to stdout
print("# of Instructions: {0}".format(block.instructions)) # how many instructions are there?
print("Addressed of the instructions: {0}".format(block.instruction_addrs)) # what are the addresses of the instructions?

#--------STATE------------------
print("-----------STATE-------------")
state = proj.factory.entry_state()
print("RIP: {0}".format(state.regs.rip)) # get the current instruction pointer
print("RAX: {0}".format(state.regs.rax))
print("Resolve value stored in the entry state: {0}".format(state.mem[proj.entry].int.resolved)) # interpret the memory at the entry point as a C int

bv = state.solver.BVV(0x1234, 32)
state.solver.eval(bv)

state.regs.rsi = state.solver.BVV(3, 64)
print("RSI: {0}".format(state.regs.rsi))
state.mem[0x1000].long = 4
print("MEM VALUE AT 0x1000 {0}".format(state.mem[0x1000].long.resolved))

#----------SIMULATION MANAGERS------------
print("-----------SIMULATION MANAGER-------------")
simgr = proj.factory.simulation_manager(state)
simgr.step()
print("Simulation active: {0}".format(simgr.active))
print("Active simulation RIP: {0}".format(simgr.active[0].regs.rip))
print("Current state register RIP: {0}".format(state.regs.rip))
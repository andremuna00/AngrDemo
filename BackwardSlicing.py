import angr
# Load the project
b = angr.Project("binaries/fauxware", load_options={"auto_load_libs": False})

# Generate a CFG first. In order to generate data dependence graph afterwards, you'll have to:
# - keep all input states by specifying keep_state=True.
# - store memory, register and temporary values accesses by adding the angr.options.refs option set.
# Feel free to provide more parameters (for example, context_sensitivity_level) for CFG
# recovery based on your needs.
cfg = b.analyses.CFGEmulated(keep_state=True,
                             state_add_options=angr.sim_options.refs,
                             context_sensitivity_level=2)

# Generate the control dependence graph
cdg = b.analyses.CDG(cfg)

# Build the data dependence graph. It might take a while. Be patient!
ddg = b.analyses.DDG(cfg)

# See where we wanna go... let's go to the exit() call, which is modeled as a
# SimProcedure.
target_func = cfg.kb.functions.function(name="exit")
# We need the CFGNode instance
target_node = cfg.get_any_node(target_func.addr)

# Let's get a BackwardSlice out of them!
# ``targets`` is a list of objects, where each one is either a CodeLocation
# object, or a tuple of CFGNode instance and a statement ID. Setting statement
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not
# have any statement, so you should always specify -1 for it.
bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

# Here is our program slice!
print(bs)
import angr

p = angr.Project('binaries/hello-world', load_options={'auto_load_libs': False})
cfg = p.analyses.CFGFast()
cfg = p.analyses.CFGEmulated(keep_state=True)


print("This is the graph:", cfg.graph)
print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

entry_node = cfg.get_any_node(p.entry)

print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(p.entry)))

print("Predecessors of the entry point:", entry_node.predecessors)
print("Successors of the entry point:", entry_node.successors)
print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])

#FUNCTION MANAGER
entry_func = cfg.kb.functions[p.entry]
print(entry_func)
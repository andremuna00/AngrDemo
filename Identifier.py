import angr
# get all the matches
p = angr.Project("binaries/identifiable")
# note analysis is executed via the Identifier call
idfer = p.analyses.Identifier()
for funcInfo in idfer.func_info:
    print(hex(funcInfo.addr), funcInfo.name) 
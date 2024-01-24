 import angr
import claripy
path_to_binary = "<path to binary>"
proj = angr.Project(path_to_binary, load_options={'auto_load_libs':False}) 
argv = [proj.filename]
sym_arg_size = 32
sym_arg=claripy.BVS('sym_arg', 8*sym_arg_size)
argv.append(sym_arg) 
entry_state = proj.factory.entry_state(args=argv,add_options={angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY})
sim = proj.factory.simulation_manager(entry_state) 
exit_point = 0x400000+0x187d
avoid_point = 0x400000+0x1890 
sim.explore(find=exit_point, avoid=avoid_point)
if sim.found:
    print("ok")
    solution = sim.found[0].solver.eval(argv[1], cast_to=bytes)
    print(solution)
else:
    print("not ok")

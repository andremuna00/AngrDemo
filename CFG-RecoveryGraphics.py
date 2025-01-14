import angr
from angrutils import plot_cfg, hook0, set_plot_style
import bingraphvis
import os

def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    with hook0(b):
        cfg = b.analyses.CFGEmulated(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)
    for addr,func in proj.kb.functions.items():
        if func.name in ['main','verify']:
            plot_cfg(cfg, "CFG/%s_%s_cfg" % (name, func.name), asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

    plot_cfg(cfg, "CFG/%s_cfg_full" % (name), asminst=True, vexinst=True, debug_info=True, remove_imports=False, remove_path_terminator=False)

    plot_cfg(cfg, "CFG/%s_cfg_classic" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
    plot_cfg(cfg, "CFG/%s_cfg_classic" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True, format="raw")

    for style in ['thick', 'dark', 'light', 'black', 'kyle']:
        set_plot_style(style)
        plot_cfg(cfg, "CFG/%s_cfg_%s" % (name, style), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)

if __name__ == "__main__":
    
    if not os.path.exists("CFG"):
        os.makedirs("CFG")

    file = "hello-world"
    proj = angr.Project("binaries/{0}".format(file), load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    analyze(proj, main.rebased_addr, file)
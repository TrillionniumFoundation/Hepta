"""Small standalone Core API with no source adapter or implicit backend."""
from .hia_program import verify_program
verify_core=verify_program

def execute_core(program,function,arguments,**limits):
    from .hia_program_runtime import execute_program
    return execute_program(verify_core(program),function,arguments,**limits)

def build_core(program,output,*,backend='native',kind='object',linker='ld',**options):
    if backend!='native':raise ValueError('explicit direct native backend required')
    from .hia_program_native import build_program_machine
    return build_program_machine(verify_core(program),output,kind=kind,linker=linker,**options)

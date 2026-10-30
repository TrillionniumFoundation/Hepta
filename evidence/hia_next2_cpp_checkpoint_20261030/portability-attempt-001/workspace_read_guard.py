
import os,runpy,sys
def guard(event,args):
    if event == "open" and isinstance(args[0], (str,bytes,os.PathLike)):
        value=os.path.abspath(os.fsdecode(args[0]))
        if value == "/workspace" or value.startswith("/workspace/"):
            raise PermissionError("portable verifier may not open original workspace files")
sys.addaudithook(guard)
target=sys.argv[1]
sys.argv=sys.argv[1:]
runpy.run_path(target,run_name="__main__")

"""Native object binding for the explicit DO03 deferred decision capsule."""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_native_object_bind as original
from tools import hia_background_managed_value_source as M
ROOT=Path(__file__).resolve().parents[1]
LAYOUT=original.LAYOUT
def source_program():
    text=original.source_program()
    text=M.replace(text,"def background_native_object_bind(","def background_native_managed_bind(")
    text=M.replace(text,str(original.magic("HIABDOC2")),str(original.magic("HIABDOC3")))
    node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=="bind_decision")
    body=ast.get_source_segment(text,node)
    for old,new in ((35,14),(36,15),(34,13)):
        body=M.replace(body,f"get(w,1024+136+{old}*8)",f"get(w,1024+136+{new}*8)")
    return M.replace_def(text,"bind_decision",body)
def main():
    name="background_optimizer_native_managed_bind"
    d=document(source_program(),name);p=ROOT/"examples/hia_bootstrap"/(name+".hepta")
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),
          sum(len(f["blocks"])for f in d["functions"]),
          sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()

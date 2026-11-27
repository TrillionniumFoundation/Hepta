"""BG registered methods using the explicit OptimizationFuture submission domain."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_native_object_methods as original
from tools import hia_background_managed_value_source as M
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C);C.update(SUB=int.from_bytes(b'HIABSM02','little'),SUB_REPLY=int.from_bytes(b'HIABSMR2','little'))
def source_program():
    text=M.replace(original.SOURCE,'def background_native_object_methods(','def background_native_optimization_methods(')
    return M.render(text+original.HELPERS,C,'background_native_optimization_methods')
def main():
    name='background_optimizer_native_optimization_methods'
    d=document(source_program(),name);p=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),
      sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()

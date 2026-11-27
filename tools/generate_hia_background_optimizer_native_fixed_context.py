"""Native installed BG initializer with an internal fixed entry table.

The NI2 domain receives only the trusted parent's tool and mapping facts.
All internal code entries are captured mechanically; the single external
Future provider is taken from the already validated sole Value binding.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_native_context as original
from tools import hia_background_managed_value_source as M
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C);C['INIT']=int.from_bytes(b'HIABGNI2','little')
ENTRY_NAMES=original.ENTRY_NAMES
def source_program():
    text=M.replace(original.SOURCE,'def background_native_context(','def background_native_fixed_context(')
    text=M.replace(text,
        'word_load(s,56)==0 or word_load(s,64)!=10100891 or word_load(s,88)==0 or word_load(s,96)!=ENTRIES*8',
        'word_load(s,56)==0 or word_load(s,64)!=10100891 or word_load(s,88)!=0 or word_load(s,96)!=0')
    text=M.replace(text,
        'word_load(s,16)>MAX-2048 or word_load(s,56)>MAX-10100891 or word_load(s,88)>MAX-ENTRIES*8',
        'word_load(s,16)>MAX-2048 or word_load(s,56)>MAX-10100891')
    text=M.replace(text,
        '        return memory(o,8,0,word_load(s,88),3,TEMP,ENTRIES*8)',
        '        put(o,TEMP+33*8,get(o,VALUES+224))\n        return again(o,8)')
    return M.render(text,C,'background_native_fixed_context')
def main():
    name='background_optimizer_native_fixed_context'
    d=document(source_program(),name)
    p=ROOT/'examples/hia_bootstrap'/(name+'.hepta');p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),
          sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()

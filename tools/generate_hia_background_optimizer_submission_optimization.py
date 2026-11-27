"""Explicit managed BG submission profile returning canonical class 74.

SM01 and its accepted/rejected domain remain frozen. SM02 changes only the
fixed native Future producer used at the existing submit linearization point.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_submission_managed as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABSM02',REPLY='HIABSMR2',
 OPT_PROVIDER_INPUT='HIAFRD02',OPT_PROVIDER_REPLY='HIAFRDR2').items()})
def source_program():
    text=original.source_template()
    text=original.replace(text,'def submission_managed(','def submission_optimization(')
    text=original.replace(text,'        request(o,SM_PROVIDER_INPUT,0)',
                         '        request(o,OPT_PROVIDER_INPUT,0)')
    text=original.replace(text,
        '    if valid(o,RP,SM_PROVIDER_REPLY)==0 or get(o,RP+96)!=1 or get(o,RP+104)>1:',
        '    expected=SM_PROVIDER_REPLY\n'
        '    if get(o,RQ)==OPT_PROVIDER_INPUT:\n'
        '        expected=OPT_PROVIDER_REPLY\n'
        '    if valid(o,RP,expected)==0 or get(o,RP+96)!=1 or get(o,RP+104)>1:')
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    name='background_optimizer_submission_optimization'
    d=document(source_program(),name)
    p=ROOT/'examples/hia_bootstrap'/(name+'.hepta');p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),
          sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()

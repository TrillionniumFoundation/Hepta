"""Candidate native code-resource activation after actual trusted binding.

This selects a separate sidecar policy; legacy mask-6 source remains unchanged.
It enables code kinds only after the actual provider and both captured Value
bindings exist. Full Value callable behavior has its own mandatory qualification.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools import generate_hia_generation_lease_owner_sidecar as base
ROOT=Path(__file__).resolve().parents[1]
def source_program():
    source=base.SOURCE
    needle='    if phase==25:\n        if r!=0:\n            return parked(o,w,11,r,5)\n'
    assert source.count(needle)==1
    source=source.replace(needle,needle+'        put(w,680,get(w,680)|56)\n')
    for name,value in sorted(base.C.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar_callable')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_callable.hepta'
    path.write_text(render_assembly(doc));print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()

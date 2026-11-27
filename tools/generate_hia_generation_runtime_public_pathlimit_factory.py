"""True ValueError before retirement admission; real OSError at 4096 bytes."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_runtime_public_filesystem_factory as prior
ROOT=Path(__file__).resolve().parents[1]
C=dict(prior.C)
MESSAGE=b'native retirement path exceeds the Linux 4096-byte profile'
def replace(s,a,b):
 assert s.count(a)==1,(a,s.count(a))
 return s.replace(a,b,1)
def source_program():
 s=prior.source_program()
 s=replace(s,'raw<'+str(C['NEG'])+' or n==0 or n>4095','raw<'+str(C['NEG'])+' or n==0 or n>4096')
 marker=f"            if get(o,{C['GEN']}+344)=={C['FSTAG']}:\n"
 check=f"""            if get(o,{C['GEN']}+160)=={C['DE']} and get(o,{C['GEN']}+168)=={C['DR']}:
                if get(o,{C['GEN']}+176)==22 and get(o,{C['GEN']}+184)==36:
                    if cap(w,{C['PRIMARY']}) or cap(w,{C['DIAG']}):
                        return quarantine(o,w,298)
                    put(w,{C['CLEAN_SIZE']},0)
                    return reject_scalar(o,w,10)
"""
 s=replace(s,marker,check+marker)
 old=f"""    if phase == 80:
        request(o, {C['V11']}, 87)
        put(o, {C['RQ']} + 104, 41)
"""
 new=f"""    if phase == 80:
        if get(w,{C['REJECT_CODE']})==10:
            request(o,{C['V11']},32)
            put(o,{C['RQ']}+104,24)
        else:
            request(o, {C['V11']}, 87)
            put(o, {C['RQ']} + 104, 41)
"""
 s=replace(s,old,new)
 m=re.search(r'^def scalar_reason_message\([^\n]*\n',s,re.M);assert m
 code='    if reason==10:\n'
 for i in range(0,len(MESSAGE),8):
  chunk=MESSAGE[i:i+8]
  code+=f"        put(o,{C['RQ']+128+i},{int.from_bytes(chunk,'little')})\n"
 code+=f'        return {len(MESSAGE)}\n'
 s=s[:m.end()]+code+s[m.end():]
 return s
def main():
 t=document(source_program(),'generation_runtime_public_pathlimit_factory')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_public_pathlimit_factory.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()

"""Explicit native BG platform linker; earlier import profiles stay unchanged."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_shared_linker import source_program as shared_source,document
ROOT=Path(__file__).resolve().parents[1]
IMPORTS=('malloc','free','pthread_create','pthread_join')
def source_program():
    source=shared_source()
    first=source.index('def allowed_import(')
    end=source.index('\ndef check_calls(',first)
    lines=['def allowed_import(s:readbuf,first:u64,end:u64) -> u64:']
    for index,name in enumerate(IMPORTS):
        raw=name.encode('ascii')+b'\0'
        tests=[f'end-first>={len(raw)}']
        for at in range(0,len(raw),8):
            part=raw[at:at+8]
            tests.append(f'uint(s,first+{at},{len(part)})=={int.from_bytes(part,"little")}')
        lines.extend(['    if '+' and '.join(tests)+':',f'        return {1<<index}'])
    lines.append('    return 0')
    return source[:first]+'\n'.join(lines)+'\n'+source[end:]
def main():
    name='background_optimizer_native_bundle_linker'
    d=document(source_program(),name)
    p=ROOT/'examples/hia_bootstrap'/(name+'.hepta');p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),
          sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()

from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_shared_linker import source_program as shared_source, document
ROOT=Path(__file__).resolve().parents[1]
IMPORTS=('pthread_create','pthread_join')
def source_program():
    source=shared_source()
    first=source.index('def allowed_import(')
    end=source.index('\ndef check_calls(',first)
    lines=['def allowed_import(s:readbuf, first:u64, end:u64) -> u64:']
    for index,name in enumerate(IMPORTS):
        raw=name.encode('ascii')+b'\0'
        tests=[f'end - first >= {len(raw)}']
        for at in range(0,len(raw),8):
            part=raw[at:at+8]
            tests.append(f'uint(s, first + {at}, {len(part)}) == {int.from_bytes(part,"little")}')
        lines.extend(['    if '+' and '.join(tests)+':',f'        return {1<<index}'])
    lines.append('    return 0')
    return source[:first]+'\n'.join(lines)+'\n'+source[end:]
def main():
    out=ROOT/'examples/hia_bootstrap/multiversion_background_worker_linker.hepta'
    obj=document(source_program(),'multiversion_background_worker_linker')
    out.write_text(render_assembly(obj))
    print(out.name,out.stat().st_size,len(obj['functions']),sum(len(f['blocks']) for f in obj['functions']),flush=True)
if __name__=='__main__':main()

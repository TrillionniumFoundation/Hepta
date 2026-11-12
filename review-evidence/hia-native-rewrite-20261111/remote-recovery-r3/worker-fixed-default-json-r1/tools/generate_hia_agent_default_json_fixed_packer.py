"""Source-bound HIA ELF packer for eight default-JSON native images.

NEW UNEXECUTED fork of the fixed CLI HIA packer. GNU as/objcopy produce only
the immutable mechanical prefix. The actual HIA packer writes the whole ELF,
all image bytes, zero padding and fixed role addresses. Its caller must bind
all eight images to fresh exact source manifests; packet bytes are no authority.
"""
from __future__ import annotations
from pathlib import Path
from hashlib import sha256
import argparse,json,struct,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT.parent/'Hepta-agent-edit-native')]
from agent_fixed_authoring import document,profile
from hepta.hia_agent_assembly import render_assembly
MAGIC=int.from_bytes(b'HIAGFP01','little')
ROWS=8
HEADER=128

def run(out,label,args):
    proc=subprocess.run(args,capture_output=True)
    (out/(label+'.stdout')).write_bytes(proc.stdout)
    (out/(label+'.stderr')).write_bytes(proc.stderr)
    (out/(label+'.process.json')).write_text(json.dumps(dict(
        argv=args,returncode=proc.returncode,stdout_bytes=len(proc.stdout),
        stdout_sha256=sha256(proc.stdout).hexdigest(),stderr_bytes=len(proc.stderr),
        stderr_sha256=sha256(proc.stderr).hexdigest()),sort_keys=True,indent=2)+'\n')
    if proc.returncode:
        sys.stdout.buffer.write(proc.stdout);sys.stdout.buffer.flush()
        sys.stderr.buffer.write(proc.stderr);sys.stderr.buffer.flush()
    proc.check_returncode()
    return proc.stdout

def template(path,out):
    original=path.read_bytes()
    (out/'source.S').write_bytes(original)
    obj=out/'carrier.o';binary=out/'carrier.bin'
    run(out,'as',['as','--64',str(out/'source.S'),'-o',str(obj)])
    run(out,'objcopy',['objcopy','-O','binary','-j','.text',str(obj),str(binary)])
    names=run(out,'nm',['nm','-n',str(obj)]).decode('ascii')
    reloc=run(out,'objdump',['objdump','-r',str(obj)]).decode('ascii')
    if 'R_X86_64' in reloc:print(reloc,flush=True)
    assert 'R_X86_64' not in reloc
    symbols={name:int(at,16) for at,_,name in (line.split() for line in names.splitlines())}
    code=binary.read_bytes()
    assert symbols['executor_start']==0 and symbols['executor_end']==len(code)
    table=symbols['image_table']
    assert 0<=table<=len(code)-512 and code[table:table+512]==bytes(512)
    assert path.read_bytes()==original
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+
        struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+
        struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+
        struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+code,176+table,original

def source(prefix,table):
    chunks=[]
    for start in range(0,len(prefix),512):
        lines=[f'def prefix_{start//512}(o:mutbuf) -> u64:']
        for at in range(start,min(len(prefix),start+512),8):
            raw=prefix[at:at+8]
            lines.append(f'    write(o, {at}, {int.from_bytes(raw,"little")}, {len(raw)})')
        lines.append('    return 0');chunks.append('\n'.join(lines)+'\n')
    body=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {HEADER} or read(s, 0) != {MAGIC} or read(s, 8) != 1:
        return 4294967293
    if read(s, 16) != {ROWS} or read(s, 24) != length(s) or read(s, 32) != 64:
        return 4294967293
    if read(s, 40) != 0 or read(s, 48) != 0 or read(s, 56) != 0:
        return 4294967293
    total = {HEADER}
    needed = {len(prefix)}
    i = 0
    while i < {ROWS}:
        size = read(s, 64 + i * 8)
        if size == 0 or size > 1048576 or total > length(s) or size > length(s) - total:
            return 4294967293
        total = total + size
        needed = ((needed + 15) & 18446744073709551600) + size
        i = i + 1
    if total != length(s):
        return 4294967293
    if length(o) < needed:
        return 4294967294
'''
    for i in range((len(prefix)+511)//512):body+=f'    prefix_{i}(o)\n'
    body+=f'''    write(o, 96, needed, 8)
    write(o, 104, needed, 8)
    source_at = {HEADER}
    target_at = {len(prefix)}
    i = 0
    while i < {ROWS}:
        size = read(s, 64 + i * 8)
        aligned = (target_at + 15) & 18446744073709551600
        while target_at < aligned:
            store(o, target_at, 0)
            target_at = target_at + 1
        write(o, {table} + (i + 1) * 8, 4194304 + target_at, 8)
        copy_bytes(o, s, target_at, source_at, size)
        source_at = source_at + size
        target_at = target_at + size
        i = i + 1
    if target_at != needed or source_at != length(s):
        return 4294967293
    return needed

def read(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def write(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''
    return body+'\n'.join(chunks)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--assembly',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    options=parser.parse_args()
    out=options.out.resolve();out.mkdir(parents=True,exist_ok=False)
    prefix,table,assembly=template(options.assembly,out)
    body=source(prefix,table)
    doc=document(body,'agent_default_json_fixed_packer')
    raw=render_assembly(doc).encode('utf-8')
    (out/'packer.authoring.py').write_text(body)
    (out/'agent_default_json_fixed_packer.hiaasm').write_bytes(raw)
    (out/'prefix.bin').write_bytes(prefix)
    row=dict(scope='DEVELOPMENT_SOURCE_NOT_COLD',prefix_bytes=len(prefix),
        prefix_sha256=sha256(prefix).hexdigest(),image_table=table,
        rows=ROWS,header_bytes=HEADER,profile=profile(doc),
        assembly_bytes=len(assembly),assembly_sha256=sha256(assembly).hexdigest(),
        source_bytes=len(raw),source_sha256=sha256(raw).hexdigest())
    (out/'layout.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
    assert options.assembly.read_bytes()==assembly
    print(json.dumps(row,sort_keys=True),flush=True)

if __name__=='__main__':main()

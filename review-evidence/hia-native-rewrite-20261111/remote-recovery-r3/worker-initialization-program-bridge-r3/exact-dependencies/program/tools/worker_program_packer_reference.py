"""HIA ELF packer for the original finite 63-role ordinary patch executor.

Development source, not an installed builder or a source-identity authority.
The caller binds each supplied image to its exact issued source manifest.
GNU as/objcopy produce only the immutable mechanical template; HIA emits the
complete final ELF and all table addresses. Missing optional roles stay zero.
"""
from pathlib import Path
from hashlib import sha256
import argparse,json,struct,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from cli_authoring import document,profile
from hepta.hia_agent_assembly import render_assembly
MAGIC=int.from_bytes(b'HIAPPK01','little')
ROWS=63
HEADER=64+ROWS*8

def run(out,label,argv):
    process=subprocess.run(argv,capture_output=True)
    (out/(label+'.stdout')).write_bytes(process.stdout)
    (out/(label+'.stderr')).write_bytes(process.stderr)
    (out/(label+'.process.json')).write_text(json.dumps({
        'argv':argv,'returncode':process.returncode,
        'stdout_bytes':len(process.stdout),'stderr_bytes':len(process.stderr),
        'stdout_sha256':sha256(process.stdout).hexdigest(),
        'stderr_sha256':sha256(process.stderr).hexdigest()},sort_keys=True,indent=2)+'\n')
    if process.returncode:
        sys.stdout.buffer.write(process.stdout);sys.stdout.buffer.flush()
        sys.stderr.buffer.write(process.stderr);sys.stderr.buffer.flush()
    process.check_returncode()
    return process.stdout

def template(path,out):
    original=path.read_bytes()
    (out/'source.S').write_bytes(original)
    obj=out/'carrier.o';binary=out/'carrier.bin'
    run(out,'as',['as','--64',str(out/'source.S'),'-o',str(obj)])
    run(out,'objcopy',['objcopy','-O','binary','-j','.text',str(obj),str(binary)])
    names=run(out,'nm',['nm','-n',str(obj)]).decode('ascii')
    reloc=run(out,'objdump',['objdump','-r',str(obj)]).decode('ascii')
    if 'R_X86_64' in reloc:
        print(reloc,flush=True)
    assert 'R_X86_64' not in reloc
    symbols={name:int(at,16) for at,_,name in (line.split() for line in names.splitlines())}
    assert symbols['executor_start']==0
    assert symbols['executor_end']==len(binary.read_bytes())
    tables=[symbols['image_table']]
    code=binary.read_bytes()
    assert len(set(tables))==1
    for at in tables:
        assert 0<=at<=len(code)-512 and code[at:at+512]==bytes(512)
    assert path.read_bytes()==original
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+
        struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+
        struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+
        struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+code,[176+at for at in tables],original

def source(prefix,tables):
    chunks=[]
    for start in range(0,len(prefix),512):
        lines=[f'def prefix_{start//512}(o:mutbuf) -> u64:']
        for at in range(start,min(len(prefix),start+512),8):
            raw=prefix[at:at+8]
            lines.append(f'    write(o, {at}, {int.from_bytes(raw,"little")}, {len(raw)})')
        lines.append('    return 0')
        chunks.append('\n'.join(lines)+'\n')
    body=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {HEADER} or read(s, 0) != {MAGIC} or read(s, 8) != 1 or read(s, 16) != 1 or read(s, 24) != {ROWS}:
        return 4294967293
    if read(s, 32) != length(s) or read(s, 40) != {HEADER} or read(s, 48) != 64 or read(s, 56) != 0:
        return 4294967293
    total = {HEADER}
    needed = {len(prefix)}
    i = 0
    while i < {ROWS}:
        size = read(s, 64 + i * 8)
        if size > 1048576 or total > length(s) or size > length(s) - total:
            return 4294967293
        if size == 0:
            return 4294967293
        total = total + size
        if size != 0:
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
        if size != 0:
            aligned = (target_at + 15) & 18446744073709551600
            while target_at < aligned:
                store(o, target_at, 0)
                target_at = target_at + 1
            table = {tables[0]}
            role = i + 1
            write(o, table + role * 8, 4194304 + target_at, 8)
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
    prefix,tables,assembly=template(options.assembly,out)
    body=source(prefix,tables)
    doc=document(body,'ordinary_patch_packer')
    hia=render_assembly(doc).encode('utf-8')
    (out/'ordinary_patch_packer.hiaasm').write_bytes(hia)
    (out/'prefix.bin').write_bytes(prefix)
    row=dict(scope='NEW_SOURCE_BOUND_DEVELOPMENT_NOT_COLD',
        prefix_bytes=len(prefix),prefix_sha256=sha256(prefix).hexdigest(),
        tables=tables,rows=ROWS,header_bytes=HEADER,profile=profile(doc),
        assembly_bytes=len(assembly),assembly_sha256=sha256(assembly).hexdigest(),
        source_bytes=len(hia),source_sha256=sha256(hia).hexdigest())
    (out/'layout.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
    assert options.assembly.read_bytes()==assembly
    print(json.dumps(row,sort_keys=True),flush=True)

if __name__=='__main__':main()

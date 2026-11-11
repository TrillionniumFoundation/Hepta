"""Native HIA ELF packer for the seven-image CLI entry development slice.

GNU as/objcopy are template authoring tools only. The emitted HIA writes every
ELF byte, embeds all seven actual images, and patches the fixed role table.
The private source-bound build fixture supplies the images; this packer alone
does not assert a complete clean source build or matching cold qualification.
"""
from pathlib import Path
import json,struct,subprocess,sys,tempfile
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT.parent/'Hepta-agent-edit-native')]
from cli_authoring import document,profile
from hepta.hia_agent_assembly import render_assembly
MAGIC=int.from_bytes(b'HIACLP01','little')

def template():
    assembly=(ROOT/'tools/cli_native_executor.S').read_bytes()
    audit=ROOT/'development/executor-template-reconstructed-r1'
    audit.mkdir(parents=True,exist_ok=False)
    (audit/'source.S').write_bytes(assembly)
    with tempfile.TemporaryDirectory(prefix='hia-cli-template-',dir='/dev/shm') as temp:
        directory=Path(temp);obj=directory/'cli.o';binary=directory/'cli.bin';snapshot=directory/'source.S'
        snapshot.write_bytes(assembly)
        def actual_tool(label,command):
            result=subprocess.run(command,capture_output=True)
            (audit/(label+'.stdout')).write_bytes(result.stdout)
            (audit/(label+'.stderr')).write_bytes(result.stderr)
            (audit/(label+'.process.json')).write_text(json.dumps({
                'command':command,'returncode':result.returncode,
                'stdout_bytes':len(result.stdout),'stderr_bytes':len(result.stderr),
                'stdout_sha256':sha256(result.stdout).hexdigest(),
                'stderr_sha256':sha256(result.stderr).hexdigest()},sort_keys=True,indent=2)+'\n')
            if result.returncode != 0:
                sys.stdout.buffer.write(result.stdout);sys.stdout.buffer.flush()
                sys.stderr.buffer.write(result.stderr);sys.stderr.buffer.flush()
            result.check_returncode()
            return result.stdout
        (audit/'source.json').write_text(json.dumps({'bytes':len(assembly),'sha256':sha256(assembly).hexdigest()},sort_keys=True)+'\n')
        actual_tool('as',['as','--64',str(snapshot),'-o',str(obj)])
        (audit/'object.o').write_bytes(obj.read_bytes())
        actual_tool('objcopy',['objcopy','-O','binary','-j','.text',str(obj),str(binary)])
        code=binary.read_bytes()
        (audit/'template.bin').write_bytes(code)
        symbol_text=actual_tool('nm',['nm','-n',str(obj)]).decode('utf-8')
        syms={name:int(at,16) for at,_,name in (line.split() for line in symbol_text.splitlines())}
        (audit/'symbols.json').write_text(json.dumps(syms,sort_keys=True,indent=2)+'\n')
        reloc=actual_tool('objdump',['objdump','-r',str(obj)]).decode('utf-8')
        (audit/'relocations.txt').write_text(reloc)
        assert 'R_X86_64' not in reloc
        assert (ROOT/'tools/cli_native_executor.S').read_bytes()==assembly
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+
            struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+
            struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+
            struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+code
    return prefix,176+syms['image_table']

def source():
    prefix,table=template()
    chunks=[]
    for start in range(0,len(prefix),512):
        lines=[f'def prefix_{start//512}(o:mutbuf) -> u64:']
        for at in range(start,min(len(prefix),start+512),8):
            raw=prefix[at:at+8]
            lines.append(f'    write(o, {at}, {int.from_bytes(raw,"little")}, {len(raw)})')
        lines.append('    return 0')
        chunks.append('\n'.join(lines)+'\n')
    head=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 120 or read(s, 0) != {MAGIC} or read(s, 8) != 1 or read(s, 16) != 7 or read(s, 24) != length(s) or read(s, 32) != 64:
        return 4294967293
    if read(s, 40) != 0 or read(s, 48) != 0 or read(s, 56) != 0:
        return 4294967293
    total = 120
    needed = {len(prefix)}
    i = 0
    while i < 7:
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
    for start in range(0,len(prefix),512):
        head+=f'    prefix_{start//512}(o)\n'
    head+=f'''    write(o, 96, needed, 8)
    write(o, 104, needed, 8)
    source_at = 120
    target_at = {len(prefix)}
    i = 0
    while i < 7:
        aligned = (target_at + 15) & 18446744073709551600
        while target_at < aligned:
            store(o, target_at, 0)
            target_at = target_at + 1
        size = read(s, 64 + i * 8)
        write(o, {table} + (i + 1) * 8, 4194304 + target_at, 8)
        copy_bytes(o, s, target_at, source_at, size)
        source_at = source_at + size
        target_at = target_at + size
        i = i + 1
    if target_at != needed:
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
    return head+'\n'.join(chunks),prefix,table

if __name__=='__main__':
    body,prefix,table=source()
    doc=document(body,'cli_native_packer')
    path=ROOT/'examples/hia_bootstrap/cli_native_packer.hiaasm'
    path.write_text(render_assembly(doc))
    (ROOT/'development/entry-executor-prefix-r1.bin').write_bytes(prefix)
    (ROOT/'development/entry-executor-layout-r1.json').write_text(
        json.dumps({'prefix_bytes':len(prefix),'image_table':table,'profile':profile(doc)},sort_keys=True,indent=2)+'\n')
    print(path.stat().st_size,profile(doc))

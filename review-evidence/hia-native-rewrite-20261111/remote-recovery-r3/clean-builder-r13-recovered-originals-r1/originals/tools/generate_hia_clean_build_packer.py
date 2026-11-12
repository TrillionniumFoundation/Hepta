"""HIA writes the native builder ELF; binutils is development template authoring."""
from pathlib import Path
import sys,struct,subprocess,tempfile,json
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent
sys.path[:0]=[str(ROOT/'tools'),str(BASE/'Hepta-agent-edit-native')]
from build_authoring import document,profile
from hepta.hia_agent_assembly import render_assembly
MAGIC=int.from_bytes(b'HIABPK01','little')
def template():
 with tempfile.TemporaryDirectory(prefix='hia-clean-build-template-',dir='/dev/shm') as tmp:
  tmp=Path(tmp);obj=tmp/'adapter.o';raw=tmp/'adapter.bin'
  subprocess.run(['as','--64',str(ROOT/'tools/clean_build_executor.S'),'-o',str(obj)],check=True,capture_output=True)
  subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
  syms={name:int(at,16) for at,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
  reloc=subprocess.check_output(['objdump','-r',str(obj)],text=True);assert 'R_X86_64' not in reloc
  code=raw.read_bytes()
 header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
 return header+code,{n:176+syms[n] for n in ('driver_call_hole','decoder_offset_value','self_size_value')}
def source():
 prefix,h=template();s=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 1048576:
        return 4294967295
    if read(s, 0) != {MAGIC} or read(s, 24) != 0:
        return 4294967295
    driver = read(s, 8)
    decoder = read(s, 16)
    if driver == 0 or decoder == 0 or driver > 1048576 or decoder > 1048576:
        return 4294967295
    if length(s) != 32 + driver + decoder:
        return 4294967295
    size = {len(prefix)} + driver + decoder
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
 for i in range(0,len(prefix),8):
  b=prefix[i:i+8];s+=f'    write(o, {i}, {int.from_bytes(b,"little")}, {len(b)})\n'
 s+=f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {h['driver_call_hole']}, {len(prefix)-h['driver_call_hole']-4}, 4)
    write(o, {h['decoder_offset_value']}, {len(prefix)} + driver, 8)
    write(o, {h['self_size_value']}, size, 8)
    copy_bytes(o, s, {len(prefix)}, 32, driver + decoder)
    return size

def read(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def write(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''
 return s,prefix,h
if __name__=='__main__':
 body,prefix,holes=source();doc=document(body,'clean_build_packer');p=ROOT/'examples/hia_bootstrap/clean_build_packer.hiaasm';p.write_text(render_assembly(doc));(ROOT/'development/executor-prefix-r1.bin').write_bytes(prefix);(ROOT/'development/executor-layout-r1.json').write_text(json.dumps(dict(bytes=len(prefix),holes=holes,profile=profile(doc)),indent=2)+'\n');print(p.stat().st_size,profile(doc))

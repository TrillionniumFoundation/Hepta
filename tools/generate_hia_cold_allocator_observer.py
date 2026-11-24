"""Author the native allocator observer and its closed dynamic ELF linker.

All admission, resource limits and phase choices are HIA. The bridge performs
only the selected loader, syscall, pointer and six-argument call actions.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from hashlib import sha256
import subprocess,struct,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_allocator_witness import document
from tools import generate_hia_linked_observer as linked
from tools import generate_hia_shared_linker as shared
ROOT=Path(__file__).resolve().parents[1]
POLICY=r'''
def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 512 or length(w) < 512:
        return 70
    phase = get(w, 0)
    if phase == 0:
        if get(w, 8) != 1:
            return finish(o, 64)
        put(o, 0, 4194337)
        put(o, 8, 10)
        put(o, 16, 268435456)
        put(o, 24, 8388608)
        put(o, 32, 16777216)
        put(o, 40, 32)
        put(o, 48, 0)
        put(o, 56, 0)
        put(w, 0, 1)
        return 1
    if phase == 1:
        if get(w, 16) != 0:
            return finish(o, 4)
        if length(s) < 32 or length(s) > 4194336:
            return finish(o, 2)
        if uint(s, 0) != @FRAME@:
            return finish(o, 2)
        image = uint(s, 8)
        fail = uint(s, 16)
        descriptor = uint(s, 24)
        if image == 0 or image > 4194304 or length(s) != 32 + image or fail > 10000:
            return finish(o, 2)
        if descriptor < 3 or descriptor > 2147483647:
            return finish(o, 2)
        put(w, 64, image)
        put(w, 72, fail)
        put(w, 80, descriptor)
        put(o, 0, 32)
        put(o, 8, image)
        put(o, 16, 2)
        put(o, 24, 15)
        put(w, 0, 2)
        return 2
    if phase == 2:
        if get(w, 16) != 0 or get(w, 32) != 15:
            return finish(o, 4)
        descriptor = get(w, 24)
        if descriptor < 3 or descriptor >= 32 or descriptor == get(w, 80):
            return finish(o, 4)
        path(o, descriptor)
        put(o, 0, 2)
        put(w, 0, 3)
        return 3
    if phase == 3:
        if get(w, 16) == 0:
            put(w, 0, 20)
            return 9
        write(o, 64, 12390, 3)
        put(w, 0, 4)
        return 4
    if phase == 4:
        if get(w, 16) != 0:
            return finish(o, 4)
        if get(w, 32) == 0:
            put(w, 0, 20)
            return 9
        put(o, 24, get(w, 80))
        put(w, 0, 5)
        return 12
    if phase == 5:
        if get(w, 16) != 0 or get(w, 32) != 1048712 or (get(w, 40) & 61440) != 32768:
            return finish(o, 4)
        put(o, 0, 1048712)
        put(o, 8, 0)
        put(o, 16, 0)
        put(o, 24, get(w, 80))
        put(o, 32, 165)
        put(o, 40, 0)
        put(w, 0, 6)
        return 5
    if phase == 6:
        if get(w, 16) != 0:
            return finish(o, 4)
        write(o, 64, @BEGIN_FIRST@, 8)
        write(o, 72, @BEGIN_LAST@, 7)
        put(w, 0, 7)
        return 10
    if phase == 7:
        if get(w, 16) != 0:
            return finish(o, 4)
        if get(w, 32) == 0:
            put(w, 0, 20)
            return 9
        put(o, 0, get(w, 72))
        put(o, 8, 32768)
        put(o, 16, 1048712)
        put(o, 24, 8)
        put(o, 32, 165)
        put(w, 0, 8)
        return 11
    if phase == 8:
        if get(w, 16) != 0:
            return finish(o, 4)
        arguments(o)
        put(w, 0, 9)
        return 6
    if phase == 9:
        if get(w, 16) != 0:
            return finish(o, 4)
        elapsed = (get(w, 40) - get(w, 24)) * 1000000000 + get(w, 48) - get(w, 32)
        put(o, 128, @RESPONSE@)
        put(o, 136, get(w, 56))
        put(o, 144, elapsed)
        arguments(o)
        put(w, 0, 10)
        return 7
    if phase == 10:
        if get(w, 16) != 0:
            return finish(o, 4)
        return finish(o, 0)
    if phase == 20:
        if get(w, 16) != 0:
            return finish(o, 4)
        return finish(o, 1)
    return finish(o, 70)

def arguments(o:mutbuf) -> u64:
    put(o, 0, 32)
    put(o, 8, 0)
    put(o, 16, 8)
    put(o, 24, 0)
    return 0
'''

def observed_bridge():
 src=(ROOT/'tools/hia_cold_allocator_observer.S').read_bytes()
 with TemporaryDirectory(prefix='hia-cold-observer-author-') as name:
  p=Path(name);(p/'bridge.S').write_bytes(src)
  r=subprocess.run(['as','--64','--fatal-warnings','-o',str(p/'bridge.o'),str(p/'bridge.S')],capture_output=True)
  if r.returncode or r.stderr:raise ValueError(r.stderr)
  raw=(p/'bridge.o').read_bytes()
  h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);rows=[struct.unpack_from('<IIQQQQIIQQ',raw,h[6]+i*64) for i in range(h[12])]
  r=rows[h[13]];ns=raw[r[4]:r[4]+r[5]]
  def name(data,at):return data[at:data.index(0,at)].decode()
  named={name(ns,r[0]):r for r in rows};tx=named['.text'];sy=named['.symtab'];st=rows[sy[6]];strings=raw[st[4]:st[4]+st[5]]
  symbols=[struct.unpack_from('<IBBHQQ',raw,sy[4]+i) for i in range(0,sy[5],24)];values={name(strings,r[0]):r for r in symbols};relocs=[]
  for row in rows:
   if row[1]==4 and rows[row[7]]==tx:
    for at in range(row[4],row[4]+row[5],24):
     off,info,add=struct.unpack_from('<QQq',raw,at);assert info&0xffffffff==4 and add==-4;relocs.append((off,name(strings,symbols[info>>32][0])))
  assert set(n for _,n in relocs)==set(linked.IMPORTS)
  parsed=(raw[tx[4]:tx[4]+tx[5]],tuple(relocs),values['policy_hole'][4],values['_start'][5])
 return src,raw,parsed

def packer_source(text,relocs,hole,start):
 linked.BRIDGE=text;linked.BRIDGE_RELOCATIONS=relocs;linked.POLICY_HOLE=hole;linked.START_SIZE=start
 parts=linked._parts
 def updated_parts():
  t,r,sy,st,n=parts();sy=bytearray(sy)
  for i in range(3,len(sy)//24):sy[i*24+4]=16
  return t,r,bytes(sy),st,n
 linked._parts=updated_parts
 section=linked._sections
 def updated_sections(*a):
  raw=bytearray(section(*a));struct.pack_into('<Q',raw,128+8,0);return bytes(raw)
 linked._sections=updated_sections
 return linked.packer_source().replace(str(int.from_bytes(b'HIALOP01','little')),str(int.from_bytes(b'HIACOP01','little')))

def executable_linker():
 source=shared.source_program();start=source.index('\ndef allowed_import(');end=source.index('\ndef check_calls(',start)
 imports=['def allowed_import(s:readbuf, first:u64, end:u64) -> u64:']
 for bit,name in enumerate(linked.IMPORTS):
  raw=name.encode()+bytes([0]);checks=[f'end - first >= {len(raw)}']
  for at in range(0,len(raw),8):
   c=raw[at:at+8];checks.append(f'uint(s, first + {at}, {len(c)}) == {int.from_bytes(c,"little")}')
  imports += ['    if '+' and '.join(checks)+':',f'        return {1<<bit}']
 imports.append('    return 0');source=source[:start]+'\n'+'\n'.join(imports)+'\n'+source[end:]
 source=source.replace('def link_shared(', 'def link_observer(')
 source=source.replace('if tag != 16 or value != 0 or extent != 0:', 'if (tag != 16 and tag != 18) or value != 0 or extent != 0:')
 source=source.replace('uint(s, h + 136, 8) != 0', '(uint(s, h + 136, 8) != 0 and uint(s, h + 136, 8) != 64)')
 source=source.replace('    layout(w)\n    total =','    if entry_admit(s, w) == 0:\n        return 4294967295\n    layout(w)\n    total =',1)
 source=re.sub(r'\b400\b','576',source);source=re.sub(r'\b408\b','584',source)
 source=source.replace('    write(o, 56, 6, 2)','    write(o, 56, 8, 2)')
 for old,new in [(344,456),(288,400),(232,344),(176,288),(120,232),(64,176)]:source=source.replace('segment(o, '+str(old)+',','segment(o, X'+str(new)+',')
 source=source.replace('segment(o, X','segment(o, ')
 source=source.replace('    rw = get(w, 176)\n    segment(o, 176', '    rw = get(w, 176)\n    put(o, 24, rx)\n    segment(o, 64, 6, 4, 64, 448, 448, 8)\n    segment(o, 120, 3, 4, 512, 28, 28, 1)\n    interpreter(o)\n    segment(o, 176',1)
 source+='''
def entry_admit(s:readbuf, w:mutbuf) -> u64:
    if get(w, 48) != 2 or get(w, 72) != 1 or get(w, 80) != 5:
        return 0
    row = get(w, 32) + 48
    name = uint(s, row, 4)
    if get(w, 64) - name < 7 or uint(s, get(w, 56) + name, 7) != 128034610115423:
        return 0
    if uint(s, row + 8, 8) != 0:
        return 0
    return 1

def interpreter(o:mutbuf) -> u64:
'''
 raw=b'/lib64/ld-linux-x86-64.so.2\0';assert len(raw)==28
 for at in range(0,len(raw),8):
  chunk=raw[at:at+8];source+=f'    write(o, {512+at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
 source+='    return 0\n';return source

def main():
 src,obj,(text,relocs,hole,start)=observed_bridge()
 policy=POLICY+linked.policy_source()[linked.policy_source().index('\ndef finish('):]
 for token,raw in [('FRAME',b'HIACAO01'),('RESPONSE',b'HIAOBR03'),('BEGIN_FIRST',b'hia_test'),('BEGIN_LAST',b'_begin\0')]:policy=policy.replace('@'+token+'@',str(int.from_bytes(raw,'little')))
 for name,source in [('cold_allocator_observer',policy),('cold_allocator_observer_packer',packer_source(text,relocs,hole,start)),('cold_observer_linker',executable_linker())]:
  d=document(source,module=name);out=render_assembly(d).encode();(ROOT/('examples/hia_bootstrap/'+name+'.hepta')).write_bytes(out)
  print(name,len(out),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']),sha256(out).hexdigest())
 print('ALLOCATOR_OBSERVER_BRIDGE',json.dumps({'source_sha256':sha256(src).hexdigest(),'object_sha256':sha256(obj).hexdigest(),'text_sha256':sha256(text).hexdigest(),'text_bytes':len(text),'policy_hole':hole,'imports':relocs,'start':start}))
if __name__=='__main__':main()

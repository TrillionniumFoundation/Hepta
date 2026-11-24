"""Author the HIA closed allocator-witness object composer and private-cell binder."""
from pathlib import Path
from tempfile import TemporaryDirectory
from hashlib import sha256
import subprocess,struct,json,ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_allocator_witness import document
ROOT=Path(__file__).resolve().parents[1]
IMPORTS=('abort','calloc','malloc','free','memset','memcpy','memmove')
STRINGS=b'\0f0\0hia_test_begin\0'+b''.join(x.encode()+b'\0' for x in IMPORTS)
NAMES=b'\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0'
def bridge():
 source=(ROOT/'tools/hia_cold_allocator_witness.S').read_bytes()
 with TemporaryDirectory(prefix='hia-cold-witness-author-') as name:
  d=Path(name);(d/'bridge.S').write_bytes(source)
  p=subprocess.run(['as','--64','--fatal-warnings','-o',str(d/'bridge.o'),str(d/'bridge.S')],capture_output=True)
  if p.returncode or p.stderr:raise ValueError(p.stderr.decode())
  obj=(d/'bridge.o').read_bytes()
 h=struct.unpack_from('<16sHHIQQQIHHHHHH',obj);sh=[struct.unpack_from('<IIQQQQIIQQ',obj,h[6]+64*i) for i in range(h[12])]
 ns=sh[h[13]];names=obj[ns[4]:ns[4]+ns[5]]
 def name(at,raw=names):return raw[at:raw.index(0,at)].decode()
 sections={name(row[0]):row for row in sh if row[0]}
 tr=sections['.text'];text=obj[tr[4]:tr[4]+tr[5]];sr=sections['.symtab'];st=sh[sr[6]];strings=obj[st[4]:st[4]+st[5]];symbols=[];addresses={}
 for at in range(sr[4],sr[4]+sr[5],24):
  row=struct.unpack_from('<IBBHQQ',obj,at);n=name(row[0],strings) if row[0] else '';symbols.append((n,row))
  if n:addresses[n]=row[4]
 rr=sections['.rela.text'];relocations=[]
 for at in range(rr[4],rr[4]+rr[5],24):
  off,info,addend=struct.unpack_from('<QQq',obj,at);n=symbols[info>>32][0]
  if n not in IMPORTS or info&0xffffffff!=4 or addend!=-4 or text[off-1:off+4]!=b'\xe8\0\0\0\0':raise ValueError('unreviewed witness import relocation')
  relocations.append((off,n))
 hole=addresses['hia_allocator_context_hole'];assert text[hole-3:hole+4]==bytes.fromhex('488d0500000000')
 assert addresses['hia_allocator_policy_offset']==len(text)
 return source,text,addresses,relocations,obj

SOURCE=r"""
def bundle(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 536 or length(s) > 8388608 or length(w) < 1048576:
        return 4294967293
    if uint(s, 0, 8) != @MAGIC@:
        return 4294967295
    policy = uint(s, 8, 8)
    object = uint(s, 16, 8)
    if policy == 0 or policy > 1048576 or object < 512 or object > 4194304:
        return 4294967295
    if length(s) != 24 + policy + object:
        return 4294967295
    put(w, 0, 24 + policy)
    put(w, 8, object)
    put(w, 16, policy)
    put(w, 24, (@PREFIX_LEN@ + policy + 15) & 18446744073709551600)
    if object_admit(s, w) == 0 or symbols_admit(s, w) == 0 or calls_admit(s, w) == 0:
        return 4294967295
    layout(w)
    total = get(w, 168)
    if total > length(o):
        return 4294967294
    zero(o, total)
    prefix(o, 64)
    copy(s, o, 24, 64 + @PREFIX_LEN@, policy)
    copy(s, o, get(w, 0) + get(w, 32), 64 + get(w, 24), get(w, 40))
    patch_fixture(s, o, w)
    object_emit(o, w)
    return total

def within(extent:u64, at:u64, count:u64) -> u64:
    return choose(at <= extent and count <= extent - at, 1, 0)

def object_admit(s:readbuf, w:mutbuf) -> u64:
    base = get(w, 0)
    size = get(w, 8)
    if uint(s, base, 8) != 282584257676671 or uint(s, base + 8, 8) != 0:
        return 0
    if uint(s, base + 16, 8) != 4299030529 or uint(s, base + 24, 8) != 0 or uint(s, base + 32, 8) != 0:
        return 0
    if uint(s, base + 48, 8) != 274877906944 or uint(s, base + 56, 2) != 0 or uint(s, base + 58, 2) != 64 or uint(s, base + 60, 2) != 7:
        return 0
    names_index = uint(s, base + 62, 2)
    sh = uint(s, base + 40, 8)
    if names_index == 0 or names_index >= 7 or sh < 64 or sh & 7 != 0 or sh != size - 448:
        return 0
    i = 0
    while i < 64:
        if byte(s, base + sh + i) != 0:
            return 0
        i = i + 1
    text = base + sh + 64
    if uint(s, text + 4, 4) != 1 or uint(s, text + 8, 8) != 6 or uint(s, text + 16, 8) != 0:
        return 0
    offset = uint(s, text + 24, 8)
    count = uint(s, text + 32, 8)
    if offset < 64 or offset & 15 != 0 or count == 0 or within(sh, offset, count) == 0:
        return 0
    put(w, 32, offset)
    put(w, 40, count)
    put(w, 112, get(w, 24) + count)
    sym_index = 0
    rela_index = 0
    i = 2
    while i < 7:
        row = base + sh + i * 64
        kind = uint(s, row + 4, 4)
        at = uint(s, row + 24, 8)
        count = uint(s, row + 32, 8)
        if uint(s, row + 16, 8) != 0 or at < 64 or within(sh, at, count) == 0:
            return 0
        if kind == 2:
            if sym_index != 0 or count < 72 or count % 24 != 0 or count // 24 > 8192 or uint(s, row + 56, 8) != 24:
                return 0
            sym_index = i
            put(w, 64, at)
            put(w, 72, count // 24)
            put(w, 192, uint(s, row + 40, 4))
        elif kind == 4:
            if rela_index != 0 or count % 24 != 0 or count // 24 > 32760 or uint(s, row + 56, 8) != 24 or uint(s, row + 44, 4) != 1:
                return 0
            rela_index = i
            put(w, 48, at)
            put(w, 56, count // 24)
            put(w, 176, uint(s, row + 40, 4))
        elif kind != 1 and kind != 3:
            return 0
        i = i + 1
    if sym_index == 0 or rela_index == 0 or get(w, 176) != sym_index:
        return 0
    strings_index = get(w, 192)
    if strings_index == 0 or strings_index >= 7 or strings_index == names_index:
        return 0
    strings = base + sh + strings_index * 64
    if uint(s, strings + 4, 4) != 3:
        return 0
    put(w, 80, uint(s, strings + 24, 8))
    put(w, 88, uint(s, strings + 32, 8))
    if get(w, 88) == 0 or byte(s, base + get(w, 80)) != 0:
        return 0
    return 1

def symbols_admit(s:readbuf, w:mutbuf) -> u64:
    base = get(w, 0)
    sym = base + get(w, 64)
    if uint(s, sym, 8) != 0 or uint(s, sym + 8, 8) != 0 or uint(s, sym + 16, 8) != 0:
        return 0
    if uint(s, sym + 24, 8) != 281487861612544 or uint(s, sym + 32, 8) != 0 or uint(s, sym + 40, 8) != 0:
        return 0
    put(w, 96, 18446744073709551615)
    i = 2
    while i < get(w, 72):
        row = sym + i * 24
        name = uint(s, row, 4)
        tag = uint(s, row + 4, 4)
        value = uint(s, row + 8, 8)
        size = uint(s, row + 16, 8)
        if name == 0 or name >= get(w, 88):
            return 0
        at = base + get(w, 80) + name
        end = base + get(w, 80) + get(w, 88)
        if tag == 65554:
            if end - at < 3 or uint(s, at, 3) != 12390 or get(w, 96) != 18446744073709551615:
                return 0
            if size == 0 or within(get(w, 40), value, size) == 0:
                return 0
            put(w, 96, value)
            put(w, 104, size)
            put(w, 32768 + i * 8, 9223372036854775808 | value)
        elif tag == 65538 or tag == 66050:
            if size == 0 or within(get(w, 40), value, size) == 0:
                return 0
            put(w, 32768 + i * 8, 9223372036854775808 | value)
        elif tag == 16 or tag == 18:
            if value != 0 or size != 0:
                return 0
            identity = import_name(s, at, end)
            if identity == 0:
                return 0
            put(w, 32768 + i * 8, identity)
        else:
            return 0
        i = i + 1
    return choose(get(w, 96) != 18446744073709551615, 1, 0)

def calls_admit(s:readbuf, w:mutbuf) -> u64:
    put(w, 120, 0)
    prefix_relocations(w)
    previous = 0
    i = 0
    while i < get(w, 56):
        row = get(w, 0) + get(w, 48) + i * 24
        at = uint(s, row, 8)
        symbol = uint(s, row + 12, 4)
        if at == 0 or (i != 0 and at < previous + 5) or within(get(w, 40), at, 4) == 0:
            return 0
        if uint(s, row + 8, 4) != 4 or symbol < 2 or symbol >= get(w, 72) or uint(s, row + 16, 8) != 18446744073709551612:
            return 0
        if uint(s, get(w, 0) + get(w, 32) + at - 1, 5) != 232:
            return 0
        identity = get(w, 32768 + symbol * 8)
        if identity < 9223372036854775808 and (identity < 2 or identity > 4):
            add_relocation(w, get(w, 24) + at, identity + 3)
        previous = at
        i = i + 1
    return 1

def add_relocation(w:mutbuf, at:u64, symbol:u64) -> u64:
    index = get(w, 120)
    put(w, 131072 + index * 16, at)
    put(w, 131080 + index * 16, symbol)
    put(w, 120, index + 1)
    return 0

def patch_fixture(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, 56):
        row = get(w, 0) + get(w, 48) + i * 24
        at = uint(s, row, 8)
        symbol = uint(s, row + 12, 4)
        identity = get(w, 32768 + symbol * 8)
        target = 18446744073709551615
        if identity >= 9223372036854775808:
            target = get(w, 24) + (identity & 9223372036854775807)
        elif identity >= 2 and identity <= 4:
            target = wrapper_offset(identity)
        if target != 18446744073709551615:
            write(o, 64 + get(w, 24) + at, target - get(w, 24) - at - 4, 4)
        i = i + 1
    return 0
"""
SOURCE+=r'''
def layout(w:mutbuf) -> u64:
    rela = (64 + get(w, 112) + 7) & 18446744073709551608
    sym = rela + get(w, 120) * 24
    strings = sym + 264
    names = strings + @STRINGS_LEN@
    sh = (names + @NAMES_LEN@ + 7) & 18446744073709551608
    put(w, 128, rela)
    put(w, 136, sym)
    put(w, 144, strings)
    put(w, 152, names)
    put(w, 160, sh)
    put(w, 168, sh + 448)
    return 0

def object_emit(o:mutbuf, w:mutbuf) -> u64:
    put(o, 0, 282584257676671)
    put(o, 16, 4299030529)
    put(o, 40, get(w, 160))
    write(o, 52, 64, 2)
    write(o, 58, 64, 2)
    write(o, 60, 7, 2)
    write(o, 62, 5, 2)
    sym = get(w, 136)
    put(o, sym + 24, 281487861612544)
    write(o, sym + 48, 1, 4)
    write(o, sym + 52, 65554, 4)
    put(o, sym + 56, get(w, 24) + get(w, 96))
    put(o, sym + 64, get(w, 104))
    write(o, sym + 72, 4, 4)
    write(o, sym + 76, 65554, 4)
    put(o, sym + 80, @BEGIN_OFFSET@)
    put(o, sym + 88, @BEGIN_SIZE@)
    object_imports(o, sym)
    object_strings(o, get(w, 144))
    object_names(o, get(w, 152))
    i = 0
    while i < get(w, 120):
        at = get(w, 128) + i * 24
        put(o, at, get(w, 131072 + i * 16))
        put(o, at + 8, (get(w, 131080 + i * 16) << 32) | 4)
        put(o, at + 16, 18446744073709551612)
        i = i + 1
    sh = get(w, 160)
    section(o, sh + 64, 1, 1, 6, 64, get(w, 112), 0, 0, 16, 0)
    section(o, sh + 128, 7, 4, 0, get(w, 128), get(w, 120) * 24, 3, 1, 8, 24)
    section(o, sh + 192, 18, 2, 0, sym, 264, 4, 2, 8, 24)
    section(o, sh + 256, 26, 3, 0, get(w, 144), @STRINGS_LEN@, 0, 0, 1, 0)
    section(o, sh + 320, 34, 3, 0, get(w, 152), @NAMES_LEN@, 0, 0, 1, 0)
    section(o, sh + 384, 44, 1, 0, get(w, 152) + @NAMES_LEN@, 0, 0, 0, 1, 0)
    return 0

def section(o:mutbuf, at:u64, name:u64, kind:u64, flags:u64, offset:u64, count:u64, link:u64, info:u64, align:u64, entry:u64) -> u64:
    write(o, at, name, 4)
    write(o, at + 4, kind, 4)
    put(o, at + 8, flags)
    put(o, at + 24, offset)
    put(o, at + 32, count)
    write(o, at + 40, link, 4)
    write(o, at + 44, info, 4)
    put(o, at + 48, align)
    put(o, at + 56, entry)
    return 0

def uint(s:readbuf, at:u64, count:u64) -> u64:
    value = 0
    i = 0
    while i < count:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(o:mutbuf, at:u64, value:u64) -> u64:
    return write(o, at, value, 8)

def write(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def copy(s:readbuf, o:mutbuf, src:u64, dst:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, dst + i, byte(s, src + i))
        i = i + 1
    return 0

def zero(o:mutbuf, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, i, 0)
        i = i + 1
    return 0
'''

def literals(name,raw):
 rows=[];parts=[]
 for start in range(0,len(raw),256):
  part=name+'_'+str(start//256);parts.append(part)
  lines=[f'def {part}(o:mutbuf, at:u64) -> u64:']
  for at in range(start,min(len(raw),start+256),8):
   chunk=raw[at:at+8];lines.append(f'    write(o, at + {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})')
  lines.append('    return 0');rows.append('\n'.join(lines))
 rows.append('\n'.join([f'def {name}(o:mutbuf, at:u64) -> u64:',*[f'    {p}(o, at)' for p in parts],'    return 0']))
 return '\n\n'.join(rows)+'\n'

def extra(text,addresses,relocations):
 result=literals('prefix',text)+literals('object_strings',STRINGS)+literals('object_names',NAMES)
 result+='\ndef prefix_relocations(w:mutbuf) -> u64:\n'+''.join(f'    add_relocation(w, {at}, {IMPORTS.index(n)+4})\n' for at,n in relocations)+'    return 0\n'
 result+='\ndef wrapper_offset(identity:u64) -> u64:\n'+''.join(f'    if identity == {i}:\n        return {addresses[n]}\n' for i,n in [(2,'hia_witness_calloc'),(3,'hia_witness_malloc'),(4,'hia_witness_free')])+'    return 18446744073709551615\n'
 result+='\ndef import_name(s:readbuf, at:u64, end:u64) -> u64:\n'
 for i,n in enumerate(IMPORTS,1):
  raw=n.encode()+b'\0';result+=f'    if end - at >= {len(raw)} and uint(s, at, {len(raw)}) == {int.from_bytes(raw,"little")}:\n        return {i}\n'
 result+='    return 0\n\ndef object_imports(o:mutbuf, at:u64) -> u64:\n'
 for i,n in enumerate(IMPORTS,4):
  result+=f'    write(o, at + {i*24}, {STRINGS.index(n.encode()+bytes([0]))}, 4)\n    write(o, at + {i*24+4}, 16, 4)\n'
 result+='    return 0\n';return result

BIND=r'''
def bind(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 4096 or length(s) > 8388608 or length(w) < 8192:
        return 4294967293
    if uint(s, 0, 8) != 282584257676671 or uint(s, 8, 8) != 0 or uint(s, 16, 8) != 4299030531:
        return 4294967295
    if uint(s, 32, 8) != 64 or uint(s, 52, 2) != 64 or uint(s, 54, 2) != 56 or uint(s, 56, 2) != 6:
        return 4294967295
    if uint(s, 120, 8) != 21474836481 or uint(s, 176, 8) != 25769803777 or uint(s, 344, 8) != 18865251666:
        return 4294967295
    text = uint(s, 128, 8)
    rw = uint(s, 184, 8)
    span = uint(s, 208, 8)
    if text < 4096 or text & 4095 != 0 or text != uint(s, 136, 8) or text != uint(s, 144, 8):
        return 4294967295
    if rw < text or rw & 4095 != 0 or rw != uint(s, 192, 8) or rw != uint(s, 200, 8):
        return 4294967295
    if uint(s, 152, 8) < @PREFIX_LEN@ or uint(s, 152, 8) != uint(s, 160, 8) or uint(s, 168, 8) != 4096:
        return 4294967295
    if text > length(s) or uint(s, 152, 8) > length(s) - text or uint(s, 152, 8) > rw - text:
        return 4294967295
    if rw > length(s) or span > length(s) - rw or span > 4096 or uint(s, 216, 8) != 4096 or uint(s, 224, 8) != 4096:
        return 4294967295
    if uint(s, 352, 8) != rw or uint(s, 360, 8) != rw or uint(s, 368, 8) != rw or uint(s, 376, 8) != span or uint(s, 384, 8) != 4096:
        return 4294967295
    if rw > 2147475455 or rw + 4096 <= text + @CONTEXT_HOLE@ + 4:
        return 4294967295
    prefix(w, 0)
    zero_range(w, 4096, @PREFIX_LEN@)
    relocation_mask(w)
    i = 0
    while i < @PREFIX_LEN@:
        if byte(w, 4096 + i) == 0 and byte(s, text + i) != byte(w, i):
            return 4294967295
        i = i + 1
    if length(o) < length(s):
        return 4294967294
    copy(s, o, 0, 0, length(s))
    put(o, 216, 8192)
    write(o, text + @CONTEXT_HOLE@, rw + 4096 - text - @CONTEXT_HOLE@ - 4, 4)
    return length(s)

def zero_range(o:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, 0)
        i = i + 1
    return 0
'''

def main():
 bridge_source,text,addresses,relocations,obj=bridge()
 values={'MAGIC':int.from_bytes(b'HIACAWP1','little'),'PREFIX_LEN':len(text),'STRINGS_LEN':len(STRINGS),'NAMES_LEN':len(NAMES),'BEGIN_OFFSET':addresses['hia_test_begin'],'BEGIN_SIZE':addresses['hia_witness_calloc']-addresses['hia_test_begin'],'CONTEXT_HOLE':addresses['hia_allocator_context_hole']}
 source=SOURCE+extra(text,addresses,relocations)
 helper=SOURCE[SOURCE.index('\ndef uint('):]
 mask='\ndef relocation_mask(o:mutbuf) -> u64:\n'+''.join(f'    write(o, {4096+at}, 16843009, 4)\n' for at,n in relocations)+'    return 0\n'
 binder=BIND+helper+literals('prefix',text)+mask
 for k,v in values.items():
  source=source.replace('@'+k+'@',str(v));binder=binder.replace('@'+k+'@',str(v))
 for name,raw in [('cold_allocator_bundle',source),('cold_allocator_bind',binder)]:
  d=document(raw,module=name);out=render_assembly(d).encode();(ROOT/('examples/hia_bootstrap/'+name+'.hepta')).write_bytes(out)
  print(name,len(out),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']),sha256(out).hexdigest())
 print('COLD_WITNESS_MECHANICAL_PREFIX',json.dumps({'source_sha256':sha256(bridge_source).hexdigest(),'text_bytes':len(text),'text_sha256':sha256(text).hexdigest(),'addresses':addresses,'relocations':relocations},sort_keys=True))
if __name__=='__main__':main()

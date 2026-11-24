"""Shared mechanical authoring and syscall helpers for native cold master roles."""
from pathlib import Path
import ast,struct,subprocess,tempfile
from tools.generate_hia_release_owner import POLICY as RELEASE_HELPERS
from tools.generate_hia_native_filter import LINK_SOURCE
ROOT=Path(__file__).resolve().parents[1]
DECODER='def unpack_chunk_rle(w:mutbuf, encoded:u64) -> u64:\n    if encoded < 33 or encoded > 65536 or (get(w, 800000) != 3544432143323187528 and get(w, 800000) != 3616489737361115464):\n        return 0\n    size = get(w, 800008)\n    payload = get(w, 800016)\n    mode = get(w, 800024)\n    if size == 0 or size > 65504 or payload != encoded - 32 or mode > 1:\n        return 0\n    if mode == 0:\n        if payload != size:\n            return 0\n        copyw(w, 940000, 800032, size)\n        return size\n    pos = 800032\n    end = 800000 + encoded\n    out = 0\n    while pos < end:\n        if end - pos < 8:\n            return 0\n        token = get(w, pos)\n        amount = token >> 1\n        pos = pos + 8\n        if amount == 0:\n            return 0\n        if token & 1 == 0:\n            if amount > end - pos or amount > size - out:\n                return 0\n            copyw(w, 940000 + out, pos, amount)\n            pos = pos + amount\n            out = out + amount\n        else:\n            if end - pos < 8 or amount > (size - out) >> 3:\n                return 0\n            value = get(w, pos)\n            pos = pos + 8\n            byte_value = value & 255\n            if value == byte_value * 72340172838076673:\n                fill_range(w, 940000 + out, amount * 8, byte_value)\n                out = out + amount * 8\n            else:\n                i = 0\n                while i < amount:\n                    put(w, 940000 + out, value)\n                    out = out + 8\n                    i = i + 1\n    if pos != end or out != size:\n        return 0\n    return size\n\ndef unpack_chunk(w:mutbuf, encoded:u64) -> u64:\n    if encoded < 33 or encoded > 65536:\n        return 0\n    magic = word_load(w, 800000)\n    if magic != 3544432143323187528 and magic != 3616489737361115464:\n        return 0\n    size = word_load(w, 800008)\n    payload = word_load(w, 800016)\n    mode = word_load(w, 800024)\n    if size == 0 or size > 65504 or payload != encoded - 32 or mode > 2:\n        return 0\n    if mode < 2:\n        return unpack_chunk_rle(w, encoded)\n    if magic != 3616489737361115464:\n        return 0\n    pos = 800032\n    end = 800000 + encoded\n    out = 0\n    while pos < end:\n        if end - pos < 3:\n            return 0\n        token = byte(w, pos)\n        amount = byte(w, pos + 1) | (byte(w, pos + 2) << 8)\n        pos = pos + 3\n        if amount == 0:\n            return 0\n        if token == 0:\n            if amount > end - pos or amount > size - out:\n                return 0\n            copyw(w, 940000 + out, pos, amount)\n            pos = pos + amount\n            out = out + amount\n        else:\n            if token != 1 or amount < 8 or end - pos < 2:\n                return 0\n            distance = byte(w, pos) | (byte(w, pos + 1) << 8)\n            pos = pos + 2\n            if distance == 0 or distance > out or amount > size - out:\n                return 0\n            copy_forward(w, 940000 + out, 940000 + out - distance, amount, distance)\n            out = out + amount\n    if pos != end or out != size:\n        return 0\n    return size\n\ndef copy_forward(w:mutbuf, to:u64, source:u64, size:u64, distance:u64) -> u64:\n    if distance != 0 and to >= source and to-source == distance and to <= length(w) and size <= length(w)-to:\n        first = choose(distance < size,distance,size)\n        copyw(w,to,source,first)\n        written = first\n        while written < size:\n            amount = choose(written < size-written,written,size-written)\n            copyw(w,to+written,to,amount)\n            written = written+amount\n        return 0\n    i = 0\n    if distance >= 8:\n        while i + 8 <= size:\n            value = word_load(w, source + i)\n            store(w, to + i, value & 255)\n            store(w, to + i + 1, (value >> 8) & 255)\n            store(w, to + i + 2, (value >> 16) & 255)\n            store(w, to + i + 3, (value >> 24) & 255)\n            store(w, to + i + 4, (value >> 32) & 255)\n            store(w, to + i + 5, (value >> 40) & 255)\n            store(w, to + i + 6, (value >> 48) & 255)\n            store(w, to + i + 7, (value >> 56) & 255)\n            i = i + 8\n    while i < size:\n        store(w, to + i, byte(w, source + i))\n        i = i + 1\n    return 0'
HELPER_NAMES=('writing','writing_at','reading','copying','transfer','hash_view','hashing','resume','sha','call','finish','minimum','same','same_input','copyw','failed','uint','get','getn','put')
def helpers():
 nodes={n.name:ast.get_source_segment(RELEASE_HELPERS,n) for n in ast.parse(RELEASE_HELPERS).body if isinstance(n,ast.FunctionDef)}
 nodes['uint']='def uint(s:readbuf,at:u64,count:u64) -> u64:\n    value = 0\n    i = 0\n    while i < count:\n        value = value | (byte(s,at+i) << (i*8))\n        i = i+1\n    return value\n'
 text='\n\n'.join(nodes[n] for n in HELPER_NAMES)
 return text.replace('return getn(w, at, 8)','return word_load(w, at)')
def template():
 with tempfile.TemporaryDirectory(prefix='hia-cold-master-author-') as tmp:
  obj=Path(tmp)/'a.o';raw=Path(tmp)/'a.bin'
  subprocess.run(['as','--64',str(ROOT/'tools/hia_cold_master_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
  subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
  symbols={name:int(addr,16) for addr,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
  assert symbols['_start']==0 and 'R_X86_64' not in subprocess.check_output(['objdump','-r',str(obj)],text=True)
  code=raw.read_bytes()
 header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
 return header+code,{n:176+symbols[n] for n in ('policy_hole','sha_hole')}
def packer(magic):
 prefix,holes=template()
 text=f"""def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 26 or uint(s,0,8) != {int.from_bytes(magic,'little')}:
        return 4294967295
    policy = uint(s,8,8)
    sha = uint(s,16,8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
"""
 for at in range(0,len(prefix),8):
  chunk=prefix[at:at+8];text+=f'    write(o,{at},{int.from_bytes(chunk,"little")},{len(chunk)})\n'
 text+=f"""    write(o,96,size,8)
    write(o,104,size,8)
    write(o,{holes['policy_hole']},{len(prefix)-holes['policy_hole']-4},4)
    write(o,{holes['sha_hole']},{len(prefix)-holes['sha_hole']-4}+policy,4)
    copy_bytes(s,o,24,{len(prefix)},policy+sha)
    return size
"""
 return text+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

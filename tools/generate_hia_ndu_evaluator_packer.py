"""Native HIA packer for the complete NDU leaf (four HIA roles).

The readable assembly capsules only translate Linux/syscall and six-word view
ABIs. No host linker, Rust library, floating helper, or interpreter is required
when the checked-in packer is executed.
"""
from pathlib import Path
import struct,subprocess,tempfile,json
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def ndu_pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 48 or length(s) > 4194352 or length(o) < 8388608:
        return 4294967293
    if word_load(s, 0) != MAGIC or word_load(s, 40) != 0:
        return 4294967295
    owner = word_load(s, 8)
    main = word_load(s, 16)
    number = word_load(s, 24)
    debug = word_load(s, 32)
    if owner < 16 or owner > 1048576 or main < 16 or main > 1048576 or number < 16 or number > 1048576 or debug < 16 or debug > 1048576:
        return 4294967295
    if length(s) != 48 + owner + main + number + debug:
        return 4294967295
    total = 176 + CLI_SIZE + JOIN_SIZE + owner + main + number + debug
    image_header(o)
    word_store(o, 96, total)
    word_store(o, 104, total)
    cli_prefix(o, 176)
    owner_at = 176 + CLI_SIZE
    join_at = owner_at + owner
    main_at = join_at + JOIN_SIZE
    number_at = main_at + main
    debug_at = number_at + number
    copy(s, o, 48, owner_at, owner)
    join_prefix(o, join_at)
    copy(s, o, 48 + owner, main_at, main + number + debug)
    poke32(o, 176 + CLI_OWNER, owner_at - (176 + CLI_OWNER + 4))
    poke32(o, 176 + CLI_EVAL, join_at - (176 + CLI_EVAL + 4))
    poke32(o, join_at + JOIN_MAIN1, main_at - (join_at + JOIN_MAIN1 + 4))
    poke32(o, join_at + JOIN_MAIN2, main_at - (join_at + JOIN_MAIN2 + 4))
    poke32(o, join_at + JOIN_NUMBER, number_at - (join_at + JOIN_NUMBER + 4))
    poke32(o, join_at + JOIN_DEBUG, debug_at - (join_at + JOIN_DEBUG + 4))
    return total

def copy(s:readbuf, o:mutbuf, at:u64, target:u64, size:u64) -> u64:
    i = 0
    while size - i >= 8:
        word_store(o, target + i, word_load(s, at + i))
        i = i + 8
    while i < size:
        store(o, target + i, byte(s, at + i))
        i = i + 1
    return target + size

def poke32(o:mutbuf, at:u64, value:u64) -> u64:
    store(o, at, value)
    store(o, at + 1, value >> 8)
    store(o, at + 2, value >> 16)
    store(o, at + 3, value >> 24)
    return 0
'''
def capsule(name):
    with tempfile.TemporaryDirectory()as tmp:
        p=Path(tmp);obj=p/'a.o';raw=p/'a.bin'
        subprocess.run(['as','--64','-o',str(obj),str(ROOT/'tools'/name)],check=True,capture_output=True)
        rel=subprocess.check_output(['readelf','-r',str(obj)],text=True)
        assert 'There are no relocations in this file.'in rel,rel
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={x.split()[-1]:int(x.split()[0],16) for x in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines()if len(x.split())==3}
        return raw.read_bytes(),symbols
def header():
    ident=b'\x7fELF'+bytes([2,1,1,0])+bytes(8)
    eh=struct.pack('<16sHHIQQQIHHHHHH',ident,2,62,1,0x400000+176,64,0,0,64,56,2,0,0,0)
    return eh+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16)
def literal(name,raw,with_at):
    lines=[f'def {name}(o:mutbuf'+(', at:u64'if with_at else '')+') -> u64:']
    off='at + 'if with_at else ''
    for i in range(0,len(raw)//8*8,8):lines.append(f'    word_store(o, {off}{i}, {int.from_bytes(raw[i:i+8],"little")})')
    for i in range(len(raw)//8*8,len(raw)):lines.append(f'    store(o, {off}{i}, {raw[i]})')
    lines.append('    return 0');return '\n'.join(lines)
def program():
    cli,c=capsule('hia_ndu_evaluator_syscalls.S');join,j=capsule('hia_ndu_evaluator_join.S')
    values={'MAGIC':int.from_bytes(b'HIANDP01','little'),'CLI_SIZE':len(cli),'JOIN_SIZE':len(join),'CLI_OWNER':c['transport_call'],'CLI_EVAL':c['evaluator_call'],'JOIN_MAIN1':j['main_call_1'],'JOIN_MAIN2':j['main_call_2'],'JOIN_NUMBER':j['number_call'],'JOIN_DEBUG':j['debug_call']}
    source=ENTRY
    import re
    for name,value in values.items():source=re.sub(r'\b'+name+r'\b',str(value),source)
    return '\n\n'.join([source,literal('image_header',header(),False),literal('cli_prefix',cli,True),literal('join_prefix',join,True)])
def render():return render_assembly(document(program(),'ndu_evaluator_packer'))
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/ndu_evaluator_packer.hepta';p.write_text(render());print(p.name,p.stat().st_size)

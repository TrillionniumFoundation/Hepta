"""Author the fixed twenty-component native system Jobctl ELF packer.

The adapter transports argv, environment, syscalls and calls between HIA owners.
All request, process, capture, publication and directory policy is HIA.
"""
from __future__ import annotations
import argparse,re,struct,subprocess,tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document

ROOT=Path(__file__).resolve().parents[1]
MAGIC=b'HIAJCT01'
MAXIMUM_IMAGE=4<<20
MODULES=(
 ('policy','system_jobctl_entry'),('control','system_jobctl_control'),
 ('json','system_jobctl_json'),('request','system_jobctl_request'),
 ('start','system_jobctl_start'),('record','system_jobctl_record'),
 ('process','system_jobctl_process'),('sha','sha256_stream'),
 ('observation','system_jobctl_observation'),('terminal','system_jobctl_terminal'),
 ('canonical','system_jobctl_value'),('supervisor','system_jobctl_supervisor'),
 ('spec','system_jobctl_spec'),('spawn','system_jobctl_spawn'),
 ('capture','system_jobctl_capture'),('publish','system_jobctl_publish'),
 ('scratch','system_jobctl_scratch'),('scratch_directory','system_jobctl_scratch_directory'),
 ('scratch_group','system_jobctl_scratch_group'),('vectors','system_jobctl_supervisor_vectors'),
)

def template():
    adapter=ROOT/'tools/hia_system_jobctl_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-system-jobctl-author-') as tmp:
        obj,raw=Path(tmp)/'adapter.o',Path(tmp)/'adapter.bin'
        subprocess.run(['as','--64',str(adapter),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(at,16) for at,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        if symbols['_start']!=0 or 'R_X86_64' in subprocess.check_output(['objdump','-r',str(obj)],text=True):
            raise ValueError('system Jobctl adapter has unresolved relocations')
        code=raw.read_bytes()
    head=(b'\x7fELF\x02\x01\x01'+bytes(9)
        +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return head+code,{alias:176+symbols[alias+'_hole'] for alias,_ in MODULES}

HELPERS=r'''
def uint(s:readbuf, at:u64) -> u64:
    return word_load(s, at)

def write(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    if size == 8:
        word_store(o, at, value)
        return 0
    index = 0
    while index < size:
        store(o, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def copy_bytes(s:readbuf, o:mutbuf, source:u64, target:u64, size:u64) -> u64:
    offset = 0
    while size - offset >= 8:
        word_store(o, target + offset, word_load(s, source + offset))
        offset = offset + 8
    while offset < size:
        store(o, target + offset, byte(s, source + offset))
        offset = offset + 1
    return 0
'''

def source_program():
    prefix,holes=template()
    header=8+8*len(MODULES)
    source=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {header} or uint(s, 0) != {int.from_bytes(MAGIC,'little')}:
        return 4294967295
    if length(w) < {8*len(MODULES)}:
        return 4294967294
    total = 0
    index = 0
    while index < {len(MODULES)}:
        size = uint(s, 8 + index * 8)
        if size == 0 or size > 1048576 or total > {MAXIMUM_IMAGE} or size > {MAXIMUM_IMAGE} - total:
            return 4294967295
        word_store(w, index * 8, total)
        total = total + size
        index = index + 1
    if length(s) != {header} + total:
        return 4294967295
    size = {len(prefix)} + total
    if size > {MAXIMUM_IMAGE} or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        raw=prefix[at:at+8]
        source+=f'    write(o, {at}, {int.from_bytes(raw,"little")}, {len(raw)})\n'
    source+='    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for index,(alias,_) in enumerate(MODULES):
        hole=holes[alias]
        source+=f'    write(o, {hole}, {len(prefix)} + word_load(w, {8*index}) - {hole+4}, 4)\n'
    source+=f'    copy_bytes(s, o, {header}, {len(prefix)}, total)\n    return size\n'
    return source+HELPERS

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_packer')
    text=render_assembly(doc)
    target=ROOT/'examples/hia_bootstrap/system_jobctl_packer.hepta'
    if args.check:
        if target.read_text()!=text:raise SystemExit('stale system Jobctl packer')
    else:target.write_text(text)
    print(target.name,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)

if __name__=='__main__':main()

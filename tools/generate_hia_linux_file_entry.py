"""Pure HIA ELF entry for the separate 8 MiB read-only file profile.

Only the result borrow grows to 8 MiB + 1; source/image/packer output remain
1 MiB. A private fd cell is outside every public borrow and the immutable
startup capability. Entry construction is HIA, without an assembler provider.
"""
from pathlib import Path
import ast
import hashlib
import json
import struct
import sys
import types

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import generate_hia_linux_process_entry as process
from tools.generate_hia_selfhost_linux_stdio import strict
from hepta.hia_agent_assembly import render_assembly

MAGIC=int.from_bytes(b'HIALFE1\x00','little')
FILE_MAGIC=int.from_bytes(b'HIALFIL1','little')
IMAGE_AT=1024
CAP=0x600000
STATE=0x601000
RESULT=0x602000
FILE_LIMIT=8388609
WORKSPACE=0xe03000
GUARD=0xf03000
STACK_TOP=0x1704000


def source_program():
    text=process.SOURCE
    text=strict(text,f'uint(s, 0, 8) != {process.MAGIC}',f'uint(s, 0, 8) != {MAGIC}')
    replacements={
        'write(o, 160, 10493952, 8)':f'write(o, 160, {STACK_TOP-CAP}, 8)',
        'at = register32(o, at, 4, 16785408)':f'at = register32(o, at, 4, {STACK_TOP})',
        'at = register32(o, at, 7, 8392704)':f'at = register32(o, at, 7, {GUARD})',
        'at = register32(o, at, 2, 6295552)':f'at = register32(o, at, 2, {RESULT})',
        'at = register32(o, at, 1, 1048576)':f'at = register32(o, at, 1, {FILE_LIMIT})',
        'at = register32(o, at, 8, 7344128)':f'at = register32(o, at, 8, {WORKSPACE})',
    }
    for before,after in replacements.items():text=strict(text,before,after)
    anchor='''    at = instruction(o, at, 0x00458949, 4)
    at = register32(o, at, 7, 6291456)
'''
    after=f'''    at = instruction(o, at, 0x00458949, 4)
    # Publish this file capability before sealing the CAP page. The fd cell
    # begins revoked; no HIA argument or serialized record supplies its value.
    at = instruction(o, at, 0xb848, 2)
    write(o, at, {FILE_MAGIC}, 8)
    at = at + 8
    at = instruction(o, at, 0x38458949, 4)
    at = instruction(o, at, 0x2504c748, 4)
    write(o, at, {STATE}, 4)
    at = at + 4
    write(o, at, 4294967295, 4)
    at = at + 4
    at = register32(o, at, 7, 6291456)
'''
    text=strict(text,anchor,after)
    # Normal return with an unretired file capability is a profile violation,
    # not a silent kernel-close success. Preserve eax (the HIA u32 result).
    anchor='''    at = at + 4
    at = instruction(o, at, 0xc789, 2)
'''
    after=f'''    at = at + 4
    at = instruction(o, at, 0x253c8348, 4)
    write(o, at, {STATE}, 4)
    at = at + 4
    at = instruction(o, at, 0x0b0f0274ff, 5)
    at = instruction(o, at, 0xc789, 2)
'''
    return strict(text,anchor,after)


def document():
    namespace=dict(vars(process));namespace['SOURCE']=source_program()
    doc=types.FunctionType(process.document.__code__,namespace)()
    doc['module']='linux_file_entry_packer'
    return doc


def frame(image):
    if type(image) is not bytes:raise TypeError('exact immutable image required')
    return struct.pack('<4Q',MAGIC,1,len(image),0)+image


def generated():return render_assembly(document())


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true')
    args=p.parse_args(argv);raw=generated().encode()
    target=ROOT/'examples/hia_bootstrap/linux_file_entry_packer.hepta'
    if args.check:
        if target.read_bytes()!=raw:raise SystemExit('Linux file entry source differs')
    else:target.write_bytes(raw)
    print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'file_result_extent':FILE_LIMIT,'workspace_extent':1048576,'image_limit':1048576,
        'matching_cold':False,'whole':False},sort_keys=True))

if __name__=='__main__':main()

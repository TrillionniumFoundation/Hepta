"""New captured two-resident entry using the original ELF/loan/limit protocol."""
from pathlib import Path
import hashlib
import json
import sys
import types

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import generate_hia_linux_file_render_entry as original
from tools.generate_hia_selfhost_linux_file_roundtrip import FILE_MAGIC,CALL_MAGIC
from hepta.hia_agent_assembly import render_assembly

MAGIC=int.from_bytes(b'HFRTPAK1','little')


def source_program():
    old=original.MAGIC
    assert old==int.from_bytes(b'HFLRPAK1','little') and original.PACK.count(str(old))==1
    namespace=dict(vars(original),FILE_MAGIC=FILE_MAGIC,CALL_MAGIC=CALL_MAGIC,
                   MAGIC=MAGIC,PACK=original.PACK.replace(str(old),str(MAGIC)))
    return types.FunctionType(original.source_program.__code__,namespace)()


def document():
    namespace=dict(vars(original),source_program=source_program)
    doc=types.FunctionType(original.document.__code__,namespace)()
    doc['module']='linux_file_roundtrip_entry_packer'
    return doc


def generated():
    return render_assembly(document())


def frame(images):
    return types.FunctionType(original.frame.__code__,dict(vars(original),MAGIC=MAGIC))(images)


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args(argv)
    raw=generated().encode();target=ROOT/'examples/hia_bootstrap/linux_file_roundtrip_entry_packer.hepta'
    if args.check:assert target.read_bytes()==raw
    else:target.write_bytes(raw)
    print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'matching_cold':False,'whole':False},sort_keys=True))


if __name__=='__main__':
    main()

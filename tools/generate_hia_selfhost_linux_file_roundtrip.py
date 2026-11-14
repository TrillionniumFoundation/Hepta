"""Independent explicit roundtrip compiler; ordinary B3 and v3 are retained."""
from pathlib import Path
import hashlib
import json
import sys
import types

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import generate_hia_selfhost_linux_file_render as original
from tools.generate_hia_selfhost_linux_stdio import build

MODULE='selfhost_linux_file_roundtrip'
EFFECT='linux_roundtrip'
OPS=('linux.roundtrip.representation','linux.roundtrip.semantic')
FILE_MAGIC=int.from_bytes(b'HIARTRD1','little')
CALL_MAGIC=int.from_bytes(b'HIARTRS1','little')


def extension_source():
    assert original.MODULE=='selfhost_linux_file_render'
    assert original.EFFECT=='linux_render' and original.OPS==('linux.render.frontend','linux.render.compiler')
    namespace=dict(vars(original),MODULE=MODULE,EFFECT=EFFECT,OPS=OPS,
                   FILE_MAGIC=FILE_MAGIC,CALL_MAGIC=CALL_MAGIC)
    source,proof=types.FunctionType(original.extension_source.__code__,namespace)()
    proof.update(explicit_module=MODULE,explicit_effect=EFFECT,
                 fixed_resident_source_roles=['private_three_request_representation','frozen_semantic_checker'],
                 new_file_capability_magic=FILE_MAGIC,new_resident_capability_magic=CALL_MAGIC,
                 original_compiler_or_profile_changed=False)
    return source,proof


def generated():
    return build(extension_source()[0],True)[0]


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');parser.add_argument('--report',type=Path)
    args=parser.parse_args(argv)
    source,proof=extension_source();raw,author,report=build(source,True)
    target=ROOT/'examples/hia_bootstrap/selfhost_linux_file_roundtrip.hepta'
    if args.check: assert target.read_text()==raw
    elif args.report is not None: target.open('x').write(raw)
    else: target.write_bytes(raw.encode())
    report.update(projection=proof,source_bytes=len(raw.encode()),source_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                  matching_cold=False,whole=False)
    if args.report:args.report.open('x').write(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('counts','source_bytes','source_sha256','matching_cold','whole')},sort_keys=True))


if __name__=='__main__':
    main()

"""Build the explicit Agent slice candidate from a matching completed cold B3."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:sys.path.insert(0,str(ROOT))
from tools.build_hia_json_preflight import (admit_cold_build, current_sources,
                                           build as build_candidate)


def build(output: Path, compiler: Path, cold_report: Path):
    sources = (ROOT/'examples/hia_bootstrap/agent_slice.hepta',
               ROOT/'examples/hia_bootstrap/native_filter_packer.hepta')
    pins = {p: p.read_bytes() for p in (compiler, cold_report, *sources)}
    admitted_sources = admit_cold_build(pins[compiler], pins[cold_report])
    if any(admitted_sources.get(p.relative_to(ROOT).as_posix()) != sha256(pins[p]).hexdigest()
           for p in sources):
        raise ValueError('native HIA Agent slice source differs from admitted cold source')
    result = build_candidate(output, compiler, cold_report, candidate='agent-slice')
    manifest_raw = result.read_bytes()
    metadata = json.loads(manifest_raw)
    image = result.parent/metadata['image_path']
    image_raw = image.read_bytes()
    from tools.generate_hia_native_filter import MAGIC
    from tools.qualify_hia_selfhost import invoke
    from tools.qualify_hia_selfhost_cli import inspect_executable
    packer_manifest = build_candidate(output/'filter',compiler,cold_report,candidate='native-filter')
    packer_manifest_raw = packer_manifest.read_bytes()
    packer_metadata = json.loads(packer_manifest_raw)
    packer = packer_manifest.parent/packer_metadata['image_path']
    packer_raw = packer.read_bytes()
    if sha256(packer_raw).hexdigest() != packer_metadata['image_sha256']:
        raise ValueError('native HIA Agent slice packer image changed')
    record, raw = invoke(output,'native-filter-pack',packer,
                         struct.pack('<2Q',MAGIC,len(image_raw))+image_raw)
    size = record.get('core_u32')
    if record.get('status') != 'returned' or type(size) is not int or not 0 < size <= min(len(raw),1 << 20):
        raise ValueError('native HIA filter packer refused Agent slice image')
    executable = raw[:size]
    inspection = inspect_executable(executable)
    if (any(p.read_bytes() != value for p, value in pins.items())
            or current_sources() != admitted_sources
            or result.read_bytes() != manifest_raw
            or packer_manifest.read_bytes() != packer_manifest_raw
            or packer.read_bytes() != packer_raw):
        raise ValueError('native HIA Agent slice build inputs changed')
    if image.read_bytes()!=image_raw or sha256(image_raw).hexdigest()!=metadata['image_sha256']:
        raise ValueError('native HIA Agent slice image changed')
    path = output/'hia-agent-slice'
    path.write_bytes(executable)
    path.chmod(0o700)
    (output/'filter-build.json').write_text(json.dumps({
        'schema':'hepta.hia.agent-slice-filter-build.v1','status':'NATIVE_FILTER_BUILT',
        'source_manifest':admitted_sources,
        'image_manifest':metadata,'packer_manifest':packer_metadata,
        'native_pack_receipt':record,'executable':inspection,
        'runtime_Python_or_host_payload_parser_required':False,
        'host_filesystem_build_driver':True,'whole_agent_replaced':False,
        'native_only_delivery_qualified':False,'production_activated':False},indent=2,sort_keys=True)+'\n')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--cold-report',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    print(build(a.output.resolve(),a.compiler.resolve(),a.cold_report.resolve()))


if __name__=='__main__':main()

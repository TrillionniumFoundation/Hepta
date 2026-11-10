"""Build an explicitly selected, syscall-only JSON Core compiler filter.

The trusted build driver binds a completed cold compiler and frontend bytes.
ELF layout/call relocation/image packing are done by the compiled HIA packer.
The delivered executable parses/verifies/compiles stdin without Python or ld.
This does not activate or replace the full production command surface.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.generate_hia_core_json_cli import MAGIC, LIMIT
from tools.build_hia_json_preflight import build as build_frontend
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'examples/hia_bootstrap/core_json_cli_packer.hiaasm'


def build(output: Path, compiler: Path, cold_report: Path, *, output_profile='flat') -> Path:
    if type(output_profile) is not str or output_profile not in ('flat','elf','exec'):
        raise ValueError('unknown native JSON CLI output profile')
    compiler_raw, cold_raw, packer_source = compiler.read_bytes(), cold_report.read_bytes(), SOURCE.read_bytes()
    frontend_source = (ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm').read_bytes()
    output.mkdir(mode=0o700)
    frontend_manifest = build_frontend(output/'frontend', compiler, cold_report, candidate='core-frontend')
    metadata = json.loads(frontend_manifest.read_bytes())
    frontend = frontend_manifest.parent/metadata['image_path']
    frontend_raw = frontend.read_bytes()
    packer, compile_receipt = compile_stage(output, 'native-packer', compiler, packer_source)
    frame = struct.pack('<4Q', MAGIC, len(frontend_raw), len(compiler_raw),
                        ('flat','elf','exec').index(output_profile))
    frame += frontend_raw + compiler_raw
    if len(frame) > LIMIT:
        raise ValueError('qualified images exceed unchanged packer source capacity')
    result, packed = invoke(output, 'native-pack', packer, frame)
    if not 0 < result['core_u32'] <= LIMIT or result['core_u32'] != len(packed[:result['core_u32']]):
        raise ValueError('native HIA packer rejected image frame')
    executable_bytes = packed[:result['core_u32']]
    inspection = inspect_executable(executable_bytes)
    if (compiler.read_bytes() != compiler_raw or cold_report.read_bytes() != cold_raw
            or SOURCE.read_bytes() != packer_source or frontend.read_bytes() != frontend_raw
            or (ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm').read_bytes() != frontend_source
            or sha256(frontend_raw).hexdigest() != metadata['image_sha256']):
        raise ValueError('native JSON CLI build inputs changed')
    executable = output/'hia-core-json'
    executable.write_bytes(executable_bytes)
    executable.chmod(0o700)
    report = {'schema':'hepta.hia.core-json-cli-build.v1', 'status':'NATIVE_JSON_CLI_BUILT',
        'output_profile':output_profile, 'executable':inspection,
        'compiler_sha256':sha256(compiler_raw).hexdigest(),
        'frontend_sha256':sha256(frontend_raw).hexdigest(),
        'frontend_source_sha256':sha256(frontend_source).hexdigest(),
        'packer_source_sha256':sha256(packer_source).hexdigest(),
        'packer_sha256':sha256(packer.read_bytes()).hexdigest(),
        'cold_report_sha256':sha256(cold_raw).hexdigest(),
        'frame_sha256':sha256(frame).hexdigest(),
        'native_compile_receipt':compile_receipt, 'native_pack_receipt':result,
        'runtime_Python_or_host_payload_parser_required':False,
        'host_filesystem_build_and_evidence_driver':True,
        'production_activated':False, 'whole_production_cli_replaced':False,
        'whole_stack_rewritten_in_hia':False}
    (output/'build.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--output-profile', choices=('flat','elf','exec'), default='flat')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                output_profile=args.output_profile))


if __name__ == '__main__':
    main()

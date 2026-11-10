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
from tools.build_hia_source_lexer import _checked_compile_receipt, _checked_native_emission

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'examples/hia_bootstrap/core_json_cli_packer.hiaasm'


def build(output: Path, compiler: Path, cold_report: Path, *, output_profile='flat') -> Path:
    if type(output_profile) is not str or output_profile not in ('flat','elf'):
        raise ValueError('unknown native JSON CLI output profile')
    compiler_raw, cold_raw, packer_source = compiler.read_bytes(), cold_report.read_bytes(), SOURCE.read_bytes()
    frontend_source = (ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm').read_bytes()
    output.mkdir(mode=0o700)
    frontend_manifest = build_frontend(output/'frontend', compiler, cold_report, candidate='core-frontend')
    metadata = json.loads(frontend_manifest.read_bytes())
    frontend_build = json.loads((frontend_manifest.parent/'build.json').read_bytes())
    frontend = frontend_manifest.parent/metadata['image_path']
    frontend_raw = frontend.read_bytes()
    if (type(frontend_build) is not dict
            or frontend_build.get('status') != 'NATIVE_CANDIDATE_BUILT'
            or frontend_build.get('manifest') != metadata
            or frontend_build.get('cold_report_sha256') != sha256(cold_raw).hexdigest()
            or metadata.get('compiler_sha256') != sha256(compiler_raw).hexdigest()
            or metadata.get('source_sha256') != sha256(frontend_source).hexdigest()
            or metadata.get('image_sha256') != sha256(frontend_raw).hexdigest()):
        raise ValueError('native JSON CLI frontend identity mismatch')
    packer, compile_receipt = compile_stage(output, 'native-packer', compiler, packer_source)
    packer_raw = packer.read_bytes()
    _checked_compile_receipt(compile_receipt, compiler_raw, packer_source, packer_raw)
    frame = struct.pack('<4Q', MAGIC, len(frontend_raw), len(compiler_raw), int(output_profile == 'elf'))
    frame += frontend_raw + compiler_raw
    if len(frame) > LIMIT:
        raise ValueError('qualified images exceed unchanged packer source capacity')
    result, packed = invoke(output, 'native-pack', packer, frame)
    executable_bytes = _checked_native_emission(result, packer_raw, frame, packed)
    if len(executable_bytes) > LIMIT:
        raise ValueError('native HIA packer rejected image frame')
    inspection = inspect_executable(executable_bytes)
    if (compiler.read_bytes() != compiler_raw or cold_report.read_bytes() != cold_raw
            or SOURCE.read_bytes() != packer_source or frontend.read_bytes() != frontend_raw
            or packer.read_bytes() != packer_raw
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
        'packer_sha256':sha256(packer_raw).hexdigest(),
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
    parser.add_argument('--output-profile', choices=('flat','elf'), default='flat')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                output_profile=args.output_profile))


if __name__ == '__main__':
    main()

"""Build the retained ObjectToken renderer from a matching-source cold compiler.

Compilation remains a fixed native ABI call. This builder validates compiler,
source, receipt and produced-byte custody before publishing an image manifest.
It neither activates a public route nor grants whole-stack qualification.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_NAME = 'examples/hia_bootstrap/nominal_tokens.hepta'
SCHEMA = 'hepta.hia.nominal-tokens-native.v1'
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))


def admit_compile_receipt(receipt, *, compiler_bytes: bytes,
                          source_bytes: bytes, image_bytes: bytes) -> None:
    """Bind the native child's actual input and executable bytes, strictly."""
    compiler_sha = sha256(compiler_bytes).hexdigest()
    source_sha = sha256(source_bytes).hexdigest()
    image_sha = sha256(image_bytes).hexdigest()
    numeric = {'input_bytes': len(source_bytes), 'produced_bytes': len(image_bytes),
               'result_u64': len(image_bytes), 'core_u32': len(image_bytes), 'abi_status': 0}
    if (type(receipt) is not dict or not image_bytes
            or len(image_bytes) > 0xffffffff
            or receipt.get('status') != 'returned'
            or receipt.get('format') != 'flat-x86-64'
            or receipt.get('return_encoding') != 'zero-extended-u32'
            or receipt.get('artifact_sha256') != compiler_sha
            or receipt.get('image_sha256') != compiler_sha
            or receipt.get('input_sha256') != source_sha
            or receipt.get('source_sha256') != source_sha
            or receipt.get('produced_sha256') != image_sha
            or receipt.get('source_unchanged') is not True
            or type(receipt.get('forbidden_compiler_modules_loaded')) is not list
            or receipt['forbidden_compiler_modules_loaded'] != []
            or any(type(receipt.get(key)) is not int or receipt[key] != value
                   for key, value in numeric.items())):
        raise ValueError('native nominal token compile receipt does not bind the consumed inputs and output')


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.build_hia_json_preflight import admit_cold_build, current_sources
    from tools.hia_selfhost_contract import PROFILE
    from tools.qualify_hia_selfhost import compile_stage

    compiler_bytes = compiler.read_bytes()
    cold_bytes = cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    source_path = ROOT / SOURCE_NAME
    source_bytes = source_path.read_bytes()
    if sources.get(SOURCE_NAME) != sha256(source_bytes).hexdigest():
        raise ValueError('nominal token source is not in the matching complete cold source contract')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'nominal-tokens', compiler, source_bytes)
    image_bytes = image.read_bytes()
    admit_compile_receipt(receipt, compiler_bytes=compiler_bytes,
                          source_bytes=source_bytes, image_bytes=image_bytes)
    receipt_path = output / 'nominal-tokens.receipt.json'
    receipt_bytes = receipt_path.read_bytes()
    if json.loads(receipt_bytes) != receipt:
        raise ValueError('nominal token compile receipt readback differs')
    if (source_path.read_bytes() != source_bytes or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or current_sources() != sources
            or image.read_bytes() != image_bytes or receipt_path.read_bytes() != receipt_bytes):
        raise ValueError('nominal token build input, receipt or image bytes changed')
    manifest = {'schema': SCHEMA, 'source_sha256': sha256(source_bytes).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    path = output / 'manifest.json'
    raw_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    path.write_bytes(raw_manifest)
    if path.read_bytes() != raw_manifest:
        raise ValueError('nominal token manifest readback differs')
    report = {'schema': 'hepta.hia.nominal-tokens-build.v1',
              'status': 'NATIVE_CANDIDATE_BUILT', 'scope': 'MATCHING_SOURCE_COLD',
              'profile': PROFILE, 'source_manifest': sources, 'manifest': manifest,
              'cold_report_sha256': sha256(cold_bytes).hexdigest(),
              'native_compile_receipt': receipt,
              'native_compile_receipt_sha256': sha256(receipt_bytes).hexdigest(),
              'all_payload_conversion_in_hia': True, 'public_diagnostics_replaced': False,
              'retained_typed_source_and_dictionary_handles': True,
              'production_activated': False, 'all_input_equivalence_proved': False,
              'whole_stack_rewritten_in_hia': False}
    report_path = output / 'build.json'
    report_bytes = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    report_path.write_bytes(report_bytes)
    if report_path.read_bytes() != report_bytes:
        raise ValueError('nominal token build report readback differs')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    path = build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve())
    print(json.dumps({'status': 'NATIVE_CANDIDATE_BUILT', 'manifest': str(path)}))


if __name__ == '__main__':
    main()

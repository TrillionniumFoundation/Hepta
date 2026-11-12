"""Build the explicit checkout-borrowed-byte ABI HIA owner.

Production build() requires a complete fresh cold report for the current source
closure before creating output. build_development() is a separate explicit
entry and records no cold authority. Neither entry activates the public selector or replaces the default backend.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_core_json_bytes import admit_compile_receipt
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCE_NAME = 'examples/hia_bootstrap/native_byte_abi.hiaasm'
SCHEMA = 'hepta.hia.native-byte-abi-native.v1'
BUILD_SCHEMA = 'hepta.hia.native-byte-abi-build.v1'
LABEL = 'native-byte-abi'
REQUIRED_SOURCE_NAMES = (
    SOURCE_NAME,
    'hepta/hia_native_byte_abi_native.py',
    'tools/generate_hia_native_byte_abi.py',
    'tools/build_hia_native_byte_abi.py',
    'tests/test_hia_native_byte_abi_native.py',
    'tests/fixtures/hia_native_byte_abi_4b.py.txt',
    'hepta/hia_native_byte_abi.py',
    'hepta/hia_native_byte_abi_selection.py',
    'hepta/hia_program_native.py',
    'tests/test_hia_native_byte_abi_integration.py',
    'tools/hia_native_byte_abi_control.py',
    'tools/hia_native_byte_abi_policy.py',
    'docs/HIA_NATIVE_BYTE_ABI_NATIVE.md',
    'tools/qualify_hia_native_byte_abi.py',
    'tests/test_hia_native_byte_abi.py',
    'tests/test_hia_agent_buffer_lifecycle.py',
    'tests/test_hia_agent_native_lease_snapshot.py',
)
DEVELOPMENT_INPUT_NAMES = REQUIRED_SOURCE_NAMES + (
    'hepta/hia_json_preflight_native.py',
    'hepta/hia_agent_assembly.py',
    'tools/build_hia_core_json_bytes.py',
    'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_selfhost.py',
    'tools/hia_selfhost_contract.py',
    'tools/generate_hia_selfhost.py',
    'hepta/hia_exception_delivery.py',
    'hepta/hia_machine_plan_control_native.py',
    'hepta/hia_checker_identity.py',
    'hepta/hia_native_helpers.py',
    'tools/hia_exception_delivery.py',
    'tools/hia_machine_plan_control.py',
    'tools/hia_core_lowering_control.py',
    'tools/hia_core_lowering_table.py',
    'tools/generate_hia_machine_plan_control.py',
    'tools/generate_hia_core_lowering.py',
)


def _digest(raw):
    return sha256(raw).hexdigest()


def _encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate native-byte-abi build receipt field')
        result[key] = value
    return result


def _publish(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
    if path.read_bytes() != raw:
        raise ValueError('native-byte-abi publication readback differs: ' + path.name)


def _build(output, compiler, compiler_bytes, source_bytes, consumed, recheck,
           *, scope, cold_bytes=None, sources=None):
    """Fixed compiler transport shared by two separately admitted entries."""
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, LABEL, compiler, source_bytes)
    image = Path(image)
    if image.parent != output or image.name != LABEL + '.image.bin':
        raise ValueError('native-byte-abi compiler published an unexpected image path')
    image_bytes = image.read_bytes()
    admit_compile_receipt(receipt, compiler_bytes=compiler_bytes,
                          source_bytes=source_bytes, image_bytes=image_bytes)
    if receipt.get('case') != LABEL or receipt.get('produced_image') != str(image):
        raise ValueError('native-byte-abi compile receipt names a different invocation or image')
    receipt_path = output / (LABEL + '.receipt.json')
    receipt_bytes = receipt_path.read_bytes()
    recorded = json.loads(receipt_bytes, object_pairs_hook=_pairs)
    admit_compile_receipt(recorded, compiler_bytes=compiler_bytes,
                          source_bytes=source_bytes, image_bytes=image_bytes)
    if _encoded(recorded) != _encoded(receipt):
        raise ValueError('native-byte-abi compile receipt readback differs')
    consumed[image], consumed[receipt_path] = image_bytes, receipt_bytes
    recheck()
    manifest = {'schema': SCHEMA, 'source_sha256': _digest(source_bytes),
                'image_path': image.name, 'image_sha256': _digest(image_bytes),
                'compiler_sha256': _digest(compiler_bytes)}
    filename = 'manifest.json' if cold_bytes is not None else 'development-manifest.json'
    manifest_path = output / filename
    manifest_bytes = _encoded(manifest)
    _publish(manifest_path, manifest_bytes)
    consumed[manifest_path] = manifest_bytes
    recheck()
    report = {
        'schema': BUILD_SCHEMA, 'status': 'NATIVE_CANDIDATE_BUILT', 'scope': scope,
        'manifest': manifest, 'native_compile_receipt': receipt,
        'native_compile_receipt_sha256': _digest(receipt_bytes),
        'component_sources': {name: _digest(consumed[ROOT / name])
                              for name in REQUIRED_SOURCE_NAMES},
        'cold_report_sha256': None if cold_bytes is None else _digest(cold_bytes),
        'source_manifest': sources,
        'production_activated': False, 'default_native_byte_abi_replaced': False,
        'all_input_equivalence_proved': False, 'whole_stack_rewritten_in_hia': False,
        'foreign_object_and_Code_ports_are_python': True,
        'original_compiler_child_timeout_seconds': 20,
    }
    if cold_bytes is None:
        report['development_input_manifest'] = {
            name: _digest(consumed[ROOT / name]) for name in DEVELOPMENT_INPUT_NAMES}
    else:
        from tools.hia_selfhost_contract import PROFILE
        report['profile'] = PROFILE
    report_path = output / ('build.json' if cold_bytes is not None else 'development-build.json')
    report_bytes = _encoded(report)
    _publish(report_path, report_bytes)
    consumed[report_path] = report_bytes
    recheck()
    return manifest_path


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    """Production build: no missing/old/partial cold or development fallback."""
    output, compiler, cold_report = (Path(p).resolve() for p in (output, compiler, cold_report))
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    component = {name: (ROOT / name).read_bytes() for name in REQUIRED_SOURCE_NAMES}
    if any(sources.get(name) != _digest(raw) for name, raw in component.items()):
        raise ValueError('native-byte-abi inputs are outside the complete matching cold source contract')
    consumed = {compiler: compiler_bytes, cold_report: cold_bytes,
                **{ROOT / name: raw for name, raw in component.items()}}

    def recheck():
        if (any(path.read_bytes() != raw for path, raw in consumed.items())
                or current_sources() != sources):
            raise ValueError('native-byte-abi build inputs, receipts or published bytes changed')

    recheck()
    return _build(output, compiler, compiler_bytes, component[SOURCE_NAME], consumed, recheck,
                  scope='MATCHING_SOURCE_COLD', cold_bytes=cold_bytes, sources=sources)


def build_development(output: Path, compiler: Path) -> Path:
    """Explicit retained compiler experiment; never called by production build."""
    output, compiler = (Path(p).resolve() for p in (output, compiler))
    compiler_bytes = compiler.read_bytes()
    component = {name: (ROOT / name).read_bytes() for name in DEVELOPMENT_INPUT_NAMES}
    consumed = {compiler: compiler_bytes,
                **{ROOT / name: raw for name, raw in component.items()}}

    def recheck():
        if any(path.read_bytes() != raw for path, raw in consumed.items()):
            raise ValueError('native-byte-abi development input or output bytes changed')

    recheck()
    return _build(output, compiler, compiler_bytes, component[SOURCE_NAME], consumed, recheck,
                  scope='EXPLICIT_COMPILER_DEVELOPMENT_COMPONENT')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development', action='store_true')
    args = parser.parse_args()
    path = (build_development(args.output, args.compiler) if args.development
            else build(args.output, args.compiler, args.cold_report))
    print(json.dumps({'status': 'NATIVE_CANDIDATE_BUILT', 'manifest': str(path),
                      'scope': 'DEVELOPMENT' if args.development else 'MATCHING_SOURCE_COLD'}))


if __name__ == '__main__':
    main()

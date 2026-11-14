"""Build the explicit normalization candidate from a complete current-source cold run.

This command produces a source-bound development selection, never a claim of
whole public-domain equivalence. It does not activate a public route. The
physical-recursion and hosted CPython boundaries remain open. No predecessor
compiler or development receipt is accepted by this production builder.
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

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_core_json_bytes import admit_compile_receipt
from tools.qualify_hia_selfhost import compile_stage, invoke

BUILD_SCHEMA = 'hepta.hia.program-normalization-build.v1'
PRODUCTION_SCHEMA = 'hepta.hia.cpython-note-packer-production.v2'
COMPONENTS = {
    'normalization': 'examples/hia_bootstrap/program_normalization.hepta',
    'front': 'examples/hia_bootstrap/core_json_bytes.hepta',
    'binary64': 'examples/hia_bootstrap/agent_binary64.hepta',
    'binary64_format': 'examples/hia_bootstrap/agent_binary64_format.hepta',
}
NOTE_SOURCE = 'examples/hia_bootstrap/cpython_note_packer.hepta'
NOTE_BYTES = 298
NOTE_SHA256 = 'd1ed5ac60b3d84952157262d6ea4252cbe4346c38417281945af636f5deacf23'
REQUIRED_SOURCE_NAMES = (
    *COMPONENTS.values(), NOTE_SOURCE,
    'hepta/hia_program_normalization_native.py',
    'hepta/hia_program_normalization_notes.py',
    'hepta/hia_core_json_bytes_native.py',
    'hepta/hia_agent_binary64_native.py',
    'hepta/hia_agent_binary64_format_native.py',
    'hepta/hia_json_preflight_native.py',
    'tools/build_hia_program_normalization.py',
    'tools/build_hia_core_json_bytes.py',
    'tools/generate_hia_program_normalization.py',
    'tools/hia_program_normalization_encoding.py',
    'tools/hia_program_normalization_front_diagnostics.py',
    'tools/hia_program_normalization_materialize.py',
    'tools/hia_program_normalization_materialize.hepta',
    'tools/generate_hia_core_json_bytes.py',
    'tools/generate_hia_cpython_note_packer.py',
    'tests/test_hia_program_normalization_native.py',
    'tests/test_hia_cpython_note_packer_native.py',
    'tests/fixtures/hia_normalization_retained_v70.json',
    'tools/hia_cpython_note_packer_reference.S',
    'tools/hia_cpython_note_packer_reference.ld',
    'tools/hia_program_normalization_notes.c',
    'tools/hia_program_normalization_notes.ld',
    'docs/HIA_PROGRAM_NORMALIZATION_NATIVE.md',
    'docs/HIA_PROGRAM_NORMALIZATION_NOTES_DEVELOPMENT.md',
    'docs/HIA_CPYTHON_NOTE_PACKER_DEVELOPMENT.md',
)


def _digest(data):
    return sha256(data).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate normalization build receipt field')
        result[key] = value
    return result


def _json(data):
    return json.loads(data, object_pairs_hook=_pairs)


def _encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def _publish(path, data):
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
    if path.read_bytes() != data:
        raise ValueError('normalization publication readback differs: ' + path.name)


def admit_note_emission(receipt, *, packer_bytes, image_bytes):
    numeric = {'input_bytes': 0, 'result_u64': len(image_bytes),
               'core_u32': len(image_bytes), 'abi_status': 0}
    if (type(receipt) is not dict or type(image_bytes) is not bytes
            or len(image_bytes) != NOTE_BYTES or _digest(image_bytes) != NOTE_SHA256
            or receipt.get('status') != 'returned'
            or receipt.get('format') != 'flat-x86-64'
            or receipt.get('return_encoding') != 'zero-extended-u32'
            or receipt.get('artifact_sha256') != _digest(packer_bytes)
            or receipt.get('image_sha256') != _digest(packer_bytes)
            or receipt.get('source_sha256') != _digest(b'')
            or receipt.get('input_sha256') != _digest(b'')
            or receipt.get('output_sha256') != _digest(image_bytes)
            or receipt.get('source_unchanged') is not True
            or type(receipt.get('forbidden_compiler_modules_loaded')) is not list
            or receipt['forbidden_compiler_modules_loaded'] != []
            or any(type(receipt.get(key)) is not int or receipt[key] != value
                   for key, value in numeric.items())):
        raise ValueError('HIA note emission receipt does not bind complete emitted bytes')


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from hepta.hia_program_normalization_native import SCHEMA, NOTE_SCHEMA
    from hepta.hia_program_normalization_notes import (
        NativeCPythonNotes, require_supported_interpreter,
    )
    from tools.hia_selfhost_contract import PROFILE

    require_supported_interpreter()
    compiler, cold_report, output = Path(compiler), Path(cold_report), Path(output)
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    # Complete source admission precedes any output-directory side effect.
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    source_bytes = {name: (ROOT / name).read_bytes() for name in REQUIRED_SOURCE_NAMES}
    if any(sources.get(name) != _digest(raw) for name, raw in source_bytes.items()):
        raise ValueError('normalization build input is outside the admitted complete cold source contract')
    consumed = {compiler: compiler_bytes, cold_report: cold_bytes,
                **{ROOT / name: raw for name, raw in source_bytes.items()}}

    def recheck():
        if (any(path.read_bytes() != data for path, data in consumed.items())
                or current_sources() != sources):
            raise ValueError('normalization build inputs, receipts or produced bytes changed')

    recheck()
    output.mkdir(mode=0o700)
    images, receipts = {}, {}
    for name, source_name in {**COMPONENTS, 'note_packer': NOTE_SOURCE}.items():
        image, receipt = compile_stage(output, name, compiler, source_bytes[source_name])
        image = Path(image)
        if image.parent != output or image.name != name + '.image.bin':
            raise ValueError('normalization compiler published an unexpected image path')
        raw = image.read_bytes()
        admit_compile_receipt(receipt, compiler_bytes=compiler_bytes,
                              source_bytes=source_bytes[source_name], image_bytes=raw)
        receipt_path = output / (name + '.receipt.json')
        receipt_bytes = receipt_path.read_bytes()
        recorded = _json(receipt_bytes)
        admit_compile_receipt(recorded, compiler_bytes=compiler_bytes,
                              source_bytes=source_bytes[source_name], image_bytes=raw)
        if _encoded(recorded) != _encoded(receipt):
            raise ValueError('normalization native compile receipt readback differs')
        images[name] = (image, raw)
        receipts[name] = receipt
        consumed[image], consumed[receipt_path] = raw, receipt_bytes
        recheck()

    packer_path, packer_bytes = images['note_packer']
    emission, note_bytes = invoke(output, 'note_emit', packer_path, b'',
                                 capacity=NOTE_BYTES, workspace_size=64)
    admit_note_emission(emission, packer_bytes=packer_bytes, image_bytes=note_bytes)
    emission_path = output / 'note_emit.receipt.json'
    emission_bytes = emission_path.read_bytes()
    recorded_emission = _json(emission_bytes)
    admit_note_emission(recorded_emission, packer_bytes=packer_bytes, image_bytes=note_bytes)
    if _encoded(recorded_emission) != _encoded(emission):
        raise ValueError('HIA note emission receipt readback differs')
    consumed[emission_path] = emission_bytes
    note_path = output / 'cpython-notes.image.bin'
    recheck()
    _publish(note_path, note_bytes)
    consumed[note_path] = note_bytes

    production = {
        'schema': PRODUCTION_SCHEMA, 'status': 'NATIVE_HIA_PACKER_EMITTED',
        'scope': 'MATCHING_SOURCE_COLD', 'profile': PROFILE,
        'source_manifest': sources,
        'compiler_sha256': _digest(compiler_bytes),
        'cold_report_sha256': _digest(cold_bytes),
        'source_sha256': _digest(source_bytes[NOTE_SOURCE]),
        'packer_image_sha256': _digest(packer_bytes),
        'image_sha256': _digest(note_bytes),
        'native_compilation': receipts['note_packer'],
        'native_emission': emission,
        'production_c_compiler_used': False,
        'physical_recursion_qualified': False,
        'whole_stack_rewritten_in_hia': False,
    }
    production_path = output / 'cpython-note-production.json'
    production_bytes = _encoded(production)
    recheck()
    _publish(production_path, production_bytes)
    consumed[production_path] = production_bytes

    # This fixed mapping obtains the actual interpreter/export-image identity;
    # it performs no document normalization and grants no all-input proof.
    notes = NativeCPythonNotes(note_bytes, _digest(note_bytes))
    try:
        identity = notes.interpreter_identity
        interpreter = {
            'implementation': 'cpython', 'version': identity['version'],
            'hexversion': identity['hexversion'], 'soabi': identity['soabi'],
            'executable_sha256': identity['executable_sha256'],
            'api_images': {row['name']: row['image_sha256'] for row in notes.api_identity},
        }
        for path in {identity['executable'], *(row['image'] for row in notes.api_identity)}:
            actual = Path(path).read_bytes()
            expected = identity['executable_sha256'] if path == identity['executable'] else next(
                row['image_sha256'] for row in notes.api_identity if row['image'] == path)
            if _digest(actual) != expected:
                raise ValueError('interpreter changed while binding normalization manifest')
            consumed[Path(path)] = actual
    finally:
        notes.close()
    manifest = {
        'schema': SCHEMA,
        'images': {name: {'image_path': images[name][0].name,
                         'image_sha256': _digest(images[name][1]),
                         'source_sha256': _digest(source_bytes[source_name])}
                   for name, source_name in COMPONENTS.items()},
        'hosted_mechanisms': {'cpython_notes': {
            'schema': NOTE_SCHEMA, 'image_path': note_path.name,
            'image_sha256': _digest(note_bytes),
            'sources': {name: _digest(source_bytes[name])
                        for name in (NOTE_SOURCE, 'hepta/hia_program_normalization_notes.py')},
            'production': {
                'receipt_path': production_path.name, 'receipt_sha256': _digest(production_bytes),
                'packer_image_path': packer_path.name, 'packer_image_sha256': _digest(packer_bytes)},
            'interpreter': interpreter,
        }},
    }
    report = {
        'schema': BUILD_SCHEMA, 'status': 'NATIVE_CANDIDATE_BUILT',
        'scope': 'MATCHING_SOURCE_COLD', 'profile': PROFILE,
        'source_manifest': sources, 'manifest': manifest,
        'compiler_sha256': _digest(compiler_bytes),
        'cold_report_sha256': _digest(cold_bytes),
        'compile_receipts': receipts, 'note_emission_receipt': emission,
        'production_c_compiler_used': False, 'packet_dependency_executed': False,
        'packet_dependency_required': False, 'default_changed': False,
        'physical_recursion_qualified': False, 'all_input_equivalence_proved': False,
        'whole_stack_rewritten_in_hia': False,
    }
    # Recheck immediately before and after both final publications. A failed
    # build leaves diagnostic intermediates but cannot return an admitted path.
    manifest_path, report_path = output / 'manifest.json', output / 'build.json'
    manifest_bytes, report_bytes = _encoded(manifest), _encoded(report)
    recheck()
    _publish(manifest_path, manifest_bytes)
    consumed[manifest_path] = manifest_bytes
    recheck()
    _publish(report_path, report_bytes)
    consumed[report_path] = report_bytes
    recheck()
    return manifest_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve())
    print(json.dumps({'status': 'NATIVE_CANDIDATE_BUILT', 'manifest': str(result)}))


if __name__ == '__main__':
    main()

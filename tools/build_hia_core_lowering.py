"""Build the complete HIA Core lowering bundle after matching-source cold admission."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))


def build(output: Path, compiler: Path, cold_report: Path, *, profile='v1') -> Path:
    from hepta.hia_core_lowering_selection import SCHEMA, SCHEMA_V2, bundle_profile
    if type(profile) is not str or profile not in ('v1', 'v2'):
        raise ValueError('native Core lowering build profile differs')
    schema = SCHEMA_V2 if profile == 'v2' else SCHEMA
    ABI_SOURCE, UNIT_SCHEMA, checked_abi, pool = bundle_profile(schema)
    from tools.build_hia_json_preflight import admit_cold_build, current_sources
    from tools.hia_selfhost_contract import PROFILE
    from tools.qualify_hia_selfhost import compile_stage

    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    abi_raw = (ROOT / ABI_SOURCE).read_bytes()
    abi = checked_abi(abi_raw)
    names = (pool, *abi['units'])
    inputs = {ABI_SOURCE: abi_raw}
    for name in names:
        relative = 'examples/hia_bootstrap/' + name + '.hepta'
        inputs[relative] = (ROOT / relative).read_bytes()
    for relative, raw in inputs.items():
        if sources.get(relative) != sha256(raw).hexdigest():
            raise ValueError('Core lowering source differs from admitted cold: ' + relative)
    # Every source and ABI is admitted before this create-only output mutation.
    output.mkdir(mode=0o700)
    compiler_sha = sha256(compiler_bytes).hexdigest()
    receipts, manifests, images = [], {}, []
    manifest_inputs = []
    for name in names:
        folder = output / name
        folder.mkdir(mode=0o700)
        relative = 'examples/hia_bootstrap/' + name + '.hepta'
        image, receipt = compile_stage(folder, name, compiler, inputs[relative])
        image_raw = image.read_bytes()
        manifest = {
            'schema': UNIT_SCHEMA, 'source_sha256': sha256(inputs[relative]).hexdigest(),
            'image_path': image.name, 'image_sha256': sha256(image_raw).hexdigest(),
            'compiler_sha256': compiler_sha,
        }
        manifest_path = folder / 'manifest.json'
        manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        with manifest_path.open('xb') as stream:
            stream.write(manifest_raw)
        manifest_inputs.append((manifest_path, manifest_raw))
        manifests[name] = name + '/manifest.json'
        receipts.append({'name': name, 'source': relative, 'manifest': manifest,
                         'native_compile_receipt': receipt})
        images.append((image, image_raw))
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or current_sources() != sources
            or any((ROOT / relative).read_bytes() != raw for relative, raw in inputs.items())
            or any(path.read_bytes() != raw for path, raw in (*images, *manifest_inputs))):
        raise ValueError('Core lowering complete build inputs or images changed')
    bundle = {
        'schema': schema, 'abi_sha256': sha256(abi_raw).hexdigest(),
        'compiler_sha256': compiler_sha, 'unit_manifests': manifests,
    }
    manifest_path = output / 'manifest.json'
    with manifest_path.open('xb') as stream:
        stream.write((json.dumps(bundle, sort_keys=True, indent=2) + '\n').encode())
    report = {
        'schema': 'hepta.hia.core-lowering-build.' + profile, 'status': 'NATIVE_CANDIDATE_BUILT',
        'profile': PROFILE, 'source_manifest': sources,
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'compiler_sha256': compiler_sha, 'bundle': bundle,
        'abi_sha256': sha256(abi_raw).hexdigest(), 'units': receipts,
        'expected_unit_count': len(names), 'actual_unit_count': len(receipts),
        'complete_Function_methods': 22, 'complete_shared_helpers': 5,
        'hosted_object_primitive_kinds': 19 if profile == 'v2' else 18,
        'ordinary_entry_requires_explicit_selector': True,
        'module_Emitter_control_and_native_object_runtime_still_hosted': profile == 'v1',
        'complete_Emitter_methods': 6 if profile == 'v2' else 0,
        'native_lazy_generator_modes': 2 if profile == 'v2' else 0,
        'native_object_runtime_still_hosted': True,
        'native_persistence_or_linking_claimed': False,
        'whole_stack_rewritten_in_hia': False, 'production_activated': False,
    }
    with (output / 'build.json').open('xb') as stream:
        stream.write((json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    return manifest_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--cold-report', required=True, type=Path)
    parser.add_argument('--profile', choices=('v1', 'v2'), default='v1')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(), profile=args.profile))

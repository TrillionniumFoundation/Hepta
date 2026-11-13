"""Build the complete five-image HIA function owner from one exact cold run.

This packages native compiler results. It does not execute or plan nominal
lowering, activate production, or turn development artifacts into qualification.
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


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from hepta.hia_composite_functions_native import KERNELS, SCHEMA
    from tools.build_hia_json_preflight import admit_cold_build, build as build_kernel, current_sources
    from tools.hia_selfhost_contract import PROFILE

    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    paths = {name: 'examples/hia_bootstrap/composite_function_' + name + '.hepta'
             for name in KERNELS}
    paths.update(types='examples/hia_bootstrap/composite_types.hepta',
                 helpers='examples/hia_bootstrap/task_helpers.hepta')
    bound = {}
    for name, path in paths.items():
        data = (ROOT / path).read_bytes()
        if path not in sources or sha256(data).hexdigest() != sources[path]:
            raise ValueError('complete function owner source is outside the exact cold contract')
        bound[name] = data

    # The complete source/dependency gate precedes the first artifact write.
    output.mkdir(mode=0o700)
    components, readback = {}, {}
    for name in KERNELS:
        manifest = build_kernel(output / name, compiler, cold_report,
                                candidate='composite-function-' + name)
        raw = manifest.read_bytes()
        value = json.loads(raw)
        if (type(value) is not dict or value.get('schema') != 'hepta.hia.composite-function-' + name + '-native.v1'
                or value.get('source_sha256') != sha256(bound[name]).hexdigest()
                or value.get('compiler_sha256') != sha256(compiler_bytes).hexdigest()
                or type(value.get('image_path')) is not str
                or Path(value['image_path']).name != value['image_path']):
            raise ValueError('native function kernel has mismatched build identity')
        image = manifest.parent / value['image_path']
        image_bytes = image.read_bytes()
        if value.get('image_sha256') != sha256(image_bytes).hexdigest():
            raise ValueError('native function kernel image changed after compilation')
        components[name] = manifest.relative_to(output).as_posix()
        readback[manifest], readback[image] = raw, image_bytes

    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or current_sources() != sources
            or any((ROOT / paths[name]).read_bytes() != value for name, value in bound.items())
            or any(path.read_bytes() != value for path, value in readback.items())):
        raise ValueError('complete native function build inputs or outputs changed')
    bundle = dict(schema=SCHEMA, kernels=components,
        types_source_sha256=sha256(bound['types']).hexdigest(),
        helpers_source_sha256=sha256(bound['helpers']).hexdigest())
    manifest = output / 'manifest.json'
    manifest.write_text(json.dumps(bundle, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.composite-functions-build.v1',
        'status': 'NATIVE_CANDIDATE_BUILT', 'profile': PROFILE,
        'source_manifest': sources, 'manifest': bundle,
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'complete_function_owner_in_hia': True,
        'production_activated': False, 'all_input_equivalence_proved': False,
        'constructor_and_outer_lower_in_hia': False,
        'whole_language_rewritten_in_hia': False, 'whole_stack_rewritten_in_hia': False,
    }, indent=2, sort_keys=True) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))

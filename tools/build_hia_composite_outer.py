"""Package complete outer lowering from a matching source-bound cold run.

Development images and their receipts do not replace that admission gate.
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
    from hepta.hia_composite_outer_native import KERNELS, SCHEMA
    from hepta.hia_composite_functions_native import KERNELS as FUNCTION_KERNELS
    from tools.build_hia_json_preflight import admit_cold_build, build as build_kernel, current_sources

    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    paths = {name: 'examples/hia_bootstrap/composite_outer_' + name + '.hiaasm'
             for name in KERNELS}
    paths.update(types='examples/hia_bootstrap/composite_types.hiaasm',
                 helpers='examples/hia_bootstrap/task_helpers.hiaasm')
    paths.update({'function_' + name: 'examples/hia_bootstrap/composite_function_' + name + '.hiaasm'
                  for name in FUNCTION_KERNELS})
    bound = {}
    for name, path in paths.items():
        data = (ROOT / path).read_bytes()
        if path not in sources or sha256(data).hexdigest() != sources[path]:
            raise ValueError('complete outer dependency is outside the exact cold contract')
        bound[name] = data
    output.mkdir(mode=0o700)
    components, readback = {}, {}
    for name in KERNELS:
        manifest = build_kernel(output / name, compiler, cold_report,
                                candidate='composite-outer-' + name)
        raw = manifest.read_bytes()
        value = json.loads(raw)
        if (type(value) is not dict
                or value.get('schema') != 'hepta.hia.composite-outer-' + name + '-native.v1'
                or value.get('source_sha256') != sha256(bound[name]).hexdigest()
                or value.get('compiler_sha256') != sha256(compiler_bytes).hexdigest()
                or type(value.get('image_path')) is not str
                or Path(value['image_path']).name != value['image_path']):
            raise ValueError('outer kernel has mismatched build identity')
        image = manifest.parent / value['image_path']
        image_bytes = image.read_bytes()
        if value.get('image_sha256') != sha256(image_bytes).hexdigest():
            raise ValueError('outer kernel image changed after compilation')
        readback[manifest], readback[image] = raw, image_bytes
        components[name] = manifest.relative_to(output).as_posix()
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or current_sources() != sources
            or any((ROOT / paths[name]).read_bytes() != data for name, data in bound.items())
            or any(path.read_bytes() != data for path, data in readback.items())):
        raise ValueError('complete outer inputs or outputs changed')
    value = {'schema': SCHEMA, 'kernels': components,
             'types_source_sha256': sha256(bound['types']).hexdigest(),
             'helpers_source_sha256': sha256(bound['helpers']).hexdigest(),
             'function_sources_sha256': {name: sha256(bound['function_' + name]).hexdigest()
                                        for name in FUNCTION_KERNELS}}
    manifest = output / 'manifest.json'
    manifest.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.composite-outer-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'source_manifest': sources, 'manifest': value,
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'complete_outer_lower_owner_in_hia': True, 'production_activated': False,
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

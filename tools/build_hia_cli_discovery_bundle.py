"""Build the optional CLI discovery bundle from five real HIA compilations.

The default CLI and its original two-image builder remain unchanged.  The
production entry requires current-source cold B3; development is explicit.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.hia_cli_discovery_bundle_custody import (
    BUNDLE_SCHEMA, CAPACITY, LABELS, OWNER_FILES, SCHEMAS, SOURCES,
    admit_cold, admit_compilation, binding, check_bindings, guard_authority,
    owner_sources, publish, read_json, require, retained_inputs,
)
from tools.qualify_hia_selfhost import compile_stage

COLD_SCOPE = 'MATCHING_CURRENT_SOURCE_COLD_CLI_DISCOVERY_BUNDLE'
DEVELOPMENT_SCOPE = 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD'
BUILD_SCHEMA = 'hepta.hia.cli-discovery-bundle-build.v1'


def _build(output, compiler, authority):
    output, compiler = Path(output).absolute(), Path(compiler).resolve(strict=True)
    compiler_raw = compiler.read_bytes()
    require(0 < len(compiler_raw) <= CAPACITY, 'bounded actual compiler image required')
    if authority is not None:
        require(str(compiler) == authority['compiler']
                and sha256(compiler_raw).hexdigest() == authority['compiler_sha256'],
                'CLI bundle compiler is not the captured current cold B3')
        guard_authority(authority)
    retained_inputs()
    before = owner_sources()
    inputs = [binding(compiler), *[binding(ROOT / name) for name in OWNER_FILES]]
    if authority is not None:
        inputs.extend(authority['input_bindings'])
    inputs = list({row['path']: row for row in inputs}.values())

    def recheck():
        check_bindings(inputs)
        require(owner_sources() == before, 'CLI bundle source changed during build')
        if authority is not None:
            guard_authority(authority)

    recheck()
    require(not output.exists() and not output.is_symlink(), 'exclusive CLI bundle output required')
    output.mkdir(mode=0o700)
    bundle = {'schema': BUNDLE_SCHEMA}
    components = {}
    for name, source_name in SOURCES.items():
        recheck()
        directory = output / name
        directory.mkdir(mode=0o700)
        raw = (ROOT / source_name).read_bytes()
        label = LABELS[name]
        # compile_stage uses the unchanged invoke(20 s, 1 MiB) producer.
        image, returned = compile_stage(directory, label, compiler, raw)
        image = Path(image)
        require(image == directory / (label + '.image.bin'), 'unexpected CLI component image path')
        actual, observed = admit_compilation(directory, label, compiler, raw, image)
        require(returned == actual, 'CLI component returned receipt is not its actual child observation')
        inputs.extend(row for row in observed if row['path'] not in {x['path'] for x in inputs})
        manifest = {'schema': SCHEMAS[name], 'source_sha256': sha256(raw).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(compiler_raw).hexdigest()}
        target = directory / 'manifest.json'
        publish(target, manifest)
        inputs.append(binding(target))
        bundle[name + '_manifest'] = name + '/manifest.json'
        bundle[name + '_manifest_sha256'] = sha256(target.read_bytes()).hexdigest()
        components[name] = {'manifest': manifest, 'actual_compile_receipt': actual,
                            'observation_bindings': observed}
        recheck()
    target = output / 'manifest.json'
    publish(target, bundle)
    inputs.append(binding(target))
    recheck()
    report = {'schema': BUILD_SCHEMA, 'status': 'NATIVE_CANDIDATE_BUILT',
              'scope': COLD_SCOPE if authority is not None else DEVELOPMENT_SCOPE,
              'matching_cold': authority is not None, 'authority': authority,
              'compiler_sha256': sha256(compiler_raw).hexdigest(),
              'compile_seconds': 20, 'capacity': CAPACITY,
              'owner_sources_before': before, 'owner_sources_after': owner_sources(),
              'components': components, 'bundle': bundle, 'input_bindings': inputs,
              'ordinary_cli_activated': False, 'whole_cli_native': False,
              'whole_native_delivery_qualified': False,
              'retained_foreign_routes': ['nonstandard or mutated discovery providers',
                  'thirteen other action providers', 'CPython mechanical object and stream ports']}
    publish(output / 'build.json', report)
    recheck()
    require(read_json((output / 'build.json').read_bytes()) == report, 'CLI bundle publication changed')
    return target


def build(output, compiler, cold_report):
    authority = admit_cold(cold_report)
    return _build(output, compiler, authority)


def build_development(output, compiler):
    return _build(output, compiler, None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--compiler', required=True, type=Path)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args(argv)
    print(build_development(args.output, args.compiler) if args.development
          else build(args.output, args.compiler, args.cold_report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

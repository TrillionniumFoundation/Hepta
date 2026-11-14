"""Build six actual HIA images with an explicit current-source cold boundary."""
from __future__ import annotations
import argparse
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.hia_cli_verified_report_custody import (
    BUNDLE_SCHEMA, CAPACITY, LABEL, OWNER_FILES, SCHEMA, SOURCE,
    admit_cold, admit_compilation, binding, check_bindings, guard_authority,
    owner_sources, publish, read_json, require, retained_inputs,
)
from tools.qualify_hia_selfhost import compile_stage

BUILD_SCHEMA = 'hepta.hia.cli-verified-report-build.v1'
COLD_SCOPE = 'MATCHING_CURRENT_SOURCE_COLD_CLI_VERIFIED_REPORT_BUNDLE'
DEVELOPMENT_SCOPE = 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD'


def _build(output, compiler, authority):
    from hepta.hia_optional_profiles import fresh_profile_capture, guard_profile_identity
    from hepta.hia_cli_verified_report_native import RESOURCE_SCHEMA, host_compatibility_sources
    from tools import build_hia_cli_discovery_bundle as companion
    from tools.qualify_hia_cli_discovery_bundle import inspect_build as inspect_companion
    output, compiler = Path(output).absolute(), Path(compiler).resolve(strict=True)
    compiler_raw = compiler.read_bytes()
    require(0 < len(compiler_raw) <= CAPACITY, 'bounded actual compiler required')
    if authority is not None:
        require(str(compiler) == authority['compiler']
                and sha256(compiler_raw).hexdigest() == authority['compiler_sha256'],
                'report compiler must be the actual captured current cold B3')
        guard_authority(authority)
    retained_inputs()
    before = owner_sources()
    optional_identity, optional_sources = fresh_profile_capture(BUNDLE_SCHEMA)
    host_sources = host_compatibility_sources()
    inputs = [binding(compiler), *[binding(ROOT / name) for name in OWNER_FILES]]
    if authority is not None:
        inputs.extend(authority['input_bindings'])
    inputs = list({row['path']: row for row in inputs}.values())

    def recheck():
        check_bindings(inputs)
        require(owner_sources() == before, 'report bundle source changed during build')
        guard_profile_identity(BUNDLE_SCHEMA, optional_identity)
        require(host_compatibility_sources() == host_sources, 'report host owners changed during build')
        if authority is not None:
            guard_authority(authority)

    recheck()
    require(not output.exists() and not output.is_symlink(), 'exclusive report bundle output required')
    cli_manifest = (companion.build_development(output, compiler) if authority is None
                    else companion.build(output, compiler, authority['cold_report']))
    cli_build = inspect_companion(output, authority)
    require(cli_build['manifest'] == str(cli_manifest), 'actual companion manifest differs')
    inputs.extend(row for row in cli_build['input_bindings'] if row['path'] not in {x['path'] for x in inputs})
    recheck()
    directory = output / 'verified_report'
    directory.mkdir(mode=0o700)
    source_raw = optional_sources[SOURCE]
    resource_root = directory / 'profile-resources'
    captured_source = resource_root / SOURCE
    captured_source.parent.mkdir(parents=True, exist_ok=False)
    with captured_source.open('xb') as stream:
        stream.write(source_raw)
    captured_identity, captured_sources = fresh_profile_capture(BUNDLE_SCHEMA, resource_root=resource_root)
    require(captured_identity == optional_identity and captured_sources[SOURCE] == source_raw,
            'captured optional report source differs')
    inputs.append(binding(captured_source))
    image, returned = compile_stage(directory, LABEL, compiler, source_raw)
    image = Path(image)
    require(image == directory / (LABEL + '.image.bin'), 'unexpected report image path')
    actual, observations = admit_compilation(directory, LABEL, compiler, source_raw, image)
    require(returned == actual, 'returned report receipt differs from actual child observation')
    manifest = {'schema': SCHEMA, 'source_sha256': sha256(source_raw).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler_raw).hexdigest(),
                'profile_resources': {'schema': RESOURCE_SCHEMA, 'profile': BUNDLE_SCHEMA,
                    'source_root': 'profile-resources', 'source_relative': SOURCE,
                    'source_sha256': sha256(source_raw).hexdigest(),
                    'identity': optional_identity, 'host_sources': host_sources}}
    report_manifest = directory / 'manifest.json'
    publish(report_manifest, manifest)
    inputs.extend(row for row in (*observations, binding(report_manifest))
                  if row['path'] not in {x['path'] for x in inputs})
    bundle = read_json(Path(cli_manifest).read_bytes())
    bundle = {**bundle, 'schema': BUNDLE_SCHEMA,
              'verified_report_manifest': 'verified_report/manifest.json',
              'verified_report_manifest_sha256': sha256(report_manifest.read_bytes()).hexdigest()}
    target = output / 'verified-report-bundle.json'
    publish(target, bundle)
    inputs.append(binding(target))
    recheck()
    report = {'schema': BUILD_SCHEMA, 'status': 'NATIVE_CANDIDATE_BUILT',
              'scope': COLD_SCOPE if authority is not None else DEVELOPMENT_SCOPE,
              'matching_cold': authority is not None, 'authority': authority,
              'compiler_sha256': sha256(compiler_raw).hexdigest(),
              'compile_seconds': 20, 'capacity': CAPACITY,
              'owner_sources_before': before, 'owner_sources_after': owner_sources(),
              'companion': cli_build, 'report_component': {'manifest': manifest,
                  'actual_compile_receipt': actual, 'observation_bindings': observations},
              'bundle': bundle, 'input_bindings': inputs,
              'ordinary_cli_activated': False, 'whole_cli_native': False,
              'whole_verify_native': False, 'whole_native_delivery_qualified': False}
    publish(output / 'verified-report-build.json', report)
    recheck()
    require(read_json((output / 'verified-report-build.json').read_bytes()) == report, 'report publication changed')
    return target


def build(output, compiler, cold_report):
    return _build(output, compiler, admit_cold(cold_report))


def build_development(output, compiler):
    return _build(output, compiler, None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args(argv)
    print(build_development(args.output, args.compiler) if args.development else
          build(args.output, args.compiler, args.cold_report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Build the discovery JSON owner from the current matching-source cold B3.

The explicit development function is distinct and is never accepted by the
production qualifier. Neither function activates or replaces the ordinary CLI.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.hia_cli_discovery_custody import (
    admit_cold, admit_compilation, binding, check_bindings, encoded, guard_authority,
    owner_sources, publish, read_json, require,
)
from hepta.hia_cli_discovery_json_native import SOURCE_NAME, SCHEMA

LABEL = 'cli-discovery-json'
COLD_SCOPE = 'MATCHING_SOURCE_COLD_CLI_DISCOVERY_JSON_BUILD'
DEVELOPMENT_SCOPE = 'DEVELOPMENT_CLI_DISCOVERY_JSON_NOT_MATCHING_SOURCE_COLD'


def _build(output, compiler, authority):
    from tools.build_hia_core_json_bytes import admit_compile_receipt
    from tools.qualify_hia_selfhost import compile_stage
    output, compiler = Path(output).absolute(), Path(compiler).resolve(strict=True)
    source_path = ROOT / SOURCE_NAME
    source, compiler_bytes = source_path.read_bytes(), compiler.read_bytes()
    before = owner_sources()
    require(compiler_bytes and len(compiler_bytes) <= 1048576, 'compiler exceeds the fixed image bound')
    consumed = [binding(compiler), binding(source_path)]
    if authority is not None:
        guard_authority(authority)
        require(str(compiler) == authority['compiler']
                and sha256(compiler_bytes).hexdigest() == authority['compiler_sha256'],
                'production discovery compiler is not the admitted actual cold B3')

    def recheck():
        check_bindings(consumed)
        require(owner_sources() == before, 'discovery build owner inputs changed')
        if authority is not None:
            guard_authority(authority)

    recheck()
    require(not output.exists() and not output.is_symlink(), 'exclusive discovery build output required')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, LABEL, compiler, source)
    image = Path(image)
    require(image == output / (LABEL + '.image.bin'), 'unexpected discovery image path')
    image_bytes = image.read_bytes()
    admit_compile_receipt(receipt, compiler_bytes=compiler_bytes, source_bytes=source, image_bytes=image_bytes)
    recorded, observations = admit_compilation(output, LABEL, compiler, source, image)
    require(encoded(recorded) == encoded(receipt), 'discovery compiler receipt memory/readback differ')
    consumed = list({row['path']: row for row in consumed + observations}.values())
    recheck()
    manifest = {'schema': SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    manifest_path = output / 'manifest.json'
    publish(manifest_path, manifest)
    consumed.append(binding(manifest_path))
    recheck()
    report = {'schema': 'hepta.hia.cli-discovery-json-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
              'scope': COLD_SCOPE if authority is not None else DEVELOPMENT_SCOPE,
              'matching_cold': authority is not None, 'authority': authority,
              'owner_sources_before': before, 'owner_sources_after': owner_sources(),
              'manifest': manifest, 'native_compile_receipt': recorded,
              'input_bindings': consumed, 'compile_seconds': 20, 'capacity': 1048576,
              'json_semantics_in_hia': True, 'build_and_qualification_still_hosted': True,
              'ordinary_cli_activated': False, 'whole_cli_native': False,
              'whole_native_delivery_qualified': False}
    path = output / 'build.json'
    publish(path, report)
    consumed.append(binding(path))
    recheck()
    return manifest_path


def build(output, compiler, cold_report):
    # Authority must be established before even the output-directory creation.
    authority = admit_cold(cold_report)
    return _build(output, compiler, authority)


def build_development(output, compiler):
    return _build(output, compiler, None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    args = parser.parse_args(argv)
    print(build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()

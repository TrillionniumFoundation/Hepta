"""Pack a cold-built HIA borrowed-buffer application as an independent ELF."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import CANDIDATES, admit_cold_build, build as build_image, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.generate_hia_native_filter import MAGIC, SAFE_CORE_LOADER_FILTER_MAGIC
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable


ROOT = Path(__file__).resolve().parents[1]
PACKER = 'native-filter'


def build_filter(output: Path, compiler: Path, cold_report: Path, *,
                 application: str, filename: str, schema: str,
                 packer=PACKER, magic=MAGIC) -> Path:
    roles = application, packer
    sources = tuple(ROOT / 'examples/hia_bootstrap' / (CANDIDATES[role][0] + '.hepta') for role in roles)
    pins = {path: path.read_bytes() for path in (compiler, cold_report, *sources)}
    admitted = admit_cold_build(pins[compiler], pins[cold_report])
    if any(admitted.get(path.relative_to(ROOT).as_posix()) != sha256(pins[path]).hexdigest()
           for path in sources):
        raise ValueError(f'{application} filter source differs from cold source')

    output.mkdir(mode=0o700)
    applications = {}
    for role in roles:
        manifest = build_image(output / role, compiler, cold_report, candidate=role)
        pins[manifest] = manifest.read_bytes()
        metadata = json.loads(pins[manifest])
        image = manifest.parent / metadata['image_path']
        pins[image] = image.read_bytes()
        if sha256(pins[image]).hexdigest() != metadata['image_sha256']:
            raise ValueError(f'{role} image differs from its receipt')
        applications[role] = image, metadata

    application_bytes = pins[applications[application][0]]
    packer_image = applications[packer][0]
    frame = struct.pack('<2Q', magic, len(application_bytes)) + application_bytes
    receipt, packed = invoke(output, 'native-pack', packer_image, frame)
    executable_bytes = _check_pack_output(receipt, packed, artifact=pins[packer_image], source=frame)
    inspection = inspect_executable(executable_bytes)
    if any(path.read_bytes() != before for path, before in pins.items()) or current_sources() != admitted:
        raise ValueError(f'{application} filter build input changed')
    executable = output / filename
    with executable.open('xb') as stream:
        stream.write(executable_bytes)
    executable.chmod(0o700)
    (output / 'build.json').write_text(json.dumps({
        'schema': schema,
        'executable': inspection,
        'executable_sha256': sha256(executable_bytes).hexdigest(),
        'compiler_sha256': sha256(pins[compiler]).hexdigest(),
        'cold_report_sha256': sha256(pins[cold_report]).hexdigest(),
        'images': {role: metadata for role, (_, metadata) in applications.items()},
        'native_pack_receipt': receipt,
    }, indent=2, sort_keys=True) + '\n')
    return executable


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build the standalone HIA Safe Core ELF loader check.')
    for flag in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + flag, type=Path, required=True)
    args = parser.parse_args()
    print(build_filter(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                       application='safe-core-elf-inventory', packer='safe-core-loader-filter',
                       magic=SAFE_CORE_LOADER_FILTER_MAGIC, filename='hia-safe-core-loader',
                       schema='hepta.hia.safe-core-loader-filter-build.v1'))

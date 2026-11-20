"""Package the cold-built HIA Worker request encoder as a static Linux executable."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import CANDIDATES, admit_cold_build, build as build_image, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.generate_hia_native_filter import MAGIC
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable


ROOT = Path(__file__).resolve().parents[1]
ROLES = ('worker-prepare', 'native-filter')


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    sources = tuple(ROOT / 'examples/hia_bootstrap' / (CANDIDATES[role][0] + '.hepta')
                    for role in ROLES)
    pins = {path: path.read_bytes() for path in (compiler, cold_report, *sources)}
    admitted = admit_cold_build(pins[compiler], pins[cold_report])
    if any(admitted.get(path.relative_to(ROOT).as_posix()) != sha256(pins[path]).hexdigest()
           for path in sources):
        raise ValueError('worker prepare source differs from cold source')

    output.mkdir(mode=0o700)
    applications = {}
    for role in ROLES:
        manifest = build_image(output / role, compiler, cold_report, candidate=role)
        pins[manifest] = manifest.read_bytes()
        metadata = json.loads(pins[manifest])
        image = manifest.parent / metadata['image_path']
        pins[image] = image.read_bytes()
        if sha256(pins[image]).hexdigest() != metadata['image_sha256']:
            raise ValueError('worker prepare image differs from its receipt')
        applications[role] = image, metadata

    worker_bytes = pins[applications['worker-prepare'][0]]
    packer = applications['native-filter'][0]
    frame = struct.pack('<2Q', MAGIC, len(worker_bytes)) + worker_bytes
    receipt, packed = invoke(output, 'native-pack', packer, frame)
    executable_bytes = _check_pack_output(receipt, packed, artifact=pins[packer], source=frame)
    inspection = inspect_executable(executable_bytes)
    if any(path.read_bytes() != before for path, before in pins.items()) or current_sources() != admitted:
        raise ValueError('worker prepare build input changed')
    executable = output / 'hia-worker-prepare'
    with executable.open('xb') as stream:
        stream.write(executable_bytes)
    executable.chmod(0o700)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.worker-prepare-build.v1',
        'executable': inspection,
        'executable_sha256': sha256(executable_bytes).hexdigest(),
        'compiler_sha256': sha256(pins[compiler]).hexdigest(),
        'cold_report_sha256': sha256(pins[cold_report]).hexdigest(),
        'images': {role: metadata for role, (_, metadata) in applications.items()},
        'native_pack_receipt': receipt,
    }, indent=2, sort_keys=True) + '\n')
    return executable


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))

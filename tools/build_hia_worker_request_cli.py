"""Build the native pre-service HIA worker request admission executable."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, build as build_image, current_sources
from tools.generate_hia_native_filter import WORKER_FILTER_MAGIC
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('examples/hia_bootstrap/worker_request.hepta',
           'examples/hia_bootstrap/worker_request_filter_packer.hepta')


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    pins = {path: path.read_bytes() for path in (compiler, cold_report, *(ROOT / name for name in SOURCES))}
    admitted = admit_cold_build(pins[compiler], pins[cold_report])
    if any(admitted.get(name) != sha256(pins[ROOT / name]).hexdigest() for name in SOURCES):
        raise ValueError('worker request input differs from admitted source')

    output.mkdir(mode=0o700)
    images = []
    receipts = {}
    for candidate in ('worker-request', 'worker-request-filter'):
        manifest = build_image(output / candidate, compiler, cold_report, candidate=candidate)
        pins[manifest] = manifest.read_bytes()
        record = json.loads(pins[manifest])
        image = manifest.parent / record['image_path']
        pins[image] = image.read_bytes()
        if sha256(pins[image]).hexdigest() != record['image_sha256']:
            raise ValueError('worker request image differs from its receipt')
        images.append(image)
        receipts[candidate] = record

    application, packer = images
    raw = pins[application]
    frame = struct.pack('<2Q', WORKER_FILTER_MAGIC, len(raw)) + raw
    receipt, packed = invoke(output, 'native-pack', packer, frame)
    size = receipt.get('core_u32')
    if type(size) is not int or not 0 < size <= min(len(packed), 1 << 20):
        raise ValueError('native worker request packer refused its image')
    executable_raw = packed[:size]
    inspection = inspect_executable(executable_raw)
    if any(path.read_bytes() != before for path, before in pins.items()) or current_sources() != admitted:
        raise ValueError('worker request build input changed')

    executable = output / 'hia-worker-admit'
    with executable.open('xb') as stream:
        stream.write(executable_raw)
    executable.chmod(0o700)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.worker-request-cli-build.v1',
        'executable_sha256': sha256(executable_raw).hexdigest(),
        'cold_report_sha256': sha256(pins[cold_report]).hexdigest(),
        'executable': inspection,
        'images': receipts,
        'packing': receipt,
    }, indent=2, sort_keys=True) + '\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    arguments = parser.parse_args()
    print(build(arguments.output.resolve(), arguments.compiler.resolve(), arguments.cold_report.resolve()))


if __name__ == '__main__':
    main()

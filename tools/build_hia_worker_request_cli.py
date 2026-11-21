"""Build the native HIA worker admission, transport and data executables."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_agent_read_page import pack_stdio
from tools.build_hia_json_preflight import admit_cold_build, build as build_image, current_sources
from tools.generate_hia_mcp_stdio_packer import (
    SOURCE as STDIO_PACKER, TERMINAL_MODE, WORKER_DATA_MODE, WORKER_RESPONSE_MODE,
)
from tools.generate_hia_native_filter import WORKER_FILTER_MAGIC
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('examples/hia_bootstrap/worker_request.hepta',
           'examples/hia_bootstrap/worker_request_filter_packer.hepta', STDIO_PACKER)


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

    terminal_build = output / 'terminal'
    terminal_build.mkdir(mode=0o700)
    terminal_raw, terminal_pack = pack_stdio(
        terminal_build, compiler, {STDIO_PACKER: pins[ROOT / STDIO_PACKER]}, TERMINAL_MODE, raw, pins)
    data_build = output / 'data-validation'
    data_build.mkdir(mode=0o700)
    data_raw, data_pack = pack_stdio(
        data_build, compiler, {STDIO_PACKER: pins[ROOT / STDIO_PACKER]}, WORKER_DATA_MODE, raw, pins)
    response_build = output / 'response'
    response_build.mkdir(mode=0o700)
    response_raw, response_pack = pack_stdio(
        response_build, compiler, {STDIO_PACKER: pins[ROOT / STDIO_PACKER]}, WORKER_RESPONSE_MODE, raw, pins)
    if any(path.read_bytes() != before for path, before in pins.items()) or current_sources() != admitted:
        raise ValueError('worker request build input changed')

    executable = output / 'hia-worker-admit'
    terminal = output / 'hia-worker-terminal'
    data_validator = output / 'hia-worker-data'
    response = output / 'hia-worker-response'
    for target, data in ((executable, executable_raw), (terminal, terminal_raw),
                         (data_validator, data_raw), (response, response_raw)):
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o700)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.worker-request-cli-build.v1',
        'executable_sha256': sha256(executable_raw).hexdigest(),
        'cold_report_sha256': sha256(pins[cold_report]).hexdigest(),
        'executable': inspection,
        'images': receipts,
        'packing': receipt,
        'response': {
            'schema': 'hepta.hia.worker-response-stdio.v1',
            'executable_sha256': sha256(response_raw).hexdigest(),
            'executable_bytes': len(response_raw),
            'native_packing': response_pack,
        },
        'data_validation': {
            'schema': 'hepta.hia.worker-data-stdio.v1',
            'executable_sha256': sha256(data_raw).hexdigest(),
            'executable_bytes': len(data_raw),
            'native_packing': data_pack,
        },
        'terminal': {
            'schema': 'hepta.hia.worker-terminal-stdio.v1',
            'executable_sha256': sha256(terminal_raw).hexdigest(),
            'executable_bytes': len(terminal_raw),
            'native_packing': terminal_pack,
        },
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

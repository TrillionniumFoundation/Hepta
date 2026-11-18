"""Build the native HIA worker admission and terminal transport executables."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, build as build_image, current_sources
from tools.build_hia_sqlite_migrate import embed
from tools.build_hia_sqlite_pager import assemble, link
from tools.generate_hia_native_filter import WORKER_FILTER_MAGIC
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable


ROOT = Path(__file__).resolve().parents[1]
LINKER = 'examples/hia_bootstrap/elf_static_linker.hepta'
TERMINAL = 'tools/hia_worker_terminal.S'
SOURCES = ('examples/hia_bootstrap/worker_request.hepta',
           'examples/hia_bootstrap/worker_request_filter_packer.hepta', LINKER, TERMINAL)


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
    linker, linker_receipt = compile_stage(terminal_build, 'linker', compiler, pins[ROOT / LINKER])
    pins[linker] = linker.read_bytes()
    if sha256(pins[linker]).hexdigest() != linker_receipt['produced_sha256']:
        raise ValueError('worker terminal linker differs from its receipt')
    objects = [assemble(terminal_build, 'worker-terminal', pins[ROOT / TERMINAL]),
               embed(terminal_build, 'worker_request', 'worker-request', raw)]
    terminal_raw, terminal_link = link(
        terminal_build, pins[linker], raw, objects, wire_magic=b'HIALNK01')
    if any(path.read_bytes() != before for path, before in pins.items()) or current_sources() != admitted:
        raise ValueError('worker request build input changed')

    executable = output / 'hia-worker-admit'
    terminal = output / 'hia-worker-terminal'
    for target, data in ((executable, executable_raw), (terminal, terminal_raw)):
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
        'terminal': {
            'schema': 'hepta.hia.worker-terminal-stdio.v1',
            'executable_sha256': sha256(terminal_raw).hexdigest(),
            'executable_bytes': len(terminal_raw),
            'linker': linker_receipt,
            'linking': terminal_link,
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

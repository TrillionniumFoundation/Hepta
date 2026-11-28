"""Bootstrap the HIA source descriptor, digest and packet owner.

This command admits a matching cold compiler before producing the standalone
ELF. The ELF itself captures files and verifies their SHA-256 pins without a
Python runtime, libc, a subprocess, or a filesystem path to another program.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_compile_receipt, _check_pack_output, _run_captured
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCES = (
    'examples/hia_bootstrap/source_capture.hepta',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'examples/hia_bootstrap/source_capture_packer.hepta',
    'tools/generate_hia_source_capture.py',
    'tools/hia_source_capture_syscalls.S',
    'tools/build_hia_source_capture.py',
)


def capture_named_sources(executable, root, named, admitted, work):
    """Hosted request transport; HIA owns source reads, hash admission and framing.

    The v2 request supplies independent digests and asks HIA to obtain bounded
    source lengths from each retained descriptor. The host does not open, read,
    hash, or stat individual sources.
    """
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        frame = bytearray(struct.pack('<8sQ8sQ', b'HIACAP02', directory, b'HIANAM01', len(named)))
        rows = []
        for alias, relative in named.items():
            relative = 'examples/hia_bootstrap/' + relative
            path, name = relative.encode('ascii'), alias.encode('ascii')
            pin = admitted.get(relative)
            if type(pin) is not str or len(pin) != 64 or bytes.fromhex(pin).hex() != pin:
                raise ValueError('release member source differs from cold admission: ' + relative)
            frame += struct.pack('<3Q', len(path), len(name), 0) + bytes.fromhex(pin) + path + name
            rows.append((alias, name))
        result = _run_captured(executable, (), bytes(frame), work, pass_fds=(directory,))
    finally:
        os.close(directory)
    if result.returncode or result.stderr:
        raise ValueError('native source capture refused admitted release inputs: ' + str(result.returncode))
    wire = result.stdout
    if wire[:16] != struct.pack('<8sQ', b'HIANAM01', len(rows)):
        raise ValueError('native source capture returned a different group')
    at, captured = 16, {}
    for alias, name in rows:
        if at + 16 > len(wire):
            raise ValueError('native source capture returned a truncated source header')
        name_size, size = struct.unpack_from('<2Q', wire, at)
        stop = at + 16 + len(name) + size
        if (stop > len(wire) or not 0 < size <= 1 << 20 or name_size != len(name)
                or wire[at + 16:at + 16 + len(name)] != name):
            raise ValueError('native source capture returned a different source extent')
        captured[alias] = wire[at + 16 + len(name):stop]
        at = stop
    if at != len(wire):
        raise ValueError('native source capture returned trailing bytes')
    return captured



def capture_root_sources(executable, root, named, admitted, work):
    """Capture explicit repository-relative native inputs through HIA HIARAW01.

    The original named compile-source interface stays unchanged.  This separate
    entry admits declared native/data paths, including docs and mechanical
    capsules, and never grants host-language source access.
    """
    from hashlib import sha256
    from tools.hia_native_worker_source_authority import checked_paths

    if type(named) is not dict or not 1 <= len(named) <= 128:
        raise ValueError("native raw capture requires 1..128 explicit names")
    checked_paths(tuple(sorted(named.values())))
    rows = []
    for alias, relative in named.items():
        if type(alias) is not str:
            raise ValueError("native raw capture alias must be text")
        name, path = alias.encode("ascii"), relative.encode("ascii")
        if (not 1 <= len(name) <= 127
                or any(not (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122
                            or c in (45, 46, 95)) for c in name)):
            raise ValueError("native raw capture alias differs from the original domain")
        pin = admitted.get(relative)
        if (type(pin) is not str or len(pin) != 64
                or bytes.fromhex(pin).hex() != pin):
            raise ValueError("native raw capture has no exact admitted digest: " + relative)
        rows.append((alias, path, name, pin))
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    captured = {}
    try:
        for alias, path, name, pin in rows:
            frame = (struct.pack("<8sQ8sQ", b"HIACAP02", directory, b"HIARAW01", 1)
                     + struct.pack("<3Q", len(path), len(name), 0)
                     + bytes.fromhex(pin) + path + name)
            result = _run_captured(executable, (), frame, work, pass_fds=(directory,))
            if (result.returncode or result.stderr or not 0 < len(result.stdout) <= 1 << 20
                    or sha256(result.stdout).hexdigest() != pin):
                raise ValueError("native raw source capture refused: " + path.decode("ascii"))
            captured[alias] = result.stdout
    finally:
        os.close(directory)
    return captured


def build(output, compiler, cold_report):
    output, compiler, cold_report = map(Path, (output, compiler, cold_report))
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    captured = {name: (ROOT / name).read_bytes() for name in SOURCES}
    if any(admitted.get(name) != sha256(raw).hexdigest() for name, raw in captured.items()):
        raise ValueError('source-capture input differs from matching cold admission')
    observer = bytes.fromhex(json.loads(report_bytes)['native_flat_observer_hex'])
    output.mkdir(mode=0o700)
    images, receipts = {}, {}
    for label, name in zip(('policy', 'sha256', 'packer'), SOURCES[:3], strict=True):
        path, receipt = compile_stage(output, label, compiler, captured[name], flat_observer=observer)
        raw = path.read_bytes()
        _check_compile_receipt(receipt, compiler=compiler_bytes, source=captured[name], produced=raw)
        images[label], receipts[label] = (path, raw), receipt
    policy, hasher = images['policy'][1], images['sha256'][1]
    frame = struct.pack('<8sQQ', b'HIACAPK1', len(policy), len(hasher)) + policy + hasher
    receipt, packed = invoke(output, 'pack', images['packer'][0], frame, flat_observer=observer)
    raw = _check_pack_output(receipt, packed, artifact=images['packer'][1], source=frame)
    inspection = inspect_executable(raw)
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != report_bytes
            or current_sources() != admitted
            or any((ROOT / name).read_bytes() != data for name, data in captured.items())
            or any(path.read_bytes() != data for path, data in images.values())):
        raise ValueError('source-capture bootstrap inputs changed before publication')
    executable = output / 'hia-source-capture'
    with executable.open('xb') as stream:
        stream.write(raw)
    executable.chmod(0o500)
    report = {
        'schema': 'hepta.hia.source-capture-build.v1',
        'status': 'NATIVE_SOURCE_CAPTURE_BUILT',
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': sha256(report_bytes).hexdigest(),
        'source_sha256': {name: sha256(data).hexdigest() for name, data in captured.items()},
        'image_sha256': {name: sha256(data).hexdigest() for name, (_, data) in images.items()},
        'executable_path': executable.name,
        'executable_sha256': sha256(raw).hexdigest(),
        'executable': inspection,
        'compile_receipts': receipts,
        'pack_receipt': receipt,
        'runtime_python_or_libc_or_child_required': False,
        'host_bootstrap_and_initial_cold_admission': True,
        'complete_native_release_lifecycle': False,
    }
    with (output / 'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.absolute(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()

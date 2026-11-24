"""Qualify the complete native release owner against an actual matching cold run.

Python prepares the independent test capabilities and bootstrap images, then
observes the native process. It does not orchestrate any release stage. This is
an external qualification fixture, not the installed release command.
"""
from __future__ import annotations

import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _build_captured, _check_compile_receipt, _check_pack_output
from tools.qualify_hia_selfhost import compile_stage, invoke


def inventory(pins):
    out = bytearray(struct.pack('<8sQ', b'HIASPI01', len(pins)))
    for name, digest in sorted(pins.items()):
        encoded = name.encode('ascii')
        if (not 0 < len(encoded) <= 4095 or name.startswith('/') or
                any(part in ('', '.', '..') for part in name.split('/')) or
                len(digest) != 64 or bytes.fromhex(digest).hex() != digest):
            raise ValueError('invalid complete source inventory')
        out += struct.pack('<Q', len(encoded)) + bytes.fromhex(digest) + encoded
    return bytes(out)


def sealed(name, raw, mode):
    fd = os.memfd_create(name, os.MFD_ALLOW_SEALING)
    offset = 0
    while offset < len(raw):
        used = os.write(fd, raw[offset:])
        if used <= 0:
            os.close(fd)
            raise OSError('failed sealed capability capture')
        offset += used
    os.fchmod(fd, mode)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def bootstrap(directory, compiler, cold, admitted):
    directory.mkdir(mode=0o700)
    observer = bytes.fromhex(json.loads(cold.read_bytes())['native_flat_observer_hex'])
    compiler_bytes = compiler.read_bytes()
    images = {}

    def image(name):
        if name not in images:
            relative = 'examples/hia_bootstrap/' + name + '.hepta'
            source = (ROOT / relative).read_bytes()
            if admitted.get(relative) != sha256(source).hexdigest():
                raise ValueError('bootstrap source differs from complete cold admission')
            path, receipt = compile_stage(directory, name, compiler, source, flat_observer=observer)
            raw = path.read_bytes()
            _check_compile_receipt(receipt, compiler=compiler_bytes, source=source, produced=raw)
            images[name] = path, raw
        return images[name]

    def packed(name, policy_names, packer_name, magic):
        parts = [image(part)[1] for part in policy_names]
        packer, packer_raw = image(packer_name)
        wire = struct.pack('<8s' + 'Q' * len(parts), magic, *map(len, parts)) + b''.join(parts)
        receipt, output = invoke(directory, name, packer, wire, flat_observer=observer)
        raw = _check_pack_output(receipt, output, artifact=packer_raw, source=wire)
        path = directory / name
        path.write_bytes(raw)
        path.chmod(0o500)
        return path

    runner = packed('hia-subprocess', ('subprocess',), 'subprocess_packer', b'HIASUPK1')
    capture = packed('hia-source-capture', ('source_capture', 'sha256_stream'),
                     'source_capture_packer', b'HIACAPK1')
    owner = packed('hia-release-owner', ('release_owner', 'release_dag', 'sha256_stream'),
                   'release_owner_packer', b'HIAOWPK1')
    _, seed_raw = _build_captured(directory / 'seed', compiler, cold)
    seed = directory / 'hia-source-build'
    seed.write_bytes(seed_raw)
    seed.chmod(0o500)
    if current_sources() != admitted:
        raise ValueError('source identity changed during the external bootstrap')
    return owner, runner, seed, capture


def qualify(output, compiler, cold_report, *, timeout=3600, trace=True):
    compiler, cold_report, output = map(Path, (compiler, cold_report, output))
    compiler_raw, cold_raw = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_raw, cold_raw)
    pins = inventory(admitted)
    output.mkdir(mode=0o700)
    owner, runner, seed, capture = bootstrap(output / 'bootstrap', compiler, cold_report, admitted)
    stage, work, published = (output / name for name in ('stage', 'work', 'published'))
    for directory in (stage, work, published):
        directory.mkdir(mode=0o700)
    raw_caps = [p.read_bytes() for p in (runner, seed, capture)] + [compiler_raw, cold_raw]
    code_fds = [sealed('release-capability-' + str(i), raw, 0o500 if i < 3 else 0o400)
                for i, raw in enumerate(raw_caps)]
    directory_fds = [os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                     for path in (ROOT, stage, work, output, published)]
    owner_fd = sealed('release-owner', owner.read_bytes(), 0o500)
    name = published.name.encode('ascii')
    header = struct.pack('<8s15Q', b'HIAOWN01', 0, time.monotonic_ns() + timeout * 1_000_000_000,
                         *directory_fds[:3], *code_fds, *directory_fds[3:], len(name), len(pins), 0)
    wire = header + b''.join(sha256(raw).digest() for raw in raw_caps) + name + pins
    request = sealed('release-owner-request', wire, 0o400)
    kept = code_fds + directory_fds + [owner_fd, request]
    command = [f'/proc/self/fd/{owner_fd}']
    if trace:
        command = ['/usr/bin/strace', '-f', '-s', '128', '-o', str(output / 'trace.log'), *command]
    begin = time.monotonic()
    try:
        result = subprocess.run(command, stdin=request, capture_output=True, pass_fds=tuple(kept),
                                env={'PATH': ''}, cwd=output, timeout=timeout + 30)
    finally:
        for fd in kept:
            os.close(fd)
    receipt = None
    if result.returncode == 0:
        receipt = json.loads(result.stdout)
        if (result.stderr or receipt.get('schema') != 'hepta.hia.release-finalize.v1' or
                receipt.get('published') is not True or receipt.get('source_attested') is not True):
            raise ValueError('native release returned an incomplete final receipt')
        package = published / 'store.hiapack'
        if (sha256(package.read_bytes()).hexdigest() != receipt['sha256'] or
                package.stat().st_size != receipt['bytes'] or
                len(tuple(stage.iterdir())) != receipt['files']):
            raise ValueError('native publication differs from its independently observed result')
    report = {
        'schema': 'hepta.hia.native-release-owner-qualification.v1',
        'scope': 'FULL_OWNER_WITH_MATCHING_COMPLETE_COLD_ADMISSION',
        'returncode': result.returncode, 'elapsed': time.monotonic() - begin,
        'source_count': len(admitted), 'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'cold_report_sha256': sha256(cold_raw).hexdigest(),
        'owner_sha256': sha256(owner.read_bytes()).hexdigest(),
        'capability_sha256': [sha256(raw).hexdigest() for raw in raw_caps],
        'stdout': result.stdout.decode('utf-8', errors='replace'),
        'stderr': result.stderr.decode('utf-8', errors='replace'),
        'receipt': receipt,
    }
    (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    if result.returncode:
        raise ValueError('native release owner failed; see qualification.json: ' + str(result.returncode))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=3600)
    parser.add_argument('--no-trace', action='store_true')
    args = parser.parse_args()
    print(json.dumps(qualify(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                             timeout=args.timeout, trace=not args.no_trace), sort_keys=True))


if __name__ == '__main__':
    main()

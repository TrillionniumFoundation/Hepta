"""Package explicit object bytes and execute one pinned standalone HIA linker.

This host driver retains input/output custody and process observations. It does
not parse ELF, resolve symbols, apply relocations, or fall back to another linker.
The caller supplies trusted compiled object code, not untrusted code to execute.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import tempfile

from tools.generate_hia_elf_linker import MAGIC, LIMIT
from tools.build_hia_elf_linker import SCHEMA, ROOT


def capture(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('native linker input must be a bounded nonempty regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            result = stream.read(limit + 1)
        after = os.fstat(fd)
        if (len(result) != before.st_size or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('native linker input changed during capture')
        return result
    finally:
        os.close(fd)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate native linker manifest key')
        result[key] = value
    return result


def _publish(output: Path, data: bytes) -> None:
    """Publish complete bytes without replacing any existing destination.

    The temporary file belongs to this invocation. A failed write or fsync
    cannot expose a partial final artifact; an existing output wins the atomic
    no-replace link. This is private-directory custody, not a hostile-host
    filesystem transaction.
    """
    fd, temporary_name = tempfile.mkstemp(prefix='.hia-link-pending-', dir=output.parent)
    temporary = Path(temporary_name)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        before = os.stat(temporary, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError('native linker temporary artifact identity changed')
        os.link(temporary, output, follow_symlinks=False)
    finally:
        try:
            try:
                current = os.stat(temporary, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    temporary.unlink()
        finally:
            os.close(fd)


def link(objects: list[Path], manifest: Path, output: Path, *, expected_compiler_sha256: str | None = None) -> dict:
    from tools.hia_selfhost_native_observer import execute
    if not 1 <= len(objects) <= 16:
        raise ValueError('native linker requires between one and sixteen objects')
    raw = capture(manifest, 16384)
    value = json.loads(raw, object_pairs_hook=_pairs)
    if type(value) is not dict or value.get('schema') != SCHEMA:
        raise ValueError('native linker manifest schema differs')
    if expected_compiler_sha256 is not None and value.get('compiler_sha256') != expected_compiler_sha256:
        raise ValueError('native linker was built by a different selected compiler')
    required = ['examples/hia_bootstrap/elf_linker.hiaasm', 'tools/generate_hia_elf_linker.py',
        'tools/build_hia_elf_linker.py', 'tools/link_hia_elf.py']
    if type(value.get('source_files')) is not dict or set(value['source_files']) != set(required):
        raise ValueError('native linker source identity inventory differs')
    for name in required:
        if sha256(capture(ROOT / name, LIMIT)).hexdigest() != value['source_files'][name]:
            raise ValueError('native linker source identity mismatch')
    executable_name = value.get('executable_path')
    if (type(executable_name) is not str or Path(executable_name).name != executable_name
            or executable_name in ('', '.', '..')):
        raise ValueError('native linker executable must be manifest-local')
    executable = capture(manifest.parent / executable_name, LIMIT)
    if sha256(executable).hexdigest() != value.get('executable_sha256'):
        raise ValueError('native linker executable identity mismatch')
    inputs = [capture(path, LIMIT) for path in objects]
    frame = struct.pack('<QQ', MAGIC, len(inputs)) + struct.pack('<' + 'Q' * len(inputs), *map(len, inputs)) + b''.join(inputs)
    if len(frame) > LIMIT:
        raise ValueError('native linker frame exceeds one MiB')
    # execute seals the captured executable bytes in a memfd; later replacement
    # of its path cannot affect this invocation or its evidence identity.
    process = execute(executable, frame, cwd=output.parent, timeout=20)
    if process.returncode or process.stderr or not 0 < len(process.stdout) <= LIMIT:
        raise ValueError('native linker refused or failed: exit=' + str(process.returncode))
    _publish(output, process.stdout)
    return {'schema': 'hepta.hia.native-elf-link-receipt.v1', 'status': 'NATIVE_HIA_LINK_RETURNED',
        'manifest_sha256': sha256(raw).hexdigest(), 'executable_sha256': sha256(executable).hexdigest(),
        'object_sha256': [sha256(data).hexdigest() for data in inputs],
        'input_sha256': sha256(frame).hexdigest(), 'output_sha256': sha256(process.stdout).hexdigest(),
        'output_bytes': len(process.stdout), 'returncode': process.returncode,
        'execution_identity': 'captured bytes; sealed memfd; one native exec',
        'host_ELF_transformations': False, 'fallback_linker': False,
        'object_semantic_correctness_proved': False, 'whole_stack_rewritten_in_hia': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('objects', type=Path, nargs='+')
    args = parser.parse_args()
    print(json.dumps(link(args.objects, args.manifest, args.output), sort_keys=True))


if __name__ == '__main__':
    main()

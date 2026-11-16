"""Bootstrap a standalone HIA assembly source builder from a cold compiler.

This Python command is an explicit bootstrap/custody boundary. Its resulting
ELF owns bundle admission, compilation and self-repacking without Python, libc,
an assembler, a filesystem lookup or another executable at runtime.
"""
from __future__ import annotations

import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_source_build import BUNDLE_MAGIC, PACK_MAGIC, ROLE_NAMES, LAYOUT
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.hia_selfhost_contract import PROFILE
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCES = (
    'examples/hia_bootstrap/source_build_policy.hepta',
    'examples/hia_bootstrap/selfhost.hepta',
    'examples/hia_bootstrap/source_build_packer.hepta',
    'tools/generate_hia_source_build.py',
    'tools/hia_source_build_syscalls.S',
    'tools/build_hia_source_build.py',
)


def _check_call_receipt(receipt, *, artifact, source, size):
    expected_artifact, expected_source = sha256(artifact).hexdigest(), sha256(source).hexdigest()
    if (receipt.get('status') != 'returned' or type(receipt.get('abi_status')) is not int or receipt['abi_status'] != 0
            or type(receipt.get('core_u32')) is not int or receipt['core_u32'] != size
            or receipt.get('artifact_sha256') != expected_artifact
            or receipt.get('image_sha256') != expected_artifact
            or receipt.get('input_sha256') != expected_source
            or receipt.get('source_sha256') != expected_source
            or type(receipt.get('input_bytes')) is not int or receipt['input_bytes'] != len(source)
            or receipt.get('source_unchanged') is not True
            or receipt.get('forbidden_compiler_modules_loaded') != []):
        raise ValueError('actual native call identity does not match captured inputs')


def _check_pack_output(receipt, output, *, artifact, source, capacity=1 << 20):
    """Bind an ordinary flat packer's complete return and captured output.

    A returned child can still report a nonzero ABI status or changed input.
    Its low-u32 output length and a parseable ELF do not establish success.
    ``artifact`` and ``source`` are the caller's snapshots taken before invoke,
    not values reconstructed from the returned receipt.
    """
    if (type(receipt) is not dict or type(output) is not bytes
            or type(artifact) is not bytes or type(source) is not bytes
            or type(capacity) is not int or not 0 < capacity <= 1 << 20):
        raise ValueError('native pack output transport differs')
    size = receipt.get('core_u32')
    if (type(size) is not int or not 0 < size <= len(output) <= capacity
            or type(receipt.get('result_u64')) is not int
            or receipt['result_u64'] != size
            or receipt.get('format') != 'flat-x86-64'
            or receipt.get('return_encoding') != 'zero-extended-u32'
            or receipt.get('output_sha256') != sha256(output).hexdigest()):
        raise ValueError('native pack return or output bytes differ')
    _check_call_receipt(receipt, artifact=artifact, source=source, size=size)
    return output[:size]


def _check_compile_receipt(receipt, *, compiler, source, produced):
    _check_call_receipt(receipt, artifact=compiler, source=source, size=len(produced))
    if (not 0 < len(produced) <= 1 << 20
            or type(receipt.get('produced_bytes')) is not int
            or receipt['produced_bytes'] != len(produced)
            or receipt.get('produced_sha256') != sha256(produced).hexdigest()):
        raise ValueError('native compile receipt does not bind actual produced bytes')


def _source_bundle(sources):
    """Bootstrap transport only; the native policy independently admits all bytes."""
    wire = bytearray(struct.pack('<3Q', BUNDLE_MAGIC, 3, 0))
    for name, raw in zip(ROLE_NAMES, sources):
        name = name.encode('ascii')
        wire += struct.pack('<3Q', len(name), 0o400, len(raw)) + name + raw
    return bytes(wire)


def _run_captured(executable, operation, wire, directory):
    """Execute a sealed descriptor; a pathname swap cannot select other code."""
    fd = os.memfd_create('hia-source-build-bootstrap', os.MFD_ALLOW_SEALING)
    try:
        at = 0
        while at < len(executable):
            count = os.write(fd, executable[at:])
            if count <= 0:
                raise OSError('short native bootstrap image write')
            at += count
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
        if fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034)) & 15 != 15:
            raise ValueError('native bootstrap descriptor was not sealed')
        return subprocess.run(['/proc/self/fd/' + str(fd), operation], input=wire,
                              capture_output=True, env={'PATH': ''}, cwd=directory,
                              timeout=120, pass_fds=(fd,))
    finally:
        os.close(fd)


def _publish_captured(directory, executable, report, *, sourcekit=None):
    """Publish captured output bytes from retained anonymous descriptors.

    O_TMPFILE plus /proc/self/fd and an explicit destination dirfd makes Python
    issue linkat(AT_SYMLINK_FOLLOW). The input inode is selected by our retained
    descriptor, and the destination is created without replacement. Success
    metadata is written only after every requested inode and its bytes are
    verified. The optional keyword keeps existing executable-only callers valid.
    """
    if sourcekit is not None and (type(sourcekit) is not bytes or not 0 < len(sourcekit) <= 64 << 20):
        raise ValueError('captured sourcekit must contain bounded exact bytes')
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = receipt_fd = sourcekit_fd = -1
    linked = sourcekit_linked = False
    directory_stat = os.fstat(dfd)
    def same_inode(left, right):
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    def write_all(target, data):
        at = 0
        while at < len(data):
            count = os.write(target, data[at:])
            if count <= 0:
                raise OSError('short captured publication write')
            at += count
    def verify_current():
        image_stat = os.fstat(fd)
        named_stat = os.stat('hia-source-build', dir_fd=dfd, follow_symlinks=False)
        if (not same_inode(image_stat, named_stat) or not stat.S_ISREG(named_stat.st_mode)
                or image_stat.st_size != len(executable) or stat.S_IMODE(image_stat.st_mode) != 0o500
                or image_stat.st_nlink != 1
                or not same_inode(directory_stat, os.stat(directory, follow_symlinks=False))
                or os.pread(fd, len(executable) + 1, 0) != executable):
            raise ValueError('published executable descriptor or bytes changed')
        return image_stat
    def verify_sourcekit():
        kit_stat = os.fstat(sourcekit_fd)
        named_stat = os.stat('sourcekit.bin', dir_fd=dfd, follow_symlinks=False)
        if (not same_inode(kit_stat, named_stat) or not stat.S_ISREG(named_stat.st_mode)
                or kit_stat.st_size != len(sourcekit) or stat.S_IMODE(kit_stat.st_mode) != 0o400
                or kit_stat.st_nlink != 1
                or not same_inode(directory_stat, os.stat(directory, follow_symlinks=False))
                or os.pread(sourcekit_fd, len(sourcekit) + 1, 0) != sourcekit):
            raise ValueError('published sourcekit descriptor or bytes changed')
        return kit_stat
    def remove_owned(name, owned_fd):
        if owned_fd < 0:
            return
        try:
            current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if same_inode(current, os.fstat(owned_fd)):
                os.unlink(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
    try:
        fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        write_all(fd, executable)
        os.fchmod(fd, 0o500)
        os.fsync(fd)
        if os.pread(fd, len(executable) + 1, 0) != executable or os.fstat(fd).st_nlink != 0:
            raise ValueError('anonymous publication inode differs from captured executable')
        if sourcekit is not None:
            sourcekit_fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=dfd)
            write_all(sourcekit_fd, sourcekit)
            os.fchmod(sourcekit_fd, 0o400)
            os.fsync(sourcekit_fd)
            if (os.pread(sourcekit_fd, len(sourcekit) + 1, 0) != sourcekit
                    or os.fstat(sourcekit_fd).st_nlink != 0):
                raise ValueError('anonymous publication inode differs from captured sourcekit')
        os.link('/proc/self/fd/' + str(fd), 'hia-source-build',
                dst_dir_fd=dfd, follow_symlinks=True)
        linked = True
        if sourcekit is not None:
            os.link('/proc/self/fd/' + str(sourcekit_fd), 'sourcekit.bin',
                    dst_dir_fd=dfd, follow_symlinks=True)
            sourcekit_linked = True
        image_stat = verify_current()
        binding = {'device': image_stat.st_dev, 'inode': image_stat.st_ino,
                   'mode': stat.S_IMODE(image_stat.st_mode), 'size': image_stat.st_size,
                   'sha256': sha256(executable).hexdigest(),
                   'directory_device': directory_stat.st_dev, 'directory_inode': directory_stat.st_ino,
                   'source': 'O_TMPFILE retained descriptor', 'no_replace': True}
        recorded = {**report, 'publication': binding}
        if sourcekit is not None:
            kit_stat = verify_sourcekit()
            kit_binding = {'device': kit_stat.st_dev, 'inode': kit_stat.st_ino,
                           'mode': stat.S_IMODE(kit_stat.st_mode), 'size': kit_stat.st_size,
                           'sha256': sha256(sourcekit).hexdigest(),
                           'directory_device': directory_stat.st_dev, 'directory_inode': directory_stat.st_ino,
                           'source': 'O_TMPFILE retained descriptor', 'no_replace': True}
            recorded.update(sourcekit_path='sourcekit.bin', sourcekit_sha256=kit_binding['sha256'],
                            sourcekit_publication=kit_binding)
        serialized = (json.dumps(recorded, indent=2, sort_keys=True) + '\n').encode()
        receipt_fd = os.open('build.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o400, dir_fd=dfd)
        write_all(receipt_fd, serialized)
        os.fsync(receipt_fd)
        verify_current()
        if sourcekit is not None:
            verify_sourcekit()
        receipt_stat = os.fstat(receipt_fd)
        if (not same_inode(receipt_stat, os.stat('build.json', dir_fd=dfd, follow_symlinks=False))
                or receipt_stat.st_nlink != 1 or stat.S_IMODE(receipt_stat.st_mode) != 0o400
                or os.pread(receipt_fd, len(serialized) + 1, 0) != serialized):
            raise ValueError('published receipt descriptor or bytes changed')
        os.fsync(dfd)
        return binding
    except BaseException:
        remove_owned('build.json', receipt_fd)
        if sourcekit_linked:
            remove_owned('sourcekit.bin', sourcekit_fd)
        if linked:
            remove_owned('hia-source-build', fd)
        raise
    finally:
        if receipt_fd >= 0:
            os.close(receipt_fd)
        if sourcekit_fd >= 0:
            os.close(sourcekit_fd)
        if fd >= 0:
            os.close(fd)
        os.close(dfd)


def build(output: Path, compiler: Path, cold_report: Path):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    source_bytes = {name: (ROOT / name).read_bytes() for name in SOURCES}
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    if any(admitted.get(name) != sha256(raw).hexdigest() for name, raw in source_bytes.items()):
        raise ValueError('source builder source missing from matching cold contract')
    if not 0 < len(compiler_bytes) <= 1 << 20:
        raise ValueError('compiler image exceeds the retained image limit')
    output.mkdir(mode=0o700)
    # The actual compiler path passed to every child contains captured bytes.
    # Per-call receipts bind the bytes actually loaded, catching even a
    # temporary swap restored before the final pathname readback.
    pinned_compiler = output / 'captured-compiler.image.bin'
    pinned_compiler.write_bytes(compiler_bytes)
    pinned_compiler.chmod(0o400)
    images, receipts = {}, {}
    for label, name in (('policy', SOURCES[0]), ('packer', SOURCES[2])):
        path, receipt = compile_stage(output, label, pinned_compiler, source_bytes[name])
        raw = path.read_bytes()
        _check_compile_receipt(receipt, compiler=compiler_bytes, source=source_bytes[name], produced=raw)
        images[label] = (path, raw)
        receipts[label] = receipt
    policy, packer = images['policy'][1], images['packer'][1]
    frame = struct.pack('<4Q', PACK_MAGIC, len(policy), len(compiler_bytes), len(packer)) + policy + compiler_bytes + packer
    receipt, packed = invoke(output, 'bootstrap-pack', images['packer'][0], frame)
    executable_bytes = _check_pack_output(receipt, packed, artifact=packer, source=frame)
    inspection = inspect_executable(executable_bytes)
    wire = _source_bundle([source_bytes[name] for name in SOURCES[:3]])
    built = _run_captured(executable_bytes, 'build', wire, output)
    if built.returncode or built.stderr:
        raise ValueError('native source-kit compilation refused the captured source bundle')
    rebuilt = _run_captured(executable_bytes, 'pack', built.stdout, output)
    if rebuilt.returncode or rebuilt.stderr or rebuilt.stdout != executable_bytes:
        raise ValueError('native source-kit identity and self-repack do not reproduce the executable')
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold_bytes
            or pinned_compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in source_bytes.items())
            or any(path.read_bytes() != raw for path, raw in images.values())
            or current_sources() != admitted):
        raise ValueError('source builder inputs changed before publication')
    executable = output / 'hia-source-build'
    report = {
        'schema': 'hepta.hia.source-build-bootstrap.v1',
        'status': 'NATIVE_SOURCE_BUILDER_BUILT',
        'source_manifest': admitted,
        'source_sha256': {name: sha256(raw).hexdigest() for name, raw in source_bytes.items()},
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'image_sha256': {name: sha256(raw).hexdigest() for name, (_, raw) in images.items()},
        'compile_receipts': receipts, 'pack_receipt': receipt,
        'executable_path': executable.name, 'executable_sha256': sha256(executable_bytes).hexdigest(),
        'executable': inspection, 'sourcekit_sha256': sha256(built.stdout).hexdigest(),
        'native_self_repack_equal': True, 'memory_layout': LAYOUT,
        'input_and_output_limit': 64 << 20, 'source_and_image_limit': 1 << 20,
        'runtime_python_or_libc_or_child_required': False,
        'runtime_source_compile_dispatch_owned_by_HIA': True,
        'retained_compiler_profile': PROFILE,
        'input_content': 'HIA assembly accepted by the current qualified selfhost compiler',
        'json_Core_frontend_included': False,
        'host_bootstrap_and_cold_custody_driver': True,
        'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False,
    }
    _publish_captured(output, executable_bytes, report, sourcekit=built.stdout)
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()

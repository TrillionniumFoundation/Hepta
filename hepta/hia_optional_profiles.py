"""Explicit versioned HIA source profiles outside the default worker ABI.

The twelve original Agent resource roles remain independent. Selecting these
source bytes does not grant a compiler, native execution or cold authority.
Installed resources never fall back to a checkout, cwd, HOME or another root.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat

PROFILE_IDENTITY_SCHEMA = 'hepta.hia.optional-profile-resources.v1'
BUILD_PROFILE_ENV = 'HEPTA_HIA_BUILD_PROFILES'

# This explicit release compatibility anchor binds the actual authored report adapters.
# It is independent of a selected image manifest. It excludes this file itself
# to avoid a self-referential digest; current-cold closure binds this file too.
VERIFIED_REPORT_HOST_PINS = {'hepta/hia_program.py': '858cfa25387af02d54dad96f63f51652fb1eb2f92341411cc35a23bf22b68c84', 'hepta/hia_schema.py': 'b6bd0864fbe2a90e8f2f705da1d81c8b1afae001d8608f54f8f1fca477cdf253', 'hepta/hia_opcodes.py': 'c95b050174d8b08a5af61b50bf21e5af87d6dbd154d0a242c4c01c170b56d217', 'hepta/hia_front_runtime.py': '59161c439b2382c22b04ccb0321cde50e48990d0428beea74cedc17b30351059', 'hepta/hia_front_continuation.py': 'd0a429525404a15cedf9c14cdeabca49ed1029d7e866e89acf77a63871f4c9e0', 'hepta/hia_exception_delivery.py': '65c61a71fa90c2a757fc24aef8eca5e36af6e6b355d2537c63345e98f8d338d2', 'hepta/hia_json_preflight_native.py': '73034735b8c4cc012c6c66c3efaff059018bfba7378dfd87065a619709663664', 'hepta/hia_machine_transport.py': '385ff8acf769fd1a3b7c004ca1986812639d66fd09aa0452f4e3b6fcc3025905', 'hepta/hia_verified_report_native.py': '76ccaee0b457cb9d0abe6606a0f8aa60e6813a1aaf66bc065ae0a853fb5690f2', 'hepta/hia_verified_report_ports.py': 'c95cca6b49db860c86c5e175ab4e4c205515dd87bf31804624d2f3ae30c9c465', 'hepta/hia_cli_verified_report_native.py': 'a98703b045c25a7cd293789aa950f569a059f19d87608d65ec3d9e5a2bb0b55b'}

OPTIONAL_PROFILE_FILES = {'hepta.hia.core-representation.v1': ('examples/hia_bootstrap/assembly_reparse.hepta', 'examples/hia_bootstrap/core_representation_internal.hepta', 'examples/hia_bootstrap/core_representation_private.hepta'), 'hepta.hia.linux-file-roundtrip.v2': ('examples/hia_bootstrap/selfhost_linux_file_roundtrip.hepta', 'examples/hia_bootstrap/linux_file_roundtrip_entry_packer.hepta', 'examples/hia_bootstrap/native_file_roundtrip.hepta', 'examples/hia_bootstrap/core_representation_private.hepta', 'examples/hia_bootstrap/file_render_checker_v4.hepta'), 'hepta.hia.cli-verified-report-bundle.v2': ('examples/hia_bootstrap/verified_report.hepta',)}

OPTIONAL_RESOURCE_PINS = {'examples/hia_bootstrap/assembly_reparse.hepta': (129081, 'b69b0c89bf4edcf754e2f565de167cfb877be0ed1bdde7af59416ab404fef447'), 'examples/hia_bootstrap/core_representation_internal.hepta': (303918, '4f709a45cbc3d3ba3bf336c5616ccd1b8c609b479e985993737bf5743edfb0ca'), 'examples/hia_bootstrap/core_representation_private.hepta': (283411, 'cca0b52ca56a84782fd4ac41f5fbed56c64ebaf8c29ce60885d23b11920cb886'), 'examples/hia_bootstrap/selfhost_linux_file_roundtrip.hepta': (425503, 'e82135e94f3bf47e8b07d041d2b3a1b098d20fd7e894824b6cc704af596c0f41'), 'examples/hia_bootstrap/linux_file_roundtrip_entry_packer.hepta': (23702, 'd6debe7ce09f1b0dd6642b58ca9c0b9a042c7b80c9199e081efdc1d8ffe12e40'), 'examples/hia_bootstrap/native_file_roundtrip.hepta': (41824, '98cf4ed7444bfcdb26e020463a572d56626de3e7ddbb1fcbb881bd7d947a7965'), 'examples/hia_bootstrap/file_render_checker_v4.hepta': (388542, '2fbedf12008851e7f428fbc60fed144c0d0ebd99d7cc93e004058a8d5e375aa9'), 'examples/hia_bootstrap/verified_report.hepta': (118278, '2d3e5a21227ccdc6f40cbbfd9b72c8d1eacbdca0b24c40fc64937506a55af048')}


def profile_files(profile):
    if type(profile) is not str or profile not in OPTIONAL_PROFILE_FILES:
        raise ValueError('an exact versioned optional HIA profile is required')
    names = OPTIONAL_PROFILE_FILES[profile]
    if (type(names) is not tuple or not names or len(names) != len(set(names))
            or any(type(name) is not str or name not in OPTIONAL_RESOURCE_PINS
                   or PurePosixPath(name).as_posix() != name
                   or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                   for name in names)):
        raise ValueError('invalid explicit optional profile declaration')
    return names


def _resource_root(resource_root):
    if resource_root is not None:
        root = Path(resource_root)
        if not root.is_absolute():
            raise ValueError('an explicit optional resource origin must be absolute')
        return root
    package = Path(__file__).resolve().parent
    checkout = package.parent
    return checkout if (checkout / 'pyproject.toml').is_file() else package / '_data'


def optional_profile_resource_path(profile, name, *, resource_root=None):
    if type(name) is not str or name not in profile_files(profile):
        raise ValueError('resource is outside the explicitly selected profile')
    return _resource_root(resource_root) / name


def _read_bound_file(root, name, *, limit, expected_length=None, expected_sha256=None):
    """Capture one regular file through held, no-follow directory descriptors.

    This returns the actual verified bytes. Callers must use that capture, not
    reopen its pathname after this function's checks. It grants no authority.
    """
    root = Path(root)
    if (not root.is_absolute() or '..' in root.parts
            or type(name) is not str or not name
            or PurePosixPath(name).as_posix() != name
            or PurePosixPath(name).is_absolute()
            or any(part in ('.', '..') for part in PurePosixPath(name).parts)
            or type(limit) is not int or limit <= 0
            or (expected_length is not None and
                (type(expected_length) is not int or not 0 <= expected_length <= limit))
            or (expected_sha256 is not None and
                (type(expected_sha256) is not str or len(expected_sha256) != 64
                 or any(c not in '0123456789abcdef' for c in expected_sha256)))):
        raise ValueError('invalid bounded regular-file capture')
    parts = (*root.parts[1:], *PurePosixPath(name).parts)
    directories = []
    descriptor = None
    file_identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                   value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    directory_identity = lambda value: (value.st_dev, value.st_ino, value.st_mode)
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        current = os.open(root.anchor, flags)
        directories.append((None, None, current, os.fstat(current)))
        for part in parts[:-1]:
            parent = current
            prior = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(prior.st_mode):
                raise ValueError('bounded file directory must not be a symlink')
            current = os.open(part, flags, dir_fd=parent)
            observed = os.fstat(current)
            directories.append((parent, part, current, observed))
            if directory_identity(prior) != directory_identity(observed):
                raise ValueError('bounded file directory changed before capture')
        prior = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if (not stat.S_ISREG(prior.st_mode) or not 0 <= prior.st_size <= limit
                or (expected_length is not None and prior.st_size != expected_length)):
            raise ValueError('bounded file must have its declared regular-file extent')
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=current)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or file_identity(prior) != file_identity(before):
            raise ValueError('bounded file changed before capture')
        chunks, remaining = [], limit + 1
        while remaining:
            block = os.read(descriptor, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b''.join(chunks)
        after = os.fstat(descriptor)
        current_leaf = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if (file_identity(before) != file_identity(after)
                or file_identity(after) != file_identity(current_leaf)
                or len(raw) != before.st_size or len(raw) > limit
                or (expected_length is not None and len(raw) != expected_length)
                or (expected_sha256 is not None and sha256(raw).hexdigest() != expected_sha256)):
            raise ValueError('bounded file identity changed or differs')
        for parent, part, directory, observed in directories:
            named = (os.stat(part, dir_fd=parent, follow_symlinks=False)
                     if parent is not None else os.stat(root.anchor, follow_symlinks=False))
            held = os.fstat(directory)
            if (directory_identity(named) != directory_identity(held)
                    or directory_identity(held) != directory_identity(observed)):
                raise ValueError('bounded file directory binding changed')
        return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for _, _, directory, _ in reversed(directories):
            os.close(directory)


def _read_exact(root, name):
    length, expected = OPTIONAL_RESOURCE_PINS[name]
    if type(length) is not int or not 0 < length <= 1 << 20:
        raise ValueError('invalid fixed optional source identity')
    return _read_bound_file(root, name, limit=1 << 20,
                            expected_length=length, expected_sha256=expected)


def fresh_profile_capture(profile, *, resource_root=None):
    """Return the identity and the same actual bytes used to compute it."""
    names = profile_files(profile)
    root = _resource_root(resource_root)
    files, captures = {}, {}
    for name in names:
        raw = _read_exact(root, name)
        captures[name] = raw
        files[name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    value = {'schema': PROFILE_IDENTITY_SCHEMA, 'profile': profile, 'files': files}
    canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return {**value, 'identity_sha256': sha256(canonical).hexdigest()}, captures


def fresh_profile_identity(profile, *, resource_root=None):
    return fresh_profile_capture(profile, resource_root=resource_root)[0]


def guard_profile_identity(profile, record, *, resource_root=None):
    if type(record) is not dict or record != fresh_profile_identity(profile, resource_root=resource_root):
        raise ValueError('optional profile source identity differs from its captured declaration')
    return record

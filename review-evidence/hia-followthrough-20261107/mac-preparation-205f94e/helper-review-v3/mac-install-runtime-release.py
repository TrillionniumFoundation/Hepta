#!/usr/bin/env python3
"""Create one SHA-identified Mac release without switching any live pointer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

ROOT = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
RELEASES = Path('/Users/qianqi/.local/lib/hepta-runtime/releases')
CURRENT = RELEASES.parent / 'current'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_owned(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert not info.st_mode & 0o022 and info.st_size <= 256 * 1024 * 1024
        raw = source.read()
        after = os.fstat(source.fileno())
    assert (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    assert len(raw) == info.st_size
    return raw


def create(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as target:
        os.fchmod(target.fileno(), mode)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    assert read_owned(path) == raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runtime-commit', 'runtime-tree', 'patch-sha256', 'binary-sha256',
                 'jobctl-sha256', 'build-receipt-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--build-receipt', type=Path, required=True)
    parser.add_argument('--purpose', choices=['isolated-shadow', 'qualified-deployment'], required=True)
    args = parser.parse_args()
    assert os.getuid() == 501
    for value in (args.runtime_commit, args.runtime_tree):
        assert re.fullmatch('[0-9a-f]{40}', value)
    for value in (args.patch_sha256, args.binary_sha256, args.jobctl_sha256, args.build_receipt_sha256):
        assert re.fullmatch('[0-9a-f]{64}', value)
    assert sha(read_owned(args.build_receipt)) == args.build_receipt_sha256
    for parent in [RELEASES, RELEASES.parent,
                   Path('/Users/qianqi/.config/hepta-runtime-mac'),
                   Path('/Users/qianqi/Library/LaunchAgents')]:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            assert info.st_uid == os.getuid() and not info.st_mode & 0o022
        finally:
            os.close(fd)
    prior = os.readlink(CURRENT)
    name = args.runtime_commit[:12] + '-macos-arm64-' + args.binary_sha256[:12]
    release = RELEASES / name
    release.mkdir(mode=0o755)
    report = {'schema': 'hepta.runtime.mac-release-staging.v1',
              'purpose': args.purpose, 'runtime_commit': args.runtime_commit,
              'runtime_tree': args.runtime_tree, 'patch_sha256': args.patch_sha256,
              'build_receipt_path': str(args.build_receipt),
              'build_receipt_sha256': args.build_receipt_sha256,
              'release': str(release), 'prior_current': prior,
              'production_modified': False, 'started_unix_ns': time.time_ns(), 'files': {}}
    try:
        for filename, expected in [('hepta-runtime', args.binary_sha256),
                                   ('hepta-runtime-jobctl', args.jobctl_sha256)]:
            source = ROOT / 'target/release' / filename
            raw = read_owned(source)
            assert sha(raw) == expected, 'compiled binary identity changed'
            create(release / filename, raw, 0o755)
            assert sha(read_owned(source)) == expected, 'compiled source changed during staging'
            report['files'][filename] = {'sha256': expected, 'bytes': len(raw), 'mode': '0755'}
        assert os.readlink(CURRENT) == prior, 'live controller link changed independently'
        report['status'] = 'staged'
        report['finished_unix_ns'] = time.time_ns()
        data = (json.dumps(report, indent=2) + '\n').encode()
        create(release / 'SOURCE.json', data, 0o644)
        create(ROOT / ('release-stage-' + name + '.json'), data, 0o600)
        print(json.dumps(report), flush=True)
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error))
        create(ROOT / ('release-stage-' + name + '-failed.json'),
               (json.dumps(report, indent=2) + '\n').encode(), 0o600)
        print(json.dumps(report), flush=True)
        raise


if __name__ == '__main__':
    if __import__('sys').flags.optimize:
        raise RuntimeError('release staging requires assertions enabled')
    main()

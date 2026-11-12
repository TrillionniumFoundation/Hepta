"""Full immutable member seal in its own strict 90 CPU / 180 wall process.

No project import, target, compiler or original test is executed.  The running
sealer's own process logs and final receipts stay outside the inner archive;
all completed target inputs, outputs, sources and process records are inside.
"""
from __future__ import annotations

import time
START = time.monotonic_ns()
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path
import resource
import signal
import stat
import sys
import tarfile
import traceback

CPU = 90
WALL_NS = 180000000000
CHUNK = 1 << 20


def usage():
    a = resource.getrusage(resource.RUSAGE_SELF)
    b = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'elapsed_ns': time.monotonic_ns() - START,
            'aggregate_cpu_seconds': a.ru_utime + a.ru_stime + b.ru_utime + b.ru_stime,
            'maxrss_kib': a.ru_maxrss}


def budget():
    value = usage()
    assert 0 <= value['aggregate_cpu_seconds'] < CPU, value
    assert 0 <= value['elapsed_ns'] < WALL_NS, value
    return value


def record(path):
    st = path.lstat()
    assert stat.S_ISREG(st.st_mode), str(path)
    h = hashlib.sha256()
    gh = hashlib.sha1(b'blob ' + str(st.st_size).encode() + b'\0')
    size = 0
    with path.open('rb') as f:
        while block := f.read(CHUNK):
            size += len(block)
            h.update(block)
            gh.update(block)
    after = path.lstat()
    assert (st.st_dev, st.st_ino, st.st_size, st.st_mode) == (after.st_dev, after.st_ino, after.st_size, after.st_mode)
    assert size == st.st_size
    return {'bytes': size, 'sha256': h.hexdigest(), 'gitsha': gh.hexdigest(), 'mode': stat.S_IMODE(st.st_mode)}


def write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    path.write_bytes(raw)
    assert path.read_bytes() == raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    assert root.is_dir()
    resource.setrlimit(resource.RLIMIT_CPU, (CPU, CPU))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def deadline(signum, frame):
        raise TimeoutError('independent full-original seal 180-second wall limit')
    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, (WALL_NS - (time.monotonic_ns() - START)) / 1e9))
    primary = None
    secondary = []
    rows = []
    complete = False
    source = Path(__file__).resolve()
    before_self = record(source)
    archive = root / 'evidence.tar.xz'
    index = root / 'evidence-members.json'
    receipt = root / 'custody.json'
    post = root / 'seal-post-output-budget.json'
    excluded = {'evidence.tar.xz', 'evidence-members.json', 'custody.json',
                'summary.json', 'seal-post-output-budget.json', 'seal-failure.json'}
    result = {'schema': 'hia-self-rebuild-independent-seal-r1', 'status': 'INCOMPLETE',
              'scope': 'READ_ONLY_COMPLETE_NEW_CI_ORIGINALS_NO_TARGET_EXECUTION',
              'cpu_seconds_strict': CPU, 'wall_seconds_strict': 180, 'address_bytes': 1 << 30,
              'excluded_outer_receipts': sorted(excluded),
              'excluded_running_seal_process_directory': 'processes/full-original-seal',
              'complete_member_bytes_sha_mode_and_after_checked': False}

    def failure(phase, exc):
        nonlocal primary
        row = {'phase': phase, 'class': type(exc).__name__, 'message': str(exc),
               'traceback': ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))}
        if primary is None:
            primary = row
        else:
            secondary.append(row)
        result['status'] = 'FAIL'

    def attempt(phase, action):
        try:
            return action()
        except BaseException as exc:
            failure(phase, exc)
            return None

    def after_members():
        for row in rows:
            path = root / row['path']
            if row['kind'] == 'directory':
                assert path.is_dir() and not path.is_symlink()
                assert stat.S_IMODE(path.lstat().st_mode) == row['mode']
            else:
                actual = record(path)
                assert all(actual[k] == row[k] for k in ('bytes', 'sha256', 'gitsha', 'mode')), row['path']

    try:
        assert not archive.exists() and not index.exists() and not receipt.exists() and not post.exists()
        for path in sorted(root.rglob('*'), key=lambda p: p.relative_to(root).as_posix()):
            name = path.relative_to(root).as_posix()
            if name in excluded or name == 'processes/full-original-seal' or name.startswith('processes/full-original-seal/'):
                continue
            st = path.lstat()
            if stat.S_ISDIR(st.st_mode):
                rows.append({'path': name, 'kind': 'directory', 'mode': stat.S_IMODE(st.st_mode), 'bytes': 0})
            else:
                assert stat.S_ISREG(st.st_mode)
                rows.append({'path': name, 'kind': 'file', **record(path)})
        write(index, rows)
        with lzma.open(archive, 'wb', filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 26,
                                              'mode': lzma.MODE_FAST, 'nice_len': 32, 'mf': lzma.MF_HC4}]) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                for row in rows:
                    item = tarfile.TarInfo(row['path'])
                    item.mode, item.mtime = row['mode'], 0
                    if row['kind'] == 'directory':
                        item.type = tarfile.DIRTYPE
                        tar.addfile(item)
                    else:
                        raw = (root / row['path']).read_bytes()
                        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
                        item.size = len(raw)
                        tar.addfile(item, io.BytesIO(raw))
        expected = {row['path']: row for row in rows}
        assert len(expected) == len(rows)
        seen = set()
        with tarfile.open(archive, 'r|xz') as tar:
            for item in tar:
                assert item.name in expected and item.name not in seen
                seen.add(item.name)
                row = expected[item.name]
                assert item.mode == row['mode'] and item.size == row['bytes']
                if row['kind'] == 'directory':
                    assert item.isdir()
                else:
                    assert item.isfile() and not item.issparse()
                    raw = tar.extractfile(item).read()
                    assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        assert seen == set(expected)
        after_members()
        result.update(archive=record(archive), member_index=record(index), members=len(rows),
                      files=sum(row['kind'] == 'file' for row in rows),
                      raw_file_bytes=sum(row['bytes'] for row in rows))
        complete = True
    except BaseException as exc:
        failure('seal-originals', exc)
    finally:
        attempt('complete-member-after', after_members)
        attempt('self-after', lambda: checked_self(source, before_self))
        result.update(primary=primary, secondary=secondary,
                      complete_member_bytes_sha_mode_and_after_checked=complete and primary is None)
        result['usage_before_output'] = attempt('budget-before-output', budget)
        result['status'] = 'PASS' if primary is None and complete else 'FAIL'
        attempt('provisional-custody', lambda: write(receipt, result))
        if primary is not None:
            result.update(status='FAIL', primary=primary, secondary=secondary,
                          complete_member_bytes_sha_mode_and_after_checked=False)
        attempt('compact-stdout', lambda: print('HIA_SELF_REBUILD_SEAL ' + json.dumps(result, sort_keys=True), flush=True))
        result['usage_after_output'] = attempt('budget-after-complete-output', budget)
        result.update(primary=primary, secondary=secondary,
                      complete_member_bytes_sha_mode_and_after_checked=complete and primary is None,
                      status='PASS' if primary is None and complete else 'FAIL')
        attempt('final-custody', lambda: write(receipt, result))
        last = attempt('budget-after-final-custody-readback', budget)
        attempt('post-output-budget-receipt', lambda: write(post, {'status': 'PASS' if primary is None else 'FAIL', 'usage': last}))
        attempt('strict-return-budget', budget)
        if primary is not None:
            result.update(status='FAIL', primary=primary, secondary=secondary,
                          complete_member_bytes_sha_mode_and_after_checked=False)
            attempt('failed-custody-rewrite', lambda: write(receipt, result))
            attempt('independent-failure', lambda: write(root / 'seal-failure.json', {'primary': primary, 'secondary': secondary, 'usage': usage()}))
        signal.setitimer(signal.ITIMER_REAL, 0)
    return 0 if primary is None and complete else 1


def checked_self(path, prior):
    assert record(path) == prior


if __name__ == '__main__':
    raise SystemExit(main())

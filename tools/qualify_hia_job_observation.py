"""Compare native job observation against the retained runtime transport oracle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import stat
import struct
import subprocess
import time


def constant(source, name):
    marker = f'const {name}: &str = r#"'
    start = source.index(marker) + len(marker)
    return source[start:source.index('"#;', start)]


def frame(query):
    parts = [str(query[name]).encode() for name in ('job_dir', 'job_id', 'unit', 'request_digest')]
    return struct.pack('<8s9Q', b'HIAJOBQ1', 0,
                       query.get('stdout_offset', 0), query.get('stderr_offset', 0),
                       query.get('limit', 16384), *map(len, parts), 0) + b''.join(parts)


def run(binary, runtime_source, output):
    binary, runtime_source, output = binary.resolve(), runtime_source.resolve(), output.resolve()
    output.mkdir(mode=0o700)
    source = runtime_source.read_text()
    oracle = '\n'.join(constant(source, name) for name in
                       ('PRIVATE_DIRECTORY_CODE', 'BOUND_OBSERVATION_CODE', 'READ_CODE'))
    cases = []

    def fixture(name, stdout=b'hello\n', stderr=b''):
        root = output / name
        root.mkdir(mode=0o700)
        state = root / 'state'
        state.mkdir(mode=0o700)
        jobs = state / 'jobs'
        jobs.mkdir(mode=0o700)
        job = jobs / 'native-read'
        job.mkdir(mode=0o700)
        query = dict(job_id='native-read', job_dir=str(job), unit='hepta-native-read.service',
                     request_digest='a' * 64, stdout_offset=0, stderr_offset=0, limit=16384)
        request = {key: query[key] for key in ('job_id', 'job_dir', 'unit', 'request_digest')}
        write_json(job / 'request.json', request)
        write_json(job / 'launch.json', {'backend': 'detached', 'unit': query['unit']})
        for name, raw in (('stdout.log', stdout), ('stderr.log', stderr)):
            if raw is not None:
                (job / name).write_bytes(raw)
                (job / name).chmod(0o600)
        return root, job, query, request

    def check(name, setup=None, stdout=b'hello\n', stderr=b'', expected=True, trace=False):
        root, job, query, request = fixture(name, stdout, stderr)
        if setup:
            setup(root, job, query, request)
        old = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c', oracle],
                             input=json.dumps(query).encode(), capture_output=True, timeout=15,
                             cwd=root, env={'PATH': '/usr/bin:/bin'})
        command = [str(binary)]
        if trace:
            command = ['/usr/bin/strace', '-f', '-s', '160', '-o', str(root / 'native.trace'),
                       '-e', 'trace=process,file,read,pread64,write', *command]
        start = time.monotonic()
        new = subprocess.run(command, input=frame(query), capture_output=True, timeout=15,
                             cwd=root, env={'PATH': ''})
        elapsed = time.monotonic() - start
        if expected:
            assert old.returncode == 0, (name, 'oracle', old.returncode, old.stderr)
            assert new.returncode == 0 and not new.stderr, (name, 'native', new.returncode, new.stderr)
            assert json.loads(new.stdout) == json.loads(old.stdout), (name, new.stdout[:1000], old.stdout[:1000])
        else:
            assert old.returncode != 0, (name, 'oracle unexpectedly admitted', old.stdout)
            assert new.returncode == 65 and not new.stdout, (name, 'native unexpectedly admitted', new.returncode, new.stdout[:1000])
        if trace:
            text = (root / 'native.trace').read_text()
            executions = [line for line in text.splitlines() if re.search(r'\bexecve(?:at)?\(', line)]
            assert len(executions) == 1 and str(binary) in executions[0], executions
            if not expected and name.startswith('binding-'):
                assert '"stdout.log"' not in text and '"stderr.log"' not in text
        (root / 'native.stdout').write_bytes(new.stdout)
        (root / 'native.stderr').write_bytes(new.stderr)
        (root / 'oracle.stdout').write_bytes(old.stdout)
        (root / 'oracle.stderr').write_bytes(old.stderr)
        cases.append(dict(case=name, accepted=expected, native_rc=new.returncode,
                          oracle_rc=old.returncode, semantic_match=True, elapsed_seconds=elapsed))
        print(name, 'PASS', round(elapsed, 4), flush=True)

    check('ordinary', stderr=b'error\n', trace=True)
    check('missing-logs', stdout=None, stderr=None)
    check('empty-logs', stdout=b'', stderr=b'')
    check('utf8-and-controls', stdout=bytes(range(256)) + '中文😀\u0000'.encode(),
          stderr=b'\xf0\x90\x80\x80\xed\xa0\x80\xe0\x9f\x80\xe1\x80A\xf0\x9f\x98')
    random_source = random.Random(731)
    raw = bytes(random_source.getrandbits(8) for _ in range(16384))
    check('utf8-random', stdout=raw, stderr=raw[::-1])
    pairs = b''.join(bytes((i, j)) for i in range(256) for j in range(256))
    for offset in range(0, len(pairs), 16384):
        check(f'utf8-pairs-{offset}', stdout=pairs, stderr=pairs[::-1],
              setup=lambda r, j, q, m, offset=offset: q.update(stdout_offset=offset, stderr_offset=offset))
    check('limit-zero', setup=lambda r, j, q, m: q.update(limit=0))
    check('limit-clamped', stdout=b'a' * 40000, setup=lambda r, j, q, m: q.update(limit=65536))
    check('cursor-eof', setup=lambda r, j, q, m: q.update(stdout_offset=6))
    check('cursor-beyond', setup=lambda r, j, q, m: q.update(stdout_offset=7), expected=False)
    check('cursor-missing', stdout=None, setup=lambda r, j, q, m: q.update(stdout_offset=1), expected=False)
    check('cursor-u64-max', setup=lambda r, j, q, m: q.update(stdout_offset=(1 << 64) - 1), expected=False)
    check('readable-metadata', setup=lambda r, j, q, m: (j / 'request.json').chmod(0o644))
    check('read-only-log', setup=lambda r, j, q, m: (j / 'stdout.log').chmod(0o400))
    check('unknown-metadata', setup=lambda r, j, q, m: write_json(j / 'request.json', {**m, 'unknown': ['中文', {'value': 1.25e25}]}))
    check('fingerprint-fallback', setup=lambda r, j, q, m: write_json(j / 'request.json',
          {**{k: v for k, v in m.items() if k != 'request_digest'}, 'request_fingerprint': m['request_digest']}))
    check('escaped-binding-key', setup=lambda r, j, q, m: write_bytes(j / 'request.json',
          json.dumps(m).replace('job_id', r'job_\u0069d').encode()))
    check('duplicate-last-binding', setup=lambda r, j, q, m: write_bytes(j / 'request.json',
          ('{"job_id":"wrong",' + json.dumps(m)[1:]).encode()))
    check('duplicate-unknown', setup=lambda r, j, q, m: write_bytes(j / 'request.json',
          (json.dumps(m)[:-1] + ',"unknown":1,"unknown":2}').encode()))
    check('metadata-depth-160', setup=lambda r, j, q, m: write_bytes(j / 'request.json',
          (json.dumps(m)[:-1] + ',"nested":' + '[' * 160 + '0' + ']' * 160 + '}').encode()))
    check('metadata-exact-bound', setup=lambda r, j, q, m: write_bytes(j / 'request.json',
          (json.dumps(m)[:-1] + ',"padding":"' + 'x' *
           (4194304 - len(json.dumps(m)[:-1].encode()) - len(',"padding":""}')) + '"}').encode()))
    check('metadata-over-million-nodes', setup=lambda r, j, q, m: write_bytes(j / 'request.json',
          (json.dumps(m)[:-1] + ',"nodes":[' + '0,' * 1050000 + '0]}').encode()))
    for key, changed in (('job_id', 'different'), ('job_dir', '/different/state/jobs/native-read'),
                         ('unit', 'different.service'), ('request_digest', 'b' * 64)):
        check('binding-' + key, setup=lambda r, j, q, m, key=key, changed=changed: q.update({key: changed}),
              expected=False, trace=True)
    check('binding-digest-null', setup=lambda r, j, q, m: write_json(j / 'request.json',
          {**m, 'request_digest': None, 'request_fingerprint': m['request_digest']}), expected=False, trace=True)
    check('binding-duplicate-last-wrong', setup=lambda r, j, q, m: write_bytes(j / 'request.json',
          (json.dumps(m)[:-1] + ',"job_id":"wrong"}').encode()), expected=False, trace=True)
    check('request-malformed', setup=lambda r, j, q, m: write_bytes(j / 'request.json', b'{'), expected=False)
    check('launch-malformed', setup=lambda r, j, q, m: write_bytes(j / 'launch.json', b'[]'), expected=False)
    check('exit-malformed', setup=lambda r, j, q, m: write_bytes(j / 'exit.json', b'null'), expected=False)
    check('exit-present', setup=lambda r, j, q, m: write_json(j / 'exit.json', {'exit_code': 0}))
    check('missing-request', setup=lambda r, j, q, m: (j / 'request.json').unlink(), expected=False)
    check('missing-launch', setup=lambda r, j, q, m: (j / 'launch.json').unlink())
    for entry in ('state', 'jobs', 'job'):
        check('public-' + entry, setup=lambda r, j, q, m, entry=entry:
              {'state': j.parent.parent, 'jobs': j.parent, 'job': j}[entry].chmod(0o755), expected=False)
    for target in ('request.json', 'launch.json', 'exit.json', 'stdout.log', 'stderr.log'):
        check('writable-' + target, setup=lambda r, j, q, m, target=target:
              make_mode(j / target, 0o660), expected=False)
        check('symlink-' + target, setup=lambda r, j, q, m, target=target:
              replace_symlink(r, j / target), expected=False)
        check('hardlink-' + target, setup=lambda r, j, q, m, target=target:
              replace_hardlink(r, j / target), expected=False)
    check('fifo-log', setup=lambda r, j, q, m: replace_fifo(j / 'stdout.log'), expected=False)
    check('directory-log', setup=lambda r, j, q, m: replace_directory(j / 'stdout.log'), expected=False)
    check('path-dot', setup=lambda r, j, q, m: q.update(job_dir=str(j.parent) + '/./' + j.name), expected=False)
    check('path-parent', setup=lambda r, j, q, m: q.update(job_dir=str(j) + '/../' + j.name), expected=False)
    check('metadata-over-bound', setup=lambda r, j, q, m: write_bytes(j / 'request.json', b' ' * (4194305)), expected=False)
    root, job, query, request = fixture('invalid-native-frames')
    good = frame(query)
    invalid_frames = {
        'empty': b'', 'short': good[:79], 'wrong-magic': b'INVALID!' + good[8:],
        'trailing': good + b'x', 'over-bound': b'X' * 65537,
        'unknown-mode': good[:8] + struct.pack('<Q', 2) + good[16:],
        'unknown-flags': good[:72] + struct.pack('<Q', 1) + good[80:],
    }
    for name, packet in invalid_frames.items():
        observed = subprocess.run([binary], input=packet, capture_output=True, timeout=15,
                                  cwd=root, env={'PATH': ''})
        assert observed.returncode == 65 and not observed.stdout, (name, observed.returncode, observed.stdout)
    extra = subprocess.run([binary, 'unadmitted'], input=good, capture_output=True, timeout=15,
                           cwd=root, env={'PATH': ''})
    assert extra.returncode == 65 and not extra.stdout
    report = dict(schema='hepta.hia.job.observation.qualification.v1', passed=True,
                  scope='native READ against the retained bound READ oracle; STATUS is separately qualified',
                  executable=str(binary), executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  runtime_source=str(runtime_source), runtime_source_sha256=hashlib.sha256(runtime_source.read_bytes()).hexdigest(),
                  cases=cases, case_count=len(cases), invalid_frame_cases=len(invalid_frames) + 1)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'case_count': len(cases)}), flush=True)
    return report


def write_bytes(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def write_json(path, value):
    write_bytes(path, json.dumps(value).encode())


def make_mode(path, mode):
    if not path.exists():
        write_json(path, {})
    path.chmod(mode)


def replace_symlink(root, path):
    if path.exists():
        path.unlink()
    target = root / ('linked-' + path.name)
    write_json(target, {})
    path.symlink_to(target)


def replace_hardlink(root, path):
    if not path.exists():
        write_json(path, {})
    os.link(path, root / ('linked-' + path.name))


def replace_fifo(path):
    path.unlink()
    os.mkfifo(path, 0o600)


def replace_directory(path):
    path.unlink()
    path.mkdir(mode=0o700)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--runtime-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary, args.runtime_source, args.output)

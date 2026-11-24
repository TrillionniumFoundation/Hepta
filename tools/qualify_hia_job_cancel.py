"""Compare the native Linux cancel host with the unchanged pinned runtime.

Every signal target is a private child created by this qualification. No shared
service, unrelated process, or reusable systemd unit name is signalled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import time

from qualify_hia_job_observation import (constant, write_bytes, write_json,
    METADATA_ENCODINGS, METADATA_UNICODE, encoded_json)
from qualify_hia_job_observation_status import identity

CHILD = r'''
import os,signal,sys,time
path,action=sys.argv[1:]
def term(signum,frame):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    os.write(fd,b'T');os.close(fd)
    if action=='exit': raise SystemExit(0)
signal.signal(signal.SIGTERM,term)
os.write(1,b'R')
while True: signal.pause()
'''


def frame(query):
    pieces = [query[name].encode() for name in ('job_dir', 'job_id', 'unit', 'request_digest')]
    images = [query[name] for name in ('hia_cancel_authority', 'hia_cancel_writer')]
    raw = [bytes.fromhex(image['hex']) for image in images]
    pins = [bytes.fromhex(image['sha256']) for image in images]
    assert all(len(pin) == 32 for pin in pins)
    grace = max(0.0, min(float(query.get('grace_seconds', 10)), 30.0))
    return (struct.pack('<8s9Q', b'HIAJCQ02', int(grace * 1_000_000_000),
                        len(raw[0]), len(raw[1]), 0, *map(len, pieces), 0)
            + b''.join(pieces) + b''.join(pins) + b''.join(raw))


def artifact(raw):
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'hex': raw.hex()}


def native_stub(stdout=b'', stderr=b'', exit_code=0, hang=False):
    """Small isolated QA ELF; never installed as a production authority."""
    if hang:
        code = bytes.fromhex('b8220000000f05ebf7')
    else:
        code = bytearray()
        fixups = []
        for descriptor, payload in ((1, stdout), (2, stderr)):
            if not payload:
                continue
            code += b'\xb8\x01\x00\x00\x00\xbf' + struct.pack('<I', descriptor)
            code += b'\x48\x8d\x35'
            fixups.append((len(code), payload))
            code += bytes(4) + b'\xba' + struct.pack('<I', len(payload)) + b'\x0f\x05'
        code += b'\xb8\x3c\x00\x00\x00\xbf' + struct.pack('<I', exit_code) + b'\x0f\x05'
        for offset, payload in fixups:
            struct.pack_into('<i', code, offset, len(code) - offset - 4)
            code += payload
    size = 120 + len(code)
    return (b'\x7fELF\x02\x01\x01' + bytes(9)
            + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, size, size, 4096) + code)


def run(binary, runtime_source, authority, writer, output, selector=None):
    binary, runtime_source, authority, writer, output = [path.resolve() for path in
                                                        (binary, runtime_source, authority, writer, output)]
    output.mkdir(mode=0o700)
    source = runtime_source.read_text()
    oracle = '\n'.join(constant(source, name) for name in
                       ('PRIVATE_DIRECTORY_CODE', 'BOUND_OBSERVATION_CODE', 'CANCEL_CODE'))
    authority_raw, writer_raw = authority.read_bytes(), writer.read_bytes()
    cases = []

    def check(name, setup=None, expected=True, exited=False, backend='detached', grace=0,
              child_action='ignore', trace=False, minimum_elapsed=None, fault=None):
        if selector and re.search(selector, name) is None:
            return
        case_root = output / name
        case_root.mkdir(mode=0o700)
        observed = []
        for implementation in ('oracle', 'native'):
            root = case_root / implementation
            root.mkdir(mode=0o700)
            state = root / 'state'
            state.mkdir(mode=0o700)
            jobs = state / 'jobs'
            jobs.mkdir(mode=0o700)
            job = jobs / 'native-cancel'
            job.mkdir(mode=0o700)
            signals = root / 'signals'
            child = subprocess.Popen(['/usr/bin/python3', '-I', '-S', '-c', CHILD,
                                      str(signals), child_action], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env={'PATH': '/usr/bin'}, cwd=root)
            try:
                assert child.stdout.read(1) == b'R'
                query = dict(job_id='native-cancel', job_dir=str(job), unit='hia-native-cancel.service',
                             request_digest='a' * 64, grace_seconds=grace,
                             hia_cancel_authority=artifact(authority_raw), hia_cancel_writer=artifact(writer_raw))
                request = {key: query[key] for key in ('job_id', 'job_dir', 'unit', 'request_digest')}
                request.update(launch_nonce='b' * 32, terminal_publication_protocol=1)
                started = dict(job_id=query['job_id'], launch_nonce=request['launch_nonce'],
                               supervisor_uid=os.geteuid(), supervisor_pid=child.pid,
                               supervisor_identity=identity(child.pid), invocation_id='c' * 32)
                write_json(job / 'request.json', request)
                write_json(job / 'launch.json', {'backend': backend, 'unit': query['unit']})
                write_json(job / 'started.json', started)
                if setup:
                    setup(root, job, query, request, started)
                argv = ([str(binary)] if implementation == 'native' else
                        ['/usr/bin/python3', '-I', '-S', '-c', oracle])
                packet = frame(query) if implementation == 'native' else json.dumps(query).encode()
                environment = {'PATH': '' if implementation == 'native' else '/usr/bin:/bin'}
                if fault:
                    label, syscall, error = fault
                    baseline_path = root / 'baseline.trace'
                    tracer = ['/usr/bin/strace', '-y', '-s', '256', '-o', str(baseline_path),
                              '-e', 'trace=' + syscall]
                    baseline = subprocess.run([*tracer, *argv], input=packet, capture_output=True,
                                              timeout=15, cwd=root, env=environment)
                    assert baseline.returncode == 0, (name, implementation, baseline.stderr)
                    deadline = time.monotonic() + 1
                    while not signals.exists() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    assert signals.read_bytes() == b'T'
                    signals.unlink()
                    (job / 'cancel-request.json').unlink()
                    calls = [line for line in baseline_path.read_text().splitlines()
                             if line.startswith(syscall + '(')]
                    def target(line):
                        if label == 'pidfd':
                            return line.startswith(f'pidfd_open({child.pid},')
                        if label == 'stat-open':
                            return f'"/proc/{child.pid}/stat"' in line or f'</proc/{child.pid}>, "stat"' in line
                        return f'"/proc/{child.pid}"' in line
                    indexes = [index + 1 for index, line in enumerate(calls) if target(line)]
                    assert len(indexes) == 1, (name, implementation, indexes)
                    fault_path = root / 'fault.trace'
                    argv = ['/usr/bin/strace', '-y', '-s', '256', '-o', str(fault_path),
                            '-e', 'trace=' + syscall,
                            '-e', f'inject={syscall}:error={error}:when={indexes[0]}', *argv]
                if name == 'detached-cancel' and implementation == 'native':
                    invalid = [b'', packet[:79], b'INVALID!' + packet[8:], packet + b'x',
                               packet[:32] + struct.pack('<Q', 1) + packet[40:],
                               packet[:72] + struct.pack('<Q', 1) + packet[80:], b'x' * ((3 << 20) + 1)]
                    for bad in invalid:
                        rejected = subprocess.run(argv, input=bad, capture_output=True, timeout=15,
                                                  cwd=root, env={'PATH': ''})
                        assert rejected.returncode == 65 and not rejected.stdout
                        assert not signals.exists() and not (job / 'cancel-request.json').exists()
                    rejected = subprocess.run([*argv, 'unadmitted'], input=packet,
                        capture_output=True, timeout=15, cwd=root, env={'PATH': ''})
                    assert rejected.returncode == 65 and not rejected.stdout
                    assert not signals.exists() and not (job / 'cancel-request.json').exists()
                if trace:
                    argv = ['/usr/bin/strace', '-f', '-y', '-s', '160', '-o', str(root / 'trace'),
                            '-e', 'trace=process,file,read,write,fcntl,fsync,fdatasync,pidfd_open,pidfd_send_signal', *argv]
                begin = time.monotonic()
                result = subprocess.run(argv, input=packet, capture_output=True, timeout=15, cwd=root,
                                        env=environment)
                elapsed = time.monotonic() - begin
                if fault:
                    injected = [line for line in fault_path.read_text().splitlines()
                                if target(line) and 'INJECTED' in line]
                    assert len(injected) == 1 and error in injected[0], (name, implementation, injected)
                if minimum_elapsed is not None:
                    assert minimum_elapsed <= elapsed < 8, (name, implementation, elapsed)
                (root / 'stdout').write_bytes(result.stdout)
                (root / 'stderr').write_bytes(result.stderr)
                (root / 'query.json').write_text(json.dumps(query) + '\n')
                if expected:
                    assert result.returncode == 0 and not result.stderr, (name, implementation,
                                                                         result.returncode, result.stderr[-2000:])
                    value = json.loads(result.stdout.decode('utf-8'))
                    if exited:
                        assert value == {'job_id': query['job_id'], 'result': 'already_exited'}, value
                    else:
                        assert value == dict(job_id=query['job_id'], result='stop_requested' if backend == 'systemd' else 'term_sent',
                                             atomic_identity=True, supervisor_pid=child.pid,
                                             termination_confirmed=False, reconcile_via='process_status'), value
                        # PID values differ because each implementation owns its
                        # own fresh child; each exact binding is asserted above.
                        value['supervisor_pid'] = 'private child'
                    observed.append(value)
                else:
                    assert result.returncode != 0, (name, implementation, result.stdout)
                    if implementation == 'native':
                        assert result.returncode == 65 and not result.stdout, (name, result.returncode, result.stdout)
                if expected and not exited:
                    deadline = time.monotonic() + 1
                    while not signals.exists() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    assert signals.read_bytes() == b'T', (name, implementation, 'signal missing or repeated')
                    receipt = json.loads((job / 'cancel-request.json').read_bytes())
                    assert receipt['job_id'] == query['job_id'] and receipt['launch_nonce'] == request['launch_nonce']
                    assert isinstance(receipt['at_unix_ms'], int) and receipt['at_unix_ms'] > 0
                    assert (job / 'cancel-request.json').stat().st_mode & 0o777 == 0o600
                else:
                    assert not signals.exists(), (name, implementation, 'unexpected signal')
                    assert not (job / 'cancel-request.json').exists(), (name, implementation, 'unexpected effect receipt')
                if implementation == 'native' and trace:
                    executions = [line for line in (root / 'trace').read_text().splitlines()
                                  if re.search(r'\bexecve(?:at)?\(', line)]
                    assert str(binary) in executions[0]
                    assert not any('python' in line or 'hepta-runtime' in line or '/bin/sh' in line for line in executions[1:]), executions
                    if expected and not exited:
                        trace_text = (root / 'trace').read_text()
                        assert trace_text.index('pidfd_open(') < trace_text.index('pidfd_send_signal(')
                        assert trace_text.index('fsync(') < trace_text.index('pidfd_send_signal(')
                (root / 'result.json').write_text(json.dumps(dict(returncode=result.returncode,
                    elapsed_seconds=elapsed, signal_observed=signals.exists())) + '\n')
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                child.stdout.close()
                child.stderr.close()
        if expected:
            assert observed[0] == observed[1], (name, observed)
        cases.append(dict(case=name, accepted=expected, already_exited=exited, semantic_match=True))
        print(name, 'PASS', flush=True)

    check('detached-cancel', trace=True)
    check('systemd-cancel', backend='systemd', trace=True)
    check('grace-owner-exits', grace=0.5, child_action='exit')
    check('grace-owner-remains', grace=0.01)
    check('already-exited', setup=lambda r, j, q, m, st: write_json(j / 'exit.json', {'exit_code': 0}), exited=True)
    check('empty-exit', setup=lambda r, j, q, m, st: write_json(j / 'exit.json', {}))
    check('already-exited-ignores-image-pin', setup=lambda r, j, q, m, st:
          (write_json(j / 'exit.json', {'exit_code': 0}), q['hia_cancel_authority'].update(sha256='0' * 64)), exited=True)
    check('started-readable-mode', setup=lambda r, j, q, m, st: (j / 'started.json').chmod(0o644))
    for encoding, prefix in METADATA_ENCODINGS:
        label = encoding + ('-bom' if prefix else '')
        check('metadata-' + label, setup=lambda r, j, q, m, st, encoding=encoding, prefix=prefix:
              (write_bytes(j / 'request.json', encoded_json({**m, 'unknown': METADATA_UNICODE}, encoding, prefix)),
               write_bytes(j / 'launch.json', encoded_json({'backend': 'detached', 'unknown': METADATA_UNICODE}, encoding, prefix)),
               write_bytes(j / 'started.json', encoded_json({**st, 'unknown': METADATA_UNICODE}, encoding, prefix))))
    check('metadata-deep', setup=lambda r, j, q, m, st: write_bytes(j / 'request.json',
          (json.dumps(m)[:-1] + ',"unknown":' + '[' * 56000 + '0' + ']' * 56000 + '}').encode()))
    check('metadata-nonfinite-unknown', setup=lambda r, j, q, m, st: write_json(j / 'request.json',
          {**m, 'unknown': [float('nan'), float('inf'), -float('inf')]}))
    check('metadata-request-over-16k', setup=lambda r, j, q, m, st: write_json(j / 'request.json', {**m, 'padding': 'x' * 20000}))
    check('metadata-started-over-16k', setup=lambda r, j, q, m, st: write_json(j / 'started.json', {**st, 'padding': 'x' * 20000}))
    def exact_metadata(job, name, value):
        prefix = json.dumps(value)[:-1] + ',"padding":"'
        write_bytes(job / name, (prefix + 'x' * (4194304 - len(prefix.encode()) - 2) + '"}').encode())
    check('metadata-request-exact-4m', setup=lambda r, j, q, m, st: exact_metadata(j, 'request.json', m))
    check('metadata-started-exact-4m', setup=lambda r, j, q, m, st: exact_metadata(j, 'started.json', st))
    check('metadata-over-4m', setup=lambda r, j, q, m, st:
          write_bytes(j / 'request.json', b' ' * 4194305), expected=False)
    for count, accepted in ((4300, True), (4301, False)):
        check('metadata-integer-' + str(count), setup=lambda r, j, q, m, st, count=count:
              write_bytes(j / 'request.json', (json.dumps(m)[:-1] + ',"unknown":' + '9' * count + '}').encode()),
              expected=accepted)
    check('identity-duplicate-keys', setup=lambda r, j, q, m, st: write_bytes(j / 'started.json',
          json.dumps(st).replace('"kind":', '"kind":"wrong","kind":').encode()))
    for field, value, label in (
        ('job_id', 'wrong', 'job'), ('launch_nonce', 'd' * 32, 'nonce'),
        ('supervisor_uid', os.geteuid() + 1, 'uid'), ('supervisor_uid', True, 'uid-bool'),
        ('supervisor_pid', 1, 'pid-one'), ('supervisor_pid', '1', 'pid-string'),
        ('supervisor_identity', {'kind': 'proc_start_ticks', 'value': 'wrong'}, 'start-ticks'),
        ('supervisor_identity', {'kind': 'wrong', 'value': 'wrong'}, 'kind'),
        ('supervisor_identity', {'kind': 'proc_start_ticks', 'value': 'wrong', 'extra': 1}, 'identity-extra'),
        ('supervisor_identity', {'kind': 'proc_start_ticks', 'value': '\ud800'}, 'identity-surrogate'),
    ):
        check('invalid-owner-' + label, setup=lambda r, j, q, m, st, field=field, value=value:
              write_json(j / 'started.json', {**st, field: value}), expected=False)
    check('systemd-invalid-invocation', backend='systemd', setup=lambda r, j, q, m, st:
          write_json(j / 'started.json', {**st, 'invocation_id': 'd' * 31}), expected=False)
    check('detached-ignores-invocation', setup=lambda r, j, q, m, st:
          write_json(j / 'started.json', {**st, 'invocation_id': 'short'}))
    check('invalid-request-nonce', setup=lambda r, j, q, m, st:
          write_json(j / 'request.json', {**m, 'launch_nonce': '\udc80'}), expected=False)
    for field in ('job_id', 'unit', 'request_digest'):
        check('binding-' + field, setup=lambda r, j, q, m, st, field=field:
              q.update({field: 'b' * 64 if field == 'request_digest' else 'different'}), expected=False)
    for name in ('request.json', 'launch.json', 'exit.json', 'started.json'):
        def writable(root, job, query, request, started, name=name):
            if not (job / name).exists():
                write_json(job / name, {})
            (job / name).chmod(0o660)
        check('unsafe-' + name, setup=writable, expected=False)
        check('malformed-' + name, setup=lambda r, j, q, m, st, name=name:
              write_bytes(j / name, b'[]'), expected=False)
    check('missing-started', setup=lambda r, j, q, m, st: (j / 'started.json').unlink(), expected=False)
    for image in ('hia_cancel_authority', 'hia_cancel_writer'):
        check('wrong-pin-' + image, setup=lambda r, j, q, m, st, image=image:
              q[image].update(sha256='0' * 64), expected=False)
        check('bad-elf-' + image, setup=lambda r, j, q, m, st, image=image:
              q.update({image: artifact(b'bad!' + bytes.fromhex(q[image]['hex'])[4:])}), expected=False)
        check('short-image-' + image, setup=lambda r, j, q, m, st, image=image:
              q.update({image: artifact(b'x' * 63)}), expected=False)
    check('maximum-images', setup=lambda r, j, q, m, st: q.update(
          hia_cancel_authority=artifact(authority_raw.ljust(1048576, b'\x00')),
          hia_cancel_writer=artifact(writer_raw.ljust(1048576, b'\x00'))))
    check('image-over-limit', setup=lambda r, j, q, m, st:
          q.update(hia_cancel_authority=artifact(authority_raw.ljust(1048577, b'\x00'))), expected=False)
    authority_answer = struct.pack('<8sQ', b'HIAJCY01', 1)
    writer_answer = struct.pack('<8sQq', b'HIAJRW01', 7, 0)
    for name, raw in (
        ('declined', native_stub(stdout=struct.pack('<8sQ', b'HIAJCY01', 0))),
        ('wrong-decision', native_stub(stdout=struct.pack('<8sQ', b'HIAJCY01', 2))),
        ('wrong-tag', native_stub(stdout=b'INVALID!' + authority_answer[8:])),
        ('short-answer', native_stub(stdout=authority_answer[:-1])),
        ('long-answer', native_stub(stdout=authority_answer + b'x')),
        ('flood-answer', native_stub(stdout=b'x' * 4096)),
        ('stderr-answer', native_stub(stdout=authority_answer, stderr=b'x')),
        ('failed-exit', native_stub(exit_code=7)),
    ):
        check('authority-' + name, setup=lambda r, j, q, m, st, raw=raw:
              q.update(hia_cancel_authority=artifact(raw)), expected=False)
    for name, raw in (
        ('wrong-tag', native_stub(stderr=b'INVALID!' + writer_answer[8:])),
        ('short-answer', native_stub(stderr=writer_answer[:-1])),
        ('long-answer', native_stub(stderr=writer_answer + b'x')),
        ('failed-exit', native_stub(exit_code=7)),
    ):
        check('writer-' + name, setup=lambda r, j, q, m, st, raw=raw:
              q.update(hia_cancel_writer=artifact(raw)), expected=False)
    check('writer-existing-temporary', setup=lambda r, j, q, m, st:
          write_bytes(j / 'cancel-request.json.tmp', b'preserved'), expected=False)
    for image in ('hia_cancel_authority', 'hia_cancel_writer'):
        check('timeout-' + image, setup=lambda r, j, q, m, st, image=image:
              q.update({image: artifact(native_stub(hang=True))}), expected=False, minimum_elapsed=4.8)
    for label, syscall, error in (('pidfd', 'pidfd_open', 'ESRCH'),
                                  ('stat-open', 'openat', 'EACCES'), ('uid-stat', 'newfstatat', 'EACCES')):
        check('fault-' + label, expected=False, fault=(label, syscall, error))
    report = dict(schema='hepta.hia.job.cancel.qualification.v1', passed=True,
                  scope='Linux pidfd cancellation with pinned HIA authority and durable writer',
                  executable=str(binary), executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  runtime_source=str(runtime_source), runtime_source_sha256=hashlib.sha256(runtime_source.read_bytes()).hexdigest(),
                  authority_sha256=hashlib.sha256(authority_raw).hexdigest(),
                  writer_sha256=hashlib.sha256(writer_raw).hexdigest(), selector=selector,
                  cases=cases, case_count=len(cases),
                  invalid_native_frame_cases=8 if any(case['case'] == 'detached-cancel' for case in cases) else 0)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'case_count': len(cases), 'selector': selector}), flush=True)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('binary', 'runtime-source', 'authority', 'writer', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--selector')
    args = parser.parse_args()
    run(args.binary, args.runtime_source, args.authority, args.writer, args.output, args.selector)

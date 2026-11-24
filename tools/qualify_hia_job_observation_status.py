"""Compare HIA v25 status snapshots with the unchanged bound STATUS oracle."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import time
import unicodedata

from qualify_hia_job_observation import (constant, write_bytes, write_json,
    METADATA_ENCODINGS, METADATA_UNICODE, encoded_json)

FLAGS = ('hia_status_snapshot', 'hia_status_terminal_facts', 'hia_status_terminal_witness',
         'hia_status_native_receipt', 'hia_status_lifecycle_facts', 'hia_status_lifecycle_owner')

DENY_EXECVE = r'''
import ctypes,json,os,sys
class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
argv=json.loads(sys.argv[1])
fd=os.open(argv[0],os.O_RDONLY|os.O_CLOEXEC)
filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,59),Filter(0x06,0,0,0x5000d),Filter(0x06,0,0,0x7fff0000))
program=Program(4,filters)
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0,ctypes.get_errno()
assert libc.prctl(22,2,ctypes.byref(program),0,0)==0,ctypes.get_errno()
os.execve(fd,argv,os.environ)
'''


def frame(query):
    parts = [query[name].encode() for name in ('job_dir', 'job_id', 'unit', 'request_digest')]
    return struct.pack('<8s9Q', b'HIAJOBQ1', 1, 0, 0, 16384, *map(len, parts), 63) + b''.join(parts)


def identity(pid):
    ticks = int(Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19])
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return {'kind': 'proc_start_ticks', 'value': boot + ':' + str(ticks)}


def run(binary, runtime_source, output):
    binary, runtime_source, output = binary.resolve(), runtime_source.resolve(), output.resolve()
    output.mkdir(mode=0o700)
    source = runtime_source.read_text()
    oracle = '\n'.join(constant(source, name) for name in
                       ('PRIVATE_DIRECTORY_CODE', 'BOUND_OBSERVATION_CODE', 'STATUS_CODE'))
    cases = []
    current_identity = identity(os.getpid())
    environment = dict(os.environ)
    native_environment = {**environment, 'PATH': ''}
    oracle_environment = {**environment, 'PATH': '/usr/bin'}

    def fixture(name, backend='detached'):
        root = output / name
        root.mkdir(mode=0o700)
        state = root / 'state'
        state.mkdir(mode=0o700)
        jobs = state / 'jobs'
        jobs.mkdir(mode=0o700)
        job = jobs / 'native-status'
        job.mkdir(mode=0o700)
        query = dict(job_id='native-status', job_dir=str(job), unit='dbus.service',
                     request_digest='a' * 64, wait_seconds=0, **{name: True for name in FLAGS})
        request = {key: query[key] for key in ('job_id', 'job_dir', 'unit', 'request_digest')}
        request.update(launch_nonce='b' * 32, terminal_publication_protocol=1)
        write_json(job / 'request.json', request)
        write_json(job / 'launch.json', {'backend': backend, 'unit': query['unit']})
        started = dict(job_id=query['job_id'], launch_nonce=request['launch_nonce'],
                       supervisor_uid=os.geteuid(), supervisor_pid=os.getpid(),
                       supervisor_identity=current_identity, invocation_id='c' * 32)
        write_json(job / 'started.json', started)
        return root, job, query, request, started

    def terminal(job, query, request, **overrides):
        receipt = dict(job_id=query['job_id'], launch_nonce=request.get('launch_nonce'),
                       terminal_publication_protocol=1, exit_code=0, timed_out=False,
                       cancelled=False, output_complete=True, output_durable=True)
        receipt.update(overrides)
        raw = json.dumps(receipt, sort_keys=True, indent=1).encode() + b'\n'
        write_bytes(job / 'exit.json', raw)
        write_json(job / 'exit.witness.json', dict(job_id=query['job_id'], launch_nonce=request.get('launch_nonce'),
                   terminal_publication_protocol=1, exit_sha256=hashlib.sha256(raw).hexdigest()))

    def check(name, setup=None, backend='detached', expected=True, trace=False, env=None):
        root, job, query, request, started = fixture(name, backend)
        if setup:
            setup(root, job, query, request, started)
        old_env = {**oracle_environment, **(env or {})}
        new_env = {**native_environment, **(env or {})}
        old = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c', oracle],
                             input=json.dumps(query).encode(), capture_output=True, timeout=15,
                             cwd=root, env=old_env)
        command = [str(binary)]
        if trace:
            command = ['/usr/bin/strace', '-f', '-y', '-s', '160', '-o', str(root / 'native.trace'),
                       '-e', 'trace=process,file,read,pread64,write', *command]
        start = time.monotonic()
        new = subprocess.run(command, input=frame(query), capture_output=True, timeout=15,
                             cwd=root, env=new_env)
        elapsed = time.monotonic() - start
        for name, value in (('native.stdout', new.stdout), ('native.stderr', new.stderr),
                            ('oracle.stdout', old.stdout), ('oracle.stderr', old.stderr)):
            (root / name).write_bytes(value)
        if expected:
            assert old.returncode == 0, (root.name, 'oracle', old.returncode, old.stderr)
            assert new.returncode == 0 and not new.stderr, (root.name, 'native', new.returncode, new.stderr)
            def comparable(value):
                # A large finite-looking decimal may round to infinity just as
                # the explicit Infinity token does. Compare decoded values.
                if isinstance(value, float) and not math.isfinite(value):
                    return ('nonfinite', 'NaN' if math.isnan(value) else 'Infinity' if value > 0 else '-Infinity')
                if isinstance(value, list):
                    return [comparable(item) for item in value]
                if isinstance(value, dict):
                    return {key: comparable(item) for key, item in value.items()}
                return value
            expected_value = comparable(json.loads(old.stdout))
            actual_value = comparable(json.loads(new.stdout.decode('utf-8')))
            assert actual_value == expected_value, (root.name, actual_value, expected_value)
        else:
            assert old.returncode != 0, (root.name, 'oracle unexpectedly admitted', old.stdout)
            assert new.returncode == 65 and not new.stdout, (root.name, 'native unexpectedly admitted', new.returncode, new.stdout[:1000])
        if trace:
            executions = [line for line in (root / 'native.trace').read_text().splitlines()
                          if re.search(r'\bexecve(?:at)?\(', line)]
            assert len(executions) in (1, 2) and str(binary) in executions[0], executions
            if len(executions) == 2:
                assert '"/usr/bin/systemctl"' in executions[1], executions
            assert not any('python' in line or 'hepta-runtime' in line for line in executions[1:]), executions
        cases.append(dict(case=root.name, accepted=expected, native_rc=new.returncode,
                          oracle_rc=old.returncode, semantic_match=True, elapsed_seconds=elapsed))
        print(root.name, 'PASS', round(elapsed, 4), flush=True)
        return root, job, query

    check('detached-running', trace=True)
    check('terminal-confirmed', setup=lambda r, j, q, m, st: terminal(j, q, m), trace=True)
    def encoded_metadata(job, query, request, started, encoding, prefix, with_terminal):
        # Each source is encoded independently. The witness commits original
        # receipt bytes, while the returned JSON object uses normalized text.
        write_bytes(job / 'request.json', encoded_json({**request, 'unknown': METADATA_UNICODE}, encoding, prefix))
        write_bytes(job / 'launch.json', encoded_json({'backend': 'systemd', 'unknown': METADATA_UNICODE}, encoding, prefix))
        write_bytes(job / 'started.json', encoded_json({**started, 'unknown': METADATA_UNICODE}, encoding, prefix))
        if with_terminal:
            terminal(job, query, request, metadata=METADATA_UNICODE)
            receipt = json.loads((job / 'exit.json').read_bytes())
            raw = encoded_json(receipt, encoding, prefix)
            write_bytes(job / 'exit.json', raw)
            witness = dict(job_id=query['job_id'], launch_nonce=request['launch_nonce'],
                           terminal_publication_protocol=1, exit_sha256=hashlib.sha256(raw).hexdigest(),
                           unknown=METADATA_UNICODE)
            write_bytes(job / 'exit.witness.json', encoded_json(witness, encoding, prefix))
    for encoding, prefix in METADATA_ENCODINGS:
        label = encoding + ('-bom' if prefix else '')
        for with_terminal in (False, True):
            check('metadata-encoding-' + label + ('-terminal' if with_terminal else '-running'),
                  backend='systemd', setup=lambda r, j, q, m, st, encoding=encoding,
                  prefix=prefix, with_terminal=with_terminal:
                  encoded_metadata(j, q, m, st, encoding, prefix, with_terminal))
    check('terminal-nonfinite-unknown', setup=lambda r, j, q, m, st:
          terminal(j, q, m, unknown=[float('nan'), float('inf'), -float('inf')]))
    for nonce in ('\udc80', '\ud800x', '\ud800\udc80'):
        check('request-nonce-surrogate-' + nonce.encode('utf-8', 'surrogatepass').hex(),
              setup=lambda r, j, q, m, st, nonce=nonce:
              (write_bytes(j / 'request.json', encoded_json({**m, 'launch_nonce': nonce})),
               terminal(j, q, {**m, 'launch_nonce': nonce})))
    def large_encoded_receipt(job, query, request):
        terminal(job, query, request)
        receipt = json.loads((job / 'exit.json').read_bytes())
        receipt['metadata'] = '\ud800' * 520000
        raw = encoded_json(receipt, 'utf-16-le', b'\xff\xfe')
        assert len(raw) < 1048576
        write_bytes(job / 'exit.json', raw)
        write_json(job / 'exit.witness.json', dict(job_id=query['job_id'], launch_nonce=request['launch_nonce'],
                   terminal_publication_protocol=1, exit_sha256=hashlib.sha256(raw).hexdigest()))
    check('terminal-utf16-surrogate-near-limit', setup=lambda r, j, q, m, st:
          large_encoded_receipt(j, q, m))
    check('systemd-large-utf16-nonce', backend='systemd', setup=lambda r, j, q, m, st:
          write_bytes(j / 'request.json', encoded_json({**m, 'launch_nonce': '\ud800' * 1900000},
                                                       'utf-16-le', b'\xff\xfe')))
    for target in ('request.json', 'started.json'):
        check('metadata-deep-' + target, backend='systemd', setup=lambda r, j, q, m, st, target=target:
              write_bytes(j / target, (json.dumps(m if target == 'request.json' else st)[:-1] +
                ',"unknown":' + '[' * 4000 + '0' + ']' * 4000 + '}').encode()))
    check('terminal-witness-missing', setup=lambda r, j, q, m, st:
          (terminal(j, q, m), (j / 'exit.witness.json').unlink()))
    for value, name in ((None, 'null'), ([], 'array'), ({}, 'empty'), ({'terminal_publication_protocol': True}, 'bool-protocol')):
        check('terminal-witness-' + name, setup=lambda r, j, q, m, st, value=value:
              (terminal(j, q, m), write_json(j / 'exit.witness.json', value)))
    check('terminal-witness-malformed', setup=lambda r, j, q, m, st:
          (terminal(j, q, m), write_bytes(j / 'exit.witness.json', b'{')))
    check('terminal-witness-public-mode', setup=lambda r, j, q, m, st:
          (terminal(j, q, m), (j / 'exit.witness.json').chmod(0o644)))
    check('terminal-witness-oversize', setup=lambda r, j, q, m, st:
          (terminal(j, q, m), write_bytes(j / 'exit.witness.json', b' ' * 4097)))
    check('terminal-witness-long-unicode', setup=lambda r, j, q, m, st:
          (terminal(j, q, m), write_json(j / 'exit.witness.json', {'job_id': '界' * 128,
             'launch_nonce': '😀' * 129, 'exit_sha256': 12, 'terminal_publication_protocol': 1})))
    check('terminal-receipt-public-mode', setup=lambda r, j, q, m, st:
          (terminal(j, q, m), (j / 'exit.json').chmod(0o644)))
    check('terminal-receipt-over-limit', setup=lambda r, j, q, m, st:
          terminal(j, q, m, padding='x' * 1048576))
    check('terminal-receipt-near-limit', setup=lambda r, j, q, m, st:
          terminal(j, q, m, padding='x' * 1047000))
    check('terminal-receipt-nested', setup=lambda r, j, q, m, st:
          terminal(j, q, m, metadata={'values': [1.2, '界', True, None]}))
    check('terminal-receipt-malformed', setup=lambda r, j, q, m, st: write_bytes(j / 'exit.json', b'[]'), expected=False)
    for value, name in ((True, 'bool'), (2, 'two'), ('1', 'string'), (None, 'null')):
        check('request-protocol-' + name, setup=lambda r, j, q, m, st, value=value:
              write_json(j / 'request.json', {**m, 'terminal_publication_protocol': value}))
    check('request-no-protocol-with-receipt', setup=lambda r, j, q, m, st:
          (write_json(j / 'request.json', {k: v for k, v in m.items() if k != 'terminal_publication_protocol'}), terminal(j, q, m)))
    for value, name in ((None, 'null'), (123, 'number'), ({'nested': 'value'}, 'object'), ('界' * 128, 'unicode128'), ('z' * 129, 'long')):
        check('request-nonce-' + name, setup=lambda r, j, q, m, st, value=value:
              (write_json(j / 'request.json', {**m, 'launch_nonce': value}), terminal(j, q, m)))
    check('legacy-terminal', setup=lambda r, j, q, m, st:
          (write_json(j / 'request.json', {k: v for k, v in m.items() if k != 'terminal_publication_protocol'}),
           write_json(j / 'exit.json', {'exit_code': 0, 'timed_out': False, 'cancelled': False})))
    check('legacy-terminal-facts', setup=lambda r, j, q, m, st:
          (write_json(j / 'request.json', {k: v for k, v in m.items() if k != 'terminal_publication_protocol'}),
           write_json(j / 'exit.json', {'exit_code': '  -0 ', 'timed_out': [], 'cancelled': 'yes',
                                      'effect_outcome': 'unknown', 'output_complete': False, 'output_durable': True})))
    def legacy(job, request, receipt):
        write_json(job / 'request.json', {k: v for k, v in request.items() if k != 'terminal_publication_protocol'})
        write_json(job / 'exit.json', receipt)
    for index, value in enumerate((0.0, -0.0, 0.9, -0.9, 1.0, -1.0, 1e100,
                                   float('nan'), float('inf'), -float('inf'),
                                   None, False, True, [], {}, '  +0_0\v\f', '\u3000-٠_०\u202f',
                                   '\U0001e4f0\U0001e4f1', '\x1c0', '1__0', '1_', '_0', '0.0',
                                   '0' * 4300, '0' * 4301, '1' * 4300)):
        check('legacy-exit-conversion-' + str(index), setup=lambda r, j, q, m, st, value=value:
              legacy(j, m, {'exit_code': value, 'timed_out': value, 'cancelled': value}))
    for index, token in enumerate(('0e999999', '1e-999999', '0.99999999999999999999',
                                   '2.4703282292062327e-324', '2.4703282292062328e-324',
                                   '1.7976931348623157e308', '1.7976931348623159e308', '9' * 4300)):
        check('legacy-number-rounding-' + str(index), setup=lambda r, j, q, m, st, token=token:
              (legacy(j, m, {}), write_bytes(j / 'exit.json',
                 ('{"exit_code":' + token + ',"timed_out":' + token + ',"cancelled":' + token + '}').encode())))
    zeroes = [cp for cp in range(0x110000) if unicodedata.decimal(chr(cp), None) == 0]
    for increment in (0, 9):
        value = '_'.join(chr(cp + increment) for cp in zeroes)
        check('legacy-all-unicode-decimal-' + str(increment), setup=lambda r, j, q, m, st, value=value:
              legacy(j, m, {'exit_code': value}))
    for target in ('timed_out', 'cancelled'):
        for value, label in (([], 'empty-array'), ({}, 'empty-object'), ('', 'empty-string'),
                             ([0], 'array'), ({'value': 0}, 'object'), ('0', 'string')):
            check('legacy-truth-' + target + '-' + label, setup=lambda r, j, q, m, st,
                  target=target, value=value: legacy(j, m, {'exit_code': 0, target: value}))
    check('detached-missing-owner', setup=lambda r, j, q, m, st: (j / 'started.json').unlink())
    check('detached-malformed-owner', setup=lambda r, j, q, m, st: write_bytes(j / 'started.json', b'{'))
    check('detached-unsafe-owner', setup=lambda r, j, q, m, st: (j / 'started.json').chmod(0o644), expected=False)
    check('detached-wrong-owner', setup=lambda r, j, q, m, st: write_json(j / 'started.json', {**st, 'launch_nonce': 'd' * 32}))
    check('detached-dead-pid', setup=lambda r, j, q, m, st: write_json(j / 'started.json', {**st, 'supervisor_pid': 2147483646}))
    check('detached-wrong-start-ticks', setup=lambda r, j, q, m, st:
          write_json(j / 'started.json', {**st, 'supervisor_identity': {'kind': 'proc_start_ticks', 'value': 'wrong'}}))
    live_root, _, _ = check('systemd-live-observations', backend='systemd', trace=True)
    live = json.loads((live_root / 'native.stdout').read_bytes())['_hia_lifecycle']
    assert live['systemd'].get('ActiveState') in ('active', 'activating')
    assert live['systemd'].get('SubState') not in ('exited', 'dead')
    assert live['observations']['observed_uid'] == os.geteuid()
    assert live['observations']['observed_identity'] == current_identity['value']
    for value, name in ((None, 'null'), ([], 'array'), (False, 'bool'), ('1000', 'string'), (os.geteuid() + 1, 'wrong')):
        check('systemd-uid-' + name, backend='systemd', setup=lambda r, j, q, m, st, value=value:
              write_json(j / 'started.json', {**st, 'supervisor_uid': value}))
    for value, name in ((None, 'null'), (-1, 'negative'), (False, 'bool'), ('42', 'string'), (2147483646, 'missing')):
        check('systemd-pid-' + name, backend='systemd', setup=lambda r, j, q, m, st, value=value:
              write_json(j / 'started.json', {**st, 'supervisor_pid': value}))
    check('systemd-malformed-owner', backend='systemd', setup=lambda r, j, q, m, st: write_bytes(j / 'started.json', b'{'))
    check('systemd-missing-owner', backend='systemd', setup=lambda r, j, q, m, st: (j / 'started.json').unlink())
    check('systemd-owner-not-object', backend='systemd', setup=lambda r, j, q, m, st: write_json(j / 'started.json', []))
    check('systemd-owner-identity-not-object', backend='systemd', setup=lambda r, j, q, m, st:
          write_json(j / 'started.json', {**st, 'supervisor_identity': 'invalid', 'invocation_id': [1, 2]}))
    check('systemd-preserved-bus-environment', backend='systemd', env={'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent-hia-observation-bus'})
    missing_bus, _, _ = check('systemd-bus-unavailable', backend='systemd', env={
        'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent-hia-observation-bus',
        'XDG_RUNTIME_DIR': '/nonexistent-hia-observation-runtime'})
    assert not json.loads((missing_bus / 'native.stdout').read_bytes())['_hia_lifecycle']['systemd']
    check('systemd-unit-not-found', backend='systemd', setup=lambda r, j, q, m, st:
          (q.update(unit='hia-native-observation-absent-unit.service'),
           write_json(j / 'request.json', {**m, 'unit': 'hia-native-observation-absent-unit.service'})))
    libc = ctypes.CDLL(None, use_errno=True)
    previous_name = ctypes.create_string_buffer(16)
    assert libc.prctl(16, previous_name, 0, 0, 0) == 0
    try:
        for raw, name in ((b'a) b) c', 'parentheses'), (b'bad\xffname', 'invalid-utf8')):
            assert libc.prctl(15, ctypes.c_char_p(raw), 0, 0, 0) == 0
            check('systemd-comm-' + name, backend='systemd')
    finally:
        assert libc.prctl(15, previous_name, 0, 0, 0) == 0

    # Trace only the observation parent for targeted syscall injection. Its
    # independently launched systemctl child is not subject to these counters.
    for label, syscall in (('process-stat-open', 'openat'), ('process-boot-open', 'openat'),
                           ('process-uid-stat', 'newfstatat')):
        root, job, query, request, started = fixture('fault-' + label, 'systemd')
        observed = []
        for implementation, command, packet, env in (
            ('oracle', ['/usr/bin/python3', '-I', '-S', '-c', oracle], json.dumps(query).encode(), oracle_environment),
            ('native', [str(binary)], frame(query), native_environment),
        ):
            trace = root / (implementation + '-baseline.trace')
            tracer = ['/usr/bin/strace', '-y', '-s', '256', '-o', str(trace), '-e', 'trace=' + syscall]
            baseline = subprocess.run([*tracer, *command], input=packet, capture_output=True,
                                      timeout=15, cwd=root, env=env)
            assert baseline.returncode == 0, (label, implementation, baseline.stderr)
            calls = [line for line in trace.read_text().splitlines() if line.startswith(syscall + '(')]
            def target(line):
                if label == 'process-stat-open':
                    return f'"/proc/{os.getpid()}/stat"' in line or f'</proc/{os.getpid()}>, "stat"' in line
                if label == 'process-boot-open':
                    return '"/proc/sys/kernel/random/boot_id"' in line
                return f'"/proc/{os.getpid()}"' in line
            indexes = [index + 1 for index, line in enumerate(calls) if target(line)]
            assert len(indexes) == 1, (label, implementation, indexes)
            fault_trace = root / (implementation + '-fault.trace')
            tracer = ['/usr/bin/strace', '-y', '-s', '256', '-o', str(fault_trace),
                      '-e', 'trace=' + syscall, '-e', f'inject={syscall}:error=EACCES:when={indexes[0]}']
            result = subprocess.run([*tracer, *command], input=packet, capture_output=True,
                                    timeout=15, cwd=root, env=env)
            (root / (implementation + '.stdout')).write_bytes(result.stdout)
            (root / (implementation + '.stderr')).write_bytes(result.stderr)
            assert result.returncode == 0 and not result.stderr, (label, implementation, result.returncode, result.stderr)
            injected = [line for line in fault_trace.read_text().splitlines() if target(line) and 'EACCES' in line]
            assert len(injected) == 1 and 'INJECTED' in injected[0], (label, implementation, injected)
            observed.append(json.loads(result.stdout))
        assert observed[0] == observed[1], (label, observed)
        facts = observed[1]['_hia_lifecycle']['observations']
        if label == 'process-uid-stat':
            assert facts['observed_uid'] is None and facts['observed_identity'] == current_identity['value']
        else:
            assert facts['observed_uid'] == os.geteuid() and facts['observed_identity'] is None and facts['observed_kind'] is None
        cases.append(dict(case='fault-' + label, accepted=True, native_rc=0, oracle_rc=0,
                          semantic_match=True, injected_errno='EACCES'))
        print('fault-' + label, 'PASS', flush=True)

    root, job, query, request, started = fixture('systemctl-exec-denied', 'systemd')
    for implementation, argv, packet, env in (
        ('oracle', ['/usr/bin/python3', '-I', '-S', '-c', oracle], json.dumps(query).encode(), oracle_environment),
        ('native', [str(binary)], frame(query), native_environment),
    ):
        command = ['/usr/bin/python3', '-I', '-S', '-c', DENY_EXECVE, json.dumps(argv)]
        result = subprocess.run(command, input=packet, capture_output=True, timeout=15, cwd=root, env=env)
        (root / (implementation + '.stdout')).write_bytes(result.stdout)
        (root / (implementation + '.stderr')).write_bytes(result.stderr)
        assert result.returncode != 0 and not result.stdout, (implementation, result.returncode, result.stdout)
        if implementation == 'native':
            assert result.returncode == 65 and not result.stderr
        else:
            assert b'PermissionError' in result.stderr and b'systemctl' in result.stderr
    cases.append(dict(case='systemctl-exec-denied', accepted=False, native_rc=65, oracle_rc=1,
                      semantic_match=True, injected_errno='EACCES via inherited seccomp'))
    print('systemctl-exec-denied', 'PASS', flush=True)
    report = dict(schema='hepta.hia.job.status.snapshot.qualification.v1', passed=True,
                  profile='v25 snapshot flags 63; original bound STATUS_CODE',
                  executable=str(binary), executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  runtime_source=str(runtime_source), runtime_source_sha256=hashlib.sha256(runtime_source.read_bytes()).hexdigest(),
                  cases=cases, case_count=len(cases))
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'case_count': len(cases)}), flush=True)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--runtime-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary, args.runtime_source, args.output)

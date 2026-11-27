"""Observe exact large original diagnostics and sealed native stdio publication."""
from __future__ import annotations
import argparse
import fcntl
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import time

from tools.qualify_hia_mcp_request_history_public import Session, pin
from tools.qualify_hia_mcp_request_history import snapshot


def cases():
    pattern = 'x"\\'+chr(0)+chr(9)+chr(127)+chr(0x200b)+chr(0x1f600)+chr(0xe0001)
    return [
        ('ascii-over-1m', {'limit': 'x'*((1 << 20)+1)}),
        ('unknown-over-1m', {'k'*((1 << 20)+1): True}),
        ('del-near-8m', {'limit': chr(127)*((8 << 20)-64)}),
        ('unicode-over-1m', {'limit': chr(0x200b)*350000}),
        ('mixed-stream-boundaries', {'limit': pattern*65537}),
        ('unknown-mixed-stream-boundaries', {pattern*65537: True}),
    ]


def request(tool, ident, parameters):
    raw = ('{"jsonrpc":"2.0","id":'+json.dumps(ident, ensure_ascii=False)+
           ',"method":"tools/call","params":{"name":'+json.dumps(tool)+
           ',"arguments":'+json.dumps(parameters, ensure_ascii=False, separators=(',', ':'))+'}}\n').encode()
    assert len(raw) < 16 << 20
    return raw


def send(session, raw):
    session.connection.process.stdin.write(raw)
    session.connection.process.stdin.flush()


def read_raw(session, timeout=120):
    # Avoid rescanning an accumulated 56 MiB message once per pipe read.
    chunks = []
    initial = bytes(session.connection.pending)
    session.connection.pending.clear()
    deadline = time.monotonic()+timeout
    if initial:
        chunks.append(initial)
    while not chunks or b'\n' not in chunks[-1]:
        left = deadline-time.monotonic()
        assert left > 0, ('diagnostic observer timeout', session.connection.process.poll())
        ready, _, _ = select.select([session.connection.process.stdout], [], [], left)
        assert ready, ('diagnostic response absent', session.connection.process.poll())
        part = os.read(session.connection.process.stdout.fileno(), 65536)
        assert part, ('diagnostic connection ended', session.connection.process.poll())
        chunks.append(part)
    last, _, rest = chunks[-1].partition(b'\n')
    chunks[-1] = last
    session.connection.pending.extend(rest)
    return b''.join(chunks)+b'\n'


def checked(session, raw, baseline, ident, name):
    response = json.loads(raw)
    assert response.get('id') == ident, (name, 'request identity mismatch')
    error = response.get('error', {})
    message = error.get('message', '').encode()
    encoded = json.dumps(error, ensure_ascii=False, separators=(',', ':')).encode()
    observed = {'code': error.get('code'), 'message_bytes': len(message),
                'message_sha256': sha256(message).hexdigest(),
                'error_json_sha256': sha256(encoded).hexdigest()}
    assert observed == {key: baseline[key] for key in observed}, (name, observed, baseline)
    (session.directory/(name+'.stdout.gz')).write_bytes(gzip.compress(raw, mtime=0))
    return {'case': name, 'response_bytes': len(raw), 'response_sha256': sha256(raw).hexdigest(),
            **observed, 'exact_original_error_equal': True, 'passed': True}


def partial_worker(session):
    controller = session.connection.process.pid
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        children = Path(f'/proc/{controller}/task/{controller}/children').read_text().split()
        for child in children:
            pid = int(child)
            try:
                if Path(f'/proc/{pid}/cmdline').read_bytes() == b'hia-mcp-request-audit\0':
                    continue
                output = Path(f'/proc/{pid}/fd/1')
                if 'memfd:hia-mcp-response' not in os.readlink(output) or output.stat().st_size < 65536:
                    continue
                os.kill(pid, signal.SIGSTOP)
                while 'State:\tT' not in Path(f'/proc/{pid}/status').read_text():
                    assert time.monotonic() < deadline
                    time.sleep(0.001)
                size = output.stat().st_size
                fd = os.open(output, os.O_RDONLY | os.O_CLOEXEC)
                seals = fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034))
                return pid, fd, size, seals
            except (FileNotFoundError, ProcessLookupError):
                continue
        time.sleep(0.001)
    raise AssertionError('no live worker with a partial private diagnostic')


def qualify(bundle, reference, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    oracle = json.loads((reference/'diagnostics.json').read_bytes())
    assert oracle['binary_sha256'] == 'd4954d5391a0a40c36fcee20b65669062715a407715d07e0801aa5ee0fdae1f2'
    expected = {row['id']: row for row in oracle['cases']}
    usage_expected = json.loads((reference/'usage-diagnostic.json').read_bytes())
    checks = []
    report = {'schema': 'hepta.hia.large-parameter-diagnostics.v1', 'passed': False,
              'scope': 'actual native stdio history/archive/usage parameter diagnostics',
              'checks': checks, 'service_sha256': pin(bundle/'hia-mcp-service'),
              'original_diagnostics_sha256': pin(reference/'diagnostics.json'),
              'whole_cold_qualified': False, 'http_qualified': False,
              'sdk_frame_bytes': (16 << 20)-1, 'canonical_query_bytes': 8 << 20,
              'query_budget_seconds': 3, 'process_state_bytes': 384 << 20,
              'private_and_published_chunk_bytes': 65536}
    try:
        for tool in ('request_history', 'request_archive'):
            session = Session(bundle, output/tool)
            try:
                before = snapshot(session.state)
                for name, parameters in cases():
                    raw_params = json.dumps(parameters, ensure_ascii=False, separators=(',', ':')).encode()
                    assert len(raw_params) == expected[name]['input_params_bytes']
                    raw = request(tool, name, parameters)
                    (session.directory/(name+'.input.gz')).write_bytes(gzip.compress(raw, mtime=0))
                    started = time.monotonic()
                    send(session, raw)
                    row = checked(session, read_raw(session), expected[name], name, name)
                    row.update(tool=tool, seconds=time.monotonic()-started)
                    checks.append(row)
                    assert snapshot(session.state) == before
                    print('NATIVE_LARGE_DIAGNOSTIC_PASS', tool, name, row['response_bytes'], flush=True)
            finally:
                session.close()

        session = Session(bundle, output/'usage-and-input-bounds')
        try:
            before = snapshot(session.state)
            raw = request('usage_stats', 'usage-large-unknown', {'k'*((1 << 20)+1): True})
            send(session, raw)
            checks.append(checked(session, read_raw(session), usage_expected, 'usage-large-unknown', 'usage-large-unknown'))
            send(session, request('request_history', 'canonical-over-limit', {'limit': 'x'*(8 << 20)}))
            value = json.loads(read_raw(session))
            assert value == {'jsonrpc': '2.0', 'id': 'canonical-over-limit', 'error': {'code': -32602, 'message': 'Invalid params'}}
            # The unchanged SDK framing discards a line beyond its 16 MiB-1
            # capacity. The following independent ping is still parsed.
            send(session, b' '*(16 << 20)+b'\n'+b'{"jsonrpc":"2.0","id":"after-frame-limit","method":"ping"}\n')
            assert json.loads(read_raw(session))['id'] == 'after-frame-limit'
            assert snapshot(session.state) == before
            checks.append({'case': 'unchanged-eight-mib-query-and-sixteen-mib-frame-bounds', 'passed': True})
        finally:
            session.close()

        session = Session(bundle, output/'private-partial-publication')
        held = None
        stopped = None
        try:
            before = snapshot(session.state)
            send(session, request('request_history', 'private-before-exit', {'limit': chr(127)*((8 << 20)-64)}))
            pid, held, size, seals = partial_worker(session)
            stopped = pid
            assert 65536 <= size < expected['del-near-8m']['error_json_bytes'] and seals == 0, (size, seals)
            session.connection.send({'jsonrpc': '2.0', 'id': 'during-private-write', 'method': 'ping'})
            assert json.loads(read_raw(session, timeout=5))['id'] == 'during-private-write'
            os.kill(pid, signal.SIGCONT)
            stopped = None
            row = checked(session, read_raw(session), expected['del-near-8m'], 'private-before-exit', 'sealed-complete-reply')
            assert fcntl.fcntl(held, getattr(fcntl, 'F_GET_SEALS', 1034)) == 15
            os.close(held)
            held = None
            row.update(partial_private_bytes=size, final_seals=15, ping_before_publication=True)
            checks.append(row)
            send(session, request('request_archive', 'cancel-private-write', {'limit': chr(127)*((8 << 20)-64)}))
            pid, held, size, seals = partial_worker(session)
            stopped = pid
            assert seals == 0
            session.connection.send({'jsonrpc': '2.0', 'method': 'notifications/cancelled',
                                     'params': {'requestId': 'cancel-private-write'}})
            value = json.loads(read_raw(session, timeout=5))
            assert value['id'] == 'cancel-private-write' and value['error'] == {'code': -32800, 'message': 'Request cancelled'}
            assert snapshot(session.state) == before
            checks.append({'case': 'cancelled-partial-diagnostic-never-published',
                           'private_bytes_before_cancel': size, 'passed': True})
        finally:
            if stopped is not None:
                try:
                    os.kill(stopped, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            if held is not None:
                os.close(held)
            session.close()
        report.update(passed=True, passed_checks=len(checks))
        return report
    finally:
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'reference', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.bundle.resolve(), args.reference.resolve(), args.output.resolve())))


if __name__ == '__main__':
    main()

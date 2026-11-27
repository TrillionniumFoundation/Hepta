"""Observe native HTTP metadata and exact retained Rust diagnostics over sockets.

The real controller and audit executables are used. Worker configuration is an
explicit fixture and no Worker execution, installed release or full cold is
claimed. Raw requests and decoded HTTP bodies remain complete in gzip files.
"""
from __future__ import annotations
import argparse
import fcntl
import gzip
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import time

from tools.qualify_hia_mcp_service_config import fixture
from tools.qualify_hia_mcp_service_owner import INIT
from tools.qualify_hia_mcp_request_history import snapshot


def pin(path):
    return sha256(path.read_bytes()).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def events(body):
    result = []
    for block in body.split(b'\n\n'):
        if not block:
            continue
        row = {}
        for line in block.split(b'\n'):
            if line.startswith(b'data: '):
                raw = line[6:]
                row['data'] = json.loads(raw) if raw else None
            elif line.startswith(b'id: '):
                row['id'] = line[4:].decode()
            elif line.startswith(b'retry: '):
                row['retry'] = int(line[7:])
        result.append(row)
    return result


def rpc(body):
    if body.startswith(b'data: '):
        values = [row['data'] for row in events(body) if row.get('data') is not None]
        assert len(values) == 1, ('unexpected SSE message count', len(values))
        return values[0]
    return json.loads(body)


class HTTP:
    def __init__(self, bundle, directory, *, state=None, token=None):
        self.bundle, self.directory = bundle, directory
        directory.mkdir(mode=0o700)
        self.state = directory/'state' if state is None else state
        self.sequence = 0
        self.session = None
        manifest = bundle/'hia-controller.json'
        pins = json.loads(manifest.read_bytes())['files']
        config = fixture()['configuration']
        config['state_dir'] = str(self.state)
        config['hia_worker']['catalog_sha256'] = pins['HIA_AGENT_NATIVE_TOOL_CATALOG.json']
        host = config['hosts']['rog']
        host['ssh_target'] = 'hia-http-metadata-fixture-unused'
        for key, role in [('entry', 'hia-job-entry'), ('submit', 'hia-job-submit'),
                          ('observation', 'hia-job-observation'), ('cancel', 'hia-job-cancel'),
                          ('launcher', 'hia-job-launch')]:
            host['native_jobs'][key] = {'executable': str(bundle/role), 'sha256': pins[role]}
        config_path = directory/'configuration.json'
        config_path.write_bytes(encoded(config))
        config_path.chmod(0o600)
        self.token = token or 'hia-http-metadata-fixture-private-token-20261127'
        token_path = directory/'token'
        token_path.write_text(self.token)
        token_path.chmod(0o600)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            self.port = reserve.getsockname()[1]
        argv = [str(bundle/'hia-mcp-http'), str(config_path), pin(config_path),
                str(manifest), pin(manifest), '127.0.0.1:'+str(self.port), str(token_path)]
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_EFFECT_OWNER_')}
        env['PATH'] = ''
        self.stdout = (directory/'server.stdout').open('wb')
        self.stderr = (directory/'server.stderr').open('wb')
        self.process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.stdout, stderr=self.stderr, start_new_session=True)
        deadline = time.monotonic()+10
        while True:
            assert self.process.poll() is None, ('HTTP startup exit', self.process.returncode)
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=0.1):
                    break
            except (OSError, TimeoutError):
                assert time.monotonic() < deadline, 'HTTP listener did not start'
                time.sleep(0.01)

    def begin(self, body=b'', *, method='POST', session=True, version='1.1', headers=None,
              token=None, label='request'):
        self.sequence += 1
        name = f'{self.sequence:03d}-'+label
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=45)
        if version == '1.0':
            connection._http_vsn = 10
            connection._http_vsn_str = 'HTTP/1.0'
        fields = {'X-Hepta-Runtime-Token': self.token if token is None else token,
                  'Host': '127.0.0.1:'+str(self.port),
                  'Content-Type': 'application/json',
                  'Accept': 'application/json, text/event-stream', 'Connection': 'close'}
        if session and self.session is not None:
            fields['Mcp-Session-Id'] = self.session
            fields['MCP-Protocol-Version'] = '2025-11-25'
        if headers:
            fields.update(headers)
        (self.directory/(name+'.input.gz')).write_bytes(gzip.compress(body, mtime=0))
        (self.directory/(name+'.request.json')).write_text(json.dumps({
            'method': method, 'version': version, 'headers': fields,
            'body_bytes': len(body), 'body_sha256': sha256(body).hexdigest()}, indent=2)+'\n')
        connection.request(method, '/mcp', body=body, headers=fields)
        response = connection.getresponse()
        return connection, response, name, time.monotonic()

    def finish(self, request, *, initial=b''):
        connection, response, name, started = request
        chunks = [initial] if initial else []
        try:
            while part := response.read(65536):
                chunks.append(part)
            raw = b''.join(chunks)
            (self.directory/(name+'.body.gz')).write_bytes(gzip.compress(raw, mtime=0))
            meta = {'status': response.status, 'headers': dict(response.getheaders()),
                    'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                    'seconds': time.monotonic()-started}
            (self.directory/(name+'.response.json')).write_text(json.dumps(meta, indent=2)+'\n')
            return meta, raw
        except Exception:
            raw = b''.join(chunks)
            (self.directory/(name+'.partial.gz')).write_bytes(gzip.compress(raw, mtime=0))
            raise
        finally:
            connection.close()

    def exchange(self, body=b'', **kwargs):
        return self.finish(self.begin(body, **kwargs))

    def initialize(self):
        meta, raw = self.exchange(encoded(INIT), session=False, label='initialize')
        assert meta['status'] == 200, (meta, raw[:1024])
        assert rpc(raw)['result']['protocolVersion'] == '2025-11-25'
        self.session = meta['headers'].get('mcp-session-id')
        assert self.session and len(self.session) == 36, meta
        ready = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
        meta, raw = self.exchange(encoded(ready), label='ready')
        assert meta['status'] == 202 and raw == b'', (meta, raw)

    def call(self, tool, arguments, ident, *, meta=None):
        params = {'name': tool, 'arguments': arguments}
        if meta is not None:
            params['_meta'] = meta
        return encoded({'jsonrpc': '2.0', 'id': ident, 'method': 'tools/call', 'params': params})

    def close(self):
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        self.stdout.close()
        self.stderr.close()


def exact_error(raw, baseline, ident):
    value = rpc(raw)
    assert value.get('id') == ident, ('response identity', value.get('id'), ident)
    error = value.get('error', {})
    message = error.get('message', '').encode()
    observed = {'code': error.get('code'), 'message_bytes': len(message),
                'message_sha256': sha256(message).hexdigest(),
                'error_json_sha256': sha256(encoded(error)).hexdigest()}
    assert observed == {key: baseline[key] for key in observed}, (ident, observed, baseline)
    return observed


def descendants(pid):
    result = []
    pending = [pid]
    while pending:
        current = pending.pop()
        try:
            children = [int(value) for value in Path(f'/proc/{current}/task/{current}/children').read_text().split()]
        except FileNotFoundError:
            continue
        result.extend(children)
        pending.extend(children)
    return result


def partial_worker(server):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        for pid in descendants(server.process.pid):
            try:
                path = Path(f'/proc/{pid}/fd/1')
                if 'memfd:hia-mcp-response' not in os.readlink(path) or path.stat().st_size < 65536:
                    continue
                os.kill(pid, signal.SIGSTOP)
                while 'State:\tT' not in Path(f'/proc/{pid}/status').read_text():
                    assert time.monotonic() < deadline
                    time.sleep(0.001)
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                return pid, fd, path.stat().st_size, fcntl.fcntl(fd, 1034)
            except (FileNotFoundError, ProcessLookupError):
                continue
        time.sleep(0.001)
    raise AssertionError('no live HTTP worker with partial private diagnostic')


def private_prefix(request):
    response = request[1]
    prefix = response.read1(65536)
    rows = events(prefix)
    assert len(rows) == 1 and rows[0]['data'] is None, ('nonprivate diagnostic', prefix[:128])
    sock = response.fp.raw._sock
    timeout = sock.gettimeout()
    try:
        sock.setblocking(False)
        # HTTPResponse leaves the consumed chunk's CRLF until it reads the
        # next chunk header. This is framing for the already public priming.
        buffered = response.fp.peek(1)
        assert response.chunk_left == 0 and buffered in (b'', b'\r\n'), (
            'published diagnostic while worker stopped', buffered[:64])
    finally:
        sock.settimeout(timeout)
    assert not select.select([sock], [], [], 0.05)[0], 'new response data while worker stopped'
    return prefix


def qualify(bundle, reference, http_reference, output, *, smoke=False):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []
    report = {'schema': 'hepta.hia.metadata-http-public.v1', 'passed': False, 'checks': checks,
              'scope': 'real native HTTP metadata routes and exact original diagnostics',
              'executable_sha256': pin(bundle/'hia-mcp-http'),
              'manifest_sha256': pin(bundle/'hia-controller.json'),
              'original_source': 'ae1c7ea593da45f7299c692a2acd44605c35be09',
              'whole_cold_qualified': False, 'installed_worker_claimed': False,
              'http_input_bytes': 4 << 20, 'query_budget_seconds': 3}
    server = None
    def passed(name, **values):
        checks.append({'case': name, 'passed': True, **values})
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')
        print('NATIVE_METADATA_HTTP_PASS', name, flush=True)
    try:
        server = HTTP(bundle, output/'server')
        server.initialize()
        before = snapshot(server.state)
        for tool in ('request_history', 'request_archive', 'usage_stats'):
            response, raw = server.exchange(server.call(tool, {}, tool), label=tool)
            value = rpc(raw)
            assert response['status'] == 200 and value.get('id') == tool, (response, value)
            assert value.get('result', {}).get('isError') is False, value
            assert snapshot(server.state) == before, tool
            passed('empty-'+tool, response=value, http=response)
        response, raw = server.exchange(encoded({'jsonrpc': '2.0', 'id': 'catalog',
                                                'method': 'tools/list', 'params': {}}), label='catalog')
        tools = rpc(raw)['result']['tools']
        assert len(tools) == 14 and len({row['name'] for row in tools}) == 14
        assert all(any(row['name'] == name for row in tools)
                   for name in ('request_history', 'request_archive', 'usage_stats'))
        passed('catalog-metadata-discovery', names=[row['name'] for row in tools])
        response, raw = server.exchange(server.call('usage_stats', {}, 'wrong-token'),
                                        token='not-the-fixture-token', label='wrong-token')
        assert response['status'] == 401 and snapshot(server.state) == before
        passed('original-private-token-authentication-before-metadata')
        if smoke:
            report.update(passed=True, passed_checks=len(checks), smoke_only=True)
            return report
        original = json.loads((reference/'diagnostics.json').read_bytes())
        assert original['binary_sha256'] == 'd4954d5391a0a40c36fcee20b65669062715a407715d07e0801aa5ee0fdae1f2'
        expected = {row['id']: row for row in original['cases']}
        large = json.loads((http_reference/'diagnostic.json').read_bytes())
        assert large['binary_sha256'] == original['binary_sha256']
        assert pin(http_reference/'diagnostic.json') == '0f028dea059cbcef900673cdf8bdba16ad7a0859519139bdb4dc76a47f8d670e'
        report['references'] = {'existing': pin(reference/'diagnostics.json'),
                                'http_large': pin(http_reference/'diagnostic.json')}
        for tool in ('request_history', 'request_archive'):
            for name, parameters, baseline in (
                ('ascii-over-1m', {'limit': 'x'*((1 << 20)+1)}, expected['ascii-over-1m']),
                ('del-near-http-4m', {'limit': chr(127)*((4 << 20)-1024)}, large),
            ):
                ident = tool+'-'+name
                request = server.call(tool, parameters, ident)
                assert len(request) <= 4 << 20
                response, raw = server.exchange(request, label=ident)
                assert response['status'] == 200, response
                observation = exact_error(raw, baseline, ident)
                assert snapshot(server.state) == before
                event_rows = events(raw)
                assert len(event_rows) == 2 and event_rows[0]['data'] is None
                stream = event_rows[1]['id'].split('/')[1]
                assert event_rows[0]['id'] == '0/'+stream and event_rows[1]['id'] == '1/'+stream
                passed(ident, http=response, exact_original_error_equal=True, **observation)
                if name == 'del-near-http-4m':
                    for index in (0, 1, 2):
                        replay_meta, replay = server.exchange(method='GET',
                            headers={'Last-Event-ID': str(index)+'/'+stream}, label=ident+'-replay-'+str(index))
                        assert replay_meta['status'] == 200, replay_meta
                        if index < 2:
                            assert exact_error(replay, baseline, ident) == observation
                            assert len(events(replay)) == (2 if index == 0 else 1)
                        else:
                            assert replay == b'', replay[:128]
                        passed(ident+'-replay-'+str(index), http=replay_meta)

        usage_expected = json.loads((reference/'usage-diagnostic.json').read_bytes())
        ident = 'usage-large-unknown'
        response, raw = server.exchange(server.call('usage_stats', {'k'*((1 << 20)+1): True}, ident), label=ident)
        assert response['status'] == 200
        passed(ident, exact_original_error_equal=True, **exact_error(raw, usage_expected, ident))

        parameters = {'limit': chr(127)*((4 << 20)-1024)}
        inline = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                  'io.modelcontextprotocol/clientCapabilities': {}}
        standard = {'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call',
                    'Mcp-Name': 'request_history'}
        for name, metadata, status in (
            ('stateless-complete-metadata', inline, 200),
            ('stateless-missing-capabilities', {'io.modelcontextprotocol/protocolVersion': '2026-07-28'}, 400),
        ):
            response, raw = server.exchange(server.call('request_history', parameters, name, meta=metadata),
                                            session=False, headers=standard, label=name)
            assert response['status'] == status, (name, response, raw[:256])
            assert response['headers']['content-type'] == ('text/event-stream' if status == 200 else 'application/json')
            if status == 200:
                observed = exact_error(raw, large, name)
                assert len(events(raw)) == 1 and 'id' not in events(raw)[0]
                passed(name, http=response, exact_original_error_equal=True, **observed)
            else:
                assert rpc(raw) == {'jsonrpc': '2.0', 'id': name, 'error': {
                    'code': -32602, 'message': 'request _meta is missing or has malformed required fields: '
                    'io.modelcontextprotocol/clientCapabilities'}}
                passed(name, http=response, original_metadata_validation_precedes_parameter_diagnostic=True)

        ident = 'http10-large-complete'
        response, raw = server.exchange(server.call('request_archive', parameters, ident),
                                        version='1.0', label=ident)
        assert response['status'] == 200 and 'transfer-encoding' not in response['headers']
        passed(ident, http=response, exact_original_error_equal=True, **exact_error(raw, large, ident))

        request = server.call('usage_stats', {}, 'exact-four-mib')
        request += b' '*((4 << 20)-len(request))
        response, raw = server.exchange(request, label='exact-four-mib')
        assert response['status'] == 200 and rpc(raw)['result']['isError'] is False
        response, raw = server.exchange(request+b' ', label='over-four-mib')
        assert response['status'] == 413, (response, raw[:256])
        assert snapshot(server.state) == before
        passed('unchanged-exact-four-mib-http-input-and-one-byte-over-refusal')

        held = stopped = None
        try:
            ident = 'private-before-exit'
            request = server.begin(server.call('request_history', parameters, ident), label=ident)
            stopped, held, size, seals = partial_worker(server)
            assert 65536 <= size < large['error_json_bytes'] and seals == 0, (size, seals)
            prefix = private_prefix(request)
            ping = encoded({'jsonrpc': '2.0', 'id': 'during-private-write', 'method': 'ping'})
            meta, pong = server.exchange(ping, label='during-private-write')
            assert meta['status'] == 200 and rpc(pong)['id'] == 'during-private-write'
            os.kill(stopped, signal.SIGCONT)
            stopped = None
            response, raw = server.finish(request, initial=prefix)
            observation = exact_error(raw, large, ident)
            assert fcntl.fcntl(held, 1034) == 15
            os.close(held)
            held = None
            passed('partial-private-output-complete-seals-before-publication',
                   private_bytes=size, complete_error_equal=True, final_seals=15, **observation)

            ident = 'cancel-private-write'
            request = server.begin(server.call('request_archive', parameters, ident), label=ident)
            stopped, held, size, seals = partial_worker(server)
            assert seals == 0
            prefix = private_prefix(request)
            stream = events(prefix)[0]['id'].split('/')[1]
            cancellation = encoded({'jsonrpc': '2.0', 'method': 'notifications/cancelled',
                                    'params': {'requestId': ident}})
            response, raw = server.exchange(cancellation, label='cancel-partial')
            assert response['status'] == 202 and raw == b''
            response, raw = server.finish(request, initial=prefix)
            assert response['status'] == 200 and raw == prefix
            for index in (0, 1):
                response, raw = server.exchange(method='GET', headers={'Last-Event-ID': str(index)+'/'+stream},
                                                label='cancel-tombstone-replay-'+str(index))
                assert response['status'] == 200
                assert raw == (prefix if index == 0 else b'')
            assert snapshot(server.state) == before
            passed('cancel-partial-never-publishes-diagnostic-and-retains-original-tombstone', private_bytes=size)
        finally:
            if stopped is not None:
                try:
                    os.kill(stopped, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            if held is not None:
                os.close(held)

        audit = [pid for pid in descendants(server.process.pid)
                 if Path(f'/proc/{pid}/cmdline').read_bytes() == b'hia-mcp-request-audit\0']
        assert len(audit) == 1, audit
        from tools.qualify_hia_mcp_request_archive import DEADLINE
        os.kill(audit[0], signal.SIGSTOP)
        try:
            wait = time.monotonic()+1
            while 'State:\tT' not in Path(f'/proc/{audit[0]}/status').read_text():
                assert time.monotonic() < wait
                time.sleep(0.001)
            started = time.monotonic()
            response, raw = server.exchange(server.call('usage_stats', {}, 'three-second-deadline'), label='three-second-deadline')
            elapsed = time.monotonic()-started
            value = rpc(raw)
            assert response['status'] == 200 and value['result']['isError'] is True
            assert value['result']['content'] == [{'type': 'text', 'text': DEADLINE}]
            assert 2.5 <= elapsed < 4.5, elapsed
        finally:
            os.kill(audit[0], signal.SIGCONT)
        response, raw = server.exchange(server.call('usage_stats', {}, 'fresh-after-stale'), label='fresh-after-stale')
        assert response['status'] == 200 and rpc(raw)['result']['isError'] is False
        assert snapshot(server.state) == before
        passed('absolute-three-second-query-deadline-and-stale-response-drain', seconds=elapsed)
        report.update(passed=True, passed_checks=len(checks))
        return report
    finally:
        if server is not None:
            server.close()
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'reference', 'http-reference', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    report = qualify(args.bundle.resolve(), args.reference.resolve(), args.http_reference.resolve(),
                     args.output.resolve(), smoke=args.smoke)
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks'])}))


if __name__ == '__main__':
    main()

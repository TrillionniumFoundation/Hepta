"""Exercise the actual native MCP process, custody, lifetime locks and cancellation.

The qualification uses the real installed controller bundle. It never replaces
an executable role with a response mock or dispatches a new successful job.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import time

from tools.generate_hia_worker_config_json import CONTROLLER_FILES


def digest(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'


INIT = {'jsonrpc': '2.0', 'id': 'init', 'method': 'initialize', 'params': {
    'protocolVersion': '2025-11-25', 'capabilities': {},
    'clientInfo': {'name': 'native-service-owner-qualification', 'version': '1'}}}
READY = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
PING = {'jsonrpc': '2.0', 'id': 'ping', 'method': 'ping'}


class Connection:
    def __init__(self, argv, env):
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=env)
        self.pending = bytearray()

    def send(self, value):
        self.process.stdin.write(wire(value))
        self.process.stdin.flush()

    def read(self, timeout=15):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0, ('response deadline', self.process.poll())
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            assert ready, ('no response', self.process.poll())
            part = os.read(self.process.stdout.fileno(), 65536)
            assert part, ('connection ended', self.process.poll(), bytes(self.pending))
            self.pending.extend(part)
        line, _, rest = self.pending.partition(b'\n')
        self.pending = bytearray(rest)
        return json.loads(line)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
        rc = self.process.wait(timeout=15)
        err = self.process.stderr.read()
        assert rc == 0 and not err, (rc, err)


def descriptors(pid):
    return sorted(os.readlink(p) for p in Path(f'/proc/{pid}/fd').iterdir())


def bridge_child(pid):
    def children(parent):
        try:
            return [int(n) for n in Path(f'/proc/{parent}/task/{parent}/children').read_text().split()]
        except FileNotFoundError:
            return []
    for worker in children(pid):
        for bridge in children(worker):
            try:
                cmdline = Path(f'/proc/{bridge}/cmdline').read_bytes()
            except FileNotFoundError:
                continue
            if cmdline == b'hia-mcp-job-bridge\x00':
                return bridge
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    original_service = args.service.read_bytes()
    original_config = args.config.read_bytes()
    original_manifest = args.manifest.read_bytes()
    baseline = json.loads(original_config)
    bundle = args.output / 'controller'
    bundle.mkdir(mode=0o700)
    saved = {}
    for name in (*CONTROLLER_FILES, 'hia-controller.json'):
        source = args.manifest.parent / name
        target = bundle / name
        shutil.copy2(source, target)
        saved[name] = (target.read_bytes(), target.stat().st_mode & 0o7777)
    manifest = bundle / 'hia-controller.json'
    config_path = args.output / 'config.json'
    env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_EFFECT_OWNER_')}
    env['PATH'] = ''
    records = []

    def arguments(config=None, config_pin=None, manifest_pin=None):
        current = dict(baseline if config is None else config)
        config_path.write_bytes(json.dumps(current, separators=(',', ':')).encode())
        config_path.chmod(0o600)
        return [str(args.service), str(config_path), config_pin or digest(config_path.read_bytes()),
                str(manifest), manifest_pin or digest(manifest.read_bytes())]

    counter = 0
    def config_for(name):
        nonlocal counter
        counter += 1
        result = json.loads(original_config)
        result['state_dir'] = str(args.output / f'state-{counter}-{name}')
        return result

    def record(name, **evidence):
        records.append({'name': name, **evidence})
        (args.output / 'partial.json').write_text(json.dumps(records, indent=2) + '\n')

    def run_case(name, *, config=None, data=None, refusal=False, changed_env=None,
                 config_pin=None, manifest_pin=None, response_ids=None, expected_rc=0):
        cfg = config or config_for(name)
        argv = arguments(cfg, config_pin, manifest_pin)
        raw = data if data is not None else wire(INIT) + wire(READY) + wire(PING)
        started = time.monotonic()
        result = subprocess.run(argv, input=raw, capture_output=True, timeout=30,
                                env=env if changed_env is None else {**env, **changed_env})
        if refusal:
            assert result.returncode == 65 and result.stdout == b'' and result.stderr == b'', (
                name, result.returncode, result.stdout[:1024], result.stderr)
        else:
            assert result.returncode == expected_rc and not result.stderr, (name, result.returncode, result.stderr)
            parsed = [json.loads(line) for line in result.stdout.splitlines()]
            if response_ids is None:
                assert parsed and parsed[-1]['id'] == 'ping', (name, parsed[-1:] if parsed else [])
            else:
                assert [message.get('id') for message in parsed] == response_ids, (name, parsed)
        record(name, rc=result.returncode, seconds=time.monotonic() - started,
               stdin_sha256=digest(raw), stdout_sha256=digest(result.stdout),
               stdout_bytes=len(result.stdout))
        return result

    run_case('startup-and-ping')
    run_case('unused-empty-environment-default', changed_env={'HEPTA_RUNTIME_STATE_DIR': ''})
    cfg = config_for('default-env')
    state = cfg.pop('state_dir')
    run_case('used-state-environment-default', config=cfg, changed_env={'HEPTA_RUNTIME_STATE_DIR': state})
    cfg = config_for('newline-state')
    cfg['state_dir'] += '\nkept'
    run_case('original-newline-state-path', config=cfg)
    cfg = config_for('dot-dot-state')
    cfg['state_dir'] = str(args.output / 'created-parent' / '..' / 'canonical-state')
    run_case('recursive-dot-dot-state', config=cfg)
    target = args.output / 'aliased-state'
    target.mkdir(mode=0o700)
    alias = args.output / 'state-alias'
    alias.symlink_to(target, target_is_directory=True)
    cfg = config_for('symlink-state')
    cfg['state_dir'] = str(alias)
    run_case('original-state-symlink-alias', config=cfg)
    assert (target / 'controller.owner.lock').is_file()
    run_case('wrong-config-pin', config_pin='0' * 64, refusal=True)
    run_case('wrong-manifest-pin', manifest_pin='0' * 64, refusal=True)
    run_case('uppercase-config-pin', config_pin='A' * 64, refusal=True)
    for mode in (0o755, 0o770, 0o1700):
        path = args.output / f'wide-state-{mode:o}'
        path.mkdir(mode=0o700)
        path.chmod(mode)
        cfg = config_for('wide-state')
        cfg['state_dir'] = str(path)
        run_case(f'existing-state-mode-{mode:o}-refused', config=cfg, refusal=True)
        assert path.stat().st_mode & 0o7777 == mode
    cfg = config_for('private-owner-mode')
    state = Path(cfg['state_dir'])
    state.mkdir(mode=0o700)
    owner = state / 'controller.owner.lock'
    owner.write_bytes(b'original lock bytes')
    owner.chmod(0o644)
    run_case('unsafe-owner-mode-is-not-repaired', config=cfg, refusal=True)
    assert owner.stat().st_mode & 0o777 == 0o644 and owner.read_bytes() == b'original lock bytes'
    owner.chmod(0o700)
    run_case('original-private-owner-execute-bit', config=cfg)
    assert owner.stat().st_mode & 0o777 == 0o700
    legacy = state / 'controller.lock'
    legacy.write_bytes(b'legacy lock bytes')
    legacy.chmod(0o644)
    run_case('legacy-lock-mode-repair-preserves-bytes', config=cfg)
    assert legacy.stat().st_mode & 0o777 == 0o600 and legacy.read_bytes() == b'legacy lock bytes'
    linked = args.output / 'owner-lock-alias'
    os.link(owner, linked)
    try:
        run_case('owner-lock-hardlink-refused', config=cfg, refusal=True)
    finally:
        linked.unlink()
    cfg = config_for('owner-lock-symlink')
    state = Path(cfg['state_dir'])
    state.mkdir(mode=0o700)
    (state / 'controller.owner.lock').symlink_to(owner)
    run_case('owner-lock-symlink-refused', config=cfg, refusal=True)
    for label, changed in (
        ('required-empty', {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': ''}),
        ('required-zero', {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '0'}),
        ('required-without-authority', {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '1'}),
        ('unpaired-authority', {'HEPTA_EFFECT_OWNER_FENCE_DIR': str(args.output)}),
        ('unpaired-owner', {'HEPTA_EFFECT_OWNER_SELF': 'v11'}),
        ('unknown-owner', {'HEPTA_EFFECT_OWNER_FENCE_DIR': str(args.output), 'HEPTA_EFFECT_OWNER_SELF': 'v99'}),
    ):
        run_case('fence-' + label, changed_env=changed, refusal=True)
    for name in CONTROLLER_FILES:
        path = bundle / name
        before, mode = saved[name]
        path.chmod(0o600)
        changed = bytearray(before)
        changed[-1] ^= 1
        path.write_bytes(changed)
        path.chmod(mode)
        try:
            run_case('role-pin-' + name, refusal=True)
        finally:
            path.chmod(0o600)
            path.write_bytes(before)
            path.chmod(mode)
    for name, cap in zip(CONTROLLER_FILES, (2 << 20, 4 << 20, 2 << 20, 1 << 20, 1 << 20) + (1 << 20,) * 14):
        path = bundle / name
        before, mode = saved[name]
        path.chmod(0o600)
        with path.open('r+b') as output:
            output.truncate(cap + 1)
        path.chmod(mode)
        try:
            run_case('role-cap-' + name, refusal=True)
        finally:
            path.chmod(0o600)
            path.write_bytes(before)
            path.chmod(mode)
    name = CONTROLLER_FILES[0]
    path = bundle / name
    alias = bundle / 'extra-link'
    os.link(path, alias)
    try:
        run_case('role-hardlink-refused', refusal=True)
    finally:
        alias.unlink()
    before, mode = saved[name]
    path.chmod(mode | 0o020)
    try:
        run_case('role-group-write-refused', refusal=True)
    finally:
        path.chmod(mode)
    path.chmod(0o400)
    try:
        run_case('nonexecutable-role-refused', refusal=True)
    finally:
        path.chmod(mode)
    # rmcp 3.9.0 counts the newline in its 16 MiB frame limit. Establish the
    # session first: a pre-initialization ping followed by EOF exits 1 in the
    # frozen original as well as HIA. Oversized lines are discarded and the
    # connection continues; they are not administrator-custody refusals.
    prefix = wire(INIT) + wire(READY)
    ping = wire(PING)
    for size in (8 << 20, (8 << 20) + 2, 16 << 20):
        run_case(f'exact-{size}-byte-line',
                 data=prefix + b' ' * (size - len(ping)) + ping,
                 response_ids=['init', 'ping'])
    oversized = wire({**PING, 'id': 'oversized'})
    run_case('over-sixteen-mib-line-discard-and-recover',
             data=prefix + b' ' * ((16 << 20) + 1 - len(oversized)) + oversized + ping,
             response_ids=['init', 'ping'])
    run_case('undelimited-eof-discarded', data=prefix + ping[:-1], response_ids=['init'])
    run_case('crlf-stream-framing', data=(prefix + ping).replace(b'\n', b'\r\n'),
             response_ids=['init', 'ping'])

    # Retain the original owner's uninitialized modern-control gates too.
    modern = {'jsonrpc': '2.0', 'id': 'ping', 'method': 'ping', 'params': {'_meta': {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientCapabilities': {}}}}
    modern_ping = wire(modern).rstrip(b'\n')
    run_case('uninitialized-exact-eight-mib-line',
             data=b' ' * ((8 << 20) - len(modern_ping)) + modern_ping + b'\n', expected_rc=1)
    run_case('uninitialized-over-eight-mib-line',
             data=b' ' * ((8 << 20) + 1) + modern_ping + b'\n', expected_rc=1)

    cfg = config_for('live')
    live_args = arguments(cfg)
    connection = Connection(live_args, env)
    try:
        connection.send(INIT)
        assert connection.read()['id'] == 'init'
        connection.send(READY)
        base_fds = descriptors(connection.process.pid)
        second = subprocess.run(live_args, input=b'', capture_output=True, timeout=15, env=env)
        assert (second.returncode, second.stdout, second.stderr) == (65, b'', b'')
        connection.send(PING)
        assert connection.read()['id'] == 'ping'
        record('lifetime-owner-excludes-second-service', second_rc=second.returncode)
        # The same queued controller lock blocks the real bridge before a job
        # can be published. Ping and cancellation must remain responsive.
        owner_path = Path(cfg['state_dir']) / 'controller.owner.lock'
        with owner_path.open('r+b') as owner:
            fcntl.lockf(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            identifier = 'pending-中'
            connection.send({'jsonrpc': '2.0', 'id': identifier, 'method': 'tools/call',
                             'params': {'name': 'hia_describe', 'arguments': {'section': 'manifest'}}})
            deadline = time.monotonic() + 10
            child = None
            while child is None and time.monotonic() < deadline:
                child = bridge_child(connection.process.pid)
                if child is None:
                    time.sleep(0.01)
            assert child is not None, 'real native bridge did not reach the owned request process'
            started = time.monotonic()
            connection.send({'jsonrpc': '2.0', 'id': 'while-pending', 'method': 'ping'})
            assert connection.read(timeout=5)['id'] == 'while-pending'
            latency = time.monotonic() - started
            notification = {'jsonrpc': '2.0', 'method': 'notifications/cancelled',
                            'params': {'requestId': identifier}}
            connection.process.stdin.write(json.dumps(notification, ensure_ascii=False).encode() + b'\n')
            connection.process.stdin.flush()
            cancelled = connection.read(timeout=5)
            assert cancelled['id'] == identifier and cancelled['error']['code'] == -32800, cancelled
            assert not list((Path(cfg['state_dir']) / 'jobs').iterdir()), 'cancelled pre-admission request published a job'
            record('pending-ping-and-cancellation', ping_seconds=latency,
                   cancelled=cancelled, bridge_pid=child)
        expected = set(range(64))
        for number in expected:
            connection.send({'jsonrpc': '2.0', 'id': number, 'method': 'tools/call',
                             'params': {'name': 'hia_describe', 'arguments': {}}})
        observed = set()
        for _ in expected:
            response = connection.read(timeout=15)
            assert response['id'] not in observed
            observed.add(response['id'])
            assert response == {'jsonrpc': '2.0', 'id': response['id'], 'error': {
                'code': -32602, 'message': 'HIA input does not match its advertised contract: '
                'arguments.section: required field is absent'}}, response
        assert observed == expected
        connection.send(PING)
        assert connection.read()['id'] == 'ping'
        assert descriptors(connection.process.pid) == base_fds
        record('concurrent-64-rejections-and-fd-release', requests=len(observed), fd_count=len(base_fds))
        connection.close()
    finally:
        if connection.process.poll() is None:
            connection.process.kill()
            connection.process.wait(timeout=10)
    assert args.service.read_bytes() == original_service
    assert args.config.read_bytes() == original_config
    assert args.manifest.read_bytes() == original_manifest
    for name, (content, mode) in saved.items():
        assert (bundle / name).read_bytes() == content
        assert (bundle / name).stat().st_mode & 0o7777 == mode
    report = {'scope': 'NATIVE_MCP_PROCESS_OWNER_CUSTODY_AND_CONCURRENCY', 'passed': True,
              'service_sha256': digest(original_service), 'count': len(records),
              'successful_job_report_not_covered_by_this_suite': True,
              'request_audit_not_covered_by_this_suite': True,
              'whole_mcp_server_qualified': False, 'cases': records}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(records), 'service_sha256': report['service_sha256']}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""One explicit Mac controller deployment; all credentials stay local.

This task helper reuses the selected runtime's HTTP client and catalog verifier.
It does not implement a gateway, worker owner, or credential transport.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
PREPARED = ROOT / 'prepared-mac-205f94e'
LIVE_CONFIG = Path('/Users/qianqi/.config/hepta-runtime-mac/runtime.json')
TOKEN = Path('/Users/qianqi/.config/hepta-runtime-mac/token')
CURRENT = Path('/Users/qianqi/.local/lib/hepta-runtime/current')
OLD_TARGET = '/Users/qianqi/.local/lib/hepta-runtime/releases/e1eb14ae8eff-macos-arm64-d7a618286d6b'
OLD_CONFIG_SHA = 'a3556d614da0123a5b252ce1da10bb3f0917233b888a3c8b4f02bb5bbb0bf1eb'
NEW_CONFIG_SHA = '2636bde8d440cd677090c0eab4db784b26e25185cecf57c4ab8e766c27c85a36'
STAGE_CONFIG_SHA = '12d41576ae3b4da439438d07f60d349416f478dfa31d173b5189aa5dc8cc6409'
PLIST = Path('/Users/qianqi/Library/LaunchAgents/org.trillionnium.hepta.runtime-controller.plist')
PLIST_SHA = '8321d54b6959647af202c61115af7a4330293f13b3d0f9f206870c366d467cfe'
LABEL = 'gui/501/org.trillionnium.hepta.runtime-controller'
CONTRACT_SHA = '5ba7036ef4d388191365da745c028c248babc52c3d00257399ff25e0380c11f9'
CATALOG_SHA = '954670433d118607f1ad55fb330a139e6d8fd998b740a9f62a41a212cc722b0e'
PINS = {
    'worker_sha256': 'cb5933bb1d08bd18b13a26e522b0d7c040db9597b49cf926874b44f9684aee6f',
    'backend_sha256': '1fd7feedfd68a0cc4f1aec1ba053d7066505817bfe2366a0ca8db1dfb7617873',
    'catalog_sha256': '8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted_bytes(path, expected=None, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        assert stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1
        assert not s.st_mode & 0o022
        if private:
            assert stat.S_IMODE(s.st_mode) == 0o600
        raw = f.read()
    if expected is not None:
        assert sha(raw) == expected, ('file identity mismatch', str(path))
    return raw


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def dump(path, value):
    write_new(path, json_bytes(value))


def launch_pid():
    p = subprocess.run(['/bin/launchctl', 'print', LABEL], capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, ('launchctl print failed', p.returncode, p.stderr)
    match = re.search(r'^\s*pid = (\d+)\s*$', p.stdout, re.M)
    assert match, 'controller pid missing'
    return int(match.group(1))


def replace_config(raw, expected):
    trusted_bytes(LIVE_CONFIG, expected, private=True)
    temp = LIVE_CONFIG.with_name('runtime.json.hia-205-' + str(os.getpid()))
    attrs = {n: os.getxattr(LIVE_CONFIG, n, follow_symlinks=False)
             for n in os.listxattr(LIVE_CONFIG, follow_symlinks=False)}
    write_new(temp, raw)
    for name, value in attrs.items():
        os.setxattr(temp, name, value, follow_symlinks=False)
    trusted_bytes(LIVE_CONFIG, expected, private=True)
    os.replace(temp, LIVE_CONFIG)
    trusted_bytes(LIVE_CONFIG, sha(raw), private=True)


def replace_current(target, expected):
    assert CURRENT.is_symlink() and os.readlink(CURRENT) == expected
    temp = CURRENT.with_name('current.hia-205-' + str(os.getpid()))
    os.symlink(target, temp)
    assert os.readlink(CURRENT) == expected
    os.replace(temp, CURRENT)
    assert os.readlink(CURRENT) == target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['probe', 'cutover'])
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--jobctl-sha256', required=True)
    parser.add_argument('--runtime-commit', required=True)
    parser.add_argument('--patch-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--shadow-report', type=Path)
    args = parser.parse_args()
    assert os.getuid() == 501
    for v in [args.binary_sha256, args.jobctl_sha256, args.patch_sha256]:
        assert re.fullmatch('[0-9a-f]{64}', v)
    assert re.fullmatch('[0-9a-f]{40}', args.runtime_commit)
    assert args.release.parent == CURRENT.parent / 'releases'
    trusted_bytes(args.release / 'hepta-runtime', args.binary_sha256)
    trusted_bytes(args.release / 'hepta-jobctl', args.jobctl_sha256)
    args.output.mkdir(mode=0o700)
    http = load_module('hia_selected_http', args.source / 'tests/runtime_http_acceptance.py')
    contracts = load_module('hia_selected_contract', args.source / 'deploy/mcp_tool_contract.py')
    contract = contracts.ToolContract.load(args.contract, CONTRACT_SHA)
    assert contract.catalog_sha256 == CATALOG_SHA
    token = trusted_bytes(TOKEN, private=True).decode().strip()
    events = args.output / 'http-events.jsonl'
    records = []

    class Client(http.Client):
        def rpc(self, method, params, notify=False):
            started = time.monotonic_ns()
            record = {'method': method, 'params': params, 'notify': notify}
            try:
                result = super().rpc(method, params, notify=notify)
                record['result'] = result
                return result
            except BaseException as e:
                record['error_type'] = type(e).__name__
                record['error'] = str(e)
                raise
            finally:
                record['elapsed_ns'] = time.monotonic_ns() - started
                records.append(record)
                with events.open('ab') as f:
                    os.chmod(events, 0o600)
                    f.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')).encode() + b'\n')
                    f.flush()
                    os.fsync(f.fileno())

    def probe(url):
        client = Client(url, token)
        tools, pages, params = [], [], {}
        for _ in range(16):
            page = client.rpc('tools/list', params)
            pages.append(page)
            tools.extend(page['tools'])
            if page.get('nextCursor') is None:
                break
            params = {'cursor': page['nextCursor']}
        else:
            raise RuntimeError('catalog pagination incomplete')
        contract.verify(tools)
        hia = sorted(t['name'] for t in tools if t['name'].startswith('hia_'))
        assert len(tools) == 113 and len(hia) == 11
        described = client.call('hia_describe', {'section': 'manifest'})
        assert described['status'] == 'completed', ('observe original HIA operation', described)
        description = described['result']
        assert description['catalog_sha256'] == PINS['catalog_sha256']
        ref = description['manifest']
        raw, cursor = bytearray(), None
        for _ in range(32):
            fields = {'catalog_sha256': PINS['catalog_sha256'], 'artifact': ref, 'max_bytes': 65536}
            if cursor is not None:
                fields['cursor'] = cursor
            response = client.call('hia_read', fields)
            assert response['status'] == 'completed', ('observe original HIA operation', response)
            page = response['result']
            assert page['artifact'] == ref
            raw.extend(page['content'].encode() if page['encoding'] == 'utf8'
                       else base64.b64decode(page['content'], validate=True))
            assert len(raw) <= 8 * 1024 * 1024
            cursor = page['next_cursor']
            if cursor is None:
                break
        else:
            raise RuntimeError('manifest pagination incomplete')
        assert sha(raw) == ref['sha256']
        manifest = json.loads(raw)
        assert manifest['schema'] == 'hepta.hia.agent.manifest.v1'
        assert {key: manifest['installation'][key] for key in PINS} == PINS
        return client, {'tool_count': len(tools), 'hia_tools': hia,
                        'whole_catalog_sha256': contract.catalog_sha256,
                        'installation': {key: manifest['installation'][key] for key in PINS},
                        'manifest_sha256': ref['sha256'], 'url': url}

    report = {'schema': 'hepta.hia.mac-controller-deployment.v1', 'mode': args.mode,
              'runtime_commit': args.runtime_commit, 'runtime_patch_sha256': args.patch_sha256,
              'binary_sha256': args.binary_sha256, 'jobctl_sha256': args.jobctl_sha256,
              'hepta_commit': '205f94ec811018f89fbf68c987c6ab8e826bb15b',
              'started_unix_ns': time.time_ns(), 'production_modified': False}
    config_changed = link_changed = False
    try:
        if args.mode == 'probe':
            trusted_bytes(PREPARED / 'runtime-staged.json', STAGE_CONFIG_SHA, private=True)
            trusted_bytes(LIVE_CONFIG, OLD_CONFIG_SHA, private=True)
            assert os.readlink(CURRENT) == OLD_TARGET
            _, report['observation'] = probe('http://127.0.0.1:8791/mcp')
        else:
            assert args.shadow_report is not None
            shadow = json.loads(trusted_bytes(args.shadow_report))
            assert shadow['status'] == 'passed' and shadow['mode'] == 'probe'
            for name in ['binary_sha256', 'jobctl_sha256', 'runtime_commit', 'runtime_patch_sha256']:
                assert shadow[name] == report[name]
            old = trusted_bytes(PREPARED / 'prior-runtime.json', OLD_CONFIG_SHA, private=True)
            new = trusted_bytes(PREPARED / 'runtime-live.json', NEW_CONFIG_SHA, private=True)
            a, b = json.loads(old), json.loads(new)
            b.pop('hia_worker')
            assert a == b, 'non-HIA runtime configuration changed'
            trusted_bytes(LIVE_CONFIG, OLD_CONFIG_SHA, private=True)
            trusted_bytes(PLIST, PLIST_SHA)
            assert CURRENT.is_symlink() and os.readlink(CURRENT) == OLD_TARGET
            before_pid = launch_pid()
            old_client = Client('http://127.0.0.1:8790/mcp', token)
            marker = args.output / 'sentinel-once.txt'
            sentinel_code = "from pathlib import Path; import time; p=Path(" + repr(str(marker)) + "); p.open('x').write('1'); print('RESTART_BEGIN',flush=True); time.sleep(20); print('ONCE_CONTENT='+p.read_text(),flush=True); print('RESTART_END',flush=True)"
            request = {'host': 'main', 'executable': sys.executable,
                       'args': ['-c', sentinel_code], 'cwd': str(args.output),
                       'idempotency_key': 'hia-controller-cutover-205-' + args.binary_sha256[:16],
                       'timeout_seconds': 90}
            started = old_client.call('process_start', request)
            sentinel_id = started['job']['id']
            assert not started.get('reused'), 'cutover sentinel key was already used'
            report['before'] = {'pid': before_pid, 'config_sha256': OLD_CONFIG_SHA,
                                'current_target': OLD_TARGET, 'sentinel_id': sentinel_id}
            dump(args.output / 'before-cutover.json', report['before'])
            replace_config(new, OLD_CONFIG_SHA)
            config_changed = True
            replace_current(str(args.release), OLD_TARGET)
            link_changed = True
            report['production_modified'] = True
            changed = subprocess.run(['/bin/launchctl', 'kickstart', '-k', LABEL], capture_output=True, text=True, timeout=40)
            report['kickstart'] = {'returncode': changed.returncode, 'stdout': changed.stdout, 'stderr': changed.stderr}
            assert changed.returncode == 0, 'controller kickstart failed'
            last_error = None
            for _ in range(60):
                try:
                    client = Client('http://127.0.0.1:8790/mcp', token)
                    break
                except (OSError, ValueError) as e:
                    last_error = str(e)
                    time.sleep(1)
            else:
                raise RuntimeError('controller did not return: ' + str(last_error))
            client, report['observation'] = probe('http://127.0.0.1:8790/mcp')
            after_pid = launch_pid()
            assert after_pid != before_pid
            mapped = subprocess.run(['/usr/sbin/lsof', '-a', '-p', str(after_pid), '-d', 'txt', '-Fn'], capture_output=True, text=True, timeout=20)
            executable = str(args.release / 'hepta-runtime')
            assert mapped.returncode == 0 and ('n' + executable) in mapped.stdout.splitlines(), 'mapped runtime identity not observed'
            again = client.call('process_start', request)
            assert again.get('reused') is True and again['job']['id'] == sentinel_id
            terminal = client.call('process_wait', {'host': 'main', 'job_id': sentinel_id, 'timeout_seconds': 30})
            assert terminal['state'] == 'succeeded', terminal
            logs = client.call('process_read', {'host': 'main', 'job_id': sentinel_id, 'limit': 16384})
            output = logs['stdout']['text']
            assert output.splitlines().count('ONCE_CONTENT=1') == 1
            assert 'RESTART_BEGIN' in output and 'RESTART_END' in output
            assert marker.read_text() == '1'
            trusted_bytes(LIVE_CONFIG, NEW_CONFIG_SHA, private=True)
            trusted_bytes(PLIST, PLIST_SHA)
            assert os.readlink(CURRENT) == str(args.release)
            trusted_bytes(args.release / 'hepta-runtime', args.binary_sha256)
            report['after'] = {'pid': after_pid, 'mapped_executable': executable,
                               'config_sha256': NEW_CONFIG_SHA, 'current_target': str(args.release),
                               'sentinel_id': sentinel_id, 'same_job_reused': True,
                               'sentinel_once': True, 'sentinel_terminal': terminal}
            report['production_deployed'] = True
        report['status'] = 'passed'
    except BaseException as e:
        report['status'] = 'failed'
        report['error_type'] = type(e).__name__
        report['error'] = str(e)
        if config_changed or link_changed:
            rollback = {}
            try:
                if link_changed:
                    replace_current(OLD_TARGET, str(args.release))
                if config_changed:
                    replace_config(trusted_bytes(PREPARED / 'prior-runtime.json', OLD_CONFIG_SHA, private=True), NEW_CONFIG_SHA)
                p = subprocess.run(['/bin/launchctl', 'kickstart', '-k', LABEL], capture_output=True, text=True, timeout=40)
                rollback = {'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr,
                            'config_restored': sha(trusted_bytes(LIVE_CONFIG, private=True)) == OLD_CONFIG_SHA,
                            'link_restored': os.readlink(CURRENT) == OLD_TARGET}
                report['production_deployed'] = False
            except BaseException as rollback_error:
                rollback = {'error_type': type(rollback_error).__name__, 'error': str(rollback_error)}
            report['rollback'] = rollback
    finally:
        report['finished_unix_ns'] = time.time_ns()
        report['event_count'] = len(records)
        if events.exists():
            report['http_events_sha256'] = sha(events.read_bytes())
        dump(args.output / 'result.json', report)
        print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

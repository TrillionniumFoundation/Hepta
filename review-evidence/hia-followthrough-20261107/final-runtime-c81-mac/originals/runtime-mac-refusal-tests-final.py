"""Observe a pinned macOS release through real MCP unsupported-write refusals."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import select
import stat
import subprocess
import time


root = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
parser = argparse.ArgumentParser()
parser.add_argument('--build-receipt', required=True)
parser.add_argument('--tag', required=True)
args = parser.parse_args()
build = json.loads((root / args.build_receipt).read_text())
assert build['passed'] and build['source_unchanged']
binary = root / 'target/release/hepta-runtime'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == build['binary_sha256']['hepta-runtime']
fixture = root / (args.tag + '-refusal-fixtures')
fixture.mkdir(mode=0o700)
test_tmp = fixture / 'tmp'
test_tmp.mkdir(mode=0o700)
assert test_tmp.resolve() == test_tmp
prior_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
assert prior_nofile[1] == resource.RLIM_INFINITY or prior_nofile[1] >= 8192
resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
os.environ['TMPDIR'] = str(test_tmp)
workspace = fixture / 'workspace'
workspace.mkdir(mode=0o700)
state = fixture / 'state'
state.mkdir(mode=0o700)
source = workspace / 'source.txt'
source.write_text('compatibility refusal original\n')
directory = workspace / 'source-directory'
directory.mkdir()
(directory / 'sentinel.txt').write_text('retain directory contents\n')
config = {
    'state_dir': str(state),
    'controller_workspace_roots': [str(workspace)],
    'hosts': {'unused-mac': {
        'ssh_target': 'localhost', 'platform': 'macos',
        'remote_state_dir': str(fixture / 'host-state'),
        'allow_execute': False, 'allow_pty': False, 'allow_write': False,
    }},
}
config_path = fixture / 'runtime.json'
config_path.write_text(json.dumps(config))
config_path.chmod(0o600)


def snapshot():
    records = []
    for path in sorted(workspace.rglob('*')):
        info = path.lstat()
        row = {'path': str(path.relative_to(workspace)),
               'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns,
               'kind': 'directory' if path.is_dir() else 'file'}
        if path.is_file():
            row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=info.st_size)
        records.append(row)
    return records


initial = snapshot()
stderr_path = fixture / 'server.stderr'
stderr = stderr_path.open('wb')
process = subprocess.Popen([str(binary), 'mcp', '--path', str(workspace),
                            '--runtime-config', str(config_path)],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=stderr, bufsize=0)
pending = b''
counter = 0


def send(message):
    process.stdin.write(json.dumps(message).encode() + b'\n')
    process.stdin.flush()


def request(method, params):
    global counter, pending
    counter += 1
    identity = counter
    send({'jsonrpc': '2.0', 'id': identity, 'method': method, 'params': params})
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        while b'\n' in pending:
            line, pending = pending.split(b'\n', 1)
            if not line.strip():
                continue
            message = json.loads(line)
            if message.get('id') == identity:
                return message
        ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        chunk = os.read(process.stdout.fileno(), 65536)
        if not chunk:
            raise RuntimeError('MCP closed stdout: ' + stderr_path.read_text(errors='replace')[-3000:])
        pending += chunk
    raise TimeoutError(method)


results = []
error = None
catalog_count = None
hia_names = []
try:
    init = request('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                   'clientInfo': {'name': 'hepta-mac-compatibility-refusal', 'version': '2.0'}})
    assert 'error' not in init, init
    send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
    catalog = request('tools/list', {})
    names = {item['name'] for item in catalog.get('result', {}).get('tools', [])}
    catalog_count = len(names)
    hia_names = sorted(name for name in names if name.startswith('hia_'))
    assert {'directory_create', 'file_move', 'directory_move', 'text_file_write'} <= names
    prior_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    cases = [
        ('directory_create', {'path': str(workspace / 'new-directory')},
         'Scoped directory creation currently requires Linux'),
        ('file_move', {'source': str(source), 'destination': str(workspace / 'moved.txt')},
         'Scoped no-replace file move currently requires Linux'),
        ('directory_move', {'source': str(directory), 'destination': str(workspace / 'moved-directory')},
         'Scoped no-replace directory move currently requires Linux'),
        ('text_file_write', {'path': str(workspace / 'new.txt'), 'mode': 'create',
         'expected_sha256': 'absent', 'content': 'must not be published'},
         'This constrained text publisher currently requires Linux'),
        ('text_file_write', {'path': str(source), 'mode': 'append',
         'expected_sha256': prior_sha, 'content': 'must not append'},
         'This constrained text publisher currently requires Linux'),
        ('text_file_write', {'path': str(source), 'mode': 'replace',
         'expected_sha256': prior_sha, 'content': 'must not replace'},
         'This constrained text publisher currently requires Linux'),
    ]
    for name, arguments, expected in cases:
        reply = request('tools/call', {'name': name, 'arguments': arguments})
        is_error = bool(reply.get('error') or reply.get('result', {}).get('isError'))
        case = {'tool': name, 'mode': arguments.get('mode'), 'refused': is_error,
                'expected_error_seen': expected in json.dumps(reply),
                'workspace_unchanged': snapshot() == initial, 'reply': reply}
        results.append(case)
        assert case['refused'] and case['expected_error_seen'] and case['workspace_unchanged'], case
except Exception as exc:
    error = type(exc).__name__ + ': ' + str(exc)
finally:
    process.stdin.close()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    stderr.close()

report = {
    'schema': 'hepta-macos-unsupported-file-api-acceptance-v2',
    'base_commit': build['base_commit'], 'patch_sha256': build['patch_sha256'],
    'published_commit': build['published_commit'], 'published_tree': build['published_tree'],
    'qualified_input_projection_sha256': build['qualified_files_sha256'],
    'binary_sha256': build['binary_sha256']['hepta-runtime'],
    'test_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'platform': platform.system(), 'machine': platform.machine(),
    'environment': {'TMPDIR': str(test_tmp), 'prior_nofile': prior_nofile,
                    'qualified_nofile': resource.getrlimit(resource.RLIMIT_NOFILE)},
    'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'catalog_tool_count': catalog_count, 'hia_catalog_names': hia_names,
    'tests': results, 'api_count': len({item['tool'] for item in results}),
    'workspace_unchanged': snapshot() == initial, 'error': error,
    'server_exit_code': process.returncode,
    'passed': error is None and len(results) == 6 and snapshot() == initial and process.returncode == 0,
}
(root / (args.tag + '-refusal-tests.json')).write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({key: value for key, value in report.items() if key != 'tests'}), flush=True)
raise SystemExit(0 if report['passed'] else 1)

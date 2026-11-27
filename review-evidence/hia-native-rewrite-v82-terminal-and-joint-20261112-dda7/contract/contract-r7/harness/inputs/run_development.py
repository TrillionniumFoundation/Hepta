"""Exact source, complete component and unchanged callers; development only."""
from pathlib import Path
from hashlib import sha256, sha1
import argparse
import base64
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import traceback
import zlib

from workflow_process import run_workflow_step

HERE = Path(__file__).resolve().parent
BASE = '65ceb711e47548f85ecf6b2ec2ae90f11dd50743'
BASE_TREE = '49a48cef565b78d0a353822026ec525789768840'
PACKET_SHA = '453be4c7be01fafa20142bd3e49da40a9c4c9d6fd80ec484fba560ac1c698354'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def identity(raw, mode):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'mode': mode,
            'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def git(root, *args):
    return subprocess.check_output(['git', '--no-replace-objects', '-C', str(root), *args])


def snapshot(root):
    rows = {}
    for path in sorted(root.rglob('*')):
        if '.git' in path.parts:
            continue
        if path.is_symlink():
            raise ValueError('unexpected source symlink: ' + str(path))
        if path.is_file():
            mode = '100755' if path.stat().st_mode & 0o111 else '100644'
            rows[path.relative_to(root).as_posix()] = identity(path.read_bytes(), mode)
    return rows


def decode_packet(raw):
    assert sha256(raw).hexdigest() == PACKET_SHA
    wrapper = json.loads(raw)
    payload = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert len(payload) == wrapper['bytes'] and sha256(payload).hexdigest() == wrapper['sha256']
    packet = json.loads(payload)
    assert packet['base_commit'] == BASE and packet['base_tree'] == BASE_TREE
    assert packet['base_count'] == 3257 and packet['final_count'] == 3272 and len(packet['files']) == 21
    assert len(packet['source_manifest']) == 3272
    for name, record in packet['files'].items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        assert name == relative.as_posix() and record['mode'] in ('100644', '100755')
        actual = identity(record['text'].encode('utf-8'), record['mode'])
        assert actual == {key: record[key] for key in actual}, name
        assert actual == packet['source_manifest'][name], name
    return packet


def prepare(base, development, evidence):
    assert git(base, 'rev-parse', 'HEAD').decode().strip() == BASE
    assert git(base, 'rev-parse', 'HEAD^{tree}').decode().strip() == BASE_TREE
    assert not git(base, 'status', '--porcelain=v1', '--untracked-files=all').strip()
    packet = decode_packet((HERE / 'SOURCE-R7.zlib.json').read_bytes())
    tracked = {}
    for record in git(base, 'ls-tree', '-r', '-z', 'HEAD').split(b'\0'):
        if not record:
            continue
        info, name = record.split(b'\t', 1)
        mode, kind, blob = info.decode().split()
        assert kind == 'blob' and mode in ('100644', '100755')
        tracked[name.decode()] = {'mode': mode, 'git_blob_sha': blob}
    before = snapshot(base)
    assert len(before) == len(tracked) == 3257 and set(before) == set(tracked)
    for name, actual in before.items():
        assert {key: actual[key] for key in tracked[name]} == tracked[name], name
        expected = packet['files'][name]['before'] if name in packet['files'] else packet['source_manifest'][name]
        assert actual == expected, name
    save(evidence / 'BASE-SOURCE.json', before)
    source = development / 'source'
    shutil.copytree(base, source, ignore=shutil.ignore_patterns('.git'))
    for name, record in packet['files'].items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        raw = record['text'].encode()
        assert identity(raw, record['mode']) == {key: record[key] for key in ('bytes', 'sha256', 'mode', 'git_blob_sha')}
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(int(record['mode'], 8) & 0o777)
    frozen = snapshot(source)
    assert frozen == packet['source_manifest']
    save(evidence / 'FROZEN-SOURCE.json', frozen)
    return source, before, frozen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--profile', choices=('native314', 'default311'), required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    assert not workspace.exists()
    workspace.mkdir()
    evidence = workspace / 'evidence'; evidence.mkdir()
    report = {'schema': 'hia.agent-contract.independent-development.v1', 'status': 'RUNNING',
        'profile': args.profile, 'python': sys.version, 'commands': [],
        'current_source_cold': False, 'whole': False, 'default_replaced': False,
        'deletion': False, 'compiler_child_limit_seconds': 20,
        'original_caller_group_limit_seconds': 1800, 'source_base': BASE}
    save(evidence / 'REPORT.json', report)
    env = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_')}
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1',
               HIA_CONTRACT_DEVELOPMENT_ROOT=str(workspace))
    source = base_before = frozen = harness_before = None
    def run(label, argv, source, seconds=1800):
        receipt = run_workflow_step(argv, cwd=source, env=env, stdout_path=evidence / (label + '.stdout'),
            stderr_path=evidence / (label + '.stderr'), receipt_path=evidence / (label + '.PROCESS.json'), seconds=seconds)
        complete = (receipt.get('status') == 'WORKFLOW_STEP_COMPLETED'
            and type(receipt.get('returncode')) is int and receipt['returncode'] == 0
            and receipt.get('timed_out') is False and receipt.get('cleanup', {}).get('complete') is True
            and receipt.get('cleanup', {}).get('errors') == [])
        report['commands'].append({'label': label, 'argv': argv, 'receipt': receipt, 'complete': complete})
        save(evidence / 'REPORT.json', report)
        assert snapshot(source) == frozen, 'source changed after ' + label
        return complete
    try:
        if args.profile == 'native314':
            assert sys.version_info[:3] == (3, 14, 4)
        else:
            assert sys.version_info[:2] == (3, 11)
        packages = {'setuptools': '78.1.1', 'wheel': '0.46.3', 'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}
        observed = {name: importlib.metadata.version(name) for name in packages}
        assert observed == packages
        report['packages'] = observed
        inputs = json.loads((HERE / 'INPUTS.json').read_bytes())
        for name, record in inputs['files'].items():
            raw = (HERE.parent / name).read_bytes()
            assert len(raw) == record['bytes'] and sha256(raw).hexdigest() == record['sha256'], name
        harness_before = {name: (HERE.parent / name).read_bytes() for name in inputs['files']}
        source, base_before, frozen = prepare(args.base.resolve(), workspace, evidence)
        if args.profile == 'default311':
            passed = run('default311', [sys.executable, '-B', str(HERE / 'run_default311.py'),
                         str(source), str(workspace / 'default311')], source, 240)
            inner_path = workspace / 'default311/REPORT.json'
            inner = json.loads(inner_path.read_bytes()) if inner_path.exists() else None
            report['default_observation'] = inner
            passed = passed and inner is not None and inner['status'] == 'PASS' and inner['count'] == 65
        else:
            compiler = json.loads((HERE / 'retained-compiler.json').read_bytes())
            binary = zlib.decompress(base64.b64decode(compiler['compiler_zlib_base64'], validate=True))
            assert len(binary) == compiler['compiler_bytes'] == 669494
            assert sha256(binary).hexdigest() == compiler['compiler_sha256'] == COMPILER_SHA
            compiler_path = workspace / 'retained-development-compiler.bin'
            compiler_path.write_bytes(binary); compiler_path.chmod(0o444)
            checks = []
            for script in ('tools/generate_hia_agent_contract.py', 'tools/generate_hia_agent_contract_foreign.py',
                           'tools/generate_hia_selfhost_contract.py'):
                checks.append(run(Path(script).stem, [sys.executable, '-B', script, '--check'], source, 240))
            controls = run('component27-plus-original-resource4', [sys.executable, '-B', str(HERE / 'run_component_group.py'),
                '--output', str(workspace / 'component'), '--compiler', str(compiler_path),
                'tests.test_hia_agent_contract_native', 'tests.test_hia_agent_contract_qualifier',
                'tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests'], source)
            component_path = workspace / 'component/REPORT.json'
            component = json.loads(component_path.read_bytes()) if component_path.exists() else None
            report['component'] = component
            controls = controls and component is not None and component['status'] == 'PASS'
            controls = controls and component['tests_run'] == 31 and component['loaded_ids'] == component['executed_ids']
            checks.append(controls)
            # A failed component remains failed; the independent unchanged
            # caller gate still records its own actual outcome and limits.
            callers = run('original55', [sys.executable, '-B', 'tools/qualify_hia_agent_contract.py',
                '--development-compiler', str(compiler_path), '--evidence', str(workspace / 'original55')], source)
            caller_path = workspace / 'original55/report.json'
            caller = json.loads(caller_path.read_bytes()) if caller_path.exists() else None
            report['callers'] = caller
            callers = callers and caller is not None and caller['status'] == 'DEVELOPMENT_CALLERS_PASS'
            checks.append(callers)
            assert compiler_path.read_bytes() == binary
            passed = all(checks)
        after = snapshot(source)
        save(evidence / 'SOURCE-AFTER.json', after)
        assert after == frozen and snapshot(args.base.resolve()) == base_before
        assert all((HERE.parent / name).read_bytes() == raw for name, raw in harness_before.items())
        report.update(status='PASS' if passed else 'FAIL', source_files=len(after),
            source_unchanged=True, base_unchanged=True, harness_unchanged=True)
    except BaseException:
        report.update(status='FAIL', exception=traceback.format_exc())
        traceback.print_exc()
    finally:
        # Preserve actual observations even when a phase raised before the
        # ordinary success readback. Failure never becomes a source authority.
        try:
            if source is not None:
                after = snapshot(source)
                save(evidence / 'SOURCE-AFTER.json', after)
                report['source_unchanged'] = after == frozen
                report['source_files'] = len(after)
                if not report['source_unchanged']:
                    report['status'] = 'FAIL'
            if base_before is not None:
                report['base_unchanged'] = snapshot(args.base.resolve()) == base_before
                if not report['base_unchanged']:
                    report['status'] = 'FAIL'
            if harness_before is not None:
                report['harness_unchanged'] = all(
                    (HERE.parent / name).read_bytes() == raw for name, raw in harness_before.items())
                if not report['harness_unchanged']:
                    report['status'] = 'FAIL'
        except BaseException:
            report.update(status='FAIL', final_guard_exception=traceback.format_exc())
        save(evidence / 'REPORT.json', report)
    print(json.dumps({key: report.get(key) for key in ('status', 'profile', 'source_files', 'source_unchanged')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

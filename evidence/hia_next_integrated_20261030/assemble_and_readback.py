"""Copy pinned, already-reviewed evidence and re-read the copied bytes as data."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT / 'hepta-integration'
HEAD = '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304'
PACKAGES = [
    ('ci', 'hia-ci-evidence-20261030', 'hia_next_ci_20261030', 'ARTIFACTS.json', '2490ef8544f7e5bbbe1ab79b09c15d0f5006a251e6491e286e54351c746103db'),
    ('resource', 'p1-p2-integrated-44e34b7-evidence', 'hia_next_resource_20261030', None, None),
    ('migration_context', 'p3-p6-integrated-44e34b7-evidence', 'hia_next_migration_context_20261030', 'DELIVERY.json', '48281c67c5220b14ef568ec443e6c65f6fd0df037f884b7a334717ece0d217e7'),
    ('stb_ndu', 'p4-evidence-staging-20261030', 'hia_next_stb_ndu_20261030', 'ARTIFACTS.json', '2b2043a9c843a585a5caa1b45ab93b23e6ce840f4271d4093af095d7b2bcda91'),
    ('agent_v12', 'p7-v12-evidence-staging-20261030', 'hia_next_agent_v12_20261030', 'DELIVERY_INDEX.json', 'b10891a1eb7ac3c9bdd1accbf180ab3923059911cda4db83267a795db994bd07'),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')


def main():
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO).decode().strip() != HEAD:
        raise ValueError('source base changed before assembly')
    out = HERE / 'root-readback'
    out.mkdir(exist_ok=False)
    inventory = []
    locations = {}
    for key, source_name, dest_name, index_name, index_sha in PACKAGES:
        source = ROOT / source_name
        destination = REPO / 'evidence' / dest_name
        if destination.exists():
            raise ValueError('refuse to overwrite an evidence package')
        if index_name:
            index_data = (source / index_name).read_bytes()
            if sha(index_data) != index_sha:
                raise ValueError('frozen delivery index differs: ' + key)
            entries = json.loads(index_data)['files']
            if isinstance(entries, list):
                entries = {row['path']: row for row in entries}
            entries = dict(entries)
            entries[index_name] = {'bytes': len(index_data), 'sha256': index_sha}
        else:
            entries = {}
            for path in sorted(source.iterdir()):
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError('unexpected resource package member')
                data = path.read_bytes()
                entries[path.name] = {'bytes': len(data), 'sha256': sha(data)}
            expected = {
                'execution.tar.xz': '7d2da6ca38890037197a291fcf9a3e34404abb34e763b6180e0c392d70108d55',
                'MANIFEST.json': 'da47d43f390aef624fe93bbf1a927a7d5cfa5b9236fd6e6fb001460b2ff6aedf',
                'verify.py': 'c53c99702942053f82b5b5199aca0f7088bbdd58faecd795ad98c09f4854eb5f',
                'VERIFICATION.json': '98b75f764e437e8fb3db7fd162b628cfbd13aa575c9778d2d9a88d1cae5d9681',
            }
            for name, value in expected.items():
                if entries[name]['sha256'] != value:
                    raise ValueError('resource pin differs: ' + name)
        validated = []
        for name, expected in sorted(entries.items()):
            rel = Path(name)
            if rel.is_absolute() or '..' in rel.parts:
                raise ValueError('unsafe delivery path')
            path = source / rel
            if any(parent.is_symlink() for parent in [path, *path.parents] if parent != ROOT.parent):
                raise ValueError('symlink delivery path')
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('nonregular delivery file')
            data = path.read_bytes()
            if len(data) != expected['bytes'] or sha(data) != expected['sha256']:
                raise ValueError('delivery member differs: ' + name)
            validated.append((rel, data, expected))
        destination.mkdir()
        for rel, data, expected in validated:
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as output:
                output.write(data)
            if sha(target.read_bytes()) != expected['sha256']:
                raise ValueError('copied member differs')
            inventory.append({'package': key, 'path': target.relative_to(REPO).as_posix(),
                              'bytes': len(data), 'sha256': expected['sha256']})
        locations[key] = destination
    write_json(out / 'COPIED_FILES.json', {'schema': 'hepta.next.copied-files.v1',
        'source_commit': HEAD, 'files': inventory,
        'total_bytes': sum(row['bytes'] for row in inventory), 'file_count': len(inventory),
        'copied_frozen_indices_exactly': True})

    commands = []
    p = locations['ci']
    commands.append(('ci', p / 'verify_ci.py', ['--root', str(p), '--pins', 'CI_PINS.json',
        '--pins-sha256', '1095dc2596424c76bab4fc99cda4bcee50c70f0c415a7e54bf23327cf28b1a5e',
        '--manifest', 'MANIFEST.json', '--manifest-sha256', '1ee9fea8cffc424cfcd3e12a3a4416682ddbfb5ad1d6ac246eb007113dfe3069',
        '--output', str(out / 'ci-verification.json')]))
    p = locations['resource']
    commands.append(('resource', p / 'verify.py', [str(p)]))
    p = locations['migration_context']
    commands.append(('migration_context', p / 'verify_evidence.py', ['--directory', str(p), '--output', str(out / 'migration-context-verification.json')]))
    p = locations['stb_ndu']
    commands.append(('stb_ndu', p / 'verify_evidence.py', ['--archive', str(p / 'hia-stb-ndu-20261030.tar.xz'),
        '--manifest', str(p / 'hia-stb-ndu-20261030.manifest.json'), '--output', str(out / 'stb-ndu-verification.json')]))
    p = locations['agent_v12']
    commands.append(('agent_v12', p / 'verify_evidence.py', ['--archive', str(p / 'p7-v12-20261030.tar.xz'),
        '--manifest', str(p / 'p7-v12-20261030.manifest.json'),
        '--archive-sha256', '537e0a9da3d220fc1b745756c12031a4d4a171dc52848cd80661dfcd81025a0d',
        '--manifest-sha256', '2ee83396b3427254461ed5037e8693644315d3c21bc6a08af59bb42346946d2c',
        '--output', str(out / 'agent-v12-verification.json')]))
    receipts = []
    for name, verifier, args in commands:
        argv = [sys.executable, '-B', str(verifier), *args]
        started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start = time.monotonic_ns()
        result = subprocess.run(argv, cwd=REPO, capture_output=True, timeout=60)
        elapsed = time.monotonic_ns() - start
        for stream, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
            (out / (name + '.' + stream)).write_bytes(data)
        receipt = {'package': name, 'argv': argv, 'cwd': str(REPO), 'started_utc': started_utc,
            'returncode': result.returncode, 'wall_ns': elapsed,
            'verifier_sha256': sha(verifier.read_bytes()),
            'stdout_bytes': len(result.stdout), 'stdout_sha256': sha(result.stdout),
            'stderr_bytes': len(result.stderr), 'stderr_sha256': sha(result.stderr),
            'archive_payload_executed': False, 'new_native_or_model_execution': False}
        write_json(out / (name + '-execution.json'), receipt)
        receipts.append(receipt)
    passed = all(row['returncode'] == 0 and row['stderr_bytes'] == 0 for row in receipts)
    write_json(out / 'RESULT.json', {'schema': 'hepta.next.root-readback.v1', 'passed': passed,
        'source_commit': HEAD, 'executions': receipts, 'package_count': len(receipts),
        'actual_new_model_generations': 0, 'actual_new_native_test_cases': 0,
        'copied_bytes': sum(row['bytes'] for row in inventory),
        'cost_scope': 'pure offline subprocess readbacks, separate from application/experiment timing',
        'wall_ns_total_sequential_children': sum(row['wall_ns'] for row in receipts)})
    print(json.dumps({'passed': passed, 'copied_files': len(inventory),
        'copied_bytes': sum(row['bytes'] for row in inventory),
        'executions': [{k: row[k] for k in ['package', 'returncode', 'wall_ns', 'stderr_bytes']} for row in receipts]}))
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()

"""Materialize a source subset from exact c7aa objects, never shared leaves."""
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
REPOSITORY = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
OVERLAY = Path('/workspace/scratch/e26ed3e2edcf/core-numeric-v88-merge-handoff-r1')


def digest(raw):
    return dict(size=len(raw), sha256=sha256(raw).hexdigest(),
                git_blob_sha1=sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def main():
    source = HERE / 'source'
    source.mkdir(mode=0o700, exist_ok=False)
    base = json.loads((HERE / 'BASE-GIT-TREE.json').read_bytes())
    contract = subprocess.check_output(['git', 'cat-file', 'blob', base['tree'] + ':tools/hia_selfhost_contract.py'], cwd=REPOSITORY)
    tree = ast.parse(contract)
    declaration = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                       and any(isinstance(a, ast.Name) and a.id == 'SOURCE_FILES' for a in n.targets))
    declared = {n.value for n in ast.walk(declaration) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    declared.update(('setup.py', 'MANIFEST.in', 'pyproject.toml', 'README.md'))
    chosen = [row for row in base['leaves'] if row['path'] in declared or
              row['path'].startswith(('hepta/', 'tools/', 'tests/', 'examples/hia_bootstrap/', 'docs/'))]
    report = dict(schema='hepta.hia.numeric-v88-source-population.v1', status='HOLD',
                  base_commit=base['commit'], base_tree=base['tree'], full_base_leaves=len(base['leaves']),
                  no_full_checkout=True, shared_worktree_leaves_read_or_modified=False,
                  source=str(source), files=[], overlay=[])
    process = subprocess.Popen(['git', 'cat-file', '--batch'], cwd=REPOSITORY,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for row in chosen:
            assert row['mode'] in ('100644', '100755') and row['type'] == 'blob'
            process.stdin.write((row['sha'] + '\n').encode()); process.stdin.flush()
            header = process.stdout.readline().decode().rstrip('\n').split(' ')
            assert header == [row['sha'], 'blob', str(row['size'])], row['path']
            raw = process.stdout.read(row['size']); assert process.stdout.read(1) == b'\n'
            actual = digest(raw)
            assert actual['size'] == row['size'] and actual['git_blob_sha1'] == row['sha']
            destination = source / row['path']; destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as stream: stream.write(raw)
            destination.chmod(int(row['mode'][-3:], 8))
            assert destination.read_bytes() == raw
            report['files'].append(dict(path=row['path'], mode=row['mode'], **actual))
        process.stdin.close()
        assert process.wait(timeout=20) == 0
        assert process.stderr.read() == b''
        for row in json.loads((OVERLAY / 'MERGE-MANIFEST.json').read_bytes())['delta']:
            path = source / row['path']; original = row['before']
            if original is None:
                assert not path.exists()
            else:
                assert digest(path.read_bytes()) == original
            raw = (OVERLAY / 'product' / row['path']).read_bytes()
            assert digest(raw) == row['after']
            path.parent.mkdir(parents=True, exist_ok=True)
            if original is None:
                with path.open('xb') as stream: stream.write(raw)
            else:
                path.write_bytes(raw)
            path.chmod(0o644)
            report['overlay'].append(row)
        report['status'] = 'EXACT_PARTIAL_SOURCE_POPULATION_AND_13_OVERLAY'
    finally:
        if process.poll() is None:
            if not process.stdin.closed: process.stdin.close()
            process.wait(timeout=20)
        report['copied_base_bytes'] = sum(row['size'] for row in report['files'])
        with (HERE / 'BASE-POPULATION.json').open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps({key: report[key] for key in ('status', 'copied_base_bytes', 'full_base_leaves', 'no_full_checkout')}))


if __name__ == '__main__':
    main()

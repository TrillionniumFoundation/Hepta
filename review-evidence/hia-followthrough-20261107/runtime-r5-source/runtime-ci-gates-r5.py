"""Pinned, durable runtime qualification; runs only in an owned candidate tree."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--cargo', required=True)
parser.add_argument('--cargo-home', required=True)
parser.add_argument('--manifest', required=True)
parser.add_argument('--patch', required=True)
parser.add_argument('--tag', required=True)
parser.add_argument('--tmp-dir', type=Path, required=True)
parser.add_argument('--expected-targets', required=True)
parser.add_argument('--expected-projection', required=True)
parser.add_argument('--delta-patch')
parser.add_argument('--previous-receipt')
parser.add_argument('--apply-base-patch', action='store_true')
parser.add_argument('--release', action='store_true')
parser.add_argument('--tool-bin', action='append', required=True)
args = parser.parse_args()
root = args.root.resolve(strict=True)
source = root / 'source'
manifest_path = root / args.manifest
manifest = json.loads(manifest_path.read_text())
patch = root / args.patch
assert sha(patch) == manifest['combined_patch_sha256']
if args.previous_receipt:
    prior = json.loads((root / args.previous_receipt).read_text())
    assert prior.get('completed_utc') and prior['source_unchanged'], prior
if args.delta_patch or args.apply_base_patch:
    key = 'before' if args.apply_base_patch else 'previous'
    for name, record in manifest['files'].items():
        assert ((not (source / name).exists()) if record[key] is None else sha(source / name) == record[key]), name
    applied_patch = patch if args.apply_base_patch else root / args.delta_patch
    expected_patch = manifest['combined_patch_sha256'] if args.apply_base_patch else manifest['delta_patch_sha256']
    assert sha(applied_patch) == expected_patch
    subprocess.run(['/usr/bin/git', 'apply', '--check', str(applied_patch)], cwd=source, check=True)
    subprocess.run(['/usr/bin/git', 'apply', str(applied_patch)], cwd=source, check=True)
for name, record in manifest['files'].items():
    assert sha(source / name) == record['after'], name


def snapshot():
    return {str(path.relative_to(source)): sha(path) for path in sorted(source.rglob('*'))
            if path.is_file() and '.git' not in path.relative_to(source).parts}


frozen = snapshot()
expected_projection_path = root / args.expected_projection
expected_projection = json.loads(expected_projection_path.read_text())
missing = sorted(set(expected_projection) - set(frozen))
extra = sorted(set(frozen) - set(expected_projection))
changed = sorted(name for name in set(frozen) & set(expected_projection)
                 if frozen[name] != expected_projection[name])
assert not (missing or extra or changed), {'missing': missing, 'extra': extra, 'changed': changed}
target_inventory_path = root / args.expected_targets
expected_targets = json.loads(target_inventory_path.read_text())
assert expected_targets['base_commit'] == manifest['base_commit']
assert expected_targets['combined_patch_sha256'] == manifest['combined_patch_sha256']
snapshot_path = root / (args.tag + '-source-files.json')
assert not snapshot_path.exists()
snapshot_path.write_text(json.dumps(frozen, indent=2, sort_keys=True) + '\n')
report_path = root / (args.tag + '-gates.json')
assert not report_path.exists()
test_tmp = args.tmp_dir
assert test_tmp.is_absolute() and len(str(test_tmp).encode()) <= 32
test_tmp.mkdir(mode=0o700)
assert test_tmp.resolve() == test_tmp
assert test_tmp.stat().st_uid == os.getuid() and test_tmp.stat().st_mode & 0o777 == 0o700
prior_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
assert prior_nofile[1] == resource.RLIM_INFINITY or prior_nofile[1] >= 8192
resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
os.umask(0o022)
env = os.environ.copy()
env.update(CARGO_HOME=args.cargo_home, CARGO_TARGET_DIR=str(root / 'target'),
           CARGO_BUILD_JOBS='4', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
           TMPDIR=str(test_tmp),
           PATH=':'.join(args.tool_bin + [str(Path(args.cargo).parent), env.get('PATH', '/usr/bin:/bin')]))
nextest_path = Path(shutil.which('cargo-nextest', path=env['PATH']))
nextest_version = subprocess.check_output([str(nextest_path), '--version'], text=True)
assert nextest_version.splitlines()[0].split()[1] == '0.9.137', nextest_version
rg_path = Path(shutil.which('rg', path=env['PATH']))
rg_version = subprocess.check_output([str(rg_path), '--version'], text=True)
report = {'schema': 'hepta-runtime-pinned-ci-platform-gates-v6',
          'base_commit': manifest['base_commit'],
          'published_commit': expected_targets['published_commit'],
          'published_tree': expected_targets['published_tree'],
          'patch_sha256': manifest['combined_patch_sha256'],
          'source_manifest_sha256': sha(manifest_path),
          'qualified_files_sha256': sha(snapshot_path),
          'qualified_file_count': len(frozen), 'platform': platform.system(),
          'input_scope': 'pinned 958 build inputs plus exact compatibility ledger; not the complete repository byte tree',
          'input_exclusions': ['historical docs/qualification artifacts', 'historical tests/evidence archives',
                               'other non-build repository files outside the retained source projection'],
          'expected_projection_sha256': sha(expected_projection_path),
          'expected_target_inventory_sha256': sha(target_inventory_path),
          'runner_sha256': sha(Path(__file__)),
          'machine': platform.machine(), 'started_utc': utc(), 'stages': [],
          'environment': {'TMPDIR': str(test_tmp), 'umask': '022', 'prior_nofile': prior_nofile,
                          'qualified_nofile': resource.getrlimit(resource.RLIMIT_NOFILE)},
          'nextest': {'path': str(nextest_path), 'sha256': sha(nextest_path), 'version': nextest_version},
          'ripgrep': {'path': str(rg_path), 'sha256': sha(rg_path), 'version': rg_version}}


def save():
    report_path.write_text(json.dumps(report, indent=2) + '\n')


cargo = [args.cargo, '+1.95.0']
save()
report['cargo_target_inventory'] = []
for mode, feature in [('all-features', '--all-features'), ('no-default', '--no-default-features')]:
    metadata_path = root / (args.tag + '-metadata-' + mode + '.json')
    metadata_log = root / (args.tag + '-metadata-' + mode + '.stderr')
    assert not metadata_path.exists() and not metadata_log.exists()
    command = cargo + ['metadata', '--offline', '--locked', '--no-deps', '--format-version', '1', feature]
    with metadata_path.open('wb') as output, metadata_log.open('wb') as errors:
        result = subprocess.run(command, cwd=source, env=env, stdout=output, stderr=errors)
    assert result.returncode == 0, (command, result.returncode, str(metadata_log))
    metadata = json.loads(metadata_path.read_text())
    packages = [item for item in metadata['packages'] if Path(item['manifest_path']).resolve() == source / 'Cargo.toml']
    assert len(packages) == 1, packages
    targets = []
    for target in packages[0]['targets']:
        relative = str(Path(target['src_path']).relative_to(source))
        targets.append({'source': relative, 'name': target['name'], 'kind': target['kind'],
                        'required_features': target.get('required-features', []),
                        'sha256': sha(source / relative), 'bytes': (source / relative).stat().st_size})
    actual_targets = {item['source']: {'sha256': item['sha256'], 'bytes': item['bytes']} for item in targets}
    assert len(targets) == len(actual_targets), 'duplicate target source paths must be reviewed'
    assert actual_targets == expected_targets['target_source_files'], {'actual': actual_targets, 'expected': expected_targets['target_source_files']}
    report['cargo_target_inventory'].append({'feature_mode': mode, 'argv': command, 'exit_code': result.returncode,
        'metadata_path': str(metadata_path), 'metadata_sha256': sha(metadata_path), 'stderr_sha256': sha(metadata_log),
        'target_count': len(targets), 'matches_complete_pinned_target_source_inventory': True, 'targets': targets})
    save()
    print(json.dumps({'metadata': mode, 'target_count': len(targets), 'matched': True}), flush=True)
commands = [
    ('fmt', ['fmt', '--all', '--', '--check']),
    ('check-all-features', ['check', '--offline', '--locked', '--all-targets', '--all-features', '-j', '4']),
    ('check-no-default', ['check', '--offline', '--locked', '--all-targets', '--no-default-features', '-j', '4']),
    ('clippy-all-features', ['clippy', '--offline', '--locked', '--all-targets', '--all-features', '-j', '4', '--', '-D', 'warnings']),
    ('clippy-no-default', ['clippy', '--offline', '--locked', '--all-targets', '--no-default-features', '-j', '4', '--', '-D', 'warnings']),
    ('nextest-all-features', ['nextest', 'run', '--offline', '--locked', '--all-targets', '--all-features', '--test-threads', '1', '--retries', '0', '--no-fail-fast']),
    ('nextest-no-default', ['nextest', 'run', '--offline', '--locked', '--all-targets', '--no-default-features', '--test-threads', '1', '--retries', '0', '--no-fail-fast']),
]
if args.release:
    commands.append(('release', ['build', '--offline', '--locked', '--release', '--all-features', '--bins', '--examples', '-j', '4']))
for name, command in commands:
    log = root / (args.tag + '-' + name + '.log')
    assert not log.exists()
    stage = {'name': name, 'argv': cargo + command, 'status': 'running',
             'started_utc': utc(), 'log': str(log)}
    report['stages'].append(stage)
    save()
    print(json.dumps(stage), flush=True)
    started = time.monotonic()
    with log.open('wb') as output:
        result = subprocess.run(stage['argv'], cwd=source, env=env, stdout=output, stderr=subprocess.STDOUT)
    stage.update(status='completed', exit_code=result.returncode,
                 elapsed_seconds=time.monotonic() - started, log_sha256=sha(log),
                 log_bytes=log.stat().st_size)
    save()
    print(json.dumps(stage), flush=True)
    lines = log.read_text(errors='replace').splitlines()
    print('\n'.join(line for line in lines if line.startswith(('test result:', 'error:', 'error[', 'failures:', '    Finished')) or 'Summary [' in line or ' FAIL ' in line), flush=True)
report['source_unchanged'] = snapshot() == frozen
report['passed'] = report['source_unchanged'] and all(stage['exit_code'] == 0 for stage in report['stages'])
if args.release:
    report['binary_sha256'] = {name: sha(root / 'target/release' / name)
                               for name in ['hepta-runtime', 'hepta-runtime-jobctl']
                               if (root / 'target/release' / name).is_file()}
report['completed_utc'] = utc()
save()
print(json.dumps(report), flush=True)
raise SystemExit(0 if report['passed'] else 1)

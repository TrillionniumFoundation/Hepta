"""Observe exact published budget cases without granting qualification."""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import traceback
import zipfile
import zlib

INPUTS = Path(__file__).resolve().parent
SOURCE_COMMIT = '4925e72d9f51f4dc3e8f4d1d2a7b24cce2f5772b'
SOURCE_TREE = 'bc276bc832a7d6f04a21d63f55645859b75a01ee'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
IMAGE_SHA = '458f8202af7c5effc8f502d1626a8ac1a3608cabf7bfa7c8371c231ad6a7a466'
HIA_SOURCE_SHA = '80cc97e3d38301a3cb03e2cef51536fb1f67ccf835ba71f89f88073e97c79611'
SUPERVISOR_SHA = 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80'
METHODS = {
    'expired': 'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner',
    'loop': 'test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline',
    'timeout': 'test_native_timeout_is_incomplete_terminated_and_not_adoptable',
}

def require(value, message):
    if not value:
        raise ValueError(message)

def raw_identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def read(path):
    return json.loads(path.read_bytes())

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write((json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                                allow_nan=False) + '\n').encode())

def snapshot(source):
    rows = {}
    for path in sorted(source.rglob('*')):
        if '.git' in path.parts or '__pycache__' in path.parts:
            continue
        if path.is_dir():
            continue
        require(not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode),
                'source is not a regular tracked byte object')
        mode = '100755' if path.stat().st_mode & 0o111 else '100644'
        rows[path.relative_to(source).as_posix()] = dict(mode=mode, **raw_identity(path.read_bytes()))
    return rows

def tree_id(rows):
    root = {}
    for name, row in rows.items():
        parts = name.split('/')
        cursor = root
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        require(parts[-1] not in cursor, 'source tree path collision')
        cursor[parts[-1]] = row
    def digest(directory):
        records = []
        for name, child in directory.items():
            if 'blob' in child:
                mode, blob, sort_name = child['mode'], child['blob'], name
            else:
                mode, blob, sort_name = '40000', digest(child), name + '/'
            records.append((sort_name.encode(), mode.encode() + b' ' + name.encode()
                            + b'\0' + bytes.fromhex(blob)))
        data = b''.join(value for _, value in sorted(records))
        return hashlib.sha1(b'tree ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    return digest(root)

def git(source, *arguments):
    result = subprocess.run(['git', '-C', str(source), *arguments],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                            timeout=30)
    return result.stdout

def harness_inputs():
    return {p.relative_to(INPUTS.parent).as_posix(): raw_identity(p.read_bytes())
            for p in sorted(INPUTS.parent.rglob('*')) if p.is_file()
            and '.git' not in p.parts and '__pycache__' not in p.parts}

def environment():
    values = {name: value for name, value in os.environ.items() if not name.startswith('HEPTA_')}
    values.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return values

def command(source, output, label, arguments):
    path = INPUTS / 'workflow_process.py'
    require(raw_identity(path.read_bytes())['sha256'] == SUPERVISOR_SHA,
            'original supervisor bytes differ')
    spec = importlib.util.spec_from_file_location('retained_workflow_process', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    folder = output / 'commands' / label
    folder.mkdir(parents=True, exist_ok=False)
    result = module.run_workflow_step(arguments, cwd=source, env=environment(),
        stdout_path=folder / 'stdout', stderr_path=folder / 'stderr',
        receipt_path=folder / 'terminal.json', seconds=1800)
    print(json.dumps({'label': label, 'status': result['status'],
                      'returncode': result['returncode'], 'seconds': result['seconds']}), flush=True)
    return result

def prepare(source, output):
    require(not output.exists(), 'diagnostic output already exists')
    output.mkdir(parents=True, mode=0o700)
    require(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 14, 4),
            'actual CPython 3.14.4 required')
    require(git(source, 'rev-parse', 'HEAD').decode().strip() == SOURCE_COMMIT,
            'authentic checkout HEAD differs')
    require(git(source, 'rev-parse', 'HEAD^{tree}').decode().strip() == SOURCE_TREE,
            'authentic checkout tree differs')
    rows = snapshot(source)
    require(len(rows) == 3324 and tree_id(rows) == SOURCE_TREE,
            'complete actual checkout bytes differ from the published 3324-file tree')
    tracked = {}
    for record in git(source, 'ls-files', '--stage', '-z').split(b'\0'):
        if not record:
            continue
        first, path = record.split(b'\t', 1)
        mode, blob, stage = first.decode().split()
        require(stage == '0', 'checkout index contains an unmerged stage')
        tracked[path.decode()] = (mode, blob)
    require(tracked == {name: (row['mode'], row['blob']) for name, row in rows.items()},
            'actual Git tracked modes and blobs differ from physical bytes')
    write(output / 'GENERATED-SOURCE.json', rows)
    write(output / 'SOURCE-ADMISSION.json', {
        'actual_head': SOURCE_COMMIT, 'actual_tree': SOURCE_TREE, 'files': 3324,
        'complete_git_mode_blob_bytes_verified': True, 'source_modified': False,
        'source_generation_reexecuted': False,
        'source_is_external_immutable_git_input': True,
        'scope': 'EXACT_EXISTING_SOURCE_FOR_NEW_DIAGNOSTIC_NOT_NEW_QUALIFICATION'})
    write(output / 'HARNESS-INPUTS.json', harness_inputs())
    packed = read(INPUTS / 'retained-compiler.json')
    compressed = base64.b64decode(packed['compiler_zlib_base64'], validate=True)
    require(len(compressed) == packed['compressed_bytes']
            and hashlib.sha256(compressed).hexdigest() == packed['compressed_sha256'],
            'retained compiler transport differs')
    compiler = zlib.decompress(compressed)
    require(len(compiler) == 669494 == packed['compiler_bytes']
            and hashlib.sha256(compiler).hexdigest() == COMPILER_SHA == packed['compiler_sha256'],
            'retained development compiler differs')
    (output / 'retained-development-compiler.bin').write_bytes(compiler)
    (output / 'retained-original-compiler-receipt.json').write_text(packed['original_receipt_utf8'])
    write(output / 'ENVIRONMENT.json', {'python': sys.version,
        'platform': platform.platform(), 'machine': platform.machine(),
        'pid': os.getpid(), 'actual_source_head': SOURCE_COMMIT,
        'current_cold': False, 'compiler_scope': packed['scope'],
        'original_compiler_limit_seconds': 20, 'ordinary_step_limit_seconds': 1800})
    return True

def build(source, output):
    before = read(output / 'GENERATED-SOURCE.json')
    require(snapshot(source) == before, 'source changed before diagnostic build')
    result = command(source, output, 'build-evaluation',
        [sys.executable, '-B', 'tools/build_hia_service_evaluation.py',
         '--compiler', str(output / 'retained-development-compiler.bin'),
         '--output', str(output / 'candidate'), '--development'])
    require(result['returncode'] == 0 and not result['timed_out'],
            'diagnostic development build did not complete')
    manifest = read(output / 'candidate/development-manifest.json')
    image = output / 'candidate' / manifest['image_path']
    require(manifest['image_sha256'] == IMAGE_SHA
            and hashlib.sha256(image.read_bytes()).hexdigest() == IMAGE_SHA,
            'new image differs from the same-source original 43341104136 image')
    require(manifest['source_sha256'] == HIA_SOURCE_SHA
            and manifest['compiler_sha256'] == COMPILER_SHA,
            'same-source image input custody differs')
    require(snapshot(source) == before, 'source changed during diagnostic build')
    write(output / 'BUILD-IDENTITY.json', {'actual_image': raw_identity(image.read_bytes()),
        'matches_prior_same_source_image_sha256': IMAGE_SHA,
        'manifest': raw_identity((output / 'candidate/development-manifest.json').read_bytes()),
        'source_unchanged': True, 'original_compile_seconds': 20, 'current_cold': False})
    return True

def case(source, output, name):
    require((output / 'BUILD-IDENTITY.json').is_file(), 'exact diagnostic build is unavailable')
    result = command(source, output, 'profile-' + name,
        [sys.executable, '-I', '-B', str(INPUTS / 'run_profile_case.py'),
         '--source', str(source), '--compiler', str(output / 'retained-development-compiler.bin'),
         '--evaluation-manifest', str(output / 'candidate/development-manifest.json'),
         '--output', str(output / ('profile-' + name)), '--group', 'namespace',
         '--method', METHODS[name]])
    path = output / ('profile-' + name) / 'REPORT.json'
    costs = output / ('profile-' + name) / 'COST-REPORT.json'
    report = read(path) if path.is_file() else None
    observed = read(costs) if costs.is_file() else None
    return (result['returncode'] == 0 and not result['timed_out']
            and report is not None and report['status'] == 'OBSERVATION_COMPLETE'
            and report['tests_run'] == 1
            and report['loaded_ids'] == report['executed_ids']
            and report['source_unchanged'] and report['input_bytes_unchanged']
            and report['mapped_images_unchanged']
            and observed is not None and observed['observer_exit_error'] is None)

def finish(source, output):
    output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'hia.same-source-evaluation-section-diagnostic.v1',
        'scope': 'INSTRUMENTED_DIAGNOSTIC_NOT_QUALIFICATION', 'status': 'HOLD',
        'source_commit': SOURCE_COMMIT, 'expected_tree': SOURCE_TREE,
        'python': sys.version, 'prior_original_run': 43341104136,
        'original_budget_or_observer_changed': False,
        'native_timing_sample_every': 64,
        'sample_durations_are_not_exact_uninstrumented_totals': True,
        'full_original_namespace35_or_ledger48_qualified': False,
        'old_failures_reclassified': False, 'current_cold': False, 'whole_native': False}
    try:
        after = snapshot(source)
        write(output / 'SOURCE-AFTER.json', after)
        before = read(output / 'GENERATED-SOURCE.json')
        changed = [p for p in sorted(before.keys() | after.keys()) if before.get(p) != after.get(p)]
        report.update(source_files=len(after), actual_tree=tree_id(after),
            source_unchanged=not changed, changed_source_paths=changed,
            authentic_head_unchanged=git(source, 'rev-parse', 'HEAD').decode().strip() == SOURCE_COMMIT,
            harness_inputs_unchanged=harness_inputs() == read(output / 'HARNESS-INPUTS.json'),
            retained_compiler_unchanged=hashlib.sha256((output / 'retained-development-compiler.bin').read_bytes()).hexdigest() == COMPILER_SHA)
        for name in changed:
            if name in after:
                target = output / 'changed-source-originals' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source / name, target)
        cases = {}
        for name in METHODS:
            folder = output / ('profile-' + name)
            cases[name] = {'original_case': read(folder / 'REPORT.json') if (folder / 'REPORT.json').exists() else None,
                'costs': read(folder / 'COST-REPORT.json') if (folder / 'COST-REPORT.json').exists() else None,
                'stage': read(output / ('STAGE-' + name + '.json')) if (output / ('STAGE-' + name + '.json')).exists() else None}
        report['cases'] = cases
        report['original_method_outcomes'] = {name: item['original_case'].get('outcome') if item['original_case'] else 'NOT_EXECUTED'
                                               for name, item in cases.items()}
        if (all(item['stage'] is not None and item['stage']['status'] == 'OBSERVATION_STAGE_COMPLETED'
                for item in cases.values()) and report['source_unchanged']
                and report['authentic_head_unchanged'] and report['harness_inputs_unchanged']
                and report['retained_compiler_unchanged']):
            report['status'] = 'OBSERVATIONS_COMPLETE'
    except BaseException:
        report['traceback'] = traceback.format_exc()
    write(output / 'REPORT.json', report)
    paths = [p for p in sorted(output.rglob('*')) if p.is_file()]
    manifest = {p.relative_to(output).as_posix(): dict(local_mode=oct(p.stat().st_mode & 0o7777),
                 **raw_identity(p.read_bytes())) for p in paths}
    write(output / 'EVIDENCE-MANIFEST.json', manifest)
    with zipfile.ZipFile(output / 'RAW-EVIDENCE.zip', 'x', compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as archive:
        for name in list(manifest) + ['EVIDENCE-MANIFEST.json']:
            archive.write(output / name, name)
    with zipfile.ZipFile(output / 'RAW-EVIDENCE.zip') as archive:
        require(archive.testzip() is None, 'completed diagnostic archive CRC differs')
    print(json.dumps({k: report.get(k) for k in ('status', 'original_method_outcomes', 'source_unchanged')}), flush=True)
    return report['status'] == 'OBSERVATIONS_COMPLETE'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--stage', choices=('prepare', 'build', *METHODS, 'finish'), required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    ok, error = False, None
    try:
        if args.stage == 'finish':
            return 0 if finish(source, output) else 1
        if args.stage == 'prepare':
            ok = prepare(source, output)
        elif args.stage == 'build':
            ok = build(source, output)
        else:
            ok = case(source, output, args.stage)
    except BaseException:
        error = traceback.format_exc()
        print(error, flush=True)
    if output.is_dir():
        write(output / ('STAGE-' + args.stage + '.json'), {'stage': args.stage,
            'status': 'OBSERVATION_STAGE_COMPLETED' if ok else 'HOLD',
            'traceback': error, 'performance_qualification': False})
    return 0 if ok else 1

if __name__ == '__main__':
    raise SystemExit(main())

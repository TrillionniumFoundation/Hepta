"""Validate new HIA JSON layout source and execute its actual native development image.

The full immutable source-closure-repair input tree is bound before and after the 180/3 owned
operation. B0/B1/B2 here are explicit new development builds, never inherited
cold qualification. Exact 43 new component cases do not replace CLI callers.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import ast
from hashlib import sha1, sha256
import importlib
import json
import os
from pathlib import Path
import re
import stat
import shutil
import subprocess
import sys
import time
import traceback

CANDIDATE = '9704596acc4470bd0042838586602e26bac7b3d1'
CANDIDATE_TREE = 'c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b'
CANDIDATE_COUNT = 4023
GIT_EXECUTABLE = None
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
CONTRACT_SHA = '29f113e1aef4fb2a72e2081b3608e47c094cd4972594d5e082716cebc8a293a2'
LIMITS = {'source_bytes': 1048576, 'functions': 128, 'blocks_total': 1536,
          'blocks_per_function': 256, 'instructions': 8192,
          'ssa_names_per_function': 2048, 'parameters_or_arguments': 16}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def digest(raw):
    return sha256(raw).hexdigest()

def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

@contextmanager
def _checked_parent(path):
    """Retain the complete absolute directory chain without following symlinks."""
    path = Path(path)
    require(path.is_absolute() and path.anchor == '/' and '..' not in path.parts
            and len(path.parts) > 1, 'noncanonical controlled IO path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def stable():
        for parent, name, child, expected in links:
            require(_directory_identity(os.fstat(child)) == expected
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False)) == expected,
                    'controlled IO directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode), 'controlled IO ancestor is not a directory')
            links.append((parent, name, child, _directory_identity(info)))
        stable()
        yield descriptors[-1], path.parts[-1], stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def _read_extent(descriptor, size):
    chunks, remaining = [], size
    while remaining:
        block = os.read(descriptor, min(1 << 20, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    require(remaining == 0, 'controlled IO original ended before its declared extent')
    return b''.join(chunks)

def _create_bytes(path, raw, mode):
    """Create through the retained parent; read back the same open descriptor."""
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            os.fchmod(descriptor, mode)
            remaining = memoryview(raw)
            while remaining:
                count = os.write(descriptor, remaining)
                require(count > 0, 'controlled IO write made no progress')
                remaining = remaining[count:]
            os.fsync(descriptor)
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and before.st_size == len(raw),
                    'create-only controlled output identity differs')
            expected = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                        before.st_gid, before.st_nlink, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
            def same_leaf(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                        info.st_gid, info.st_nlink, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns) == expected
            require(same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only output name changed')
            stable()
            os.lseek(descriptor, 0, os.SEEK_SET)
            require(_read_extent(descriptor, len(raw)) == raw
                    and same_leaf(os.fstat(descriptor))
                    and same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only descriptor readback differs')
            stable()
        finally:
            os.close(descriptor)

def _create_directory(path, mode=0o700):
    with _checked_parent(path) as (parent, name, stable):
        os.mkdir(name, mode=mode, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            observed = os.fstat(descriptor)
            require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.geteuid()
                    and not stat.S_IMODE(observed.st_mode) & 0o077
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False))
                        == _directory_identity(observed),
                    'create-only private directory differs')
            stable()
        finally:
            os.close(descriptor)

def create(path, raw):
    _create_bytes(path, raw, 0o600)
    return {'path': str(path), 'size': len(raw), 'sha256': digest(raw),
            'git_blob_sha1': blob(raw)}

def save(path, value):
    return create(path, wire(value))

def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)

def regular(path, *, system_binary=False):
    """Read a stable ordinary file through an entirely no-follow directory chain."""
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_size >= 0
                    and (before.st_nlink >= 1 if system_binary else before.st_nlink == 1),
                    'nonregular or aliased input: ' + str(path))
            if system_binary:
                require(before.st_size <= 64 << 20 and before.st_uid in (0, os.geteuid())
                        and not stat.S_IMODE(before.st_mode) & 0o022,
                        'unbounded or mutable runner interpreter')
            else:
                require(before.st_uid == os.geteuid(), 'input is not owned by this runner')
            require(signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == signature(before), 'input changed before read: ' + str(path))
            stable()
            raw = _read_extent(descriptor, before.st_size)
            require(signature(os.fstat(descriptor)) == signature(before)
                    and signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == signature(before), 'input changed while read: ' + str(path))
            stable()
            return raw, stat.S_IMODE(before.st_mode)
        finally:
            os.close(descriptor)

def relative(name):
    require(type(name) is str and name and '\0' not in name, 'invalid source member')
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts
            and str(path) == name and path.parts[0] != '.git', 'noncanonical source member')
    return path

def git_environment():
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(('GIT_', 'LD_'))}
    environment['GIT_OPTIONAL_LOCKS'] = '0'
    return environment

def git(source, *arguments, data=None):
    process = subprocess.run([GIT_EXECUTABLE, '--no-replace-objects', *arguments], cwd=source,
                             env=git_environment(), input=data, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=True)
    return process.stdout

def metadata(source):
    index = git(source, 'ls-files', '--stage', '-z')
    git(source, 'diff', '--cached', '--quiet', CANDIDATE_TREE, '--')
    head = git(source, 'rev-parse', 'HEAD').decode().strip()
    tree = git(source, 'rev-parse', 'HEAD^{tree}').decode().strip()
    require(head == CANDIDATE and tree == CANDIDATE_TREE,
            'real detached source HEAD/tree is not the fixed authoring input')
    status = git(source, 'status', '--porcelain=v1', '--untracked-files=no').decode()
    require(status == '', 'fixed source checkout has a tracked modification')
    return {'actual_head': head, 'actual_head_tree': tree,
            'actual_index_tree': CANDIDATE_TREE, 'actual_index_sha256': digest(index),
            'actual_head_is_candidate': True, 'tracked_status': status}

def inventory(source, tree, count):
    expected = {}
    for record in git(source, 'ls-tree', '-rz', tree).split(b'\0'):
        if not record:
            continue
        header, encoded = record.split(b'\t', 1)
        mode, kind, identity = header.decode().split()
        name = encoded.decode('utf-8')
        require(kind == 'blob' and mode in ('100644', '100755'), 'nonregular Git leaf')
        require(name not in expected, 'duplicate source leaf')
        expected[name] = (mode, identity)
    require(len(expected) == count, 'complete source population differs')
    rows = []
    for name in sorted(expected):
        mode, identity = expected[name]
        raw, actual_mode = regular(source / relative(name))
        require(bool(actual_mode & 0o111) == (mode == '100755') and blob(raw) == identity,
                'complete source mode/blob differs: ' + name)
        rows.append({'path': name, 'mode': mode, 'size': len(raw),
                     'git_blob_sha1': identity, 'sha256': digest(raw),
                     'posix_mode': actual_mode})
    return rows


def physical_candidate(source, rows):
    """Verify the entire fresh source namespace, including ignored entries."""
    root_info = source.lstat()
    require(stat.S_ISDIR(root_info.st_mode), 'candidate root is not a physical directory')
    expected_files = {row['path'] for row in rows}
    expected_directories = {''}
    for name in expected_files:
        parent = relative(name).parent
        while str(parent) != '.':
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    files, directories = set(), {''}
    pending = [(source, '')]
    git_directory_seen = False
    while pending:
        directory, relative_directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name if not relative_directory else relative_directory + '/' + entry.name
                info = entry.stat(follow_symlinks=False)
                if name == '.git':
                    require(stat.S_ISDIR(info.st_mode), 'private clone Git metadata is not a directory')
                    git_directory_seen = True
                    continue
                if stat.S_ISDIR(info.st_mode):
                    require(name not in directories, 'duplicate physical directory')
                    directories.add(name)
                    pending.append((Path(entry.path), name))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    require(name not in files, 'duplicate physical source member')
                    files.add(name)
                else:
                    raise RuntimeError('candidate namespace contains a symlink or nonregular member: ' + name)
    require(git_directory_seen and files == expected_files and directories == expected_directories,
            'complete physical candidate namespace differs from its canonical source tree')
    return {'schema': 'hia.json-pretty-physical-source-namespace.v1',
            'root': str(source), 'excluded_only': ['.git'],
            'file_count': len(files), 'directory_count': len(directories),
            'files': sorted(files), 'directories': sorted(directories),
            'ignored_and_untracked_extras_rejected': True}

def structure(document, assembly):
    functions = document['functions']
    blocks = [block for fn in functions for block in fn['blocks']]
    operations = [op for block in blocks for op in block['ops']]
    maximum_ssa = maximum_names = maximum_args = 0
    for fn in functions:
        definitions = list(fn['params'])
        maximum_args = max(maximum_args, len(fn['params']))
        for block in fn['blocks']:
            definitions += block['params']
            maximum_args = max(maximum_args, len(block['params']))
            term = block['term']
            if term['op'] == 'jump':
                maximum_args = max(maximum_args, len(term['args']))
            elif term['op'] == 'branch':
                maximum_args = max(maximum_args, len(term['then']['args']), len(term['else']['args']))
            for op in block['ops']:
                definitions += op['out']
                maximum_args = max(maximum_args, len(op['args']))
        maximum_names = max(maximum_names, len({value['name'] for value in definitions}))
        for value in definitions:
            require(re.fullmatch(r'v[0-9]+', value['name']) is not None, 'unexpected SSA identifier')
            maximum_ssa = max(maximum_ssa, int(value['name'][1:]))
    return {'source_bytes': len(assembly), 'source_lines': len(assembly.splitlines()),
            'functions': len(functions), 'blocks_total': len(blocks),
            'blocks_per_function': max(len(fn['blocks']) for fn in functions),
            'instructions': len(operations), 'ssa_names_per_function': maximum_names,
            'ssa_source_numeric_suffix_max_observation_only': maximum_ssa,
            'parameters_or_arguments': maximum_args}

def main():
    global GIT_EXECUTABLE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    evidence = args.output
    context_raw, _ = regular(args.context)
    context = json.loads(context_raw)
    GIT_EXECUTABLE = context['git']['resolved']
    require(context['schema'] == 'hia.json-pretty-actions-context.v1'
            and context['source'] == str(source)
            and context['evidence'] == str(evidence)
            and context['policy_sha256'] == args.policy_sha256
            and context['candidate_commit'] == CANDIDATE
            and context['candidate_tree'] == CANDIDATE_TREE
            and context['candidate_leaves'] == CANDIDATE_COUNT
            and context['controller_seconds'] == 180
            and context['cleanup_seconds'] == 3,
            'frozen development context differs')
    require(not os.path.lexists(evidence), 'new authoring evidence directory already exists')
    _create_directory(evidence)
    report = {'schema': 'hia.json-pretty-actions-authoring.v1', 'status': 'HOLD',
              'context_sha256': digest(context_raw), 'policy_sha256': args.policy_sha256,
              'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
              'actual_checkout_HEAD_is_candidate': True,
              'source_scope': 'COMPLETE_4023_LEAF_INPUT_TREE_AND_PHYSICAL_NAMESPACE',
              'outer_controller_seconds': 180, 'cleanup_seconds': 3,
              'native_compiler_executed': False, 'Core_VM_executed': False,
              'product_tests_executed': False, 'cold_qualified': False,
              'old_v1_results_inherited': False, 'original_limits_changed': False,
              'derived_global_contracts_regenerated': False,
              'native_execution': False, 'original_CLI_callers_run': False,
              'source_preserved': False, 'candidate_physical_namespace_verified': False,
              'formal_full_resource_prerequisites_checked': False,
              'desktop_interpreter_identity_claimed': False}
    before = before_meta = physical_before = None
    linker = linker_raw = None
    started = time.monotonic()
    try:
        require(not any(value for name, value in os.environ.items()
                        if name.startswith(('GIT_', 'LD_', 'HEPTA_HIA_'))),
                'native development inherited a selector or execution redirection')
        executable = Path(sys.executable).resolve(strict=True)
        python_raw, _ = regular(executable, system_binary=True)
        require(sys.version_info[:3] == (3, 14, 4)
                and str(executable) == context['python']['resolved']
                and digest(python_raw) == context['python']['binary']['sha256'],
                'actual selected Actions interpreter changed')
        report['python'] = dict(context['python'])
        before_meta = metadata(source)
        before = inventory(source, CANDIDATE_TREE, CANDIDATE_COUNT)
        report['candidate_before'] = save(evidence / 'candidate-before.json', before)
        report['candidate_metadata_before'] = before_meta
        physical_before = physical_candidate(source, before)
        report['candidate_physical_before'] = save(evidence / 'candidate-physical-before.json', physical_before)
        report['candidate_physical_namespace_verified'] = True

        controls = Path(__file__).resolve().parent
        policy_raw, _ = regular(controls / 'policy.json')
        require(digest(policy_raw) == args.policy_sha256, 'development policy differs')
        policy = json.loads(policy_raw)
        for name, pin in policy['controls'].items():
            original, _ = regular(controls / name)
            require(len(original) == pin['bytes'] and digest(original) == pin['sha256'],
                    'frozen development input changed: ' + name)
        contract_raw, _ = regular(source / 'docs/HIA_SELFHOST_CORE_SUPPORT.json')
        require(digest(contract_raw) == CONTRACT_SHA, 'original unchanged support profile differs')
        contract = json.loads(contract_raw)
        require({key: contract['limits'][key] for key in LIMITS} == LIMITS
                and contract['limits']['ssa_index_max_is_internal_only'] is True
                and contract['abi']['core_return'] == 'u32',
                'original compiler limits or entry contract differ')
        report['unchanged_limits'] = dict(LIMITS, source_lines=16384)
        report['contract_sha256'] = CONTRACT_SHA
        assembly, _ = regular(controls / 'json_pretty.hiaasm')
        document_raw, _ = regular(controls / 'json_pretty.hia.json')
        cases_raw, _ = regular(controls / 'cases.json')
        cases = json.loads(cases_raw)
        expected_ids = [row['name'] for row in cases]
        require(len(expected_ids) == len(set(expected_ids)) == 43,
                'new development case denominator differs')
        report['expected_development_test_ids'] = expected_ids
        report['assembly'] = create(evidence / 'json_pretty.hiaasm', assembly)
        report['IR_document'] = create(evidence / 'json_pretty.hia.json', document_raw)
        report['cases'] = create(evidence / 'cases.json', cases_raw)
        document = json.loads(document_raw)
        observed = structure(document, assembly)
        require(all(observed[key] <= maximum for key, maximum in LIMITS.items())
                and observed['source_lines'] <= 16384
                and document['functions'][0]['returns'] == ['u32'],
                'new source violates unchanged compiler profile')
        report['structure'] = observed
        sys.path.insert(0, str(source))
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_program import verify_program
        require(render_assembly(document).encode('utf-8') == assembly,
                'canonical IR and assembly differ')
        checked = assemble_program(assembly)
        checked_document = verify_program(document)
        require(checked.sha256 == checked_document.sha256, 'public Core representations differ')
        report['public_Core_verifier'] = {'status': 'PASS', 'checked_sha256': checked.sha256,
                                          'assembly_and_IR_equal': True}
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        native = evidence / 'native'
        _create_directory(native)
        selfhost_raw, _ = regular(source / 'examples/hia_bootstrap/selfhost.hiaasm')
        report['selfhost_source_sha256'] = digest(selfhost_raw)
        linker = Path(shutil.which('ld')).resolve(strict=True)
        linker_raw, _ = regular(linker, system_binary=True)
        linker_version = subprocess.run([str(linker), '--version'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True)
        report['linker'] = {'path': str(linker), 'sha256': digest(linker_raw),
                            'version_stdout': linker_version.stdout.decode('utf-8'),
                            'version_stderr_sha256': digest(linker_version.stderr)}
        report['development_bootstrap_attempted'] = True
        seed, seed_receipt = build_seed(native)
        report['seed_receipt'] = seed_receipt
        report['native_compiler_executed'] = None
        first, first_receipt = compile_stage(native, 'B1', seed, selfhost_raw,
                                            image_format='seed-shared')
        report['native_compiler_executed'] = True
        second, second_receipt = compile_stage(native, 'B2', first, selfhost_raw)
        first_raw, _ = regular(first)
        second_raw, _ = regular(second)
        require(first_raw == second_raw, 'new development B1/B2 bytes differ')
        report['development_compiler'] = {
            'scope': 'CURRENT_SOURCE_B0_TO_B1_B2_DEVELOPMENT_NOT_COLD_FIXED_POINT',
            'B1': first_receipt, 'B2': second_receipt,
            'B1_equals_B2': True, 'compiler_sha256': digest(second_raw),
            'cold_qualification_claimed': False, 'B3_or_mutation_qualification_claimed': False}
        image, image_receipt = compile_stage(native, 'json-pretty', second, assembly)
        image_raw, _ = regular(image)
        report['native_build'] = image_receipt
        report['native_image'] = {'path': str(image), 'bytes': len(image_raw),
                                   'sha256': digest(image_raw)}
        require(image_receipt['forbidden_compiler_modules_loaded'] == []
                and image_receipt['source_unchanged'] is True, 'native source compilation differs')
        bridge_raw, _ = regular(controls / 'byte_bridge.py')
        report['byte_bridge_source'] = create(evidence / 'byte_bridge.py', bridge_raw)
        command = [str(executable), '-I', '-S', '-B', str(controls / 'native_cases.py'),
                   '--source', str(source), '--image', str(image),
                   '--image-sha256', digest(image_raw),
                   '--cases', str(controls / 'cases.json'),
                   '--cases-sha256', digest(cases_raw),
                   '--bridge', str(controls / 'byte_bridge.py'),
                   '--bridge-sha256', digest(bridge_raw),
                   '--report', str(evidence / 'native-cases.json')]
        report['native_case_command'] = command
        report['new_native_case_child_deadline_seconds'] = 5
        report['native_execution'] = None
        child_started = time.monotonic_ns()
        try:
            process = subprocess.run(command, cwd=evidence, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        except subprocess.TimeoutExpired as error:
            report['native_child_stdout'] = create(evidence / 'native-child.stdout.log', error.stdout or b'')
            report['native_child_stderr'] = create(evidence / 'native-child.stderr.log', error.stderr or b'')
            report['native_child'] = {'status': 'TIMEOUT', 'deadline_seconds': 5,
                                      'wall_elapsed_ns': time.monotonic_ns() - child_started}
            raise
        report['native_child_stdout'] = create(evidence / 'native-child.stdout.log', process.stdout)
        report['native_child_stderr'] = create(evidence / 'native-child.stderr.log', process.stderr)
        report['native_child'] = {'status': 'RETURNED', 'returncode': process.returncode,
                                  'deadline_seconds': 5,
                                  'wall_elapsed_ns': time.monotonic_ns() - child_started}
        require(process.returncode == 0, 'native development case child failed')
        case_report_raw, _ = regular(evidence / 'native-cases.json')
        case_report = json.loads(case_report_raw)
        report['native_execution'] = True
        report['native_cases_original'] = {
            'path': str(evidence / 'native-cases.json'), 'size': len(case_report_raw),
            'sha256': digest(case_report_raw), 'git_blob_sha1': blob(case_report_raw)}
        report['native_cases'] = case_report
        require(case_report['schema'] == 'hia.json-pretty-native-cases.v1'
                and case_report['status'] == 'NATIVE_JSON_LAYOUT_DEVELOPMENT_CASES_PASS'
                and case_report['image_sha256'] == digest(image_raw)
                and case_report['cases_sha256'] == digest(cases_raw)
                and case_report['bridge_source_sha256'] == digest(bridge_raw)
                and case_report['installed_bridge_resource_qualified'] is False
                and case_report['original37_guarded_native_invocations'] == 61
                and case_report['bridge6_actual_native_invocations'] == 47
                and case_report['bridge6_include_one_host_type_admission_control'] is True
                and case_report['loaded_test_ids'] == case_report['executed_test_ids'] == expected_ids
                and len(case_report['tests']) == 43
                and [row['id'] for row in case_report['tests']] == expected_ids
                and all(row['status'] == 'PASS' for row in case_report['tests'])
                and all(case_report[field] == 0 for field in
                    ('failures', 'errors', 'skips', 'expectedFailures', 'unexpectedSuccesses')),
                'native exact original development case result differs')
        require(regular(controls / 'byte_bridge.py')[0] == bridge_raw,
                'new byte bridge source changed during native cases')
        require(regular(image)[0] == image_raw and regular(second)[0] == second_raw
                and regular(controls / 'json_pretty.hiaasm')[0] == assembly,
                'development image or HIA source changed')
        report['status'] = 'DEVELOPMENT_JSON_PRETTY_NATIVE_PASS'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['error'] = {'type': type(error).__name__, 'message': str(error),
                           'traceback': traceback.format_exc()}
        traceback.print_exc()
    finally:
        try:
            if before is not None:
                after = inventory(source, CANDIDATE_TREE, CANDIDATE_COUNT)
                report['candidate_after'] = save(evidence / 'candidate-after.json', after)
                report['candidate_metadata_after'] = metadata(source)
                physical_after = physical_candidate(source, after)
                report['candidate_physical_after'] = save(evidence / 'candidate-physical-after.json', physical_after)
                report['source_preserved'] = (after == before
                    and report['candidate_metadata_after'] == before_meta
                    and physical_after == physical_before)
                require(report['source_preserved'], 'complete development source changed during execution')
            if linker_raw is not None:
                require(regular(linker, system_binary=True)[0] == linker_raw,
                        'actual development linker changed')
                report['linker_preserved'] = True
            final_python, _ = regular(Path(sys.executable).resolve(strict=True), system_binary=True)
            require(digest(final_python) == context['python']['binary']['sha256'],
                    'actual Actions interpreter changed during native development')
        except BaseException as error:
            report['status'] = 'HOLD'
            report['preservation_error'] = {'type': type(error).__name__, 'message': str(error),
                                           'traceback': traceback.format_exc()}
        report['wall_seconds'] = time.monotonic() - started
        save(evidence / 'report.json', report)
    print(json.dumps({'status': report['status'], 'wall_seconds': report['wall_seconds'],
                      'native_case_execution_requested': report['native_execution'],
                      'report': str(evidence / 'report.json')}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_JSON_PRETTY_NATIVE_PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())

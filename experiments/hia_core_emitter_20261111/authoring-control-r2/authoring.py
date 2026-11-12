"""One complete, source-only Emitter v2 authoring attempt under the original owner.

The base has a real 608 HEAD and an independently verified 9b index/tree. The
new checkout keeps that truthful HEAD while its complete candidate index is
bound to canonical 80ec. No commit object, compiler result, or cold result is
fabricated. All 39 prospective units are newly generated, never relabelled v1.
"""
from __future__ import annotations
import argparse
import ast
from hashlib import sha1, sha256
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import traceback

BASE_SOURCE = Path('/home/qian-qi/he26corelowering-native-r1/source')
BASE_HEAD = '608157e52b0b94e0d294f6b99c4e809869f183aa'
BASE_HEAD_TREE = 'e7c29a60796a1a78946a2c667aa80df86529e532'
BASE_CANDIDATE = '9b350732ce1dac60ec5689838ab80b853d700751'
BASE_INDEX = '7191e2e9926d0c1f653e775e891c35d48efeb46f'
BASE_COUNT = 3984
CANDIDATE = '80ec04ae7489209b122c874531d194c67b30dfed'
CANDIDATE_TREE = '963e980c2486e1f7c74fa42bc8132ef6b1b8b690'
CANDIDATE_COUNT = 4023
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
CONTRACT_SHA = '745f466a9f695d698ec5d6004e781183924cc7590153f85a911004fa2dd9e074'
ROOT = Path('/home/qian-qi/he26coreemitter-authoring-r2')
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

def create(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    return {'path': str(path), 'size': len(raw), 'sha256': digest(raw),
            'git_blob_sha1': blob(raw)}

def save(path, value):
    return create(path, wire(value))

def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)

def regular(path):
    """Read only a stable single-link regular file; never open a FIFO."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            'nonregular or aliased input: ' + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        require(signature(opened) == signature(before), 'input changed before read: ' + str(path))
        chunks, remaining = [], before.st_size + 1
        while remaining:
            block = os.read(descriptor, min(1048576, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b''.join(chunks)
        require(len(raw) == before.st_size and signature(os.fstat(descriptor)) == signature(before)
                and signature(path.lstat()) == signature(before),
                'input changed while read: ' + str(path))
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
    process = subprocess.run(['git', '--no-replace-objects', *arguments], cwd=source,
                             env=git_environment(), input=data, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=True)
    return process.stdout

def metadata(source, expected_index):
    index = git(source, 'ls-files', '--stage', '-z')
    git(source, 'diff', '--cached', '--quiet', expected_index, '--')
    head = git(source, 'rev-parse', 'HEAD').decode().strip()
    tree = git(source, 'rev-parse', 'HEAD^{tree}').decode().strip()
    require(head == BASE_HEAD and tree == BASE_HEAD_TREE, 'actual checkout provenance differs')
    owner, _ = regular(source / 'tools/hia_selfhost_process_owner.py')
    require(digest(owner) == OWNER_SHA, 'original process owner source differs')
    return {'actual_head': head, 'actual_head_tree': tree, 'actual_index_tree': expected_index,
            'actual_index_sha256': digest(index), 'actual_head_is_candidate': False,
            'tracked_status': git(source, 'status', '--porcelain=v1', '--untracked-files=no').decode(),
            'owner_sha256': digest(owner)}

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
    return {'schema': 'hia.core-emitter-physical-source-namespace.v1',
            'root': str(source), 'excluded_only': ['.git'],
            'file_count': len(files), 'directory_count': len(directories),
            'files': sorted(files), 'directories': sorted(directories),
            'ignored_and_untracked_extras_rejected': True}

def ast_control(source):
    trees = [ast.parse(regular(source / name)[0], type_comments=True) for name in
             ('tests/fixtures/hia_program_native_608.py.txt',
              'tools/hia_core_lowering_policy.py', 'hepta/hia_program_native.py')]
    def node(tree, kind, name):
        return next(item for item in tree.body if isinstance(item, kind) and item.name == name)
    def normalized(item):
        return ast.dump(item, include_attributes=False)
    classes = {}
    for name, count in (('_Function', 22), ('_Emitter', 6)):
        original, policy, retained = [node(tree, ast.ClassDef, name) for tree in trees]
        methods = [item.name for item in original.body if isinstance(item, ast.FunctionDef)]
        require(len(methods) == count and normalized(original) == normalized(policy),
                'complete original policy AST differs: ' + name)
        additions = [item for item in retained.body
                     if isinstance(item, ast.FunctionDef) and item.name == '__new__']
        require(len(additions) == 1, 'selector wrapper inventory differs: ' + name)
        retained.body = [item for item in retained.body if item not in additions]
        require(normalized(original) == normalized(retained), 'retained oracle AST differs: ' + name)
        classes[name] = methods
    helpers = ('_reject', '_words', '_bounds', '_normalize', '_prologue')
    for name in helpers:
        original = node(trees[0], ast.FunctionDef, name)
        policy = node(trees[1], ast.FunctionDef, name)
        retained = node(trees[2], ast.FunctionDef, '_reference' + name)
        retained.name = name
        require(normalized(original) == normalized(policy) == normalized(retained),
                'complete original helper AST differs: ' + name)
    return {'classes': classes, 'helpers': list(helpers), 'original_bodies': 33, 'all_exact': True}

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    require(args.root.resolve(strict=True) == ROOT, 'unexpected fresh authoring root')
    source, evidence = ROOT / 's', ROOT / 'evidence'
    evidence.mkdir(mode=0o700)
    input_raw, _ = regular(ROOT / 'control/SOURCE-INPUTS.json')
    inputs = json.loads(input_raw)
    report = {'schema': 'hia.core-emitter-development-authoring.v1', 'status': 'HOLD',
              'base_canonical_commit': BASE_CANDIDATE, 'base_index_tree': BASE_INDEX,
              'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
              'actual_checkout_HEAD_is_candidate': False, 'source_scope': 'COMPLETE_4023_LEAF_INPUT_TREE',
              'outer_controller_seconds': 180, 'cleanup_seconds': 3,
              'native_compiler_executed': False, 'Core_VM_executed': False,
              'product_tests_executed': False, 'cold_qualified': False,
              'old_v1_results_inherited': False, 'original_limits_changed': False,
              'generated_outputs_are_new_v2_observations': True,
              'derived_global_contracts_regenerated': False, 'units': [],
              'source_preserved': False, 'base_preserved': False,
              'base_scope': 'tracked canonical bytes and modes only',
              'candidate_physical_namespace_verified': False,
              'resource_line': 'source-only development clone: >=2GiB available; no formal full resource or inode qualification',
              'formal_full_resource_prerequisites_checked': False}
    before_base = before_candidate = before_meta = candidate_meta = physical_before = None
    started = time.monotonic()
    try:
        require(inputs['schema'] == 'hia.core-emitter-authoring-source-inputs.v1'
                and inputs['base_source'] == str(BASE_SOURCE)
                and inputs['base_index_tree'] == BASE_INDEX and inputs['base_canonical_commit'] == BASE_CANDIDATE
                and inputs['canonical_candidate'] == CANDIDATE and inputs['candidate_tree'] == CANDIDATE_TREE
                and len(inputs['delta']) == 67, 'frozen source input interface differs')
        executable = Path(sys.executable).resolve(strict=True)
        python_raw, _ = regular(executable)
        require(digest(python_raw) == PYTHON_SHA and sys.version_info[:3] == (3, 14, 4),
                'original actual Python executable differs')
        report['python'] = {'executable': sys.executable, 'resolved': str(executable),
                            'sha256': digest(python_raw), 'version': sys.version}
        before_meta = metadata(BASE_SOURCE, BASE_INDEX)
        before_base = inventory(BASE_SOURCE, BASE_INDEX, BASE_COUNT)
        report['base_before'] = save(evidence / 'base-before.json', before_base)
        report['base_metadata_before'] = before_meta
        space = os.statvfs(ROOT)
        report['available_bytes_before'] = space.f_bavail * space.f_frsize
        require(report['available_bytes_before'] >= 2 * (1 << 30),
                'insufficient independent development clone space')
        command = ['git', '--no-replace-objects', 'clone', '--quiet', '--no-hardlinks',
                   '--no-checkout', str(BASE_SOURCE), str(source)]
        report['clone_command'] = command
        subprocess.run(command, check=True, env=git_environment())
        git(source, 'checkout', '--quiet', '--detach', BASE_HEAD)
        git(source, 'read-tree', '--reset', '-u', BASE_INDEX)
        require(metadata(source, BASE_INDEX) == before_meta
                and inventory(source, BASE_INDEX, BASE_COUNT) == before_base,
                'independent no-hardlink clone differs')
        current = {row['path']: row for row in before_base}
        seen = set()
        for row in inputs['delta']:
            name = row['path']
            require(name not in seen, 'duplicate candidate delta')
            seen.add(name)
            path = source / relative(name)
            raw = row['content'].encode('utf-8')
            require(row['mode'] in ('100644', '100755') and len(raw) == row['size']
                    and digest(raw) == row['sha256'] and blob(raw) == row['git_blob_sha1'],
                    'candidate source bytes differ: ' + name)
            old = current.get(name)
            expected = row['before']
            if old is None:
                require(expected is None and not os.path.lexists(path), 'unexpected existing candidate member')
            else:
                require(expected == {key: old[key] for key in ('mode', 'git_blob_sha1', 'size')},
                        'candidate overwrite does not bind the original member')
                original, _ = regular(path)
                require(blob(original) == old['git_blob_sha1'], 'candidate member changed before overwrite')
                path.unlink()
            path.parent.mkdir(parents=True, exist_ok=True)
            create(path, raw)
            path.chmod(0o755 if row['mode'] == '100755' else 0o644)
            actual = git(source, 'hash-object', '-w', '--stdin', data=raw).decode().strip()
            require(actual == row['git_blob_sha1'], 'candidate Git object import differs')
            git(source, 'update-index', '--add', '--cacheinfo', row['mode'] + ',' + actual + ',' + name)
        require(git(source, 'write-tree').decode().strip() == CANDIDATE_TREE,
                'complete candidate index tree differs from the canonical tree')
        candidate_meta = metadata(source, CANDIDATE_TREE)
        before_candidate = inventory(source, CANDIDATE_TREE, CANDIDATE_COUNT)
        report['candidate_before'] = save(evidence / 'candidate-before.json', before_candidate)
        report['candidate_metadata_before'] = candidate_meta
        physical_before = physical_candidate(source, before_candidate)
        report['candidate_physical_before'] = save(evidence / 'candidate-physical-before.json', physical_before)
        report['candidate_physical_namespace_verified'] = True
        report['materialized_delta'] = [{key: row[key] for key in
            ('path', 'mode', 'size', 'sha256', 'git_blob_sha1', 'before')} for row in inputs['delta']]
        for row in inputs['delta']:
            if row['path'].endswith('.py'):
                compile(regular(source / row['path'])[0], row['path'], 'exec')
        report['original_AST'] = ast_control(source)
        contract_raw, _ = regular(source / 'docs/HIA_SELFHOST_CORE_SUPPORT.json')
        require(digest(contract_raw) == CONTRACT_SHA, 'original unchanged support profile differs')
        contract = json.loads(contract_raw)
        require({key: contract['limits'][key] for key in LIMITS} == LIMITS
                and contract['limits']['ssa_index_max_is_internal_only'] is True,
                'original authoring limits differ')
        report['unchanged_limits'] = dict(LIMITS, source_lines=16384)
        report['contract_sha256'] = CONTRACT_SHA
        sys.path.insert(0, str(source))
        generator = importlib.import_module('tools.generate_hia_core_lowering')
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.hia_core_lowering_ir import compile_policy
        from hepta.hia_core_lowering_selection import _MODE_ARITIES, _GENERATOR_MODES, checked_abi
        literals, functions, entries, instructions = compile_policy(generator.POLICY.read_text())
        require(len(functions) == len(entries) == len(_MODE_ARITIES) == 36
                and len(instructions) == 2428 and len(literals.values) == 312
                and max(item.slot_count for item in functions) == 510,
                'frozen complete finite IR population differs')
        require(list(entries) == [name for name, _ in _MODE_ARITIES],
                'complete ordered mode identity differs')
        for number, (name, count) in enumerate(_MODE_ARITIES, 1):
            require(entries[name]['mode'] == number and len(entries[name]['parameters']) == count,
                    'mode number or bound arity differs: ' + name)
        require([name for name, entry in entries.items() if entry['generator']] == list(_GENERATOR_MODES)
                == ['_native_generator_0', '_native_generator_1'], 'lazy generator mode identity differs')
        report['finite_IR'] = {'functions': len(functions), 'literal_count': len(literals.values),
                              'instructions': len(instructions), 'maximum_slots': 510, 'modes': entries}
        sources, abi = generator.generated()
        require(len(sources) == 39 and len(abi['units']) == 38
                and [name for name, _ in sources] == ['core_lowering_pool', *abi['units']],
                'complete generated unit inventory differs')
        abi_raw = wire(abi)
        require(checked_abi(abi_raw) == abi, 'ordinary v2 ABI admission differs')
        report['abi'] = create(evidence / 'hia_core_lowering_abi.json', abi_raw)
        report['expected_unit_count'] = len(sources)
        authoring, assembled = evidence / 'authoring', evidence / 'assembled'
        authoring.mkdir(mode=0o700)
        assembled.mkdir(mode=0o700)
        for name, authored in sources:
            item = {'name': name, 'status': 'HOLD'}
            report['units'].append(item)
            item['authoring'] = create(authoring / (name + '.py.txt'), authored.encode())
            document = generator.document(authored, name)
            assembly = render_assembly(document).encode('utf-8')
            item.update(create(assembled / (name + '.hiaasm'), assembly))
            observed = structure(document, assembly)
            item['structure'] = observed
            for key, maximum in LIMITS.items():
                require(observed[key] <= maximum, name + ' exceeds unchanged ' + key)
            require(observed['source_lines'] <= 16384, name + ' exceeds unchanged source line bound')
            checked = assemble_program(assembly)
            item['public_core_roundtrip'] = True
            item['checked_core_sha256'] = checked.sha256
            item['status'] = 'PASS'
            print(json.dumps({'unit': name, 'status': 'PASS', **observed}), flush=True)
        require(len(report['units']) == 39 and all(row['status'] == 'PASS' for row in report['units']),
                'complete actual unit denominator differs')
        report['status'] = 'DEVELOPMENT_EMITTER_AUTHORING_PASS'
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error),
                           'traceback': traceback.format_exc()}
        traceback.print_exc()
    finally:
        try:
            if before_candidate is not None:
                after_candidate = inventory(source, CANDIDATE_TREE, CANDIDATE_COUNT)
                report['candidate_after'] = save(evidence / 'candidate-after.json', after_candidate)
                report['candidate_metadata_after'] = metadata(source, CANDIDATE_TREE)
                physical_after = physical_candidate(source, after_candidate)
                report['candidate_physical_after'] = save(evidence / 'candidate-physical-after.json', physical_after)
                report['source_preserved'] = (after_candidate == before_candidate
                    and report['candidate_metadata_after'] == candidate_meta
                    and physical_after == physical_before)
                require(report['source_preserved'], 'complete candidate changed during authoring')
            if before_base is not None:
                after_base = inventory(BASE_SOURCE, BASE_INDEX, BASE_COUNT)
                report['base_after'] = save(evidence / 'base-after.json', after_base)
                report['base_metadata_after'] = metadata(BASE_SOURCE, BASE_INDEX)
                report['base_preserved'] = after_base == before_base and report['base_metadata_after'] == before_meta
                require(report['base_preserved'], 'readonly original changed during authoring')
        except BaseException as error:
            report['status'] = 'HOLD'
            report['preservation_error'] = {'type': type(error).__name__, 'message': str(error),
                                           'traceback': traceback.format_exc()}
        report['wall_seconds'] = time.monotonic() - started
        save(evidence / 'report.json', report)
    print(json.dumps({'status': report['status'], 'wall_seconds': report['wall_seconds'],
                      'units_observed': len(report['units']), 'report': str(evidence / 'report.json')}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_EMITTER_AUTHORING_PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())

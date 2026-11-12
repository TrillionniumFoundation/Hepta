"""Generate every new Core/Emitter v2 unit from one exact, real Git checkout.

This source-only worker is owned for 180 seconds. It executes no native image,
Core VM, product caller, cold qualification, or replacement qualification gate.
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

CANDIDATE = '80ec04ae7489209b122c874531d194c67b30dfed'
CANDIDATE_TREE = '963e980c2486e1f7c74fa42bc8132ef6b1b8b690'
CANDIDATE_COUNT = 4023
GIT_EXECUTABLE = None
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
CONTRACT_SHA = '745f466a9f695d698ec5d6004e781183924cc7590153f85a911004fa2dd9e074'
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

def regular(path, *, system_binary=False):
    """Read only a stable single-link regular file; never open a FIFO."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and
            (before.st_nlink >= 1 if system_binary else before.st_nlink == 1),
            'nonregular or aliased input: ' + str(path))
    if system_binary:
        require(before.st_size <= 64 << 20 and before.st_uid in (0, os.geteuid())
                and not stat.S_IMODE(before.st_mode) & 0o022,
                'unbounded or mutable runner interpreter')
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
    require(context['schema'] == 'hia.core-emitter-actions-context.v1'
            and context['source'] == str(source)
            and context['evidence'] == str(evidence)
            and context['policy_sha256'] == args.policy_sha256
            and context['candidate_commit'] == CANDIDATE
            and context['candidate_tree'] == CANDIDATE_TREE
            and context['candidate_leaves'] == CANDIDATE_COUNT
            and context['controller_seconds'] == 180
            and context['cleanup_seconds'] == 3,
            'frozen source-only context differs')
    require(not os.path.lexists(evidence), 'new authoring evidence directory already exists')
    evidence.mkdir(mode=0o700)
    report = {'schema': 'hia.core-emitter-actions-authoring.v1', 'status': 'HOLD',
              'context_sha256': digest(context_raw), 'policy_sha256': args.policy_sha256,
              'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
              'actual_checkout_HEAD_is_candidate': True,
              'source_scope': 'COMPLETE_4023_LEAF_INPUT_TREE_AND_PHYSICAL_NAMESPACE',
              'outer_controller_seconds': 180, 'cleanup_seconds': 3,
              'native_compiler_executed': False, 'Core_VM_executed': False,
              'product_tests_executed': False, 'cold_qualified': False,
              'old_v1_results_inherited': False, 'original_limits_changed': False,
              'generated_outputs_are_new_v2_observations': True,
              'derived_global_contracts_regenerated': False, 'units': [],
              'source_preserved': False, 'candidate_physical_namespace_verified': False,
              'formal_full_resource_prerequisites_checked': False,
              'desktop_interpreter_identity_claimed': False}
    before = before_meta = physical_before = None
    started = time.monotonic()
    try:
        require(not any(value for name, value in os.environ.items()
                        if name.startswith(('GIT_', 'LD_', 'HEPTA_HIA_'))),
                'source authoring inherited a selector or execution redirection')
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
        syntax_names = (
            'tools/hia_core_lowering_policy.py', 'tools/hia_core_lowering_ir.py',
            'tools/generate_hia_core_lowering.py', 'hepta/hia_core_lowering_native.py',
            'hepta/hia_core_lowering_selection.py', 'hepta/hia_program_native.py',
            'tools/build_hia_core_lowering.py',
        )
        for name in syntax_names:
            compile(regular(source / name)[0], name, 'exec')
        report['source_syntax_checked'] = list(syntax_names)
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
        report['status'] = 'DEVELOPMENT_ACTIONS_EMITTER_AUTHORING_PASS'
    except BaseException as error:
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
                require(report['source_preserved'], 'complete authoring input changed during generation')
            final_python, _ = regular(Path(sys.executable).resolve(strict=True), system_binary=True)
            require(digest(final_python) == context['python']['binary']['sha256'],
                    'actual Actions interpreter changed during source-only authoring')
        except BaseException as error:
            report['status'] = 'HOLD'
            report['preservation_error'] = {'type': type(error).__name__, 'message': str(error),
                                           'traceback': traceback.format_exc()}
        report['wall_seconds'] = time.monotonic() - started
        save(evidence / 'report.json', report)
    print(json.dumps({'status': report['status'], 'wall_seconds': report['wall_seconds'],
                      'units_observed': len(report['units']),
                      'report': str(evidence / 'report.json')}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_ACTIONS_EMITTER_AUTHORING_PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())

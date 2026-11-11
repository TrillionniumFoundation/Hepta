"""One fresh development authoring run; no native compiler or product tests."""
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

BASE_COMMIT = '608157e52b0b94e0d294f6b99c4e809869f183aa'
BASE_TREE = 'e7c29a60796a1a78946a2c667aa80df86529e532'
CANDIDATE_COMMIT = '7d73eabbfed50254a5a94e555fff17405b8a6892'
CANDIDATE_TREE = '095e31fc7baba6941d5f78d132ea6630e0dc83ae'
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(raw):
    return sha256(raw).hexdigest()


def write(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as output:
        output.write(raw)
    return {'path': str(path), 'size': len(raw), 'sha256': digest(raw)}


def git(source, *args, environment=None, data=None):
    return subprocess.run(['git', '--no-replace-objects', *args], cwd=source,
                          env=environment, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def identity(source):
    return {
        'head': git(source, 'rev-parse', 'HEAD').decode().strip(),
        'tree': git(source, 'rev-parse', 'HEAD^{tree}').decode().strip(),
        'status': git(source, 'status', '--porcelain=v1', '--untracked-files=all').decode(),
    }


def inventory(source, tree):
    records = git(source, 'ls-tree', '-rz', tree).split(b'\0')
    output = []
    for record in records:
        if not record:
            continue
        prefix, name = record.split(b'\t', 1)
        mode, kind, expected = prefix.decode().split()
        path = name.decode('utf-8')
        require(kind == 'blob' and mode in ('100644', '100755'), 'non-regular source member: ' + path)
        item = source / path
        metadata = item.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not item.is_symlink(), 'source member type differs: ' + path)
        require(('100755' if metadata.st_mode & 0o111 else '100644') == mode, 'source executable mode differs: ' + path)
        raw = item.read_bytes()
        actual = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(actual == expected, 'source Git blob differs: ' + path)
        output.append({'path': path, 'mode': mode, 'size': len(raw), 'git_blob_sha1': actual,
                       'sha256': digest(raw)})
    require(len({row['path'] for row in output}) == len(output), 'source inventory contains duplicates')
    return output


def ast_control(source):
    original = ast.parse((source / 'tests/fixtures/hia_program_native_608.py.txt').read_bytes())
    policy = ast.parse((source / 'tools/hia_core_lowering_policy.py').read_bytes())
    old_class = next(n for n in original.body if isinstance(n, ast.ClassDef) and n.name == '_Function')
    new_class = next(n for n in policy.body if isinstance(n, ast.ClassDef) and n.name == '_Function')
    require(ast.dump(old_class, include_attributes=False) == ast.dump(new_class, include_attributes=False),
            'complete original Function AST changed')
    helpers = ('_reject', '_words', '_bounds', '_normalize', '_prologue')
    for name in helpers:
        old = next(n for n in original.body if isinstance(n, ast.FunctionDef) and n.name == name)
        new = next(n for n in policy.body if isinstance(n, ast.FunctionDef) and n.name == name)
        require(ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False),
                'original helper AST changed: ' + name)
    methods = [n.name for n in old_class.body if isinstance(n, ast.FunctionDef)]
    require(len(methods) == 22, 'original method inventory differs')
    return {'complete_class_ast_equal': True, 'method_names': methods, 'method_count': len(methods),
            'helper_names': list(helpers), 'helper_count': len(helpers)}


def structure(document, assembly):
    functions = document['functions']
    blocks = [block for fn in functions for block in fn['blocks']]
    operations = [op for block in blocks for op in block['ops']]
    maximum_ssa = 0
    maximum_names = 0
    maximum_args = 0
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
        unique_names = {definition['name'] for definition in definitions}
        maximum_names = max(maximum_names, len(unique_names))
        for definition in definitions:
            name = definition['name']
            require(re.fullmatch(r'v[0-9]+', name) is not None, 'unexpected generated SSA identifier')
            maximum_ssa = max(maximum_ssa, int(name[1:]))
    return {
        'source_bytes': len(assembly), 'source_lines': len(assembly.splitlines()),
        'functions': len(functions), 'blocks_total': len(blocks),
        'blocks_per_function': max(len(fn['blocks']) for fn in functions),
        'instructions': len(operations), 'ssa_names_per_function': maximum_names,
        'ssa_source_numeric_suffix_max_observation_only': maximum_ssa,
        'parameters_or_arguments': maximum_args,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    source, evidence = root / 's', root / 'evidence'
    evidence.mkdir(mode=0o700)
    inputs = json.loads((root / 'control/SOURCE-INPUTS.json').read_bytes())
    base = Path(inputs['base_source'])
    report = {
        'schema': 'hepta.hia.core-lowering-development-authoring.v1', 'status': 'HOLD',
        'base_commit': BASE_COMMIT, 'base_tree': BASE_TREE,
        'canonical_candidate_commit': CANDIDATE_COMMIT, 'canonical_candidate_tree': CANDIDATE_TREE,
        'local_git_head_claim': '608 base plus explicitly verified candidate overlay; not a fabricated checkout',
        'native_compiler_executed': False, 'core_vm_executed': False,
        'product_tests_executed': False, 'cold_qualified': False, 'units': [],
        'source_preserved': False, 'base_preserved': False,
        'original_limits_changed': False, 'outer_controller_seconds': 180,
    }
    before_base = before_candidate = None
    started = time.monotonic()
    try:
        executable = Path(sys.executable).resolve()
        python_raw = executable.read_bytes()
        require(digest(python_raw) == PYTHON_SHA, 'actual Python executable identity differs')
        require(sys.version_info[:3] == (3, 14, 4), 'actual Python version differs')
        report['python'] = {'path': sys.executable, 'resolved': str(executable),
                            'sha256': digest(python_raw), 'version': sys.version}
        before_identity = identity(base)
        require(before_identity['head'] == BASE_COMMIT and before_identity['tree'] == BASE_TREE
                and before_identity['status'] == '', 'immutable base Git identity differs')
        before_base = inventory(base, 'HEAD')
        require(len(before_base) == 3925, 'exact608 complete leaf inventory differs')
        report['base_before'] = write(evidence / 'base-before.json', before_base)
        command = ['git', '--no-replace-objects', 'clone', '--quiet', '--no-hardlinks',
                   '--no-checkout', str(base), str(source)]
        report['clone_command'] = command
        subprocess.run(command, check=True)
        git(source, 'checkout', '--quiet', '--detach', BASE_COMMIT)
        require(identity(source) == before_identity, 'fresh clone Git identity differs')
        require(inventory(source, 'HEAD') == before_base, 'fresh clone byte/mode identity differs')
        environment = dict(os.environ)
        environment['GIT_INDEX_FILE'] = str(root / 'control/candidate.index')
        git(source, 'read-tree', 'HEAD', environment=environment)
        for row in inputs['delta']:
            path = Path(row['path'])
            require(not path.is_absolute() and '..' not in path.parts and path.parts[0] != '.git',
                    'unsafe candidate relative path')
            destination = source / path
            require(not destination.exists(), 'this additive candidate unexpectedly overwrites a base member')
            raw = row['content'].encode('utf-8')
            require(len(raw) == row['size'] and digest(raw) == row['sha256'],
                    'candidate source payload differs')
            require(sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob_sha1'],
                    'candidate Git blob differs')
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as output:
                output.write(raw)
            destination.chmod(0o755 if row['mode'] == '100755' else 0o644)
            blob = git(source, 'hash-object', '-w', '--stdin', data=raw).decode().strip()
            require(blob == row['git_blob_sha1'], 'candidate object import differs')
            git(source, 'update-index', '--add', '--cacheinfo',
                row['mode'] + ',' + blob + ',' + row['path'], environment=environment)
        candidate_tree = git(source, 'write-tree', environment=environment).decode().strip()
        require(candidate_tree == CANDIDATE_TREE, 'complete overlay tree differs from canonical candidate')
        report['local_head'] = git(source, 'rev-parse', 'HEAD').decode().strip()
        report['actual_candidate_index_tree'] = candidate_tree
        before_candidate = inventory(source, candidate_tree)
        require(len(before_candidate) == 3936, 'complete candidate leaf inventory differs')
        report['candidate_before'] = write(evidence / 'candidate-before.json', before_candidate)
        for row in inputs['delta']:
            if row['path'].endswith('.py'):
                compile((source / row['path']).read_bytes(), row['path'], 'exec')
        report['python_syntax_checked'] = [row['path'] for row in inputs['delta'] if row['path'].endswith('.py')]
        report['original_ast'] = ast_control(source)
        sys.path.insert(0, str(source))
        generator = importlib.import_module('tools.generate_hia_core_lowering')
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.hia_core_lowering_ir import compile_policy
        literals, functions, entries, instructions = compile_policy(generator.POLICY.read_text())
        require(len(functions) == 28 and len(entries) == 28, 'complete policy mode inventory differs')
        report['finite_control'] = {
            'functions': len(functions), 'literal_count': len(literals.values),
            'instructions': len(instructions), 'maximum_slots': max(f.slot_count for f in functions),
            'modes': entries,
        }
        sources, abi = generator.generated()
        report['expected_unit_count'] = len(sources)
        report['abi'] = write(evidence / 'hia_core_lowering_abi.json', abi)
        contract = json.loads((source / 'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes())
        limits = contract['limits']
        report['limits'] = {name: limits[name] for name in (
            'source_bytes', 'functions', 'blocks_total', 'blocks_per_function',
            'instructions', 'ssa_names_per_function', 'parameters_or_arguments')}
        require(limits['ssa_index_max_is_internal_only'] is True,
                'original SSA name-identity profile differs')
        report['ssa_name_profile'] = 'unique names per function <=2048; source spelling numeric suffix is not an admission limit'
        report['native_image_limits_not_executed'] = ['output capacity', 'relocations', 'machine compilation']
        report['additional_unchanged_source_line_bound'] = 16384
        assembled = evidence / 'assembled'
        assembled.mkdir(mode=0o700)
        for name, authoring in sources:
            item = {'name': name, 'status': 'HOLD'}
            report['units'].append(item)
            document = generator.document(authoring, name)
            assembly = render_assembly(document).encode('utf-8')
            path = assembled / (name + '.hiaasm')
            with path.open('xb') as output:
                output.write(assembly)
            item.update({'path': str(path), 'size': len(assembly), 'sha256': digest(assembly)})
            observed = structure(document, assembly)
            item['structure'] = observed
            for key, maximum in report['limits'].items():
                require(observed[key] <= maximum, name + ' exceeds unchanged ' + key)
            require(observed['source_lines'] <= 16384, name + ' exceeds unchanged source line bound')
            checked = assemble_program(assembly)
            item['public_core_roundtrip'] = True
            item['checked_core_sha256'] = checked.sha256
            item['status'] = 'PASS'
            print(json.dumps({'unit': name, 'status': 'PASS', **observed}), flush=True)
        require(len(report['units']) == report['expected_unit_count']
                and all(row['status'] == 'PASS' for row in report['units']),
                'authoring unit denominator differs')
        report['status'] = 'DEVELOPMENT_AUTHORING_PASS'
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error),
                           'traceback': traceback.format_exc()}
        traceback.print_exc()
    finally:
        try:
            if before_candidate is not None:
                after_candidate = inventory(source, CANDIDATE_TREE)
                report['candidate_after'] = write(evidence / 'candidate-after.json', after_candidate)
                report['source_preserved'] = before_candidate == after_candidate
                require(report['source_preserved'], 'candidate source changed during authoring')
            if before_base is not None:
                after_base = inventory(base, 'HEAD')
                report['base_after'] = write(evidence / 'base-after.json', after_base)
                report['base_preserved'] = before_base == after_base and identity(base) == before_identity
                require(report['base_preserved'], 'immutable base changed during authoring')
        except BaseException as error:
            report['preservation_error'] = {'type': type(error).__name__, 'message': str(error),
                                            'traceback': traceback.format_exc()}
            report['status'] = 'HOLD'
        report['wall_seconds'] = time.monotonic() - started
        write(evidence / 'report.json', report)
    print(json.dumps({'status': report['status'], 'wall_seconds': report['wall_seconds'],
                      'units_observed': len(report['units']), 'report': str(evidence / 'report.json')}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_AUTHORING_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

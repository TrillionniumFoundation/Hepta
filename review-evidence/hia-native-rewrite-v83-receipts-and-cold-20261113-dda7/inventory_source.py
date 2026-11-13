"""Inventory the complete frozen source without importing or executing it."""
from collections import defaultdict
from hashlib import sha1, sha256
import ast
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent/'v83-native-receipt-union-r1/source'


def main():
    frozen = json.loads((SOURCE.parent/'FINAL-SOURCE-MANIFEST.json').read_bytes())
    extensions, scopes, modules = defaultdict(lambda: {'files': 0, 'bytes': 0}), {}, {}
    for name, row in sorted(frozen.items()):
        raw = (SOURCE/name).read_bytes()
        assert len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256']
        assert sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == row['blob']
        assert ('100755' if (SOURCE/name).stat().st_mode & 0o111 else '100644') == row['mode']
        suffix = Path(name).suffix or '<no suffix>'
        extensions[suffix]['files'] += 1
        extensions[suffix]['bytes'] += len(raw)
        scope = name.split('/', 1)[0] if '/' in name else '<root>'
        counts = scopes.setdefault(scope, {'files': 0, 'bytes': 0, 'extensions': {}})
        counts['files'] += 1
        counts['bytes'] += len(raw)
        ext = counts['extensions'].setdefault(suffix, {'files': 0, 'bytes': 0})
        ext['files'] += 1
        ext['bytes'] += len(raw)
        if name.startswith('hepta/') and name.endswith('.py'):
            tree = ast.parse(raw, filename=name)
            imports, functions = [], []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.append({'line': node.lineno, 'kind': 'import',
                                    'names': [a.name for a in node.names]})
                elif isinstance(node, ast.ImportFrom):
                    imports.append({'line': node.lineno, 'kind': 'from',
                                    'module': node.module, 'level': node.level,
                                    'names': [a.name for a in node.names]})
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append({'name': node.name, 'line': node.lineno, 'end_line': node.end_lineno,
                        'ast_sha256_this_interpreter': sha256(ast.dump(node).encode()).hexdigest()})
            modules[name] = {'identity': row, 'syntactic_imports': imports,
                             'syntactic_functions_including_nested': functions}
    checker = ast.parse((SOURCE/'hepta/hia_checker_identity.py').read_bytes())
    declarations = {}
    wanted = {'CORE_SOURCE_FILES', 'MECHANISM_SOURCE_FILES', 'NATIVE_OWNERS',
              'HELD_NATIVE_OWNERS', 'CAPTURED_NATIVE_OWNERS',
              'CHECKER_MECHANISM_EXTERNAL_PROVIDERS'}
    for node in checker.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in wanted:
                declarations[node.targets[0].id] = ast.literal_eval(node.value)
    assert set(declarations) == wanted
    core, mechanisms = map(set, (declarations['CORE_SOURCE_FILES'], declarations['MECHANISM_SOURCE_FILES']))
    assert (len(core), len(mechanisms), len(core|mechanisms)) == (54, 29, 83)
    assert not core & mechanisms
    result = {'schema': 'hia.frozen-source-complete-static-inventory.v83.r1',
        'source_commit': '4925e72d9f51f4dc3e8f4d1d2a7b24cce2f5772b',
        'source_tree': 'bc276bc832a7d6f04a21d63f55645859b75a01ee',
        'files': len(frozen), 'all_frozen_source_bytes_read_and_verified': True,
        'extensions': dict(extensions), 'top_level_scopes': scopes,
        'all_hepta_python_modules': modules, 'explicit_checker_declarations': declarations,
        'syntactic_imports_are_not_a_complete_dynamic_dependency_graph': True,
        'business_executions': 0, 'loaded_test_methods': 0,
        'file_or_function_counts_are_not_semantic_replacement_percentages': True,
        'retained_python_count_does_not_grant_deletion_authority': True,
        'whole_native': False, 'current_source_cold': False}
    (HERE/'SOURCE-SURFACE-INVENTORY.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps({'files': len(frozen), 'hepta_python_modules': len(modules),
        'core': len(core), 'mechanisms': len(mechanisms),
        'all_bytes_verified': True, 'business_executions': 0}, sort_keys=True))


if __name__ == '__main__':
    main()

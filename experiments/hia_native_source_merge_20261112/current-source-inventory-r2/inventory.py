"""Full-tree and full-package source inventory; no semantic/native PASS inference."""
from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
import ast
import json
import subprocess

ROOT = Path('/workspace/scratch/e26ed3e2edcf/combined-gates-r2')
OLD = Path('/workspace/scratch/e26ed3e2edcf/Hepta')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/current-native-owner-inventory-r2')
TREE = '0c64c55c6aaee3febe88fbaaec91dee3d5bfe195'

def symbols(raw):
    text = raw.decode()
    syntax = ast.parse(text)
    lines = text.splitlines(keepends=True)
    result = []
    indexed_nodes = []
    def walk(node, prefix):
        following = prefix
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = '.'.join((*prefix, node.name))
            start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
            source = ''.join(lines[start - 1:node.end_lineno]).encode()
            identity = (type(node).__name__, node.name, node.lineno, node.col_offset,
                        node.end_lineno, node.end_col_offset)
            indexed_nodes.append(identity)
            result.append({'name': name, 'kind': type(node).__name__,
                'first_line': start, 'last_line': node.end_lineno,
                'syntax_line': node.lineno, 'syntax_column': node.col_offset,
                'syntax_end_column': node.end_col_offset,
                'bytes': len(source), 'sha256': sha256(source).hexdigest(),
                'decorators': [ast.unparse(d) for d in node.decorator_list]})
            following = (*prefix, node.name)
        # Definitions under if/try/loop/with/handlers must also be included.
        for child in ast.iter_child_nodes(node):
            walk(child, following)
    walk(syntax, ())
    independently_observed = [(type(n).__name__, n.name, n.lineno, n.col_offset,
                               n.end_lineno, n.end_col_offset)
        for n in ast.walk(syntax)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    assert sorted(indexed_nodes) == sorted(independently_observed)
    imports = []
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            imports.extend(x.name for x in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append('.' * node.level + (node.module or ''))
    selectors = sorted({node.value for node in ast.walk(syntax)
                        if isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and node.value.startswith('HEPTA_HIA_') and '\n' not in node.value
                        and len(node.value) <= 150})
    return result, sorted(set(imports)), selectors

OUT.mkdir(exist_ok=False)
tree_raw = subprocess.check_output(['git', 'ls-tree', '-rlz', TREE], cwd=ROOT)
leaves = []
extensions, extension_bytes, roots, root_bytes = Counter(), Counter(), Counter(), Counter()
for row in tree_raw.split(b'\0'):
    if not row:
        continue
    meta, name = row.split(b'\t', 1)
    mode, kind, digest, size = meta.decode().split()
    name, size = name.decode(), int(size)
    ext = Path(name).suffix or '(no suffix)'
    first = name.split('/')[0]
    leaves.append({'path': name, 'mode': mode, 'type': kind, 'git_blob': digest, 'bytes': size})
    extensions[ext] += 1
    extension_bytes[ext] += size
    roots[first] += 1
    root_bytes[first] += size
modules, errors = [], []
for entry in leaves:
    name = entry['path']
    if not name.startswith('hepta/') or not name.endswith('.py'):
        continue
    raw = (ROOT / name).read_bytes()
    record = {**entry, 'sha256': sha256(raw).hexdigest(), 'lines': len(raw.splitlines())}
    try:
        current, imports, selectors = symbols(raw)
        old_path = OLD / name
        prior = symbols(old_path.read_bytes())[0] if old_path.exists() else []
        old_symbols = defaultdict(list)
        for previous in prior:
            old_symbols[previous['name']].append(previous)
        for value in current:
            previous = old_symbols.get(value['name'], [])
            value['prior_same_name_definitions'] = len(previous)
            value['compared_to_original_PR_head'] = (
                'added' if not previous else
                'source_identical' if any(value['sha256'] == item['sha256'] for item in previous)
                else 'changed')
        record.update(symbols=current, imports=imports, literal_selector_names=selectors,
                      complete_ast_definition_identity_coverage=True,
                      duplicate_qualified_names={name:count for name,count in Counter(v['name'] for v in current).items() if count>1},
                      removed_symbols=[x for x in old_symbols if x not in {s['name'] for s in current}],
                      module_compared_to_original_PR_head=(
                          'added' if not old_path.exists() else
                          'source_identical' if raw == old_path.read_bytes() else 'changed'))
    except (SyntaxError, UnicodeError) as error:
        record['parse_error'] = {'type': type(error).__name__, 'message': str(error)}
        errors.append(name)
    modules.append(record)
states = Counter(x['module_compared_to_original_PR_head'] for x in modules if 'module_compared_to_original_PR_head' in x)
symbols_total = Counter(v['kind'] for row in modules for v in row.get('symbols', []))
summary = {
    'schema': 'hia.current-combined-source-owner-inventory.v2',
    'status': 'COMPLETE_TREE_AND_ALL_AST_DEFINITIONS_SOURCE_INVENTORY_NOT_SEMANTIC_CLOSURE',
    'source_commit': '83a0c59e9e2268cd0b80f3dd2752dc175e2db36a',
    'same_tree_CI_head': 'bde0f67740e12b91c0d60cf72b1af0ba9a4b4742',
    'source_tree': TREE, 'original_PR_head': 'acffa9262f31d073f8f0a6f0201eae201039f619',
    'default_branch_head_last_observed': '5831f52fada45e076f8f68f198a15c0585e6104f',
    'source_leaves': len(leaves), 'source_bytes': sum(x['bytes'] for x in leaves),
    'extension_counts': dict(sorted(extensions.items())),
    'extension_bytes': dict(sorted(extension_bytes.items())),
    'root_counts': dict(sorted(roots.items())), 'root_bytes': dict(sorted(root_bytes.items())),
    'package_python_modules': len(modules), 'package_python_bytes': sum(x['bytes'] for x in modules),
    'package_python_lines': sum(x['lines'] for x in modules),
    'package_definition_counts': dict(symbols_total), 'package_module_change_counts': dict(states),
    'package_parse_errors': errors,
    'all_package_definition_identities_independently_equal_ast_walk': all(row.get('complete_ast_definition_identity_coverage') for row in modules),
    'prior_inventory_r1_symbol_omissions_preserved': True,
    'method': 'Every Git tree leaf inventoried; every hepta Python module parsed and every class/function source span including decorators hashed. Original-PR comparison is exact source identity, not a semantic or execution claim.',
    'limits': [
        'A .hia/.hiaasm file or native-named Python module does not establish native ownership or default selection.',
        'The presence of a selector literal is source evidence only, not an executed native path.',
        'Unchanged Python source may still dispatch to native images; source identity alone does not classify its semantics.',
        'Tools, tests, Rust and runtime dependencies still require their own complete replacement and qualification.',
        'No percentage of whole-native completion is inferred from file or line counts.',
    ],
    'whole_native_delivery_qualified': False,
    'old_stack_removal_qualified': False,
}
for name, data in (('SUMMARY.json', summary), ('PACKAGE-SYMBOLS.json', modules), ('TREE-INVENTORY.json', leaves)):
    with (OUT / name).open('x') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')
print(json.dumps(summary))

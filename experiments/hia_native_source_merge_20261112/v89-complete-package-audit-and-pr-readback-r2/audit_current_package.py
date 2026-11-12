"""Read the passed v89 package by Git identity without importing product code."""
from pathlib import Path
import ast
from collections import defaultdict
import hashlib
import json
import os
import stat
import sys
import tomllib

OUT = Path(__file__).resolve().parent
SOURCE = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
META = json.loads((OUT/'GIT-IDENTITY.json').read_bytes())
OLD = Path('/workspace/scratch/e26ed3e2edcf/root/project-audit-20261112-r1')

def write(name, value):
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2)+'\n').encode()
    with (OUT/name).open('xb') as stream:
        stream.write(raw)
    return dict(name=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

pins = {row['path']: row for row in META['pins']}
raws = {}
physical = []
for name, expected in pins.items():
    path = SOURCE/name
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, name
    raw = path.read_bytes()
    assert identity(before) == identity(path.lstat()), name
    blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    assert len(raw) == expected['size'] and blob == expected['sha'], name
    actual_mode = '100755' if before.st_mode & 0o111 else '100644'
    assert actual_mode == expected['mode'], name
    physical.append(dict(path=name, git_blob_sha1=blob, sha256=hashlib.sha256(raw).hexdigest(),
                         bytes=len(raw), physical_identity=list(identity(before))))
    raws[name] = raw

observed = {str(p.relative_to(SOURCE)) for p in (SOURCE/'hepta').rglob('*.py')}
expected = {name for name in pins if name.startswith('hepta/')}
assert observed == expected and len(expected) == 172
modules, local_edges = [], []
external = defaultdict(set)
for name in sorted(expected):
    raw = raws[name]
    tree = ast.parse(raw, filename=name)
    imports, dynamic = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(dict(kind='import', module=alias.name, names=[], level=0,
                                line=node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(dict(kind='from', module=node.module or '',
                                names=[alias.name for alias in node.names],
                                level=node.level, line=node.lineno))
        elif isinstance(node, ast.Call):
            fn = node.func
            call = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            if call in ('__import__', 'import_module', 'exec', 'eval', 'CDLL', 'PyDLL',
                        'CFUNCTYPE', 'PYFUNCTYPE', 'Popen', 'system', 'mmap'):
                dynamic.append(dict(name=call, line=node.lineno, expression=ast.unparse(node)))
    for row in imports:
        module = 'hepta.'+row['module'] if row['level'] == 1 else row['module']
        if module == 'hepta' or module.startswith('hepta.'):
            local_edges.append(dict(source=name, module=module, names=row['names'], line=row['line']))
        elif module:
            external[module.split('.')[0]].add(name)
    modules.append(dict(path=name, git_blob_sha1=pins[name]['sha'],
                        sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                        lines=len(raw.splitlines()), imports=imports,
                        dynamic_or_foreign_call_sites=dynamic))

def branches(path, class_name, method, variable):
    text = raws[path].decode()
    tree = ast.parse(text)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    function = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method)
    rows = []
    for node in ast.walk(function):
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == variable
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and type(node.test.comparators[0].value) is int):
            rows.append(dict(operation=node.test.comparators[0].value, line=node.lineno,
                             source='\n'.join(ast.get_source_segment(text, item) for item in node.body)))
    return sorted(rows, key=lambda row: row['operation'])

core = branches('hepta/hia_core_lowering_native.py', 'LoweringSession', '_primitive', 'opcode')
cli_tree = ast.parse(raws['hepta/hia_cli_native.py'])
cli_class = next(node for node in cli_tree.body if isinstance(node, ast.ClassDef) and node.name == 'CliSession')
cli_methods = [node.name for node in cli_class.body if isinstance(node, ast.FunctionDef)
               and any(isinstance(n, ast.Compare) and isinstance(n.left, ast.Name)
                       and n.left.id == 'operation' for n in ast.walk(node))]
assert len(cli_methods) == 1
cli = branches('hepta/hia_cli_native.py', 'CliSession', cli_methods[0], 'operation')
assert [row['operation'] for row in core] == list(range(1, 20))
assert [row['operation'] for row in cli] == list(range(1, 42))
old_modules = json.loads((OLD/'PACKAGE-MODULES.json').read_bytes())
old_map = {row['path']: row for row in old_modules}
new_map = {row['path']: row for row in modules}
delta = dict(added=sorted(set(new_map)-set(old_map)), removed=sorted(set(old_map)-set(new_map)),
             changed=[name for name in sorted(set(old_map)&set(new_map))
                      if old_map[name]['blob'] != new_map[name]['git_blob_sha1']],
             previous_scope='752495d542d1cc7811321e37f3e7a3a140368d19')
project = tomllib.loads(raws['pyproject.toml'].decode())
summary = dict(schema='hia.full-repository-and-static-package-inventory.v2',
    status='PASSED_V89_SOURCE_STATIC_INVENTORY_NOT_WHOLE_NATIVE_CLOSURE',
    commit=META['commit'], tree=META['tree'], source_directory_name_is_not_a_version_identity=True,
    full_git_tree_recomputed=META['full_git_tree_recomputed'], repository_files=META['whole_leaves'],
    repository_bytes=META['whole_bytes'], top_level=META['top_level'], extensions=META['extensions'],
    package_module_count=len(modules), package_bytes=sum(row['bytes'] for row in modules),
    package_lines=sum(row['lines'] for row in modules), local_import_edges=len(local_edges),
    external_import_roots=[dict(module=name, local_runtime_stdlib=name in sys.stdlib_module_names,
                               importers=sorted(paths)) for name, paths in sorted(external.items())],
    pyproject=project, core_hosted_primitive_branches=core, cli_hosted_effect_branches=cli,
    prior_audit_delta=delta, all_package_original_bytes_git_matched=True,
    all_package_AST_parsed=True, product_imports_executed=False, tests_executed=False,
    limitations=['Static import edges include optional branches and are not a runtime trace.',
                 'The whole Git tree is inventoried; fresh physical reads cover all172 package modules and pyproject only.',
                 'AST parsing and source volume are not semantic or execution coverage.',
                 'This snapshot is v89; numeric/integer/CLI newer source drafts are separate.',
                 'The 19/41 dispatch branches remain even when HIA owns selected algorithms.'],
    whole_native_rewrite_complete=False, old_stack_deletion_ready=False)
records = [write('PACKAGE-MODULES.json', modules), write('LOCAL-IMPORT-EDGES.json', local_edges),
           write('PHYSICAL-PINS.json', physical), write('AUDIT.json', summary)]
write('MANIFEST.json', records)
print(json.dumps({key:summary[key] for key in ('commit','tree','repository_files','repository_bytes',
    'package_module_count','package_bytes','package_lines','local_import_edges','prior_audit_delta')}))

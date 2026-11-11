"""Read every tracked candidate blob and every Python AST at exact 0ef9541b.

This distinguishes a complete static inventory from dynamic or semantic closure.
New isolated native components have separate source manifests and are not silently
attributed to this unchanged Git tree.
"""
import ast
from collections import Counter
from hashlib import sha1, sha256
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent
REPO = ROOT / 'Hepta-agent-edit-native'
COMMIT = '0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5'
TREE = '6ef9e1713065436a3b1886fe9edcf0a4a1120773'


def git(*args):
    return subprocess.check_output(['git', '-C', str(REPO), *args])


assert git('rev-parse', 'HEAD').decode().strip() == COMMIT
assert git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE
assert not git('status', '--porcelain', '--untracked-files=no')
tree_raw = git('ls-tree', '-rz', '--full-tree', 'HEAD')
started = time.monotonic_ns()
files, python, package, tools, failures = [], [], [], [], []
extensions = Counter()
for record in tree_raw.split(b'\0'):
    if not record:
        continue
    metadata, path_raw = record.split(b'\t', 1)
    mode, kind, oid = metadata.decode().split()
    assert kind == 'blob'
    relative = path_raw.decode()
    path = REPO / relative
    if mode == '120000':
        assert path.is_symlink()
        raw = path.readlink().as_posix().encode()
    else:
        assert mode in ('100644', '100755') and path.is_file() and not path.is_symlink()
        raw = path.read_bytes()
        assert ('100755' if path.stat().st_mode & 0o111 else '100644') == mode
    assert sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == oid, relative
    extension = path.suffix or 'extensionless'
    extensions[extension] += 1
    files.append(dict(path=relative, mode=mode, git_blob=oid, bytes=len(raw), sha256=sha256(raw).hexdigest()))
    if path.suffix != '.py':
        continue
    try:
        parsed = ast.parse(raw, filename=relative)
    except Exception as exc:
        failures.append(dict(path=relative, error_class=type(exc).__name__, error=str(exc)))
        continue
    imports, literal_paths, native_switches = set(), set(), set()
    for node in ast.walk(parsed):
        if isinstance(node, ast.Import):
            imports.update(item.name for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = '.' * node.level + (node.module or '')
            imports.add(prefix)
            imports.update(prefix + '.' + item.name for item in node.names)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if ('hia_bootstrap/' in value or value.endswith(('.hia', '.hiaasm'))) and len(value) < 1024:
                literal_paths.add(value)
            if value.startswith(('HIA_', 'HEPTA_')) and len(value) < 160 and 'NATIVE' in value:
                native_switches.add(value)
    public = [node.name for node in parsed.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not node.name.startswith('_')]
    entry = dict(path=relative, sha256=sha256(raw).hexdigest(), lines=len(raw.splitlines()),
                 purpose=(ast.get_docstring(parsed) or '').split('\n')[0], imports=sorted(imports),
                 public_top_level_definitions=public, literal_hia_paths=sorted(literal_paths),
                 literal_native_switches=sorted(native_switches), native_replacement_proven_by_inventory=False)
    python.append(entry)
    if relative.startswith('hepta/'):
        package.append(entry)
    if relative.startswith('tools/'):
        tools.append(entry)
assert not failures, failures
assert git('ls-tree', '-rz', '--full-tree', 'HEAD') == tree_raw
assert not git('status', '--porcelain', '--untracked-files=no')
result = dict(schema='hia.complete-static-candidate-audit.v1', status='PASS_STATIC_INVENTORY_ONLY',
              repository='TrillionniumFoundation/Hepta', candidate_commit=COMMIT, candidate_tree=TREE,
              product_main='5831f52fada45e076f8f68f198a15c0585e6104f',
              counts=dict(files=len(files), bytes=sum(f['bytes'] for f in files), files_by_extension=dict(sorted(extensions.items())),
                          python_files=len(python), package_python_modules=len(package), hosted_tools=len(tools),
                          hia_assembly_files=extensions['.hiaasm'], hia_json_source_files=extensions['.hia']),
              files=files, package_modules=package, hosted_tools=tools, all_python_ASTs=python,
              scope=dict(all_tracked_blob_bytes_and_modes_equal_to_commit=True, all_retained_python_parsed=True,
                         new_isolated_development_components_in_this_commit=False,
                         every_line_semantically_audited=False, dynamic_call_closure_proven=False,
                         all_runtime_owners_native=False, old_stack_can_be_removed=False,
                         current_source_cold_and_full_retained_pass=False), elapsed_ns=time.monotonic_ns()-started)
target = OUT / 'candidate-static-inventory.json'
assert not target.exists()
target.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps(dict(status=result['status'], counts=result['counts'], inventory=str(target),
                     inventory_bytes=target.stat().st_size, inventory_sha256=sha256(target.read_bytes()).hexdigest()), sort_keys=True))

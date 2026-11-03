"""Conservative syntax inventory, not whole-program dataflow or an external census."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APIS = frozenset({'load_project', 'LoadedProject', 'load_package', 'Package',
                  'package_snapshot', 'verify_lock', 'write_lock', 'analyze_project', 'analyze'})
FIELDS = frozenset({'program', 'entry', 'sources', 'source_bytes', 'identity',
                    'modules', 'package', 'package_state', 'locked', 'bindings',
                    'c_imports', 'unchanged', 'report', 'project'})
RECEIVERS = frozenset({'project', 'loaded_project', 'graph', 'original'})


def inspect_source(text):
    tree = ast.parse(text)
    rows = set()
    aliases = set(APIS)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for name in node.names:
                if name.name in APIS:
                    aliases.add(name.asname or name.name)
                    rows.add((node.lineno, 'import', ast.unparse(node)))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, 'attr', None)
            if (name == 'getattr' and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in FIELDS
                    and isinstance(node.args[0], ast.Attribute)
                    and node.args[0].attr == 'project'):
                rows.add((node.lineno, 'reflective-surface', ast.unparse(node)))
            if name in aliases:
                rows.add((node.lineno, 'call', ast.unparse(node.func)))
        if isinstance(node, ast.Attribute) and node.attr in FIELDS:
            receiver = node.value.id if isinstance(node.value, ast.Name) else getattr(node.value, 'attr', None)
            if receiver in RECEIVERS or receiver == 'project':
                rows.add((node.lineno, 'surface', ast.unparse(node)))
    return [{'line': line, 'kind': kind, 'expression': expression}
            for line, kind, expression in sorted(rows)]


def inventory(root=ROOT):
    # Entire production package pinned, not only files where the heuristic matched.
    # This forces manual review on newly introduced aliases/reflective consumers.
    files, references = {}, {}
    for path in sorted((root / 'hepta').rglob('*.py')):
        data = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        files[relative] = hashlib.sha256(data).hexdigest()
        matches = inspect_source(data.decode('utf-8'))
        if matches:
            references[relative] = matches
    return {'schema': 'hepta.loader-consumer-audit.v1',
            'scope': 'production Python source syntax; manual dataflow review required',
            'source_sha256': files, 'references': references}


if __name__ == '__main__':
    print(json.dumps(inventory(), sort_keys=True, indent=2))

"""Parse fixed new controls only; never import their modules or run workers."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import time
root = Path(__file__).absolute().parent
started = time.monotonic_ns()
expected = {
    'controller.py': 'b2a17727804f9ae80f5a8757363a11e33c485fa2a1fd32f48546ac01cc727241',
    'controller.A1.original.py': '14951d857c6a6ed1a5e28f362b5e486af940bb597baa868e2f7848b9250db163',
    'source_authoring_worker.py': '22d05d8676c4f2e5a4d95387c925f28a3580eae268f3c8e85207abb6ea9a8217',
}
report = {'schema': 'hia.cli-json.remote-source-r3c.ast-control.v1', 'status': 'HOLD',
          'runtime': {'version': sys.version, 'executable': str(Path(sys.executable).resolve())},
          'files': [], 'errors': [], 'module_import_or_worker_execution': False,
          'source_generation': False, 'native_execution': False}
raws = {}
try:
    for name, digest in expected.items():
        raw = (root / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, name
        raws[name] = raw
        tree = ast.parse(raw, filename=name)
        report['files'].append({'path': str(root / name), 'bytes': len(raw),
                                'sha256': digest, 'top_level_functions': [
                                    node.name for node in tree.body if isinstance(node, ast.FunctionDef)]})
    old = ast.parse(raws['controller.A1.original.py'])
    new = ast.parse(raws['controller.py'])
    old_functions = {node.name: ast.dump(node, include_attributes=False)
                     for node in old.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    new_functions = {node.name: ast.dump(node, include_attributes=False)
                     for node in new.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    assert old_functions.keys() == new_functions.keys()
    changed = sorted(name for name in old_functions if old_functions[name] != new_functions[name])
    assert changed == ['copy_small_originals', 'finalize'], changed
    report['changed_functions'] = changed
    report['unchanged_top_level_functions'] = sorted(name for name in old_functions if name not in changed)
    report['parent_fd_decorator'] = [ast.dump(x, include_attributes=False) for x in next(
        n for n in new.body if isinstance(n, ast.FunctionDef) and n.name == 'parent_fd').decorator_list]
    assert report['parent_fd_decorator'] == ["Name(id='contextmanager', ctx=Load())"]
    for name, raw in raws.items():
        assert (root / name).read_bytes() == raw
    report['source_before_after_equal'] = True
    report['status'] = 'THREE_PYTHON_SYNTAX_AND_TWO_FUNCTION_DELTA_PASS_NO_EXECUTION'
except BaseException as error:
    import traceback
    report['errors'].append({'type': type(error).__name__, 'message': str(error),
                             'traceback': traceback.format_exc()})
report['elapsed_ns'] = time.monotonic_ns() - started
output = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
fd = os.open(root / 'AST-REPORT.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    at = 0
    while at < len(output):
        count = os.write(fd, output[at:])
        if count <= 0:
            raise OSError('short AST report write')
        at += count
    os.fsync(fd)
finally:
    os.close(fd)
assert (root / 'AST-REPORT.json').read_bytes() == output
print(json.dumps({'status': report['status'], 'report_bytes': len(output),
                  'report_sha256': hashlib.sha256(output).hexdigest(), 'elapsed_ns': report['elapsed_ns']},
                 sort_keys=True))
raise SystemExit(0 if not report['errors'] else 1)

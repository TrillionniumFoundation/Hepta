"""Execute actual boundary methods without importing unavailable compiler deps.

The selected AST nodes retain their original source filename/line identity.
This is explicitly a Python boundary/dispatch test, not full module import or
native qualification. The same test file must run against the restored package.
"""
import ast
from hashlib import sha1, sha256
import importlib.util
import json
from pathlib import Path
import sys
import time
import types
import unittest

root = Path(__file__).resolve().parent
mode = sys.argv[1]
source = root / ("original/hia_adaptive.py" if mode == "original" else "hepta/hia_adaptive.py")
raw = source.read_bytes()
blob_sha1 = sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
if mode == "original":
    assert blob_sha1 == "1b30383c47fbc2f1d3e100aa012126c6436f6f41", blob_sha1
tree = ast.parse(raw, filename=str(source))
selected = []
methods = {"_open", "_arguments", "call_many", "measure"}
for node in tree.body:
    if isinstance(node, ast.ClassDef) and node.name == "AdaptiveRejected":
        selected.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name == "_digest":
        selected.append(node)
    elif isinstance(node, ast.ClassDef) and node.name == "AdaptiveRuntime":
        node.body = [method for method in node.body
                     if isinstance(method, ast.FunctionDef) and method.name in methods]
        selected.append(node)

module = types.ModuleType("hepta.hia_adaptive")
module.__file__ = str(source)
module.__dict__.update(json=json, sha256=sha256, time=time, _MAX_BATCH=65536,
                       _identity=lambda: "argument-boundary-fixture")
exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), module.__dict__)
package = types.ModuleType("hepta")
package.__path__ = []
package.hia_adaptive = module
sys.modules["hepta"] = package
sys.modules["hepta.hia_adaptive"] = module
test_path = root / "tests/test_hia_adaptive_arguments.py"
spec = importlib.util.spec_from_file_location("argument_tests", test_path)
tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tests)
suite = unittest.defaultTestLoader.loadTestsFromTestCase(tests.AdaptiveArgumentSnapshotTests)
result = unittest.TextTestRunner(verbosity=2).run(suite)
record = {
    "mode": mode, "source_base_commit": "953fa62dee5aa563551d57b1374ab95b6d548b45",
    "source_sha256": sha256(raw).hexdigest(),
    "source_git_blob_sha1": blob_sha1,
    "test_sha256": sha256(test_path.read_bytes()).hexdigest(),
    "execution_scope": "actual AST-extracted boundary and dispatch methods with Python call spies",
    "full_package_imported": False, "native_compiler_or_code_executed": False,
    "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
    "skipped": len(result.skipped), "passed": result.wasSuccessful(),
    "failure_records": [{"test": str(test), "traceback": detail} for test, detail in result.failures],
    "error_records": [{"test": str(test), "traceback": detail} for test, detail in result.errors],
}
(root / (mode + "-boundary-result.json")).write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record))
sys.exit(0 if result.wasSuccessful() else 1)

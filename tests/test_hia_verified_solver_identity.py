"""Actual import/load controls prevent a proof from claiming replacement Z3 bytes."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOLVER = Path(importlib.util.find_spec("z3").origin).resolve().parent
PRELUDE = r'''
import ctypes, hashlib, importlib, json, os, py_compile, shutil, sys, types
from pathlib import Path
from unittest.mock import patch
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
sys.path.insert(1, sys.argv[2])
'''
CONTROLLED = r'''
from hepta.hia_safe_core import _solver_identity
from hepta.hia_solver_identity import VerifiedSolverRejected
import z3
def library_path():
    function = z3.z3core.Z3_get_version.__defaults__[0].f
    library, = [item for item in function._objects.values() if hasattr(item, '_name')]
    return Path(library._name)
def proof(name='candidate.so'):
    from hepta.hia_verified_scalar import build_verified_scalar
    from tests.test_hia_program import arithmetic
    return build_verified_scalar(arithmetic('int.div.checked', 'u64'), root / name)
def rejected(name='candidate.so'):
    try:
        proof(name)
    except VerifiedSolverRejected:
        pass
    else:
        raise AssertionError('unbound solver published a successful proof')
    assert not (root / name).exists()
'''


class VerifiedSolverIdentityTests(unittest.TestCase):
    def child(self, source):
        with tempfile.TemporaryDirectory(prefix="hia-solver-identity-") as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "hepta", root / "hepta", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(SOLVER, root / "z3", ignore=shutil.ignore_patterns("__pycache__"))
            result = subprocess.run([sys.executable, "-I", "-B", "-c",
                                     PRELUDE + textwrap.dedent(source), str(root), str(ROOT)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fresh_actual_proof_binds_all_executed_sources_and_native_mapping(self):
        self.child(CONTROLLED + r'''
identity = _solver_identity(z3)
binding = identity['load_binding']
assert binding['profile'] == 'hia.loaded-z3.python-source-and-library.linux.v1'
assert binding['controlled_import'] is True and binding['binding_code_matches_source'] is True
assert binding['preloaded_solver_authorized'] is False
files = {path.name: path.read_bytes() for path in (root / 'z3').glob('*.py')}
assert len(files) == 10
assert binding['binding_files'] == {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
digest = hashlib.sha256()
for name, raw in sorted(files.items()):
    digest.update(name.encode() + b'\0' + raw + b'\0')
assert identity['binding_sha256'] == digest.hexdigest()
library = library_path(); info = library.stat()
assert identity['library_sha256'] == hashlib.sha256(library.read_bytes()).hexdigest()
native = binding['library']
assert native['device_major'] == os.major(info.st_dev) and native['device_minor'] == os.minor(info.st_dev)
assert native['inode'] == info.st_ino and native['source_size'] == info.st_size
assert native['anchor_symbol'] == 'Z3_get_version' and native['mapped_executable_segments'] >= 1
assert native['file_identity_rechecked'] is True and native['loaded_mapping_bound'] is True
assert binding['monitor_sha256'] == hashlib.sha256((root / 'hepta/hia_solver_identity.py').read_bytes()).hexdigest()
report = proof()
assert report['validation']['complete'] and report['validation']['solver'] == identity
assert 'hia_solver_identity.py' in report['validation']['checker']['source_identity']
assert _solver_identity(z3) == identity
''')

    def test_preloaded_python_solver_cannot_be_registered_retroactively(self):
        self.child(r'''
import z3
from hepta.hia_safe_core import _solver_identity
from hepta.hia_solver_identity import VerifiedSolverRejected
try:
    _solver_identity(z3)
except VerifiedSolverRejected as error:
    assert 'before controlled admission' in str(error) and 'new process' in str(error)
else:
    raise AssertionError('already executing solver acquired a retroactive source identity')
''')

    def test_source_change_before_first_proof_never_receives_loaded_identity(self):
        for filename in ("__init__.py", "z3core.py", "z3.py"):
            for atomic in (False, True):
                with self.subTest(filename=filename, atomic=atomic):
                    self.child(CONTROLLED + r'''
filename, atomic = CHANGE
path = root / 'z3' / filename
changed = path.read_bytes() + b'\nraise RuntimeError("these replacement bindings did not execute")\n'
if atomic:
    replacement = path.with_suffix('.replacement')
    replacement.write_bytes(changed); os.replace(replacement, path)
else:
    path.write_bytes(changed)
assert z3.get_version_string() == '4.15.4'
rejected()
'''.replace('CHANGE', repr((filename, atomic))))

    def test_atomic_library_replacement_before_first_proof_is_rejected(self):
        self.child(CONTROLLED + r'''
library = library_path(); before = library.stat()
replacement = library.with_suffix('.replacement')
replacement.write_bytes(library.read_bytes() + b'\nnew-unloaded-file\n')
os.replace(replacement, library)
assert library.stat().st_ino != before.st_ino
assert z3.get_version_string() == '4.15.4'
rejected()
''')

    def test_same_inode_same_size_library_write_with_restored_mtime_is_rejected(self):
        self.child(CONTROLLED + r'''
library = library_path(); before = library.stat()
with library.open('r+b') as stream:
    stream.seek(-1, 2); original = stream.read(1)
    stream.seek(-1, 2); stream.write(bytes([original[0] ^ 1])); stream.flush(); os.fsync(stream.fileno())
os.utime(library, ns=(before.st_atime_ns, before.st_mtime_ns))
after = library.stat()
assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
rejected()
''')

    def test_same_inode_library_append_before_first_proof_is_rejected(self):
        self.child(CONTROLLED + r'''
library = library_path(); before = library.stat()
with library.open('ab') as stream:
    stream.write(b'\nchanged-after-load\n'); stream.flush(); os.fsync(stream.fileno())
assert library.stat().st_ino == before.st_ino
assert z3.get_version_string() == '4.15.4'
rejected()
''')

    def test_library_change_between_audit_capture_and_dlopen_is_rejected(self):
        for atomic in (False, True):
            with self.subTest(atomic=atomic):
                self.child(r'''
from hepta.hia_safe_core import _solver_identity
from hepta.hia_solver_identity import VerifiedSolverRejected
done = False
def change_after_capture(event, args):
    global done
    if event == 'ctypes.dlopen' and not done:
        done = True
        path = Path(args[0])
        changed = path.read_bytes() + b'\nchanged-in-loader-window\n'
        if ATOMIC:
            replacement = path.with_suffix('.replacement')
            replacement.write_bytes(changed); os.replace(replacement, path)
        else:
            path.write_bytes(changed)
sys.addaudithook(change_after_capture)
try:
    import z3
except VerifiedSolverRejected:
    pass
else:
    raise AssertionError('native import admitted bytes changed after its pre-load capture')
assert done
'''.replace('ATOMIC', repr(atomic)))

    def test_source_change_after_get_code_cannot_execute_a_second_snapshot(self):
        self.child(r'''
from hepta.hia_safe_core import _solver_identity
from hepta.hia_solver_identity import VerifiedSolverRejected
from importlib.machinery import SourceFileLoader
original = SourceFileLoader.get_code
changed = False
def raced(loader, name):
    global changed
    code = original(loader, name)
    if name == 'z3.z3types':
        path = Path(loader.path)
        path.write_bytes(path.read_bytes() + b'\nraise RuntimeError("changed after get_code")\n')
        changed = True
    return code
with patch.object(SourceFileLoader, 'get_code', raced):
    try:
        import z3
    except VerifiedSolverRejected:
        pass
    else:
        raise AssertionError('code/source capture race acquired an identity')
assert changed
''')

    def test_timestamp_valid_stale_solver_constants_and_nested_code_are_rejected(self):
        changes = (("z3consts.py", "Z3_L_TRUE = 1", "Z3_L_TRUE = 2"),
                   ("z3core.py", "if s != None:", "if s == None:"))
        for change in changes:
            with self.subTest(file=change[0]):
                self.child(r'''
filename, before_text, after_text = CHANGE
path = root / 'z3' / filename
raw = path.read_text(); before = path.stat()
assert raw.count(before_text) == 1 and len(before_text) == len(after_text)
py_compile.compile(str(path), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
path.write_text(raw.replace(before_text, after_text))
os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
assert path.stat().st_size == before.st_size
from hepta.hia_safe_core import _solver_identity
from hepta.hia_solver_identity import VerifiedSolverRejected
try:
    import z3
except VerifiedSolverRejected as error:
    assert 'stale bytecode' in str(error)
else:
    raise AssertionError('timestamp-valid stale solver code was accepted')
'''.replace('CHANGE', repr(change)))

    def test_reloads_and_replacement_module_objects_cannot_keep_old_authority(self):
        for reload in (False, True):
            with self.subTest(reload=reload):
                self.child(CONTROLLED + r'''
if RELOAD:
    try:
        importlib.reload(z3.z3core)
    except VerifiedSolverRejected:
        pass
    else:
        raise AssertionError('solver reload was admitted')
else:
    replacement = types.ModuleType('z3.z3core')
    replacement.__dict__.update(z3.z3core.__dict__)
    sys.modules['z3.z3core'] = replacement
rejected()
'''.replace('RELOAD', repr(reload)))

    def test_unexecuted_extra_source_and_missing_loaded_source_fail_closed(self):
        for extra in (False, True):
            with self.subTest(extra=extra):
                self.child(CONTROLLED + r'''
if EXTRA:
    (root / 'z3/unexecuted.py').write_text('raise RuntimeError("not imported")\n')
else:
    (root / 'z3/z3types.py').unlink()
rejected()
'''.replace('EXTRA', repr(extra)))

    def test_preloaded_native_library_cannot_receive_a_first_load_capture(self):
        for another in (False, True):
            with self.subTest(another_copy=another):
                self.child(r'''
library = root / 'z3/lib/libz3.so'
if ANOTHER:
    other = root / 'libz3-another.so'
    shutil.copyfile(library, other); library = other
keep = ctypes.CDLL(str(library))
from hepta.hia_safe_core import _solver_identity
import hepta.hia_solver_identity as monitor
try:
    import z3
except Exception:
    assert monitor._FAILURE is not None
else:
    raise AssertionError('pre-existing solver image acquired an initial load identity')
'''.replace('ANOTHER', repr(another)))

    def test_solver_source_drift_during_real_queries_withdraws_publication(self):
        self.child(CONTROLLED + r'''
original = z3.Solver.check
changed = False
def checking(solver, *args):
    global changed
    result = original(solver, *args)
    if not changed:
        changed = True
        path = root / 'z3/__init__.py'
        path.write_bytes(path.read_bytes() + b'\nraise RuntimeError("post-query replacement")\n')
    return result
with patch.object(z3.Solver, 'check', checking):
    rejected()
assert changed
''')

    def test_library_change_after_success_cannot_authorize_another_proof(self):
        self.child(CONTROLLED + r'''
first = proof('first.so')
assert first['validation']['complete']
library = library_path()
with library.open('ab') as stream:
    stream.write(b'\nchanged-between-proofs\n')
rejected('second.so')
assert (root / 'first.so').is_file()
''')


if __name__ == "__main__":
    unittest.main()

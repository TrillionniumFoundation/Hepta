"""Unselected Core helpers do not initialize an unrelated foreign ABI."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('hia_json_canonical_native', 'hia_json_decode_native', 'hia_sha256_native')


class OptionalForeignABISourceTests(unittest.TestCase):
    def child(self, body):
        source = 'import sys\nsys.path.insert(0, ' + repr(str(ROOT)) + ')\n' + body
        completed = subprocess.run([sys.executable, '-I', '-B', '-c', source],
                                   capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout, b'complete\n')

    def test_unselected_core_imports_and_real_foreign_hash_do_not_load_ctypes(self):
        self.child('''import importlib.abc, hashlib
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == 'ctypes' or name.startswith('ctypes.'):
            raise AssertionError('unselected import entered ctypes')
sys.meta_path.insert(0, Deny())
assert 'ctypes' not in sys.modules
from hepta import hia_program
from hepta import hia_json_canonical_native as canonical
from hepta import hia_json_decode_native as decode
from hepta import hia_sha256_native as sha
assert canonical.selected_canonical_wire('1', max_nodes=1, max_depth=0) is None
assert sha.payload_sha256(b'actual payload') == hashlib.sha256(b'actual payload').digest()
assert decode.arena_sizes(16, 10, 2)[0] > 0
assert 'ctypes' not in sys.modules
print('complete')
''')

    def test_invalid_profiles_remain_prior_to_real_foreign_import(self):
        self.child('''import importlib.abc
fault = ImportError('actual controlled ctypes import')
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == 'ctypes': raise fault
sys.meta_path.insert(0, Deny())
from hepta import hia_json_canonical_native as canonical
from hepta import hia_json_decode_native as decode
from hepta import hia_sha256_native as sha
for module, cls, method in ((canonical, canonical.NativeJsonCanonicalizer, 'canonicalize'),
                            (decode, decode.NativeJsonDecoder, 'arena'),
                            (sha, sha.NativeSha256, 'digest')):
    instance = object.__new__(cls)
    arguments = {} if module is sha else {'max_nodes': 8, 'max_depth': 2}
    for invalid in ('text', bytearray(1), b'x' * (module.MAX_BYTES + 1)):
        try: getattr(instance, method)(invalid, **arguments)
        except ValueError: pass
        else: raise AssertionError('invalid profile accepted')
    for repetition in range(2):
        try: getattr(instance, method)(b'1', **arguments)
        except ImportError as error: assert error is fault
        else: raise AssertionError('selected import refusal was hidden')
        assert 'ctypes' not in vars(module)
assert 'ctypes' not in sys.modules
print('complete')
''')

    def test_live_module_replacements_and_recursive_import_refusal_are_preserved(self):
        self.child('''import types
from hepta import hia_json_canonical_native as canonical
from hepta import hia_json_decode_native as decode
from hepta import hia_sha256_native as sha
assert 'ctypes' not in sys.modules
partial = types.ModuleType('ctypes')
partial.__spec__ = types.SimpleNamespace(_initializing=True)
sys.modules['ctypes'] = partial
for module in (canonical, decode, sha):
    try: module._ensure_ctypes()
    except RuntimeError as error: assert str(error) == 'native ctypes import is still active'
    else: raise AssertionError('partial FFI was admitted')
    assert 'ctypes' not in vars(module)
    replacement = object()
    module.ctypes = replacement
    assert module._ensure_ctypes() is replacement
    del module.ctypes
del sys.modules['ctypes']
import ctypes
for module in (canonical, decode, sha):
    assert module.ctypes is ctypes
    assert vars(module)['ctypes'] is ctypes
    for name in ('unrelated', '_missing'):
        try: getattr(module, name)
        except AttributeError: pass
        else: raise AssertionError('unrelated name was synthesized')
print('complete')
''')

    def test_actual_selected_methods_use_each_dynamic_buffer_provider(self):
        self.child('''import ctypes, types
from hepta import hia_json_canonical_native as canonical
from hepta import hia_json_decode_native as decode
from hepta import hia_sha256_native as sha
for module, cls, method, returned in ((canonical, canonical.NativeJsonCanonicalizer, 'canonicalize', 1),
        (decode, decode.NativeJsonDecoder, 'arena', 64), (sha, sha.NativeSha256, 'digest', 32)):
    instance = object.__new__(cls)
    calls = []
    def allocate(*arguments):
        calls.append(arguments)
        return ctypes.create_string_buffer(*arguments)
    def entry(source, size, out, capacity, state, extent):
        assert ctypes.string_at(source, size) == b'1'
        assert capacity == len(out) and extent == len(state)
        return returned
    instance._entry = entry
    module.ctypes = types.SimpleNamespace(create_string_buffer=allocate)
    arguments = {} if module is sha else {'max_nodes': 8, 'max_depth': 2}
    result = getattr(instance, method)(b'1', **arguments)
    assert type(result) is bytes and len(result) == returned
    assert len(calls) == 3 and calls[0] == (b'1', 1)
    fault = MemoryError('actual replacement provider refusal')
    def refused(*arguments): raise fault
    module.ctypes = types.SimpleNamespace(create_string_buffer=refused)
    try: getattr(instance, method)(b'1', **arguments)
    except MemoryError as error: assert error is fault
    else: raise AssertionError('later provider replacement was ignored')
print('complete')
''')

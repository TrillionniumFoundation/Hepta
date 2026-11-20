"""Real UUID providers remain dynamic while unused imports stay uninitialized."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/uuid_provider_972_reference_bodies.json'
FIXTURE_SHA256 = '459ada2affd9a2a0aa421ce96da88ba21a2eab13f59f7a6ac319ddf90fe03afe'
METHODS = {
    'hepta/hia_agent_service.py:HIAAgentService._reference_call',
    'hepta/hia_agent_service.py:HIAAgentService._hia_context_reference',
    'hepta/hia_agent_service.py:HIAAgentService._reference_slot_acquire',
    'hepta/hia_agent_store.py:AgentStore._put_reference',
}


class UUIDProviderSourceTests(unittest.TestCase):
    def child(self, body):
        source = 'import sys\nsys.path.insert(0, ' + repr(str(ROOT)) + ')\n' + body
        completed = subprocess.run([sys.executable, '-I', '-B', '-c', source],
                                   capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout, b'complete\n')

    def test_all_original_identifier_method_bodies_remain_exact(self):
        raw = (ROOT / FIXTURE).read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), FIXTURE_SHA256)
        fixed = json.loads(raw)
        self.assertEqual(fixed['base_head'], '972ecbb9ae7535d7526f655eed87b75c563dec13')
        self.assertEqual(set(fixed['complete_identifier_method_bodies']), METHODS)
        for identifier, expected in fixed['complete_identifier_method_bodies'].items():
            path, qualified = identifier.split(':')
            owner, name = qualified.split('.')
            current = (ROOT / path).read_bytes()
            cls = next(node for node in ast.parse(current).body
                       if isinstance(node, ast.ClassDef) and node.name == owner)
            node = next(node for node in cls.body
                        if isinstance(node, ast.FunctionDef) and node.name == name)
            body = b''.join(current.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
            self.assertEqual({'bytes': len(body), 'sha256': sha256(body).hexdigest()}, expected)

    def test_unused_imports_stay_uninitialized_and_explicit_uuid_is_same_real_module(self):
        self.child('''from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
assert 'uuid' not in sys.modules and '_uuid' not in sys.modules
for module in (service, store):
    assert 'uuid' not in vars(module) and not module._UUID_PROVIDER_BOUND
actual = service.uuid
import uuid
assert actual is uuid and vars(service)['uuid'] is uuid
assert store.uuid is uuid and vars(store)['uuid'] is uuid
assert type(uuid.uuid4()) is uuid.UUID
from unittest.mock import patch
token = object()
with patch('hepta.hia_agent_service.uuid.uuid4', return_value=token):
    assert service.uuid.uuid4() is token and store.uuid.uuid4() is token
assert type(uuid.uuid4()) is uuid.UUID
for module in (service, store):
    try: getattr(module, 'unrelated_uuid_name')
    except AttributeError as error:
        assert str(error) == "module %r has no attribute 'unrelated_uuid_name'" % module.__name__
    else: raise AssertionError('unrelated module attribute synthesized')
print('complete')
''')

    def test_failed_and_recursive_imports_do_not_bind_and_import_time_replacement_wins(self):
        self.child('''import builtins, types
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
real_import = builtins.__import__
fault = ImportError('same actual identifier import failure')
def refused(name, *args, **kwargs):
    if name == 'uuid': raise fault
    return real_import(name, *args, **kwargs)
for module in (service, store):
    builtins.__import__ = refused
    try:
        for repetition in range(2):
            try: module._ensure_uuid()
            except ImportError as error: assert error is fault
            else: raise AssertionError('provider import failure hidden')
            assert 'uuid' not in vars(module) and not module._UUID_PROVIDER_BOUND
    finally: builtins.__import__ = real_import
partial = types.ModuleType('uuid')
partial.__spec__ = types.SimpleNamespace(_initializing=True)
sys.modules['uuid'] = partial
for module in (service, store):
    try: module.uuid
    except RuntimeError as error: assert str(error) == 'identifier uuid import is still active'
    else: raise AssertionError('incomplete identifier module was bound')
    assert 'uuid' not in vars(module) and not module._UUID_PROVIDER_BOUND
del sys.modules['uuid']
for module in (service, store):
    token = object()
    def rebind(name, *args, **kwargs):
        if name == 'uuid': module.uuid = token
        return real_import(name, *args, **kwargs)
    builtins.__import__ = rebind
    try: assert module._ensure_uuid() is token
    finally: builtins.__import__ = real_import
    assert vars(module)['uuid'] is token and module._UUID_PROVIDER_BOUND
print('complete')
''')

    def test_replacement_deletion_and_builtin_lookup_are_not_repaired(self):
        self.child('''import builtins
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
for module in (service, store):
    module.uuid = None
    assert module._ensure_uuid() is None and module._UUID_PROVIDER_BOUND
    assert 'uuid' not in sys.modules
    provider = object()
    module.uuid = provider
    assert module._ensure_uuid() is provider
    del module.uuid
    try: module.uuid
    except AttributeError: pass
    else: raise AssertionError('deliberate module deletion repaired')
    try: module._ensure_uuid()
    except NameError as error: assert error.name == 'uuid'
    else: raise AssertionError('deliberate global deletion repaired')
    builtins.uuid = provider
    try: assert module._ensure_uuid() is provider
    finally: del builtins.uuid
    assert 'uuid' not in vars(module) and 'uuid' not in sys.modules
print('complete')
''')

    def test_actual_context_uuid_port_keeps_explicit_lookup_order_and_error_identity(self):
        self.child('''from types import SimpleNamespace
from hepta import hia_agent_service as service
from hepta import hia_service_context_native as native
trace, primary = [], RuntimeError('same uuid provider failure')
class Identifier:
    @property
    def hex(self):
        trace.append('hex')
        return 'e' * 32
class Provider:
    def uuid4(self):
        trace.append('uuid4')
        return Identifier()
provider = Provider()
class Namespace(dict):
    def __getitem__(self, key):
        trace.append(('get', key))
        return super().__getitem__(key)
frame = object.__new__(native.ContextFrame)
frame.service = None
frame.data = {'manifest': {'sha256': 's' * 64}}
frame.namespace = Namespace(uuid=provider)
frame.effect(43)
assert frame.data['context'] == {'id': 'ctx-' + 'e' * 32, 'sha256': 's' * 64}
assert trace == [('get', 'uuid'), 'uuid4', 'hex']
assert 'uuid' not in vars(service) and not service._UUID_PROVIDER_BOUND
frame.namespace = {}
try: frame.effect(43)
except KeyError as error: assert error.args == ('uuid',)
else: raise AssertionError('explicit missing provider repaired')
class Refused:
    def uuid4(self): raise primary
frame.namespace = {'uuid': Refused()}
try: frame.effect(43)
except RuntimeError as error: assert error is primary
else: raise AssertionError('provider exception replaced')
service.uuid = provider
frame.namespace = vars(service)
trace.clear()
frame.effect(43)
assert trace == ['uuid4', 'hex'] and service._UUID_PROVIDER_BOUND
del service.uuid
try: frame.effect(43)
except KeyError as error: assert error.args == ('uuid',)
else: raise AssertionError('post-use default deletion repaired')
assert 'uuid' not in sys.modules
print('complete')
''')

    def test_actual_store_lookup_keeps_explicit_namespace_builtins_and_default_binding(self):
        self.child('''from hepta import hia_agent_store as store
from hepta import hia_store_artifact_profile_native as native
frame = object.__new__(native.StoreArtifactProfileFrame)
provider, builtin_provider = object(), object()
frame.namespace, frame.global_builtins = {'uuid': provider}, {'uuid': builtin_provider}
assert frame._global('uuid') is provider
assert 'uuid' not in vars(store) and not store._UUID_PROVIDER_BOUND
frame.namespace = {}
assert frame._global('uuid') is builtin_provider
frame.global_builtins = {}
try: frame._global('uuid')
except NameError as error: assert error.name == 'uuid'
else: raise AssertionError('explicit missing provider repaired')
primary = RuntimeError('same actual namespace refusal')
class Refused(dict):
    def __getitem__(self, key): raise primary
frame.namespace = Refused()
try: frame._global('uuid')
except RuntimeError as error: assert error is primary
else: raise AssertionError('namespace exception replaced')
assert 'uuid' not in sys.modules
frame.namespace = vars(store)
actual = frame._global('uuid')
import uuid
assert actual is uuid and store.uuid is uuid and store._UUID_PROVIDER_BOUND
store.uuid = provider
assert frame._global('uuid') is provider
del store.uuid
frame.global_builtins = {'uuid': builtin_provider}
assert frame._global('uuid') is builtin_provider
assert 'uuid' not in vars(store)
print('complete')
''')


if __name__ == '__main__':
    unittest.main()

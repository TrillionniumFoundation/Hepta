"""Frozen original describe observer with no product-derived expectations.

The complete finite input inventory is fixed independently of the candidate.
The command-line observer saves every original row before importing a VM,
adapter, generated source or native image. Error metadata and destruction order
are observed in the actual interpreter; they are never normalized across it.
"""
from __future__ import annotations

import argparse
import ast
import builtins
from collections import Counter
from hashlib import sha1, sha256
import importlib.abc
import json
import os
from pathlib import Path
import platform
import sys
import types
import weakref

REPOSITORY = Path(__file__).resolve().parents[1]
ROOT = Path(__file__).resolve().parent / 'fixtures/hia_service_describe_original_3424'
ORIGINAL = ROOT / 'describe.3424.py.txt'
ORIGINAL_BYTES = 1992
ORIGINAL_SHA256 = 'bfed8acb543c9234c553c3e01ff37bfa24233c1a8b57adae3215a2839fc6c481'
ORIGINAL_GIT_BLOB_SHA1 = 'd8919b32ecfb528bacdd60fdf516cadc1573ea6f'
# This is the unmodified source-authoring CPython 3.12.14 dump identity.
# ast.dump formatting is runtime-specific; live structure is compared to the
# independently pinned source parsed by that same runtime below.
ORIGINAL_AST_SHA256 = '47f8d551356d60cd31574e6f8c41324240bad3413023df966ae34f36ac0f4fe4'
FREEZE_SHA256 = '04ca13dab6daa102bada5b7069687e058a57ebea2efe38d602d7e97b1e78425d'
LATE = []
GLOBAL_PHASE = 'setup'


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()


def original_inputs():
    raw = (ROOT / 'freeze.json').read_bytes()
    if sha256(raw).hexdigest() != FREEZE_SHA256:
        raise AssertionError('independent describe input freeze changed')
    frozen = json.loads(raw)
    for name, row in frozen['inputs'].items():
        value = (ROOT / name).read_bytes()
        if len(value) != row['bytes'] or sha256(value).hexdigest() != row['sha256']:
            raise AssertionError('independent describe input changed: ' + name)
    values = json.loads((ROOT / 'cases.json').read_bytes())['cases']
    if (len(values) != frozen['case_count'] or len(values) != 291
            or [case['id'] for case in values] != frozen['ordered_ids']):
        raise AssertionError('complete original describe case identities changed')
    return values


def frozen_code():
    raw = ORIGINAL.read_bytes()
    blob = b'blob ' + str(len(raw)).encode() + b'\0' + raw
    if (len(raw) != ORIGINAL_BYTES or sha256(raw).hexdigest() != ORIGINAL_SHA256
            or sha1(blob).hexdigest() != ORIGINAL_GIT_BLOB_SHA1):
        raise AssertionError('original describe method bytes changed')
    text = 'class Original:\n' + raw.decode()
    tree = ast.parse(text)
    method = tree.body[0].body[0]
    runtime_ast = ast.dump(method, include_attributes=False)
    namespace = {}
    exec(compile(text, str(ORIGINAL), 'exec', dont_inherit=True), namespace)
    return vars(namespace['Original'])['_hia_describe'].__code__, runtime_ast


ORIGINAL_CODE, ORIGINAL_RUNTIME_AST_DUMP = frozen_code()


class NoProduct(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('hepta', 'tools') or fullname.startswith(('hepta.', 'tools.')):
            raise AssertionError('original-only observer imported product: ' + fullname)


def no_effect(event, arguments):
    if (event in {'subprocess.Popen', 'os.system', 'sqlite3.connect', 'ctypes.dlopen',
                  'ctypes.dlsym', 'socket.__new__', 'os.fork', 'os.forkpty', 'os.posix_spawn'}
            or event.startswith('os.exec')):
        raise AssertionError('original-only describe provider attempted effect: ' + event)


class Namespace(dict):
    pass


class Harness:
    def __init__(self, case):
        self.case = case
        self.events, self.durable_rows = [], []
        self.tags, self.refs, self.serials, self.error_ids = {}, {}, {}, {}
        self.hits = Counter()
        self.faults = self.store_lookups = self.profile_calls = 0
        self.namespace = self.service = None
        self.phase, self.closed = 'setup', False

    def label(self, kind):
        self.serials[kind] = self.serials.get(kind, 0) + 1
        return kind + str(self.serials[kind])

    def tag(self, value, name):
        reference = weakref.ref(value)
        self.tags[id(value)] = (name, reference)
        self.refs[name] = reference
        return value

    def view(self, value):
        kind = type(value)
        if kind in (str, int, bool, type(None), float):
            return value
        if kind is bytes:
            return {'bytes': len(value), 'sha256': sha256(value).hexdigest()}
        tagged = self.tags.get(id(value))
        if tagged is not None and tagged[1]() is value:
            return {'object': tagged[0], 'type': kind.__name__}
        if kind in (tuple, list):
            return [self.view(item) for item in value]
        if kind is dict:
            return {key: self.view(item) for key, item in value.items()}
        return {'unlabelled_type': kind.__name__}

    def active(self):
        error = sys.exception()
        return None if error is None else self.error_ids.get(id(error), type(error).__name__)

    def note(self, point, **values):
        row = {'event': point, 'phase': self.phase, 'active_exception': self.active(),
               **{key: self.view(value) for key, value in values.items()}}
        if self.closed:
            LATE.append({'case': self.case['id'], 'observer_phase': GLOBAL_PHASE, **row})
        else:
            self.events.append(row)

    def error(self, point, kind=None):
        cls = getattr(builtins, kind or self.case['error_type'])
        error = cls('fault:' + point)
        self.error_ids[id(error)] = 'fault:' + point
        return error

    def hit(self, point, **values):
        self.hits[point] += 1
        self.note(point, occurrence=self.hits[point], **values)
        if self.case.get('fault') == point and self.hits[point] == self.case.get('fault_at', 1):
            self.faults += 1
            raise self.error(point)

    def importer(self, name, globals=None, locals=None, fromlist=(), level=0):
        self.hit('import.call', name=name, fromlist=fromlist, level=level,
                 original_globals=globals is self.namespace())
        if self.case.get('latebind') == 'import_reject':
            self.namespace()['reject'] = self.rebound_reject
        return CatalogModule(self)

    def catalog(self, schema):
        self.hit('catalog.call', schema=schema)
        if self.case.get('schema_mode') == 'unsupported':
            raise self.error('unsupported-language-schema', 'ValueError')
        if self.case.get('latebind') == 'catalog_reject':
            self.namespace()['reject'] = self.rebound_reject
        return Tracked(self, 'language')

    def reject(self, code, message):
        self.hit('reject.call', code=code, message=message)
        if self.case['reject_returns']:
            return Ignored(self, 'reject-result')
        error = ValueError(code + ':' + message)
        self.error_ids[id(error)] = 'rejection:' + code
        try:
            raise error
        finally:
            del error

    def rebound_reject(self, code, message):
        self.note('reject.rebound')
        return self.reject(code, message)

    def profile(self, schema, language, receiver):
        self.profile_calls += 1
        self.hit('store.profile.call', schema=schema, language=language, receiver=receiver)
        self.durable_rows.append({'schema': self.view(schema), 'language': self.view(language)})
        self.note('store.profile.persisted', count=len(self.durable_rows))
        if self.case['store_mode'] == 'replace-in-profile':
            self.service()._stored = Store(self, 'replacement')
            self.note('store.replaced-on-service')
        mode = self.case['pair_mode']
        if mode == 'not-iterable':
            return Tracked(self, 'profile-noniterable')
        values = [Tracked(self, 'profile'), Tracked(self, 'language-ref')]
        if mode == 'zero':
            return ()
        if mode == 'one':
            return (values[0],)
        if mode == 'three':
            return (*values, Tracked(self, 'extra-profile-value'))
        if mode == 'tuple':
            return tuple(values)
        return ProfilePair(self, values)


class Tracked:
    def __init__(self, harness, name):
        self.h, self.name = harness, name
        harness.tag(self, name)

    def __del__(self):
        self.h.note(self.name + '.delete')


class Ignored(Tracked):
    def __bool__(self):
        self.h.note(self.name + '.unexpected-truth')
        raise AssertionError('ignored provider return was tested')


class Truth(Tracked):
    def __init__(self, harness, name, mode):
        super().__init__(harness, name)
        self.mode = mode

    def __bool__(self):
        self.h.hit(self.name + '.truth')
        if self.mode == 'bad':
            return 'not-a-bool'
        return self.mode != 'false'


class BackendToken(Tracked):
    def __init__(self, harness):
        super().__init__(harness, 'backend-token')

    def __ne__(self, other):
        self.h.hit('backend.ne', other=other)
        mode = self.h.case['backend_comparison']
        return NotImplemented if mode == 'notimplemented' else Truth(self.h, 'backend', mode)


class SectionKey(Tracked):
    def __init__(self, harness):
        super().__init__(harness, 'section-key')

    def __hash__(self):
        self.h.hit('section.hash')
        if self.h.case['section_mode'] == 'hash-fault':
            raise self.h.error('section.hash')
        return hash(self.h.case['section'])

    def __eq__(self, other):
        self.h.hit('section.eq', other=other)
        mode = self.h.case['section_mode']
        if mode == 'eq-fault':
            raise self.h.error('section.eq')
        if mode == 'eq-bad':
            return Truth(self.h, 'section-eq', 'bad')
        return mode != 'eq-false' and other == self.h.case['section']


class TraceMap:
    def __init__(self, harness, name, values):
        self.h, self.name, self.values = harness, name, values
        harness.tag(self, name)

    def __getattribute__(self, name):
        if name == 'get':
            harness = object.__getattribute__(self, 'h')
            harness.hit(object.__getattribute__(self, 'name') + '.get.lookup')
        return object.__getattribute__(self, name)

    def __contains__(self, key):
        self.h.hit(self.name + '.contains.' + key)
        if key == 'cursor' and self.h.case.get('latebind') == 'cursor_reject':
            self.h.namespace()['reject'] = self.h.rebound_reject
        override = 'contains_cursor' if key == 'cursor' else 'contains_backend'
        if override in self.h.case:
            return Truth(self.h, self.name + '.contains.' + key, self.h.case[override])
        return key in self.values

    def __getitem__(self, key):
        self.h.hit(self.name + '.getitem.' + key)
        return self.values[key]

    def get(self, key, default=None):
        self.h.hit(self.name + '.get.call', key=key, default=default)
        return self.values.get(key, default)


class CatalogModule:
    def __init__(self, harness):
        self.h = harness
        harness.tag(self, 'catalog-module')

    def __getattribute__(self, name):
        if name == 'opcode_catalog':
            harness = object.__getattribute__(self, 'h')
            harness.hit('module.catalog.lookup')
            mode = harness.case.get('catalog_mode')
            if mode == 'missing':
                raise AttributeError('opcode_catalog')
            if mode == 'descriptor-fault':
                raise harness.error('module.catalog.descriptor')
            if mode == 'non-callable':
                return None
            return CatalogCallable(harness)
        return object.__getattribute__(self, name)

    def __del__(self):
        self.h.note('catalog-module.delete')


class CatalogCallable(Tracked):
    def __init__(self, harness):
        super().__init__(harness, 'catalog-callable')

    def __call__(self, schema):
        return self.h.catalog(schema)


class ProfilePair(Tracked):
    def __init__(self, harness, values):
        super().__init__(harness, 'profile-pair')
        self.values = values

    def __iter__(self):
        self.h.hit('profile-pair.iter')
        if self.h.case['pair_mode'] == 'iter-fault':
            raise self.h.error('profile-pair.iter')
        return PairIterator(self.h, self.values)


class PairIterator(Tracked):
    def __init__(self, harness, values):
        super().__init__(harness, 'profile-iterator')
        self.values, self.index = values, 0

    def __iter__(self):
        return self

    def __next__(self):
        index = self.index
        self.index += 1
        self.h.hit('profile-pair.next', index=index)
        if self.h.case['pair_mode'] == 'next' + str(index) + '-fault':
            raise self.h.error('profile-pair.next' + str(index))
        if index >= len(self.values):
            raise StopIteration
        return self.values[index]


class ProfileCallable(Tracked):
    def __init__(self, harness, store, retain):
        super().__init__(harness, 'profile-callable')
        self.store, self.receiver = store if retain else None, store.label
        harness.note('profile-callable.create', retained_receiver=retain)

    def __call__(self, schema, language):
        return self.h.profile(schema, language, self.receiver)


class Store:
    def __init__(self, harness, role='store'):
        self.h, self.label = harness, harness.label(role)
        harness.tag(self, self.label)
        harness.note('store.create', receiver=self.label)

    def __getattribute__(self, name):
        if name == 'profile':
            harness = object.__getattribute__(self, 'h')
            harness.hit('store.profile.lookup', receiver=object.__getattribute__(self, 'label'))
            mode = harness.case['profile_binding']
            if mode != 'method':
                return ProfileCallable(harness, self, mode == 'bound-callable')
        return object.__getattribute__(self, name)

    def profile(self, schema, language):
        return self.h.profile(schema, language, self.label)

    def __del__(self):
        self.h.note('store.delete', receiver=self.label)


class StoreDescriptor:
    def __get__(self, instance, owner):
        if instance is None:
            return self
        harness = object.__getattribute__(instance, '_h')
        harness.note('store.descriptor.get')
        return Store(harness)


RESOURCE_KEYS = ('schema_registry', 'assembly_grammar', 'core_language',
    'byte_bootstrap_guide', 'self_hosting_core_guide', 'self_hosting_core_support',
    'machine_validation_guide', 'proof_contract_guide', 'buffer_lifecycle_guide',
    'examples', 'diagnostics', 'plan_schema', 'machine_plan_guide', 'macro_policy',
    'macro_policy_guide')


class Service:
    def __init__(self, harness):
        self._h = harness
        harness.tag(self, 'service')
        harness.service = weakref.ref(self)
        self._stored = (Store(harness) if harness.case['store_mode']
                        in ('persistent', 'replace-in-profile') else None)
        resources = {name: 'resource:' + name for name in RESOURCE_KEYS}
        resources.pop(harness.case.get('missing_resource'), None)
        artifacts = {name: 'profile-artifact:' + name
                     for name in ('backend', 'lowering', 'target', 'validation', 'plan')}
        artifacts.pop(harness.case.get('missing_profile_artifact'), None)
        profiles = {'backend': TraceMap(harness, 'backend-profile', {'id': 'backend-id'}),
                    'artifact': 'artifact-profile'}
        profiles.pop(harness.case.get('missing_profile'), None)
        self._resources = TraceMap(harness, 'resources', resources)
        self._artifacts = TraceMap(harness, 'profile_artifacts', artifacts)
        self._profiles = TraceMap(harness, 'profiles', profiles)

    def __getattribute__(self, name):
        if name in ('store', 'resources', 'profile_artifacts', 'profiles', 'manifest', 'catalog_sha256'):
            harness = object.__getattribute__(self, '_h')
            harness.hit('service.' + name)
            if name == 'store':
                harness.store_lookups += 1
                mode = harness.case['store_mode']
                if mode == 'descriptor':
                    return object.__getattribute__(self, name)
                if mode in ('temporary', 'changing'):
                    return Store(harness)
                return object.__getattribute__(self, '_stored')
            if name == 'manifest':
                return 'manifest-reference'
            if name == 'catalog_sha256':
                return 'c' * 64
            return object.__getattribute__(self, {'resources': '_resources',
                'profile_artifacts': '_artifacts', 'profiles': '_profiles'}[name])
        return object.__getattribute__(self, name)


class DescriptorService(Service):
    store = StoreDescriptor()


def namespace(harness):
    result = Namespace(__name__='hepta.hia_agent_service', __package__='hepta')
    bound_builtins = dict(vars(builtins))
    bound_builtins['__import__'] = harness.importer
    if harness.case.get('missing_import'):
        del bound_builtins['__import__']
    if harness.case.get('noncallable_import'):
        bound_builtins['__import__'] = None
    result['__builtins__'] = bound_builtins
    if not harness.case.get('missing_reject'):
        target = bound_builtins if harness.case.get('reject_in_builtins') else result
        target['reject'] = None if harness.case.get('noncallable_reject') else harness.reject
    harness.namespace = weakref.ref(result)
    return result


def arguments(harness):
    case = harness.case
    mode = case.get('section_mode')
    section = (SectionKey(harness) if mode in ('key', 'hash-fault', 'eq-fault', 'eq-bad', 'eq-false')
               else [] if mode == 'list' else None if mode == 'none' else case['section'])
    values = {} if mode == 'missing' else {'section': section}
    if case['cursor']:
        values['cursor'] = 'cursor-token'
    if case['backend']:
        values['backend_profile'] = (BackendToken(harness) if 'backend_comparison' in case
            else 'another-backend' if case.get('backend_mismatch') else 'backend-id')
    schema = case.get('schema_mode')
    if schema not in (None, 'missing'):
        values['language_schema'] = (Tracked(harness, 'language-schema') if schema == 'object'
            else None if schema == 'none' else '' if schema == 'empty' else 'not-supported')
    return TraceMap(harness, 'args', values)


def error_record(harness, error, seen=None):
    seen = set() if seen is None else seen
    if id(error) in seen:
        return {'cycle': type(error).__name__}
    seen.add(id(error))
    get = BaseException.__getattribute__
    result = {'type': type(error).__name__, 'identity': harness.error_ids.get(id(error)),
              'args': harness.view(get(error, 'args')),
              'suppress_context': get(error, '__suppress_context__')}
    for name in ('name', 'obj', '__notes__'):
        try:
            value = get(error, name)
        except AttributeError:
            continue
        result[name] = harness.view(value)
    for name in ('__cause__', '__context__'):
        other = get(error, name)
        result[name] = None if other is None else error_record(harness, other, seen)
    return result


def original_factory(ns):
    return types.FunctionType(ORIGINAL_CODE, ns)


def invoke(harness, function, service, args):
    try:
        result = function(service, args)
    except BaseException as error:
        harness.phase = 'caller-exception'
        return {'status': 'raised', 'error': error_record(harness, error)}
    else:
        harness.phase = 'caller-result'
        return {'status': 'returned', 'value': harness.view(result)}


def observe(case, *, factory=original_factory):
    harness = Harness(case)
    ns = namespace(harness)
    function = factory(ns)
    service = (DescriptorService if case['store_mode'] == 'descriptor' else Service)(harness)
    args = arguments(harness)
    harness.phase = 'call'
    if case['outer']:
        try:
            error = KeyError('outer-error')
            harness.error_ids[id(error)] = 'outer-error'
            raise error
        except KeyError:
            del error
            outcome = invoke(harness, function, service, args)
            harness.note('caller.outer-after')
    else:
        outcome = invoke(harness, function, service, args)
    harness.phase = 'caller-input-release'
    del service, args, function, ns
    record = {'case': case['id'], 'outcome': outcome, 'trace': harness.events,
        'faults_reached': harness.faults, 'actual_profile_calls': harness.profile_calls,
        'store_lookups': harness.store_lookups, 'durable_rows': harness.durable_rows,
        'weakly_observed_alive': {name: ref() is not None
                                for name, ref in sorted(harness.refs.items())}}
    raw = canonical(record)
    harness.closed = True
    return json.loads(raw)


def differences(expected, actual, path='$'):
    if type(expected) is not type(actual):
        return [{'path': path, 'expected': expected, 'actual': actual}]
    rows = []
    if type(expected) is dict:
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                rows.append({'path': path + '.' + key, 'expected': expected.get(key), 'actual': actual.get(key)})
            else:
                rows.extend(differences(expected[key], actual[key], path + '.' + key))
    elif type(expected) is list:
        if len(expected) != len(actual):
            rows.append({'path': path + '.length', 'expected': len(expected), 'actual': len(actual)})
        for index, (left, right) in enumerate(zip(expected, actual)):
            rows.extend(differences(left, right, path + '[' + str(index) + ']'))
    elif expected != actual:
        rows.append({'path': path, 'expected': expected, 'actual': actual})
    return rows


def source_pins():
    paths = ['tests/hia_service_describe_oracle.py', 'tests/test_hia_service_describe_native.py']
    paths += [str(path.relative_to(REPOSITORY)) for path in sorted(ROOT.iterdir()) if path.is_file()]
    return {name: sha256((REPOSITORY / name).read_bytes()).hexdigest() for name in paths}


def independent_vm_image(program):
    import ctypes
    from hepta import hia_service_describe_native as native
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    image = object.__new__(native.NativeServiceDescribe)
    image.image_sha256, image.entry_count = 'independent-vm-no-executable-mapping', 0

    def entry(source, size, output, capacity, state, extent):
        image.entry_count += 1
        raw = ctypes.string_at(source, size)
        buffers = (raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        owners = [_Owner(index + 1, bytearray(value)) for index, value in enumerate(buffers)]
        machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
        code = machine.invoke(machine.functions['f0'],
            [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError('describe independent VM changed immutable request')
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        return code

    image._entry = entry
    return image


def run(mode, output, manifest=None):
    global GLOBAL_PHASE
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    values, before = original_inputs(), source_pins()
    runtime_ast = ORIGINAL_RUNTIME_AST_DUMP.encode()
    (output / 'original-runtime-ast.txt').write_bytes(runtime_ast)
    if mode == 'original':
        sys.meta_path.insert(0, NoProduct())
        sys.addaudithook(no_effect)
    GLOBAL_PHASE = 'originals'
    expected = [observe(case) for case in values]
    expected_raw = canonical(expected)
    (output / 'originals.json').write_bytes(expected_raw)
    original_late = list(LATE)
    if mode == 'original':
        after = source_pins()
        passed = not LATE and before == after and len(expected) == 291
        report = {'status': 'PASS' if passed else 'FAIL', 'runtime': sys.version,
            'runtime_version': platform.python_version(), 'count': len(expected),
            'ordered_ids': [case['id'] for case in values], 'sha256': sha256(expected_raw).hexdigest(),
            'original_late_events': original_late, 'source_unchanged': before == after,
            'original_code_policy': 'same frozen original code object reused through fresh namespaces',
            'selected_or_native_or_VM_execution': False}
    else:
        # Candidate imports, source assembly and mapping start only after all
        # original rows have been saved. No candidate supplies expectations.
        import ctypes
        import struct
        from hepta import hia_agent_service as api
        from hepta import hia_service_describe_native as native
        from hepta import hia_native_delivery as delivery
        from tools.build_hia_service_describe import INPUTS
        pins = {name: sha256((REPOSITORY / name).read_bytes()).hexdigest() for name in INPUTS}
        if mode == 'vm':
            from hepta.hia_agent_assembly import assemble_program
            program = assemble_program(native.SOURCE.read_bytes())
            image = independent_vm_image(program)
            bundle_pins = {}
        else:
            manifest = Path(manifest).resolve(strict=True)
            image = native.installed_service_describe(str(manifest))
            manifest_data = json.loads(manifest.read_bytes())
            image_path = manifest.parent / manifest_data['image_path']
            bundle_pins = {str(path): sha256(path.read_bytes()).hexdigest()
                           for path in (manifest, image_path)}
        entries, frames, forbidden_calls = Counter(), [0], []
        actual_entry = image._entry
        reference = api._NATIVE_SERVICE_DESCRIBE_REFERENCE
        packet_count = [0]

        def forbidden(*args, **kwargs):
            forbidden_calls.append(True)
            raise AssertionError('selected describe invoked retained original body')

        def factory(ns):
            def selected(service, arguments):
                frames[0] += 1
                return native.ServiceDescribeFrame(image, service, arguments, namespace=ns).finish()
            return selected

        GLOBAL_PHASE = 'candidate'
        try:
            api._NATIVE_SERVICE_DESCRIBE_REFERENCE = forbidden
            with (output / 'complete-packets.jsonl').open('xb') as packets:
                def counted(source, size, out, capacity, state, extent):
                    request = ctypes.string_at(source, size)
                    old_output, old_state = ctypes.string_at(out, capacity), ctypes.string_at(state, extent)
                    code = actual_entry(source, size, out, capacity, state, extent)
                    magic, event = struct.unpack('<2Q', request[:16])
                    if magic != native.REQUEST_MAGIC or code != native.OUTPUT_BYTES:
                        raise AssertionError('describe machine return differs from exact ABI')
                    entries[str(event)] += 1
                    packet_count[0] += 1
                    packets.write(canonical({'index': packet_count[0], 'request': request.hex(),
                        'output_before': old_output.hex(), 'state_before': old_state.hex(),
                        'output_after': ctypes.string_at(out, capacity).hex(),
                        'state_after': ctypes.string_at(state, extent).hex(), 'return': code}))
                    return code
                image._entry = counted
                actual = [observe(case, factory=factory) for case in values]
        finally:
            image._entry = actual_entry
            api._NATIVE_SERVICE_DESCRIBE_REFERENCE = reference
        actual_raw = canonical(actual)
        (output / 'actuals.json').write_bytes(actual_raw)
        (output / 'complete-observations.json').write_bytes(canonical([
            {'case': case['id'], 'expected': left, 'actual': right, 'equal': left == right}
            for case, left, right in zip(values, expected, actual)]))
        after = source_pins()
        stable = (before == after
            and pins == {name: sha256((REPOSITORY / name).read_bytes()).hexdigest() for name in INPUTS}
            and all(sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in bundle_pins.items())
            and (output / 'originals.json').read_bytes() == expected_raw)
        custody = list(delivery.custody_snapshot())
        passed = (expected_raw == actual_raw and stable and not LATE and not custody
                  and len(actual) == frames[0] == 291 and not forbidden_calls
                  and entries['0'] == 291 and entries['1'] == entries['2'] + entries['3'])
        report = {'status': 'PASS' if passed else 'FAIL', 'runtime': sys.version,
            'runtime_version': platform.python_version(), 'mode': mode, 'original_count': len(expected),
            'actual_count': len(actual), 'actual_frames': frames[0], 'ordered_ids': [case['id'] for case in values],
            'differences': differences(expected, actual), 'originals_sha256': sha256(expected_raw).hexdigest(),
            'actuals_sha256': sha256(actual_raw).hexdigest(), 'original_late_events': original_late,
            'all_late_events': LATE, 'actual_entry_events': dict(entries), 'complete_packet_count': packet_count[0],
            'actual_native_entries': sum(entries.values()) if mode == 'native' else 0,
            'actual_VM_entries': sum(entries.values()) if mode == 'vm' else 0,
            'remaining_delivery_custody': custody, 'retained_reference_calls': forbidden_calls,
            'expected_written_before_candidate_imports': True,
            'original_code_policy': 'same frozen original code object reused through fresh namespaces',
            'source_image_manifest_and_originals_unchanged': stable, 'component_input_pins': pins,
            'bundle_pins': bundle_pins, 'namespace_seam': 'explicit finite opaque-provider observations',
            'public_selection_qualified_by_this_observer': False,
            'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False}
    report['original_ast_identity'] = {
        'method_bytes': ORIGINAL_BYTES, 'method_sha256': ORIGINAL_SHA256,
        'method_git_blob': ORIGINAL_GIT_BLOB_SHA1,
        'authoring_ast_sha256': ORIGINAL_AST_SHA256, 'authoring_runtime': 'CPython 3.12.14',
        'runtime': sys.version, 'implementation': sys.implementation.name,
        'dump_file': 'original-runtime-ast.txt', 'dump_bytes': len(runtime_ast),
        'dump_sha256': sha256(runtime_ast).hexdigest(),
        'comparison_policy': 'independently pinned source and live method parsed by the same runtime'}
    report['schema'] = 'hepta.hia.service-describe-finite-observer.v1'
    (output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({key: report[key] for key in ('status', 'runtime_version')}
                     | {'mode': mode, 'cases': len(values)}, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('original', 'vm', 'native'), required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    if (options.mode == 'native') != (options.manifest is not None):
        parser.error('only native mode requires --manifest')
    if str(REPOSITORY) not in sys.path:
        sys.path.insert(0, str(REPOSITORY))
    raise SystemExit(run(options.mode, options.output, options.manifest))

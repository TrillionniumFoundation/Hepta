"""Fresh-lane complete observations; original output is frozen before candidates."""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
import platform
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests import hia_service_verification_oracle as oracle
def captured_json(path):
    raw = Path(path).read_bytes()
    return raw, json.loads(raw), sha256(raw).hexdigest()

def put(path, value):
    raw = oracle.canonical(value) + b'\n'
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return sha256(raw).hexdigest()

def source_snapshot():
    names = ['tests/hia_service_verification_oracle.py', 'tests/hia_service_verification_observer.py',
             'tests/fixtures/hia_service_verification_original_r12/cases.json']
    names += ['tests/fixtures/hia_service_verification_original_r12/' + x for x in oracle.PINNED]
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names}

class VMEntry:
    """No image -> closure -> image cycle is introduced by this fixture."""
    def __init__(self, program):
        from hepta.hia_program_runtime_prepared import prepare_runtime_program
        self.program, self.calls = prepare_runtime_program(program), 0
    def __call__(self, source, size, output, capacity, state, extent):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        raw = ctypes.string_at(source, size)
        owners = [_Owner(i + 1, bytearray(x)) for i, x in enumerate((
            raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)))]
        machine = _Machine(self.program, 4_000_000, 16 << 20, None, 128)
        code = machine.invoke(machine.functions['f0'],
                              [_View(owner, i != 0) for i, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError('VM changed read-only request')
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        self.calls += 1
        return code

class EntryCounter:
    def __init__(self, entry):
        self.entry, self.calls = entry, 0
    def __call__(self, *args):
        self.calls += 1
        return self.entry(*args)

_ABSENT = object()

class ScopedImporter:
    """Route only the original business namespace to its fake importer."""
    __slots__ = ('namespace_identity', 'original', 'provider')
    def __init__(self, namespace, original, provider):
        self.namespace_identity=id(namespace)
        self.original,self.provider=original,provider
    def __call__(self,name,globals=None,locals=None,fromlist=(),level=0):
        if (id(globals)==self.namespace_identity and level==1
                and name in ('hia_optimization','hia_program','hia_machine_plan','hia_program_native','hia_safe_core','hia_safe_core_elf')):
            return self.provider(name,globals,locals,fromlist,level)
        return self.original(name,globals,locals,fromlist,level)

class PublicFactory:
    """Real public dispatch with the actual original global/import namespace."""
    def __init__(self, lane, manifest):
        import os
        from hepta import hia_agent_service as api, hia_agent_assembly
        from hepta import hia_service_verification_native as native
        self.api, self.native = api, native
        self.lane, self.manifest = lane, manifest
        self.saved, self.saved_mappings = [], []
        self.active_world = self.old_namespace = None
        self.old_selector = os.environ.get(native.SELECTOR, _ABSENT)
        if lane == 'unselected':
            self.image = None
            os.environ.pop(native.SELECTOR, None)
        elif lane == 'vm':
            image = object.__new__(native.NativeServiceVerification)
            image.image_sha256 = 'independent-VM-not-executable'
            image._entry = VMEntry(hia_agent_assembly.assemble_program(native.SOURCE.read_bytes()))
            self.image = image
            self.original_loader = native.installed_service_verification
            native.installed_service_verification = self.vm_loader
            os.environ[native.SELECTOR] = 'explicit-independent-vm-fixture'
        else:
            self.image = native.installed_service_verification(manifest)
            self.original_entry = self.image._entry
            self.image._entry = EntryCounter(self.original_entry)
            os.environ[native.SELECTOR] = str(manifest)
        self.retained_calls = 0

    def vm_loader(self, selector):
        if selector != 'explicit-independent-vm-fixture':
            raise AssertionError('independent VM binding differs')
        return self.image

    def poison(self, *args, **kwargs):
        self.retained_calls += 1
        raise AssertionError('selected verification called a retained complete business body')

    def replace(self, owner, name, value):
        self.saved.append((owner, name, vars(owner).get(name, _ABSENT)))
        setattr(owner, name, value)

    def install_world(self, world):
        if self.active_world is not None:
            if self.active_world is not world:
                raise AssertionError('nested verification changed the actual observation world')
            return
        self.active_world = world
        namespace = world.namespace
        self.old_namespace = namespace
        for name, value in namespace.items():
            if not name.startswith('__'):
                self.replace(self.api, name, value)
        seen = set()
        for captured in self.api._SERVICE_VERIFICATION_GLOBAL_BUILTINS.values():
            if id(captured) in seen:
                continue
            seen.add(id(captured))
            old = captured['__import__']
            self.saved_mappings.append((captured, '__import__', old))
            captured['__import__'] = ScopedImporter(
                vars(self.api), old, namespace['__builtins__']['__import__'])
        if self.lane != 'unselected':
            for number, name in enumerate(oracle.METHODS, 1):
                self.replace(self.api, '_SERVICE_VERIFICATION_REFERENCE_' + str(number), self.poison)
                self.replace(self.api.HIAAgentService, name + '_reference',
                             staticmethod(self.poison) if number == 6 else self.poison)
        world.namespace = vars(self.api)

    def __call__(self, world, mode, arguments):
        self.install_world(world)
        function = getattr(self.api.HIAAgentService, oracle.METHODS[oracle.MODES.index(mode)])
        call = {'callee': function, 'arguments': arguments}
        del function, arguments, world
        return call.pop('callee')(*call.pop('arguments'))

    def restore_case(self):
        if self.active_world is not None:
            self.active_world.namespace = self.old_namespace
        while self.saved_mappings:
            mapping, name, previous = self.saved_mappings.pop()
            mapping[name] = previous
        while self.saved:
            owner, name, previous = self.saved.pop()
            if previous is _ABSENT:
                delattr(owner, name)
            else:
                setattr(owner, name, previous)
        self.active_world = self.old_namespace = None

    def close(self):
        import os
        self.restore_case()
        if self.old_selector is _ABSENT:
            os.environ.pop(self.native.SELECTOR, None)
        else:
            os.environ[self.native.SELECTOR] = self.old_selector
        if self.lane == 'vm':
            self.native.installed_service_verification = self.original_loader
        elif self.lane == 'native':
            self.image._entry = self.original_entry

def candidate_factory(lane, manifest):
    factory=PublicFactory(lane,manifest)
    return factory,factory.image

def differences(expected, actual, path=''):
    if type(expected) is not type(actual):
        return [{'path': path, 'expected': expected, 'actual': actual}]
    if isinstance(expected, dict):
        result = []
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                result.append({'path': path + '/' + key, 'expected_present': key in expected,
                               'actual_present': key in actual})
            else:
                result.extend(differences(expected[key], actual[key], path + '/' + key))
        return result
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [{'path': path, 'expected': expected, 'actual': actual}]
        result = []
        for i, (left, right) in enumerate(zip(expected, actual)):
            result.extend(differences(left, right, path + '/' + str(i)))
        return result
    return [] if expected == actual else [{'path': path, 'expected': expected, 'actual': actual}]

def run(lane, inputs_path, output, expected_path=None, manifest=None):
    inputs_raw, value, input_pin = captured_json(inputs_path)
    cases = value['cases']
    if type(cases) is not list or len({x['id'] for x in cases}) != len(cases):
        raise ValueError('input IDs are not unique')
    output = Path(output)
    output.mkdir(mode=0o700)
    before = source_snapshot()
    put(output / 'source-before.json', before)
    authority = authority_raw = None
    if lane != 'original':
        if expected_path is None:
            raise ValueError('candidate requires a frozen original authority')
        authority_raw, authority, authority_pin = captured_json(expected_path)
        if (authority['schema'] != 'hepta.hia.service-verification-original-authority.v1'
                or authority['status'] != 'ORIGINAL_ONLY'
                or authority['runtime'] != sys.version
                or authority['runtime_version'] != list(sys.version_info[:3])
                or authority['implementation'] != platform.python_implementation()
                or authority['candidate_executed'] is not False
                or authority['inputs_sha256'] != input_pin or authority['count'] != len(cases)
                or authority['ordered_ids'] != [x['id'] for x in cases]):
            raise ValueError('candidate inputs differ from original authority')
        for name in ('first', 'second'):
            original = Path(authority[name]['path'])
            if sha256(original.read_bytes()).hexdigest() != authority[name]['sha256']:
                raise ValueError('frozen original bytes changed')
        if Path(authority['first']['path']).read_bytes() != Path(authority['second']['path']).read_bytes():
            raise ValueError('independent original lanes are unequal')
        put(output / 'original-authority.json', {'path': str(Path(expected_path).absolute()),
              'sha256': authority_pin, 'inputs_sha256': input_pin})
    # This complete authority is fixed before any product/VM/native import.
    candidate_bytes = {}
    if lane != 'original':
        for name in ('hepta/hia_service_verification_native.py',
                     'hepta/hia_service_verification_protocol.py',
                     'examples/hia_bootstrap/service_verification.hepta',
                     'hepta/hia_native_delivery.py', 'hepta/hia_json_preflight_native.py',
                     'hepta/hia_agent_service.py', 'hepta/hia_native_helpers.py',
                     'hepta/hia_opcodes.py', 'hepta/hia_agent_assembly.py',
                     'hepta/hia_emission_native.py', 'hepta/hia_store_lifecycle_native.py',
                     'hepta/hia_program.py', 'hepta/hia_program_runtime.py',
                     'hepta/hia_program_runtime_prepared.py', 'hepta/hia_service_lease_native.py'):
            candidate_bytes[str(ROOT / name)] = (ROOT / name).read_bytes()
        if lane == 'native':
            manifest_path = Path(manifest).resolve(strict=True)
            manifest_raw = manifest_path.read_bytes()
            candidate_bytes[str(manifest_path)] = manifest_raw
            manifest_value = json.loads(manifest_raw)
            image_name = manifest_value['image_path']
            if type(image_name) is not str or Path(image_name).name != image_name or image_name in ('', '.', '..'):
                raise ValueError('native observation image is not a sibling basename')
            image_path = manifest_path.parent / image_name
            candidate_bytes[str(image_path)] = image_path.read_bytes()
            if sha256(candidate_bytes[str(image_path)]).hexdigest() != manifest_value['image_sha256']:
                raise ValueError('native observation image differs from its manifest')
    def audit_event(event, args):
        if event in ('sqlite3.connect','subprocess.Popen','os.system','os.posix_spawn','os.exec','os.fork','os.forkpty'):
            raise AssertionError('finite verification oracle does not use real SQL/process providers: '+event)
        if lane == 'original' and event == 'import' and args and str(args[0]).split('.')[0] == 'hepta':
            raise AssertionError('original lane imported a product module')
    sys.addaudithook(audit_event)
    factory, image = (None, None) if lane == 'original' else candidate_factory(lane, manifest)
    expected_stream = None if authority is None else Path(authority['first']['path']).open('rb')
    failures, emitted = 0, 0
    expected_digest = sha256()
    try:
        with (output / 'observations.jsonl').open('xb') as observations, \
             (output / 'raw-tracebacks.jsonl').open('xb') as tracebacks, \
             (output / 'differences.jsonl').open('xb') as diffs:
            for case in cases:
                try:
                    observed, raw_tracebacks = oracle.observe_case(case, factory=oracle.original_factory if factory is None else factory)
                finally:
                    if factory is not None:
                        factory.restore_case()
                # The returned record is already deeply sealed at its declared
                # consumer endpoint. Capture bytes once, before the next case.
                raw = oracle.canonical(observed) + b'\n'
                observations.write(raw)
                tracebacks.write(oracle.canonical({'id': case['id'], 'tracebacks': raw_tracebacks}) + b'\n')
                if expected_stream is not None:
                    expected_raw = expected_stream.readline()
                    if not expected_raw:
                        raise ValueError('original observation stream ended early')
                    expected_digest.update(expected_raw)
                    expected = json.loads(expected_raw)
                    if expected['id'] != case['id']:
                        raise ValueError('original input order differs')
                    diff = differences(expected, observed)
                    if diff:
                        failures += 1
                    diffs.write(oracle.canonical({'id': case['id'], 'equal_bytes': raw == expected_raw,
                                                 'differences': diff}) + b'\n')
                    if bool(diff) != (raw != expected_raw):
                        raise AssertionError('typed comparison and complete bytes disagree')
                emitted += 1
        if expected_stream is not None and expected_stream.read(1):
            raise ValueError('original stream has extra records')
    finally:
        if expected_stream is not None:
            expected_stream.close()
        if factory is not None:
            # Keep the immutable native entry counter available in the report.
            recorded_entries = 0 if image is None else image._entry.calls
            recorded_retained = factory.retained_calls
            factory.close()
        else:
            recorded_entries = recorded_retained = 0
    if authority is not None and expected_digest.hexdigest() != authority['first']['sha256']:
        raise ValueError('actually consumed original bytes differ from authority')
    after = source_snapshot()
    put(output / 'source-after.json', after)
    if before != after or Path(inputs_path).read_bytes() != inputs_raw:
        raise ValueError('source or input changed')
    if authority is not None:
        if Path(expected_path).read_bytes() != authority_raw:
            raise ValueError('original authority changed')
        for name in ('first', 'second'):
            if sha256(Path(authority[name]['path']).read_bytes()).hexdigest() != authority[name]['sha256']:
                raise ValueError('original observation changed during candidate')
    if any(Path(name).read_bytes() != raw for name, raw in candidate_bytes.items()):
        raise ValueError('candidate source, manifest or actual image changed')
    report = {'schema': 'hepta.hia.service-verification-observations.v1', 'lane': lane,
              'runtime_version': list(sys.version_info[:3]),
              'implementation': platform.python_implementation(),
              'candidate_source_manifest_image_pins': {
                  name: sha256(raw).hexdigest() for name, raw in candidate_bytes.items()},
              'actual_image_sha256': None if image is None else image.image_sha256,
              'runtime': sys.version, 'executable': sys.executable, 'inputs_sha256': input_pin,
              'count': emitted, 'ordered_ids': [x['id'] for x in cases], 'differences': failures,
              'source_before': before, 'source_after': after, 'whole_stack_qualified': False,
              'public_route': True,
              'native_or_VM_entries': recorded_entries, 'retained_body_calls': recorded_retained,
              'files': {name: sha256((output / name).read_bytes()).hexdigest() for name in (
                  'observations.jsonl', 'raw-tracebacks.jsonl', 'differences.jsonl')}}
    put(output / 'report.json', report)
    return 0 if failures == 0 else 1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lane', choices=('original', 'vm', 'native', 'unselected'), required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.lane, args.inputs, args.output, args.expected, args.manifest))

if __name__ == '__main__':
    main()

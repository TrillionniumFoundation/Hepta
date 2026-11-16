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
from tests import hia_store_file_capture_owned_fd_v2_oracle as oracle
FORWARD_SOURCE = '''
def stable_read(path, limit, *, dir_fd=None):
    frame = _FRAME(_IMAGE, 1, {'path': path, 'limit': limit, 'dir_fd': dir_fd}, namespace=_NAMESPACE)
    del path, limit, dir_fd
    return frame.finish()
def capture_path(path, roots, limit):
    frame = _FRAME(_IMAGE, 2, {'path': path, 'roots': roots, 'limit': limit}, namespace=_NAMESPACE)
    del path, roots, limit
    return frame.finish()
'''
_FORWARD_CODE = compile(FORWARD_SOURCE, '<file-capture-literal-bridge>', 'exec')

def captured_json(path):
    raw = Path(path).read_bytes()
    return raw, json.loads(raw), sha256(raw).hexdigest()

def put(path, value):
    raw = oracle.canonical(value) + b'\n'
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return sha256(raw).hexdigest()

def source_snapshot():
    names = ['tests/hia_store_file_capture_owned_fd_v2_oracle.py', 'tests/hia_store_file_capture_owned_fd_v2_observer.py',
             'tests/fixtures/hia_store_file_capture_inputs_v1.json',
             'tests/fixtures/hia_store_file_capture_owned_fd_v2/legacy-complete-inputs.json']
    names += ['tests/fixtures/hia_store_file_capture_owned_fd_v2/' + x + '.py.txt'
              for x in oracle.PINNED]
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names}

class VMEntry:
    """No image -> closure -> image cycle is introduced by this fixture."""
    def __init__(self, program):
        self.program, self.calls = program, 0
    def __call__(self, source, size, output, capacity, state, extent):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        raw = ctypes.string_at(source, size)
        owners = [_Owner(i + 1, bytearray(x)) for i, x in enumerate((
            raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)))]
        machine = _Machine(self.program, 2_000_000, 16 << 20, None, 128)
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

def candidate_factory(lane, manifest):
    from hepta import hia_store_file_capture_native as native
    if lane == 'vm':
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime_prepared import prepare_runtime_program
        image = object.__new__(native.NativeStoreFileCapture)
        image.image_sha256 = 'independent-VM-not-executable'
        image._entry = VMEntry(prepare_runtime_program(assemble_program(native.SOURCE.read_bytes())))
    else:
        image = native.installed_store_file_capture(manifest)
        image._entry = EntryCounter(image._entry)
    def factory(namespace, mode):
        previous = namespace['stable_read']
        override = not hasattr(previous, '__code__') or previous.__code__.co_name != 'stable_read'
        namespace.update(_FRAME=native.StoreFileCaptureFrame, _IMAGE=image, _NAMESPACE=namespace)
        exec(_FORWARD_CODE, namespace)
        result = namespace['stable_read' if mode == 'stable' else 'capture_path']
        if override:
            namespace['stable_read'] = previous
        return result
    return factory, image

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
        if (authority['schema'] != 'hepta.hia.store-file-capture-original-authority.v2'
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
            original_raw = original.read_bytes()
            if (type(authority[name]['bytes']) is not int or authority[name]['bytes'] < 0
                    or len(original_raw) != authority[name]['bytes']
                    or sha256(original_raw).hexdigest() != authority[name]['sha256']):
                raise ValueError('frozen original bytes changed')
            del original_raw
        if Path(authority['first']['path']).read_bytes() != Path(authority['second']['path']).read_bytes():
            raise ValueError('independent original lanes are unequal')
        put(output / 'original-authority.json', {'path': str(Path(expected_path).absolute()),
              'sha256': authority_pin, 'inputs_sha256': input_pin})
    # This complete authority is fixed before any product/VM/native import.
    candidate_bytes = {}
    if lane != 'original':
        for name in ('hepta/hia_store_file_capture_native.py',
                     'hepta/hia_store_file_capture_protocol.py',
                     'examples/hia_bootstrap/store_file_capture.hepta',
                     'hepta/hia_native_delivery.py', 'hepta/hia_json_preflight_native.py'):
            candidate_bytes[str(ROOT / name)] = (ROOT / name).read_bytes()
        if lane == 'vm':
            for name in ('hepta/hia_agent_assembly.py', 'hepta/hia_program.py',
                         'hepta/hia_program_runtime.py', 'hepta/hia_program_runtime_prepared.py'):
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
    factory, image = (None, None) if lane == 'original' else candidate_factory(lane, manifest)
    expected_stream = None if authority is None else Path(authority['first']['path']).open('rb')
    failures, emitted = 0, 0
    expected_digest = sha256()
    expected_byte_count = 0
    try:
        with (output / 'observations.jsonl').open('xb') as observations, \
             (output / 'raw-tracebacks.jsonl').open('xb') as tracebacks, \
             (output / 'differences.jsonl').open('xb') as diffs:
            for case in cases:
                observed, raw_tracebacks = oracle.observe(case, factory=factory)
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
        if expected_stream is not None:
            if expected_stream.read(1):
                raise ValueError('original stream has extra records')
            expected_byte_count = expected_stream.tell()
    finally:
        if expected_stream is not None:
            expected_stream.close()
    if authority is not None and (expected_digest.hexdigest() != authority['first']['sha256']
            or expected_byte_count != authority['first']['bytes']):
        raise ValueError('actually consumed original bytes differ from authority')
    after = source_snapshot()
    put(output / 'source-after.json', after)
    if before != after or Path(inputs_path).read_bytes() != inputs_raw:
        raise ValueError('source or input changed')
    if authority is not None:
        if Path(expected_path).read_bytes() != authority_raw:
            raise ValueError('original authority changed')
        for name in ('first', 'second'):
            original_raw = Path(authority[name]['path']).read_bytes()
            if (len(original_raw) != authority[name]['bytes']
                    or sha256(original_raw).hexdigest() != authority[name]['sha256']):
                raise ValueError('original observation changed during candidate')
            del original_raw
    if any(Path(name).read_bytes() != raw for name, raw in candidate_bytes.items()):
        raise ValueError('candidate source, manifest or actual image changed')
    # Capture each emitted stream once. The report binds both its digest and
    # byte count to these exact bytes; no original observation is regenerated.
    emitted_pins, emitted_sizes = {}, {}
    for name in ('observations.jsonl', 'raw-tracebacks.jsonl', 'differences.jsonl'):
        emitted_raw = (output / name).read_bytes()
        emitted_pins[name] = sha256(emitted_raw).hexdigest()
        emitted_sizes[name] = len(emitted_raw)
        del emitted_raw
    report = {'schema': 'hepta.hia.store-file-capture-observations.v2', 'lane': lane,
              'runtime_version': list(sys.version_info[:3]),
              'implementation': platform.python_implementation(),
              'candidate_source_manifest_image_pins': {
                  name: sha256(raw).hexdigest() for name, raw in candidate_bytes.items()},
              'actual_image_sha256': None if image is None else image.image_sha256,
              'runtime': sys.version, 'executable': sys.executable, 'inputs_sha256': input_pin,
              'count': emitted, 'ordered_ids': [x['id'] for x in cases], 'differences': failures,
              'source_before': before, 'source_after': after, 'whole_stack_qualified': False,
              'raw_descriptor_primitive_used': False,
              'native_or_VM_entries': 0 if image is None else image._entry.calls,
              'files': emitted_pins, 'file_sizes': emitted_sizes}
    for name, pin in emitted_pins.items():
        emitted_raw = (output / name).read_bytes()
        if len(emitted_raw) != emitted_sizes[name] or sha256(emitted_raw).hexdigest() != pin:
            raise ValueError('emitted observation stream changed before report')
        del emitted_raw
    put(output / 'report.json', report)
    return 0 if failures == 0 else 1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lane', choices=('original', 'vm', 'native'), required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.lane, args.inputs, args.output, args.expected, args.manifest))

if __name__ == '__main__':
    main()

"""Replay the exact historical Describe corpus through current discovery Mode 1.

The archive preserves the complete original files. Only qualification adapters
translate the declared old/current frame ABI and explicit terminal handshake.
Neither old hosted implementation nor old image becomes a product default.
"""
from __future__ import annotations

import argparse
import ast
import base64
from collections import Counter
import ctypes
import gzip
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import types

SELF = 'tests/hia_service_describe_current_replay.py'
TEST = 'tests/test_hia_service_describe_current_replay.py'
CORPUS = 'tests/fixtures/hia_service_describe_0ae_originals_v1.json.gz'
CORPUS_SHA256 = '10258c60d04847f5abdae9fe0f191916df708dd64d1d86a8ecf7984edee1feb7'
ORIGINAL_COMMIT = '0ae97aca6c29fde873815b1ea9bcdfc4555fc3d3'
ORACLE = 'tests/hia_service_describe_oracle.py'
FAULTS = 'tests/hia_service_describe_faults.py'
METHOD = 'tests/fixtures/hia_service_describe_original_3424/describe.3424.py.txt'
EXECUTED_BYTES = Path(__file__).resolve().read_bytes()
OLD_PORTS = (
    'import_catalog', 'has_cursor', 'reject_cursor', 'has_backend_profile',
    'backend_differs', 'reject_profile', 'language_schema', 'language',
    'profile_pair', 'section', 'resources', 'result', 'release_locals',
)
CURRENT_PORTS = (
    'describe_import', 'describe_cursor', 'describe_reject_cursor',
    'describe_backend_present', 'describe_backend_differs',
    'describe_reject_backend', 'describe_language_schema', 'describe_language',
    'describe_profile', 'describe_section', 'describe_resources',
    'describe_result', 'describe_release',
)
HISTORICAL_PATHS = frozenset((
    'examples/hia_bootstrap/service_describe.hepta',
    'hepta/hia_service_describe_native.py',
    'hepta/hia_service_describe_protocol.py',
    'tests/fixtures/hia_service_describe_original_3424/cases.json',
    METHOD,
    'tests/fixtures/hia_service_describe_original_3424/freeze.json',
    'tests/fixtures/hia_service_describe_original_3424/source-identity.json',
    FAULTS, ORACLE, 'tests/test_hia_service_describe_native.py',
    'tools/build_hia_service_describe.py', 'tools/generate_hia_service_describe.py',
    'tools/qualify_hia_service_describe_callers.py',
))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode()


def digest(raw):
    return sha256(raw).hexdigest()


def check_execution(root):
    root = Path(root).resolve(strict=True)
    if (Path(__file__).resolve().read_bytes() != EXECUTED_BYTES
            or (root / SELF).read_bytes() != EXECUTED_BYTES):
        raise ValueError('Describe replay implementation differs from executed source')
    return root


def corpus(root):
    root = check_execution(root)
    raw = (root / CORPUS).read_bytes()
    if digest(raw) != CORPUS_SHA256:
        raise ValueError('fixed complete Describe corpus differs')
    value = json.loads(gzip.decompress(raw))
    if (type(value) is not dict or set(value) != {
            'schema', 'commit', 'files', 'original_case_count',
            'original_provider_fault_count'}
            or value['schema'] != 'hepta.hia.service-describe-original-corpus.v1'
            or value['commit'] != ORIGINAL_COMMIT
            or type(value['original_case_count']) is not int
            or value['original_case_count'] != 291
            or type(value['original_provider_fault_count']) is not int
            or value['original_provider_fault_count'] != 170
            or type(value['files']) is not list):
        raise ValueError('Describe corpus identity differs')
    files = {}
    for item in value['files']:
        if type(item) is not dict or set(item) != {
                'path', 'mode', 'git_blob', 'bytes', 'sha256', 'base64'}:
            raise ValueError('Describe corpus file record differs')
        name = item['path']
        if (type(name) is not str or name not in HISTORICAL_PATHS
                or name in files or item['mode'] != '100644'
                or type(item['bytes']) is not int):
            raise ValueError('Describe corpus file identity differs')
        data = base64.b64decode(item['base64'], validate=True)
        blob = sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if (len(data) != item['bytes'] or digest(data) != item['sha256']
                or blob != item['git_blob']):
            raise ValueError('Describe corpus exact original bytes differ')
        files[name] = data
    if set(files) != HISTORICAL_PATHS:
        raise ValueError('Describe corpus is incomplete')
    if (root / CORPUS).read_bytes() != raw:
        raise ValueError('Describe corpus changed during capture')
    check_execution(root)
    return files


def materialize(root, target):
    files = corpus(root)
    target = Path(target)
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, raw in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o444)
        if path.read_bytes() != raw:
            raise ValueError('historical file materialization differs')
    if corpus(root) != files:
        raise ValueError('historical corpus changed during materialization')
    return files


def inputs(root):
    root = check_execution(root)
    raw = (root / 'tools/build_hia_service_discovery.py').read_bytes()
    declarations = [
        ast.literal_eval(node.value) for node in ast.parse(raw).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'INPUTS'
                for target in node.targets)
    ]
    if len(declarations) != 1 or type(declarations[0]) is not tuple:
        raise ValueError('current discovery input declaration differs')
    names = set(declarations[0])
    mandatory = {
        'examples/hia_bootstrap/service_discovery.hepta',
        'hepta/hia_service_discovery_native.py',
        'hepta/hia_service_discovery_protocol.py', 'hepta/hia_agent_service.py',
        'hepta/hia_native_delivery.py', 'tools/build_hia_service_discovery.py',
    }
    if not mandatory <= names:
        raise ValueError('current discovery source closure omits required inputs')
    names.update((SELF, TEST, CORPUS, 'pyproject.toml'))
    names.update(path.relative_to(root).as_posix()
                 for path in (root / 'hepta').rglob('*.py')
                 if '_data' not in path.parts)
    result = {}
    for name in sorted(names):
        if (type(name) is not str or Path(name).is_absolute()
                or '..' in Path(name).parts):
            raise ValueError('invalid discovery captured source path')
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('discovery captured source is not regular: ' + name)
        result[name] = digest(path.read_bytes())
    check_execution(root)
    return result


def verify_inputs(root, before):
    if inputs(root) != before:
        raise ValueError('Describe current or qualification inputs changed')


def require_fresh_candidate(root):
    if any(name == 'hepta' or name.startswith('hepta.') for name in sys.modules):
        raise ValueError('Describe replay requires a fresh process before candidate imports')
    spec = importlib.util.find_spec('hepta')
    expected = (Path(root) / 'hepta/__init__.py').resolve(strict=True)
    if spec is None or spec.origin is None or Path(spec.origin).resolve(strict=True) != expected:
        raise ValueError('Describe candidate import does not select the captured root')


def verify_loaded_candidate(root, before):
    root = Path(root).resolve(strict=True)
    for name, module in tuple(sys.modules.items()):
        if name != 'hepta' and not name.startswith('hepta.'):
            continue
        location = getattr(module, '__file__', None)
        if type(location) is not str:
            raise ValueError('Describe loaded candidate has no captured physical source')
        path = Path(location).resolve(strict=True)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('Describe loaded candidate is outside the captured root') from error
        if relative not in before or digest(path.read_bytes()) != before[relative]:
            raise ValueError('Describe loaded candidate differs from captured input bytes')


def load_oracle(history):
    path = Path(history) / ORACLE
    spec = importlib.util.spec_from_file_location(
        'hia_service_describe_original_0ae', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_current_relation(root, files):
    raw = (Path(root) / 'hepta/hia_agent_service.py').read_bytes()
    tree, lines = ast.parse(raw), raw.splitlines(keepends=True)
    service = next(node for node in tree.body
                   if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
    methods = [node for node in service.body
               if isinstance(node, ast.FunctionDef) and node.name == '_hia_describe']
    if len(methods) != 1:
        raise ValueError('current Describe original method identity differs')
    node = methods[0]
    current = b''.join(lines[node.lineno - 1:node.end_lineno])
    if current != files[METHOD]:
        raise ValueError('current Describe reference differs from complete original')
    from hepta import hia_service_discovery_protocol as protocol
    if (tuple(protocol.PORTS[:13]) != CURRENT_PORTS
            or protocol.MODE_RANGES[protocol.DESCRIBE] != (1, 13)
            or protocol.DESCRIBE != 1
            or (protocol.REQUEST_BYTES, protocol.OUTPUT_BYTES,
                protocol.STATE_BYTES) != (128, 96, 192)):
        raise ValueError('current Mode 1 Describe protocol differs')
    return {
        'original_method_sha256': digest(current),
        'ports': [{'number': i, 'original': old, 'current': new}
                  for i, (old, new) in enumerate(zip(OLD_PORTS, CURRENT_PORTS), 1)],
        'mode': 1, 'old_request_state_bytes': [80, 128],
        'current_request_state_bytes': [128, 192],
        'new_explicit_terminal_event': protocol.FINALIZE,
    }


def vm_image(program, native):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    image = object.__new__(native.NativeServiceDiscovery)
    image.image_sha256 = 'independent-vm-no-executable-mapping'
    image.admitted_source_sha256 = digest(native.SOURCE.read_bytes())

    def entry(source, size, output, capacity, state, extent):
        raw = ctypes.string_at(source, size)
        buffers = (raw, ctypes.string_at(output, capacity),
                   ctypes.string_at(state, extent))
        owners = [_Owner(i + 1, bytearray(value))
                  for i, value in enumerate(buffers)]
        machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
        code = machine.invoke(machine.functions['f0'],
                              [_View(owner, i != 0)
                               for i, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError('discovery independent VM wrote immutable request')
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        return code
    image._entry = entry
    return image


def selected_image(root, mode, manifest, native):
    expected_source = (Path(root) / 'examples/hia_bootstrap/service_discovery.hepta').resolve(strict=True)
    if native.SOURCE.resolve(strict=True) != expected_source:
        raise ValueError('Describe current source resource path differs from captured root')
    if mode == 'vm':
        from hepta.hia_agent_assembly import assemble_program
        return vm_image(assemble_program(native.SOURCE.read_bytes()), native), {}
    manifest = Path(manifest).resolve(strict=True)
    value = json.loads(manifest.read_bytes())
    image_path = manifest.parent / value['image_path']
    before = {str(path): digest(path.read_bytes())
              for path in (manifest, image_path)}
    image = native.installed_service_discovery(str(manifest))
    if any(digest(Path(name).read_bytes()) != pin for name, pin in before.items()):
        raise ValueError('current discovery bundle changed during capture')
    return image, before


def finite(root, output, mode, manifest=None, expected_file=None):
    root = check_execution(root)
    require_fresh_candidate(root)
    before = inputs(root)
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = materialize(root, output / 'history')
    oracle = load_oracle(output / 'history')
    values = oracle.original_inputs()
    # The complete frozen observer produces all expectations before candidate imports.
    oracle.GLOBAL_PHASE = 'originals'
    blocker = oracle.NoProduct()
    if any(name == 'hepta' or name.startswith('hepta.') for name in sys.modules):
        raise ValueError('candidate imported before original observations')
    sys.meta_path.insert(0, blocker)
    try:
        expected = [oracle.observe(case) for case in values]
    finally:
        sys.meta_path.remove(blocker)
    expected_raw = oracle.canonical(expected)
    (output / 'originals.json').write_bytes(expected_raw)
    (output / 'originals.json').chmod(0o444)
    original_late = list(oracle.LATE)
    if expected_file is not None and Path(expected_file).read_bytes() != expected_raw:
        raise AssertionError('fresh original observations differ before current replay')
    from hepta import hia_agent_service as api
    from hepta import hia_service_discovery_native as native
    from hepta import hia_native_delivery as delivery
    relation = check_current_relation(root, files)
    image, bundle = selected_image(root, mode, manifest, native)
    verify_loaded_candidate(root, before)
    frames, forbidden_calls, packet_count = [0], [], [0]
    entries = Counter()
    entry = image._entry
    references = {
        '_SERVICE_DISCOVERY_DESCRIBE_REFERENCE': api._SERVICE_DISCOVERY_DESCRIBE_REFERENCE,
    }
    class_reference = api.HIAAgentService._hia_describe_reference

    def forbidden(*args, **kwargs):
        forbidden_calls.append(True)
        raise AssertionError('current discovery invoked retained Describe body')

    def factory(namespace):
        def selected(service, arguments):
            frames[0] += 1
            return native.ServiceDiscoveryFrame(
                image, native.DESCRIBE, service, arguments,
                namespace=namespace).finish()
        return selected

    oracle.GLOBAL_PHASE = 'candidate'
    try:
        api._SERVICE_DISCOVERY_DESCRIBE_REFERENCE = forbidden
        api.HIAAgentService._hia_describe_reference = forbidden
        with (output / 'complete-packets.jsonl').open('xb') as packets:
            def counted(source, size, out, capacity, state, extent):
                request = ctypes.string_at(source, size)
                old_output = ctypes.string_at(out, capacity)
                old_state = ctypes.string_at(state, extent)
                code = entry(source, size, out, capacity, state, extent)
                words = struct.unpack('<16Q', request)
                if (words[0] != native.REQUEST_MAGIC
                        or words[5] != native.DESCRIBE
                        or code != native.OUTPUT_BYTES
                        or (size, capacity, extent) != (128, 96, 192)):
                    raise AssertionError('current Describe actual frame differs')
                entries[str(words[1])] += 1
                packet_count[0] += 1
                packets.write(canonical({
                    'index': packet_count[0], 'request': request.hex(),
                    'output_before': old_output.hex(), 'state_before': old_state.hex(),
                    'output_after': ctypes.string_at(out, capacity).hex(),
                    'state_after': ctypes.string_at(state, extent).hex(),
                    'return': code,
                }))
                return code
            image._entry = counted
            actual = [oracle.observe(case, factory=factory) for case in values]
    finally:
        image._entry = entry
        api.HIAAgentService._hia_describe_reference = class_reference
        for name, reference in references.items():
            setattr(api, name, reference)
    actual_raw = canonical(actual)
    (output / 'actuals.json').write_bytes(actual_raw)
    (output / 'complete-observations.json').write_bytes(canonical([
        {'case': case['id'], 'expected': left, 'actual': right,
         'equal': not oracle.differences(left, right)}
        for case, left, right in zip(values, expected, actual)
    ]))
    custody = list(delivery.custody_snapshot())
    verify_loaded_candidate(root, before)
    verify_inputs(root, before)
    stable = (corpus(root) == files
              and all(digest(Path(name).read_bytes()) == pin
                      for name, pin in bundle.items())
              and (output / 'originals.json').read_bytes() == expected_raw
              and (expected_file is None or Path(expected_file).read_bytes() == expected_raw))
    changes = oracle.differences(expected, actual)
    passed = (stable and expected_raw == actual_raw and not changes
              and not oracle.LATE and not custody and not forbidden_calls
              and len(expected) == len(actual) == frames[0] == 291
              and entries['0'] == 291 and entries['4'] == 291
              and entries['1'] == entries['2'] + entries['3'])
    report = {
        'schema': 'hepta.hia.service-describe-current-replay.v1',
        'passed': passed, 'mode': mode, 'scope': 'HISTORICAL_COMPONENT_REPLAY',
        'matching_cold_qualified': False,
        'original_commit': ORIGINAL_COMMIT, 'original_cases': 291,
        'actual_cases': len(actual), 'actual_frames': frames[0],
        'ordered_ids': [case['id'] for case in values],
        'differences': changes, 'original_late_events': original_late,
        'all_late_events': oracle.LATE, 'remaining_delivery_custody': custody,
        'retained_reference_calls': forbidden_calls,
        'expected_written_before_candidate_imports': True,
        'originals_sha256': digest(expected_raw), 'actuals_sha256': digest(actual_raw),
        'actual_entry_events': dict(entries), 'complete_packet_count': packet_count[0],
        'actual_native_entries': sum(entries.values()) if mode == 'native' else 0,
        'actual_VM_entries': sum(entries.values()) if mode == 'vm' else 0,
        'source_before': before, 'source_after': inputs(root),
        'source_image_manifest_and_originals_unchanged': stable,
        'bundle_pins': bundle, 'relation': relation,
        'public_selection_qualified_by_this_observer': False,
        'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False,
    }
    (output / 'report.json').write_bytes(canonical(report))
    return report


def adapted_fault_source(raw):
    if digest(raw) != '2e607d1e6d4c0c27764f4bed0e5d3cab38d8a9eee470aadd958efd7a65fa646a':
        raise ValueError('original complete fault source differs')
    text = raw.decode()
    edits = []

    def replace(old, new, count=1):
        nonlocal text
        if text.count(old) != count:
            raise ValueError('Describe fault adapter seam differs: ' + old)
        edits.append({'old': old, 'new': new, 'count': count})
        text = text.replace(old, new)

    replace('from hepta import hia_service_describe_native as native',
            'from hepta import hia_service_discovery_native as native')
    replace('from hepta.hia_service_describe_protocol import REFUSED',
            'from hepta.hia_service_discovery_protocol import REFUSED')
    replace('native.ServiceDescribeFrame', 'native.ServiceDiscoveryFrame')
    replace('super().__init__(image, object(), {}, namespace={',
            'super().__init__(image, native.DESCRIBE, object(), {}, namespace={')
    replace("native.PORTS", "MODE_PORTS", text.count("native.PORTS"))
    replace("native.PORT[", "MODE_PORT[", text.count("native.PORT["))
    replace("struct.unpack('<16Q', ctypes.string_at(state, native.STATE_BYTES))",
            "struct.unpack('<24Q', ctypes.string_at(state, native.STATE_BYTES))")
    replace("struct.pack('<16Q', *state_words)",
            "struct.pack('<24Q', *state_words)")
    replace("struct.unpack('<10Q', ctypes.string_at(source, native.REQUEST_BYTES))",
            "struct.unpack('<16Q', ctypes.string_at(source, native.REQUEST_BYTES))", 2)
    replace("'ServiceDescribeUnknown'", "'ServiceDiscoveryUnknown'")
    replace('0 if target_event == native.INITIALIZE else MODE_PORT[target_port]',
            '0 if target_event in (native.INITIALIZE, native.FINALIZE) else MODE_PORT[target_port]')
    replace("            last = row['trace'][-1]",
            "            last = row['trace'][-2]\n            terminal = row['trace'][-1]")
    replace("and bool(row['frame']['local_slots']))",
            "and terminal['event'] == native.FINALIZE and terminal['port'] == 0\n"
            "                      and not row['frame']['local_slots']\n"
            "                      and row['retained_original_local_slots'] == sorted(native.LOCAL_NAMES[native.DESCRIBE]))")
    replace("        'visits': providers.visits, 'provider_events': providers.events,",
            "        'retained_original_local_slots': retained_original_locals(actual),\n"
            "        'visits': providers.visits, 'provider_events': providers.events,")
    helper = (
        "\nMODE_PORTS = EXPECTED_PORTS\n"
        "MODE_PORT = {name: index + 1 for index, name in enumerate(MODE_PORTS)}\n"
        "CURRENT_PORTS = " + repr(CURRENT_PORTS) + "\n"
        "if tuple(native.PORTS[:13]) != CURRENT_PORTS or native.MODE_RANGES[native.DESCRIBE] != (1, 13):\n"
        "    raise ValueError('current Describe mode does not implement the complete original port map')\n"
        "\ndef retained_original_locals(error):\n"
        "    traceback = None if error is None else error.__traceback__\n"
        "    found = []\n"
        "    while traceback is not None:\n"
        "        frame = traceback.tb_frame\n"
        "        if frame.f_code is native.ServiceDiscoveryFrame._drive.__code__:\n"
        "            if found:\n"
        "                raise AssertionError('duplicate original-local owning drive frame')\n"
        "            found = sorted(frame.f_locals['original_locals'])\n"
        "        traceback = traceback.tb_next\n"
        "    return found\n\n"
    )
    replace('\nclass _Resource:\n', helper + '\nclass _Resource:\n')
    projected = text.encode()
    inverse = text
    for item in reversed(edits):
        if inverse.count(item['new']) != item['count']:
            raise ValueError('fault adapter exact inverse is ambiguous')
        inverse = inverse.replace(item['new'], item['old'])
    if inverse.encode() != raw:
        raise ValueError('fault adapter does not restore the full original')
    return projected, edits


def faults(root, output, manifest):
    root = check_execution(root)
    require_fresh_candidate(root)
    before = inputs(root)
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = materialize(root, output / 'history')
    relation = check_current_relation(root, files)
    projected, edits = adapted_fault_source(files[FAULTS])
    (output / 'adapted-fault-controls.py').write_bytes(projected)
    (output / 'exact-original-inverse.json').write_bytes(canonical({
        'original_sha256': digest(files[FAULTS]), 'current_sha256': digest(projected),
        'splices': edits, 'original_control_count': 170,
        'original_control_names_and_provider_inventory_preserved': True,
    }))
    namespace = {'__name__': 'hia_service_describe_current_faults',
                 '__file__': str(output / 'adapted-fault-controls.py')}
    exec(compile(projected, namespace['__file__'], 'exec', dont_inherit=True), namespace)
    native = namespace['native']
    image, bundle = selected_image(root, 'native', manifest, native)
    verify_loaded_candidate(root, before)
    historical = namespace['run_controls'](image, output / 'original-170')
    extra = []
    folder = output / 'current-terminal-38'
    folder.mkdir(mode=0o700)
    for exceptional in (False, True):
        for mutation in (*namespace['ABI_MUTATIONS'], None):
            error = RuntimeError('original provider before current terminal ACK') if exceptional else None
            providers = namespace['_Providers'](
                error_port='import_catalog' if exceptional else None, error=error)
            row = namespace['_run_one'](
                image, providers, mutation=mutation, target_event=native.FINALIZE,
                lose_ack=mutation is None, retry=True)
            wanted = ['import_catalog'] if exceptional else list(OLD_PORTS)
            passed = namespace['_unknown_without_retry'](row, wanted)
            name = ('raised-' if exceptional else 'returned-') + (mutation or 'lost-final-ACK')
            row['passed'] = bool(passed)
            row['control'] = name
            raw = canonical(row)
            (folder / (name + '.json')).write_bytes(raw)
            extra.append({'control': name, 'passed': bool(passed),
                          'raw_sha256': digest(raw), 'bytes': len(raw)})
    verify_loaded_candidate(root, before)
    verify_inputs(root, before)
    stable = (corpus(root) == files
              and all(digest(Path(name).read_bytes()) == pin
                      for name, pin in bundle.items()))
    report = {
        'schema': 'hepta.hia.service-describe-current-fault-replay.v1',
        'passed': (stable and historical['status'] == 'PASS'
                   and historical['control_count'] == 170
                   and len(historical['controls']) == 170
                   and all(row['passed'] is True for row in historical['controls'])
                   and len(extra) == 38 and all(row['passed'] is True for row in extra)),
        'historical_control_count': historical['control_count'],
        'current_terminal_control_count': len(extra), 'current_terminal_controls': extra,
        'historical_report': 'original-170/report.json', 'relation': relation,
        'source_before': before, 'source_after': inputs(root), 'bundle_pins': bundle,
        'source_image_manifest_unchanged': stable, 'custody_registry_reset': False,
        'matching_cold_qualified': False, 'whole_native_delivery_qualified': False,
    }
    (output / 'report.json').write_bytes(canonical(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('vm', 'native', 'faults'), required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--expected', type=Path)
    args = parser.parse_args()
    if (args.mode in ('native', 'faults')) != (args.manifest is not None):
        parser.error('only actual native modes require a manifest')
    if args.mode != 'faults' and args.expected is None:
        parser.error('finite replay requires the fresh original-only observations')
    root = args.root.resolve(strict=True)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    report = (faults(root, args.output, args.manifest) if args.mode == 'faults'
              else finite(root, args.output, args.mode, args.manifest, args.expected))
    print(json.dumps({key: value for key, value in report.items()
                      if key in ('schema', 'passed', 'actual_cases',
                                 'historical_control_count', 'current_terminal_control_count')}))
    return 0 if report['passed'] is True else 1


if __name__ == '__main__':
    raise SystemExit(main())

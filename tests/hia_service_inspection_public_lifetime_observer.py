"""One fresh original, unselected-public or selected-public lifetime child."""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'tests/fixtures/hia_service_inspection_public_lifetime_v1'
FREEZE = DIRECTORY / 'source-identity.json'
CASES = DIRECTORY / 'cases.json'
ORACLE = ROOT / 'tests/hia_service_inspection_public_lifetime_oracle.py'


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def put(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encoded(value))


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def runtime():
    return {'version': sys.version, 'version_info': list(sys.version_info[:3]),
            'implementation': platform.python_implementation(),
            'executable': str(Path(sys.executable).resolve())}


def source_authority(wanted):
    raw = FREEZE.read_bytes()
    if sha256(raw).hexdigest() != wanted:
        raise ValueError('lifetime source freeze is not the external pin')
    value = json.loads(raw)
    if (value.get('schema') != 'hepta.hia.service-inspection-public-lifetime-source.v1'
            or value.get('base_count') != 16 or value.get('whole_qualification') is not False):
        raise ValueError('lifetime source authority differs')
    captured = {}
    for name, expected in value['files'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or not name:
            raise ValueError('invalid source path')
        body = (ROOT / path).read_bytes()
        if pin(body) != expected:
            raise ValueError('frozen source changed: ' + name)
        captured[name] = body
    return raw, value, captured


def audit(original):
    def check(event, arguments):
        if original and event == 'import' and (arguments[0] == 'hepta' or arguments[0].startswith('hepta.')):
            raise RuntimeError('original lifetime observer cannot import product')
        if (event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.posix_spawnp',
                      'os.fork', 'os.forkpty', 'sqlite3.connect')
                or event.startswith('os.exec')):
            raise RuntimeError('lifetime observer cannot execute external/SQL provider')
    return check


def load_oracle(raw):
    spec = importlib.util.spec_from_file_location('_inspection_public_lifetime', ORACLE)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(ORACLE), 'exec'), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', choices=('original', 'unselected', 'native'), required=True)
    parser.add_argument('--source-freeze-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected', type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    if args.backend == 'original':
        if any(v is not None for v in (args.expected, args.expected_sha256, args.manifest)):
            raise ValueError('original child has no candidate authority')
    elif args.expected is None or not args.expected_sha256:
        raise ValueError('public candidate requires an external original report pin')
    if (args.backend == 'native') != (args.manifest is not None):
        raise ValueError('only selected native child requires an image')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    begin = time.time_ns()
    freeze_raw, freeze, captured = source_authority(args.source_freeze_sha256)
    cases = json.loads(captured[str(CASES.relative_to(ROOT))])['cases']
    planned = [row['id'] for row in cases]
    if len(planned) != 16 or len(set(planned)) != 16:
        raise ValueError('complete supplemental input domain differs')
    current_runtime = runtime()
    expected_raw = expected = expected_stream_raw = None
    if args.backend != 'original':
        expected_raw = args.expected.read_bytes()
        if sha256(expected_raw).hexdigest() != args.expected_sha256:
            raise ValueError('original child report is not the external pin')
        expected = json.loads(expected_raw)
        if (expected.get('schema') != 'hepta.hia.service-inspection-public-lifetime-child.v1'
                or expected.get('backend') != 'original' or expected.get('status') != 'PASS'
                or expected.get('runtime') != current_runtime or expected.get('planned') != planned
                or expected.get('started') != planned or expected.get('stopped') != planned
                or expected.get('source_freeze_sha256') != args.source_freeze_sha256
                or expected.get('source_unchanged') is not True
                or expected.get('product_imported') is not False):
            raise ValueError('complete same-runtime original child authority differs')
        expected_stream_raw = (args.expected.parent / 'observations.jsonl').read_bytes()
        if pin(expected_stream_raw) != expected['files']['observations.jsonl']:
            raise ValueError('original complete observation bytes differ')
        put(args.output / 'accepted-original.json', {
            'report': expected, 'report_pin': pin(expected_raw),
            'observation_pin': pin(expected_stream_raw), 'time_ns': time.time_ns(),
            'candidate_product_not_yet_imported': True})
    sys.addaudithook(audit(args.backend == 'original'))
    oracle = load_oracle(captured[str(ORACLE.relative_to(ROOT))])
    owner = None
    api = native = image = None
    saved = {}
    constructor_context = {}
    entry_counts, frame_counts, public_counts, per_case_entries = (
        Counter(), Counter(), Counter(), Counter())
    case_label = ['outside-case']
    product_sources = manifest_raw = image_raw = image_path = None
    old_selector = None
    selector_present = False
    selector_name = 'HEPTA_HIA_SERVICE_INSPECTION_MANIFEST'
    if args.backend != 'original':
        # Only after complete independently pinned original admission.
        sys.path.insert(0, str(ROOT))
        from hepta import hia_agent_service as api
        from tools.build_hia_json_preflight import current_sources
        product_sources = current_sources()
        saved['inspect'] = api._SERVICE_INSPECTION_INSPECT_REFERENCE
        saved['candidate'] = api._SERVICE_INSPECTION_CANDIDATE_REFERENCE
        selector_present = selector_name in os.environ
        old_selector = os.environ.get(selector_name)
        if args.backend == 'unselected':
            os.environ.pop(selector_name, None)
            def owner(mode, make_service, make_arguments, namespace, original):
                attribute = ('_SERVICE_INSPECTION_INSPECT_REFERENCE' if mode == 1
                             else '_SERVICE_INSPECTION_CANDIDATE_REFERENCE')
                previous = getattr(api, attribute)
                # Exact frozen body; only fake globals are substituted.
                # The actual lazy public dispatcher/call shape remain intact.
                setattr(api, attribute, original)
                try:
                    public_counts[str(mode)] += 1
                    method = (api.HIAAgentService._hia_inspect if mode == 1
                              else api.HIAAgentService._hia_candidate)
                    return method(make_service(), make_arguments())
                finally:
                    setattr(api, attribute, previous)
        else:
            import ctypes
            import struct
            from hepta import hia_service_inspection_native as native
            from hepta.hia_native_delivery import custody_snapshot
            if custody_snapshot():
                raise ValueError('selected lifetime child starts with retained custody')
            manifest_raw = args.manifest.read_bytes()
            value = json.loads(manifest_raw)
            image_path = args.manifest.parent / value['image_path']
            image_raw = image_path.read_bytes()
            image = native.installed_service_inspection(str(args.manifest))
            saved['entry'] = image._entry
            saved['constructor'] = native.ServiceInspectionFrame
            saved['class_inspect'] = api.HIAAgentService._hia_inspect_reference
            saved['class_candidate'] = api.HIAAgentService._hia_candidate_reference
            def counted_entry(source, size, output, capacity, state, extent):
                request = struct.unpack('<8Q', ctypes.string_at(source, 64))
                result = saved['entry'](source, size, output, capacity, state, extent)
                if request[0] != native.REQUEST_MAGIC or result != native.OUTPUT_BYTES:
                    raise AssertionError('native lifetime receipt extent differs')
                entry_counts[str(request[1])] += 1
                per_case_entries[case_label[0]] += 1
                return result
            def constructor(admitted, mode, service, arguments, **keywords):
                original = constructor_context['original']
                namespace = constructor_context['namespace']
                if admitted is not image or keywords or mode != constructor_context['mode']:
                    raise AssertionError('actual public constructor identity differs')
                names = original.__code__.co_varnames + original.__code__.co_cellvars
                if tuple(names) != tuple(api._SERVICE_INSPECTION_LOCAL_NAMES[mode]):
                    raise AssertionError('original local layout differs')
                frame_counts[str(mode)] += 1
                return saved['constructor'](admitted, mode, service, arguments,
                    namespace=namespace, global_builtins=original.__builtins__, local_names=names)
            def forbidden(*values, **keywords):
                raise AssertionError('selected lifetime route called retained complete body')
            def owner(mode, make_service, make_arguments, namespace, original):
                if constructor_context:
                    raise AssertionError('supplemental fixture unexpectedly reentered')
                constructor_context.update(mode=mode, namespace=namespace, original=original)
                try:
                    public_counts[str(mode)] += 1
                    method = (api.HIAAgentService._hia_inspect if mode == 1
                              else api.HIAAgentService._hia_candidate)
                    return method(make_service(), make_arguments())
                finally:
                    constructor_context.clear()
            image._entry = counted_entry
            native.ServiceInspectionFrame = constructor
            api._SERVICE_INSPECTION_INSPECT_REFERENCE = forbidden
            api._SERVICE_INSPECTION_CANDIDATE_REFERENCE = forbidden
            api.HIAAgentService._hia_inspect_reference = forbidden
            api.HIAAgentService._hia_candidate_reference = forbidden
            os.environ[selector_name] = str(args.manifest.resolve())
    expected_lines = None if expected_stream_raw is None else expected_stream_raw.splitlines(keepends=True)
    if expected_lines is not None and len(expected_lines) != len(planned):
        raise ValueError('original complete table count differs')
    started, stopped, mismatches, errors, fault_misses = [], [], [], [], []
    try:
        with (args.output / 'observations.jsonl').open('xb') as stream, \
             (args.output / 'raw-tracebacks.jsonl').open('xb') as raw_stream:
            for index, case in enumerate(cases):
                case_label[0] = case['id']
                started.append(case['id'])
                try:
                    value, raw_tb = oracle.observe(case, owner)
                    if value['fault_hits'] != (1 if case.get('fault') is not None else 0):
                        fault_misses.append(case['id'])
                    row = encoded(value)
                    stream.write(row)
                    stream.flush()
                    raw_stream.write(encoded({'case_id': case['id'], 'traceback': raw_tb}))
                    raw_stream.flush()
                    if expected_lines is not None:
                        original_row = json.loads(expected_lines[index])
                        if original_row['case_id'] != case['id'] or encoded(original_row) != expected_lines[index]:
                            raise ValueError('original table order/canonical bytes differ')
                        if row != expected_lines[index]:
                            mismatches.append(case['id'])
                            put(args.output / ('difference-' + str(index) + '.json'),
                                {'case_id': case['id'], 'original': original_row, 'candidate': value})
                except BaseException as error:
                    errors.append({'case_id': case['id'], 'class': type(error).__name__,
                                   'message': str(error)})
                    raw_stream.write(encoded({'case_id': case['id'],
                                              'observer_error': traceback.format_exc()}))
                    raw_stream.flush()
                finally:
                    stopped.append(case['id'])
    finally:
        if image is not None:
            image._entry = saved['entry']
            native.ServiceInspectionFrame = saved['constructor']
            api.HIAAgentService._hia_inspect_reference = saved['class_inspect']
            api.HIAAgentService._hia_candidate_reference = saved['class_candidate']
        if api is not None:
            api._SERVICE_INSPECTION_INSPECT_REFERENCE = saved['inspect']
            api._SERVICE_INSPECTION_CANDIDATE_REFERENCE = saved['candidate']
            if selector_present:
                os.environ[selector_name] = old_selector
            else:
                os.environ.pop(selector_name, None)
    stable = (FREEZE.read_bytes() == freeze_raw
              and all((ROOT / name).read_bytes() == raw for name, raw in captured.items()))
    authority_stable = (expected_raw is None or (
        args.expected.read_bytes() == expected_raw
        and (args.expected.parent / 'observations.jsonl').read_bytes() == expected_stream_raw))
    product_stable = api is None or current_sources() == product_sources
    remaining = [] if image is None else custody_snapshot()
    selected_ok = (image is None or (frame_counts['1'] == 8 and frame_counts['2'] == 8
        and all(per_case_entries[name] > 0 for name in planned)
        and args.manifest.read_bytes() == manifest_raw and image_path.read_bytes() == image_raw))
    route_ok = api is None or public_counts == Counter({'1': 8, '2': 8})
    good = (stable and authority_stable and product_stable and selected_ok and route_ok
            and not remaining and started == stopped == planned
            and not mismatches and not errors and not fault_misses)
    files = {}
    for name in ('observations.jsonl', 'raw-tracebacks.jsonl'):
        files[name] = pin((args.output / name).read_bytes())
    report = {
        'schema': 'hepta.hia.service-inspection-public-lifetime-child.v1',
        'status': 'PASS' if good else 'HOLD', 'backend': args.backend,
        'runtime': current_runtime, 'planned': planned, 'started': started, 'stopped': stopped,
        'mismatches': mismatches, 'observer_errors': errors, 'fault_misses': fault_misses,
        'source_freeze_sha256': sha256(freeze_raw).hexdigest(),
        'source_pins': freeze['files'], 'source_unchanged': stable,
        'original_authority_unchanged': authority_stable,
        'original_report_pin': None if expected_raw is None else pin(expected_raw),
        'files': files, 'product_imported': api is not None,
        'actual_public_dispatch': api is not None,
        'unselected_reference_has_exact_frozen_body_and_fake_globals': args.backend == 'unselected',
        'selected_retained_complete_handlers_poisoned': args.backend == 'native',
        'constructor_only_injects_original_namespace': args.backend == 'native',
        'frame_counts': dict(frame_counts), 'native_entry_counts': dict(entry_counts),
        'public_dispatch_counts': dict(public_counts), 'entries_by_case': dict(per_case_entries),
        'remaining_delivery_custody': remaining, 'product_sources': product_sources,
        'product_sources_unchanged': product_stable,
        'manifest': None if args.manifest is None else str(args.manifest),
        'manifest_pin': None if manifest_raw is None else pin(manifest_raw),
        'image_pin': None if image_raw is None else pin(image_raw),
        'started_time_ns': begin, 'finished_time_ns': time.time_ns(),
        'pid': os.getpid(), 'pgid': os.getpgid(0), 'parent_pid': os.getppid(),
        'argv': sys.argv, 'cwd': os.getcwd(),
        'old_116_and_9_basis_replaced': False, 'actual_SQL_or_external_provider': False,
        'whole_qualification': False, 'all_runtime_histories_proved': False,
    }
    put(args.output / 'report.json', report)
    print(encoded({'status': report['status'], 'backend': args.backend,
                   'cases': len(started), 'report_pin': pin((args.output / 'report.json').read_bytes())}).decode(), end='')
    return 0 if good else 1


if __name__ == '__main__':
    raise SystemExit(main())

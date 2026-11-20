"""One isolated original or actual-image service-slot observation stream.

This program never derives expected results from HIA. A candidate child requires
the complete prior original child report, its immutable ordered inputs, exact
runtime identity and full original semantic/late-event bytes.
"""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import platform
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
ORACLE_PATH = ROOT / 'tests/hia_service_slot_original_oracle.py'
INPUT_PATH = ROOT / 'tests/fixtures/hia_service_slot_observation_inputs_v1/inputs.json'
ORIGINAL_ROOT = ROOT / 'tests/fixtures/hia_service_slot_original_bc011'
INPUTS_SHA256 = '625d6fdb004b28e0f207f1fc22052dca55b28bacea09d9f3053674a78ee9d001'


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def digest(path):
    value = sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            value.update(chunk)
    return value.hexdigest()


def write(path, value):
    with Path(path).open('xb') as target:
        target.write(encoded(value))


def runtime():
    return {'version': sys.version, 'implementation': platform.python_implementation(),
            'cache_tag': sys.implementation.cache_tag, 'executable': str(Path(sys.executable).resolve()),
            'pointer_bits': struct.calcsize('P') * 8}


def source_snapshot():
    paths = [Path(__file__).resolve(), ORACLE_PATH, INPUT_PATH,
             ORIGINAL_ROOT / 'rollback.bc011.py.txt', ORIGINAL_ROOT / 'adopt.bc011.py.txt',
             ORIGINAL_ROOT / 'FREEZE.json']
    return {str(path.relative_to(ROOT)): {'bytes': path.stat().st_size,
            'sha256': digest(path)} for path in paths}


def reject_original_execution(event, arguments):
    if event == 'import' and (arguments[0] == 'hepta' or arguments[0].startswith('hepta.')):
        raise RuntimeError('original observer cannot import a product module')
    if event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.posix_spawnp',
                 'os.fork', 'os.forkpty', 'sqlite3.connect'):
        raise RuntimeError('observer cannot run a provider process or real SQL: ' + event)
    if event.startswith('os.exec'):
        raise RuntimeError('observer cannot replace its process')


def load_oracle():
    spec = importlib.util.spec_from_file_location('hia_service_slot_original_oracle', ORACLE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def lines(path):
    with Path(path).open('rb') as source:
        for index, raw in enumerate(source):
            if not raw.endswith(b'\n'):
                raise ValueError('truncated input line: ' + str(index))
            value = json.loads(raw)
            if encoded(value) != raw:
                raise ValueError('input is not the fixed canonical encoding')
            yield value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kind', choices=('original', 'native'), required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--cases-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    if digest(INPUT_PATH) != INPUTS_SHA256:
        raise ValueError('independent frozen base inputs changed')
    if digest(args.cases) != args.cases_sha256:
        raise ValueError('frozen ordered cases differ')
    if args.kind == 'original' and (args.expected is not None or args.manifest is not None):
        raise ValueError('original observer must have no candidate capability')
    if args.kind == 'native' and (args.expected is None or args.manifest is None):
        raise ValueError('native observer requires exact prior original evidence')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    started_ns = time.time_ns()
    before, runtime_before = source_snapshot(), runtime()
    write(args.output / 'source-before.json', before)
    write(args.output / 'runtime.json', runtime_before)
    sys.addaudithook(reject_original_execution if args.kind == 'original' else
                     lambda event, arguments: reject_original_execution(event, arguments)
                     if event != 'import' else None)
    oracle = load_oracle()
    oracle.original_sources()
    expected_report = None
    expected_report_raw = None
    expected_files = {}
    expected_stream = expected_late_stream = None
    original_written_before_mapping = False
    reference_calls = []
    frames = {'rollback': 0, 'adopt': 0}
    entries = {'0': 0, '1': 0, '2': 0, '3': 0, '4': 0}
    image = saved_entry = None
    api = native = None
    source_before = manifest_bytes = source_bytes = image_bytes = None
    manifest_value = None
    old_aliases = None
    original_frame_class = None
    constructor_context = None
    old_selector_present = False
    old_selector = None
    public_dispatch_calls = {'rollback': 0, 'adopt': 0}
    mapped_time_ns = None
    complete = False
    count = 0
    ids, differences, witness_failures = [], [], []
    seen_ids = set()
    parent_pid, parent_pgid = os.getppid(), os.getpgid(0)

    if args.kind == 'native':
        report_path = args.expected / 'report.json'
        expected_report_raw = report_path.read_bytes()
        expected_report = json.loads(expected_report_raw)
        if (expected_report.get('schema') != 'hepta.hia.service-slot-observer.v1'
                or expected_report.get('kind') != 'original'
                or expected_report.get('status') != 'PASS'
                or expected_report.get('runtime') != runtime_before
                or expected_report.get('inputs_sha256') != args.cases_sha256
                or expected_report.get('source_before') != before
                or expected_report.get('source_after') != before
                or expected_report.get('product_imported') is not False):
            raise ValueError('prior complete original/runtime/source authority differs')
        for name in ('observations.jsonl', 'late-events.jsonl', 'tracebacks.jsonl'):
            path = args.expected / name
            expected_files[name] = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest(path)}
        expected_files['report.json'] = {'path': str(report_path),
            'bytes': len(expected_report_raw), 'sha256': sha256(expected_report_raw).hexdigest()}
        if report_path.read_bytes() != expected_report_raw:
            raise ValueError('original report changed after its captured-byte admission')
        if (expected_files['observations.jsonl']['sha256'] != expected_report['observations_sha256']
                or expected_files['late-events.jsonl']['sha256'] != expected_report['late_events_sha256']
                or expected_files['tracebacks.jsonl']['sha256'] != expected_report['tracebacks_sha256']):
            raise ValueError('original stream changed before candidate admission')
        write(args.output / 'accepted-original-evidence.json', {
            'accepted_time_ns': time.time_ns(), 'report': expected_report,
            'files': expected_files, 'source_snapshot': before})
        original_written_before_mapping = True
        # The saved independent expected stream was accepted before this first
        # product import. It is never regenerated by a candidate child.
        sys.path.insert(0, str(ROOT))
        from hepta import hia_agent_service as api
        from hepta import hia_service_slot_native as native
        from hepta import hia_native_delivery as delivery
        from tools.build_hia_json_preflight import current_sources
        source_before = current_sources()
        manifest_bytes = args.manifest.read_bytes()
        manifest_value = json.loads(manifest_bytes)
        source_bytes = native.SOURCE.read_bytes()
        image_path = args.manifest.parent / manifest_value['image_path']
        image_bytes = image_path.read_bytes()
        if (sha256(source_bytes).hexdigest() != manifest_value['source_sha256']
                or sha256(image_bytes).hexdigest() != manifest_value['image_sha256']):
            raise ValueError('candidate source/image identity differs')
        write(args.output / 'candidate-inputs-before.json', {
            'sources': source_before, 'manifest': str(args.manifest),
            'manifest_sha256': sha256(manifest_bytes).hexdigest(), 'manifest_value': manifest_value,
            'image_sha256': sha256(image_bytes).hexdigest(),
            'source_sha256': sha256(source_bytes).hexdigest()})
        image = native.installed_service_slot(str(args.manifest))
        mapped_time_ns = time.time_ns()
        saved_entry = image._entry

        def entry(source, size, output, capacity, state, extent):
            packet = struct.unpack('<10Q', ctypes.string_at(source, size))
            result = saved_entry(source, size, output, capacity, state, extent)
            event = str(packet[1])
            if event not in entries:
                raise AssertionError('unexpected continuation event')
            entries[event] += 1
            return result

        image._entry = entry
        old_aliases = (api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE,
                       api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE)

        def forbidden(*values, **keywords):
            reference_calls.append('retained complete original handler')
            raise AssertionError('selected service-slot called a retained whole handler')

        api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE = forbidden
        api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = forbidden

        original_frame_class = native.ServiceSlotFrame
        constructor_context = {}
        old_selector_present = native.SELECTOR in os.environ
        old_selector = os.environ.get(native.SELECTOR)
        os.environ[native.SELECTOR] = str(args.manifest.resolve())

        def public_constructor(selected_image, selected_mode, service, arguments):
            mode = constructor_context['mode']
            if (selected_image is not image or selected_mode !=
                    (native.ROLLBACK if mode == 'rollback' else native.ADOPT)):
                raise AssertionError('actual public dispatcher selected another image or mode')
            frames[mode] += 1
            # Only the constructor receives the independent fake provider
            # namespace. It returns before the real public dispatcher invokes
            # finish, so this observer does not retain service/arguments across
            # any HIA effect or terminal local release.
            return original_frame_class(selected_image, selected_mode, service,
                arguments, namespace=constructor_context['namespace'])

        native.ServiceSlotFrame = public_constructor

        def factory(mode, make_service, make_arguments, namespace):
            constructor_context['mode'] = mode
            constructor_context['namespace'] = namespace
            try:
                public_dispatch_calls[mode] += 1
                method = (api.HIAAgentService._hia_rollback if mode == 'rollback'
                          else api.HIAAgentService._hia_adopt)
                return method(make_service(), make_arguments())
            finally:
                constructor_context.clear()

        expected_stream = (args.expected / 'observations.jsonl').open('rb')
        expected_late_stream = (args.expected / 'late-events.jsonl').open('rb')
    else:
        factory = None

    observations = (args.output / 'observations.jsonl').open('xb')
    late_output = (args.output / 'late-events.jsonl').open('xb')
    raw_output = (args.output / 'tracebacks.jsonl').open('xb')
    cuts_output = (args.output / 'cutpoints.jsonl').open('xb')
    comparisons = (args.output / 'comparisons.jsonl').open('xb')
    fatal = None
    try:
        for case in lines(args.cases):
            if type(case.get('id')) is not str or case['id'] in seen_ids:
                raise ValueError('invalid or duplicate ordered input identity')
            row = oracle.observe(case, factory=factory)
            actual = encoded(row['observation'])
            late = encoded({'case': case['id'], 'late_events': row['late_events']})
            observations.write(actual)
            late_output.write(late)
            raw_output.write(encoded({'case': case['id'], 'tracebacks': row['raw_tracebacks']}))
            cuts_output.write(encoded({'case': case['id'], 'cutpoints': row['cutpoints']}))
            if (row['observation']['callback_errors']
                    or (case.get('fault') is not None and not row['observation']['fault_injected'])):
                witness_failures.append(case['id'])
            equal = late_equal = None
            expected_hash = expected_late_hash = None
            if expected_stream is not None:
                expected_raw, expected_late = expected_stream.readline(), expected_late_stream.readline()
                equal, late_equal = actual == expected_raw, late == expected_late
                expected_hash, expected_late_hash = sha256(expected_raw).hexdigest(), sha256(expected_late).hexdigest()
                if not equal or not late_equal:
                    differences.append({'case': case['id'], 'observation_equal': equal,
                        'late_events_equal': late_equal, 'expected_sha256': expected_hash,
                        'actual_sha256': sha256(actual).hexdigest(),
                        'expected_late_sha256': expected_late_hash,
                        'actual_late_sha256': sha256(late).hexdigest()})
            comparisons.write(encoded({'case': case['id'], 'equal': equal, 'late_equal': late_equal,
                'actual_sha256': sha256(actual).hexdigest(), 'expected_sha256': expected_hash,
                'actual_late_sha256': sha256(late).hexdigest(), 'expected_late_sha256': expected_late_hash}))
            ids.append(case['id'])
            seen_ids.add(case['id'])
            count += 1
        if expected_stream is not None and (expected_stream.read(1) or expected_late_stream.read(1)):
            raise ValueError('candidate stream did not consume the full original scope')
        if expected_report is not None and ids != expected_report['ordered_ids']:
            raise ValueError('candidate ordered IDs differ from original full scope')
        complete = True
    except BaseException as error:
        fatal = {'type': type(error).__name__, 'message': str(error),
                 'traceback': traceback.format_exc()}
    finally:
        for stream in (observations, late_output, raw_output, cuts_output, comparisons,
                       expected_stream, expected_late_stream):
            if stream is not None:
                stream.close()
        if image is not None:
            image._entry = saved_entry
        if old_aliases is not None:
            (api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE,
             api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE) = old_aliases
        if original_frame_class is not None:
            native.ServiceSlotFrame = original_frame_class
            constructor_context.clear()
            if old_selector_present:
                os.environ[native.SELECTOR] = old_selector
            else:
                os.environ.pop(native.SELECTOR, None)

    after = source_snapshot()
    original_unchanged = (all(digest(row['path']) == row['sha256'] for row in expected_files.values())
        and (expected_report_raw is None or report_path.read_bytes() == expected_report_raw))
    candidate_unchanged = None
    custody = []
    if args.kind == 'native':
        candidate_unchanged = (args.manifest.read_bytes() == manifest_bytes
            and native.SOURCE.read_bytes() == source_bytes
            and image_path.read_bytes() == image_bytes and current_sources() == source_before)
        custody = delivery.custody_snapshot()
        write(args.output / 'candidate-inputs-after.json', {'sources': current_sources(),
            'manifest_sha256': digest(args.manifest), 'image_sha256': digest(image_path),
            'source_sha256': sha256(native.SOURCE.read_bytes()).hexdigest()})
    write(args.output / 'source-after.json', after)
    write(args.output / 'differences.json', differences)
    status = ('PASS' if complete and fatal is None and before == after and original_unchanged
              and not differences and not witness_failures and not custody
              and candidate_unchanged is not False and not reference_calls else 'HOLD')
    report = {'schema': 'hepta.hia.service-slot-observer.v1', 'status': status,
        'kind': args.kind, 'runtime': runtime_before, 'pid': os.getpid(),
        'parent_pid': parent_pid, 'pgid': parent_pgid,
        'argv': sys.argv, 'cwd': os.getcwd(), 'started_time_ns': started_ns,
        'finished_time_ns': time.time_ns(), 'inputs_path': str(args.cases),
        'inputs_sha256': args.cases_sha256, 'count': count, 'ordered_ids': ids,
        'scope_complete': complete, 'fatal': fatal, 'witness_failures': witness_failures,
        'observations_sha256': digest(args.output / 'observations.jsonl'),
        'late_events_sha256': digest(args.output / 'late-events.jsonl'),
        'tracebacks_sha256': digest(args.output / 'tracebacks.jsonl'),
        'cutpoints_sha256': digest(args.output / 'cutpoints.jsonl'),
        'source_before': before, 'source_after': after,
        'expected_files': expected_files, 'expected_file_unchanged': original_unchanged,
        'original_written_before_mapping': original_written_before_mapping,
        'candidate_mapped_time_ns': mapped_time_ns, 'candidate_source_image_manifest_unchanged': candidate_unchanged,
        'manifest_sha256': None if manifest_bytes is None else sha256(manifest_bytes).hexdigest(),
        'manifest_value': manifest_value, 'source_manifest': source_before,
        'actual_frames': frames, 'actual_native_entries': entries, 'remaining_delivery_custody': custody,
        'actual_public_dispatch_selected': args.kind == 'native',
        'public_dispatch_calls': public_dispatch_calls,
        'constructor_namespace_glue': ('independent fake namespace only; real public dispatcher, '
            'loader, original frame class and finish' if args.kind == 'native' else None),
        'retained_reference_poisoned': args.kind == 'native',
        'reference_calls': reference_calls, 'differences': differences,
        'product_imported': args.kind == 'native',
        'VM_executed': False, 'SQL_executed': False,
        'all_inputs_or_whole_stack_qualified': False}
    write(args.output / 'report.json', report)
    print(encoded({'status': status, 'kind': args.kind, 'count': count,
                   'differences': len(differences), 'report_sha256': digest(args.output / 'report.json')}).decode(), end='')
    return 0 if status == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Eight protocol-05 controls under one original 180/3 matching-cold owner.

The original protocol-04 six controls and all original 89 callers are separate
unchanged populations. This entry reuses their cold, compile, custody and owner
readers and preserves all 547 complete capture/projection records for Native8.
"""
from __future__ import annotations
import argparse, base64, ctypes, json, os, stat, struct, sys, time, traceback, unittest
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_json_wire_key_summary as legacy
SCHEMA = 'hepta.hia.json-wire-leaf-cache-native8.v1'
SCOPE = 'MATCHING_SOURCE_COLD_WIRE_LEAF_CACHE_NATIVE8'
CLASS = 'tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests'
IDS = (
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_01_scalar_and_string_boundaries_full_request_projection",
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_02_fanout_depth_cycle_budget_and_failure_order",
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_03_capacity_and_handle_collisions_fall_back",
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_04_protocol_packets_extents_and_canaries",
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_05_custom_replaced_observer_and_renderer_stay_protocol02",
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_06_ordinary_fresh_sessions_forbid_host_encoder_and_retained_owner",
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_07_long_strings_and_key_value_identity_keep_original_windows",
    "tests.test_hia_json_wire_leaf_cache.WireLeafCacheNativeTests.test_08_digit_limit_and_limb_requests_are_never_cached",
)
ANOMALIES = legacy.ANOMALIES
SOURCE_FILES = legacy.SOURCE_FILES + (
    'tools/qualify_hia_json_wire_leaf_cache.py',
    'tests/test_hia_json_wire_leaf_cache.py')
CAPTURES = (144, 168, 2, 0, 10, 0, 28, 16)
PROJECTIONS = (72, 84, 1, 0, 0, 0, 14, 8)
TRACE_ROW_LIMIT = 8 << 20
TRACE_BYTES_LIMIT = 128 << 20
TRACE_RECORD_LIMIT = 20000
require = legacy.require
read, pin, json_read, create = legacy.read, legacy.pin, legacy.json_read, legacy.create
runtime_identity, fixture_binding = legacy.runtime_identity, legacy.fixture_binding
flatten, closed_owner = legacy.flatten, legacy.closed_owner

def cold_context(cold):
    context = legacy.cold_context(cold)
    for name in SOURCE_FILES:
        require(context['source_manifest'].get(name) == pin(ROOT / name)['sha256'],
                'wire8 dependency is outside this exact cold source closure: ' + name)
    return context

def owned_environment(environment, cold, fixture):
    result = legacy.owned_environment(environment, cold, fixture)
    result.pop('HEPTA_HIA_JSON_WIRE_KEY_SUMMARY_FIXTURE_EVIDENCE')
    result['HEPTA_HIA_JSON_WIRE_LEAF_CACHE_FIXTURE_EVIDENCE'] = str(Path(fixture).absolute())
    return result

def inventory(directory):
    result = []
    for path in sorted(Path(directory).rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode), 'wire8 retained output is not a regular file')
        bound = TRACE_BYTES_LIMIT if path.name == 'native8-projection-trace.jsonl' else 16 << 20
        result.append(pin(path, bound))
    return result

def inspect_trace(directory, expected):
    path = Path(directory) / 'native8-projection-trace.jsonl'
    raw = read(path, TRACE_BYTES_LIMIT)
    observed = pin(path, TRACE_BYTES_LIMIT)
    require(expected['file'] == observed and expected['records'] == 547
            and expected['capture_records'] == 368 and expected['projection_records'] == 179,
            'wire8 whole trace pin/population differs')
    captures, projections, seen = [0] * 8, [0] * 8, {}
    lines = raw.splitlines(keepends=True)
    require(len(lines) == 547, 'wire8 complete trace row count differs')
    for index, line in enumerate(lines):
        row = json.loads(line)
        require((json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode() == line
                and type(row['index']) is int and row['index'] == index
                and row['test'] in IDS, 'wire8 full canonical trace row differs')
        method = IDS.index(row['test'])
        value = row['value']
        if row['kind'] == 'complete-capture':
            captures[method] += 1
            ci = value['capture_index']
            require(type(ci) is int and ci == len(seen), 'wire8 exact capture sequence differs')
            seen[ci] = (row['test'], value)
        else:
            require(row['kind'] == 'successful-projection', 'wire8 trace kind differs')
            projections[method] += 1
            a, b = value['old_capture'], value['new_capture']
            require(type(a) is int and type(b) is int and a in seen and b in seen
                    and seen[a][0] == seen[b][0] == row['test'], 'wire8 projection capture binding differs')
            positions = value['omitted_old_rows']
            require(type(positions) is list and all(type(x) is int for x in positions)
                    and positions == sorted(set(positions))
                    and all(0 <= x < len(seen[a][1]['trace']) for x in positions),
                    'wire8 complete omitted-row positions differ')
    require(tuple(captures) == CAPTURES and tuple(projections) == PROJECTIONS,
            'wire8 per-method capture/projection population differs')
    return {'file': observed, 'records': 547, 'capture_records': 368, 'projection_records': 179}

def validate_child(value, context, runtime, binding, directory):
    require(type(value) is dict and value.get('schema') == SCHEMA and value.get('status') == 'PASS'
            and value.get('scope') == SCOPE and value.get('error') is None
            and value.get('preservation_error') is None and value.get('recording_errors') == []
            and value.get('recording_failed') is False,
            'wire8 child did not pass with complete original diagnostics')
    for key in ('expected_ids', 'loaded_ids', 'executed_ids'):
        require(value.get(key) == list(IDS), 'wire8 complete eight-method order differs: ' + key)
    require(type(value.get('tests_run')) is int and value['tests_run'] == 8
            and value.get('unittest_successful') is True and value.get('loader_errors') == []
            and all(value.get(key) == [] for key in ANOMALIES), 'wire8 original result has anomalies')
    require(value.get('cold_before') == context == value.get('cold_after')
            and value.get('runtime_before') == runtime == value.get('runtime_after')
            and value.get('fixture_before') == binding == value.get('fixture_after')
            and type(value.get('fixture_setup_calls')) is int and value['fixture_setup_calls'] == 1
            and value.get('fixture_scope') == 'MATCHING_SOURCE_COLD_BUILD'
            and value.get('foreign_object_transport_still_hosted') is True
            and value.get('original_wire89_pass_claimed') is False
            and value.get('whole_native_delivery_qualified') is False,
            'wire8 fixture/runtime/source identity or scope differs')
    rows = value.get('actual_wire_step_returns')
    require(type(rows) is list and rows, 'wire8 has no actual normal step returns')
    seen, tests, protocols, statuses = set(), set(), set(), set()
    accepted_magic = tuple(int.from_bytes(word, 'little') for word in (b'HIAWIR02', b'HIAWIR04', b'HIAWIR05'))
    for row in rows:
        require(type(row) is dict and set(row) == {'test', 'image_sha256', 'session_protocol_magic', 'status', 'count'}
                and row['test'] in IDS and row['image_sha256'] == binding['wire']['manifest']['image_sha256']
                and type(row['session_protocol_magic']) is int and row['session_protocol_magic'] in accepted_magic
                and type(row['status']) is int and 0 <= row['status'] < (1 << 32)
                and type(row['count']) is int and row['count'] > 0,
                'wire8 normal step row lacks its exact method/image/protocol binding')
        key = (row['test'], row['image_sha256'], row['session_protocol_magic'], row['status'])
        require(key not in seen, 'duplicate wire8 normal step row')
        seen.add(key); tests.add(row['test']); protocols.add(row['session_protocol_magic']); statuses.add(row['status'])
    require(tests == set(IDS) and protocols == set(accepted_magic) and {1, 2, 199} <= statuses,
            'wire8 complete method/legacy/current/rejection native observations differ')
    require(value.get('denied_VM') == [] and value.get('capture_counts') == list(CAPTURES)
            and value.get('projection_counts') == list(PROJECTIONS)
            and all(type(n) is int for n in value['capture_counts'] + value['projection_counts']),
            'wire8 VM exclusion or exact complete projection counts differ')
    entries = value.get('actual_native_entries')
    require(type(entries) is list and entries, 'wire8 actual native entries missing')
    entry_tests, entry_keys = set(), set()
    for row in entries:
        require(type(row) is dict and set(row) == {'test', 'status', 'count'}
                and row['test'] in IDS and type(row['status']) is int
                and 0 <= row['status'] < (1 << 32) and type(row['count']) is int
                and row['count'] > 0, 'wire8 actual native entry row differs')
        key = (row['test'], row['status'])
        require(key not in entry_keys, 'wire8 duplicate native entry row')
        entry_keys.add(key); entry_tests.add(row['test'])
    require(entry_tests == set(IDS), 'wire8 some method never returned from the native entry')
    inspect_trace(directory, value['trace'])
    return value


def child(cold, directory):
    from tests import test_hia_json_wire_leaf_cache as cases
    from hepta import hia_json_wire_native as bridge
    from hepta import hia_program_runtime as core_runtime
    context, runtime = cold_context(cold), runtime_identity()
    directory = Path(directory).absolute()
    require(not directory.exists(), 'wire8 child output already exists')
    directory.mkdir(mode=0o700)
    fixture = directory / 'fixture'
    environment = owned_environment(os.environ, cold, fixture)
    report = {'schema': SCHEMA, 'scope': SCOPE, 'status': 'HOLD', 'expected_ids': list(IDS),
        'loaded_ids': [], 'executed_ids': [], 'loader_errors': [], 'fixture_setup_calls': 0,
        'fixture_scope': None, 'fixture_before': None, 'fixture_after': None,
        'cold_before': context, 'cold_after': None, 'runtime_before': runtime, 'runtime_after': None,
        'recording_errors': [], 'recording_failed': False,
        'denied_VM': [], 'capture_counts': [0] * 8, 'projection_counts': [0] * 8, 'foreign_object_transport_still_hosted': True,
        'original_wire89_pass_claimed': False, 'whole_native_delivery_qualified': False,
        'step_meaning': 'WireSession.step returned normally from the admitted wire image; not whole-method PASS.',
        'protocol_meaning': 'Session initial protocol; deliberate malformed ACK bytes are tested separately.'}
    current, returned, recording_failed = ['outside-test'], Counter(), [False]
    captures, native_entries = {}, Counter()
    trace_n, trace_bytes, trace_hash = [0], [0], sha256()
    trace = None
    image_holder, actual_entry, entry_wrapper = [None], [None], [None]
    started = time.monotonic()
    actual_setup = cases.WireLeafCacheNativeTests.setUpClass
    actual_step = bridge.WireSession.step
    actual_capture, actual_projection = cases._capture, cases._projection

    def error():
        recording_failed[0] = True
        try:
            report['recording_errors'].append(traceback.format_exc())
        except BaseException:
            pass
    def atom(value):
        if value is None:return {'type':'None'}
        if type(value) is bool:return {'type':'bool','value':value}
        if type(value) is int:
            magnitude=abs(value)
            return {'type':'int','negative':value<0,'magnitude_le':magnitude.to_bytes((magnitude.bit_length()+7)//8 or 1,'little').hex()}
        if type(value) is float:return {'type':'float','bits':struct.pack('<d',value).hex()}
        if type(value) is str:return {'type':'str','utf32le':value.encode('utf-32le','surrogatepass').hex()}
        if type(value) is bytes:return {'type':'bytes','base64':base64.b64encode(value).decode()}
        return {'type':'container-or-opaque','module':type(value).__module__,'name':type(value).__qualname__}
    def encode(value):
        if type(value) is bytes:return {'bytes_base64':base64.b64encode(value).decode()}
        if type(value) in (tuple,list):return [encode(x) for x in value]
        if type(value) is dict:return {str(k):encode(v) for k,v in value.items()}
        return value
    def record(kind,value):
        row={'index':trace_n[0],'kind':kind,'test':current[0],'value':encode(value)}
        raw=(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode()
        require(len(raw)<=TRACE_ROW_LIMIT and trace_n[0]<TRACE_RECORD_LIMIT
                  and trace_bytes[0]+len(raw)<=TRACE_BYTES_LIMIT,'finite complete diagnostic trace extent')
        trace.write(raw);trace_hash.update(raw);trace_n[0]+=1;trace_bytes[0]+=len(raw)
    def denied(*a,**k):
        report['denied_VM'].append(current[0]);raise AssertionError('Native8 must not enter Core VM')

    def setup(cls):
        report['fixture_setup_calls'] += 1
        actual_setup()
        require(type(cls.image) is bridge.NativeJsonWire and cls.temp is None,
                'wire8 fixture is not the retained current-cold native image')
        report['fixture_scope'] = cls.scope
        report['fixture_before'] = fixture_binding(fixture, context)
        require(cls.image.image_sha256 == report['fixture_before']['wire']['manifest']['image_sha256']
                and cls.format_image.image_sha256 == report['fixture_before']['format']['manifest']['image_sha256'],
                'wire8 live fixture images differ from the compiled originals')

        image_holder[0] = cls.image
        actual_entry[0] = cls.image._entry
        report['actual_native_entry_address'] = ctypes.cast(actual_entry[0], ctypes.c_void_p).value
        report['actual_native_logical_image_bytes'] = len(cls.image._mapping)
        require(bytes(cls.image._mapping) == read(fixture / 'build/json-wire.image.bin'),
                'wire8 complete live image differs')
        def entry(*args):
            status = actual_entry[0](*args)
            try:
                require(current[0] in IDS and type(status) is int, 'wire8 native entry active method')
                native_entries[(current[0], status)] += 1
            except BaseException:
                error()
            return status
        entry_wrapper[0] = entry
        cls.image._entry = entry

    def step(session, packet=None):
        status = actual_step(session, packet)
        try:
            require(session.image is cases.WireLeafCacheNativeTests.image and current[0] in IDS,
                    'wire8 step escaped its actual native fixture or active method')
            returned[(current[0], session.image.image_sha256, session._protocol_magic, status)] += 1
        except BaseException:
            # Recording cannot replace the original normal return. Qualification
            # independently refuses even one preserved recording failure.
            recording_failed[0] = True
            try:
                report['recording_errors'].append(traceback.format_exc())
            except BaseException:
                pass
        return status

    def capture(*values,**options):
        result=actual_capture(*values,**options)
        try:
            index=IDS.index(current[0]);report['capture_counts'][index]+=1
            capture_index=sum(report['capture_counts'])-1;captures[id(result)]=capture_index
            evidence={k:v for k,v in result.items() if k not in ('session','observer','outcome')}
            evidence['outcome']=[result['outcome'][0],atom(result['outcome'][1])]
            evidence['capture_index']=capture_index
            evidence['initial_protocol_magic']=result['session']._protocol_magic
            evidence['observer_values']={str(h):atom(v) for h,v in result['observer']._objects.items()}
            record('complete-capture',evidence)
        except BaseException:error()
        return result
    def projection(case,old,new):
        omitted=actual_projection(case,old,new)
        try:
            index=IDS.index(current[0]);report['projection_counts'][index]+=1
            positions={id(row):i for i,row in enumerate(old['trace'])}
            record('successful-projection',{'old_capture':captures[id(old)],'new_capture':captures[id(new)],
                'omitted_old_rows':[positions[id(row)] for row in omitted]})
        except BaseException:error()
        return omitted

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            current[0] = test.id()
            report['executed_ids'].append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            try:
                return super().stopTest(test)
            finally:
                current[0] = 'outside-test'

    try:
        trace = (directory / 'native8-projection-trace.jsonl').open('xb')
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(CLASS)
        report['loaded_ids'] = [test.id() for test in flatten(suite)]
        report['loader_errors'] = list(loader.errors)
        require(report['loaded_ids'] == list(IDS) and not loader.errors, 'wire8 exact test discovery differs')
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            stack.enter_context(patch.object(cases.WireLeafCacheNativeTests, 'setUpClass', classmethod(setup)))
            stack.enter_context(patch.object(bridge.WireSession, 'step', step))
            stack.enter_context(patch.object(cases, '_capture', capture))
            stack.enter_context(patch.object(cases, '_projection', projection))
            stack.enter_context(patch.object(core_runtime._Machine, 'invoke', side_effect=denied))
            stream = stack.enter_context((directory / 'unittest.log').open('x'))
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        require(image_holder[0] is not None and image_holder[0]._entry is entry_wrapper[0],
                'wire8 fixture entry wrapper changed')
        report.update(tests_run=result.testsRun, unittest_successful=result.wasSuccessful())
        for key, attr in zip(ANOMALIES, ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')):
            report[key] = [dict(test=item[0].id(), detail=item[1]) if isinstance(item, tuple)
                           else dict(test=item.id()) for item in getattr(result, attr)]
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        if image_holder[0] is not None and actual_entry[0] is not None:
            image_holder[0]._entry = actual_entry[0]
        report['actual_native_entries'] = [dict(test=key[0], status=key[1], count=count)
            for key, count in sorted(native_entries.items())]
        report['recording_failed'] = recording_failed[0]
        report['actual_wire_step_returns'] = [dict(test=key[0], image_sha256=key[1],
            session_protocol_magic=key[2], status=key[3], count=count) for key, count in sorted(returned.items())]
        try:
            if trace is not None:
                trace.flush(); os.fsync(trace.fileno()); trace.close()
                actual_trace = read(directory / 'native8-projection-trace.jsonl', TRACE_BYTES_LIMIT)
                require(len(actual_trace) == trace_bytes[0]
                        and sha256(actual_trace).hexdigest() == trace_hash.hexdigest(),
                        'wire8 full trace readback differs')
                report['trace'] = {'file': pin(directory / 'native8-projection-trace.jsonl', TRACE_BYTES_LIMIT),
                    'records': trace_n[0], 'capture_records': sum(report['capture_counts']),
                    'projection_records': sum(report['projection_counts'])}
            report['cold_after'] = cold_context(cold)
            report['runtime_after'] = runtime_identity()
            report['fixture_after'] = fixture_binding(fixture, context)
            validate_child(report, context, runtime, report['fixture_after'], directory)
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        create(directory / 'report.json', report)
    return 0 if report['status'] == 'PASS' else 1


def owned(cold, directory):
    from tools import hia_selfhost_process_owner as owner
    context, runtime = cold_context(cold), runtime_identity()
    directory = Path(directory).absolute()
    require(not directory.exists(), 'preserve previous wire8 originals; use a new evidence directory')
    directory.mkdir(mode=0o700, parents=True)
    owner_dir = directory / 'owner'; owner_dir.mkdir(mode=0o700)
    child_dir = directory / 'child'
    command = [sys.executable, '-B', str(Path(__file__).resolve()), '--child',
               '--cold-report', str(Path(cold).resolve(strict=True)), '--evidence-dir', str(child_dir)]
    environment = owned_environment(os.environ, cold, child_dir / 'fixture')
    final = {'schema': SCHEMA, 'scope': SCOPE, 'status': 'HOLD', 'closed': False,
             'command': command, 'environment': environment, 'cwd': str(ROOT),
             'expected_ids': list(IDS), 'qualification_seconds': 180, 'cleanup_seconds': 3,
             'cold_before': context, 'runtime_before': runtime,
             'original_wire89_unchanged': True, 'original_cache7_unchanged': True,
             'original_Core116_UNPACK18_and_32_gates_unchanged': True,
             'whole_native_delivery_qualified': False}
    create(directory / 'INTENT.json', final)
    returned = None
    try:
        returned = owner.run_owned(command, cwd=ROOT, env=environment,
            stdout_path=owner_dir / 'child.stdout.log', stderr_path=owner_dir / 'child.stderr.log',
            receipt_path=owner_dir / 'process-owner.json', qualification_seconds=180, cleanup_seconds=3)
        create(directory / 'RETURNED-OWNER.json', returned)
        final['owner'] = closed_owner(returned, owner_dir, command, environment)
        final['closed'] = True
        require(final['owner']['natural'], 'wire8 owner did not finish naturally inside its original budget')
        binding = fixture_binding(child_dir / 'fixture', context)
        report = json_read(child_dir / 'report.json')
        validate_child(report, context, runtime, binding, child_dir)
        final.update(child_report=pin(child_dir / 'report.json'), fixture=binding,
                     actual_wire_step_returns=report['actual_wire_step_returns'],
                     actual_native_entries=report['actual_native_entries'], trace=report['trace'])
        final['status'] = 'MATCHING_COLD_WIRE_LEAF_CACHE_NATIVE8_PASS'
    except BaseException:
        final['status'] = 'HOLD'
        final['error'] = traceback.format_exc()
    finally:
        if final['closed']:
            try:
                final['retained_originals'] = inventory(directory)
                final['cold_after'] = cold_context(cold)
                final['runtime_after'] = runtime_identity()
                require(final['cold_after'] == context and final['runtime_after'] == runtime,
                        'wire8 current cold/source/runtime changed after closure')
            except BaseException:
                final['status'] = 'HOLD'
                final['preservation_error'] = traceback.format_exc()
        else:
            final['child_originals_read'] = False
            final['unconfirmed_owner_originals_left_in_place'] = True
        create(directory / 'FINAL.json', final)
    print(json.dumps({key: final.get(key) for key in ('schema', 'scope', 'status', 'closed', 'error')}, sort_keys=True))
    return 0 if final['status'] == 'MATCHING_COLD_WIRE_LEAF_CACHE_NATIVE8_PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--child', action='store_true')
    args = parser.parse_args()
    return child(args.cold_report, args.evidence_dir) if args.child else owned(args.cold_report, args.evidence_dir)


if __name__ == '__main__':
    raise SystemExit(main())

"""Exact legal 8 MiB and one-byte-larger candidate, through raw JSON ingress."""
from hashlib import sha256
import json
from pathlib import Path
import resource
import struct
import subprocess
import time
import traceback

import sys
sys.dont_write_bytecode = True
REFERENCE = Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/reference-0ef-r2")
sys.path.insert(0,str(REFERENCE))
from hepta.hia_edit_query import apply_edit
from hepta.hia_program_tools import bounded_json_wire

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
OUT = ROOT / 'development/snapshot-whole-boundary-r1'
OUT.mkdir(exist_ok=False)
EMPTY = OUT / 'empty'
EMPTY.mkdir()
original = BASE.parent / 'application-reference-r1/fixtures/native-edit-apply-next/development/whole-Core-boundary-r2/case-000'
original_input = (original / 'input.bin').read_bytes()
assert sha256(original_input).hexdigest() == '0c5d7909dcc12775bf9b9d3423741c0d836ab5e0d589ed8e47d94a338ed537af'
header = struct.unpack_from('<8Q', original_input)
assert header[4] == 8 << 20
program = original_input[64:64+header[4]]
query_wire = (original / 'expected-query.bin').read_bytes()
query = json.loads(query_wire)
bundle_path = ROOT / 'development/build-r2/bundle.json'
bundle_raw = bundle_path.read_bytes()
bundle = json.loads(bundle_raw)
assert bundle['status'] == 'PASS'
exe = Path(bundle['executable']['path'])
exe_raw = exe.read_bytes()
assert sha256(exe_raw).hexdigest() == bundle['executable']['sha256']
pins = {Path(__file__): Path(__file__).read_bytes(), original / 'input.bin': original_input,
        original / 'expected-query.bin': query_wire, bundle_path: bundle_raw, exe: exe_raw}
for filename in ('expected-candidate.bin','expected-receipt.bin'):
    pins[original / filename] = (original / filename).read_bytes()
for module in list(sys.modules.values()):
    filename = getattr(module,'__file__',None)
    if filename and Path(filename).is_file() and Path(filename).is_relative_to(REFERENCE):
        pins[Path(filename)] = Path(filename).read_bytes()
M = lambda raw: int.from_bytes(raw, 'little')
summary = dict(status='INCOMPLETE', scope='ACTUAL_NATIVE_RAW_JSON_FULL_PROGRAM_BOUNDARY_SNAPSHOT_AND_BYTE_LIMIT', whole_stack_closed=False)
started = time.monotonic_ns()
results = []


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


try:
    for value, label in ((2, 'exact-8MiB-base-and-candidate'), (10, 'candidate-8MiB-plus1-late-refusal')):
        case = OUT / ('case-' + str(len(results)).zfill(3))
        case.mkdir()
        response = ('{"attrs":{"value":' + str(value) + '}}').encode()
        expected, error = None, None
        oracle_start = time.monotonic_ns()
        try:
            changed, receipt = apply_edit(program, query, response)
            expected = (changed.canonical_bytes, bounded_json_wire(receipt, 8 << 20), query_wire)
        except Exception as exc:
            error = dict(type=type(exc).__name__, text=str(exc), code=getattr(exc, 'code', None))
        if value == 2:
            assert expected is not None and error is None and len(expected[0]) == 8 << 20
            assert expected == tuple((original / ('expected-' + name + '.bin')).read_bytes() for name in ('candidate', 'receipt', 'query'))
        else:
            assert expected is None and error is not None
            assert error['type'] == 'HIAProgramRejected' and error['text'] == 'E_HIA_LIMIT: program exceeds byte budget before encoding'
        oracle = dict(label=label, expected_accepted=expected is not None, error=error,
                      oracle_elapsed_ns=time.monotonic_ns()-oracle_start)
        (case / 'oracle.json').write_text(json.dumps(oracle, indent=2, sort_keys=True) + '\n')
        if expected:
            for name, raw in zip(('candidate', 'receipt', 'query'), expected):
                (case / ('expected-' + name + '.bin')).write_bytes(raw)
        else:
            (case / 'expected-error.txt').write_text(error['text'])
        payload = struct.pack('<8Q', M(b'HIAEJN01'), 111, 1, 4300, len(program), len(query_wire), len(response), 0) + program + query_wire + response
        (case / 'input.bin').write_bytes(payload)
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.monotonic_ns()
        with (case / 'stdout.bin').open('xb') as stdout, (case / 'stderr.bin').open('xb') as stderr:
            child = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, cwd=EMPTY,
                                     env={'PATH': str(EMPTY), 'HOME': str(EMPTY), 'LANG': 'C'}, preexec_fn=limits)
            try:
                child.communicate(payload, timeout=180)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(); raise
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        stdout = (case / 'stdout.bin').read_bytes()
        stderr = (case / 'stderr.bin').read_bytes()
        row = dict(label=label, exitcode=child.returncode, wall_ns=time.monotonic_ns()-start,
                   cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                   input_bytes=len(payload), input_sha256=sha256(payload).hexdigest(),
                   stdout_bytes=len(stdout), stdout_sha256=sha256(stdout).hexdigest(),
                   stderr_bytes=len(stderr), stderr_sha256=sha256(stderr).hexdigest())
        (case / 'observed-process.json').write_text(json.dumps(row, indent=2, sort_keys=True) + '\n')
        assert len(stderr) >= 128, row
        event = struct.unpack_from('<16Q', stderr)
        assert event[:3] == (M(b'HIACDE01'), 7, 111) and event[9] == 1 and not any(event[11:]), (row, event)
        if expected:
            assert child.returncode == 0 and len(stderr) == 128 and event[4:6] == (0, 0), (row, event)
            assert event[6:8] == (30, 0) and event[8] == len(stdout)
            actual_header = struct.unpack_from('<8Q', stdout)
            assert actual_header == (M(b'HIAEDR01'), 1, *map(len, expected), 0, 0, 0)
            assert stdout[64:] == b''.join(expected)
            row['outcome'] = 'COMPLETE_CANDIDATE_RECEIPT_QUERY_BYTE_EQUAL'
        else:
            domain = {'HIAEditRejected': 1, 'HIAProgramRejected': 2, 'UnicodeEncodeError': 3, 'AgentRejected': 4}[error['type']]
            assert child.returncode == 2 and not stdout and event[4] == domain, (row, event, error)
            assert event[8] == len(error['text'].encode()) and stderr[128:] == error['text'].encode(), (row, event, error)
            row.update(outcome='COMPLETE_PUBLIC_ERROR_TEXT_EQUAL_BEFORE_PUBLICATION', error=error)
        row.update(status='PASS', raw_JSON_ingress=True, empty_PATH_HOME=True, fixed_native_executor=True,
                   all_63_semantic_images_actual=True, host_runtime_semantics=False)
        (case / 'result.json').write_text(json.dumps(row, indent=2, sort_keys=True) + '\n')
        results.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)
    summary.update(status='PASS', case_count=len(results), results=results)
except BaseException as exc:
    summary.update(status='FAIL', completed_cases=results, error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    summary.update(elapsed_ns=time.monotonic_ns()-started, source_before_after_equal=all(p.read_bytes() == raw for p, raw in pins.items()),
                   cpu_limit_s=90, address_space_limit_bytes=1 << 30, per_case_wall_timeout_s=180,
                   executable_sha256=sha256(exe_raw).hexdigest())
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('results', 'completed_cases')}, sort_keys=True), flush=True)
    assert summary['source_before_after_equal']

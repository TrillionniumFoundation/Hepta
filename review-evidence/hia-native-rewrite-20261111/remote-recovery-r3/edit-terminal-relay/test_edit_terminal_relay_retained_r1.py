"""New relay protocol replay of all original 87 complete edit fixtures.

All original bytes remain pinned. An additional HIA SWITCH has one declared
sequence increment. Every other terminal byte, every business output byte and
exit code is compared exactly. The original byte-exact old-protocol test is
retained separately and is not represented as passing this new protocol.
"""
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

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
OUT = ROOT / 'development/relay-complete-replay-r1'
OUT.mkdir(exist_ok=False)
EMPTY = OUT / 'empty'
EMPTY.mkdir()
bundle_path = ROOT / 'development/build-r2/bundle.json'
bundle_raw = bundle_path.read_bytes()
bundle = json.loads(bundle_raw)
assert bundle['status'] == 'PASS'
exe = Path(bundle['executable']['path'])
exe_raw = exe.read_bytes()
assert sha256(exe_raw).hexdigest() == bundle['executable']['sha256']
FIXTURES = BASE.parent / 'application-reference-r1/fixtures/native-edit-apply-next/development'
restore_path = BASE.parent / 'application-reference-r1/restore.json'
restore_raw = restore_path.read_bytes()
assert json.loads(restore_raw)['status'] == 'PASS'
panels = [FIXTURES / 'complete-native-r1', FIXTURES / 'complete-native-panel-r2',
    BASE / 'native-edit-json-next/development/json-native-r2',
    BASE / 'native-edit-json-next/development/raw-prefix-native-r1']
pins = {Path(__file__): Path(__file__).read_bytes(), bundle_path: bundle_raw, exe: exe_raw, restore_path: restore_raw}
rows = []
started = time.monotonic_ns()
summary = dict(status='INCOMPLETE', scope='ACTUAL_NATIVE_87_EDIT_CASES_WITH_EXACT_TERMINAL_RELAY_SEQUENCE_REVISION',
               whole_stack_closed=False, cold_qualification=False, host_semantic_runtime=False)


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


REFERENCE = Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/reference-0ef-r2")
sys.path.insert(0,str(REFERENCE))
from hepta.hia_program import verify_program,HIAProgramRejected
for module in list(sys.modules.values()):
    name=getattr(module,"__file__",None)
    if name and Path(name).is_file() and Path(name).is_relative_to(REFERENCE):
        pins[Path(name)]=Path(name).read_bytes()

def expected_relay_terminal(raw,original_stderr):
    """Predict the one new SWITCH from the original owner control flow.

    Root-only errors terminate without crossing a new owner boundary.
    Query/apply outcomes cross exactly once. Core stage 8 exists in both
    initial admission and post-patch verification, so that ambiguity is
    resolved by a separate exact-reference admission of the immutable base.
    """
    assert len(raw)>=64 and len(original_stderr)>=128
    header=struct.unpack_from("<8Q",raw);event=struct.unpack_from("<16Q",original_stderr)
    assert event[0]==int.from_bytes(b"HIACDE01","little") and event[1]==7
    assert header[0] in (int.from_bytes(b"HIAEIN01","little"),int.from_bytes(b"HIAEJN01","little"))
    assert event[2]==header[1] and event[9]==header[2]
    assert len(raw)==64+sum(header[4:7]) and header[7]==0
    stage=event[10];domain=event[4];base_oracle=None
    if domain==0:
        assert event[5]==0 and stage==0
        increment=1;reason="query_or_apply_success"
    elif stage==31:
        assert domain==1 and header[0]==int.from_bytes(b"HIAEJN01","little")
        increment=0;reason="root_raw_query_decode_error"
    elif stage in (7,10):
        assert domain==2 and header[2]<5
        increment=0;reason="root_program_prefix_error"
    elif stage==0:
        increment=0;reason="root_previous_child_refusal"
    elif stage==8:
        assert domain==2 and header[2]<5 and header[4]>0
        previous_digits=sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(header[3])
            try:
                verify_program(raw[64:64+header[4]])
            except HIAProgramRejected as error:
                assert str(error).encode()==original_stderr[128:]
                increment=0;reason="root_initial_Core_admission_error"
                base_oracle=dict(accepted=False,error_class=type(error).__name__,error=str(error))
            else:
                increment=1;reason="apply_candidate_Core_verification_error"
                base_oracle=dict(accepted=True)
        finally:
            sys.set_int_max_str_digits(previous_digits)
    else:
        assert stage in (1,2,3,4,5,101,102,103,104,201,202,203,204,205,206,207),event
        increment=1;reason="query_or_apply_semantic_error"
    assert event[3] < (1<<64)-increment
    expected=bytearray(original_stderr)
    struct.pack_into("<Q",expected,24,event[3]+increment)
    return bytes(expected),dict(original_sequence=event[3],
        expected_sequence=event[3]+increment,required_switch_increment=increment,
        original_owner_class=reason,reference_base_admission=base_oracle,
        original_stderr_sha256=sha256(original_stderr).hexdigest(),
        revised_expected_stderr_sha256=sha256(expected).hexdigest())

try:
    for panel in panels:
        original_summary = (panel / 'summary.json').read_bytes()
        assert json.loads(original_summary)['status'] == 'PASS'
        pins[panel / 'summary.json'] = original_summary
        for original in sorted(panel.glob('case-*')):
            raw = (original / 'input.bin').read_bytes()
            expected_stdout = (original / 'stdout.bin').read_bytes()
            expected_stderr = (original / 'stderr.bin').read_bytes()
            original_stderr = expected_stderr
            expected_stderr, sequence_contract = expected_relay_terminal(raw, original_stderr)
            original_process = json.loads((original / 'process.json').read_text())
            expected_exit = original_process.get('returncode', original_process.get('exitcode'))
            assert expected_exit in (0, 2), (original, original_process)
            case = OUT / ('case-' + str(len(rows)).zfill(3))
            case.mkdir()
            source_pins = {p.name: dict(bytes=p.stat().st_size, sha256=sha256(p.read_bytes()).hexdigest())
                           for p in original.iterdir() if p.is_file()}
            start = time.monotonic_ns()
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            done = subprocess.run([str(exe)], input=raw, capture_output=True, cwd=EMPTY,
                                  env={'PATH': str(EMPTY), 'HOME': str(EMPTY), 'LANG': 'C'},
                                  preexec_fn=limits, timeout=180)
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            (case / 'stdout.bin').write_bytes(done.stdout)
            (case / 'stderr.bin').write_bytes(done.stderr)
            row = dict(original_case=str(original), original_files=source_pins,
                       actual_exitcode=done.returncode, expected_exitcode=expected_exit,
                       wall_ns=time.monotonic_ns()-start,
                       child_cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                       stdout_bytes=len(done.stdout), stdout_sha256=sha256(done.stdout).hexdigest(),
                       stderr_bytes=len(done.stderr), stderr_sha256=sha256(done.stderr).hexdigest(),
                       full_stdout_equal=done.stdout == expected_stdout,
                       complete_revised_stderr_equal=done.stderr == expected_stderr,
                       original_stderr_equal=done.stderr == original_stderr,
                       terminal_sequence_contract=sequence_contract,
                       source_before_after_equal=all((original / name).stat().st_size == pin['bytes'] and
                           sha256((original / name).read_bytes()).hexdigest() == pin['sha256'] for name, pin in source_pins.items()))
            (case / 'observed.json').write_text(json.dumps(row, indent=2, sort_keys=True) + '\n')
            assert row['source_before_after_equal']
            assert done.returncode == expected_exit and row['full_stdout_equal'] and row['complete_revised_stderr_equal'], row
            row['status'] = 'PASS'
            rows.append(row)
            print(json.dumps({k: v for k, v in row.items() if k != 'original_files'}, sort_keys=True), flush=True)
    assert len(rows) == 87, len(rows)
    required_switches=sum(r['terminal_sequence_contract']['required_switch_increment'] for r in rows)
    assert required_switches>0
    summary.update(status='PASS', case_count=len(rows), results=rows,
        extra_terminal_switches=required_switches,
        original_protocol_exact_stderr_test_claim=False,
        entire_stdout_error_payload_and_all_other_terminal_bytes_equal=True)
except BaseException as exc:
    summary.update(status='FAIL', completed_cases=rows, error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    summary.update(elapsed_ns=time.monotonic_ns()-started, source_before_after_equal=all(p.read_bytes() == raw for p, raw in pins.items()),
                   cpu_limit_s=90, address_space_limit_bytes=1 << 30, per_case_wall_timeout_s=180,
                   bundle_sha256=sha256(bundle_raw).hexdigest(), executable_sha256=sha256(exe_raw).hexdigest())
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('results', 'completed_cases')}, sort_keys=True), flush=True)
    assert summary['source_before_after_equal']

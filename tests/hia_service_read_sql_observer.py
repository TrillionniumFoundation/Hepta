"""The separate frozen SQL-expression originals, then fresh actual-image cases.

No expectation comes from the native port graph. Original children forbid
product/Native/VM/SQLite imports and finish both complete observations before
the first candidate child. The existing 86/6286 inventory is independent.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_service_read_sql_original_e7'
FREEZE_SHA256 = 'c0710f644d6aec7681f5d90d1b2e49949aa335e764cf1865557647cd0c6f1ba1'


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def pin(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def admit():
    raw = (ORIGINAL / 'freeze.json').read_bytes()
    if sha256(raw).hexdigest() != FREEZE_SHA256:
        raise ValueError('independent SQL expression freeze differs')
    freeze = json.loads(raw)
    before = {name: pin(ORIGINAL / name) for name in freeze['files']}
    if before != freeze['files']:
        raise ValueError('independent SQL expression source differs')
    cases = json.loads((ORIGINAL / 'inputs.json').read_bytes())['cases']
    if (len(cases) != 86 or len({case['id'] for case in cases}) != 86
            or sum(case['outer'] is True for case in cases) != 43
            or freeze['supersedes_existing_86_or_6286'] is not False):
        raise ValueError('complete separate SQL expression inventory differs')
    if ((ORIGINAL / 'freeze.json').read_bytes() != raw
            or {name: pin(ORIGINAL / name) for name in before} != before):
        raise ValueError('independent SQL inputs changed during admission')
    return cases, before


def environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def run(directory, argv):
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'command.json').write_bytes(canonical({'argv': argv, 'timeout_seconds': 15,
                                                       'new_component_child_only': True}))
    process = subprocess.Popen(argv, cwd=ROOT, env=environment(),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=15)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        (directory / 'stdout.log').write_bytes(stdout)
        (directory / 'stderr.log').write_bytes(stderr)
        (directory / 'execution.json').write_bytes(canonical({
            'returncode': process.returncode, 'leader_reaped': process.poll() is not None,
            'communicate_completed': False}))
        raise
    (directory / 'stdout.log').write_bytes(stdout)
    (directory / 'stderr.log').write_bytes(stderr)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        group_present = False
    else:
        group_present = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    record = {'returncode': process.returncode, 'leader_reaped': process.poll() is not None,
              'communicate_completed': True, 'unexpected_remaining_group': group_present}
    (directory / 'execution.json').write_bytes(canonical(record))
    if process.returncode != 0 or group_present:
        raise AssertionError(('SQL expression child failed', argv, record, stdout, stderr))


def candidate_case(args):
    cases, original_before = admit()
    case, = [case for case in cases if case['id'] == args.candidate_case]
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from hepta import hia_service_read_native as native
    from hepta import hia_agent_service as api
    from hepta.hia_native_delivery import custody_snapshot
    from tools.build_hia_service_read import INPUTS
    import gc
    image = native.installed_service_read(str(args.manifest))
    before = {name: pin(ROOT / name) for name in INPUTS}
    spec = importlib.util.spec_from_file_location('independent_read_sql_original', ORIGINAL / 'sql_original_oracle.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    actual_entry, counts = image._entry, {'entries': 0}
    def entry(*arguments):
        counts['entries'] += 1
        return actual_entry(*arguments)
    def forbidden(*arguments, **keywords):
        raise AssertionError('selected SQL read entered the retained Python body')
    def selected(namespace):
        def invoke(service, arguments):
            return native.ServiceReadFrame(image, service, arguments, namespace=namespace).finish()
        return invoke
    # Only this candidate glue substitutes the owner. The frozen observer and
    # its full original body bytes are never changed, including GC/exception
    # observations and explicit result/input/traceback consumer boundaries.
    oracle.original_function = selected
    # Capture and restore these exact three attributes without importing mock.
    # Its signature reflection creates unrelated collectable class cycles before
    # the unchanged original observer's declared GC boundary.
    previous_reference = api._SERVICE_READ_REFERENCE
    previous_method = api.HIAAgentService._hia_read_reference
    previous_entry = image._entry
    try:
        api._SERVICE_READ_REFERENCE = forbidden
        api.HIAAgentService._hia_read_reference = forbidden
        image._entry = entry
        observation, late, raw_traceback = oracle.observe(case)
    finally:
        image._entry = previous_entry
        api.HIAAgentService._hia_read_reference = previous_method
        api._SERVICE_READ_REFERENCE = previous_reference
    post_boundary_gc = gc.collect()
    assert observation['fault_count'] == (1 if case.get('fault') else 0)
    after = {name: pin(ROOT / name) for name in INPUTS}
    remaining = custody_snapshot()
    assert before == after and not remaining and counts['entries'] > 0
    assert admit()[1] == original_before
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'observation.json').write_bytes(canonical(observation))
    (args.output / 'late-events.json').write_bytes(canonical(late))
    (args.output / 'raw-traceback.json').write_bytes(canonical(raw_traceback))
    (args.output / 'identity.json').write_bytes(canonical({'runtime': sys.version,
        'executable': sys.executable, 'case_id': case['id'], 'fresh_process': True,
        'candidate_linear_code_reset_or_warmed': False, 'entries': counts['entries'],
        'image_sha256': image.image_sha256, 'source_before': before, 'source_after': after,
        'original_source_pins': original_before, 'post_boundary_gc_collected': post_boundary_gc,
        'remaining_delivery_custody': remaining, 'exception_or_GC_fields_normalized': False,
        'whole_native_stack_qualified': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--original-only', action='store_true')
    choice.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--candidate-case')
    args = parser.parse_args()
    if args.candidate_case:
        if args.manifest is None:
            raise ValueError('a candidate case requires its explicit image')
        candidate_case(args)
        return 0
    cases, before = admit()
    begin = time.monotonic()
    args.output.mkdir(parents=True, exist_ok=False)
    original_rows = []
    # Finish every same-runtime original pair before starting ANY candidate.
    for index, case in enumerate(cases):
        paths = []
        for ordinal in (1, 2):
            directory = args.output / 'originals' / ('%03d' % index) / str(ordinal)
            observation = directory / 'observation'
            run(directory, [sys.executable, '-I', '-B', '-S', str(ORIGINAL / 'sql_original_oracle.py'),
                '--case-id', case['id'], '--output', str(observation)])
            paths.append(observation)
        files = ('observation.json', 'late-events.json', 'raw-traceback.json', 'identity.json')
        for name in files:
            if (paths[0] / name).read_bytes() != (paths[1] / name).read_bytes():
                raise AssertionError(('complete original SQL observations differ', case['id'], name))
        original_rows.append({'case_id': case['id'], 'path': str(paths[0]),
                              'file_pins': {name: pin(paths[0] / name) for name in files}})
    frozen = canonical({'schema': 'hepta.hia.service-read-SQL-originals-before-candidate.v1',
        'runtime': sys.version, 'complete_inputs': 86, 'complete_original_children': 172,
        'all_pairs_equal': True, 'original_rows': original_rows, 'source_pins': before,
        'candidate_started': False})
    (args.output / 'originals-FROZEN-before-candidate.json').write_bytes(frozen)
    rows = []
    for index, (case, original) in enumerate(zip(cases, original_rows)):
        expected = Path(original['path'])
        if args.manifest is None:
            actual = args.output / 'originals' / ('%03d' % index) / '2' / 'observation'
        else:
            directory = args.output / 'candidate' / ('%03d' % index)
            actual = directory / 'observation'
            run(directory, [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                '--manifest', str(args.manifest), '--candidate-case', case['id'], '--output', str(actual)])
        equal = all((expected / name).read_bytes() == (actual / name).read_bytes()
                    for name in ('observation.json', 'late-events.json'))
        rows.append({'case_id': case['id'], 'equal_canonical_and_late_bytes': equal,
                     'original': original, 'actual_path': str(actual),
                     'actual_files': {p.name: pin(p) for p in sorted(actual.glob('*.json'))}})
    after = admit()[1]
    originals_stable = all(pin(Path(row['path']) / name) == value
        for row in original_rows for name, value in row['file_pins'].items())
    passed = before == after and originals_stable and all(row['equal_canonical_and_late_bytes'] for row in rows)
    report = {'schema': 'hepta.hia.service-read-sql-expression-observations.v1',
        'status': 'PASS' if passed else 'FAIL', 'runtime': sys.version,
        'scope': 'ORIGINAL_ONLY' if args.manifest is None else 'FINITE_ACTUAL_IMAGE_FRESH_PROCESSES',
        'case_count': len(rows), 'original_children': 172,
        'candidate_children': 0 if args.manifest is None else len(rows),
        'originals_frozen_before_candidate_sha256': sha256(frozen).hexdigest(),
        'originals_unchanged': originals_stable, 'source_before': before, 'source_after': after,
        'rows': rows, 'elapsed_seconds': time.monotonic() - begin,
        'retained_read_body_forbidden_in_each_candidate_child': args.manifest is not None,
        'old_86_base_and_6286_fault_inventory_replaced': False,
        'actual_SQL_resource_registration_or_ACK_loss_proved': False,
        'all_interpreter_history_equivalence_proved': False,
        'all_input_equivalence_proved': False, 'whole_native_stack_qualified': False}
    (args.output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({name: report[name] for name in ('status', 'scope', 'case_count', 'elapsed_seconds')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

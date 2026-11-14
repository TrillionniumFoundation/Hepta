"""One reviewed u32 entry-layout attempt. AUTHORING ONLY until authorized.

No ordinary/cold/whole promotion, image fallback or automatic product retry.
"""
from pathlib import Path
import inspect
import json
import shutil
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import entry_support as support


def result_base():
    return {'status': 'FAIL', 'encoding_profile': support.PLAN['encoding_profile'],
            'whole_stack_rewrite_complete': False, 'all_input_correctness_proved': False,
            'matching_current_new_cold': False, 'ordinary_encoding_qualification': 'NOT_RUN',
            'original_unittest_method_executed': False, 'entry_projection_calls': 0,
            'product_retries': 0, 'finalization_errors': []}


def report_admission(report, journal, bridge):
    expected = support.PLAN['expected']
    checks = report['checks']
    support.require(type(checks) is dict and list(checks) == expected['check_ids']
                    and len(checks) == 20 and all(type(value) is bool for value in checks.values()),
                    'complete original 20 checks or exact order differs')
    # Preserve every assertion in the original method on its explicit-source
    # projection. This is not execution of the original ordinary fixture.
    support.require(report['references_completed_before_native_compilation'] is True
                    and len(report['references']) == 4 and all(checks.values())
                    and report['whole_stack_rewrite_complete'] is False
                    and report['all_input_correctness_proved'] is False,
                    'an original entry-layout assertion failed')
    support.require(journal.counts == expected['call_counts']
                    and all(row['status'] == 'RETURNED' for row in journal.calls),
                    'original complete call inventory did not return')
    for kind, key in (('compile', 'compile_labels'), ('invoke', 'invoke_labels'),
                      ('tool', 'link_labels'), ('executable', 'executable_labels')):
        support.require([row['label'] for row in journal.calls if row['kind'] == kind] == expected[key],
                        'original call labels or order differ: ' + kind)
    references = [row for row in journal.calls if row['kind'] == 'reference']
    compilations = [row for row in journal.calls if row['kind'] == 'compile']
    support.require(max(row['finished_monotonic_ns'] for row in references)
                    < min(row['started_monotonic_ns'] for row in compilations),
                    'all resource references must finish before native compilation')
    support.require(bridge.count == 4 and len(bridge.records) == 4
                    and all(row['status'] == 'RETURNED' for row in bridge.records),
                    'four actual original 15-second ELF owners required')
    for row in bridge.records:
        returned = json.loads((Path(row['path']) / 'RETURNED.json').read_bytes())
        support.complete_owner(returned, 15)
        request = json.loads((Path(row['path']) / 'REQUEST.json').read_bytes())
        support.require(request['command'][4] == str(support.SOURCE / 'tools/hia_selfhost_cli_child.py'),
                        'unexpected fixed runtime bridge consumer')
    return {'checks': 20, 'passing': sum(checks.values()), 'failing_ids': [], 'ordered_check_ids': list(checks),
            'original_method_assertions_preserved': True, 'call_counts': journal.counts,
            'all_eight_references_completed_before_first_native_compile': True,
            'reference_default_max_steps': 1000000, 'original_SOURCE_rebound': False}


def child():
    started = time.monotonic_ns()
    result = result_base()
    before = initial_controls = modules = initial_functions = None
    qualifier = old_child = old_source = None
    completed_original_report = False
    try:
        before = support.source_snapshot(support.OUT / 'SOURCE-CHILD-BEFORE.json')
        initial_controls = support.controls()
        support.dump(support.OUT / 'CONTROLS-CHILD-BEFORE.json', initial_controls)
        support.dump(support.OUT / 'RUNTIME-CHILD-BEFORE.json', support.runtime())
        support.dump(support.OUT / 'TOOLS-CHILD-BEFORE.json', support.toolchain())
        support.dump(support.OUT / 'PROJECTION-CHILD-BEFORE.json', support.projection_guard())
        support.dump(support.OUT / 'INPUTS-CHILD-BEFORE.json', support.input_guard())
        sys.path.insert(0, str(support.SOURCE))
        from tools import qualify_hia_selfhost as qualifier
        from tools import hia_selfhost_names as names
        from tools import hia_selfhost_cfg_worklist as cfg
        from tools import hia_selfhost_process_owner as owner
        from tools import qualify_hia_selfhost_cli as cli
        from hepta import hia_program as program
        from hepta import hia_program_runtime as runtime
        modules = (qualifier, names, cfg, owner, cli, program, runtime)
        initial_functions = support.original_functions(modules)
        support.dump(support.OUT / 'ORIGINAL-FUNCTIONS-BEFORE.json', initial_functions)
        support.require(inspect.signature(runtime.execute_program).parameters['max_steps'].default == 1000000,
                        'original resource-reference default fuel differs')
        old_child, old_source = qualifier.CHILD, qualifier.SOURCE
        support.require(qualifier.NATIVE_OBSERVER is None and qualifier.NATIVE_LINKED_OBSERVER is None
                        and str(old_child) == support.PLAN['loader_projection']['original']['path']
                        and str(old_source) == support.PLAN['ordinary_SOURCE_path'],
                        'unselected original loader or SOURCE binding differs')
        qualifier.CHILD = Path(support.PLAN['loader_projection']['projected']['path'])
        namespace = dict(vars(names))
        projection = support.ROOT / 'entry_projection.py'
        exec(compile(projection.read_bytes(), str(projection), 'exec'), namespace)
        import entry_transport
        compilers = [('original', support.ROOT / 'actual-inputs/B3.image.bin'),
                     ('modified', support.ROOT / 'actual-inputs/M3.image.bin')]
        with entry_transport.RuntimeBridge(owner, support.OUT / 'runtime-bridges') as bridge, \
                support.GateJournal(qualifier, cli, program) as journal:
            result['entry_projection_calls'] = 1
            report = namespace['qualify_entry_layout_explicit'](
                support.DATA, compilers, source_path=support.SOURCE / support.PLAN['new_source_relative'])
        completed_original_report = True
        support.write(support.OUT / 'ENTRY-REPORT.json',
                      (json.dumps(report, indent=2, allow_nan=False) + '\n').encode())
        support.require(qualifier.SOURCE is old_source, 'ordinary SOURCE was rebound')
        result['entry'] = report_admission(report, journal, bridge)
        result['status'] = 'PASS_FINITE_U32_ENTRY_LAYOUT_20_ONLY'
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if qualifier is not None and old_child is not None:
            qualifier.CHILD = old_child
        for name, operation in (
                ('SOURCE', lambda: support.same_source(before, support.OUT / 'SOURCE-CHILD-AFTER.json')),
                ('CONTROLS', support.controls), ('RUNTIME', support.runtime), ('TOOLS', support.toolchain),
                ('INPUTS', support.input_guard), ('PROJECTION', support.projection_guard),
                ('FUNCTIONS', lambda: support.original_functions(modules)),
                ('ACTUAL-FRAMES', lambda: support.frame_inventory(completed_original_report))):
            try:
                value = operation()
                if name not in ('SOURCE', 'ACTUAL-FRAMES'):
                    support.dump(support.OUT / (name + '-CHILD-AFTER.json'), value)
                if name == 'CONTROLS':
                    support.require(value == initial_controls, 'fixed control bytes changed')
                if name == 'FUNCTIONS':
                    support.require(value == initial_functions, 'original callable bodies changed')
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': name, 'type': type(error).__name__,
                    'error': str(error), 'traceback': traceback.format_exc()})
        if qualifier is not None and old_source is not None and qualifier.SOURCE is not old_source:
            result['status'] = 'FAIL'
            result['finalization_errors'].append({'name': 'SOURCE-BINDING', 'error': 'binding changed'})
        result['elapsed_ns'] = time.monotonic_ns() - started
        support.dump(support.OUT / 'RESULT.json', result)
        print(json.dumps({key: result.get(key) for key in ('status', 'entry', 'elapsed_ns',
              'matching_current_new_cold', 'whole_stack_rewrite_complete')}, sort_keys=True), flush=True)
    return 0 if result['status'] == 'PASS_FINITE_U32_ENTRY_LAYOUT_20_ONLY' else 1


def driver():
    support.require(not support.OUT.exists() and not support.OUT.is_symlink(),
                    'one unique attempt; old failure or output must never be overwritten')
    support.OUT.mkdir(parents=True, mode=0o700)
    support.DATA.mkdir(mode=0o700)
    support.write(support.OUT / 'PLAN.json', support.PLAN_RAW)
    support.write(support.OUT / 'RUNNER.py', Path(__file__).read_bytes())
    result = result_base()
    result['owner_launch_intents'] = 0
    started = time.monotonic_ns()
    before = None
    try:
        support.dump(support.OUT / 'RUNTIME-PREFLIGHT.json', support.runtime())
        support.dump(support.OUT / 'TOOLS-PREFLIGHT.json', support.toolchain())
        support.dump(support.OUT / 'CONTROLS-PREFLIGHT.json', support.controls())
        support.dump(support.OUT / 'PROJECTION-PREFLIGHT.json', support.projection_guard())
        support.dump(support.OUT / 'INPUTS-PREFLIGHT.json', support.input_guard())
        free = shutil.disk_usage(support.OUT).free
        support.dump(support.OUT / 'STORAGE-PREFLIGHT.json', {'actual_free_bytes': free,
            'required_free_bytes': support.PLAN['storage']['required_free_bytes'],
            'no_second_source_tree_or_original_ZIP': True})
        support.require(free >= support.PLAN['storage']['required_free_bytes'], 'raw evidence reserve unavailable')
        before = support.source_snapshot(support.OUT / 'SOURCE-OUTER-BEFORE.json')
        sys.path.insert(0, str(support.SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
                   '--plan-sha256', support.pin(support.PLAN_RAW)['sha256'], '--child']
        environment = support.PLAN['environment']
        support.dump(support.OUT / 'LAUNCH-INTENT.json', {'command': command, 'cwd': str(support.SOURCE),
            'env': environment, 'supervisor_env': environment, 'qualification_seconds': 180,
            'cleanup_seconds': 3, 'all_eight_references_and_twenty_checks_share_this_budget': True,
            'intent_is_not_execution_proof': True, 'product_retries': 0})
        result['owner_launch_intents'] = 1
        returned = run_owned(command, cwd=support.SOURCE, env=environment, supervisor_env=environment,
            stdout_path=support.OUT / 'child.stdout.bin', stderr_path=support.OUT / 'child.stderr.bin',
            receipt_path=support.OUT / 'OWNER.json', qualification_seconds=180, cleanup_seconds=3)
        support.dump(support.OUT / 'OWNER-RETURNED.json', returned)
        result['owner'] = returned
        support.owner_return(support.OUT / 'OWNER.json', returned)
        support.complete_owner(returned, 180)
        child_result = json.loads((support.OUT / 'RESULT.json').read_bytes())
        result['child'] = child_result
        support.require(child_result['status'] == 'PASS_FINITE_U32_ENTRY_LAYOUT_20_ONLY'
                        and child_result['entry_projection_calls'] == 1,
                        'finite original entry-layout gate did not pass')
        result['status'] = 'PASS_FINITE_U32_ENTRY_LAYOUT_20_ONLY'
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        for name, operation in (
                ('SOURCE', lambda: support.same_source(before, support.OUT / 'SOURCE-OUTER-AFTER.json')),
                ('CONTROLS', support.controls), ('RUNTIME', support.runtime), ('TOOLS', support.toolchain),
                ('INPUTS', support.input_guard)):
            try:
                value = operation()
                if name != 'SOURCE':
                    support.dump(support.OUT / (name + '-OUTER-AFTER.json'), value)
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': name, 'type': type(error).__name__,
                    'error': str(error), 'traceback': traceback.format_exc()})
        if not (support.OUT / 'ACTUAL-FRAMES.json').exists():
            try:
                support.frame_inventory(False)
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': 'PARTIAL-FRAME-READBACK',
                    'type': type(error).__name__, 'error': str(error), 'traceback': traceback.format_exc()})
        result.update(elapsed_ns=time.monotonic_ns() - started,
                      free_bytes=shutil.disk_usage(support.OUT).free)
        support.dump(support.OUT / 'OUTER.json', result)
        try:
            raw = support.raw_inventory()
        except BaseException as error:
            support.dump(support.OUT / 'RAW-INVENTORY-ERROR.json', {'type': type(error).__name__,
                'error': str(error), 'traceback': traceback.format_exc()})
            # Preserve the actual OUTER gate result. A separate custody failure
            # prevents a successful launcher exit without rewriting that result.
            return 1
        print(json.dumps({'status': result['status'], 'elapsed_ns': result['elapsed_ns'],
            'raw': raw, 'matching_current_new_cold': False, 'whole_stack_rewrite_complete': False},
            sort_keys=True), flush=True)
    return 0 if result['status'] == 'PASS_FINITE_U32_ENTRY_LAYOUT_20_ONLY' else 1


if __name__ == '__main__':
    arguments = sys.argv[1:]
    support.require(len(arguments) in (2, 3) and arguments[0] == '--plan-sha256'
                    and arguments[1] == support.pin(support.PLAN_RAW)['sha256']
                    and (len(arguments) == 2 or arguments[2] == '--child'),
                    'exact reviewed plan SHA and fixed argument shape required')
    raise SystemExit(child() if len(arguments) == 3 else driver())

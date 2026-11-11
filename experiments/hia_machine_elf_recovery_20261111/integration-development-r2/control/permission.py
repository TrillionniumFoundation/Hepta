"""Actual old/new private permission comparison on the real issued ELF lookup."""
from pathlib import Path
import argparse
from hashlib import sha256
import json
import sys
import traceback
import types
from common import (ROOT, SOURCE, IMAGE_SHA, HIA_SHA, checked_config, create,
                    read_json, require, stable_file, wire)
config = checked_config(ROOT / 'control/config.json')
sys.path.insert(0, str(SOURCE))
from hepta.hia_machine_elf_native import installed_machine_elf, ElfSession
from tests.test_hia_machine_elf_native import pending_lookup

def exception_state(exc):
    return {'type': type(exc).__name__, 'args': repr(exc.args),
        'traceback': [(x.name, x.filename, x.lineno) for x in traceback.extract_tb(exc.__traceback__)],
        'context_type': None if exc.__context__ is None else type(exc.__context__).__name__}

def one(image, session_type):
    actual = image._entry
    native_returns = []
    def observing_entry(*args):
        result = actual(*args)
        native_returns.append(result)
        return result
    image._entry = observing_entry
    session = None
    try:
        session, ledger, _ = pending_lookup(image, session_type)
        require(session.pending and not session.finished and native_returns,
                'real image did not issue an observable foreign lookup')
        before = list(ledger)
        error = None
        try:
            session.step()
        except RuntimeError as exc:
            error = exc
        require(error is not None, 'pending step did not refuse')
        error_before = exception_state(error)
        after_refusal = {'finished': session.finished, 'pending': session.pending}
        effect_error = None
        try:
            session.observe()
        except BaseException as exc:
            effect_error = exception_state(exc)
        effect_delta = ledger[len(before):]
        require(exception_state(error) == error_before,
                'later observation changed the original refusal traceback or context')
        return {'native_statuses': native_returns, 'initial_ledger': before,
            'step_exception': error_before, 'after_refusal': after_refusal,
            'effect_exception': effect_error, 'effect_ledger_delta': effect_delta,
            'final_ledger': list(ledger), 'native_call_count': len(native_returns),
            'finished_after': session.finished, 'pending_after': session.pending}
    finally:
        image._entry = actual
        if session is not None:
            session.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'schema': 'hepta.hia.machine-elf.private-permission-comparison.v1',
        'status': 'HOLD', 'scope': 'PRIVATE_STEP_OBSERVE_ONLY_PUBLIC_RUN_ALREADY_FINALIZES',
        'loaded': 1, 'executed': 0, 'loaded_case_ids': ['pending-step-real-issued-lookup'],
        'executed_case_ids': []}
    try:
        old = config['baseline_guard']
        old_source_pin, old_source = stable_file(ROOT / 'control/session-before.py.txt',
                                                 old['source_sha256'], collect=True)
        image_pin, image_bytes = stable_file(old['image_path'], IMAGE_SHA, collect=True)
        require(image_pin['bytes'] == 269358, 'old actual image length differs')
        source_pin, _ = stable_file(old['hia_source_path'], HIA_SHA)
        manifest, manifest_pin = read_json(old['manifest_path'], old['manifest_sha256'])
        build, build_pin = read_json(old['build_path'], old['build_sha256'])
        require(manifest['source_sha256'] == HIA_SHA and manifest['image_sha256'] == IMAGE_SHA
            and build['manifest'] == manifest
            and build['native_compile_receipt']['produced_sha256'] == IMAGE_SHA
            and build['native_compile_receipt']['input_sha256'] == HIA_SHA,
            'old actual source/image/manifest/receipt binding differs')
        report['baseline_binding'] = {'source': old_source_pin, 'hia_source': source_pin,
            'image': image_pin, 'manifest': manifest_pin, 'build': build_pin}
        module = types.ModuleType('hepta._elf_guard_baseline')
        module.__package__ = 'hepta'
        module.__file__ = str(ROOT / 'control/session-before.py.txt')
        exec(compile(old_source, module.__file__, 'exec'), module.__dict__)
        baseline = module.NativeMachineElf(image_bytes, IMAGE_SHA)
        fixed = installed_machine_elf(str(args.manifest))
        require(fixed.image_sha256 == IMAGE_SHA and fixed.admitted_source_sha256 == HIA_SHA,
                'fixed actual selected image/source binding differs')
        previous = one(baseline, module.ElfSession)
        current = one(fixed, ElfSession)
        report.update(baseline=previous, candidate=current, executed=1,
                      executed_case_ids=['pending-step-real-issued-lookup'])
        require(previous['step_exception']['type'] == current['step_exception']['type']
            and previous['step_exception']['args'] == current['step_exception']['args'],
            'pending refusal API changed')
        require(previous['after_refusal'] == {'finished': False, 'pending': True}
            and previous['effect_exception'] is None and previous['effect_ledger_delta'],
            'real historical private replay counterexample not observed')
        require(current['after_refusal'] == {'finished': True, 'pending': False}
            and current['effect_exception']['type'] == 'RuntimeError'
            and current['effect_ledger_delta'] == [],
            'candidate did not permanently revoke the issued foreign effect')
        require(previous['native_statuses'] == current['native_statuses'],
                'comparison did not reach the same actual native permission')
        report['status'] = 'PASS'
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'text': str(exc),
                             'traceback': traceback.format_exc()}
    finally:
        create(args.output, wire(report))
        print(json.dumps({'stage': 'private-permission', 'status': report['status']}), flush=True)
    return 0 if report['status'] == 'PASS' else 1
if __name__ == '__main__':
    raise SystemExit(main())

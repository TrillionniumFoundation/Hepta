"""Qualify all retained ELF callers with the explicit native object owner.

This is one component gate. It does not certify arbitrary foreign comparison
schedules, installed execution, or the complete native project.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_machine_elf import build, current_sources, OWNED_SOURCE_FILES

MODULES = (
    'tests.test_hia_machine_x64', 'tests.test_hia_machine_plan',
    'tests.test_hia_program_native', 'tests.test_hia_safe_core_artifact',
)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def _bytes_pin(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _development_sources():
    # Development scope is explicit; this map is not a cold source closure.
    from tools.hia_selfhost_contract import SOURCE_FILES
    return {name: _bytes_pin(ROOT / name)
            for name in sorted(set(SOURCE_FILES) | set(OWNED_SOURCE_FILES))}


def qualify(output, *, cold_report=None, development_manifest=None):
    output = Path(output)
    if (cold_report is None) == (development_manifest is None):
        raise ValueError('choose exactly one current cold report or development manifest')
    output.mkdir(mode=0o700)
    report = {
        'schema': 'hepta.hia.machine-elf-callers.v1', 'status': 'HOLD',
        'scope': ('MATCHING_SOURCE_COLD_BUILD' if cold_report is not None
                  else 'EXPLICIT_DEVELOPMENT_ONLY_NOT_COLD'),
        'modules': list(MODULES),
        'whole_writer_qualified': False, 'whole_native_delivery_qualified': False,
        'foreign_timsort_schedule_closed': False,
        'retained_writer_calls': [],
    }
    failure = None
    started = time.monotonic()
    sources = None
    before = None
    try:
        if cold_report is not None:
            cold_report = Path(cold_report)
            cold_raw = cold_report.read_bytes()
            cold = json.loads(cold_raw)
            nested = json.loads(Path(cold['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            manifest = build(output / 'qualified', compiler, cold_report)
            report['cold_report_sha256'] = sha256(cold_raw).hexdigest()
            sources = current_sources
        else:
            manifest = Path(development_manifest).resolve(strict=True)
            sources = _development_sources
        before = sources()
        report['source_before'] = before
        manifest_raw = manifest.read_bytes()
        from hepta import hia_machine_elf as public
        from hepta.hia_machine_elf_native import installed_machine_elf
        native = installed_machine_elf(str(manifest))
        calls_before = native.calls.copy()

        def forbidden(*unused, **ignored):
            report['retained_writer_calls'].append('write_elf_object')
            raise AssertionError('retained ELF writer entered the selected caller gate')

        suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
        loaded = [test.id() for test in flatten(suite)]
        report['loaded_test_ids'] = loaded
        report['tests_loaded'] = len(loaded)
        if not loaded or len(set(loaded)) != len(loaded) or unittest.defaultTestLoader.errors:
            raise ValueError('complete distinct retained caller test discovery required')
        with patch.dict(os.environ, {'HEPTA_HIA_MACHINE_ELF_MANIFEST': str(manifest)}), \
                patch.object(public, '_reference_write_elf_object', forbidden):
            result = unittest.TextTestRunner(verbosity=2, resultclass=ObservedResult).run(suite)
        counts = {
            'errors': len(result.errors), 'failures': len(result.failures),
            'skips': len(result.skipped), 'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses),
        }
        native_delta = dict(native.calls - calls_before)
        report.update(
            tests_run=result.testsRun, executed_test_ids=result.executed,
            anomaly_counts=counts, native_operation_counts=native_delta,
            failures=[(test.id(), trace) for test, trace in result.failures],
            errors=[(test.id(), trace) for test, trace in result.errors],
            manifest_sha256=sha256(manifest_raw).hexdigest(),
            image_sha256=native.image_sha256,
        )
        if (result.testsRun != len(loaded) or result.executed != loaded
                or any(counts.values()) or report['retained_writer_calls']
                or not native_delta or manifest.read_bytes() != manifest_raw):
            raise ValueError('complete retained ELF caller conjunction failed')
        if cold_report is not None and cold_report.read_bytes() != cold_raw:
            raise ValueError('cold input changed during caller qualification')
        report['status'] = 'SELECTED_NATIVE_ELF_CALLERS_PASS'
    except BaseException as exc:
        failure = exc
        report['failure'] = {
            'type': type(exc).__name__, 'text': str(exc), 'traceback': traceback.format_exc(),
        }
    finally:
        try:
            if before is not None:
                report['source_after'] = sources()
                if report['source_after'] != before:
                    raise ValueError('retained caller source changed')
                report['source_stable'] = True
        except BaseException as exc:
            report['status'] = 'HOLD'
            report['source_failure'] = {
                'type': type(exc).__name__, 'text': str(exc), 'traceback': traceback.format_exc(),
            }
            if failure is None:
                failure = exc
        report['seconds'] = time.monotonic() - started
        if failure is not None:
            report['status'] = 'HOLD'
        with (output / 'report.json').open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
    if failure is not None:
        raise failure
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    args = parser.parse_args()
    value = qualify(args.output, cold_report=args.cold_report,
                    development_manifest=args.development_manifest)
    print(json.dumps({'status': value['status'], 'tests_run': value['tests_run']}))


if __name__ == '__main__':
    main()

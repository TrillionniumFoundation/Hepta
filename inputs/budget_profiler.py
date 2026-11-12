"""Explicit timing observer for exact R6 originals; never a qualification gate.

Every public operation, fresh source read, original deadline and full original
Evaluation ABI observer is retained. Timers add Python frames and CPU work.
Inclusive costs must not be summed; the report also records child subtraction.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch


def dump(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)


class CostProbe:
    def __init__(self, args):
        self.args = args
        self.source = args.source.resolve(strict=True)
        self.output = args.output.resolve()
        sys.path.insert(0, str(self.source))
        self.rows, self.stack, self.public, self.contexts = [], [], [], []
        self.totals = defaultdict(Counter)
        self.entry_totals = defaultdict(Counter)
        self.active = 'before-test'
        self.controls = ExitStack()
        self.source_metadata = json.loads((self.output.parent / 'GENERATED-SOURCE.json').read_bytes())
        self.start = time.monotonic_ns()
        self.wall_start = time.time_ns()
        self.input_hash = sha256(Path(__file__).read_bytes()).hexdigest()

    def timed(self, owner, name, label, *, describe=None, observe=None):
        original = getattr(owner, name)
        def wrapped(*arguments, **keywords):
            detail = describe(arguments, keywords) if describe is not None else {}
            row = {'index': len(self.rows), 'label': label, 'test': self.active,
                   'parent': self.stack[-1] if self.stack else None, 'detail': detail,
                   'start_ns': time.monotonic_ns() - self.start}
            self.rows.append(row)
            self.stack.append(row['index'])
            cpu = time.process_time_ns()
            value = None
            ok = False
            try:
                value = original(*arguments, **keywords)
                ok = True
                return value
            except BaseException as error:
                row['exception_type'] = type(error).__name__
                raise
            finally:
                row['elapsed_ns'] = time.monotonic_ns() - self.start - row['start_ns']
                row['cpu_ns'] = time.process_time_ns() - cpu
                row['returned'] = ok
                if self.stack.pop() != row['index']:
                    raise AssertionError('diagnostic timing stack changed')
                if observe is not None and ok:
                    observe(value, row)
                value = None
        self.controls.enter_context(patch.object(owner, name, wrapped))

    def aggregate(self, owner, name, label, *, mode=None):
        original = getattr(owner, name)
        def wrapped(*arguments, **keywords):
            key = (self.active, label, str(mode(arguments) if mode is not None else 'all'))
            begin, cpu = time.monotonic_ns(), time.process_time_ns()
            try:
                return original(*arguments, **keywords)
            finally:
                elapsed, used = time.monotonic_ns() - begin, time.process_time_ns() - cpu
                row = self.entry_totals[key]
                row['calls'] += 1
                row['elapsed_ns'] += elapsed
                row['cpu_ns'] += used
        self.controls.enter_context(patch.object(owner, name, wrapped))

    def bench(self, contract):
        # Direct full-map diagnostics only. These are not qualification results.
        # Disabling only the optional fast protocol invokes the unchanged
        # original read_bytes expression; no byte/digest is cached between calls.
        observations = []
        for fast in (False, True, True, False):
            with ExitStack() as scope:
                if not fast:
                    scope.enter_context(patch.object(contract, '_SOURCE_PATH_PROTOCOL', None))
                cpu, start = time.process_time_ns(), time.monotonic_ns()
                values = contract.file_digests(self.source)
                elapsed, used = time.monotonic_ns() - start, time.process_time_ns() - cpu
                expected = {name: self.source_metadata[name]['sha256'] for name in values}
                if values != expected:
                    raise AssertionError('full fresh source map differs from frozen R6')
                observations.append({'optional_fast_enabled': fast, 'elapsed_ns': elapsed, 'cpu_ns': used,
                                     'files': len(values), 'bytes': sum(self.source_metadata[n]['bytes'] for n in values),
                                     'ordered_map_sha256': sha256(json.dumps(list(values.items()), separators=(',', ':')).encode()).hexdigest(),
                                     'all_digest_values_match_frozen_source': True})
        self.benchmark = observations

    def __enter__(self):
        from hepta import hia_agent_service as service
        from hepta import hia_agent_store as store
        from hepta import hia_agent_contract as contract
        from hepta import hia_agent_runner as runners
        from hepta import hia_program_native as backend
        from hepta import hia_checker_identity as checker
        from hepta import artifact_publication_native as publisher
        from hepta import hia_service_evaluation_native as evaluation
        from hepta.hia_machine_plan_control_native import PlanFrame
        from tools import hia_selfhost_contract as source_contract
        from tools import build_hia_json_preflight as source_admission
        from tools import build_hia_artifact_publication as publisher_builder
        from tests import test_hia_agent_native_tools as original_tests

        self.bench(source_contract)
        self.fast_admitted = source_contract._source_protocol_current(self.source)
        self.buffering = None if source_contract._SOURCE_PATH_PROTOCOL is None else source_contract._SOURCE_PATH_PROTOCOL[4]
        self.start = time.monotonic_ns()
        self.wall_start = time.time_ns()

        original_start, original_stop = unittest.TestResult.startTest, unittest.TestResult.stopTest
        def begin(result, test):
            self.active = test.id()
            return original_start(result, test)
        def end(result, test):
            try:
                return original_stop(result, test)
            finally:
                self.active = 'outside-test'
        self.controls.enter_context(patch.object(unittest.TestResult, 'startTest', begin))
        self.controls.enter_context(patch.object(unittest.TestResult, 'stopTest', end))

        def public_result(value, row):
            record = {'index': row['index'], 'test': row['test'], 'tool': row['detail']['tool'],
                      'status': value.get('status'), 'start_ns': row['start_ns'], 'elapsed_ns': row['elapsed_ns']}
            if 'error' in value:
                record['error'] = value['error']
            if row['detail']['tool'] == 'hia_context':
                record['context_response'] = value.get('result')
            self.public.append(record)

        def fresh_map(value, row):
            row['source_count'] = len(value)
            row['source_bytes'] = sum(self.source_metadata[name]['bytes'] for name in value)
            row['all_digests_equal_frozen_R6'] = all(self.source_metadata[name]['sha256'] == digest
                                                    for name, digest in value.items())
            if not row['all_digests_equal_frozen_R6']:
                raise AssertionError('a fresh production source admission changed')

        original_teardown = original_tests.AgentToolCase.tearDown
        def teardown(case):
            try:
                self.contexts.extend(dict(row) for row in case.service.store.db.execute('SELECT id,created_ns FROM contexts'))
                dump(self.output / 'EXISTING-CLIENT-RECORDS.json', case.client.records)
            finally:
                original_teardown(case)
        self.controls.enter_context(patch.object(original_tests.AgentToolCase, 'tearDown', teardown))

        original_init = evaluation.NativeEvaluationImage.__init__
        def image_init(image, raw, expected, namespace=None):
            original_init(image, raw, expected, namespace)
            native = image._entry
            def native_only(*args):
                before, cpu = time.monotonic_ns(), time.process_time_ns()
                try:
                    return native(*args)
                finally:
                    elapsed, used = time.monotonic_ns() - before, time.process_time_ns() - cpu
                    row = self.entry_totals[(self.active, 'evaluation.C-entry-only', 'all')]
                    row['calls'] += 1; row['elapsed_ns'] += elapsed; row['cpu_ns'] += used
            image._entry = native_only
        self.controls.enter_context(patch.object(evaluation.NativeEvaluationImage, '__init__', image_init))
        # The child wraps this C-only observer with its exact retained full ABI
        # observer. _invoke therefore includes that original validation work.
        self.aggregate(evaluation.EvaluationFrame, '_invoke', 'evaluation.invoke-with-original-ABI-observer',
                       mode=lambda a: a[0].mode)
        self.aggregate(evaluation.EvaluationFrame, '_effect', 'evaluation.fixed-foreign-effect',
                       mode=lambda a: a[0].mode)
        self.aggregate(evaluation.NativeEvaluationService, 'finish', 'evaluation.complete-mode',
                       mode=lambda a: a[1].mode)

        self.timed(service.HIAAgentService, 'call', 'service.call',
                   describe=lambda a, k: {'tool': a[1]}, observe=public_result)
        for name in ('_hia_emit_reference', '_hia_verify_reference', '_compile_reference',
                     '_remaining_ms_reference', '_budget_reference', '_context_reference', '_required_claims'):
            self.timed(service.HIAAgentService, name, 'service.' + name)
        for name in ('put', 'json', 'get', 'get_json', 'profile', 'check_profile'):
            self.timed(store.AgentStore, name, 'store.' + name)
        for owner, name, label in (
            (source_contract, 'file_digests', 'source.file_digests'),
            (source_contract, 'support_contract', 'source.support_contract'),
            (source_contract, 'validate_contract', 'source.validate_contract'),
            (source_admission, 'current_sources', 'source.current_sources'),
            (publisher_builder, 'current_sources', 'publication.current_sources'),
            (publisher, '_admitted_code', 'publication.admit_code'),
            (publisher, '_execute_native', 'publication.execute'),
            (contract, 'installation_manifest', 'installation.manifest'),
            (service, 'installation_manifest', 'service.installation_manifest'),
            (backend, '_implementation_hash', 'backend.implementation_hash'),
            (checker, 'checker_digest', 'checker.digest'),
            (checker, 'checker_source_identity', 'checker.source_identity'),
            (runners, 'run_reference_batch', 'runner.reference_batch'),
            (runners, 'run_native_batch', 'runner.native_batch'),
        ):
            self.timed(owner, name, label, observe=fresh_map if label == 'source.file_digests' else None)
        self.timed(publisher.subprocess, 'run', 'subprocess.run',
                   describe=lambda a, k: {'operation': str(a[0][1]) if len(a[0]) > 1 else ''})
        return self

    def __exit__(self, kind, value, tb):
        self.controls.close()
        for row in self.rows:
            row['exclusive_elapsed_ns'], row['exclusive_cpu_ns'] = row['elapsed_ns'], row['cpu_ns']
        for row in self.rows:
            if row['parent'] is not None:
                parent = self.rows[row['parent']]
                parent['exclusive_elapsed_ns'] -= row['elapsed_ns']
                parent['exclusive_cpu_ns'] -= row['cpu_ns']
        totals = defaultdict(Counter)
        per_test = defaultdict(lambda: defaultdict(Counter))
        for row in self.rows:
            for target in (totals[row['label']], per_test[row['test']][row['label']]):
                target['calls'] += 1
                for key in ('elapsed_ns', 'cpu_ns', 'exclusive_elapsed_ns', 'exclusive_cpu_ns'):
                    target[key] += row[key]
                target['fresh_source_files'] += row.get('source_count', 0)
                target['fresh_source_bytes'] += row.get('source_bytes', 0)
        source_rows = [row for row in self.rows if row['label'] == 'source.file_digests']
        attribution = []
        for row in source_rows:
            parents = []
            current = row['parent']
            while current is not None:
                parent = self.rows[current]
                parents.append({'index': parent['index'], 'label': parent['label'], 'detail': parent['detail']})
                current = parent['parent']
            attribution.append({'source_index': row['index'], 'parents_inner_to_outer': parents,
                                'start_ns': row['start_ns'], 'elapsed_ns': row['elapsed_ns'],
                                'cpu_ns': row['cpu_ns'], 'test': row['test']})
        report = {'schema': 'hia.evaluation.original-budget-phase-cost.v1',
                  'scope': 'INSTRUMENTED_DIAGNOSTIC_NOT_QUALIFICATION', 'python': sys.version,
                  'actual_frozen_source_tree': '76f273c30134b34157b12113e4f0449498b08fe0',
                  'method': self.args.method, 'group': self.args.group,
                  'original_methods_and_deadlines_changed': False, 'full_original_ABI_observer_retained': True,
                  'fresh_admission_count_or_domain_reduced': False, 'cross_call_digest_cache': False,
                  'observer_adds_python_frames_and_CPU_cost': True,
                  'monotonic_origin_ns': self.start, 'realtime_origin_ns': self.wall_start,
                  'protocol_admitted': self.fast_admitted, 'actual_read_buffering': self.buffering,
                  'full_map_ABBA': self.benchmark, 'totals': dict(totals), 'per_test': dict(per_test),
                  'entry_totals': [{'test': key[0], 'label': key[1], 'mode': key[2], **row}
                                   for key, row in sorted(self.entry_totals.items())],
                  'public_calls': self.public, 'contexts': self.contexts,
                  'fresh_scan_ancestry': attribution,
                  'all_completed_source_digests_equal_frozen_source': all(row.get('all_digests_equal_frozen_R6', False)
                                                                         for row in source_rows),
                  'input_script_unchanged': sha256(Path(__file__).read_bytes()).hexdigest() == self.input_hash,
                  'observer_exit_error': None if kind is None else ''.join(traceback.format_exception(kind, value, tb)),
                  'old_results_reclassified': False, 'whole_native': False, 'current_cold': False}
        if self.output.is_dir():
            dump(self.output / 'COST-TIMINGS.json', self.rows)
            dump(self.output / 'COST-REPORT.json', report)
        return False

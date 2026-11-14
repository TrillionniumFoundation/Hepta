"""One original fresh-admission observation; no replacement product providers."""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback
import types
import _hashlib
import _io
from diagnose_source_scan import identity, snapshot, write_json

TOOL_ID = 5
TOOL_NAME = 'hia-one-original-fresh-scan'
EXPECTED_FUNCTIONS = ('validate_contract', 'support_contract', 'file_digests',
                      '_source_protocol_current', '_source_relative_name', '_source_lexical_read')

def binding_snapshot(module):
    namespace = vars(module)
    assert all(type(key) is str for key in namespace)
    return tuple(sorted((name, id(value)) for name, value in namespace.items()))

def function_snapshot(function):
    assert type(function) is types.FunctionType
    kw = function.__kwdefaults__
    assert kw is None or (type(kw) is dict and all(type(k) is str for k in kw))
    return (id(function), id(function.__code__), id(function.__globals__),
            id(function.__builtins__), id(function.__defaults__), id(kw),
            None if kw is None else tuple((k, id(v)) for k, v in kw.items()))

def inventory_lines(raw):
    module = ast.parse(raw)
    function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'file_digests')
    assignments = [n for n in function.body if isinstance(n, ast.Assign)
                   and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                   and n.targets[0].id == 'paths']
    assert len(assignments) == 1
    assignment = assignments[0]
    assert isinstance(function.body[-1], ast.Return)
    assert assignment.end_lineno < function.body[-1].lineno
    assert isinstance(assignment.value, ast.Call) and isinstance(assignment.value.func, ast.Name)
    assert assignment.value.func.id == 'sorted'
    return assignment.lineno, function.body[-1].lineno

class Observer:
    def __init__(self, functions, open_provider, sha_provider, markers):
        self.names = {f.__code__: name for name, f in functions.items()}
        assert len(self.names) == len(functions)
        self.digest_code = functions['file_digests'].__code__
        self.open_provider, self.sha_provider = open_provider, sha_provider
        self.markers = markers
        self.events, self.intervals, self.lines, self.errors = [], [], [], []
        self.stack = []
        self.active = False
        self.fresh = False
        self.ordinal = 0
        self.last_completed = 0
        self.inventory = None
        self.inventory_complete = False

    def phase(self):
        if not self.fresh:
            return 'outside_fresh'
        return 'inventory' if self.inventory is not None and not self.inventory_complete else 'fresh_files'

    def begin(self, kind, name, frame_id):
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        record = {'sequence': len(self.intervals), 'kind': kind, 'name': name,
                  'frame_id': frame_id, 'parent': self.stack[-1]['sequence'] if self.stack else None,
                  'wall_start_ns': wall, 'cpu_start_ns': cpu, 'fresh': self.fresh,
                  'phase': self.phase(), 'ordinal': self.ordinal if self.fresh else 0}
        self.intervals.append(record)
        self.stack.append(record)
        self.events.append([len(self.events), 'begin', record['sequence'], wall, cpu])

    def end(self, kind, name, frame_id, event, result=None):
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        if not self.stack or (self.stack[-1]['kind'], self.stack[-1]['name'], self.stack[-1]['frame_id']) != (kind, name, frame_id):
            self.errors.append(['unpaired_end', kind, name, frame_id, event])
            return
        record = self.stack.pop()
        record.update(wall_end_ns=wall, cpu_end_ns=cpu, exit_event=event)
        if kind == 'python':
            if type(result) in (bytes, str, dict):
                record['return_type'] = type(result).__name__
                record['return_length'] = len(result)
            else:
                record['return_type'] = type(result).__name__
            if name == '_source_protocol_current':
                record['guard_true'] = result is True
        self.events.append([len(self.events), 'end', record['sequence'], wall, cpu])

    def c_name(self, value):
        if value is self.open_provider:
            return 'open'
        if value is self.sha_provider:
            return 'sha256'
        # CPython 3.14 FileIO.read emits a builtin_method subtype event.
        # Keep its admitted C-function family; the exact FileIO owner is checked below.
        if not isinstance(value, types.BuiltinFunctionType):
            return None
        owner = value.__self__
        if type(owner) is _io.FileIO:
            name = value.__name__
            if name in ('read', '__exit__', 'close'):
                return {'read': 'read', '__exit__': 'context_exit', 'close': 'explicit_close'}[name]
        if type(owner) is _hashlib.HASH and value.__name__ == 'hexdigest':
            return 'hexdigest'
        return None

    def profile(self, frame, event, arg):
        if event in ('call', 'return'):
            name = self.names.get(frame.f_code)
            if name is None:
                return
            if event == 'call':
                if name == 'current_sources':
                    if self.active:
                        self.errors.append(['nested_current_sources'])
                    self.active = True
                if not self.active:
                    return
                if name == 'file_digests':
                    if self.fresh:
                        self.errors.append(['nested_file_digests'])
                    self.fresh = True
                if name == '_source_lexical_read':
                    self.ordinal += 1
                self.begin('python', name, id(frame))
            else:
                if not self.active:
                    return
                self.end('python', name, id(frame), event, arg)
                if name == '_source_lexical_read':
                    self.last_completed = self.ordinal
                if name == 'file_digests':
                    self.fresh = False
                if name == 'current_sources':
                    self.active = False
        elif event in ('c_call', 'c_return', 'c_exception') and self.active:
            name = self.c_name(arg)
            if name is None:
                return
            if event == 'c_call':
                self.begin('c', name, id(frame))
            else:
                self.end('c', name, id(frame), event)

    def line(self, code, line_number):
        assert code is self.digest_code
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        self.lines.append([line_number, wall, cpu])
        if line_number == self.markers[0] and self.inventory is None:
            self.inventory = {'wall_start_ns': wall, 'cpu_start_ns': cpu}
        if line_number == self.markers[1] and self.inventory is not None and not self.inventory_complete:
            self.inventory.update(wall_end_ns=wall, cpu_end_ns=cpu)
            self.inventory_complete = True

    def finish(self, expected, final_map, contract_path, manifest):
        assert not self.active and not self.fresh and not self.stack and not self.errors
        assert self.inventory_complete
        assert all('wall_end_ns' in row and 'cpu_end_ns' in row for row in self.intervals)
        python = Counter(row['name'] for row in self.intervals if row['kind'] == 'python')
        for name in ('current_sources', 'validate_contract', 'support_contract', 'file_digests'):
            assert python[name] == 1, (name, python[name])
        guards = [r for r in self.intervals if r['name'] == '_source_protocol_current' and r['fresh']]
        lexical = [r for r in self.intervals if r['name'] == '_source_lexical_read' and r['fresh']]
        assert len(guards) == expected['expected_guard_calls_inside_file_digests'] == 1823
        assert all(row['guard_true'] for row in guards)
        assert len(lexical) == self.ordinal == self.last_completed == expected['fresh_paths'] == 1551
        assert all(r.get('return_type') == 'bytes' for r in lexical)
        assert sum(r['return_length'] for r in lexical) == expected['fresh_bytes'] == 58637295
        counters = Counter(row['name'] for row in self.intervals if row['kind'] == 'c' and row['fresh'])
        for name in ('open', 'read', 'context_exit', 'sha256', 'hexdigest'):
            assert counters[name] == 1551, (name, counters[name])
        assert all(r['exit_event'] == 'c_return' for r in self.intervals if r['kind'] == 'c')
        paths = sorted(k for k in final_map if k != contract_path)
        assert len(paths) == 1551
        # Association is derived from the pinned sorted-comprehension source.
        # The observer never reads f_locals, path arguments, or returned map contents.
        associations = []
        per_file_counts = {}
        for interval in self.intervals:
            if interval['kind'] == 'c' and interval['fresh']:
                per_file_counts.setdefault(interval['ordinal'], Counter())[interval['name']] += 1
        for ordinal, (path, row) in enumerate(zip(paths, lexical, strict=True), 1):
            assert row['ordinal'] == ordinal and row['return_length'] == manifest[path]['bytes']
            associations.append({'ordinal': ordinal, 'inferred_from_pinned_source_path': path,
                                 'observed_bytes_length': row['return_length'], 'actual_path_argument_observed': False})
            per_file = per_file_counts.get(ordinal, Counter())
            assert all(per_file[name] == 1 for name in ('open', 'read', 'context_exit', 'sha256', 'hexdigest'))
        totals = {}
        children = Counter()
        for row in self.intervals:
            if row['parent'] is not None:
                children[row['parent']] += row['wall_end_ns'] - row['wall_start_ns']
            key = row['kind'] + ':' + row['name']
            item = totals.setdefault(key, {'calls': 0, 'inclusive_wall_ns': 0, 'inclusive_cpu_ns': 0})
            item['calls'] += 1
            item['inclusive_wall_ns'] += row['wall_end_ns'] - row['wall_start_ns']
            item['inclusive_cpu_ns'] += row['cpu_end_ns'] - row['cpu_start_ns']
        residuals = [{'sequence': row['sequence'], 'name': row['name'],
                      'unlabelled_wall_residual_ns': row['wall_end_ns'] - row['wall_start_ns'] - children[row['sequence']]}
                     for row in self.intervals if row['kind'] == 'python']
        assert all(r['unlabelled_wall_residual_ns'] >= 0 for r in residuals)
        return {'python_calls': dict(python), 'fresh_c_calls': dict(counters), 'inclusive_totals': totals,
                'inventory_statement_interval': self.inventory, 'residuals': residuals,
                'inferred_path_associations': associations, 'actual_path_arguments_observed': False,
                'observer_overhead_included': True, 'uninstrumented_deadline_result': None}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    source, harness, out = args.source.resolve(), args.harness.resolve(), args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    expected = json.loads(args.inputs.read_bytes())
    report = {'schema': 'hepta.r20.single-original-fresh-breakdown.v1', 'status': 'DIAGNOSTIC_FAILURE',
              'source_commit': expected['source_commit'], 'source_tree': expected['source_tree'],
              'product_calls_attempted': 0, 'product_tests': 0, 'compilers': 0, 'Native': 0, 'VM': 0,
              'qualification': False, 'whole_native': False, 'python': sys.version,
              'filesystem_cache_warmed_by_full_source_guards': True, 'automatic_retry': False}
    before = observer = final_map = None
    selected_profile = selected_line = None
    profile_installed = tool_owned = callback_installed = local_enabled = False
    errors = []
    try:
        assert tuple(sys.version_info[:3]) == (3, 14, 4) == tuple(expected['python_version'])
        sys.dont_write_bytecode = True
        assert sys.getprofile() is None and sys.gettrace() is None
        assert sys.monitoring.get_tool(TOOL_ID) is None and sys.monitoring.get_events(TOOL_ID) == 0
        manifest_raw = (harness / expected['source_manifest_file']).read_bytes()
        assert identity(manifest_raw) == expected['source_manifest']
        manifest = json.loads(manifest_raw)
        fresh_raw = (harness / expected['fresh_map_file']).read_bytes()
        assert identity(fresh_raw) == expected['fresh_map']
        expected_fresh = json.loads(fresh_raw)
        before = snapshot(source, expected)
        write_json(out / 'SOURCE-BEFORE.json', before)
        assert before['files'] == {name: {'mode': r['git_mode'], **{k: r[k] for k in ('bytes', 'sha256', 'git_blob')}} for name, r in manifest.items()}
        sys.path.insert(0, str(source))
        from tools import hia_selfhost_contract as contract
        from tools import build_hia_json_preflight as builder
        functions = {'current_sources': builder.current_sources, **{n: getattr(contract, n) for n in EXPECTED_FUNCTIONS}}
        module_before = [binding_snapshot(m) for m in (contract, builder)]
        function_before = {n: function_snapshot(f) for n, f in functions.items()}
        assert contract._SOURCE_PATH_PROTOCOL is not None and contract._SOURCE_PATH_PROTOCOL[4] == 0
        assert contract._source_io.open is _io.open and contract.sha256 is builder.sha256 is hashlib.sha256
        assert contract.ROOT == builder.ROOT == source
        contract_raw = (source / 'tools/hia_selfhost_contract.py').read_bytes()
        assert identity(contract_raw) == expected['function_source']
        markers = inventory_lines(contract_raw)
        assert list(markers) == expected['inventory_markers']
        assert sys.monitoring.get_local_events(TOOL_ID, functions['file_digests'].__code__) == 0
        observer = Observer(functions, _io.open, hashlib.sha256, markers)
        selected_profile, selected_line = observer.profile, observer.line
        sys.monitoring.use_tool_id(TOOL_ID, TOOL_NAME)
        tool_owned = True
        previous = sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.LINE, selected_line)
        if previous is not None:
            sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.LINE, previous)
            raise RuntimeError('unused tool slot retained a foreign LINE callback; restored before any product')
        callback_installed = True
        sys.monitoring.set_local_events(TOOL_ID, observer.digest_code, sys.monitoring.events.LINE)
        local_enabled = True
        sys.setprofile(selected_profile)
        profile_installed = True
        report['product_calls_attempted'] += 1
        try:
            final_map = builder.current_sources()
        finally:
            if sys.getprofile() is selected_profile:
                sys.setprofile(None)
                profile_installed = False
            else:
                errors.append('profile changed while armed; foreign replacement not cleared')
            if sys.monitoring.get_tool(TOOL_ID) == TOOL_NAME:
                sys.monitoring.set_local_events(TOOL_ID, observer.digest_code, 0)
                local_enabled = False
                returned = sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.LINE, None)
                callback_installed = False
                if returned is not selected_line:
                    if returned is not None:
                        sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.LINE, returned)
                    errors.append('LINE callback changed while armed; prior returned callback restored')
                sys.monitoring.free_tool_id(TOOL_ID)
                tool_owned = False
            else:
                errors.append('monitoring tool ownership changed while armed')
        assert not errors
        assert [binding_snapshot(m) for m in (contract, builder)] == module_before
        assert {n: function_snapshot(f) for n, f in functions.items()} == function_before
        assert type(final_map) is dict and all(type(k) is str and type(v) is str for k, v in final_map.items())
        assert len(final_map) == 1552
        actual_fresh = {k: v for k, v in final_map.items() if k != contract.CONTRACT_PATH}
        assert actual_fresh == expected_fresh
        assert final_map[contract.CONTRACT_PATH] == manifest[contract.CONTRACT_PATH]['sha256']
        write_json(out / 'ACTUAL-CURRENT-SOURCES.json', final_map)
        summary = observer.finish(expected, final_map, contract.CONTRACT_PATH, manifest)
        write_json(out / 'COMPONENTS.json', summary)
        report['status'] = 'ONE_ORIGINAL_FRESH_OBSERVATION_COMPLETE'
        report['actual_fresh_paths'] = len(actual_fresh)
        report['actual_current_sources_paths'] = len(final_map)
        report['bindings_and_function_definitions_unchanged'] = True
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        terminal_errors = []
        def attempt_terminal(label, action):
            try:
                return action()
            except BaseException:
                detail = {'action': label, 'traceback': traceback.format_exc()}
                terminal_errors.append(detail)
                try:
                    print(json.dumps({'terminal_evidence_error': detail}, sort_keys=True), file=sys.stderr, flush=True)
                except BaseException:
                    pass
                return None
        def release_profile():
            if profile_installed and sys.getprofile() is selected_profile:
                sys.setprofile(None)
        def release_monitor():
            if tool_owned and sys.monitoring.get_tool(TOOL_ID) == TOOL_NAME:
                if local_enabled:
                    sys.monitoring.set_local_events(TOOL_ID, observer.digest_code, 0)
                if callback_installed:
                    returned = sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.LINE, None)
                    if returned is not selected_line and returned is not None:
                        sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.LINE, returned)
                        errors.append('unexpected foreign callback restored during terminal cleanup')
                sys.monitoring.free_tool_id(TOOL_ID)
        attempt_terminal('profile cleanup', release_profile)
        attempt_terminal('monitor cleanup', release_monitor)
        report['observer_cleanup_errors'] = errors
        report['profile_is_original_none'] = False
        report['monitor_tool_released'] = False
        attempt_terminal('profile state', lambda: report.update(profile_is_original_none=sys.getprofile() is None))
        attempt_terminal('monitor state', lambda: report.update(monitor_tool_released=sys.monitoring.get_tool(TOOL_ID) is None))
        if observer is not None:
            attempt_terminal('ordered events save', lambda: write_json(out / 'ORDERED-EVENTS.json',
                {'events': observer.events, 'intervals': observer.intervals,
                 'line_events': observer.lines, 'observer_errors': observer.errors,
                 'incomplete_stack': observer.stack}))
        if final_map is not None:
            def save_final_map():
                if not (out / 'ACTUAL-CURRENT-SOURCES.json').exists():
                    write_json(out / 'ACTUAL-CURRENT-SOURCES.json', final_map)
            attempt_terminal('actual current sources save', save_final_map)
        after = None
        try:
            after = snapshot(source, expected)
            report['source_unchanged'] = before is not None and before == after
        except BaseException:
            report['source_readback_error'] = traceback.format_exc()
            report['source_unchanged'] = False
        if after is not None:
            attempt_terminal('source after save', lambda: write_json(out / 'SOURCE-AFTER.json', after))
        report['terminal_evidence_errors'] = terminal_errors
        if errors or terminal_errors or not report['source_unchanged'] or not report['profile_is_original_none'] or not report['monitor_tool_released']:
            report['status'] = 'DIAGNOSTIC_FAILURE'
        report['methodological_limits'] = [
            'One original current_sources call only; no automatic replay.',
            'Observer overhead is included; no subtraction or uninstrumented deadline claim.',
            'Source guards warm filesystem caches outside counters.',
            'Context-exit timing is not isolated close(2) timing; missing events mean incomplete coverage.',
            'Per-file names are inferred from pinned sorted source and final validated map; path arguments and returned map contents were not read by callbacks.',
            'No product function or global provider replaced; no source bytes or frame objects in event records.']
        attempt_terminal('terminal report save', lambda: write_json(out / 'REPORT.json', report))
        if terminal_errors:
            report['status'] = 'DIAGNOSTIC_FAILURE'
        attempt_terminal('terminal stdout report', lambda: print(json.dumps(report, sort_keys=True), flush=True))
        if terminal_errors:
            report['status'] = 'DIAGNOSTIC_FAILURE'
    return 0 if report['status'] == 'ONE_ORIGINAL_FRESH_OBSERVATION_COMPLETE' else 1

if __name__ == '__main__':
    raise SystemExit(main())

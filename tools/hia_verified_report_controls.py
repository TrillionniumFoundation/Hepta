"""Actual original-policy/report-owner/CLI comparisons, never cold authority."""
from __future__ import annotations
from pathlib import Path
import contextlib
import copy
import ctypes
import base64
import hashlib
import io
import json
import os
import sys
import time
import traceback
import weakref
import zlib
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def run_observations(output, manifest):
    SOURCE = ROOT
    OUT = Path(output).absolute()
    OUT.mkdir(exist_ok=False)
    manifest = Path(manifest).resolve(strict=True)


    def pin(raw):
        return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


    def save(name, value):
        (OUT / name).write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n')


    def snapshot():
        return {p.relative_to(SOURCE).as_posix(): {**pin(p.read_bytes()), 'mode': p.stat().st_mode & 511}
                for p in sorted(SOURCE.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}


    def error_value(error):
        if error is None:
            return None
        return {'type': type(error).__module__ + '.' + type(error).__qualname__,
                'text': str(error), 'name': getattr(error, 'name', None),
                'code': getattr(error, 'code', None), 'suppress_context': error.__suppress_context__,
                'context': error_value(error.__context__) if error.__context__ is not error else 'self',
                'cause': error_value(error.__cause__) if error.__cause__ is not error else 'self'}


    def represented(value):
        if type(value) in (set, frozenset):
            return {'type': type(value).__name__, 'items': sorted(value)}
        if type(value) is bytes:
            return {'type': 'bytes', 'hex': value.hex()}
        return {'type': type(value).__module__ + '.' + type(value).__qualname__, 'value': value,
                'ordered_json': json.dumps(value, ensure_ascii=True, sort_keys=False)}


    def observed(call, old_codes):
        calls = []
        def profile(frame, event, arg):
            if event == 'call' and frame.f_code in old_codes:
                calls.append(old_codes[frame.f_code])
        stdout, stderr = io.StringIO(), io.StringIO()
        result = error = None
        previous = sys.getprofile()
        try:
            sys.setprofile(profile)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    result = represented(call())
                except BaseException as caught:
                    error = error_value(caught)
        finally:
            sys.setprofile(previous)
        return {'result': result, 'exception': error, 'stdout': stdout.getvalue(),
                'stderr': stderr.getvalue()}, calls


    before = snapshot()
    save('SOURCE-BEFORE.json', before)
    started = time.monotonic_ns()
    report = {'schema': 'hepta.verified-report.actual-observations.v1', 'status': 'FAIL',
              'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY',
              'python': sys.version, 'cases': [], 'new_whole_verify_claim': False}
    frame_log = (OUT / 'ACTUAL-MACHINE-FRAMES.jsonl').open('w')
    frame_count = 0
    fixed_sources = {}
    wrapped_entries = []


    def packed(raw):
        return {**pin(raw), 'zlib_base64': base64.b64encode(zlib.compress(raw, 1)).decode()}


    def journal_entry(entry, label):
        def actual(source, source_size, output, output_size, workspace, workspace_size):
            nonlocal frame_count
            source_before = ctypes.string_at(source, source_size)
            output_before = ctypes.string_at(output, output_size)
            workspace_before = ctypes.string_at(workspace, workspace_size)
            result = entry(source, source_size, output, output_size, workspace, workspace_size)
            source_after = ctypes.string_at(source, source_size)
            def source_record(raw):
                if raw == fixed_sources.get(label):
                    return {**pin(raw), 'fixed_file': label + '-source.bin'}
                return packed(raw)
            row = {'index': frame_count, 'image': label, 'return': result,
                   'source_before': source_record(source_before), 'source_after': source_record(source_after),
                   'output_before': packed(output_before),
                   'output_after': packed(ctypes.string_at(output, output_size)),
                   'workspace_before': packed(workspace_before),
                   'workspace_after': packed(ctypes.string_at(workspace, workspace_size))}
            frame_log.write(json.dumps(row, separators=(',', ':')) + '\n')
            frame_count += 1
            return result
        return actual


    try:
        from hepta import hia_program as program, cli
        from hepta.hia_schema import PRIMITIVE_PROFILES, COMPOSITE_PROFILES
        from hepta.hia_verified_report_native import NativeVerifiedReport, ARITIES
        from hepta.hia_cli_verified_report_native import NativeReportCli
        from hepta.hia_cli_native import installed_cli, installed_cli_strict, _ACTIVE_SESSIONS
        from tests.test_hia_program import m, f, b, c, ret
        from tests.test_hia_program_composite import module
        selected_cli = installed_cli_strict(str(manifest))
        assert type(selected_cli) is NativeReportCli
        owner = selected_cli.verified_report
        assert type(owner) is NativeVerifiedReport
        report['actual_selected_manifest'] = {'path': str(manifest), **pin(manifest.read_bytes())}
        fixed_sources['report'] = owner.table
        (OUT / 'report-source.bin').write_bytes(owner.table)
        wrapped_entries.append((owner, owner._entry))
        owner._entry = journal_entry(owner._entry, 'report')
        old = program._NATIVE_VERIFIED_REPORT_ANCHORS
        old_codes = {row[2]: name for name, row in old.items()}
        doc = m(f('calculate', [], ['u32'], [], [b('entry', [], [c('answer', 'u32', 7)], ret('answer'))]))

        def add_case(name, expected, actual, entries, old_calls, *, require_native=False, no_old=False, extra=None):
            row = {'name': name, 'expected': expected, 'actual': actual, 'equal': expected == actual,
                   'actual_hia_entries': entries, 'original_policy_frames': old_calls,
                   'require_native': require_native, 'require_no_original_frames': no_old}
            if extra:
                row.update(extra)
            row['passed'] = row['equal'] and (entries > 0 or not require_native) and (not old_calls or not no_old)
            report['cases'].append(row)
            save('PROGRESS.json', report)

        documents = []
        for schema in list(PRIMITIVE_PROFILES) + list(COMPOSITE_PROFILES):
            document = copy.deepcopy(doc) if schema in PRIMITIVE_PROFILES else module([], copy.deepcopy(doc['functions'][0]))
            document['schema'] = schema
            documents.append((schema, document))
            value = program.verify_program(document)
            for name in ARITIES:
                expected, _ = observed(lambda: old[name][1](value), old_codes)
                initial = owner.entries
                actual, calls = observed(lambda: owner.run(name, value), old_codes)
                add_case(schema + ':' + name, expected, actual, owner.entries - initial, calls,
                         require_native=True, no_old=True)

        # Original constructor is public and grants no authority. Each root keeps
        # its exact behavior for malformed bytes, structured mismatch and bad text.
        for label, value in (
            ('invalid-json', program.VerifiedProgram(b'{')),
            ('bad-utf8', program.VerifiedProgram(b'\xff')),
            ('structured-mismatch', program.VerifiedProgram(b'{}', b'{}')),
        ):
            for name in ARITIES:
                expected, _ = observed(lambda: old[name][1](value), old_codes)
                initial = owner.entries
                actual, calls = observed(lambda: owner.run(name, value), old_codes)
                add_case(label + ':' + name, expected, actual, owner.entries - initial, calls,
                         require_native=True, no_old=True)

        value = program.verify_program(doc)
        real_verify = program.verify_program
        real_decode = program.decode_internal_canonical
        real_hash = program.payload_sha256
        real_profile = program.profile_for_schema
        real_feature = program.supports_feature

        def providers(selected, mutation=None):
            events = []
            def verify(value):
                events.append('verify')
                return real_verify(value)
            def decode(value, **kwargs):
                events.append(['decode', hashlib.sha256(value).hexdigest(), list(kwargs.items())])
                return real_decode(value, **kwargs)
            class Digest:
                def __init__(self, data): self.data = data
                def hex(self): events.append('hex'); return self.data.hex()
                def __del__(self): events.append('digest-retired')
            def hashed(value):
                events.append(['hash', hashlib.sha256(value).hexdigest()])
                return Digest(real_hash(value))
            def profile(schema):
                events.append(['profile', schema])
                return real_profile(schema)
            def feature(schema, name):
                events.append(['feature', schema, name])
                return real_feature(schema, name)
            initial = owner.entries
            with patch.multiple(program, verify_program=verify, decode_internal_canonical=decode,
                                payload_sha256=hashed, profile_for_schema=profile, supports_feature=feature):
                result, calls = observed(lambda: owner.invoke_bound_report(value.report) if selected else value.report(), old_codes)
            result['events'] = events
            return result, calls, owner.entries - initial

        expected, _, _ = providers(False)
        actual, calls, count = providers(True)
        add_case('all-live-providers-order-alias-retirement', expected, actual, count, calls,
                 require_native=True, no_old=True)

        for name, replacement in (
            ('as_dict', lambda self: real_decode(self.canonical_bytes, max_nodes=program.MAX_NODES, max_depth=program.MAX_DEPTH)),
            ('sha256', property(lambda self: 'replacement-digest')),
            ('normalization_report', property(lambda self: {'actual': 'replacement'})),
            ('report', lambda self: {'actual': 'foreign-report'}),
        ):
            with patch.object(program.VerifiedProgram, name, replacement):
                expected, _ = observed(lambda: value.report(), old_codes)
                initial = owner.entries
                actual, calls = observed(lambda: owner.invoke_bound_report(value.report), old_codes)
                add_case('class-replacement-' + name, expected, actual, owner.entries - initial, calls,
                         require_native=name != 'report',
                         extra={'root_foreign_expected': name == 'report'})

        getter = old['sha256'][1]
        original_code = getter.__code__
        def changed(self): return 'changed-original-getter-code'
        try:
            getter.__code__ = changed.__code__
            expected, _ = observed(lambda: value.report(), old_codes)
            initial = owner.entries
            actual, calls = observed(lambda: owner.invoke_bound_report(value.report), old_codes)
            add_case('property-original-function-code-replaced', expected, actual, owner.entries - initial, calls,
                     require_native=True)
        finally:
            getter.__code__ = original_code

        for selected in (False, True):
            events = []
            def access(self, name):
                events.append(name)
                return object.__getattribute__(self, name)
            initial = owner.entries
            with patch.object(program.VerifiedProgram, '__getattribute__', access):
                result, calls = observed(lambda: owner.invoke_bound_report(value.report) if selected else value.report(), old_codes)
            result['events'] = events
            if not selected:
                expected = result
            else:
                add_case('real-getattribute-foreign-root', expected, result, owner.entries - initial, calls,
                         extra={'native_expected': 0})
                assert owner.entries == initial

        def contextual(selected):
            class Outer(Exception): pass
            class Provider(Exception): pass
            def bad(value): raise Provider('provider actual error')
            try:
                raise Outer('outer handled')
            except Outer:
                with patch.object(program, 'payload_sha256', bad):
                    return observed(lambda: owner.run('sha256', value) if selected else old['sha256'][1](value), old_codes)
        expected, _ = contextual(False)
        initial = owner.entries
        actual, calls = contextual(True)
        add_case('outer-handled-provider-error-context', expected, actual, owner.entries - initial, calls,
                 require_native=True, no_old=True)

        real = program.verify_program
        try:
            del program.verify_program
            expected, _ = observed(lambda: old['report'][1](value), old_codes)
            initial = owner.entries
            actual, calls = observed(lambda: owner.run('report', value), old_codes)
            add_case('missing-live-provider-nameerror', expected, actual, owner.entries - initial, calls,
                     require_native=True, no_old=True)
        finally:
            program.verify_program = real

        # Use the actual admitted bundle's retained original five-image manifest.
        # The qualification owner separately admits either its cold fixture or an
        # explicit development build; observations never grant cold authority.
        base_manifest = (manifest.parent / 'manifest.json').resolve(strict=True)
        original_cli = installed_cli(str(base_manifest))
        assert original_cli.control is selected_cli.control
        wrapped_entries.append((original_cli.control, original_cli.control._entry))
        original_cli.control._entry = journal_entry(original_cli.control._entry, 'cli-control')
        report['actual_companion_manifest'] = {'path': str(base_manifest), **pin(base_manifest.read_bytes())}
        valid_file = OUT / 'program.core.hepta'
        valid_file.write_bytes(value.canonical_bytes)
        invalid_file = OUT / 'invalid.core.hepta'
        invalid_file.write_bytes(b'{')
        cases = [
            ['verify', '--input', str(valid_file)],
            ['verify', '--input', str(invalid_file)],
            ['verify', '--input', str(OUT / 'absent.core.hepta')],
            ['verify', '--input', str(valid_file), '--output', str(OUT / 'forbidden-output')],
            ['inspect', '--input', str(valid_file)],
            ['normalize', '--input', str(valid_file)],
            ['capabilities'], ['catalog', '--schema', 'hepta.hia.program.v8'],
        ]
        for index, arguments in enumerate(cases):
            expected, _ = observed(lambda: cli._HIA_DISCOVERY_DEFINITIONS[2](arguments), old_codes)
            initial = owner.entries
            actual, calls = observed(lambda: selected_cli.run(arguments, cli), old_codes)
            add_case('retained-argv-' + str(index) + '-' + arguments[0], expected, actual,
                     owner.entries - initial, calls)
        positive_cases = []
        for index, (schema, document) in enumerate(documents):
            path = OUT / ('schema-' + str(index) + '.core.hepta')
            path.write_text(json.dumps(document, ensure_ascii=False))
            positive_cases.append(('verify-' + schema, ['verify', str(path)], True))
        positive_cases.extend([
            ('verify-invalid-json', ['verify', str(invalid_file)], False),
            ('verify-absent-file', ['verify', str(OUT / 'absent.core.hepta')], False),
            ('verify-output-refused', ['verify', str(valid_file), '--output', str(OUT / 'forbidden-output')], False),
            ('verify-directory', ['verify', str(OUT)], False),
            ('inspect-preserved', ['inspect', str(valid_file)], False),
            ('normalize-preserved', ['normalize', str(valid_file)], False),
        ])
        for label, arguments, native in positive_cases:
            expected, _ = observed(lambda: cli._HIA_DISCOVERY_DEFINITIONS[2](arguments), old_codes)
            initial = owner.entries
            actual, calls = observed(lambda: selected_cli.run(arguments, cli), old_codes)
            add_case('actual-cli-positional-' + label, expected, actual, owner.entries - initial,
                     calls, require_native=native, no_old=native)
        assert not (OUT / 'forbidden-output').exists()
        assert not _ACTIVE_SESSIONS

        # The local per-session effect adapter must not create a self-retaining
        # bound-method cycle. This observes ordinary reference retirement, no GC.
        session = selected_cli.prepare(['verify', str(valid_file)], cli)
        assert session.kind == 0
        held = weakref.ref(session)
        session.run()
        del session
        report['session_released_without_gc'] = held() is None
        assert report['session_released_without_gc']
        report['native_entries'] = owner.entries
        report['case_count'] = len(report['cases'])
        report['failed_cases'] = [row['name'] for row in report['cases'] if not row['passed']]
        assert not report['failed_cases'], report['failed_cases']
        report['status'] = 'PASS'
    except BaseException:
        report['traceback'] = traceback.format_exc()
    finally:
        for selected, original_entry in reversed(wrapped_entries):
            selected._entry = original_entry
        frame_log.close()
        report['actual_machine_frames'] = frame_count
        report['actual_machine_frames_file'] = pin((OUT / 'ACTUAL-MACHINE-FRAMES.jsonl').read_bytes())
        after = snapshot()
        save('SOURCE-AFTER.json', after)
        report['source_unchanged'] = before == after
        if before != after:
            report['status'] = 'FAIL'
        report['wall_ns'] = time.monotonic_ns() - started
        save('REPORT.json', report)
    return report

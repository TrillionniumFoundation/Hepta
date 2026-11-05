"""Real collector/replay cleanup boundary; separate from historical inventories."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from tests import test_core_byte_facts_capture_replay as byte_harness
from tests import test_core_seven_certificate_diagnostic as seven_capture
from tests import test_core_seven_certificate_runner as seven_harness
from tests import test_core_syntax_diagnostic_capture as capture_harness
from tools import core_syntax_diagnostic_capture as collector
from tools.check_core_syntax_staged import digest


TARGETS = ('LinearTransport', 'CertPart02', 'SevenCertificatePart02')


class CleanupReplayTests(unittest.TestCase):
    def capture(self, target, setup=None):
        manifest = b'{"markers":[]}\n'
        reference = dict(path='diagnostic-manifest.json', sha256=digest(manifest))
        original = collector.capture_result

        def invoke(*args, **kwargs):
            kwargs['safe_root'].write(reference['path'], manifest)
            return original(*args, **kwargs, manifest_reference=reference)

        script = 'import os;os.write(1,b"real child output\\n")'
        with patch.object(collector, 'capture_result', side_effect=invoke):
            if target == 'SevenCertificatePart02':
                result, files, _ = seven_capture.SevenCaptureTests().capture(script, setup=setup)
            else:
                result, files, _ = capture_harness.DiagnosticCaptureTests().run_child(
                    script, target=target, setup=setup)
        return result, files, manifest, reference

    def test_actual_terminal_round_trip_all_three_profiles(self):
        for target in TARGETS:
            with self.subTest(target=target):
                result, files, _, reference = self.capture(target)
                self.assertEqual(result['status'], 'diagnostic_completed', result)
                names, _ = collector.target_configuration(target)
                process = collector.validate_terminal_cleanup(files[names[2]], result, reference)
                self.assertIs(process['cleanup_deadline_exceeded'], False)
                self.assertIs(process['cleanup_incomplete'], False)
                # Every event line uses the strict decoder, not only terminal.
                for index in (0, 1):
                    rows = files[names[2]].splitlines(keepends=True)
                    rows[index] = rows[index].replace(b'{', b'{"unreviewed_number":1e999,', 1)
                    with self.assertRaisesRegex(ValueError, 'non-finite cleanup JSON number'):
                        collector.validate_terminal_cleanup(b''.join(rows), result, reference)
                if target == 'LinearTransport':
                    from tools import diagnose_core_syntax_declarations as declarations
                    with tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        for name, raw in files.items():
                            (root / name).write_bytes(raw)
                        (root / reference['path']).write_bytes(b'{"markers":[]}\n')
                        receipt = dict(status='diagnostic_completed', stages=[dict(name=target,
                            status=result['status'], process_started=True, capture_files=result['files'])])
                        raw = collector._record_bytes(receipt)
                        for old, new in (
                                (b'"status":"diagnostic_completed"', b'"status":"diagnostic_timeout","status":"diagnostic_completed"'),
                                (b'"status":"diagnostic_completed"', b'"status":"diagnostic_timeout","sta\\u0074us":"diagnostic_completed"'),
                                (b'{', b'{"number":NaN,'), (b'{', b'{"number":Infinity,'),
                                (b'{', b'{"number":1e999,')):
                            (root / 'RESULT.json').write_bytes(raw.replace(old, new, 1))
                            output = io.BytesIO()
                            class Stdout:
                                buffer = output
                            with patch('sys.stdout', Stdout()), self.assertRaises(ValueError):
                                declarations.print_events(root)
                            self.assertEqual(output.getvalue(), b'')
                        (root / 'RESULT.json').write_bytes(json.dumps(receipt, indent=2).encode()+b'\n')
                        output = io.BytesIO()
                        with patch('sys.stdout', type('Stdout', (), {'buffer': output})()):
                            declarations.print_events(root)
                        self.assertIn(b'real child output', output.getvalue())

    def test_byte_facts_replay_refuses_rehashed_cleanup_lies(self):
        item = self.capture('CertPart02')
        verifier = byte_harness.CaptureReplayTests()
        verifier.verify(item)
        missing = object()
        mutations = [('cleanup_deadline_exceeded', value) for value in (True, 0, None, missing)]
        mutations += [('cleanup_incomplete', value) for value in (0, None, missing)]
        mutations += [('leader_cleanup_error', 'OSError'), ('interrupted', True), ('interrupted', 0)]
        for key, value in mutations:
            with self.subTest(key=key, value='missing' if value is missing else value):
                result, files, manifest, reference = deepcopy(item)
                name = 'CertPart02.events.jsonl'
                rows = [json.loads(line) for line in files[name].splitlines()]
                if value is missing:
                    del rows[-1]['process'][key]
                else:
                    rows[-1]['process'][key] = value
                files[name] = b''.join(collector._record_bytes(row) for row in rows)
                # Rehash the mutated container too: rejection must depend on
                # cleanup semantics, not a deliberately stale file digest.
                identity = dict(path=name, bytes=len(files[name]), sha256=digest(files[name]))
                result['files'][name] = identity
                result['compact_receipt_reference'] = identity
                result['metadata_written_bytes'] = len(files[name])
                result['metadata_remaining_bytes'] = collector.METADATA_LIMIT - len(files[name])
                with self.assertRaises(ValueError):
                    verifier.verify((result, files, manifest, reference))
        # A rehashed container cannot hide a first adverse value by repeating
        # its JSON key. Non-finite spellings are never emitted by the collector.
        for old, new in (
                (b'"cleanup_deadline_exceeded":false', b'"cleanup_deadline_exceeded":true,"cleanup_deadline_exceeded":false'),
                (b'"status":"diagnostic_completed"', b'"status":"diagnostic_infrastructure_failed","status":"diagnostic_completed"'),
                (b'"process":{', b'"process":{"unreviewed_number":NaN,'),
                (b'"process":{', b'"process":{"unreviewed_number":Infinity,'),
                (b'"process":{', b'"process":{"unreviewed_number":1e999,')):
            with self.subTest(json_mutation=new):
                result, files, manifest, reference = deepcopy(item)
                name = 'CertPart02.events.jsonl'
                lines = files[name].splitlines(keepends=True)
                self.assertIn(old, lines[-1])
                lines[-1] = lines[-1].replace(old, new, 1)
                files[name] = b''.join(lines)
                identity = dict(path=name, bytes=len(files[name]), sha256=digest(files[name]))
                result['files'][name] = identity
                result['compact_receipt_reference'] = identity
                result['metadata_written_bytes'] = len(files[name])
                result['metadata_remaining_bytes'] = collector.METADATA_LIMIT - len(files[name])
                with self.assertRaises(ValueError):
                    verifier.verify((result, files, manifest, reference))

    def test_actual_late_cleanup_replays_only_as_failure(self):
        for target in TARGETS:
            state = dict(offset=0, delayed=False)

            def setup(safe, stack):
                popen, monotonic = collector.subprocess.Popen, time.monotonic

                def launch(*args, **kwargs):
                    child = popen(*args, **kwargs)
                    wait = child.wait

                    def observe(*args, **kwargs):
                        result = wait(*args, **kwargs)
                        # The real child is reaped; only the observation clock
                        # crosses the unchanged cleanup deadline afterwards.
                        state.update(offset=3, delayed=True)
                        return result

                    child.wait = observe
                    return child

                stack.enter_context(patch.object(collector.subprocess, 'Popen', side_effect=launch))
                stack.enter_context(patch.object(collector.time, 'monotonic',
                    side_effect=lambda: monotonic() + state['offset']))

            with self.subTest(target=target):
                item = self.capture(target, setup)
                result, files, _, reference = item
                self.assertTrue(state['delayed'])
                self.assertEqual(result['status'], 'diagnostic_infrastructure_failed', result)
                self.assertTrue(result['leader_reaped'])
                self.assertTrue(result['cleanup_deadline_exceeded'])
                self.assertTrue(result['cleanup_incomplete'])
                names, _ = collector.target_configuration(target)
                collector.validate_terminal_cleanup(files[names[2]], result, reference)
                contradicted = dict(result, cleanup_deadline_exceeded=False,
                    cleanup_incomplete=not (result['leader_reaped'] and result['drain_complete']))
                with self.assertRaisesRegex(ValueError, 'cleanup terminal live result differs'):
                    collector.validate_terminal_cleanup(files[names[2]], contradicted, reference)
                if target == 'CertPart02':
                    byte_harness.CaptureReplayTests().verify(item)
                if target == 'LinearTransport':
                    # Actual failed terminal bytes must not be presented under
                    # a rehashed successful top-level declaration summary.
                    from tools import diagnose_core_syntax_declarations as declarations
                    with tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        for name, raw in files.items():
                            (root / name).write_bytes(raw)
                        (root / reference['path']).write_bytes(item[2])
                        receipt = dict(status='diagnostic_completed', stages=[dict(name=target,
                            status=result['status'], process_started=True, capture_files=result['files'])])
                        missing_files = deepcopy(receipt)
                        missing_files['stages'][0]['status'] = 'diagnostic_completed'
                        del missing_files['stages'][0]['capture_files']
                        for summary in (receipt, missing_files):
                            with self.subTest(summary=summary):
                                (root / 'RESULT.json').write_bytes(collector._record_bytes(summary))
                                output = io.BytesIO()
                                class Stdout:
                                    buffer = output
                                with patch('sys.stdout', Stdout()), self.assertRaisesRegex(
                                        ValueError, 'completed diagnostic target status differs'):
                                    declarations.print_events(root)
                                self.assertEqual(output.getvalue(), b'')

    def test_seven_collector_round_trip_keeps_exact_process_schema(self):
        case = seven_harness.SevenRunnerTests()
        case.prepared, case.proposal, case.diagnostic = seven_capture.fixture()

        def inspect(path, report, identity, support):
            self.assertEqual(report['status'], 'diagnostic_completed', report)
            case.replay(path, identity, support)
            process = report['stages'][-1]['process']
            self.assertIs(process['cleanup_deadline_exceeded'], False)
            result_path = Path(path) / 'RESULT.json'
            original = result_path.read_bytes()
            changes = (
                ({'unreviewed_cleanup_semantics': False}, 'target process schema differs'),
                ({'cleanup_deadline_exceeded': 0}, 'target process flag type differs'),
                ({'cleanup_deadline_exceeded': True, 'cleanup_incomplete': True},
                 'completed capture cleanup incomplete or late'),
            )
            try:
                for changeset, message in changes:
                    with self.subTest(changes=changeset):
                        changed = json.loads(original)
                        changed['stages'][-1]['process'].update(changeset)
                        result_path.write_bytes(collector._record_bytes(changed))
                        with self.assertRaisesRegex(ValueError, message):
                            case.replay(path, identity, support)
            finally:
                result_path.write_bytes(original)

        case.exercise(inspect=inspect)


if __name__ == '__main__':
    unittest.main()

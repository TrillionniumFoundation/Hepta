"""Structural checks for proposed Lean inputs, never evidence of kernel proofs.

No Lean or native target is executed. Original complete independently supplied
Raw/bytes remain the oracle; new generator self-consistency is insufficient.
"""
from copy import deepcopy
from hashlib import sha256
import json
import re
import unittest

from tools import check_core_syntax_lean as original
from tools import core_syntax_structured_sources as structured


class StructuredTransportSourceTests(unittest.TestCase):
    LAYOUT = (
        ('linear', 'HiaCoreSyntaxSlice', 'linear', 'linear'),
        ('parallel', 'HiaCoreSyntaxSlice', 'parallel', 'parallel'),
        ('wrong_phi', 'HiaCoreSyntaxSlice.WrongPhi', 'linear', 'mutated'),
        ('literal_two', 'HiaCoreSyntaxSlice.LiteralTwo', 'linear', 'mutated'),
        ('wrong_condition', 'HiaCoreSyntaxSlice.WrongCondition', 'linear', 'mutated'),
    )

    @classmethod
    def setUpClass(cls):
        prior = original.build_inputs()
        cls.inputs = {}
        for key, namespace, stem, cert in cls.LAYOUT:
            source = prior['positive'] if key in ('linear', 'parallel') else prior['negatives'][key]['source']
            byte_matches = re.findall(r'(?m)^def ' + stem + r'Bytes : List Nat := (\[[^\n]*\])$', source)
            raw_matches = re.findall(r'(?m)^def ' + stem + r'Raw : Raw := ([^\n]+)$', source)
            if len(byte_matches) != 1 or len(raw_matches) != 1:
                raise AssertionError('original full input definitions must be unique')
            raw_bytes = bytes(json.loads(byte_matches[0]))
            tree = original.strict_canonical(raw_bytes)
            if original.render_raw(tree) != raw_matches[0]:
                raise AssertionError('original Raw differs from independently supplied complete bytes')
            artifact = structured.build_structured_input(key, tree, raw_bytes, namespace, stem, cert)
            cls.inputs[key] = (tree, raw_bytes, artifact)
        cls.small_tree = {'a': list(range(110)), 'b': 'tail'}
        cls.small_bytes = json.dumps(cls.small_tree, sort_keys=True, separators=(',', ':')).encode()
        cls.small = structured.build_structured_input('test', cls.small_tree, cls.small_bytes,
                                                      'HiaCoreSyntaxSlice.Test', 'test', 'test')

    def verify(self, source=None, manifest=None):
        structured.verify_structured_source(source if source is not None else self.small.source,
                                            manifest if manifest is not None else self.small.manifest,
                                            self.small_tree, self.small_bytes)

    def test_all_five_complete_inputs_flatten_to_original_raw_and_bytes(self):
        for key, (tree, raw_bytes, artifact) in self.inputs.items():
            with self.subTest(input=key):
                structured.verify_structured_source(artifact.source, artifact.manifest, tree, raw_bytes)
                self.assertEqual(artifact.manifest['canonical_sha256'], sha256(raw_bytes).hexdigest())
                self.assertEqual(artifact.manifest['canonical_bytes'], len(raw_bytes))
        self.assertEqual(self.inputs['linear'][1], original.fixed_input()['bytes'])
        self.assertEqual(len(self.inputs['linear'][1]), 14466)

    def test_external_full_input_oracle_cannot_be_replaced_by_self_consistency(self):
        tree, raw_bytes, artifact = self.inputs['linear']
        wrong_tree, wrong_bytes, _ = self.inputs['literal_two']
        for expected_tree, expected_bytes in ((tree, wrong_bytes), (wrong_tree, raw_bytes),
                                               (wrong_tree, wrong_bytes), (tree, raw_bytes + b'0')):
            with self.subTest(byte_sha=sha256(expected_bytes).hexdigest()), self.assertRaises(ValueError):
                structured.verify_structured_source(artifact.source, artifact.manifest,
                                                    expected_tree, expected_bytes)

    def test_manifest_snapshot_and_source_digest_are_bound(self):
        artifact = self.small
        self.assertEqual(sha256(artifact.manifest_json.encode()).hexdigest(), artifact.manifest_sha256)
        manifest = artifact.manifest
        self.assertEqual(manifest['source_sha256'], sha256(artifact.source.encode()).hexdigest())
        manifest['canonical_sha256'] = '0' * 64
        self.assertNotEqual(artifact.manifest['canonical_sha256'], '0' * 64)
        with self.assertRaises(ValueError):
            self.verify(manifest=manifest)
        with self.assertRaises(ValueError):
            self.verify(source=artifact.source + '\n-- unbound source change\n')

    def test_segment_intervals_exactly_partition_every_original_byte(self):
        for key, (tree, raw_bytes, artifact) in self.inputs.items():
            with self.subTest(input=key):
                segments = artifact.manifest['segments']
                self.assertTrue(segments)
                cursor = 0
                for segment in segments:
                    self.assertEqual(segment['start'], cursor)
                    self.assertGreater(segment['end'], cursor)
                    self.assertLessEqual(segment['end'], len(raw_bytes))
                    piece = raw_bytes[segment['start']:segment['end']]
                    self.assertEqual(segment['sha256'], sha256(piece).hexdigest())
                    cursor = segment['end']
                self.assertEqual(cursor, len(raw_bytes))
                self.assertEqual(len({segment['name'] for segment in segments}), len(segments))

    def test_omitted_duplicated_reordered_or_overlapping_segment_metadata_fails(self):
        initial = self.small.manifest
        segments = initial['segments']
        self.assertGreater(len(segments), 2)
        variants = (segments[:-1], segments + segments[:1], segments[::-1],
                    [segments[1], segments[0]] + segments[2:])
        for replacement in variants:
            manifest = deepcopy(initial)
            manifest['segments'] = replacement
            with self.subTest(count=len(replacement)), self.assertRaises(ValueError):
                self.verify(manifest=manifest)
        for field, value in (('start', 1), ('end', len(self.small_bytes) + 1), ('sha256', '0' * 64)):
            manifest = deepcopy(initial)
            manifest['segments'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(manifest=manifest)

    def test_each_complete_proposed_source_remains_inside_existing_byte_caps(self):
        total = 0
        for key, (_, _, artifact) in self.inputs.items():
            size = len(artifact.source.encode())
            self.assertLessEqual(size, 2 * 1024 * 1024, key)
            total += size
            for forbidden in ('native_decide', 'sorryAx', 'set_option maxHeartbeats',
                              'set_option maxRecDepth'):
                self.assertNotIn(forbidden, artifact.source)
            self.assertIsNone(re.search(r'(?m)^\s*(axiom|unsafe|opaque)\b', artifact.source))
        self.assertLessEqual(total, 8 * 1024 * 1024)

    def rebound_definition(self, name, rhs):
        """Refresh untrusted digests: full flattening must still detect changes."""
        pattern = r'(?m)^(def ' + re.escape(name) + r' : .+? := )(.+)$'
        source, count = re.subn(pattern, lambda m: m[1] + rhs, self.small.source)
        self.assertEqual(count, 1)
        manifest = self.small.manifest
        manifest['source_sha256'] = sha256(source.encode()).hexdigest()
        manifest['definitions'] = [
            {'name': n, 'type': ty, 'rhs_sha256': sha256(value.encode()).hexdigest()}
            for n, ty, value in re.findall(r'(?m)^def ([A-Za-z][A-Za-z0-9_]*) : (.+?) := (.+)$', source)]
        return source, manifest

    def test_rehashed_byte_mutations_and_numeric_digit_splits_fail_full_binding(self):
        segments = self.small.manifest['segments']
        digit = next(s for s in segments if self.small_bytes[s['start']:s['end']] == b'1')
        # [49] followed by a digit means 12, not 1 with an arbitrary suffix.
        for rhs in ('[50]', '[49,50]', '[48,49]', '[256]', '[true]'):
            with self.subTest(rhs=rhs), self.assertRaises(ValueError):
                self.verify(*self.rebound_definition(digit['name'], rhs))
        for byte in (44, 93, 125):
            part = next(s for s in segments if self.small_bytes[s['start']:s['end']] == bytes([byte]))
            with self.subTest(delimiter=byte), self.assertRaises(ValueError):
                self.verify(*self.rebound_definition(part['name'], '[58]'))
        key = next(s for s in segments if self.small_bytes[s['start']:s['end']] == b'"a":')
        for rhs in ('[34,97,34,44]', '[34,97,35,58]'):
            with self.subTest(key_packet=rhs), self.assertRaises(ValueError):
                self.verify(*self.rebound_definition(key['name'], rhs))

    def test_rehashed_omitted_duplicated_reordered_suffixes_fail(self):
        manifest = self.small.manifest
        segments, tails = manifest['segments'], manifest['tails']
        for rhs in (tails[1], segments[0]['name'] + ' ++ ' + segments[0]['name'] + ' ++ ' + tails[1],
                    segments[1]['name'] + ' ++ ' + segments[0]['name'] + ' ++ ' + tails[2],
                    segments[0]['name'] + ' ++ ' + tails[2]):
            with self.subTest(rhs=rhs), self.assertRaises(ValueError):
                self.verify(*self.rebound_definition(tails[0], rhs))
        for replacement in (tails[:-1], tails[::-1], tails[:1] + tails[:1] + tails[2:]):
            changed = self.small.manifest
            changed['tails'] = replacement
            with self.subTest(tail_count=len(replacement)), self.assertRaises(ValueError):
                self.verify(manifest=changed)
        with self.assertRaises(ValueError):
            self.verify(*self.rebound_definition(tails[-1], '[48]'))

    def test_rehashed_raw_reordering_missing_fields_and_duplicate_keys_fail(self):
        raw_name = self.small.manifest['raw_name']
        a = original.render_raw(self.small_tree['a'])
        b = original.render_raw(self.small_tree['b'])
        for rhs in ('(.obj [([98],' + b + '),([97],' + a + ')])',
                    '(.obj [([97],' + a + '),([97],' + b + ')])',
                    '(.obj [([97],' + a + ')])'):
            with self.subTest(rhs_prefix=rhs[:35]), self.assertRaises(ValueError):
                self.verify(*self.rebound_definition(raw_name, rhs))

    def test_exact_fuel_depth_and_numeric_delimiter_metadata_are_checked(self):
        manifest = self.small.manifest
        nodes = manifest['nodes']
        root = nodes[0]
        self.assertEqual((root['fuel'], root['depth']), (4096, 32))
        for parent in nodes:
            for index, child_id in enumerate(parent['children']):
                child = nodes[child_id]
                self.assertEqual(child['fuel'], parent['fuel'] - 2 - index)
                self.assertEqual(child['depth'], parent['depth'] - 1)
            if parent['leaf']:
                self.assertLessEqual(parent['end'] - parent['start'], 256)
        num = next(n for n in nodes if n['kind'] == 'num')
        self.assertIn(num['delimiter'], (44, 93, 125))
        # These reject mismatched proposed arguments, not all alternative fuel values.
        for field, value in (('fuel', 0), ('fuel', num['fuel'] + 1), ('depth', 0),
                             ('depth', num['depth'] + 1), ('delimiter', 50),
                             ('delimiter', None), ('leaf', False)):
            changed = deepcopy(manifest)
            changed['nodes'][num['id']][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.verify(manifest=changed)
        for field, value in (('transport_fuel', 4097), ('transport_fuel', 4096.0),
                             ('transport_depth', 33), ('leaf_byte_limit', 257)):
            changed = deepcopy(manifest)
            changed[field] = value
            with self.subTest(limit=field), self.assertRaises(ValueError):
                self.verify(manifest=changed)

        for collection, field, value in (('segments', 'start', False),
                                         ('nodes', 'id', 0.0),
                                         ('list_steps', 'index', 0.0)):
            changed = deepcopy(manifest)
            self.assertEqual(changed[collection][0][field], 0)
            changed[collection][0][field] = value
            with self.subTest(collection=collection, field=field), self.assertRaises(ValueError):
                self.verify(manifest=changed)

    def test_invalid_canonical_digit_key_and_trailing_forms_cannot_build(self):
        for raw in (b'{"a":01}', b'{"a":1}0', b'{"a":1,"a":2}', b'{"b":1,"a":2}',
                    b'{"a":[1,]}', b'{"a":1;"b":2}', b'{"a":"\\n"}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                structured.build_structured_input('bad', {'a': 1}, raw,
                                                  'HiaCoreSyntaxSlice.Bad', 'bad', 'bad')

    def test_all_generated_theorems_are_named_and_root_statements_unchanged(self):
        for key, namespace, stem, cert in self.LAYOUT:
            artifact = self.inputs[key][2]
            names = re.findall(r'(?m)^theorem ([A-Za-z][A-Za-z0-9_]*)\b', artifact.source)
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual({namespace + '.' + name for name in names}, artifact.expected_theorems)
            self.assertEqual(sorted(artifact.expected_theorems), artifact.manifest['expected_theorems'])
            self.assertIn('theorem ' + cert + '_serialized : serializeRaw transportFuel transportDepth ' +
                          stem + 'Raw = some ' + stem + 'Bytes', artifact.source)
            self.assertIn('theorem ' + cert + '_parsed : parseRaw transportFuel transportDepth ' +
                          stem + 'Bytes = some (' + stem + 'Raw, [])', artifact.source)
            self.assertIn('theorem ' + cert + '_transport : checkedEncode ' +
                          stem + 'Raw = some ' + stem + 'Bytes', artifact.source)
            self.assertLessEqual(len(names), 906)
        numeric = next(n for n in self.small.manifest['nodes'] if n['kind'] == 'num')
        parser_line = next(line for line in self.small.source.splitlines()
                           if line.startswith('theorem test_p' + str(numeric['id']) + ' '))
        self.assertIn(str(numeric['delimiter']) + ' :: tail', parser_line)
        self.assertNotIn('++ tail)', parser_line)

    def test_rehashed_proof_parameter_and_root_suffix_changes_are_rejected(self):
        node = next(n for n in self.small.manifest['nodes'] if n['kind'] == 'num')
        original_statement = 'parseRaw ' + str(node['fuel']) + ' ' + str(node['depth'])
        needle = 'theorem test_p' + str(node['id']) + ' '
        line = next(line for line in self.small.source.splitlines() if line.startswith(needle))
        variants = (
            self.small.source.replace(line, line.replace(original_statement, 'parseRaw 0 ' + str(node['depth']), 1), 1),
            self.small.source.replace(line, line.replace(str(node['delimiter']) + ' :: tail', '50 :: tail'), 1),
            self.small.source.replace('testBytes = some (testRaw, [])', 'testBytes = some (testRaw, [48])', 1),
            self.small.source.replace('serializeRaw transportFuel transportDepth testRaw = some testBytes',
                                      'serializeRaw 4097 transportDepth testRaw = some testBytes', 1),
        )
        for changed in variants:
            self.assertNotEqual(changed, self.small.source)
            manifest = self.small.manifest
            manifest['source_sha256'] = sha256(changed.encode()).hexdigest()
            with self.subTest(hash=manifest['source_sha256']), self.assertRaises(ValueError):
                self.verify(source=changed, manifest=manifest)

    def test_rehashed_unsupported_commands_and_namespace_changes_are_rejected(self):
        for command in ('#eval 1', 'axiom trusted : False', 'set_option maxRecDepth 100000',
                        'namespace Shadow', 'unsafe def nativeHook : Nat := 1'):
            source = self.small.source.replace('namespace HiaCoreSyntaxSlice.Test\n',
                                                'namespace HiaCoreSyntaxSlice.Test\n' + command + '\n', 1)
            manifest = self.small.manifest
            manifest['source_sha256'] = sha256(source.encode()).hexdigest()
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.verify(source=source, manifest=manifest)


class StructuredStagedAdmissionMockTests(unittest.TestCase):
    """Runner mocks test gating only; they do not establish any Lean theorem."""
    @classmethod
    def setUpClass(cls):
        from tools import core_syntax_structured_stages
        cls.prepared = core_syntax_structured_stages.build_inputs()

    def exercise(self, omit_auxiliary=False):
        from contextlib import redirect_stdout
        from io import StringIO
        from pathlib import Path
        import tempfile
        from tools import check_core_syntax_staged as runner
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executable = root / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'nonexecutable mock only')
            (root / 'pinned/lib/lean').mkdir(parents=True)
            identity = {'mock-source': 'a' * 64}
            support = {'lib/lean/Init.olean': 'b' * 64,
                       'lib/lean/Lean/Elab/Tactic/Omega.olean': 'c' * 64}
            calls = []
            omitted = []

            def invoke(exe, source, output, module_root):
                stage = next(s for s in self.prepared['stages'] if s.name == source.stem)
                calls.append(stage.name)
                self.assertEqual(source.read_text(), stage.source)
                inventory = sorted(stage.expected_theorems)
                if omit_auxiliary and stage.name == 'LinearTransport':
                    main = {'HiaCoreSyntaxSlice.linear_' + ending for ending in
                            ('bounds', 'serialized', 'parsed', 'length', 'byte_range', 'transport')}
                    auxiliary = next(name for name in inventory if name not in main)
                    inventory.remove(auxiliary)
                    omitted.append(auxiliary)
                output.write_bytes(b'NOT A REAL OLEAN; ' + stage.name.encode())
                return {'returncode': 0, 'timed_out': False, 'incomplete': False,
                        'output_truncated': False, 'stderr': '',
                        'stdout': '\n'.join("'" + name + "' does not depend on any axioms" for name in inventory)}

            report = runner.execute_plan(executable, root / 'out', self.prepared, identity, support,
                                         lambda: identity, lambda exe: support,
                                         sha256(executable.read_bytes()).hexdigest(), run_process=invoke)
            self.assertEqual(report['authority'], 'DENY_ALL')
            self.assertEqual(len(report['obligations']), 12)
            self.assertTrue(all(item['status'] == 'unproved' for item in report['obligations']))
            for key in ('actual_core_bridge_proved', 'python_exporter_refinement_proved',
                        'body_prefix_refinement_proved', 'all_edge_transfer_proved',
                        'initialization_elision_authorized', 'native_admission',
                        'production_admission', 'performance_qualified', 'quota_equivalence'):
                self.assertIs(report[key], False)
            result = root / 'out/RESULT.json'
            self.assertEqual(json.loads(result.read_text()), report)
            self.assertLessEqual(result.stat().st_size, runner.MAX_DIAGNOSTIC)
            printed = StringIO()
            with redirect_stdout(printed):
                runner.print_diagnostics(root / 'out')
            self.assertIn('RESULT.json', printed.getvalue())
            self.assertNotIn('NOT A REAL OLEAN', printed.getvalue())
            return report, calls, omitted

    def test_complete_mocked_structured_dag_and_bounded_diagnostics(self):
        report, calls, omitted = self.exercise()
        self.assertEqual(report['status'], 'passed', report.get('error'))
        self.assertTrue(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls, [stage.name for stage in self.prepared['stages']])
        self.assertEqual(report['invocations'], 10)
        self.assertEqual(omitted, [])
        self.assertEqual(len(report['theorems']), 66)
        self.assertEqual(len(report['rejection_certificates']), 10)
        self.assertLessEqual(self.prepared['manifest']['proof_input_bytes'], 8 * 1024 * 1024)

    def test_missing_auxiliary_blocks_first_transport_and_every_successor(self):
        report, calls, omitted = self.exercise(omit_auxiliary=True)
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls, ['Baseline', 'SyntaxData', 'LinearTransport'])
        self.assertEqual(len(omitted), 1)
        self.assertEqual(report['stages'][-1]['status'], 'failed')

    def test_rehashed_wrapper_cannot_omit_auxiliary_from_printed_inventory(self):
        from dataclasses import replace
        from tools import check_core_syntax_staged as runner
        prepared = dict(self.prepared)
        stages = list(prepared['stages'])
        index = next(i for i, stage in enumerate(stages) if stage.name == 'LinearTransport')
        stage = stages[index]
        auxiliary = 'HiaCoreSyntaxSlice.linear_s1'
        self.assertIn(auxiliary, stage.expected_theorems)
        printed = '#print axioms ' + auxiliary + '\n'
        self.assertEqual(stage.source.count(printed), 1)
        stages[index] = replace(stage, source=stage.source.replace(printed, '', 1),
                                expected_theorems=stage.expected_theorems - {auxiliary})
        manifest = deepcopy(prepared['manifest'])
        manifest['stages'] = [item.manifest() for item in stages]
        manifest['proof_input_bytes'] = sum(item.source_bytes for item in stages)
        encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':'))
        prepared.update(stages=tuple(stages), sources={item.module_name: item.source for item in stages},
                        manifest=manifest, manifest_json=encoded,
                        manifest_sha256=sha256(encoded.encode()).hexdigest())
        # All outer metadata is consistent; the unchanged inner proof inventory
        # must still require this auxiliary's axiom check.
        self.assertEqual(prepared['structured_certificates'], self.prepared['structured_certificates'])
        self.assertEqual(manifest['structured_certificates'], self.prepared['manifest']['structured_certificates'])
        self.assertEqual(manifest['stages'], [item.manifest() for item in prepared['stages']])
        self.assertEqual(manifest['proof_input_bytes'], self.prepared['manifest']['proof_input_bytes'] - len(printed.encode()))
        with self.assertRaisesRegex(ValueError, 'complete structured theorem inventory differs'):
            runner.validate_plan(prepared)

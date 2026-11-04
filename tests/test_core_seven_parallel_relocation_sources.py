"""Source-only relocation roundtrip and adversaries; never launch Lean."""
from dataclasses import replace
from functools import lru_cache
import time
import unittest
from unittest.mock import patch

from tools import core_seven_parallel_relocation_sources as relocation

seven = relocation.seven


@lru_cache(maxsize=1)
def fixture():
    prepared = seven.original.build_inputs()
    previous = seven.build_sources(prepared)  # fully authenticate the cached oracle
    with patch.object(seven, 'validate_sources') as gate:
        proposal = relocation.build_sources(prepared, previous)
        assert gate.call_count == 2
        assert gate.call_args_list[0].args == (prepared, previous)
        assert gate.call_args_list[1].args == (prepared, previous)
    return prepared, previous, proposal


class ParallelRelocationSourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared, cls.previous, cls.proposal = fixture()

    def change(self, *, index=None, source=None, stages=None, manifest=None):
        stages = list(self.proposal.stages if stages is None else stages)
        if index is not None:
            stages[index] = replace(stages[index], source=source)
        return replace(self.proposal, stages=tuple(stages),
                       manifest_json=relocation.encode(self.proposal.manifest if manifest is None else manifest))

    def render(self, changes):
        stages = list(self.proposal.stages)
        for index, rows in changes.items():
            stages[index] = relocation._render_stage(stages[index], rows)
        return self.change(stages=stages)

    def rehash(self, proposal):
        return replace(proposal, manifest_json=relocation.encode(relocation._manifest(
            self.prepared, self.previous, proposal.stages)))

    def reject(self, proposal, calls=1):
        # Only the old expensive gate is mocked. All candidate checks are real.
        with patch.object(seven, 'validate_sources') as gate:
            with self.assertRaises((ValueError, TypeError, KeyError, IndexError, StopIteration)):
                relocation.validate_sources(self.prepared, self.previous, proposal)
            self.assertEqual(gate.call_count, calls)
            if calls:
                self.assertEqual(gate.call_args_list[0].args, (self.prepared, self.previous))
            if calls == 2:
                self.assertEqual(gate.call_args_list[1].args, (self.prepared, self.previous))

    def test_authentic_unmocked_roundtrip_and_closed_gates(self):
        start = time.monotonic()
        result = relocation.validate_sources(self.prepared, self.previous, self.proposal)
        print('\nAuthentic relocation roundtrip seconds: %.3f' % (time.monotonic() - start))
        self.assertEqual(result['authority'], 'DENY_ALL')
        self.assertFalse(result['acceptance_eligible'])
        self.assertEqual(result['stage_counts'], relocation.COUNTS)
        self.assertEqual(relocation._recover(self.previous, self.proposal.stages), self.previous)
        manifest = self.proposal.manifest
        self.assertEqual(len(manifest['obligations']), 12)
        self.assertTrue(all(x['status'] == 'unproved' for x in manifest['obligations']))
        self.assertTrue(all(manifest[k] == v for k, v in seven.facts.DENY.items()))
        self.assertFalse(manifest['timing_measured'])
        self.assertTrue(manifest['source_only'])
        self.assertEqual(manifest['moved_raw_bytes'], 100165)
        self.assertEqual(len(self.proposal.retained_sources), 22)
        self.assertEqual(result['retained_source_bytes'], sum(len(s.encode()) for s in self.proposal.retained_sources.values()))
        self.assertLessEqual(result['manifest_bytes'], relocation.MAX_MANIFEST)

    def test_both_mandatory_old_gates_and_actual_reconstruction(self):
        with patch.object(seven, 'validate_sources') as gate:
            relocation.validate_sources(self.prepared, self.previous, self.proposal)
            self.assertEqual(gate.call_count, 2)
            first, second = [c.args[1] for c in gate.call_args_list]
            self.assertIs(first, self.previous)
            self.assertIsNot(second, self.previous)
            self.assertEqual(second, self.previous)
            self.assertIs(gate.call_args_list[1].args[0], self.prepared)

    def test_old_gate_failure_propagates(self):
        with patch.object(seven, 'validate_sources', side_effect=ValueError('old gate failed')) as gate:
            with self.assertRaisesRegex(ValueError, 'old gate failed'):
                relocation.validate_sources(self.prepared, self.previous, self.proposal)
            gate.assert_called_once_with(self.prepared, self.previous)
        with patch.object(seven, 'validate_sources', side_effect=[None, ValueError('recovered gate failed')]) as gate:
            with self.assertRaisesRegex(ValueError, 'recovered gate failed'):
                relocation.validate_sources(self.prepared, self.previous, self.proposal)
            self.assertEqual(gate.call_count, 2)

    def test_490_and_492_moved(self):
        left = seven.original._parse(self.previous.stages[4].source)[1]
        right = seven.original._parse(self.previous.stages[5].source)[1]
        start = next(i for i, r in enumerate(right) if seven._aux(r))
        for count in (490, 492):
            with self.subTest(count=count):
                self.reject(self.rehash(self.render({4: left + right[start:start + count],
                    5: right[:start] + right[start + count:]})))

    def test_move_0491_instead_of_0490(self):
        left = seven.original._parse(self.proposal.stages[4].source)[1]
        right = list(seven.original._parse(self.proposal.stages[5].source)[1])
        start = next(i for i, r in enumerate(right) if seven._aux(r))
        moved = right[start]
        right[start] = left[-1]
        self.reject(self.rehash(self.render({4: left[:-1] + (moved,), 5: tuple(right)})))

    def test_swap_moved_facts(self):
        left = list(seven.original._parse(self.proposal.stages[4].source)[1])
        left[-491], left[-490] = left[-490], left[-491]
        self.reject(self.rehash(self.render({4: tuple(left)})))

    def test_foreign_auxiliary(self):
        left = list(seven.original._parse(self.proposal.stages[4].source)[1])
        right = list(seven.original._parse(self.proposal.stages[6].source)[1])
        index = next(i for i, r in enumerate(right) if seven._aux(r))
        left[-1], right[index] = right[index], left[-1]
        self.reject(self.rehash(self.render({4: tuple(left), 6: tuple(right)})))

    def test_proof_mutation_with_all_source_hashes_recomputed(self):
        source = self.proposal.stages[4].source
        # Equal-length mutation cannot be rejected merely by moved byte count.
        row = seven.original._parse(source)[1][-1]
        changed = row[3].decode().replace('by ', 'by\t', 1)
        self.assertNotEqual(changed, row[3].decode())
        proposal = self.change(index=4, source=source.replace(row[3].decode(), changed, 1))
        self.reject(self.rehash(proposal))

    def test_anchor_wrong_or_not_immediately_before(self):
        left = list(seven.original._parse(self.proposal.stages[4].source)[1])
        left[-492], left[-493] = left[-493], left[-492]
        self.reject(self.rehash(self.render({4: tuple(left)})))
        source = self.proposal.stages[4].source.replace('parallel_pl113_0', 'parallel_pl113_X')
        self.reject(self.change(index=4, source=source))

    def test_extra_and_changed_imports(self):
        for index in (4, 5, 10):
            source = self.proposal.stages[index].source
            self.reject(self.change(index=index, source='import Init\n' + source))
            wrong = source.replace(self.proposal.stages[index].parents[0], seven.original.PREFIX + '.Baseline', 1)
            self.reject(self.change(index=index, source=wrong))

    def test_actual_metadata_forgery(self):
        for index in (4, 5):
            for field, value in (
                ('name', 'Forged'), ('module_name', 'Forged.Module'),
                ('parents', (seven.original.PREFIX + '.Baseline',)),
                ('explicit_imports', ('Init',)), ('direct_imports', ('Init',)),
                ('rejection_names', ('invented',)), ('expected_theorems', frozenset({'Forged.theorem'}))):
                with self.subTest(index=index, field=field):
                    stages = list(self.proposal.stages)
                    stages[index] = replace(stages[index], **{field: value})
                    self.reject(self.rehash(self.change(stages=stages)))

    def test_print_missing_duplicate_reordered_or_foreign(self):
        for index in (4, 5):
            source = self.proposal.stages[index].source
            lines = [line + '\n' for line in source.splitlines() if line.startswith('#print axioms ')]
            for old, new in ((lines[0], ''), (lines[0], lines[0] * 2),
                             (lines[0] + lines[1], lines[1] + lines[0]),
                             (lines[0], '#print axioms Forged.subject\n')):
                with self.subTest(index=index, new=new[:80]):
                    self.reject(self.rehash(self.change(index=index, source=source.replace(old, new, 1))))

    def test_namespace_and_nine_unchanged_sources(self):
        source = self.proposal.stages[4].source.replace('namespace HiaCoreSyntaxSlice\n',
                    'namespace HiaCoreSyntaxSlice\nnamespace Forged\n', 1)
        self.reject(self.change(index=4, source=source))
        for index in (0, 1, 2, 3, 6, 7, 8, 9, 10):
            with self.subTest(index=index):
                self.reject(self.change(index=index, source=self.proposal.stages[index].source + '\n'))

    def test_original_stage_binding(self):
        originals = list(self.proposal.original_stages)
        originals[4] = replace(originals[4], source=originals[4].source + '\n')
        self.reject(replace(self.proposal, original_stages=tuple(originals)), calls=0)

    def test_manifest_input_commitment_and_prior_manifest(self):
        for field in ('inputs_sha256', 'original_manifest_sha256', 'previous_seven_manifest_sha256', 'moved_raw_sha256'):
            manifest = self.proposal.manifest
            manifest[field] = '0' * 64
            self.reject(self.change(manifest=manifest), calls=2)

    def test_each_input_byte_is_reauthenticated_by_old_gate(self):
        # No mocks: each changed binding must fail the mandatory supplied-old gate.
        for key in self.prepared['binding_inputs']:
            with self.subTest(input=key):
                bindings = {k: dict(v) for k, v in self.prepared['binding_inputs'].items()}
                raw = bytes(bindings[key]['bytes'])
                bindings[key]['bytes'] = bytes([raw[0] ^ 1]) + raw[1:]
                with self.assertRaises(ValueError):
                    relocation.validate_sources(dict(self.prepared, binding_inputs=bindings), self.previous, self.proposal)

    def test_manifest_strict_bool_integer_and_float_types(self):
        for key, value in (('moved_count', True), ('moved_count', 491.0),
                           ('retained_execution_copies', False), ('source_only', 1),
                           ('acceptance_eligible', 0), ('remaining_auxiliaries', 104.0),
                           ('protocol', seven.PROTOCOL), ('schema', seven.SCHEMA)):
            manifest = self.proposal.manifest
            manifest[key] = value
            self.reject(self.change(manifest=manifest), calls=2)
        manifest = self.proposal.manifest
        manifest['stage_counts'][-1] = True
        self.reject(self.change(manifest=manifest), calls=2)

    def test_manifest_overflow_and_noncanonical_serialization(self):
        self.reject(replace(self.proposal, manifest_json=' ' * (relocation.MAX_MANIFEST + 1)), calls=0)
        self.reject(replace(self.proposal, manifest_json=self.proposal.manifest_json + '\n'), calls=2)

    def test_retention_caps_all_extra_copies(self):
        base = relocation.validate_retention(self.proposal)
        self.assertEqual(relocation.validate_retention(self.proposal, ('-- marker\n',)), base + 10)
        for extra in ((self.proposal.stages[4].source,) * 8,
                      tuple(s.source for s in self.previous.stages),
                      ('x' * (relocation.MAX_SOURCE + 1),), ['not a tuple']):
            with self.assertRaises(ValueError):
                relocation.validate_retention(self.proposal, extra)
        with patch.object(seven, 'validate_sources') as gate:
            with self.assertRaises(ValueError):
                relocation.validate_sources(self.prepared, self.previous, self.proposal,
                    tuple(s.source for s in self.previous.stages))
            gate.assert_called_once_with(self.prepared, self.previous)

    def test_old_typed_apis_reject_new_candidate(self):
        from tools import core_seven_certificate_diagnostic_sources as diagnostic
        from tools import core_seven_part04_diagnostic_sources as part04
        # These existing APIs run their real full gate, including the type guard.
        for invoke in (seven.validate_sources, diagnostic.build_diagnostic_sources,
                       part04.build_diagnostic_sources):
            with self.assertRaisesRegex(ValueError, 'distinct seven-certificate type'):
                invoke(self.prepared, self.proposal)
        self.reject(self.previous, calls=0)

    def test_acceptance_reconstruction_rejects_candidate_protocol(self):
        from tools import core_seven_acceptance_plan as acceptance
        data = {'original/' + s.name + '.lean': s.source.encode()
                for s in self.prepared['stages']}
        data.update({s.module_name.replace('.', '/') + '.lean': s.source.encode()
                     for s in self.proposal.stages})
        data['seven-manifest.json'] = self.proposal.manifest_json.encode()

        class ReadOnlySnapshot:
            def read(self, name):
                return data[name]

        # Cache only preparation, never the actual admission check. No runner,
        # subprocess, filesystem mutation or Lean invocation is involved.
        with patch.object(acceptance, 'prepare', return_value=(self.prepared, self.previous)) as prepare:
            with patch.object(seven, 'validate_sources', wraps=seven.validate_sources) as gate:
                with self.assertRaisesRegex(ValueError, 'distinct source-only schema and protocol'):
                    acceptance.reconstruct(ReadOnlySnapshot())
                prepare.assert_called_once_with()
                gate.assert_called_once()
                actual = gate.call_args.args[1]
                self.assertEqual(actual.manifest_json, self.proposal.manifest_json)
                self.assertEqual(actual.stages[4].source, self.proposal.stages[4].source)

    def test_forward_candidate_dependency(self):
        source = self.proposal.stages[4].source
        rows = seven.original._parse(source)[1]
        row = rows[-491]
        changed = row[3].decode().replace(' := ', ' := parallel_bf0490 ', 1)
        self.reject(self.rehash(self.change(index=4, source=source.replace(row[3].decode(), changed, 1))))

    def test_duplicate_moved_fact(self):
        rows = list(seven.original._parse(self.proposal.stages[4].source)[1])
        rows[-1] = rows[-2]
        self.reject(self.rehash(self.render({4: tuple(rows)})))


if __name__ == '__main__':
    unittest.main()

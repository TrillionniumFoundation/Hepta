"""Source-only inverse/ownership adversaries. No Lean or acceptance execution."""
from dataclasses import replace
from functools import lru_cache
import unittest
from unittest.mock import patch

from tools import core_seven_certificate_sources as seven


@lru_cache(maxsize=1)
def fixture():
    prepared = seven.original.build_inputs()
    return prepared, seven.build_sources(prepared)


class SevenCertificateSourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared, cls.proposal = fixture()

    def changed(self, index=None, source=None, manifest=None, stages=None):
        stages = list(self.proposal.stages if stages is None else stages)
        if index is not None:
            stages[index] = replace(stages[index], source=source)
        return replace(self.proposal, stages=tuple(stages),
                       manifest_json=seven.encode(self.proposal.manifest if manifest is None else manifest))

    def validate(self, proposal):
        # Fixture oracle is unchanged and fully authenticated at construction.
        # Keep complete byte-fact insertion/inverse checks on every candidate.
        def authenticated(value):
            self.assertIs(value, self.prepared)
        with patch.object(seven.facts, '_original', side_effect=authenticated):
            return seven.validate_sources(self.prepared, proposal)

    def reject(self, proposal):
        with self.assertRaises((ValueError, TypeError, KeyError, IndexError)):
            self.validate(proposal)

    def test_real_full_validation_and_closed_gates(self):
        result = seven.validate_sources(self.prepared, self.proposal)
        self.assertEqual(result['authority'], 'DENY_ALL')
        self.assertFalse(result['acceptance_eligible'])
        self.assertEqual(result['stage_counts'], seven.COUNTS)
        m = self.proposal.manifest
        self.assertEqual(m['original_source_bytes'], 2400382)
        self.assertEqual(len(m['obligations']), 12)
        self.assertTrue(all(x['status'] == 'unproved' for x in m['obligations']))
        self.assertEqual(len(m['expected_targets']), 66)
        self.assertEqual(len(m['historical_negatives']), 10)
        self.assertFalse(m['timing_measured'])
        self.assertLessEqual(result['manifest_bytes'], 32768)
        self.assertEqual(result['retained_source_bytes'], sum(len(s.encode()) for s in self.proposal.retained_sources.values()))
        self.assertEqual(len(self.proposal.retained_sources), 22)

    def test_full_inverse_exact_eleven_and_old_inverse(self):
        recovered = seven.invert_sources(self.prepared, self.proposal)
        old = seven.facts._derive(self.prepared)
        self.assertEqual(recovered, old.stages)
        for source, original in zip(recovered, self.prepared['stages']):
            self.assertEqual(seven.facts.inverse_source(source.source, original.source,
                             old.manifest['edits'][original.name]), original.source.encode())
        self.assertEqual(self.proposal.manifest['historical_negatives'], self.prepared['negatives'])

    def test_existing_validators_are_invoked(self):
        with patch.object(seven.facts, 'validate_sources', wraps=seven.facts.validate_sources) as validator:
            self.validate(self.proposal)
            validator.assert_called_once()

    def test_changed_declaration_rehashed_manifest(self):
        stage = self.proposal.stages[2]
        source = stage.source.replace(' := ', ' :=  ', 1)
        changed = self.changed(2, source)
        manifest = changed.manifest
        manifest['stages'][2] = seven.facts._compact(changed.stages[2])
        self.reject(self.changed(stages=changed.stages, manifest=manifest))

    def test_missing_declaration(self):
        source = self.proposal.stages[2].source
        _, rows, _ = seven.original._parse(source)
        self.reject(self.changed(2, source.replace(rows[0][3].decode(), '', 1)))

    def test_duplicate_declaration(self):
        source = self.proposal.stages[2].source
        _, rows, _ = seven.original._parse(source)
        self.reject(self.changed(2, source.replace(rows[0][3].decode(), rows[0][3].decode() * 2, 1)))

    def test_same_name_wrong_owner(self):
        stage = self.proposal.stages[2]
        source = stage.source.replace('namespace HiaCoreSyntaxSlice\n', 'namespace Impostor\n').replace(
            'end HiaCoreSyntaxSlice\n', 'end Impostor\n').replace('#print axioms HiaCoreSyntaxSlice.', '#print axioms Impostor.')
        self.reject(self.changed(2, source))

    def test_shifted_cut_with_consistent_prints(self):
        stages = list(self.proposal.stages)
        a = seven.original._parse(stages[2].source)[1]
        b = seven.original._parse(stages[3].source)[1]
        for index, rows in ((2, a[:-1]), (3, a[-1:] + b)):
            source, names = seven._render(rows, stages[index].parents[0])
            stages[index] = replace(stages[index], source=source, expected_theorems=names)
        self.reject(self.changed(stages=stages))

    def test_forward_reference(self):
        stage = self.proposal.stages[2]
        rows = seven.original._parse(stage.source)[1]
        later = rows[-1][2]
        source = stage.source.replace(rows[0][3].decode(), rows[0][3].decode().replace(' := ', ' := ' + later + ' ', 1), 1)
        self.reject(self.changed(2, source))

    def test_split_proof_and_namespace(self):
        stage = self.proposal.stages[2]
        self.reject(self.changed(2, stage.source.replace('namespace HiaCoreSyntaxSlice\n',
                         'namespace HiaCoreSyntaxSlice\nnamespace Extra\n', 1)))

    def test_missing_or_duplicate_print(self):
        source = self.proposal.stages[9].source
        line = next(x + '\n' for x in source.splitlines() if x.startswith('#print axioms '))
        for replacement in ('', line + line):
            with self.subTest(replacement=replacement):
                self.reject(self.changed(9, source.replace(line, replacement, 1)))

    def test_faulty_renderer_cannot_substitute_print_subject(self):
        render = seven._render
        def faulty(rows, parent):
            source, names = render(rows, parent)
            subject = seven._prints(source)[0]
            return source.replace('#print axioms ' + subject + '\n', '#print axioms Forged.subject\n', 1), names
        with patch.object(seven, '_render', side_effect=faulty):
            previous = seven.facts._derive(self.prepared)
            stages = seven._derive_stages(previous.stages)
            # Do not rely on emitter metadata generation to reject the attack.
            self.reject(self.changed(stages=stages))

    def test_original_contextual_print_subjects(self):
        stage = self.proposal.stages[0]
        self.assertNotEqual(frozenset(seven._prints(stage.source)), stage.expected_theorems)
        self.assertEqual(frozenset(seven._qualified_prints(stage.source)), stage.expected_theorems)

    def test_same_size_inventory_forgery(self):
        stages = list(self.proposal.stages)
        stage = stages[2]
        wrong = set(stage.expected_theorems)
        wrong.remove(sorted(wrong)[0])
        wrong.add('Forged.subject')
        stages[2] = replace(stage, expected_theorems=frozenset(wrong))
        candidate = self.changed(stages=stages, manifest=seven._manifest(
            self.prepared, tuple(stages), self.proposal.manifest['previous_transform_manifest_sha256']))
        with patch.object(seven, '_derive_stages', return_value=tuple(stages)):
            self.reject(candidate)

    def test_imported_support_prints_preserved(self):
        old = self.prepared['stages'][8]
        own = seven._declared(old.source)
        imported = set(seven._prints(old.source)) - own
        self.assertTrue(imported)
        source = self.proposal.stages[9].source
        for name in imported:
            self.assertIn('#print axioms ' + name + '\n', source)
        name = sorted(imported)[0]
        self.reject(self.changed(9, source.replace('#print axioms ' + name + '\n', '', 1)))

    def test_relocated_consumer_print(self):
        source = self.proposal.stages[9].source
        line = next(x + '\n' for x in source.splitlines() if x.startswith('#print axioms '))
        self.reject(self.changed(9, source.replace(line, '', 1) + line))

    def test_consumer_frame_forgery(self):
        self.reject(self.changed(9, self.proposal.stages[9].source.replace(seven.REJECTION_FRAME, '', 1)))

    def test_wrongarm_isolation_and_intentional_duplicate(self):
        a = seven._declared(self.proposal.stages[9].source)
        b = seven._declared(self.proposal.stages[10].source)
        self.assertTrue(a & b)  # intentional duplicate in disjoint environments
        stage = self.proposal.stages[10]
        source = stage.source.replace('.CertPart04\n', '.ConnectionsTransportRejections\n', 1)
        self.reject(self.changed(10, source))

    def test_faulty_emitter_cannot_authorize_wrong_parent(self):
        stages = list(self.proposal.stages)
        stage = stages[4]
        wrong = seven.original.PREFIX + '.Baseline'
        stages[4] = replace(stage, source=stage.source.replace(stage.parents[0], wrong, 1),
                            parents=(wrong,), explicit_imports=(wrong,), direct_imports=('Init', wrong))
        candidate = self.changed(stages=stages, manifest=seven._manifest(
            self.prepared, tuple(stages), self.proposal.manifest['previous_transform_manifest_sha256']))
        with patch.object(seven, '_derive_stages', return_value=tuple(stages)):
            self.reject(candidate)

    def test_parent_metadata_cannot_hide_import(self):
        stages = list(self.proposal.stages)
        stages[3] = replace(stages[3], parents=(stages[4].module_name,))
        self.reject(self.changed(stages=stages))

    def test_helper_and_root_substitution_unchanged(self):
        for index, old, new in ((1, 'def facts ', 'def factsX '), (4, 'by exact (linear_bf0594).2', 'by decide +kernel')):
            source = self.proposal.stages[index].source
            self.assertIn(old, source)
            self.reject(self.changed(index, source.replace(old, new, 1)))

    def test_negative_current_coordinate_and_historical_are_bound(self):
        for field in ('negative_declaration_locations', 'historical_negatives'):
            manifest = self.proposal.manifest
            manifest[field].pop(next(iter(manifest[field])))
            self.reject(self.changed(manifest=manifest))

    def test_distinct_schema_and_integer_types(self):
        for field, value in (('protocol', seven.original.PROTOCOL), ('schema', seven.facts.PROTOCOL),
                             ('cuts', [True] + list(seven.CUTS[1:])), ('cuts', list(seven.CUTS[:-1]) + [4215.0])):
            manifest = self.proposal.manifest
            manifest[field] = value
            self.reject(self.changed(manifest=manifest))

    def test_manifest_scalar_types_outside_cuts(self):
        for section, key in (('framing', 'syntax_prefix_start'), ('negative_declaration_locations', None)):
            manifest = self.proposal.manifest
            target = manifest[section]
            if key is None:
                target = target[next(iter(target))]
                key = 'line'
            target[key] = float(target[key])
            self.reject(self.changed(manifest=manifest))
        manifest = self.proposal.manifest
        manifest['retained_execution_copies'] = False
        self.reject(self.changed(manifest=manifest))

    def test_each_full_input_binding_is_revalidated(self):
        for key in self.prepared['binding_inputs']:
            with self.subTest(input=key):
                bindings = {k: dict(v) for k, v in self.prepared['binding_inputs'].items()}
                raw = bytes(bindings[key]['bytes'])
                bindings[key]['bytes'] = bytes([raw[0] ^ 1]) + raw[1:]
                changed = dict(self.prepared, binding_inputs=bindings)
                with self.assertRaises(ValueError):
                    seven.validate_sources(changed, self.proposal)

    def test_manifest_overflow(self):
        self.reject(replace(self.proposal, manifest_json=' ' * 32769))

    def test_retained_third_generation_rejected(self):
        old = seven.facts._derive(self.prepared)
        with self.assertRaises(ValueError):
            seven.validate_retention(self.proposal, tuple(s.source for s in old.stages))

    def test_all_marker_execution_and_evidence_copies_count(self):
        self.assertEqual(seven.validate_retention(self.proposal, ('-- marker\n',)),
                         seven.validate_retention(self.proposal) + len('-- marker\n'))
        source = self.proposal.stages[4].source
        with self.assertRaises(ValueError):
            seven.validate_retention(self.proposal, (source,) * 8)
        with self.assertRaises(ValueError):
            seven.validate_retention(self.proposal, ('x' * (seven.MAX_SOURCE + 1),))

    def test_fact_root_group_fragmentation(self):
        stages = list(self.proposal.stages)
        left = seven.original._parse(stages[3].source)[1]
        right = seven.original._parse(stages[4].source)[1]
        fact = next(r for r in right if seven._aux(r))
        for index, rows in ((3, left + (fact,)), (4, tuple(r for r in right if r is not fact))):
            source, names = seven._render(rows, stages[index].parents[0])
            stages[index] = replace(stages[index], source=source, expected_theorems=names)
        self.reject(self.changed(stages=stages))

    def test_old_admission_plan_rejects_new_protocol(self):
        from tools.check_core_syntax_staged import validate_plan
        forged = dict(self.prepared, stages=self.proposal.stages, manifest=self.proposal.manifest,
                      manifest_json=self.proposal.manifest_json, manifest_sha256=self.proposal.manifest_sha256,
                      sources=self.proposal.sources)
        with self.assertRaises(ValueError):
            validate_plan(forged)

    def test_old_type_not_retargeted(self):
        with self.assertRaises(ValueError):
            self.validate(seven.facts.ByteFactsSources(self.proposal.original_stages,
                                                      self.proposal.stages, self.proposal.manifest_json))


if __name__ == '__main__':
    unittest.main()

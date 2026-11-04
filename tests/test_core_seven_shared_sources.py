"""Real full-input proof-edit inverse and hostile candidate mutations."""
from dataclasses import replace
from collections import Counter
import unittest
from tools import core_seven_shared_sources as s


class SharedSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = s.seven.original.build_inputs()
        cls.previous = s.seven.build_sources(cls.prepared)
        cls.proposal = s.build_sources(cls.prepared, cls.previous)

    def reject(self, proposal):
        with self.assertRaises(ValueError):
            s.validate_sources(self.prepared, self.previous, proposal)

    def change(self, index, edit):
        stages = list(self.proposal.stages)
        stages[index] = replace(stages[index], source=edit(stages[index].source))
        return replace(self.proposal, stages=tuple(stages))

    def test_full_actual_source_inverse_and_unchanged_original_subjects(self):
        p = self.proposal
        old = s.nocode._relocated(self.prepared, self.previous)
        self.assertEqual(tuple(len(x.expected_theorems) for x in p.stages), s.COUNTS)
        prior_subjects = frozenset().union(*(x.expected_theorems for x in old.stages))
        actual_subjects = frozenset().union(*(x.expected_theorems for x in p.stages))
        self.assertEqual(actual_subjects, prior_subjects | s.HELPER_NAMES)
        # The authenticated old schedule intentionally prints 61 subjects in
        # more than one module. Preserve their multiplicities as well as names.
        self.assertEqual(Counter(n for x in p.stages for n in x.expected_theorems),
                         Counter(n for x in old.stages for n in x.expected_theorems) +
                         Counter(s.HELPER_NAMES))
        self.assertEqual(s.COUNTS[:4], (101, 256, 290, 291))
        for before, after in zip(old.stages, p.stages):
            self.assertEqual(before.rejection_names, after.rejection_names)
            self.assertEqual(before.direct_imports, after.direct_imports)
        self.assertEqual(p.original_stages, self.prepared['stages'])
        self.assertEqual(p.manifest['helper_names'], sorted(s.HELPER_NAMES))
        self.assertEqual(p.manifest['prefix_cuts'], [256, 546, 837])
        self.assertEqual(len(p.manifest['generic_relocation']['subjects']), 45)
        self.assertGreater(p.manifest['proof_changes'], 28)
        self.assertTrue(all(n > 0 for n in p.manifest['literal_proof_reuses'].values()))
        self.assertLess(p.manifest['retained_source_bytes'], s.MAX_TOTAL_SOURCE)
        self.assertFalse(p.manifest['acceptance_eligible'])
        self.assertFalse(p.manifest['kernel_core_syntax_connection_checked'])

    def test_statement_cannot_be_weakened(self):
        self.reject(self.change(3, lambda x: x.replace('serializeFields 4085 29', 'serializeFields 4084 29', 1)))

    def test_child_certificate_cannot_be_substituted(self):
        self.reject(self.change(3, lambda x: x.replace('linear_s154)', 'linear_s153)', 1)))

    def test_shared_proof_body_cannot_be_changed(self):
        self.reject(self.change(3, lambda x: x.replace('Shared.parse_fields_last_packet',
                                                    'Shared.parse_fields_cons_packet', 1)))

    def test_data_and_nocode_headers_still_exact(self):
        self.reject(self.change(3, lambda x: x.replace('noncomputable def ', 'def ', 1)))
        self.reject(self.change(3, lambda x: x.replace('[98,108,111,99,107,115]', '[98,108,111,99,107,116]', 1)))

    def test_helper_tampering_and_hidden_axiom_rejected(self):
        self.reject(self.change(0, lambda x: x.replace('namespace HiaCoreSyntaxSlice.Shared',
                             'namespace HiaCoreSyntaxSlice.Shared\naxiom forged : False', 1)))

    def test_original_subject_or_new_helper_cannot_be_omitted(self):
        for index, subject in ((0, 'HiaCoreSyntaxSlice.Shared.parse_root'),
                               (1, next(iter(self.proposal.stages[1].expected_theorems)))):
            stages = list(self.proposal.stages)
            stages[index] = replace(stages[index], expected_theorems=stages[index].expected_theorems - {subject})
            self.reject(replace(self.proposal, stages=tuple(stages)))

    def test_generic_layer_and_repartition_cannot_hide_changes(self):
        self.reject(self.change(0, lambda x: x.replace(s.GENERIC_FRAME, '', 1)))
        self.reject(self.change(0, lambda x: x.replace('def parseRaw', 'def changedRaw', 1)))
        self.reject(self.change(1, lambda x: x.replace(s.seven.PREFIX_FRAME,
                    '#print axioms HiaCoreSyntaxSlice.Shared.parse_root\n' + s.seven.PREFIX_FRAME, 1)))
        manifest = self.proposal.manifest
        manifest['prefix_cuts'] = [255, 546, 837]
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))

    def test_literal_proof_reference_cannot_be_forged(self):
        changes = s._context(self.prepared, self.previous)[4]
        name, (_, raw) = next((name, pair) for name, pair in changes.items()
                              if s._literal_family(name.rsplit('.', 1)[1]) == 'byte_facts')
        old = raw.decode()
        _, proof = s._body(raw)
        forged = old.replace(proof, 'by\n  exact HiaCoreSyntaxSlice.Shared.parse_root\n')
        index = next(i for i, stage in enumerate(self.proposal.stages) if old in stage.source)
        self.reject(self.change(index, lambda text: text.replace(old, forged, 1)))
        manifest = self.proposal.manifest
        manifest['literal_proof_reuses']['byte_facts'] = 0
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))

    def test_manifest_cannot_authorize_or_hide_edits(self):
        for key, value in (('acceptance_eligible', True), ('proof_changes', 0),
                           ('kernel_core_syntax_connection_checked', True)):
            manifest = self.proposal.manifest
            manifest[key] = value
            self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))

    def test_unplanned_retained_copy_is_counted(self):
        with self.assertRaises(ValueError):
            s.validate_retention(self.proposal, ('x' * s.MAX_SOURCE,) * 3)


class ApplicationParserTests(unittest.TestCase):
    def test_nested_certificate_arguments_preserved(self):
        self.assertEqual(s._arguments('f (g x (h y)) [1, 2] z'), ['f', '(g x (h y))', '[1, 2]', 'z'])
        for malformed in ('f (x', 'f [x)', 'f x)'):
            with self.assertRaises(ValueError):
                s._arguments(malformed)


if __name__ == '__main__':
    unittest.main()

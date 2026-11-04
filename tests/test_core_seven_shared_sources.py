"""Real full-input proof-edit inverse and hostile candidate mutations."""
from dataclasses import replace
from collections import Counter
import unittest
from tools import core_seven_shared_sources as s


# Independent handwritten controls for the real linear_p6 -> linear_p151 failure.
# A diagnostic compiles these against the actual checked parent and the new
# helper. Their statements and altered closing byte do not come from the emitter.
STRING_REBASE_POSITIVE_CONTROL = '''import HiaSyntaxResearch.CertPart01
import BoundHelpers
namespace HiaCoreSyntaxSlice.AtomReuseRegression
noncomputable def bytes : List Nat := [34,100,103,95,115,104,97,114,101,100,95,48,34]
noncomputable def raw : Raw := .str [100,103,95,115,104,97,114,101,100,95,48]
theorem byte_alias : bytes = HiaCoreSyntaxSlice.linear_b6 := by rfl
theorem raw_alias : raw = HiaCoreSyntaxSlice.linear_r6 := by rfl
theorem shape : HiaCoreSyntaxSlice.linear_b6 =
    34 :: ([100,103,95,115,104,97,114,101,100,95,48] ++ [34]) := by rfl
theorem replay (tail : List Nat) : parseRaw 4087 29 (bytes ++ tail) = some (raw, tail) := by
  exact (HiaCoreSyntaxSlice.Shared.parse_string_rebase_bound 4084 26 4086 28
    HiaCoreSyntaxSlice.linear_r6 raw HiaCoreSyntaxSlice.linear_b6 bytes
    ([100,103,95,115,104,97,114,101,100,95,48] ++ [34]) shape byte_alias raw_alias
    HiaCoreSyntaxSlice.linear_p6 tail)
end HiaCoreSyntaxSlice.AtomReuseRegression
#print axioms HiaCoreSyntaxSlice.AtomReuseRegression.byte_alias
#print axioms HiaCoreSyntaxSlice.AtomReuseRegression.raw_alias
#print axioms HiaCoreSyntaxSlice.AtomReuseRegression.shape
#print axioms HiaCoreSyntaxSlice.AtomReuseRegression.replay
'''
STRING_REBASE_NEGATIVE_CONTROL = '''import HiaSyntaxResearch.CertPart01
namespace HiaCoreSyntaxSlice.AtomReuseNegative
theorem changed_closing_byte :
    ([34,100,103,95,115,104,97,114,101,100,95,48,35] : List Nat) =
      HiaCoreSyntaxSlice.linear_b6 := by rfl
end HiaCoreSyntaxSlice.AtomReuseNegative
'''


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
        self.assertEqual(s.COUNTS[:5], (102, 256, 444, 735, 1057))
        for before, after in zip(old.stages, p.stages):
            self.assertEqual(before.rejection_names, after.rejection_names)
            self.assertEqual(before.direct_imports, after.direct_imports)
        self.assertEqual(p.original_stages, self.prepared['stages'])
        self.assertEqual(p.manifest['helper_names'], sorted(s.HELPER_NAMES))
        self.assertEqual(p.manifest['prefix_cuts'], [256, 546, 837])
        self.assertEqual(len(p.manifest['generic_relocation']['subjects']), 46)
        self.assertEqual(p.manifest['part02_extension']['declaration_bytes'], 121930)
        self.assertEqual(p.manifest['part02_extension']['preceding_prefix_cuts'], [256, 700, 837])
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

    def test_fixed_extension_reconstructs_exact_v4_and_original_order(self):
        old, syntax, _, blocks, _ = s._context(self.prepared, self.previous)
        v4 = s._repartition(s._render(old, syntax, blocks, helpers=True))
        extended = s._extend_part02(v4)
        self.assertEqual(s._undo_extension(extended, v4), v4)
        old_blocks, new_blocks = s.seven._extract(v4)[1], s.seven._extract(extended)[1]
        self.assertEqual(tuple(r for b in old_blocks for r in b),
                         tuple(r for b in new_blocks for r in b))
        self.assertEqual(s._partition_checks(extended, new_blocks), 45994)
        self.assertIn('HiaCoreSyntaxSlice.linear_transport', extended[4].expected_theorems)
        self.assertNotIn('HiaCoreSyntaxSlice.linear_transport', extended[3].expected_theorems)

    def test_moved_declarations_cannot_be_dropped_duplicated_or_reassigned(self):
        source = self.proposal.stages[3].source.replace('\nnoncomputable def ', '\ndef ')
        row = s.seven.original._parse(source)[1][-1][3].decode()
        self.reject(self.change(3, lambda text: text.replace(row, '', 1)))
        self.reject(self.change(3, lambda text: text.replace(row, row + row, 1)))
        manifest = self.proposal.manifest
        manifest['part02_extension']['last'] = 'HiaCoreSyntaxSlice.linear_bf0593'
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))
        manifest = self.proposal.manifest
        manifest['part02_extension']['preceding_prefix_cuts'] = [256, 699, 837]
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))

    def test_new_boundary_checks_actual_import_and_forward_reference(self):
        self.reject(self.change(3, lambda text: text.replace('import HiaSyntaxResearch.CertPart01',
                                                          'import HiaSyntaxResearch.CertPart03', 1)))
        unmarked = tuple(replace(stage, source=stage.source.replace('\nnoncomputable def ', '\ndef '))
                         for stage in self.proposal.stages)
        syntax, blocks, _, _ = s.seven._extract(unmarked)
        changed = list(blocks[2])
        ns, kind, name, raw = changed[-1]
        header, _ = s._body(raw)
        changed[-1] = (ns, kind, name, (header + ' := by\n  exact HiaCoreSyntaxSlice.parallel_p0\n').encode())
        forged = (*blocks[:2], tuple(changed), *blocks[3:])
        with self.assertRaisesRegex(ValueError, 'forward or recursive actual transport reference'):
            s._partition_checks(unmarked, forged)

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

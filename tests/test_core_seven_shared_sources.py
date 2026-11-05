"""Real full-input proof-edit inverse and hostile candidate mutations."""
from dataclasses import replace
from collections import Counter
import unittest
from unittest.mock import patch
from tools import core_seven_shared_sources as s
from tools import core_seven_shared_acceptance_plan as plan
from tools import core_syntax_structured_sources as structured


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


# Independent closed, nested Raw/byte controls for v7 exact-bound reuse.
# The source emitter does not produce these inputs. A diagnostic compiles every
# positive and negative with the pinned Lean kernel before fresh acceptance.
COMPOUND_POSITIVE_CONTROL = '''import HiaSyntaxResearch.Baseline
namespace HiaCoreSyntaxSlice.CompoundReuseRegression
noncomputable def firstRaw : Raw := .arr [.obj [([97], .str [120]), ([98], .num 7)]]
noncomputable def firstBytes : List Nat := [91,123,34,97,34,58,34,120,34,44,34,98,34,58,55,125,93]
theorem first_s0 : serializeRaw 64 8 firstRaw = some firstBytes := by decide +kernel
theorem first_p0 (tail : List Nat) : parseRaw 64 8 (firstBytes ++ tail) = some (firstRaw, tail) := by rfl
noncomputable def nextRaw : Raw := .arr [.obj [([97], .str [120]), ([98], .num 7)]]
noncomputable def nextBytes : List Nat := [91] ++ ([123,34,97,34,58,34,120,34,44,34,98,34,58,55,125] ++ [93])
theorem next_s0 : serializeRaw 64 8 nextRaw = some nextBytes := by
  exact first_s0
theorem next_p0 (tail : List Nat) : parseRaw 64 8 (nextBytes ++ tail) = some (nextRaw, tail) := by
  exact first_p0 tail
end HiaCoreSyntaxSlice.CompoundReuseRegression
#print axioms HiaCoreSyntaxSlice.CompoundReuseRegression.first_s0
#print axioms HiaCoreSyntaxSlice.CompoundReuseRegression.first_p0
#print axioms HiaCoreSyntaxSlice.CompoundReuseRegression.next_s0
#print axioms HiaCoreSyntaxSlice.CompoundReuseRegression.next_p0
'''
COMPOUND_NEGATIVE_CONTROLS = {
    'different_bytes': COMPOUND_POSITIVE_CONTROL.replace(
        'noncomputable def nextBytes : List Nat := [91] ++ ([123,34,97,34,58,34,120,34,44,34,98,34,58,55,125] ++ [93])',
        'noncomputable def nextBytes : List Nat := [91] ++ ([123,34,97,34,58,34,120,34,44,34,98,34,58,56,125] ++ [93])'),
    'different_raw': COMPOUND_POSITIVE_CONTROL.replace(
        'noncomputable def nextRaw : Raw := .arr [.obj [([97], .str [120]), ([98], .num 7)]]',
        'noncomputable def nextRaw : Raw := .arr [.obj [([97], .str [120]), ([98], .num 8)]]'),
    'zero_fuel': COMPOUND_POSITIVE_CONTROL.replace(' : serializeRaw 64 8 nextRaw', ' : serializeRaw 0 8 nextRaw').replace(
        ' : parseRaw 64 8 (nextBytes', ' : parseRaw 0 8 (nextBytes'),
    'zero_depth': COMPOUND_POSITIVE_CONTROL.replace(' : serializeRaw 64 8 nextRaw', ' : serializeRaw 64 0 nextRaw').replace(
        ' : parseRaw 64 8 (nextBytes', ' : parseRaw 64 0 (nextBytes'),
}


# Handwritten generic controls; independent of the consumer proof emitter.
CONSUMER_POSITIVE_CONTROL = "import HiaSyntaxResearch.Baseline\nnamespace HiaCoreSyntaxSlice.ConsumerRewriteRegression\ntheorem raw_tag (tree : Raw) (label : List Nat) :\n    decide (tree = Raw.str label) =\n      (match tree with | .str actual => decide (actual = label) | _ => false) := by\n  cases tree <;> simp\ntheorem changed_end (front : List Nat) :\n    front ++ [125] ≠ front ++ [93] := by\n  induction front with\n  | nil => intro same; cases same\n  | cons head rest ih =>\n    intro same\n    exact ih (List.cons.inj same).2\nend HiaCoreSyntaxSlice.ConsumerRewriteRegression\n#print axioms HiaCoreSyntaxSlice.ConsumerRewriteRegression.raw_tag\n#print axioms HiaCoreSyntaxSlice.ConsumerRewriteRegression.changed_end\n"
CONSUMER_NEGATIVE_CONTROLS = {
    'nonstring_tag': CONSUMER_POSITIVE_CONTROL.replace('| _ => false)', '| _ => true)'),
    'equal_closing_byte': CONSUMER_POSITIVE_CONTROL.replace('front ++ [93]', 'front ++ [125]'),
}


class SharedSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = s.seven.original.build_inputs()
        cls.previous = s.seven.build_sources(cls.prepared)
        cls.proposal = s.build_sources(cls.prepared, cls.previous)
        cls.unrepaired = s._undo_consumer_repairs(cls.proposal.stages)
        cls.unscheduled = s._undo_scheduled_prints(cls.unrepaired)

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

    def test_untrusted_reference_is_byte_identical_to_checked_old_builder(self):
        reference = plan._reference_seven(self.prepared)
        self.assertEqual(reference, self.previous)
        self.assertEqual(reference.manifest_json, self.previous.manifest_json)
        self.assertEqual(reference.manifest_sha256, self.previous.manifest_sha256)
        self.assertEqual(len(reference.stages), 11)
        self.assertEqual(tuple(x.source.encode() for x in reference.stages),
                         tuple(x.source.encode() for x in self.previous.stages))
        self.assertFalse(reference.manifest['acceptance_eligible'])

    def test_both_actual_old_validation_gates_are_mandatory(self):
        reference = plan._reference_seven(self.prepared)
        actual_gate = s.seven.validate_sources
        for failing_call in (1, 2):
            visited = []
            def inject(prepared, candidate, *args, **kwargs):
                visited.append(candidate)
                if len(visited) == failing_call:
                    raise ValueError('required old gate ' + str(failing_call))
                return actual_gate(prepared, candidate, *args, **kwargs)
            with self.subTest(failing_call=failing_call), patch.object(
                    s.seven, 'validate_sources', side_effect=inject):
                with self.assertRaisesRegex(ValueError, 'required old gate ' + str(failing_call)):
                    s.validate_sources(self.prepared, reference, self.proposal)
            self.assertEqual(len(visited), failing_call)
            self.assertIs(visited[0], reference)
            if failing_call == 2:
                self.assertIsNot(visited[1], reference)
                self.assertEqual(visited[1], reference)

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
        source = self.unscheduled[3].source.replace('\nnoncomputable def ', '\ndef ')
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
                         for stage in self.unscheduled)
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


    def test_compound_layer_recovers_every_frozen_v6_module(self):
        old, syntax, _, blocks, _ = s._context(self.prepared, self.previous)
        v6 = s._extend_part02(s._repartition(s._render(old, syntax, blocks, helpers=True)))
        names = s.nocode._definitions(replace(old, stages=v6))
        actual = tuple(replace(stage, source=s.nocode._transform(stage.source, names[stage.name], inverse=True))
                       for stage in self.unscheduled)
        recovered = s._undo_compound_sharing(actual, v6)
        self.assertEqual(s._v6_source_hashes(recovered), dict(s.V6_SOURCE_SHA256))
        reuse = self.proposal.manifest['compound_proof_reuses']
        self.assertEqual((reuse['serializer'], reuse['parser'], reuse['proofs']), (403, 403, 806))
        self.assertTrue(reuse['exact_bounds'])
        self.assertEqual(reuse['prior_v6_dependency_references'], 45994)
        self.assertEqual(reuse['candidate_dependency_references'], 46800)
        # Existing eleven modules, declarations and all subject multiplicities.
        self.assertEqual(tuple(r[:3] for b in s.seven._extract(actual)[1] for r in b),
                         tuple(r[:3] for b in s.seven._extract(v6)[1] for r in b))
        self.assertEqual(Counter(n for stage in actual for n in stage.expected_theorems),
                         Counter(n for stage in v6 for n in stage.expected_theorems))

    def test_compound_reference_and_manifest_cannot_be_forged(self):
        old, syntax, _, blocks, _ = s._context(self.prepared, self.previous)
        v6 = s._extend_part02(s._repartition(s._render(old, syntax, blocks, helpers=True)))
        changes = s._compound_context(v6)[3]
        _, (_, raw) = next(iter(changes.items()))
        header, _ = s._body(raw)
        forged = (header + ' := by\n  exact HiaCoreSyntaxSlice.Shared.parse_root\n').encode()
        index = next(i for i, stage in enumerate(self.proposal.stages) if raw.decode() in stage.source)
        self.reject(self.change(index, lambda text: text.replace(raw.decode(), forged.decode(), 1)))
        manifest = self.proposal.manifest
        manifest['compound_proof_reuses']['proofs'] -= 1
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))



    def test_print_schedule_restores_all_actual_v7_bytes_and_multiplicities(self):
        p = self.proposal
        self.assertEqual(s._v7_source_hashes(self.unscheduled), dict(s.V7_SOURCE_SHA256))
        self.assertEqual(p.manifest['print_schedule']['moved_subjects'], 7190)
        self.assertFalse(p.manifest['print_schedule']['proof_or_declaration_changes'])
        self.assertEqual(p.manifest['print_schedule']['source_byte_delta'], 0)
        for before, after in zip(self.unscheduled, self.unrepaired):
            self.assertEqual(before.source_bytes, after.source_bytes)
            self.assertEqual(Counter(s.seven._qualified_prints(before.source)),
                             Counter(s.seven._qualified_prints(after.source)))
        self.assertEqual(p.stages[0], self.unscheduled[0])
        self.assertEqual(self.unrepaired[9:], self.unscheduled[9:])

    def test_print_schedule_cannot_drop_duplicate_substitute_or_delay_queries(self):
        source = self.proposal.stages[3].source
        subject = s.PRINT_PATTERN.findall(source)[0]
        command = '#print axioms ' + subject + '\n'
        self.reject(self.change(3, lambda text: text.replace(command, '', 1)))
        self.reject(self.change(3, lambda text: text.replace(command, command + command, 1)))
        self.reject(self.change(3, lambda text: text.replace(command,
            '#print axioms HiaCoreSyntaxSlice.Shared.parse_root\n', 1)))
        # The original footer is semantically meaningful, but is not this
        # registered candidate's fixed scheduling transformation.
        self.reject(self.change(3, lambda _: self.unscheduled[3].source))
        manifest = self.proposal.manifest
        manifest['print_schedule']['moved_subjects'] -= 1
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))


    def test_consumer_repairs_reconstruct_complete_actual_old_bytes(self):
        candidate = self.proposal.stages
        recovered = s._undo_consumer_repairs(candidate)
        self.assertEqual(recovered, self.unrepaired)
        self.assertEqual(s.digest(recovered[9].source.encode()), s.CONSUMER_BASE_SHA256)
        self.assertEqual(recovered[:9], candidate[:9])
        self.assertEqual(s.digest(recovered[10].source.encode()), s.WRONG_ARM_BASE_SHA256)
        self.assertEqual(Counter(s.seven._qualified_prints(recovered[10].source)),
                         Counter(s.seven._qualified_prints(candidate[10].source)))
        self.assertEqual(recovered[10].source.count('\n'), candidate[10].source.count('\n'))
        self.assertEqual(Counter(s.seven._qualified_prints(recovered[9].source)),
                         Counter(s.seven._qualified_prints(candidate[9].source)))
        self.assertEqual(recovered[9].source.count('\n'), candidate[9].source.count('\n'))
        self.assertEqual(len(candidate[9].expected_theorems), 75)
        self.assertEqual(self.proposal.manifest['consumer_proofs']['proof_changes'], 8)
        values = s._consumer_byte_values(candidate)
        actual = s._changed_byte_value(s.CHANGED_BYTE_RHS, values)
        original = values['linearBytes']['value']
        self.assertEqual(len(actual), 14466)
        self.assertEqual(actual[:-1], original[:-1])
        self.assertEqual((original[-1], actual[-1]), (125, 93))
        # Every original target prefix remains literal; generic definitions are
        # retained in full by the independent old-source SHA, not just a count.
        names = (*s.CONSUMER_NAMES, 'reject_changed_exact_byte')
        for name in names:
            before = next(line for line in recovered[9].source.splitlines()
                          if line.startswith('theorem ' + name + ' : '))
            after = next(line for line in candidate[9].source.splitlines()
                         if line.startswith('theorem ' + name + ' : '))
            self.assertEqual(before.partition(' := by')[0], after.partition(' := by')[0])

    def test_consumer_target_local_proof_and_negative_clause_tampering_reject(self):
        edits = (
            ('with literalValue := 2', 'with literalValue := 3'),
            ('| _ => no) := (by cases raw', '| _ => yes) := (by cases raw'),
            ('| _ => false) := (by cases raw', '| _ => true) := (by cases raw'),
            ('have impossible := necessary.2.2', 'have impossible := necessary.2'),
            ('have accepted : SliceSyntaxRelation', 'have accepted : True'),
            ('exact if_pos accepted', 'exact of_decide_eq_true rfl'),
        )
        for before, after in edits:
            self.assertIn(before, self.proposal.stages[9].source)
            self.reject(self.change(9, lambda text, a=before, b=after: text.replace(a, b, 1)))

    def test_wrong_arm_mutation_statement_and_projected_field_remain_bound(self):
        source = self.proposal.stages[10].source
        original, ledger = s._wrong_arm_source(source, inverse=True)
        self.assertEqual(s.digest(original.encode()), s.WRONG_ARM_BASE_SHA256)
        self.assertEqual(s._wrong_arm_source(original)[0], source)
        self.assertEqual(ledger['name'], 'HiaCoreSyntaxSlice.reject_wrong_arm_implementation')
        self.assertEqual(len(self.proposal.stages[10].expected_theorems), 1)
        for before, after in (
            ('let edge := field (field header "term") "else"', 'let edge := field (field header "term") "then"'),
            ('reconstruct raw hint = d :=', 'd = d :='),
            (').incoming ≠ HiaGuardedUsizeSlice.linear_0.incoming', ').literalOrdinal ≠ HiaGuardedUsizeSlice.linear_0.literalOrdinal'),
            ('some HiaGuardedUsizeSlice.linear_0) :=', 'some { HiaGuardedUsizeSlice.linear_0 with literalValue := 2 }) :='),
            ('(by decide +kernel)', '(by native_decide)'),
        ):
            self.assertIn(before, source)
            self.reject(self.change(10, lambda text, a=before, b=after: text.replace(a, b, 1)))
        manifest = self.proposal.manifest
        manifest['consumer_proofs']['wrong_arm']['projected_field'] = 'literalOrdinal'
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))

    def test_changed_byte_actual_reference_data_and_cancellation_are_bound(self):
        source = self.proposal.stages[9].source
        for before, after in (
            (s.CHANGED_BYTE_RHS, s.CHANGED_BYTE_RHS.replace('[93]', '[125]')),
            (s.CHANGED_BYTE_RHS, s.CHANGED_BYTE_RHS.replace('linear_v0_0', 'parallel_v0_0')),
            ('cancel linear_v0_0 [125] [93]', 'cancel linear_v0_0 [125] [125]'),
            ('noncomputable def linearBytes : List Nat := ' + s.CHANGED_BYTE_RHS,
             'def linearBytes : List Nat := ' + s.CHANGED_BYTE_RHS),
        ):
            self.assertIn(before, source)
            self.reject(self.change(9, lambda text, a=before, b=after: text.replace(a, b, 1)))
        # Corrupt the actually referenced parent, retaining the consumer text.
        before = 'noncomputable def linear_g0 : List Nat := [123]'
        index = next(i for i, stage in enumerate(self.proposal.stages) if before in stage.source)
        self.reject(self.change(index, lambda text: text.replace(before, before.replace('123', '124'), 1)))
        manifest = self.proposal.manifest
        manifest['consumer_proofs']['changed_byte_representation']['bytes'] -= 1
        self.reject(replace(self.proposal, manifest_json=s.encode(manifest)))


class ByteAliasScanTests(unittest.TestCase):
    def test_exact_integer_domain_matches_the_old_predicate(self):
        class IntegerSubclass(int):
            pass
        atoms = [-1, 0, 1, 255, 256, 10 ** 100, False, True,
                 IntegerSubclass(1), 1.0, None, object()]
        values = [[], list(range(256)), (), b'abc']
        values += [[x] for x in atoms]
        values += [[x, y] for x in atoms for y in atoms]
        for value in values:
            expected = type(value) is list and all(
                type(n) is int and 0 <= n < 256 for n in value)
            with self.subTest(value=value):
                if expected:
                    self.assertEqual(structured._byte_alias_bytes(value), bytes(value))
                else:
                    with self.assertRaisesRegex(ValueError, 'byte alias range'):
                        structured._byte_alias_bytes(value)

    def test_type_protocols_cannot_impersonate_builtin_int(self):
        callbacks = []
        class Mimic(type):
            def __hash__(cls):
                callbacks.append('hash')
                return hash(int)
            def __eq__(cls, other):
                callbacks.append('equality')
                return True
        class Impostor(metaclass=Mimic):
            def __index__(self):
                callbacks.append('index')
                return 7
        class IntegerSubclass(int):
            def __index__(self):
                callbacks.append('subclass index')
                return 7
        class ListSubclass(list):
            def __iter__(self):
                callbacks.append('list iteration')
                return super().__iter__()
        for value in ([Impostor()], [IntegerSubclass(7)], ListSubclass([7])):
            with self.assertRaisesRegex(ValueError, 'byte alias range'):
                structured._byte_alias_bytes(value)
        self.assertEqual(callbacks, [])

    def test_unused_alias_still_obeys_range_and_expanded_length_bounds(self):
        tree = {'a': 1}
        raw = b'{"a":1}'
        namespace = 'HiaCoreSyntaxSlice.ByteScan'
        example = structured.build_structured_input('tiny', tree, raw, namespace, 'tiny', 'tiny')
        for value, reason in (([0] * 33, 'byte alias length'),
                              ([0] * 32 + [256], 'byte alias range')):
            rhs = '[' + ','.join(map(str, value)) + ']'
            extra = 'def unused : List Nat := ' + rhs + '\n'
            source = example.source.replace('end ' + namespace + '\n',
                                            extra + 'end ' + namespace + '\n')
            manifest = example.manifest
            manifest['source_sha256'] = structured.digest(source.encode())
            manifest['definitions'].append(dict(name='unused', type='List Nat',
                                                rhs_sha256=structured.digest(rhs.encode())))
            with self.subTest(reason=reason), patch.object(structured.old, 'MAX_BYTES', 32):
                with self.assertRaisesRegex(ValueError, reason):
                    structured.verify_structured_source(source, manifest, tree, raw)


class CompoundProofTests(unittest.TestCase):
    """Small handwritten sources, independent of the production emitter."""
    NS = 'Hand'
    RAW = '(.arr [(.obj [([97], (.str [120])), ([98], (.num 7))])])'
    BYTES = '[91,123,34,97,34,58,34,120,34,44,34,98,34,58,55,125,93]'

    def definitions(self):
        return {'Hand.aRaw': self.RAW, 'Hand.bRaw': self.RAW,
                'Hand.aBytes': self.BYTES, 'Hand.bBytes': 'aBytes'}

    def statement(self, name, *, serial, raw='bRaw', byte='bBytes', fuel=64, depth=8):
        if serial:
            return ('theorem %s : serializeRaw %d %d %s = some %s := by decide +kernel\n' %
                    (name, fuel, depth, raw, byte)).encode()
        return ('theorem %s (tail : List Nat) : parseRaw %d %d (%s ++ tail) = some (%s, tail) := by rfl\n' %
                (name, fuel, depth, byte, raw)).encode()

    def seed(self, *, serial=True, owner='Parent'):
        first = {}
        name = 'a_s0' if serial else 'a_p0'
        raw = self.statement(name, serial=serial, raw='aRaw', byte='aBytes')
        self.assertIsNone(s._reuse_compound(self.NS, name, raw, self.definitions(), first, owner, set()))
        return first

    def test_exact_bounds_closed_raw_and_actual_bytes_reuse(self):
        for serial in (True, False):
            first = self.seed(serial=serial)
            name = 'b_s0' if serial else 'b_p0'
            raw = self.statement(name, serial=serial)
            actual = s._reuse_compound(self.NS, name, raw, self.definitions(), first, 'Child', {'Parent'})
            reference = 'Hand.a_s0' if serial else 'Hand.a_p0 tail'
            self.assertEqual(actual, (s._body(raw)[0] + ' := by\n  exact (' + reference + ')\n').encode())

    def test_each_semantic_key_component_is_required(self):
        for serial in (True, False):
            name = 'b_s0' if serial else 'b_p0'
            for component in ('raw', 'bytes', 'fuel', 'depth'):
                definitions, kwargs = self.definitions(), {}
                if component == 'raw':
                    definitions['Hand.bRaw'] = self.RAW.replace('.num 7', '.num 8')
                elif component == 'bytes':
                    definitions['Hand.bBytes'] = self.BYTES.replace(',55,', ',56,')
                else:
                    kwargs[component] = 63 if component == 'fuel' else 7
                raw = self.statement(name, serial=serial, **kwargs)
                self.assertIsNone(s._reuse_compound(self.NS, name, raw, definitions,
                                                    self.seed(serial=serial), 'Child', {'Parent'}))

    def test_aliases_resolve_in_the_defining_namespace_and_cycles_reject(self):
        definitions = self.definitions()
        definitions.update({'Hand.bBytes': 'Other.alias', 'Other.alias': 'actual',
                            'Other.actual': self.BYTES, 'Hand.actual': '[0]'})
        self.assertEqual(s._literal_alias_bytes('Hand', 'bBytes', definitions),
                         tuple(s.json.loads(self.BYTES)))
        definitions['Other.actual'] = 'alias'
        with self.assertRaisesRegex(ValueError, 'acyclic bounded'):
            s._literal_alias_bytes('Hand', 'bBytes', definitions)

    def test_nonclosed_data_or_nonliteral_bytes_cannot_reuse(self):
        for key, value in (('Hand.bRaw', '(.arr [externalRaw])'),
                           ('Hand.bBytes', 'aBytes ++ []')):
            definitions = self.definitions()
            definitions[key] = value
            self.assertIsNone(s._reuse_compound(self.NS, 'b_s0', self.statement('b_s0', serial=True),
                                                definitions, self.seed(), 'Child', {'Parent'}))

    def test_branch_visibility_and_registration_order_are_required(self):
        first = self.seed(owner='Sibling')
        raw = self.statement('b_s0', serial=True)
        self.assertIsNone(s._reuse_compound(self.NS, 'b_s0', raw, self.definitions(),
                                            first, 'Child', {'Parent'}))
        # A later declaration can use this branch's own earlier proof.
        later = self.statement('b_s1', serial=True)
        result = s._reuse_compound(self.NS, 'b_s1', later, self.definitions(),
                                  first, 'Child', {'Parent'})
        self.assertIn(b'exact (Hand.b_s0)', result)

    def test_zero_bounds_are_never_candidates(self):
        for component in ('fuel', 'depth'):
            raw = self.statement('b_s0', serial=True, **{component: 0})
            self.assertIsNone(s._reuse_compound(self.NS, 'b_s0', raw, self.definitions(),
                                                self.seed(), 'Child', {'Parent'}))

    def test_control_mutations_preserve_the_independent_prior_proofs(self):
        self.assertEqual(len(COMPOUND_NEGATIVE_CONTROLS), 4)
        prefix = COMPOUND_POSITIVE_CONTROL.split('noncomputable def nextRaw')[0]
        for text in COMPOUND_NEGATIVE_CONTROLS.values():
            self.assertNotEqual(text, COMPOUND_POSITIVE_CONTROL)
            self.assertEqual(text.split('noncomputable def nextRaw')[0], prefix)
            self.assertIn('exact first_s0', text)
            self.assertIn('exact first_p0 tail', text)



class PrintSchedulingTests(unittest.TestCase):
    def test_independent_queries_move_without_changing_any_other_byte(self):
        z = b'theorem z : True := by trivial\n'
        a = b'theorem a : True := by trivial\n'
        rows = (('Control', 'theorem', 'z', z), ('Control', 'theorem', 'a', a))
        source = ('import Parent\nnamespace Control\n' + z.decode() + a.decode() +
                  'end Control\n#print axioms Control.a\n#print axioms Control.z\n')
        scheduled = s._move_prints(source, rows)
        self.assertIn(z.decode() + '#print axioms Control.z\n' + a.decode(), scheduled)
        self.assertEqual(s._restore_print_tail(scheduled), source)
        self.assertEqual(s.PRINT_PATTERN.sub('', source), s.PRINT_PATTERN.sub('', scheduled))
        self.assertEqual(len(scheduled), len(source))

    def test_missing_duplicated_or_foreign_subject_is_rejected(self):
        row = ('Control', 'theorem', 'z', b'theorem z : True := by trivial\n')
        body = 'import Parent\nnamespace Control\n' + row[3].decode() + 'end Control\n'
        for suffix in ('', '#print axioms Control.a\n',
                       '#print axioms Control.z\n#print axioms Control.z\n'):
            with self.assertRaises(ValueError):
                s._move_prints(body + suffix, (row,))
        with self.assertRaises(ValueError):
            s._restore_print_tail(body + '#print axioms Control.z\n#print axioms Control.z\n')


class ApplicationParserTests(unittest.TestCase):
    def test_nested_certificate_arguments_preserved(self):
        self.assertEqual(s._arguments('f (g x (h y)) [1, 2] z'), ['f', '(g x (h y))', '[1, 2]', 'z'])
        for malformed in ('f (x', 'f [x)', 'f x)'):
            with self.assertRaises(ValueError):
                s._arguments(malformed)


if __name__ == '__main__':
    unittest.main()

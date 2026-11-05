"""Actual full-input inverse and adversarial header/body tests; no mocked proof success."""
from dataclasses import replace
import unittest

from tools import core_seven_nocode_sources as n


class NoCodeHeaderTests(unittest.TestCase):
    def test_exact_namespaces_and_inverse(self):
        source = ('namespace A\nsection\ndef x : Nat := 1\nend\n'
                  'namespace B\ndef x : Nat := 2\nend B\n'
                  'theorem t : x = 1 := rfl\nend A\n')
        names = frozenset({'A.x', 'A.B.x'})
        marked = n._transform(source, names)
        self.assertEqual(marked.count('noncomputable def '), 2)
        self.assertEqual(n._transform(marked, names, inverse=True), source)
        self.assertIn('theorem t : x = 1 := rfl', marked)

    def test_header_state_duplicate_missing_and_unclosed_rejected(self):
        names = frozenset({'A.x'})
        for text, inverse in (
            ('namespace A\ndef x : Nat := 1\nend A\n', True),
            ('namespace A\nnoncomputable def x : Nat := 1\nend A\n', False),
            ('namespace A\ndef x : Nat := 1\ndef x : Nat := 2\nend A\n', False),
            ('namespace B\ndef x : Nat := 1\nend B\n', False),
            ('namespace A\ndef x : Nat := 1\n', False),
        ):
            with self.subTest(text=text, inverse=inverse), self.assertRaises(ValueError):
                n._transform(text, names, inverse=inverse)


class NoCodeFullInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = n.seven.original.build_inputs()
        cls.previous = n.seven.build_sources(cls.prepared)
        cls.proposal = n.build_sources(cls.prepared, cls.previous)

    def reject(self, proposal):
        with self.assertRaises(ValueError):
            n.validate_sources(self.prepared, self.previous, proposal)

    def changed(self, index, edit):
        stages = list(self.proposal.stages)
        stages[index] = replace(stages[index], source=edit(stages[index].source))
        return replace(self.proposal, stages=tuple(stages))

    def test_actual_all_inputs_and_inventories_preserved(self):
        p = self.proposal
        self.assertEqual(tuple(len(s.expected_theorems) for s in p.stages), n.COUNTS)
        self.assertEqual(sum(s.source.count('noncomputable def ') for s in p.stages), 7685)
        self.assertEqual(p.manifest['added_source_bytes'], 107590)
        self.assertEqual(p.manifest['retained_source_bytes'], 5700944)
        self.assertEqual(p.original_stages, self.prepared['stages'])
        self.assertFalse(p.manifest['acceptance_eligible'])
        self.assertFalse(p.manifest['kernel_core_syntax_connection_checked'])
        self.assertFalse(p.manifest['actual_core_bridge_proved'])
        self.assertTrue(all(row['status'] == 'unproved' for row in p.manifest['obligations']))
        # Header prefixes have no newlines: negative declaration coordinates and
        # every original theorem's complete proof text are unchanged.
        old = n._relocated(self.prepared, self.previous)
        for before, after in zip(old.stages, p.stages):
            self.assertEqual(before.source.count('\n'), after.source.count('\n'))
            self.assertEqual(n.seven._qualified_prints(before.source),
                             n.seven._qualified_prints(after.source))

    def test_removed_marker_rejected(self):
        self.reject(self.changed(1, lambda s: s.replace('noncomputable def ', 'def ', 1)))

    def test_data_body_change_rejected(self):
        def corrupt(source):
            start = source.index('noncomputable def ')
            end = source.index('\n', start)
            # Even a semantic no-op source change is outside this exact proposal.
            return source[:end] + ' ' + source[end:]
        self.reject(self.changed(1, corrupt))

    def test_theorem_and_unrelated_source_mutations_rejected(self):
        self.reject(self.changed(3, lambda s: s.replace('theorem ', 'axiom ', 1)))
        self.reject(self.changed(0, lambda s: s + '\n-- unexpected\n'))

    def test_metadata_and_inventory_mutations_rejected(self):
        stages = list(self.proposal.stages)
        stages[2] = replace(stages[2], expected_theorems=frozenset())
        self.reject(replace(self.proposal, stages=tuple(stages)))

    def test_manifest_cannot_upgrade_or_hide_definition(self):
        for key, value in (('acceptance_eligible', True),
                           ('kernel_core_syntax_connection_checked', True),
                           ('transport_definitions', 7684)):
            manifest = self.proposal.manifest
            manifest[key] = value
            with self.subTest(key=key):
                self.reject(replace(self.proposal, manifest_json=n.encode(manifest)))

    def test_retained_copies_count_toward_existing_budget(self):
        with self.assertRaises(ValueError):
            n.validate_retention(self.proposal, ('x' * (n.MAX_SOURCE + 1),))
        with self.assertRaises(ValueError):
            n.validate_retention(self.proposal, ('x' * n.MAX_SOURCE,) * 2)


if __name__ == '__main__':
    unittest.main()

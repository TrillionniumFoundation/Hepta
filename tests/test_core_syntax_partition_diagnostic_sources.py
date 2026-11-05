"""Reversible source/control tests, not kernel acceptance."""
from copy import deepcopy
from dataclasses import replace
import unittest

from tools import core_syntax_partition_sources as original
from tools import core_syntax_partition_diagnostic_sources as sources
from tools import check_core_syntax_staged as base


class PartitionDiagnosticSourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = original.build_inputs()
        cls.diagnostic = sources.build_diagnostic_sources(cls.prepared)

    def reject(self, diagnostic, prepared=None):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            sources.validate_diagnostic_sources(self.prepared if prepared is None else prepared, diagnostic)

    def changed(self, source=None, manifest=None, stages=None):
        stages = list(self.diagnostic.stages if stages is None else stages)
        if source is not None:
            stages[3] = replace(stages[3], source=source)
        return sources.DiagnosticSources(tuple(stages), sources.encode(
            self.diagnostic.manifest if manifest is None else manifest))

    def test_complete_original_and_exact_inverse(self):
        result = sources.validate_diagnostic_sources(self.prepared, self.diagnostic)
        self.assertFalse(result['acceptance_eligible'])
        self.assertLessEqual(result['marker_count'], 24)
        self.assertEqual(sources.strip_markers(self.diagnostic.stages[3].source,
                         self.diagnostic.manifest), self.prepared['stages'][3].source.encode())
        self.assertEqual(self.diagnostic.stages[:3], self.prepared['stages'][:3])
        self.assertEqual(len(self.prepared['expected_theorems']), 66)
        self.assertEqual(len(self.prepared['negatives']), 10)
        self.assertEqual(len(self.prepared['manifest']['inputs']), 5)
        m = self.diagnostic.manifest
        self.assertEqual(m['maximum_processes'], 4)
        self.assertEqual(m['retained_total_source_bytes'], 2400382+self.diagnostic.stages[3].source_bytes)
        labels = {label for marker in m['markers'] for label in marker['anchors']}
        self.assertTrue({'before_linear_roots', 'after_linear_transport', 'before_parallel_data',
                         'before_first_parallel_theorem', 'after_final_inventory'} <= labels)

    def test_ordinary_acceptance_rejects_derivative(self):
        prepared = dict(self.prepared, stages=self.diagnostic.stages)
        with self.assertRaises(ValueError):
            base.validate_plan(prepared)
        stages = list(self.prepared['stages']); stages[3] = self.diagnostic.stages[3]
        with self.assertRaises(ValueError):
            base.validate_plan(dict(self.prepared, stages=tuple(stages)))

    def test_rehashed_body_and_import_edits_rejected(self):
        source = self.diagnostic.stages[3].source
        for altered in (source.replace(':= by', ':= by\n  skip', 1),
                        source.replace('import Hia', 'import Other', 1)):
            self.assertNotEqual(source, altered)
            m = self.diagnostic.manifest
            m['diagnostic_target_source_sha256'] = sources.digest(altered.encode())
            m['diagnostic_target_source_bytes'] = len(altered.encode())
            m['retained_total_source_bytes'] = 2400382 + len(altered.encode())
            updated = list(self.diagnostic.stages)
            updated[3] = replace(updated[3], source=altered)
            m['stages'] = sources.framing._stage_bindings(self.prepared, updated)
            self.reject(self.changed(source=altered, manifest=m))

    def test_shifted_forged_reordered_missing_marker_rejected(self):
        for kind in ('offset', 'anchor', 'order', 'missing'):
            m = self.diagnostic.manifest
            if kind == 'offset': m['markers'][0]['original_offset'] += 1
            if kind == 'anchor': m['markers'][0]['anchors'] = ['forged']
            if kind == 'order': m['markers'][:2] = reversed(m['markers'][:2])
            if kind == 'missing': m['markers'].pop()
            self.reject(self.changed(manifest=m))

    def test_changed_parent_and_extra_stage_rejected(self):
        stages = list(self.diagnostic.stages)
        stages[2] = replace(stages[2], source=stages[2].source+'\n')
        self.reject(self.changed(stages=stages))
        self.reject(self.changed(stages=self.diagnostic.stages+(self.prepared['stages'][4],)))

    def test_original_edits_rejected_before_derivation(self):
        stages = list(self.prepared['stages'])
        stages[3] = replace(stages[3], source=stages[3].source.replace('linear_r0','linear_r1',1))
        with self.assertRaises(ValueError):
            sources.build_diagnostic_sources(dict(self.prepared, stages=tuple(stages)))

    def test_forged_acceptance_budget_and_manifest_fields_rejected(self):
        for key, value in (('acceptance_eligible', True), ('maximum_processes', 5),
                           ('retained_total_source_bytes', 1), ('target', 'CertPart03')):
            m = self.diagnostic.manifest; m[key] = value
            self.reject(self.changed(manifest=m))

    def test_unplanned_duplicate_markers_and_type_confusion(self):
        self.reject(self.changed(source=self.diagnostic.stages[3].source+'#check "extra"\n'))
        m = self.diagnostic.manifest; m['markers'][0]['instrumented_offset'] = True
        self.reject(self.changed(manifest=m))

    def test_relocated_marker_inside_command_rejected_after_exact_inverse(self):
        m = self.diagnostic.manifest
        raw = self.prepared['stages'][3].source.encode()
        m['markers'][0]['original_offset'] += 3
        pieces, cursor, added = [], 0, 0
        for marker in m['markers']:
            at = marker['original_offset']; block = marker['text'].encode()
            marker['instrumented_offset'] = at+added
            pieces.extend((raw[cursor:at], block)); cursor = at; added += len(block)
        pieces.append(raw[cursor:])
        altered = b''.join(pieces).decode()
        self.assertEqual(sources.strip_markers(altered, m), raw)
        m['diagnostic_target_source_sha256'] = sources.digest(altered.encode())
        updated = list(self.diagnostic.stages)
        updated[3] = replace(updated[3], source=altered)
        m['stages'] = sources.framing._stage_bindings(self.prepared, updated)
        self.reject(self.changed(source=altered, manifest=m))

"""Pure-source diagnostic isolation tests; no Lean process or acceptance."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from unittest import TestCase, mock

from tools import core_syntax_declaration_diagnostic_sources as diagnostic
from tools import core_syntax_structured_stages as structured


class DeclarationDiagnosticSourceTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = structured.build_inputs()
        cls.value = diagnostic.build_diagnostic_sources(cls.prepared)
        cls.original = cls.prepared['stages'][2].source.encode('utf-8')

    def rebuilt(self, source=None, manifest=None, stages=None):
        m = deepcopy(self.value.manifest if manifest is None else manifest)
        stages = self.value.stages if stages is None else stages
        if source is not None:
            stages = stages[:2] + (replace(stages[2], source=source),)
        raw = stages[2].source.encode('utf-8')
        m['diagnostic_linear_source_sha256'] = diagnostic.digest(raw)
        m['diagnostic_linear_source_bytes'] = len(raw)
        m['retained_total_source_bytes'] = m['original_total_source_bytes'] + len(raw)
        m['stages'] = diagnostic._stage_bindings(self.prepared, stages)
        return diagnostic.DiagnosticSources(stages, diagnostic.encode(m))

    def rejected(self, value):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            diagnostic.validate_diagnostic_sources(self.prepared, value)

    def test_exact_strip_and_complete_original_bindings(self):
        self.assertEqual(diagnostic.strip_markers(self.value.stages[2].source, self.value.manifest), self.original)
        result = diagnostic.validate_diagnostic_sources(self.prepared, self.value)
        self.assertIs(result['acceptance_eligible'], False)
        self.assertEqual(result['marker_count'], 24)
        self.assertEqual(len(self.prepared['expected_theorems']), 66)
        self.assertEqual(len(self.prepared['negatives']), 10)
        self.assertEqual(len(self.prepared['manifest']['inputs']), 5)

    def test_exact_three_nonaccepting_stage_metadata(self):
        self.assertEqual(tuple(s.name for s in self.value.stages), diagnostic.SCHEDULED)
        self.assertEqual(self.value.stages[:2], self.prepared['stages'][:2])
        self.assertEqual(replace(self.value.stages[2], source=self.prepared['stages'][2].source), self.prepared['stages'][2])
        self.assertEqual(self.value.manifest['maximum_processes'], 3)
        self.assertEqual(len(self.value.manifest['not_scheduled_stage_names']), 7)
        self.assertIs(self.value.manifest['acceptance_eligible'], False)

    def test_deterministic_and_immutable(self):
        second = diagnostic.build_diagnostic_sources(self.prepared)
        self.assertEqual(second, self.value)
        with self.assertRaises(FrozenInstanceError):
            second.manifest_json = '{}'
        with self.assertRaises(TypeError):
            second.sources['extra'] = 'text'
        transient = second.manifest
        transient['acceptance_eligible'] = True
        self.assertIs(second.manifest['acceptance_eligible'], False)

    def test_full_original_validation_precedes_instrumentation(self):
        broken = {**self.prepared, 'manifest_sha256': '0' * 64}
        with mock.patch.object(diagnostic, '_sites', side_effect=AssertionError('must not derive')) as sites:
            with self.assertRaises(ValueError):
                diagnostic.build_diagnostic_sources(broken)
            sites.assert_not_called()

    def test_complete_byte_budget_counts_retained_original_and_added_copy(self):
        m = self.value.manifest
        self.assertEqual(m['diagnostic_linear_source_bytes'], len(self.original) + sum(len(x['text'].encode()) for x in m['markers']))
        self.assertEqual(m['retained_total_source_bytes'], sum(s.source_bytes for s in self.prepared['stages']) + self.value.stages[2].source_bytes)
        with mock.patch.object(diagnostic, 'MAX_TOTAL_SOURCE', m['retained_total_source_bytes'] - 1):
            with self.assertRaises(ValueError):
                diagnostic.build_diagnostic_sources(self.prepared)
        with mock.patch.object(diagnostic, 'MAX_SOURCE', self.value.stages[2].source_bytes - 1):
            with self.assertRaises(ValueError):
                diagnostic.build_diagnostic_sources(self.prepared)

    def test_marker_templates_order_and_all_24_anchors(self):
        records = self.value.manifest['markers']
        self.assertEqual(len(records), 24)
        self.assertEqual(len({r['original_offset'] for r in records}), len(records))
        self.assertEqual([r['original_offset'] for r in records], sorted(r['original_offset'] for r in records))
        self.assertEqual(sum(len(r['anchors']) for r in records), 24)
        for index, entry in enumerate(records):
            self.assertEqual(entry['id'], f'HIA_DIAG_v1_LIN_{index:03d}')
            self.assertEqual(entry['text'], '#check "' + entry['id'] + '"\n')
        self.assertEqual(records[-1]['original_offset'], len(self.original))

    def test_offsets_are_utf8_bytes_not_character_indexes(self):
        source = self.prepared['stages'][2].source
        late = self.value.manifest['markers'][-4]
        offset = late['original_offset']
        self.assertGreater(offset, len(self.original[:offset].decode('utf-8')))
        bad = self.value.manifest
        bad['markers'][-4]['original_offset'] = len(self.original[:offset].decode('utf-8'))
        self.rejected(self.rebuilt(manifest=bad))
        self.assertEqual(source.encode(), self.original)

    def test_rehashed_missing_original_byte_and_changed_proof_rejected(self):
        source = self.value.stages[2].source
        for changed in (source.replace('linear_g0', 'linear_g1', 1),
                        source.replace('withinBounds linearRaw = true', 'True', 1),
                        source.replace('import HiaSyntaxResearch.SyntaxData', 'import Init', 1)):
            self.rejected(self.rebuilt(source=changed))

    def test_rehashed_marker_id_template_and_extra_io_rejected(self):
        source = self.value.stages[2].source
        for changed in (source.replace('HIA_DIAG_v1_LIN_000', 'HIA_DIAG_v1_LIN_999', 1),
                        source.replace('#check "HIA_DIAG_v1_LIN_000"', '#eval IO.println "bad"', 1),
                        source + '#check "HIA_DIAG_v1_LIN_000"\n',
                        source + 'run_cmd pure ()\n'):
            self.rejected(self.rebuilt(source=changed))

    def test_rehashed_offset_inside_command_even_when_strip_recovers_source(self):
        m = self.value.manifest
        m['markers'][0]['original_offset'] += 1
        chunks, cursor, added = [], 0, 0
        for entry in m['markers']:
            off = entry['original_offset']
            block = entry['text'].encode()
            entry['instrumented_offset'] = off + added
            chunks.extend((self.original[cursor:off], block))
            cursor = off
            added += len(block)
        chunks.append(self.original[cursor:])
        changed = b''.join(chunks).decode()
        self.assertEqual(diagnostic.strip_markers(changed, m), self.original)
        self.rejected(self.rebuilt(source=changed, manifest=m))

    def test_missing_duplicate_reordered_or_overlimit_marker_manifest(self):
        for kind in ('missing', 'duplicate', 'reorder', 'overlimit'):
            m = self.value.manifest
            if kind == 'missing':
                m['markers'].pop()
            elif kind == 'duplicate':
                m['markers'][1] = deepcopy(m['markers'][0])
            elif kind == 'reorder':
                m['markers'][1], m['markers'][2] = m['markers'][2], m['markers'][1]
            else:
                m['markers'].append(deepcopy(m['markers'][-1]))
            self.rejected(self.rebuilt(manifest=m))

    def test_rehashed_anchor_labels_and_adjacent_commands_rejected(self):
        for field, replacement in (('anchors', ['invented']), ('previous_command', None),
                                   ('next_command', {'kind': 'theorem', 'name': 'invented', 'start': 0, 'end': 1})):
            m = self.value.manifest
            m['markers'][2][field] = replacement
            self.rejected(self.rebuilt(manifest=m))

    def test_changed_baseline_syntaxdata_and_fourth_stage_rejected(self):
        for index in (0, 1):
            stages = list(self.value.stages)
            stages[index] = replace(stages[index], source=stages[index].source + '\n')
            self.rejected(self.rebuilt(stages=tuple(stages)))
        self.rejected(diagnostic.DiagnosticSources(self.value.stages + (self.prepared['stages'][3],), self.value.manifest_json))

    def test_protocol_acceptance_manifest_and_source_accounting_rejected(self):
        mutations = (('protocol', 'acceptance'), ('acceptance_eligible', True),
                     ('maximum_processes', 4), ('maximum_processes', True),
                     ('original_manifest_sha256', '0'*64), ('candidate_site_count', 25),
                     ('original_total_source_bytes', 0), ('not_scheduled_stage_names', []))
        for field, value in mutations:
            m = self.value.manifest
            m[field] = value
            self.rejected(self.rebuilt(manifest=m))

    def test_manifest_cap_extra_fields_and_numeric_types_rejected(self):
        self.assertLessEqual(len(self.value.manifest_json.encode()), diagnostic.MAX_MANIFEST)
        for field, value in (('unexpected', 'payload'), ('marker_count', 24.0),
                             ('diagnostic_linear_source_bytes', True)):
            m = self.value.manifest
            m[field] = value
            self.rejected(diagnostic.DiagnosticSources(self.value.stages, diagnostic.encode(m)))
        m = self.value.manifest
        m['unexpected'] = 'x' * diagnostic.MAX_MANIFEST
        self.rejected(diagnostic.DiagnosticSources(self.value.stages, diagnostic.encode(m)))
        m = self.value.manifest
        m['markers'][0]['unexpected'] = 'payload'
        self.rejected(self.rebuilt(manifest=m))

    def test_unsupported_original_command_boundary_rejected(self):
        for text in ('import X\nnamespace X\n#eval 1\n',
                     'import X\ndef a : Nat := 1\n  unexpected\n',
                     'import X\r\n', 'import X'):
            with self.assertRaises(ValueError):
                diagnostic._commands(text)

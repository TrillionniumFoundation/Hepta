"""Single-factor N -> M -> O preparation tests. Never runs Lean."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import re
from unittest import TestCase, mock

from tools import core_syntax_declaration_diagnostic_sources as marker
from tools import core_syntax_noncomputable_diagnostic_sources as candidate
from tools import core_syntax_structured_stages as structured


class NoncomputableDiagnosticSourceTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = structured.build_inputs()
        cls.value = candidate.build_noncomputable_diagnostic(cls.prepared)
        cls.original = cls.prepared['stages'][2].source.encode()
        cls.m_raw = cls.value.marker_source.encode()

    def rehash(self, source=None, manifest=None, marker_source=None, stages=None):
        m = deepcopy(self.value.manifest if manifest is None else manifest)
        ss = self.value.stages if stages is None else stages
        if source is not None:
            ss = ss[:2] + (replace(ss[2], source=source),)
        retained = self.value.marker_source if marker_source is None else marker_source
        n_raw = ss[2].source.encode()
        m['candidate_linear_source_sha256'] = candidate.digest(n_raw)
        m['candidate_linear_source_bytes'] = len(n_raw)
        m['marker_linear_source_sha256'] = candidate.digest(retained.encode())
        m['marker_linear_source_bytes'] = len(retained.encode())
        m['retained_total_source_bytes'] = m['original_total_source_bytes'] + len(retained.encode()) + len(n_raw)
        m['stages'] = marker._stage_bindings(self.prepared, ss)
        return candidate.NoncomputableDiagnosticSources(ss, candidate.encode(m), retained)

    def reject(self, value):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            candidate.validate_noncomputable_diagnostic(self.prepared, value)

    def test_complete_reversible_family_and_unchanged_843_proofs(self):
        n = self.value.stages[2].source
        m = self.value.manifest
        restored = candidate.strip_noncomputable(n, m['definition_offsets'])
        self.assertEqual(restored, self.m_raw)
        self.assertEqual(marker.strip_markers(restored.decode(), m['base_marker_manifest']), self.original)
        self.assertEqual(len(re.findall(r'(?m)^noncomputable def ', n)), 1537)
        self.assertNotRegex(n, r'(?m)^def ')
        before = re.findall(rb'(?m)^theorem (\w+)', self.original)
        self.assertEqual(len(before), 843)
        self.assertEqual(re.findall(r'(?m)^theorem (\w+)', n), [x.decode() for x in before])
        self.assertEqual(m['definition_type_counts'], candidate.TYPE_COUNTS)
        result = candidate.validate_noncomputable_diagnostic(self.prepared, self.value)
        self.assertEqual(result['added_source_bytes'], 21518)
        self.assertIs(result['acceptance_eligible'], False)

    def test_full_original_marker_validator_is_used_unchanged(self):
        with mock.patch.object(marker, 'validate_diagnostic_sources', wraps=marker.validate_diagnostic_sources) as checked:
            candidate.validate_noncomputable_diagnostic(self.prepared, self.value)
            self.assertEqual(checked.call_count, 1)
            supplied_original, supplied_m = checked.call_args.args
            self.assertIs(supplied_original, self.prepared)
            self.assertEqual(supplied_m.stages[2].source.encode(), self.m_raw)
            self.assertNotIn('noncomputable def ', supplied_m.stages[2].source)

    def test_marker_positions_adjusted_without_changing_original_coordinates(self):
        m = self.value.manifest
        self.assertEqual(len(self.value.markers), 24)
        n_raw = self.value.stages[2].source.encode()
        for old, new in zip(m['base_marker_manifest']['markers'], self.value.markers):
            self.assertEqual(old['original_offset'], new['original_offset'])
            self.assertEqual({k: v for k, v in old.items() if k != 'instrumented_offset'},
                             {k: v for k, v in new.items() if k != 'instrumented_offset'})
            shift = 14 * sum(x < old['instrumented_offset'] for x in m['definition_offsets'])
            self.assertEqual(new['instrumented_offset'], old['instrumented_offset'] + shift)
            pos = new['instrumented_offset']
            self.assertEqual(n_raw[pos:pos + len(new['text'].encode())], new['text'].encode())
        self.assertEqual(self.value.markers[0]['instrumented_offset'], m['base_marker_manifest']['markers'][0]['instrumented_offset'])

    def test_frozen_object_and_readonly_retained_source(self):
        with self.assertRaises(FrozenInstanceError):
            self.value.marker_source = ''
        with self.assertRaises(TypeError):
            self.value.retained_extra_sources['other'] = ''
        with self.assertRaises(TypeError):
            self.value.sources['other'] = ''
        self.assertEqual(dict(self.value.retained_extra_sources), {candidate.EXTRA_SOURCE_PATH: self.value.marker_source})
        transient = self.value.markers
        transient[0]['instrumented_offset'] = -1
        self.assertGreaterEqual(self.value.markers[0]['instrumented_offset'], 0)
        transient = self.value.manifest
        transient['definition_type_counts']['Raw'] = 0
        self.assertEqual(self.value.manifest['definition_type_counts']['Raw'], 158)

    def test_combined_manifest_and_complete_retained_source_budgets(self):
        m = self.value.manifest
        self.assertLessEqual(len(self.value.manifest_json.encode()), 32768)
        self.assertNotIn('markers', m)
        self.assertEqual(len(m['definition_offsets']), 1537)
        self.assertEqual(len(m['adjusted_marker_offsets']), 24)
        self.assertEqual(m['retained_total_source_bytes'], sum(x.source_bytes for x in self.prepared['stages']) + len(self.m_raw) + self.value.stages[2].source_bytes)
        with mock.patch.object(candidate, 'MAX_MANIFEST', len(self.value.manifest_json.encode()) - 1):
            self.reject(self.value)
        with mock.patch.object(candidate, 'MAX_SOURCE', self.value.stages[2].source_bytes - 1):
            self.reject(self.value)
        with mock.patch.object(candidate, 'MAX_TOTAL_SOURCE', m['retained_total_source_bytes'] - 1):
            self.reject(self.value)

    def test_missing_duplicate_extra_or_wrong_modifier_token(self):
        n = self.value.stages[2].source
        changed = (n.replace('noncomputable ', '', 1),
                   n.replace('noncomputable ', 'noncomputable noncomputable ', 1),
                   n.replace('noncomputable ', 'noncomputable  ', 1),
                   n.replace('noncomputable ', 'unsafe ', 1),
                   n + 'noncomputable def extra : List Nat := []\n')
        for source in changed:
            self.reject(self.rehash(source=source))

    def test_subset_permutation_duplicate_offset_and_numeric_type(self):
        for kind in ('subset', 'permutation', 'duplicate', 'offbyone', 'bool', 'float'):
            m = self.value.manifest
            offsets = m['definition_offsets']
            if kind == 'subset':
                offsets.pop()
            elif kind == 'permutation':
                offsets[0], offsets[1] = offsets[1], offsets[0]
            elif kind == 'duplicate':
                offsets[1] = offsets[0]
            elif kind == 'offbyone':
                offsets[0] += 1
            elif kind == 'bool':
                offsets[0] = True
            else:
                offsets[0] = float(offsets[0])
            self.reject(self.rehash(manifest=m))

    def test_same_count_relocated_modifier_to_theorem_rejected(self):
        m = self.value.manifest
        offsets = m['definition_offsets']
        offsets[-1] = self.m_raw.index(b'theorem linear_bounds ')
        chunks, cursor = [], 0
        for position in offsets:
            chunks.extend((self.m_raw[cursor:position], candidate.MODIFIER))
            cursor = position
        chunks.append(self.m_raw[cursor:])
        source = b''.join(chunks).decode()
        self.assertEqual(candidate.strip_noncomputable(source, offsets), self.m_raw)
        self.reject(self.rehash(source=source, manifest=m))

    def test_rehashed_rhs_name_type_function_and_codegen_edits(self):
        n = self.value.stages[2].source
        changes = (n.replace('linear_g0 :', 'linear_gX :', 1),
                   n.replace('linear_g0 : List Nat := [123]', 'linear_g0 : List Nat := [125]', 1),
                   n.replace('linear_g0 : List Nat', 'linear_g0 : Raw', 1),
                   n.replace('linear_g0 : List Nat', 'linear_g0 (x : Nat) : List Nat', 1),
                   n.replace('linear_g0 : List Nat := [123]', 'linear_g0 : List Nat := linear_g0', 1),
                   n.replace('linear_g0 : List Nat := [123]', 'linear_g0 : List Nat := linear_g1', 1),
                   n.replace('noncomputable def ', 'noncomputable partial def ', 1),
                   n.replace('noncomputable def ', 'noncomputable opaque ', 1),
                   n + 'set_option maxRecDepth 999999\n')
        for source in changes:
            self.assertNotEqual(source, n)
            self.reject(self.rehash(source=source))

    def test_rehashed_proof_inventory_marker_or_original_input_change(self):
        n = self.value.stages[2].source
        for source in (n.replace('withinBounds linearRaw = true', 'True', 1),
                       n.replace('#print axioms HiaCoreSyntaxSlice.linear_bounds\n', '', 1),
                       n.replace('HIA_DIAG_v1_LIN_000', 'HIA_DIAG_v1_LIN_999', 1)):
            self.reject(self.rehash(source=source))
        broken = {**self.prepared, 'canonical_bytes': b'{}'}
        with self.assertRaises(ValueError):
            candidate.build_noncomputable_diagnostic(broken)

    def test_stale_or_rehashed_marker_and_candidate_layer_binding(self):
        for field in ('original_manifest_sha256', 'base_marker_manifest_sha256',
                      'original_linear_source_sha256', 'candidate_linear_source_sha256',
                      'marker_linear_source_sha256'):
            m = self.value.manifest
            m[field] = '0' * 64
            self.reject(candidate.NoncomputableDiagnosticSources(self.value.stages, candidate.encode(m), self.value.marker_source))
        m = self.value.manifest
        m['base_marker_manifest']['markers'][0]['anchors'] = ['invented']
        m['base_marker_manifest_sha256'] = candidate.digest(candidate.encode(m['base_marker_manifest']).encode())
        self.reject(self.rehash(manifest=m))
        self.reject(self.rehash(marker_source=self.value.marker_source.replace('linear_g0', 'linear_g1', 1)))

    def test_stale_marker_offsets_and_type_counts_rejected(self):
        m = self.value.manifest
        m['adjusted_marker_offsets'] = [x['instrumented_offset'] for x in m['base_marker_manifest']['markers']]
        self.reject(self.rehash(manifest=m))
        for value in (157, 158.0, True):
            m = self.value.manifest
            m['definition_type_counts']['Raw'] = value
            self.reject(self.rehash(manifest=m))
        m = self.value.manifest
        m['definition_count'] = 1536
        self.reject(self.rehash(manifest=m))

    def test_nonacceptance_schedule_metadata_and_retained_path_fixed(self):
        self.assertEqual(self.value.stages[:2], self.prepared['stages'][:2])
        for field, value in (('acceptance_eligible', True), ('maximum_processes', 4),
                             ('maximum_processes', True), ('protocol', 'acceptance'),
                             ('retained_extra_source_path', '../outside.lean')):
            m = self.value.manifest
            m[field] = value
            self.reject(self.rehash(manifest=m))
        self.reject(candidate.NoncomputableDiagnosticSources(self.value.stages + (self.prepared['stages'][3],), self.value.manifest_json, self.value.marker_source))
        ss = (replace(self.value.stages[0], source=self.value.stages[0].source + '\n'),) + self.value.stages[1:]
        self.reject(self.rehash(stages=ss))

    def test_rehashed_float_stage_byte_counts_rejected_in_both_layers(self):
        for nested in (False, True):
            m = self.value.manifest
            bindings = m['base_marker_manifest']['stages'] if nested else m['stages']
            bindings[2]['source_bytes'] = float(bindings[2]['source_bytes'])
            if nested:
                m['base_marker_manifest_sha256'] = candidate.digest(candidate.encode(m['base_marker_manifest']).encode())
            self.reject(candidate.NoncomputableDiagnosticSources(self.value.stages, candidate.encode(m), self.value.marker_source))

    def test_manifest_extra_keys_overflow_and_noncanonical_json(self):
        for value in ('unexpected', 'x' * candidate.MAX_MANIFEST):
            m = self.value.manifest
            m['extra'] = value
            self.reject(self.rehash(manifest=m))
        self.reject(replace(self.value, manifest_json=self.value.manifest_json + '\n'))

    def test_data_family_parser_rejects_unsupported_declaration_shapes(self):
        source = self.prepared['stages'][2].source
        for changed in (source.replace('def linear_g0 :', 'def linear_g0 (x : Nat) :', 1),
                        source.replace('def linear_g0 : List Nat', 'def linear_g0 : String', 1),
                        source.replace('def linear_g0', 'unsafe def linear_g0', 1),
                        source.replace('def linear_g0', 'noncomputable def linear_g0', 1)):
            with self.assertRaises(ValueError):
                candidate._eligible_definitions(changed)

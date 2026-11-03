"""Single-factor noncomputable-data diagnostic derivative, never acceptance.

O is the complete original source; M adds reviewed position markers; N inserts
only the fixed noncomputable token before the entire reviewed data family.
This module does not change formal validators or execute Lean.
"""
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, replace
import json
import re
from types import MappingProxyType

from tools import core_syntax_declaration_diagnostic_sources as marker
from tools.check_guarded_slice_lean import require

PROTOCOL = 'noncomputable-data-declaration-diagnostic-v1'
MODIFIER = b'noncomputable '
DEFINITION_COUNT = 1537
TYPE_COUNTS = {'List Nat': 1223, 'Raw': 158, 'List (List Nat × Raw)': 94, 'List Raw': 62}
MAX_MANIFEST = 32 * 1024
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
EXTRA_SOURCE_PATH = 'marker-original/LinearTransport.lean'
digest, encode = marker.digest, marker.encode


@dataclass(frozen=True)
class NoncomputableDiagnosticSources:
    stages: tuple
    manifest_json: str
    marker_source: str

    @property
    def manifest(self):
        return json.loads(self.manifest_json)

    @property
    def manifest_sha256(self):
        return digest(self.manifest_json.encode('utf-8'))

    @property
    def sources(self):
        return MappingProxyType({s.module_name: s.source for s in self.stages})

    @property
    def retained_extra_sources(self):
        return MappingProxyType({EXTRA_SOURCE_PATH: self.marker_source})

    @property
    def markers(self):
        manifest = self.manifest
        return [{**entry, 'instrumented_offset': offset}
                for entry, offset in zip(manifest['base_marker_manifest']['markers'],
                                         manifest['adjusted_marker_offsets'])]


def _eligible_definitions(original_source):
    """Read full declarations from independently validated O, never from N."""
    raw = original_source.encode('utf-8')
    rows = []
    for command in marker._commands(original_source):
        if command['kind'] != 'def':
            continue
        text = raw[command['start']:command['end']].decode('utf-8')
        match = re.fullmatch(r'def ([A-Za-z][A-Za-z0-9_]*) : (Raw|List Nat|List Raw|List \(List Nat × Raw\)) := ([^\n]+)\n', text)
        require(match is not None, 'eligible data must be a closed parameterless single-line definition')
        name, type_name, rhs = match.groups()
        rows.append({'offset': command['start'], 'name': name, 'type': type_name,
                     'rhs_sha256': digest(rhs.encode())})
    require(len(rows) == DEFINITION_COUNT and dict(Counter(r['type'] for r in rows)) == TYPE_COUNTS,
            'complete reviewed noncomputable data family')
    return rows


def _definition_offsets(prepared, base):
    original = prepared['stages'][2].source
    rows = _eligible_definitions(original)
    # Existing independent full-source validation also parses every RHS and
    # rejects self/forward references and unsupported expression forms.
    original_definitions = prepared['structured_certificates']['linear']['manifest']['definitions']
    require([{'name': r['name'], 'type': r['type'], 'rhs_sha256': r['rhs_sha256']} for r in rows]
            == original_definitions, 'independent original declaration family binding')
    markers = base.manifest['markers']
    offsets = [r['offset'] + sum(len(m['text'].encode('ascii')) for m in markers
                                if m['original_offset'] <= r['offset']) for r in rows]
    m_raw = base.stages[2].source.encode('utf-8')
    actual = list(re.finditer(rb'(?m)^def ([A-Za-z][A-Za-z0-9_]*) : ([^\n]+?) := ', m_raw))
    require([m.start() for m in actual] == offsets and
            [m.group(1).decode() for m in actual] == [r['name'] for r in rows] and
            [m.group(2).decode() for m in actual] == [r['type'] for r in rows],
            'complete O-to-M definition boundary mapping')
    return offsets


def strip_noncomputable(source, offsets):
    """Independent exact interval deletion, without normalizing Lean text."""
    require(type(source) is str and len(source.encode('utf-8')) <= MAX_SOURCE,
            'candidate source type/byte cap')
    require(type(offsets) is list and len(offsets) == DEFINITION_COUNT and
            all(type(x) is int and x >= 0 for x in offsets) and
            all(a < b for a, b in zip(offsets, offsets[1:])), 'complete strictly ordered definition offsets')
    raw = source.encode('utf-8')
    chunks, cursor = [], 0
    for i, offset in enumerate(offsets):
        pos = offset + i * len(MODIFIER)
        require(cursor <= pos and pos + len(MODIFIER) <= len(raw) and
                raw[pos:pos + len(MODIFIER)] == MODIFIER, 'exact noncomputable insertion token/position')
        chunks.append(raw[cursor:pos])
        cursor = pos + len(MODIFIER)
    chunks.append(raw[cursor:])
    return b''.join(chunks)


def build_noncomputable_diagnostic(prepared):
    # This performs the original full-DAG checks before any N derivation.
    base = marker.build_diagnostic_sources(prepared)
    offsets = _definition_offsets(prepared, base)
    m_raw = base.stages[2].source.encode('utf-8')
    chunks, cursor = [], 0
    for offset in offsets:
        chunks.extend((m_raw[cursor:offset], MODIFIER))
        cursor = offset
    chunks.append(m_raw[cursor:])
    source = b''.join(chunks).decode('utf-8')
    stages = base.stages[:2] + (replace(base.stages[2], source=source),)
    adjusted = [entry['instrumented_offset'] + len(MODIFIER) * bisect_left(offsets, entry['instrumented_offset'])
                for entry in base.manifest['markers']]
    original_total = sum(s.source_bytes for s in prepared['stages'])
    manifest = {'schema': 'hepta.hia.noncomputable-diagnostic-sources.v1', 'protocol': PROTOCOL,
                'acceptance_eligible': False, 'maximum_processes': 3,
                'original_manifest_sha256': prepared['manifest_sha256'],
                'base_marker_manifest': base.manifest, 'base_marker_manifest_sha256': base.manifest_sha256,
                'modifier': MODIFIER.decode('ascii'), 'definition_count': DEFINITION_COUNT,
                'definition_type_counts': TYPE_COUNTS.copy(), 'definition_offsets': offsets,
                'adjusted_marker_offsets': adjusted,
                'original_linear_source_sha256': prepared['stages'][2].source_sha256,
                'marker_linear_source_sha256': digest(m_raw),
                'candidate_linear_source_sha256': digest(source.encode('utf-8')),
                'original_linear_source_bytes': prepared['stages'][2].source_bytes,
                'marker_linear_source_bytes': len(m_raw), 'candidate_linear_source_bytes': len(source.encode('utf-8')),
                'original_total_source_bytes': original_total,
                'retained_total_source_bytes': original_total + len(m_raw) + len(source.encode('utf-8')),
                'retained_extra_source_path': EXTRA_SOURCE_PATH,
                'stages': marker._stage_bindings(prepared, stages)}
    require(len(source.encode()) <= MAX_SOURCE and manifest['retained_total_source_bytes'] <= MAX_TOTAL_SOURCE,
            'complete O/M/N source byte budgets')
    require(len(encode(manifest).encode()) <= MAX_MANIFEST, 'combined two-layer manifest byte cap')
    result = NoncomputableDiagnosticSources(stages, encode(manifest), base.stages[2].source)
    validate_noncomputable_diagnostic(prepared, result)
    return result


def validate_noncomputable_diagnostic(prepared, candidate):
    require(isinstance(candidate, NoncomputableDiagnosticSources), 'frozen noncomputable candidate required')
    require(type(candidate.manifest_json) is str and len(candidate.manifest_json.encode()) <= MAX_MANIFEST,
            'combined two-layer manifest byte cap')
    m = candidate.manifest
    fields = {'schema', 'protocol', 'acceptance_eligible', 'maximum_processes',
              'original_manifest_sha256', 'base_marker_manifest', 'base_marker_manifest_sha256',
              'modifier', 'definition_count', 'definition_type_counts', 'definition_offsets',
              'adjusted_marker_offsets', 'original_linear_source_sha256', 'marker_linear_source_sha256',
              'candidate_linear_source_sha256', 'original_linear_source_bytes', 'marker_linear_source_bytes',
              'candidate_linear_source_bytes', 'original_total_source_bytes', 'retained_total_source_bytes',
              'retained_extra_source_path', 'stages'}
    require(type(m) is dict and set(m) == fields and candidate.manifest_json == encode(m), 'exact canonical candidate manifest schema')
    require(m['schema'] == 'hepta.hia.noncomputable-diagnostic-sources.v1' and m['protocol'] == PROTOCOL and
            m['acceptance_eligible'] is False and type(m['maximum_processes']) is int and m['maximum_processes'] == 3,
            'nonaccepting three-stage candidate protocol')
    for field in ('definition_count', 'original_linear_source_bytes', 'marker_linear_source_bytes',
                  'candidate_linear_source_bytes', 'original_total_source_bytes', 'retained_total_source_bytes'):
        require(type(m[field]) is int, 'integer candidate count/size field')
    require(m['modifier'] == MODIFIER.decode('ascii') and m['definition_count'] == DEFINITION_COUNT and
            type(m['definition_type_counts']) is dict and
            all(type(v) is int for v in m['definition_type_counts'].values()) and
            m['definition_type_counts'] == TYPE_COUNTS, 'exact modifier and full data type inventory')
    require(type(candidate.stages) is tuple and len(candidate.stages) == 3 and
            tuple(s.name for s in candidate.stages) == marker.SCHEDULED and
            candidate.stages[:2] == prepared['stages'][:2], 'unchanged first two and exactly three candidate stages')
    require(type(candidate.marker_source) is str and len(candidate.marker_source.encode()) <= MAX_SOURCE,
            'retained M source type/size')
    require(replace(candidate.stages[2], source=prepared['stages'][2].source) == prepared['stages'][2],
            'only third-stage source may change')
    require(m['retained_extra_source_path'] == EXTRA_SOURCE_PATH, 'fixed retained M path')
    n_raw, m_raw = candidate.stages[2].source.encode(), candidate.marker_source.encode()
    require(strip_noncomputable(candidate.stages[2].source, m['definition_offsets']) == m_raw,
            'independent N-to-M exact source recovery')
    base_json = encode(m['base_marker_manifest'])
    require(digest(base_json.encode()) == m['base_marker_manifest_sha256'], 'frozen base marker manifest hash')
    base = marker.DiagnosticSources(candidate.stages[:2] +
        (replace(candidate.stages[2], source=candidate.marker_source),), base_json)
    # The unchanged validator establishes all O input/proof bindings and exact
    # M marker placement. N is never handed to a relaxed original parser.
    marker.validate_diagnostic_sources(prepared, base)
    require(encode(m['base_marker_manifest']['stages']) ==
            encode(marker._stage_bindings(prepared, base.stages)),
            'canonical base marker stage bindings')
    offsets = _definition_offsets(prepared, base)
    require(m['definition_offsets'] == offsets, 'entire independently derived eligible offset family')
    original = marker.strip_markers(candidate.marker_source, m['base_marker_manifest'])
    require(original == prepared['stages'][2].source.encode(), 'independent M-to-O exact source recovery')
    adjusted = [entry['instrumented_offset'] + len(MODIFIER) * bisect_left(offsets, entry['instrumented_offset'])
                for entry in base.manifest['markers']]
    require(type(m['adjusted_marker_offsets']) is list and all(type(x) is int for x in m['adjusted_marker_offsets']) and
            m['adjusted_marker_offsets'] == adjusted, 'exact adjusted N marker coordinate array')
    for entry, pos in zip(base.manifest['markers'], adjusted):
        raw_marker = entry['text'].encode('ascii')
        old_pos = entry['instrumented_offset']
        require(m_raw[old_pos:old_pos + len(raw_marker)] == raw_marker and
                n_raw[pos:pos + len(raw_marker)] == raw_marker, 'marker bytes at M and N coordinates')
    original_total = sum(s.source_bytes for s in prepared['stages'])
    require(m['original_manifest_sha256'] == prepared['manifest_sha256'] and
            m['original_linear_source_sha256'] == digest(original) and
            m['marker_linear_source_sha256'] == digest(m_raw) and
            m['candidate_linear_source_sha256'] == digest(n_raw), 'O/M/N and preparation hash identities')
    require(m['original_linear_source_bytes'] == len(original) and m['marker_linear_source_bytes'] == len(m_raw) and
            m['candidate_linear_source_bytes'] == len(n_raw) and len(n_raw) - len(m_raw) == DEFINITION_COUNT * len(MODIFIER) and
            m['original_total_source_bytes'] == original_total and
            m['retained_total_source_bytes'] == original_total + len(m_raw) + len(n_raw), 'complete retained O/M/N source accounting')
    require(len(n_raw) <= MAX_SOURCE and original_total + len(m_raw) + len(n_raw) <= MAX_TOTAL_SOURCE,
            'complete O/M/N source byte budgets')
    require(encode(m['stages']) == encode(marker._stage_bindings(prepared, candidate.stages)), 'exact canonical candidate stage bindings')
    require(candidate.markers == [{**entry, 'instrumented_offset': pos}
                                 for entry, pos in zip(base.manifest['markers'], adjusted)], 'current marker view')
    return {'definition_count': DEFINITION_COUNT, 'added_source_bytes': len(n_raw) - len(m_raw),
            'candidate_source_bytes': len(n_raw), 'retained_total_source_bytes': m['retained_total_source_bytes'],
            'combined_manifest_bytes': len(candidate.manifest_json.encode()), 'acceptance_eligible': False}

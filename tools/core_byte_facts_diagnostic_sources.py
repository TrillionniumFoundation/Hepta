"""Bounded reversible reporting markers over authenticated byte-fact sources.

This is a separate nonaccepting four-stage diagnostic, not proof completion,
Lean execution, or full-DAG acceptance. The original exact11 oracle and the
independent insertion checker remain mandatory before marker validation.
"""
from dataclasses import replace

from tools import core_byte_facts_sources as facts
from tools import core_syntax_partition_sources as original
from tools import core_syntax_declaration_diagnostic_sources as framing
from tools.check_guarded_slice_lean import require
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS

PROTOCOL = 'compositional-byte-facts-position-diagnostic-v1'
SCHEMA = 'hepta.hia.byte-facts-position-diagnostic.v1'
SCHEDULED = original.NAMES[:4]
NOT_SCHEDULED = original.NAMES[4:]
MAX_MARKERS = 24
MAX_MANIFEST = 32768
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
DiagnosticSources = framing.DiagnosticSources
digest = framing.digest
encode = framing.encode


def _sites(proposal):
    commands = framing._commands(proposal.stages[3].source)
    by_name = {}
    for command in commands:
        if command['kind'] in ('def', 'theorem'):
            require(command['name'] not in by_name, 'unique byte-fact diagnostic anchors')
            by_name[command['name']] = command
    theorems = [c for c in commands if c['kind'] == 'theorem']
    require(len(theorems) == 1298 and len(by_name) == 2715, 'complete transformed Part02 declaration inventory')
    candidates = []
    def boundary(name, side, label):
        require(name in by_name, 'missing named byte-fact diagnostic anchor')
        candidates.append((by_name[name]['start' if side == 'before' else 'end'], label))
    boundary(theorems[0]['name'], 'before', 'before_first_theorem')
    roots = ('linear_bounds', 'linear_serialized', 'linear_parsed', 'linear_length',
             'linear_byte_range', 'linear_transport')
    boundary(roots[0], 'before', 'before_linear_roots')
    for name in roots:
        boundary(name, 'after', 'after_' + name)
    for ordinal in (0, 63, 127, 255, 383, 511, 594):
        name = 'linear_bf%04d' % ordinal
        for side in ('before', 'after'):
            boundary(name, side, side + '_' + name)
    printed = [c for c in commands if c['kind'] == 'print']
    require(len(printed) == 1298 and commands[-1298:] == printed, 'complete transformed print suffix')
    require(set(c['name'] for c in printed) == proposal.stages[3].expected_theorems,
            'full transformed print inventory')
    candidates.extend(((printed[0]['start'], 'before_final_inventory'),
                       (printed[-1]['end'], 'after_final_inventory')))
    require(len(candidates) == MAX_MARKERS, 'fixed candidate boundary selection')
    grouped = {}
    for offset, label in candidates:
        grouped.setdefault(offset, []).append(label)
    sites = []
    for offset, labels in sorted(grouped.items()):
        previous = [c for c in commands if c['end'] == offset]
        following = [c for c in commands if c['start'] == offset]
        require(len(previous) <= 1 and len(following) <= 1 and (previous or following),
                'marker must be at a complete transformed command boundary')
        sites.append(dict(original_offset=offset, anchors=sorted(labels),
                          previous_command=previous[0] if previous else None,
                          next_command=following[0] if following else None))
    require(0 < len(sites) <= MAX_MARKERS, 'marker count cap')
    return sites


def _marker(index):
    require(type(index) is int and 0 <= index < MAX_MARKERS, 'bounded marker ID')
    ident = 'HIA_DIAG_v1_P02_%03d' % index
    return ident, '#check "' + ident + '"\n'


def strip_markers(source, manifest):
    """Remove exact intervals only; original_offset refers to transformed text."""
    require(type(source) is str and type(manifest) is dict and manifest.get('protocol') == PROTOCOL,
            'byte-facts diagnostic strip protocol and types')
    raw = source.encode()
    require(len(raw) <= MAX_SOURCE, 'marked file cap')
    markers = manifest.get('markers')
    require(type(markers) is list and 0 < len(markers) <= MAX_MARKERS, 'bounded marker inventory')
    chunks, cursor, restored_size, previous = [], 0, 0, -1
    fields = {'original_offset', 'anchors', 'previous_command', 'next_command',
              'id', 'text', 'sha256', 'instrumented_offset'}
    for index, marker in enumerate(markers):
        require(type(marker) is dict and set(marker) == fields, 'exact marker schema')
        ident = 'HIA_DIAG_v1_P02_' + str(index).zfill(3)
        text = '#check \"' + ident + '\"\n'
        block = text.encode()
        offset, original_offset = marker['instrumented_offset'], marker['original_offset']
        require(type(offset) is int and type(original_offset) is int and
                cursor <= offset <= len(raw)-len(block) and original_offset > previous,
                'ordered nonoverlapping marker intervals')
        require(marker['id'] == ident and marker['text'] == text and marker['sha256'] == digest(block)
                and raw[offset:offset+len(block)] == block, 'fixed exact marker command')
        chunks.append(raw[cursor:offset]); restored_size += offset-cursor
        require(restored_size == original_offset, 'unmarked transformed offset binding')
        cursor = offset+len(block); previous = original_offset
    chunks.append(raw[cursor:])
    restored = b''.join(chunks)
    require(b'#check ' not in restored and b'HIA_DIAG_' not in restored, 'unrecorded marker remains')
    return restored


def _bindings(proposal, stages):
    bindings = framing._stage_bindings({'stages': proposal.stages}, stages)
    for stage, binding in zip(stages, bindings):
        binding['inventory_count'] = len(stage.expected_theorems)
        binding['inventory_sha256'] = digest(encode(sorted(stage.expected_theorems)).encode())
    return bindings


def _derive(prepared, proposal):
    raw = proposal.stages[3].source.encode()
    chunks, markers, cursor, added = [], [], 0, 0
    for index, site in enumerate(_sites(proposal)):
        ident, text = _marker(index)
        block = text.encode(); offset = site['original_offset']
        chunks.extend((raw[cursor:offset], block))
        markers.append({**site, 'id': ident, 'text': text, 'sha256': digest(block),
                        'instrumented_offset': offset+added})
        added += len(block); cursor = offset
    chunks.append(raw[cursor:])
    marked = b''.join(chunks)
    stages = proposal.stages[:3] + (replace(proposal.stages[3], source=marked.decode()),)
    old_total = sum(s.source_bytes for s in prepared['stages'])
    transformed_total = sum(s.source_bytes for s in proposal.stages)
    retained = old_total + transformed_total + len(marked)
    require(all(s.source_bytes <= MAX_SOURCE for s in prepared['stages'] + proposal.stages + stages)
            and retained <= MAX_TOTAL_SOURCE, 'all original transformed and marked source budgets')
    manifest = dict(schema=SCHEMA, protocol=PROTOCOL, acceptance_eligible=False,
        source_only=True, maximum_processes=4, scheduled_stage_names=list(SCHEDULED),
        not_scheduled_stage_names=list(NOT_SCHEDULED), target='CertPart02',
        original_manifest_sha256=prepared['manifest_sha256'],
        transformation_manifest_sha256=proposal.manifest_sha256,
        original_target_source_sha256=digest(raw), diagnostic_target_source_sha256=digest(marked),
        original_target_source_bytes=len(raw), diagnostic_target_source_bytes=len(marked),
        original_total_source_bytes=old_total, transformed_total_source_bytes=transformed_total,
        retained_total_source_bytes=retained, candidate_site_count=MAX_MARKERS,
        marker_count=len(markers), markers=markers, stages=_bindings(proposal, stages),
        kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
        python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
        all_edge_transfer_proved=False,
        obligations=[dict(id=n,status='unproved') for n,_ in OBLIGATIONS], **DENY)
    encoded = encode(manifest)
    require(len(encoded.encode()) <= MAX_MANIFEST, 'bounded marker manifest')
    return DiagnosticSources(stages, encoded)


def build_diagnostic_sources(prepared, proposal):
    facts.validate_sources(prepared, proposal)
    diagnostic = _derive(prepared, proposal)
    _validate_markers(prepared, proposal, diagnostic)
    return diagnostic


def _validate_markers(prepared, proposal, diagnostic):
    require(isinstance(diagnostic, DiagnosticSources) and type(diagnostic.stages) is tuple and
            tuple(s.name for s in diagnostic.stages) == SCHEDULED, 'exact four transformed diagnostic stages')
    require(type(diagnostic.manifest_json) is str and len(diagnostic.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded diagnostic manifest')
    manifest = diagnostic.manifest
    require(manifest.get('protocol') == PROTOCOL and manifest.get('schema') == SCHEMA and
            diagnostic.manifest_json == encode(manifest), 'separate canonical byte-facts diagnostic protocol')
    require(diagnostic.stages[:3] == proposal.stages[:3], 'fresh transformed parent sources unchanged')
    actual, target = diagnostic.stages[3], proposal.stages[3]
    require(replace(actual, source=target.source) == target, 'only Part02 marker text may change')
    require(strip_markers(actual.source, manifest) == target.source.encode(), 'exact transformed source recovery')
    # A second deterministic reconstruction validates the complete anchor
    # metadata; exact interval removal above is the independent byte inverse.
    expected = _derive(prepared, proposal)
    require(diagnostic == expected, 'exact diagnostic markers, anchors, inventories and accounting')
    return dict(marker_count=manifest['marker_count'], acceptance_eligible=False, authority='DENY_ALL',
                diagnostic_source_bytes=actual.source_bytes,
                retained_total_source_bytes=manifest['retained_total_source_bytes'])


def validate_diagnostic_sources(prepared, proposal, diagnostic):
    facts.validate_sources(prepared, proposal)
    return _validate_markers(prepared, proposal, diagnostic)

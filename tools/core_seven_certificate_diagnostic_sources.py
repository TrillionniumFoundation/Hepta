"""Four fixed reversible reporting markers over authenticated seven-part sources.

This is a separate nonaccepting four-stage diagnostic, not proof completion,
Lean execution, or full-DAG acceptance. The original exact11 oracle and the
independent insertion checker remain mandatory before marker validation.
"""
from dataclasses import replace

from tools import core_seven_certificate_sources as seven
from tools import core_syntax_partition_sources as original
from tools import core_syntax_declaration_diagnostic_sources as framing
from tools.check_guarded_slice_lean import require
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS

PROTOCOL = 'seven-certificate-first-four-diagnostic-v1'
SCHEMA = 'hepta.hia.seven-certificate-first-four-diagnostic.v1'
SCHEDULED = seven.NAMES[:4]
NOT_SCHEDULED = seven.NAMES[4:]
MAX_MARKERS = 24
PLANNED_MARKERS = 4
MAX_MANIFEST = 32768
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
TARGET_SOURCE_BYTES = 22083
TARGET_SOURCE_SHA256 = '10f92e1cbcaa1b0623b7eb6b4203bd47fa5ad574e23ef8d11e8d0000f7c5002d'
DiagnosticSources = framing.DiagnosticSources
digest = framing.digest
encode = framing.encode


def _sites(proposal):
    commands = framing._commands(proposal.stages[3].source)
    declarations = [c for c in commands if c['kind'] in ('def', 'theorem')]
    by_name = {c['name']: c for c in declarations}
    theorems = [c for c in declarations if c['kind'] == 'theorem']
    require(len(declarations) == len(by_name) == 96 and len(theorems) == 54,
            'exact target declaration and theorem inventories')
    require(declarations[0]['name'] == 'linear_k3_0' and
            theorems[0]['name'] == 'linear_kd3_0' and theorems[-1]['name'] == 'linear_p0',
            'fixed target extent')
    printed = [c for c in commands if c['kind'] == 'print']
    require(len(printed) == 54 and commands[-54:] == printed and
            set(c['name'] for c in printed) == proposal.stages[3].expected_theorems,
            'exact final target inventory suffix')
    candidates = [(by_name['linear_k3_0']['start'], 'before:HiaCoreSyntaxSlice.linear_k3_0')]
    for name, ordinal in (('linear_p3', 810), ('linear_p2', 814), ('linear_p0', 837)):
        require(theorems[ordinal - 784]['name'] == name, 'frozen original theorem ordinal')
        candidates.append((by_name[name]['end'], 'after:HiaCoreSyntaxSlice.' + name + ':ordinal=' + str(ordinal)))
    require(tuple(x[0] for x in candidates) == (65, 10206, 11746, 19464), 'frozen byte sites')
    return [dict(original_offset=offset, anchors=[anchor],
                 previous_command=next((c for c in commands if c['end'] == offset), None),
                 next_command=next((c for c in commands if c['start'] == offset), None))
            for offset, anchor in candidates]


def _marker(index):
    require(type(index) is int and 0 <= index < PLANNED_MARKERS, 'bounded marker ID')
    ident = 'HIA_SEVEN_DIAG_v1_P02_%03d' % index
    return ident, '#check "' + ident + '"\n'


def strip_markers(source, manifest):
    """Remove exact intervals only; original_offset refers to transformed text."""
    require(type(source) is str and type(manifest) is dict and manifest.get('protocol') == PROTOCOL,
            'seven-certificate diagnostic strip protocol and types')
    raw = source.encode()
    require(len(raw) <= MAX_SOURCE, 'marked file cap')
    markers = manifest.get('markers')
    require(type(markers) is list and len(markers) == PLANNED_MARKERS, 'bounded marker inventory')
    chunks, cursor, restored_size, previous = [], 0, 0, -1
    fields = {'original_offset', 'anchors', 'previous_command', 'next_command',
              'id', 'text', 'sha256', 'instrumented_offset'}
    for index, marker in enumerate(markers):
        require(type(marker) is dict and set(marker) == fields, 'exact marker schema')
        ident = 'HIA_SEVEN_DIAG_v1_P02_' + str(index).zfill(3)
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
    require(b'#check ' not in restored and b'HIA_DIAG_' not in restored and b'HIA_SEVEN_DIAG_' not in restored, 'unrecorded marker remains')
    return restored


def _bindings(proposal, stages):
    bindings = framing._stage_bindings({'stages': proposal.stages}, stages)
    for stage, binding in zip(stages, bindings):
        binding['inventory_count'] = len(stage.expected_theorems)
        binding['inventory_sha256'] = digest(encode(sorted(stage.expected_theorems)).encode())
    return bindings


def retained_sources(prepared, proposal, stages):
    return {**{'original/' + s.name + '.lean': s.source for s in prepared['stages']},
            **{(s.module_name.replace('.', '/') if i < 3 else 'seven/' + s.name) + '.lean': s.source
               for i, s in enumerate(proposal.stages)},
            stages[3].module_name.replace('.', '/') + '.lean': stages[3].source}


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
    retained = seven.validate_retention(proposal, (marked.decode(),))
    require(retained == old_total + transformed_total + len(marked), 'actual retention accounting')
    require(all(s.source_bytes <= MAX_SOURCE for s in prepared['stages'] + proposal.stages + stages)
            and retained <= MAX_TOTAL_SOURCE, 'all original transformed and marked source budgets')
    manifest = dict(schema=SCHEMA, protocol=PROTOCOL, acceptance_eligible=False,
        source_only=True, maximum_processes=4, scheduled_stage_names=list(SCHEDULED),
        not_scheduled_stage_names=list(NOT_SCHEDULED), target='SevenCertificatePart02',
        original_manifest_sha256=prepared['manifest_sha256'],
        seven_manifest_sha256=proposal.manifest_sha256,
        original_target_source_sha256=digest(raw), diagnostic_target_source_sha256=digest(marked),
        original_target_source_bytes=len(raw), diagnostic_target_source_bytes=len(marked),
        original_total_source_bytes=old_total, transformed_total_source_bytes=transformed_total,
        retained_total_source_bytes=retained, candidate_site_count=PLANNED_MARKERS,
        marker_count=len(markers), markers=markers, stages=_bindings(proposal, stages),
        retained_paths={name: dict(bytes=len(text.encode()), sha256=digest(text.encode()))
                        for name,text in retained_sources(prepared, proposal, stages).items()},
        kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
        python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
        all_edge_transfer_proved=False,
        obligations=[dict(id=n,status='unproved') for n,_ in OBLIGATIONS], **DENY)
    encoded = encode(manifest)
    require(len(encoded.encode()) <= MAX_MANIFEST, 'bounded marker manifest')
    return DiagnosticSources(stages, encoded)


def build_diagnostic_sources(prepared, proposal):
    seven.validate_sources(prepared, proposal)
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
            diagnostic.manifest_json == encode(manifest), 'separate canonical seven-certificate diagnostic protocol')
    require(diagnostic.stages[:3] == proposal.stages[:3], 'fresh transformed parent sources unchanged')
    actual, target = diagnostic.stages[3], proposal.stages[3]
    require(actual.source_bytes == TARGET_SOURCE_BYTES and actual.source_sha256 == TARGET_SOURCE_SHA256,
            'frozen instrumented target identity')
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
    seven.validate_sources(prepared, proposal)
    return _validate_markers(prepared, proposal, diagnostic)

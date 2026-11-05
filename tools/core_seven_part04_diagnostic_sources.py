"""Eleven fixed reversible reporting markers over authenticated seven-part sources.

This is a separate nonaccepting six-stage diagnostic, not proof completion,
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

PROTOCOL = 'seven-certificate-first-six-diagnostic-v1'
SCHEMA = 'hepta.hia.seven-certificate-first-six-diagnostic.v1'
SCHEDULED = seven.NAMES[:6]
NOT_SCHEDULED = seven.NAMES[6:]
MAX_MARKERS = 24
PLANNED_MARKERS = 11
MAX_MANIFEST = 32768
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
TARGET_SOURCE_BYTES = 551195
TARGET_SOURCE_SHA256 = 'e2f6c4730ac5df1bc703fc7a53a92f6e616822f1d61a7569548ceb62a2b75429'
DiagnosticSources = framing.DiagnosticSources
digest = framing.digest
encode = framing.encode


def _sites(proposal):
    target = proposal.stages[5]
    require(target.source_bytes == 550810 and target.source_sha256 ==
            'a4fdf6b42713f4ff028ec7f2febbfcd1e5e3eb862a86d897b31c8375295140a7',
            'frozen original Part04 identity')
    commands = framing._commands(target.source)
    declarations = [c for c in commands if c['kind'] in ('def', 'theorem')]
    by_name = {c['name']: c for c in declarations}
    theorems = [c for c in declarations if c['kind'] == 'theorem']
    original_theorems = [c for c in theorems if '_bf' not in c['name']]
    require(len(declarations) == len(by_name) == 2714 and len(theorems) == 1298
            and len(original_theorems) == 703, 'exact target declaration and theorem inventories')
    require(declarations[0]['name'] == 'parallel_r113' and
            declarations[-1]['name'] == 'mutated_kd87_0', 'fixed target extent')
    printed = [c for c in commands if c['kind'] == 'print']
    require(len(printed) == 1298 and commands[-1298:] == printed and
            set(c['name'] for c in printed) == target.expected_theorems,
            'exact final target inventory suffix')
    candidates = [(by_name['parallel_r113']['start'], 'before:HiaCoreSyntaxSlice.parallel_r113')]
    for name, ordinal in (('parallel_p3', 1653), ('parallel_p2', 1657),
                          ('parallel_p0', 1680), ('parallel_bounds', 1681),
                          ('parallel_parsed', 1683)):
        require(original_theorems[ordinal - 1407]['name'] == name,
                'frozen original theorem ordinal')
        candidates.append((by_name[name]['end'], 'after:HiaCoreSyntaxSlice.' + name + ':ordinal=' + str(ordinal)))
    candidates.append((by_name['parallel_bf0594']['end'], 'after:HiaCoreSyntaxSlice.parallel_bf0594'))
    for name, qualified, ordinal in (
            ('parallel_transport', 'HiaCoreSyntaxSlice.parallel_transport', 1686),
            ('mutated_kd87_0', 'HiaCoreSyntaxSlice.WrongPhi.mutated_kd87_0', 2109)):
        require(original_theorems[ordinal - 1407]['name'] == name,
                'frozen original theorem ordinal')
        candidates.append((by_name[name]['end'], 'after:' + qualified + ':ordinal=' + str(ordinal)))
    candidates.extend(((printed[0]['start'], 'before_final_inventory'),
                       (printed[-1]['end'], 'after_final_inventory')))
    require(tuple(x[0] for x in candidates) ==
            (65, 102701, 104333, 112569, 112729, 113075, 243492, 243951,
             484546, 484578, 550810), 'frozen byte sites')
    sites = []
    for offset, anchor in candidates:
        previous = [c for c in commands if c['end'] == offset]
        following = [c for c in commands if c['start'] == offset]
        require(len(previous) == 1 and len(following) <= 1 and
                (following or offset == target.source_bytes), 'exact command boundary')
        sites.append(dict(original_offset=offset, anchors=[anchor],
                          previous_command=previous[0],
                          next_command=following[0] if following else None))
    return sites


def _marker(index):
    require(type(index) is int and 0 <= index < PLANNED_MARKERS, 'bounded marker ID')
    ident = 'HIA_SEVEN_DIAG_v1_P04_%03d' % index
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
        ident = 'HIA_SEVEN_DIAG_v1_P04_' + str(index).zfill(3)
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
            **{(s.module_name.replace('.', '/') if i < 5 else 'seven/' + s.name) + '.lean': s.source
               for i, s in enumerate(proposal.stages)},
            stages[5].module_name.replace('.', '/') + '.lean': stages[5].source}


def _derive(prepared, proposal):
    raw = proposal.stages[5].source.encode()
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
    stages = proposal.stages[:5] + (replace(proposal.stages[5], source=marked.decode()),)
    old_total = sum(s.source_bytes for s in prepared['stages'])
    transformed_total = sum(s.source_bytes for s in proposal.stages)
    retained = seven.validate_retention(proposal, (marked.decode(),))
    require(retained == old_total + transformed_total + len(marked), 'actual retention accounting')
    require(all(s.source_bytes <= MAX_SOURCE for s in prepared['stages'] + proposal.stages + stages)
            and retained <= MAX_TOTAL_SOURCE, 'all original transformed and marked source budgets')
    manifest = dict(schema=SCHEMA, protocol=PROTOCOL, acceptance_eligible=False,
        source_only=True, maximum_processes=6, scheduled_stage_names=list(SCHEDULED),
        not_scheduled_stage_names=list(NOT_SCHEDULED), target='SevenCertificatePart04',
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
            tuple(s.name for s in diagnostic.stages) == SCHEDULED, 'exact six transformed diagnostic stages')
    require(type(diagnostic.manifest_json) is str and len(diagnostic.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded diagnostic manifest')
    manifest = diagnostic.manifest
    require(manifest.get('protocol') == PROTOCOL and manifest.get('schema') == SCHEMA and
            diagnostic.manifest_json == encode(manifest), 'separate canonical seven-certificate diagnostic protocol')
    require(diagnostic.stages[:5] == proposal.stages[:5], 'fresh transformed parent sources unchanged')
    actual, target = diagnostic.stages[5], proposal.stages[5]
    require(actual.source_bytes == TARGET_SOURCE_BYTES and actual.source_sha256 == TARGET_SOURCE_SHA256,
            'frozen instrumented target identity')
    require(replace(actual, source=target.source) == target, 'only Part04 marker text may change')
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

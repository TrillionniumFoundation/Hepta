"""Reversible four-stage reporting diagnostic, never partition qualification."""
from dataclasses import replace

from tools import core_syntax_partition_sources as original
from tools import core_syntax_declaration_diagnostic_sources as framing
from tools.check_guarded_slice_lean import require
from tools.check_core_syntax_staged import validate_plan

PROTOCOL = 'partition-position-diagnostic-v1'
SCHEDULED = original.NAMES[:4]
NOT_SCHEDULED = original.NAMES[4:]
MAX_MARKERS = 24
MAX_MANIFEST = 32768
DiagnosticSources = framing.DiagnosticSources
digest = framing.digest
encode = framing.encode


def _validate_original(prepared):
    validate_plan(prepared)
    require(prepared['manifest'].get('protocol') == original.PROTOCOL,
            'complete exact eleven-stage partition required')
    # validate_plan already invokes original.validate_bindings on this protocol.
    require(tuple(s.name for s in prepared['stages']) == original.NAMES,
            'fixed original partition inventory')


def _sites(prepared):
    commands = framing._commands(prepared['stages'][3].source)
    theorems = [c for c in commands if c['kind'] == 'theorem']
    by_name = {c['name']: c for c in commands if c['kind'] in ('def', 'theorem')}
    require(len(theorems) == 703 and len(by_name) == 2120, 'fixed target declaration counts')
    candidates = []
    def add(offset, label):
        candidates.append((offset, label))
    def boundary(name, side, label):
        require(name in by_name, 'required diagnostic anchor missing')
        add(by_name[name]['start' if side == 'before' else 'end'], label)
    boundary(theorems[0]['name'], 'before', 'before_first_theorem')
    for ordinal in (64, 128, 256, 384, 512, 640, 703):
        add(theorems[ordinal-1]['end'], 'after_theorem_' + str(ordinal))
    roots = ('linear_bounds', 'linear_serialized', 'linear_parsed', 'linear_length',
             'linear_byte_range', 'linear_transport')
    boundary(roots[0], 'before', 'before_linear_roots')
    for name in roots:
        boundary(name, 'after', 'after_' + name)
    parallel_defs = [c for c in commands if c['kind'] == 'def' and c['name'].startswith('parallel')]
    require(parallel_defs, 'parallel data anchors missing')
    boundary(parallel_defs[0]['name'], 'before', 'before_parallel_data')
    # Segment/tail definitions precede the first parallel theorem; later node
    # definitions are interspersed with proofs and are not called initial data.
    first_parallel = next(c for c in theorems if c['name'].startswith('parallel'))
    add(first_parallel['start'], 'before_first_parallel_theorem')
    add(first_parallel['end'], 'after_first_parallel_theorem')
    printed = [c for c in commands if c['kind'] == 'print']
    require(len(printed) == 703 and commands[-703:] == printed, 'exact target print suffix')
    add(printed[0]['start'], 'before_final_inventory')
    add(printed[-1]['end'], 'after_final_inventory')
    require(len(candidates) <= MAX_MARKERS, 'candidate marker cap')
    grouped = {}
    for offset, label in candidates:
        grouped.setdefault(offset, []).append(label)
    sites = []
    for offset, labels in sorted(grouped.items()):
        previous = [c for c in commands if c['end'] == offset]
        following = [c for c in commands if c['start'] == offset]
        require(len(previous) <= 1 and len(following) <= 1 and (previous or following),
                'complete command boundary required')
        sites.append(dict(original_offset=offset, anchors=sorted(labels),
                          previous_command=previous[0] if previous else None,
                          next_command=following[0] if following else None))
    return sites


def _marker(index):
    require(type(index) is int and 0 <= index < MAX_MARKERS, 'marker index bound')
    ident = 'HIA_DIAG_v1_P02_%03d' % index
    return ident, '#check "' + ident + '"\n'


def strip_markers(source, manifest):
    require(type(source) is str and type(manifest) is dict, 'diagnostic source types')
    raw = source.encode()
    require(len(raw) <= original.MAX_SOURCE, 'source cap')
    markers = manifest.get('markers')
    require(type(markers) is list and 0 < len(markers) <= MAX_MARKERS, 'marker list cap')
    chunks, cursor, restored_size, previous_offset = [], 0, 0, -1
    fields = {'original_offset', 'anchors', 'previous_command', 'next_command',
              'id', 'text', 'sha256', 'instrumented_offset'}
    for index, marker in enumerate(markers):
        require(type(marker) is dict and set(marker) == fields, 'exact marker fields')
        ident, text = _marker(index)
        block = text.encode()
        offset, original_offset = marker['instrumented_offset'], marker['original_offset']
        require(type(offset) is int and type(original_offset) is int and
                cursor <= offset <= len(raw)-len(block) and original_offset > previous_offset,
                'ordered marker byte intervals')
        require(marker['id'] == ident and marker['text'] == text and
                marker['sha256'] == digest(block) and raw[offset:offset+len(block)] == block,
                'fixed exact marker bytes')
        chunks.append(raw[cursor:offset]); restored_size += offset-cursor
        require(restored_size == original_offset, 'original offset binding')
        cursor = offset+len(block); previous_offset = original_offset
    chunks.append(raw[cursor:])
    restored = b''.join(chunks)
    require(b'#check ' not in restored and b'HIA_DIAG_' not in restored, 'unexpected marker remains')
    return restored


def _derive(prepared):
    raw = prepared['stages'][3].source.encode()
    chunks, markers, cursor, added = [], [], 0, 0
    for index, site in enumerate(_sites(prepared)):
        ident, text = _marker(index); block = text.encode(); offset = site['original_offset']
        chunks.extend((raw[cursor:offset], block))
        markers.append({**site, 'id': ident, 'text': text, 'sha256': digest(block),
                        'instrumented_offset': offset+added})
        added += len(block); cursor = offset
    chunks.append(raw[cursor:])
    source = b''.join(chunks).decode()
    stages = prepared['stages'][:3] + (replace(prepared['stages'][3], source=source),)
    total = sum(s.source_bytes for s in prepared['stages'])
    manifest = dict(schema='hepta.hia.partition-position-diagnostic.v1', protocol=PROTOCOL,
        acceptance_eligible=False, maximum_processes=4, scheduled_stage_names=list(SCHEDULED),
        not_scheduled_stage_names=list(NOT_SCHEDULED), target='CertPart02',
        original_manifest_sha256=prepared['manifest_sha256'], original_target_source_sha256=digest(raw),
        diagnostic_target_source_sha256=digest(source.encode()), original_target_source_bytes=len(raw),
        diagnostic_target_source_bytes=len(source.encode()), original_total_source_bytes=total,
        retained_total_source_bytes=total+len(source.encode()), marker_count=len(markers), markers=markers,
        stages=framing._stage_bindings(prepared, stages))
    require(all(s.source_bytes <= original.MAX_SOURCE for s in stages) and
            total+len(source.encode()) <= original.MAX_TOTAL_SOURCE, 'retained source budgets')
    encoded = encode(manifest)
    require(len(encoded.encode()) <= MAX_MANIFEST, 'diagnostic manifest cap')
    return DiagnosticSources(stages, encoded)


def build_diagnostic_sources(prepared):
    _validate_original(prepared)
    diagnostic = _derive(prepared)
    validate_diagnostic_sources(prepared, diagnostic)
    return diagnostic


def validate_diagnostic_sources(prepared, diagnostic):
    _validate_original(prepared)
    require(isinstance(diagnostic, DiagnosticSources) and type(diagnostic.stages) is tuple and
            tuple(s.name for s in diagnostic.stages) == SCHEDULED, 'exact four diagnostic stages')
    require(type(diagnostic.manifest_json) is str and
            len(diagnostic.manifest_json.encode()) <= MAX_MANIFEST, 'manifest size/type')
    require(diagnostic.stages[:3] == prepared['stages'][:3], 'unchanged three parents')
    actual, original_stage = diagnostic.stages[3], prepared['stages'][3]
    require(replace(actual, source=original_stage.source) == original_stage, 'only target source may change')
    require(strip_markers(actual.source, diagnostic.manifest) == original_stage.source.encode(),
            'exact independent marker removal')
    expected = _derive(prepared)
    require(diagnostic == expected, 'exact independently reconstructed diagnostic metadata and anchors')
    return {'marker_count': diagnostic.manifest['marker_count'], 'acceptance_eligible': False}

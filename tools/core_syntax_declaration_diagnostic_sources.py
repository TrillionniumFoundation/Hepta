"""Pure bounded diagnostic source derivation; never an acceptance protocol.

Validate the complete original DAG first. Add only fixed String #check commands,
then independently remove exact recorded byte intervals to recover that original.
No Lean process, IO marker, proof acceptance, or downstream scheduling occurs here.
"""
from dataclasses import dataclass, replace
from hashlib import sha256
import json
import re
from types import MappingProxyType

from tools.check_guarded_slice_lean import require

PROTOCOL = 'declaration-position-diagnostic-v1'
MAX_MARKERS = 24
MAX_MANIFEST = 32 * 1024
THEOREM_COUNT = 843
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
SCHEDULED = ('Baseline', 'SyntaxData', 'LinearTransport')
NOT_SCHEDULED = ('ParallelTransport', 'WrongPhiTransport', 'LiteralTwoTransport',
                 'WrongConditionTransport', 'Connections', 'TransportRejections', 'WrongArm')


def digest(data):
    return sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


@dataclass(frozen=True)
class DiagnosticSources:
    stages: tuple
    manifest_json: str

    @property
    def manifest(self):
        return json.loads(self.manifest_json)

    @property
    def manifest_sha256(self):
        return digest(self.manifest_json.encode('utf-8'))

    @property
    def sources(self):
        return MappingProxyType({stage.module_name: stage.source for stage in self.stages})


def _validate_original(prepared):
    # Import locally: this source-only helper is not part of the acceptance
    # validator, and the existing validator must never accept this derivative.
    from tools.check_core_syntax_staged import validate_plan
    from tools.core_syntax_structured_stages import PROTOCOL as STRUCTURED_PROTOCOL
    validate_plan(prepared)
    require(prepared['manifest'].get('protocol') == STRUCTURED_PROTOCOL,
            'complete structured original preparation required')
    require(tuple(s.name for s in prepared['stages']) == SCHEDULED + NOT_SCHEDULED,
            'fixed original ten-stage order')
    require(len(prepared['stages'][2].expected_theorems) == THEOREM_COUNT,
            'reviewed original theorem inventory changed')


def _commands(source):
    """Scan only the already independently validated generated-source grammar.

    Positions are UTF-8 bytes, never character counts. A command owns all its
    continuation lines up to the next top-level command (or the end of source).
    """
    raw = source.encode('utf-8')
    require(raw.endswith(b'\n'), 'original source must end with newline')
    commands, offset = [], 0
    for line in raw.splitlines(keepends=True):
        require(line.endswith(b'\n') and b'\r' not in line, 'unsupported source newline')
        text = line[:-1].decode('utf-8')
        match = re.match(r'^(import|namespace|def|theorem|end) ([A-Za-z][A-Za-z0-9_.]*)\b', text)
        printed = re.fullmatch(r'#print axioms ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match or printed:
            kind, name = match.groups() if match else ('print', printed.group(1))
            commands.append({'kind': kind, 'name': name, 'start': offset})
        else:
            require(text.startswith('  ') and commands and commands[-1]['kind'] == 'theorem',
                    'unsupported or ambiguous generated command boundary')
        offset += len(line)
    for i, command in enumerate(commands):
        command['end'] = commands[i + 1]['start'] if i + 1 < len(commands) else len(raw)
    require(commands and commands[0]['kind'] == 'import', 'original import boundary')
    return commands


def _sites(prepared):
    stage = prepared['stages'][2]
    commands = _commands(stage.source)
    by_name = {}
    for command in commands:
        if command['kind'] in ('def', 'theorem'):
            require(command['name'] not in by_name, 'duplicate original declaration anchor')
            by_name[command['name']] = command
    certificate = prepared['structured_certificates']['linear']['manifest']
    require(certificate['stem'] == certificate['cert'] == 'linear' and
            certificate['namespace'] == 'HiaCoreSyntaxSlice', 'original linear naming')
    theorems = [c for c in commands if c['kind'] == 'theorem']
    require(len(theorems) == THEOREM_COUNT, 'reviewed theorem ordinal inventory')
    candidates = []

    def boundary(name, side, label):
        require(name in by_name, 'missing original diagnostic anchor: ' + name)
        candidates.append((by_name[name]['start' if side == 'before' else 'end'], label))

    segment_names = [x['name'] for x in certificate['segments']]
    tail_names = certificate['tails']
    require(segment_names and tail_names, 'complete segment and tail anchors')
    segment_commands = sorted((by_name[n] for n in segment_names), key=lambda c: c['start'])
    tail_commands = sorted((by_name[n] for n in tail_names), key=lambda c: c['start'])
    boundary(segment_commands[0]['name'], 'before', 'before_first_segment')
    boundary(segment_commands[-1]['name'], 'after', 'after_last_segment')
    boundary(tail_commands[-1]['name'], 'after', 'after_last_tail')
    boundary(theorems[0]['name'], 'before', 'before_first_theorem')
    for leaf, kind, suffix in ((True, 'serialization', 's'), (True, 'parsing', 'p'),
                               (False, 'serialization', 's'), (False, 'parsing', 'p')):
        names = {f'linear_{suffix}{node["id"]}' for node in certificate['nodes'] if node['leaf'] == leaf}
        choices = [c for c in theorems if c['name'] in names]
        require(choices, 'missing leaf/container diagnostic anchor')
        boundary(choices[0]['name'], 'after', 'after_first_' + ('leaf_' if leaf else 'nonleaf_') + kind)
    for ordinal in (128, 256, 384, 512, 640, 768):
        boundary(theorems[ordinal - 1]['name'], 'after', 'after_theorem_' + str(ordinal))
    roots = ('linear_bounds', 'linear_serialized', 'linear_parsed', 'linear_length',
             'linear_byte_range', 'linear_transport')
    nonroot = [c for c in theorems if c['name'] not in roots]
    require(nonroot, 'missing non-root diagnostic anchor')
    boundary(nonroot[-1]['name'], 'after', 'after_last_nonroot_theorem')
    boundary(roots[0], 'before', 'before_linear_bounds')
    for name in roots:
        boundary(name, 'after', 'after_' + name)
    printed = [c for c in commands if c['kind'] == 'print']
    require(len(printed) == THEOREM_COUNT and commands[-len(printed):] == printed,
            'complete contiguous original final print inventory')
    candidates.extend(((printed[0]['start'], 'before_final_inventory'),
                       (printed[-1]['end'], 'after_final_inventory')))
    require(len(candidates) == MAX_MARKERS, 'fixed 24 candidate algorithm')
    grouped = {}
    for offset, label in candidates:
        grouped.setdefault(offset, []).append(label)
    sites = []
    for offset, labels in sorted(grouped.items()):
        previous = [c for c in commands if c['end'] == offset]
        following = [c for c in commands if c['start'] == offset]
        require(len(previous) <= 1 and len(following) <= 1 and (previous or following),
                'diagnostic offset is not an exact command boundary')
        sites.append({'original_offset': offset, 'anchors': sorted(labels),
                      'previous_command': previous[0] if previous else None,
                      'next_command': following[0] if following else None})
    require(0 < len(sites) <= MAX_MARKERS, 'bounded diagnostic marker count')
    return sites


def _marker(index):
    require(type(index) is int and 0 <= index < MAX_MARKERS, 'marker ID bound')
    ident = f'HIA_DIAG_v1_LIN_{index:03d}'
    return ident, '#check "' + ident + '"\n'


def strip_markers(source, manifest):
    """Remove only recorded exact intervals; do not trust broad regex erasure."""
    require(type(source) is str and type(manifest) is dict, 'diagnostic strip types')
    raw = source.encode('utf-8')
    require(len(raw) <= MAX_SOURCE, 'diagnostic source byte budget')
    markers = manifest.get('markers')
    require(type(markers) is list and 0 < len(markers) <= MAX_MARKERS, 'marker inventory bound')
    chunks, cursor, restored_size, previous_offset = [], 0, 0, -1
    for index, entry in enumerate(markers):
        require(type(entry) is dict and set(entry) == {
            'original_offset', 'anchors', 'previous_command', 'next_command',
            'id', 'text', 'sha256', 'instrumented_offset'}, 'exact marker manifest schema')
        ident, text = _marker(index)
        block = text.encode('ascii')
        position = entry['instrumented_offset']
        original_offset = entry['original_offset']
        require(type(position) is int and type(original_offset) is int and
                cursor <= position <= len(raw) - len(block) and original_offset > previous_offset,
                'ordered exact marker offsets')
        require(entry['id'] == ident and entry['text'] == text and entry['sha256'] == digest(block),
                'exact fixed marker template and ID')
        require(raw[position:position + len(block)] == block, 'marker byte interval mismatch')
        chunk = raw[cursor:position]
        chunks.append(chunk)
        restored_size += len(chunk)
        require(restored_size == original_offset, 'original/instrumented offset correspondence')
        cursor = position + len(block)
        previous_offset = original_offset
    chunks.append(raw[cursor:])
    restored = b''.join(chunks)
    require(b'#check ' not in restored and b'HIA_DIAG_v1_LIN_' not in restored,
            'unexpected or duplicate diagnostic marker remains')
    return restored



def _stage_bindings(prepared, stages):
    # Full imports/theorem inventories already belong to the frozen original
    # manifest. Reference them rather than copying 843 names into live metadata.
    return [{'name': stage.name, 'module_name': stage.module_name,
             'source_sha256': stage.source_sha256, 'source_bytes': stage.source_bytes,
             'original_stage_manifest_sha256': digest(encode(original.manifest()).encode())}
            for original, stage in zip(prepared['stages'], stages)]


def build_diagnostic_sources(prepared):
    _validate_original(prepared)
    original = prepared['stages'][2].source.encode('utf-8')
    chunks, markers, cursor, added = [], [], 0, 0
    for index, site in enumerate(_sites(prepared)):
        ident, text = _marker(index)
        block = text.encode('ascii')
        offset = site['original_offset']
        chunks.extend((original[cursor:offset], block))
        markers.append({**site, 'id': ident, 'text': text, 'sha256': digest(block),
                        'instrumented_offset': offset + added})
        added += len(block)
        cursor = offset
    chunks.append(original[cursor:])
    source = b''.join(chunks).decode('utf-8')
    stages = prepared['stages'][:2] + (replace(prepared['stages'][2], source=source),)
    original_total = sum(s.source_bytes for s in prepared['stages'])
    retained_total = original_total + len(source.encode('utf-8'))
    require(all(s.source_bytes <= MAX_SOURCE for s in stages) and retained_total <= MAX_TOTAL_SOURCE,
            'retained original plus instrumented source budget')
    manifest = {'schema': 'hepta.hia.declaration-diagnostic-sources.v1', 'protocol': PROTOCOL,
                'acceptance_eligible': False, 'maximum_processes': 3,
                'scheduled_stage_names': list(SCHEDULED), 'not_scheduled_stage_names': list(NOT_SCHEDULED),
                'original_manifest_sha256': prepared['manifest_sha256'],
                'original_linear_source_sha256': digest(original),
                'diagnostic_linear_source_sha256': digest(source.encode('utf-8')),
                'original_linear_source_bytes': len(original),
                'diagnostic_linear_source_bytes': len(source.encode('utf-8')),
                'original_total_source_bytes': original_total,
                'retained_total_source_bytes': retained_total,
                'candidate_site_count': MAX_MARKERS, 'marker_count': len(markers), 'markers': markers,
                'stages': _stage_bindings(prepared, stages)}
    require(len(encode(manifest).encode()) <= MAX_MANIFEST, 'bounded diagnostic preparation manifest')
    result = DiagnosticSources(stages, encode(manifest))
    validate_diagnostic_sources(prepared, result)
    return result


def validate_diagnostic_sources(prepared, diagnostic):
    _validate_original(prepared)
    require(isinstance(diagnostic, DiagnosticSources), 'frozen diagnostic source object required')
    require(type(diagnostic.stages) is tuple and len(diagnostic.stages) == 3 and
            tuple(s.name for s in diagnostic.stages) == SCHEDULED, 'exact three diagnostic stages')
    require(type(diagnostic.manifest_json) is str and
            len(diagnostic.manifest_json.encode()) <= MAX_MANIFEST, 'bounded diagnostic preparation manifest')
    manifest = diagnostic.manifest
    fields = {'schema', 'protocol', 'acceptance_eligible', 'maximum_processes',
              'scheduled_stage_names', 'not_scheduled_stage_names', 'original_manifest_sha256',
              'original_linear_source_sha256', 'diagnostic_linear_source_sha256',
              'original_linear_source_bytes', 'diagnostic_linear_source_bytes',
              'original_total_source_bytes', 'retained_total_source_bytes',
              'candidate_site_count', 'marker_count', 'markers', 'stages'}
    require(set(manifest) == fields, 'exact diagnostic manifest schema fields')
    for name in ('original_linear_source_bytes', 'diagnostic_linear_source_bytes',
                 'original_total_source_bytes', 'retained_total_source_bytes',
                 'candidate_site_count', 'marker_count'):
        require(type(manifest[name]) is int, 'integer diagnostic size/count field')
    require(diagnostic.manifest_json == encode(manifest), 'canonical diagnostic manifest encoding')
    require(manifest['schema'] == 'hepta.hia.declaration-diagnostic-sources.v1' and
            manifest['protocol'] == PROTOCOL and manifest['acceptance_eligible'] is False and
            type(manifest['maximum_processes']) is int and manifest['maximum_processes'] == 3 and
            manifest['scheduled_stage_names'] == list(SCHEDULED) and
            manifest['not_scheduled_stage_names'] == list(NOT_SCHEDULED), 'nonaccepting diagnostic protocol')
    require(manifest['original_manifest_sha256'] == prepared['manifest_sha256'], 'frozen original manifest binding')
    require(diagnostic.stages[:2] == prepared['stages'][:2], 'baseline and syntax data must remain unchanged')
    actual = diagnostic.stages[2]
    original_stage = prepared['stages'][2]
    require(replace(actual, source=original_stage.source) == original_stage, 'only linear source may change')
    raw, original = actual.source.encode('utf-8'), original_stage.source.encode('utf-8')
    require(strip_markers(actual.source, manifest) == original, 'independent marker stripping must recover exact original bytes')
    sites = _sites(prepared)
    require(len(sites) == manifest['marker_count'] == len(manifest['markers']) and
            manifest['candidate_site_count'] == MAX_MARKERS, 'fixed diagnostic site count')
    for site, marker in zip(sites, manifest['markers']):
        require({k: marker[k] for k in site} == site, 'independent original declaration anchor binding')
    total = sum(s.source_bytes for s in prepared['stages'])
    require(manifest['original_linear_source_sha256'] == digest(original) and
            manifest['diagnostic_linear_source_sha256'] == digest(raw) and
            manifest['original_linear_source_bytes'] == len(original) and
            manifest['diagnostic_linear_source_bytes'] == len(raw) and
            manifest['original_total_source_bytes'] == total and
            manifest['retained_total_source_bytes'] == total + len(raw), 'diagnostic source identities and accounting')
    require(len(raw) <= MAX_SOURCE and total + len(raw) <= MAX_TOTAL_SOURCE, 'complete diagnostic source byte budgets')
    require(manifest['stages'] == _stage_bindings(prepared, diagnostic.stages), 'exact diagnostic stage bindings')
    # The stripped source is exactly the source already independently validated
    # at entry. Recheck the original preparation after all derivation checks too.
    _validate_original(prepared)
    return {'marker_count': len(sites), 'diagnostic_source_bytes': len(raw),
            'retained_total_source_bytes': total + len(raw), 'acceptance_eligible': False}

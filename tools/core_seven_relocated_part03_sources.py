"""Closed source-only Part03 reporting derivative; never grants acceptance.

The inverse consumes actual marked bytes, rescans their fixed command topology,
and passes the recovered eleven-stage candidate through the unchanged complete
relocation, old-seven and original source validators. No compiler is launched.
"""
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from types import MappingProxyType

from tools import core_seven_certificate_sources as seven
from tools import core_seven_parallel_relocation_sources as relocation
from tools import core_syntax_declaration_diagnostic_sources as framing
from tools.check_guarded_slice_lean import require

SCHEMA = 'hepta.hia.seven-relocated-part03-sources.v1'
PROTOCOL = 'seven-relocated-part03-sources-v1'
TARGET = 'RelocatedPart03'
SCHEDULED = seven.NAMES[:5]
PLANNED_MARKERS = 11
MAX_MARKERS = 24
MAX_SOURCE = 2097152
MAX_TOTAL_SOURCE = 8388608
MAX_MANIFEST = 6616
TARGET_SOURCE_BYTES = 612761
TARGET_SOURCE_SHA256 = 'd920662dc97070e94fe95852af6ecbf15f5e4d35a25da4d6a2db977e1005f626'
UNMARKED_SOURCE_BYTES = 612376
UNMARKED_SOURCE_SHA256 = '076ba8582022029d053a80b279f13be2423334a9cb682a35b8889ff004370632'
OFFSETS = (65, 543, 125190, 125617, 310120, 432982, 473279, 533147, 533170, 572551, 612376)
ANCHORS = ('before:linearRaw', 'after:linear_parsed', 'after:linear_bf0594',
           'after:linear_transport', 'after:parallel_p61:parallel-original-theorem-256',
           'after:parallel_pl113_0;before:parallel_bf0000',
           'after:parallel_bf0255;moved-fact-256', 'after:parallel_bf0490;moved-fact-491',
           'before_final_inventory', 'after_final_inventory_subject_828',
           'after_final_inventory_subject_1655')
# Frozen neighbor records are independent of caller-provided manifest metadata.
NEIGHBORS = ((('namespace', 'HiaCoreSyntaxSlice', 36, 65), ('def', 'linearRaw', 65, 98)), (('theorem', 'linear_parsed', 334, 543), ('theorem', 'linear_bf0000', 543, 694)), (('theorem', 'linear_bf0594', 125052, 125190), ('theorem', 'linear_length', 125190, 125304)), (('theorem', 'linear_transport', 125421, 125617), ('def', 'parallel_g0', 125617, 125653)), (('theorem', 'parallel_p61', 310001, 310120), ('def', 'parallel_r62', 310120, 310482)), (('theorem', 'parallel_pl113_0', 432204, 432982), ('theorem', 'parallel_bf0000', 432982, 433137)), (('theorem', 'parallel_bf0255', 473121, 473279), ('theorem', 'parallel_bf0256', 473279, 473436)), (('theorem', 'parallel_bf0490', 532691, 533147), ('end', 'HiaCoreSyntaxSlice', 533147, 533170)), (('end', 'HiaCoreSyntaxSlice', 533147, 533170), ('print', 'HiaCoreSyntaxSlice.linear_bf0000', 533170, 533217)), (('print', 'HiaCoreSyntaxSlice.parallel_bf0226', 572502, 572551), ('print', 'HiaCoreSyntaxSlice.parallel_bf0227', 572551, 572600)), (('print', 'HiaCoreSyntaxSlice.parallel_sl99_9', 612327, 612376), None))


def digest(data):
    return sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False) + '\n'


@dataclass(frozen=True)
class RelocatedPart03DiagnosticSources:
    stages: tuple
    manifest_json: str

    @property
    def manifest(self):
        return json.loads(self.manifest_json)

    @property
    def manifest_sha256(self):
        return digest(self.manifest_json.encode())

    @property
    def sources(self):
        return MappingProxyType({s.module_name: s.source for s in self.stages})


def _record(raw):
    return dict(bytes=len(raw), sha256=digest(raw))


def _marker(index):
    require(type(index) is int and 0 <= index < PLANNED_MARKERS, 'fixed marker index')
    ident = 'HIA_SEVEN_DIAG_v1_P03_%03d' % index
    return ident, '#check "' + ident + '"\n'


def _markers(raw):
    require(type(raw) is bytes and _record(raw) == dict(bytes=UNMARKED_SOURCE_BYTES,
            sha256=UNMARKED_SOURCE_SHA256), 'frozen unmarked Part03 bytes')
    commands = framing._commands(raw.decode('utf-8'))
    require(len(commands) == 4614, 'complete command scan')
    theorems = [c for c in commands if c['kind'] == 'theorem']
    parallel = [c for c in theorems if c['name'].startswith('parallel_') and '_bf' not in c['name']]
    moved = [c for c in theorems if c['name'].startswith('parallel_bf')]
    printed = [c for c in commands if c['kind'] == 'print']
    require(len(theorems) == 1655 and len(parallel) == 563 and
            parallel[255]['name'] == 'parallel_p61' and len(moved) == 491 and
            moved[255]['name'] == 'parallel_bf0255' and moved[490]['name'] == 'parallel_bf0490',
            'fixed actual theorem ordinals')
    require(len(printed) == 1655 and commands[-1655:] == printed and
            printed[827]['name'] == 'HiaCoreSyntaxSlice.parallel_bf0226' and
            printed[-1]['name'] == 'HiaCoreSyntaxSlice.parallel_sl99_9', 'fixed final print ordinals')
    result = []
    for i, offset in enumerate(OFFSETS):
        before = [c for c in commands if c['end'] == offset]
        after = [c for c in commands if c['start'] == offset]
        require(len(before) == 1 and len(after) == (0 if i == 10 else 1), 'unique command boundary')
        neighbors = (before[0], after[0] if after else None)
        actual = tuple(None if c is None else (c['kind'], c['name'], c['start'], c['end']) for c in neighbors)
        require(actual == NEIGHBORS[i], 'independently rescanned fixed neighbors')
        ident, text = _marker(i)
        result.append(dict(id=ident, text=text, sha256=digest(text.encode()), original_offset=offset,
                           instrumented_offset=offset+35*i, anchor=ANCHORS[i],
                           previous_command=neighbors[0], next_command=neighbors[1]))
    return result


def strip_markers(source, manifest):
    """Inverse actual bytes, then independently authenticate fixed topology."""
    require(type(source) is str and type(manifest) is dict and
            manifest.get('schema') == SCHEMA and manifest.get('protocol') == PROTOCOL,
            'exact Part03 strip types and protocol')
    raw = source.encode('utf-8')
    require(len(raw) <= MAX_SOURCE, 'marked source cap')
    markers = manifest.get('markers')
    require(type(markers) is list and len(markers) == PLANNED_MARKERS, 'eleven markers required')
    chunks, cursor, restored_size = [], 0, 0
    fields = {'id', 'text', 'sha256', 'original_offset', 'instrumented_offset',
              'anchor', 'previous_command', 'next_command'}
    for i, marker in enumerate(markers):
        require(type(marker) is dict and set(marker) == fields, 'exact marker fields')
        offset, original = marker['instrumented_offset'], marker['original_offset']
        ident, text = _marker(i)
        block = text.encode()
        require(type(offset) is int and type(original) is int and
                original == OFFSETS[i] and offset == original+35*i and
                cursor <= offset <= len(raw)-35, 'fixed ordered marker offsets')
        require(marker['id'] == ident and marker['text'] == text and
                marker['sha256'] == digest(block) and raw[offset:offset+35] == block,
                'exact marker bytes identity and order')
        chunks.append(raw[cursor:offset]); restored_size += offset-cursor
        require(restored_size == original, 'accumulated actual inverse offset')
        cursor = offset+35
    chunks.append(raw[cursor:])
    restored = b''.join(chunks)
    require(b'#check' not in restored and b'HIA_DIAG_' not in restored and
            b'HIA_SEVEN_DIAG_' not in restored, 'no unrecorded marker text')
    # Canonical equality also rejects bool-as-int inside neighbor records.
    require(encode(markers) == encode(_markers(restored)), 'fixed rescanned topology records')
    require(_record(raw) == dict(bytes=TARGET_SOURCE_BYTES, sha256=TARGET_SOURCE_SHA256),
            'frozen marked Part03 identity')
    return restored


def retained_sources(prepared, proposal, stages):
    return {**{'original/' + s.name + '.lean': s.source for s in prepared['stages']},
            **{(s.module_name.replace('.', '/') if i < 4 else 'relocated/' + s.name) + '.lean': s.source
               for i, s in enumerate(proposal.stages)},
            'HiaSyntaxResearch/CertPart03.lean': stages[4].source}


def _derive(prepared, previous, proposal):
    raw = proposal.stages[4].source.encode()
    markers = _markers(raw)
    chunks, cursor = [], 0
    for marker in markers:
        offset = marker['original_offset']
        chunks.extend((raw[cursor:offset], marker['text'].encode())); cursor = offset
    chunks.append(raw[cursor:])
    marked = b''.join(chunks)
    stages = proposal.stages[:4] + (replace(proposal.stages[4], source=marked.decode()),)
    retained = retained_sources(prepared, proposal, stages)
    file_map = {n: _record(s.encode()) for n, s in retained.items()}
    require(len(file_map) == 23 and sum(x['bytes'] for x in file_map.values()) == 6206115
            and all(x['bytes'] <= MAX_SOURCE for x in file_map.values()), 'exact retained source accounting')
    manifest = dict(schema=SCHEMA, protocol=PROTOCOL, source_only=True, acceptance_eligible=False,
        maximum_processes=5, target=TARGET, module_name='HiaSyntaxResearch.CertPart03',
        original_manifest_sha256=prepared['manifest_sha256'], previous_seven_manifest_sha256=previous.manifest_sha256,
        relocation_manifest_sha256=proposal.manifest_sha256, unmarked=_record(raw), marked=_record(marked),
        source_file_map_sha256=digest(encode(file_map).encode()), marker_count=11, markers=markers,
        subject_count=1655, subject_sequence_sha256=digest(encode(seven._qualified_prints(raw.decode())).encode()),
        kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
        python_exporter_refinement_proved=False, body_prefix_refinement_proved=False, all_edge_transfer_proved=False,
        obligations=[dict(id=n, status='unproved') for n, _ in seven.facts.OBLIGATIONS], authority=dict(seven.facts.DENY))
    encoded = encode(manifest)
    require(len(encoded.encode()) == MAX_MANIFEST, 'fixed compact diagnostic manifest bytes')
    return RelocatedPart03DiagnosticSources(stages, encoded)


def validate_diagnostic_sources(prepared, previous, proposal, diagnostic):
    require(type(diagnostic) is RelocatedPart03DiagnosticSources and type(diagnostic.stages) is tuple
            and len(diagnostic.stages) == 5 and tuple(s.name for s in diagnostic.stages) == SCHEDULED,
            'distinct exact five-stage source type')
    require(type(proposal) is relocation.ParallelRelocationSources and type(proposal.stages) is tuple
            and len(proposal.stages) == 11, 'exact complete candidate source type')
    require(type(diagnostic.manifest_json) is str and len(diagnostic.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded manifest string')
    manifest = diagnostic.manifest
    require(type(manifest) is dict and diagnostic.manifest_json == encode(manifest), 'canonical LF manifest')
    require(diagnostic.stages[:4] == proposal.stages[:4], 'unchanged authenticated parent sources')
    actual, target = diagnostic.stages[4], proposal.stages[4]
    require(type(actual) is type(target) and replace(actual, source=target.source) == target,
            'unchanged target metadata')
    restored = strip_markers(actual.source, manifest)
    require(restored == target.source.encode(), 'actual inverse equals retained unmarked source')
    recovered_stages = proposal.stages[:4] + (replace(actual, source=restored.decode()),) + proposal.stages[5:]
    recovered = relocation.ParallelRelocationSources(proposal.original_stages, recovered_stages, proposal.manifest_json)
    # Mandatory actual-byte inverse and both complete old/original gates.
    relocation.validate_sources(prepared, previous, recovered, (actual.source,))
    expected = _derive(prepared, previous, recovered)
    require(diagnostic.manifest_json == expected.manifest_json and diagnostic.stages == expected.stages,
            'closed exact source manifest and stages')
    return dict(marker_count=11, acceptance_eligible=False, authority='DENY_ALL',
                diagnostic_source_bytes=actual.source_bytes, retained_total_source_bytes=6206115)


def build_diagnostic_sources(prepared, previous, proposal):
    result = _derive(prepared, previous, proposal)
    validate_diagnostic_sources(prepared, previous, proposal, result)
    return result

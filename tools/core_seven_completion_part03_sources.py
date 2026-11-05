"""Original #603 completion barrier, source only and permanently nonaccepting.

Exact inverse restores the old marked bytes, then the complete unmarked original
candidate. Every validation calls the unchanged full relocation/seven/input gates.
"""
from dataclasses import dataclass, fields, replace
import json
from types import MappingProxyType
from tools import core_seven_relocated_part03_sources as original
from tools.check_guarded_slice_lean import require

seven, relocation = original.seven, original.relocation
encode, digest, _record = original.encode, original.digest, original._record
SCHEMA = 'hepta.hia.seven-completion-part03-sources.v1'
PROTOCOL = 'seven-completion-part03-sources-v1'
TARGET = 'CompletionPart03'
SCHEDULED = original.SCHEDULED
PLANNED_MARKERS, MAX_MARKERS = 12, 24
MAX_SOURCE, MAX_TOTAL_SOURCE = original.MAX_SOURCE, original.MAX_TOTAL_SOURCE
MAX_MANIFEST = 8192
MANIFEST_BYTES = 7444
UNMARKED_SOURCE_BYTES, UNMARKED_SOURCE_SHA256 = original.UNMARKED_SOURCE_BYTES, original.UNMARKED_SOURCE_SHA256
TARGET_SOURCE_BYTES = 612821
TARGET_SOURCE_SHA256 = '9bfe4a4e80641e00bb4944ac4d7bc3580cab0c6694bfc462ee083da6ff4b2ab9'
MARKER_ORDER = tuple(range(9)) + (11, 9, 10)
MARKER_IDS = tuple('HIA_SEVEN_COMP_v1_P03_%03d' % i for i in MARKER_ORDER)
SENTINEL_TEXT = '#print axioms True.intro\n'
SENTINEL_OFFSET = original.OFFSETS[8] + 35 * 9
SENTINEL_OUTPUT = "'True.intro' does not depend on any axioms\n"
INSERTED_BYTES = len(SENTINEL_TEXT.encode()) + 35
OFFSETS = original.OFFSETS[:9] + (original.OFFSETS[8],) + original.OFFSETS[9:]
MARKER_OFFSETS = tuple(original.OFFSETS[i] + 35*i for i in range(9)) + (SENTINEL_OFFSET + 25,) + tuple(original.OFFSETS[i] + 35*i + INSERTED_BYTES for i in (9,10))
retained_sources = original.retained_sources

@dataclass(frozen=True, slots=True)
class CompletionPart03DiagnosticSources:
    stages: tuple
    manifest_json: str

    @property
    def manifest(self): return json.loads(self.manifest_json)

    @property
    def manifest_sha256(self): return digest(self.manifest_json.encode())

    @property
    def sources(self): return MappingProxyType({s.module_name: s.source for s in self.stages})


def _stage_types(stages):
    stage_type = seven.original.legacy.Stage
    require(type(stages) is tuple and len(stages) == 11, 'exact eleven stage tuple')
    for stage in stages:
        require(type(stage) is stage_type and set(vars(stage)) == {f.name for f in fields(stage_type)},
                'closed exact stage type and fields')
        require(all(type(getattr(stage, key)) is str for key in ('name','module_name','source')), 'stage strings')
        for key in ('parents','explicit_imports','direct_imports','rejection_names'):
            value = getattr(stage, key)
            require(type(value) is tuple and all(type(x) is str for x in value), 'stage tuples')
        require(type(stage.expected_theorems) is frozenset and all(type(x) is str for x in stage.expected_theorems), 'stage subjects')


def _marker(index):
    require(type(index) is int and 0 <= index < 12, 'fixed marker index')
    ident = MARKER_IDS[index]
    return ident, '#check "' + ident + '"\n'


def _markers(raw):
    old = original._markers(raw)  # Full command scan and frozen neighbor checks.
    result = []
    for index, suffix in enumerate(MARKER_ORDER):
        ident, text = _marker(index)
        if suffix == 11:
            row = dict(old[8], anchor='after_checked_environment_barrier',
                previous_command=dict(kind='print', name='True.intro', start=SENTINEL_OFFSET,
                                      end=SENTINEL_OFFSET+25))
        else: row = dict(old[suffix])
        row.update(id=ident, text=text, sha256=digest(text.encode()), instrumented_offset=MARKER_OFFSETS[index])
        result.append(row)
    return result


def strip_completion(source, manifest):
    """Restore and authenticate the complete ORIGINAL eleven-marker source."""
    require(type(source) is str and type(manifest) is dict and manifest.get('schema') == SCHEMA
            and manifest.get('protocol') == PROTOCOL, 'completion source protocol')
    raw = source.encode()
    require(len(raw) == TARGET_SOURCE_BYTES and digest(raw) == TARGET_SOURCE_SHA256, 'frozen completion bytes')
    markers = manifest.get('markers')
    require(type(markers) is list and len(markers) == 12, 'twelve ordered markers')
    require(raw[SENTINEL_OFFSET:SENTINEL_OFFSET+25] == SENTINEL_TEXT.encode(), 'reserved sentinel bytes')
    chunks, cursor = [], 0
    for index, suffix in enumerate(MARKER_ORDER):
        offset = MARKER_OFFSETS[index]
        ident, text = _marker(index)
        require(raw[offset:offset+35] == text.encode(), 'fixed completion marker bytes')
        if suffix == 11:
            require(cursor == SENTINEL_OFFSET, 'sentinel uniquely follows008')
            require(offset == cursor+25, 'one fixed barrier command')
        else:
            chunks.append(raw[cursor:offset]); chunks.append(original._marker(suffix)[1].encode())
        cursor = offset+35
    chunks.append(raw[cursor:])
    restored = b''.join(chunks)
    require(_record(restored) == dict(bytes=original.TARGET_SOURCE_BYTES, sha256=original.TARGET_SOURCE_SHA256), 'exact old marked inverse')
    old_markers = []
    for index, suffix in enumerate(MARKER_ORDER):
        if suffix == 11: continue
        row = dict(markers[index]); ident, text = original._marker(suffix)
        row.update(id=ident, text=text, sha256=digest(text.encode()), instrumented_offset=original.OFFSETS[suffix]+35*suffix)
        old_markers.append(row)
    unmarked = original.strip_markers(restored.decode(), dict(schema=original.SCHEMA, protocol=original.PROTOCOL, markers=old_markers))
    require(encode(markers) == encode(_markers(unmarked)), 'rescanned exact completion marker topology')
    return restored


def strip_markers(source, manifest):
    restored = strip_completion(source, manifest)
    # Full old inverse uses independently rescanned unmarked bytes, not caller metadata.
    raw = restored
    for i in reversed(range(11)):
        offset = original.OFFSETS[i]+35*i
        raw = raw[:offset]+raw[offset+35:]
    return original.strip_markers(restored.decode(), dict(schema=original.SCHEMA, protocol=original.PROTOCOL, markers=original._markers(raw)))


def _derive(prepared, previous, proposal):
    old = original._derive(prepared, previous, proposal)
    raw = proposal.stages[4].source.encode()
    markers = _markers(raw)
    chunks, cursor = [], 0
    for index, suffix in enumerate(MARKER_ORDER):
        offset = OFFSETS[index]
        chunks.append(raw[cursor:offset])
        if suffix == 11: chunks.append(SENTINEL_TEXT.encode())
        chunks.append(markers[index]['text'].encode()); cursor = offset
    chunks.append(raw[cursor:])
    marked = b''.join(chunks)
    require(len(marked) == TARGET_SOURCE_BYTES and len(marked)-len(old.stages[4].source.encode()) == 60, 'exact added source budget')
    stages = proposal.stages[:4] + (replace(proposal.stages[4], source=marked.decode()),)
    manifest = old.manifest
    manifest.update(schema=SCHEMA, protocol=PROTOCOL, target=TARGET, marker_count=12, markers=markers,
        marked=_record(marked), old_marked=_record(old.stages[4].source.encode()),
        sentinel=dict(subject='True.intro', text=SENTINEL_TEXT, instrumented_offset=SENTINEL_OFFSET,
                      bytes=25, sha256=digest(SENTINEL_TEXT.encode()), after_marker=MARKER_IDS[8], before_marker=MARKER_IDS[9]),
        source_file_map_sha256=digest(encode({n:_record(s.encode()) for n,s in retained_sources(prepared,proposal,stages).items()}).encode()))
    encoded = encode(manifest)
    require(len(encoded.encode()) == MANIFEST_BYTES <= MAX_MANIFEST, 'fixed manifest within unchanged cap')
    return CompletionPart03DiagnosticSources(stages, encoded)


def validate_diagnostic_sources(prepared, previous, proposal, diagnostic):
    require(type(diagnostic) is CompletionPart03DiagnosticSources and type(diagnostic.stages) is tuple
            and len(diagnostic.stages) == 5, 'exact completion source type')
    require(type(proposal) is relocation.ParallelRelocationSources and type(proposal.stages) is tuple
            and len(proposal.stages) == 11, 'complete original relocation context')
    _stage_types(proposal.stages); _stage_types(diagnostic.stages+proposal.stages[5:])
    require(tuple(s.name for s in diagnostic.stages) == SCHEDULED and diagnostic.stages[:4] == proposal.stages[:4], 'original four parents')
    require(type(diagnostic.manifest_json) is str and len(diagnostic.manifest_json.encode()) <= MAX_MANIFEST, 'manifest bound')
    require(diagnostic.manifest_json == encode(diagnostic.manifest), 'canonical manifest')
    actual, target = diagnostic.stages[4], proposal.stages[4]
    require(replace(actual, source=target.source) == target, 'original target metadata')
    restored = strip_markers(actual.source, diagnostic.manifest)
    require(restored == target.source.encode(), 'complete original inverse bytes')
    recovered = relocation.ParallelRelocationSources(proposal.original_stages,
        proposal.stages[:4]+(replace(actual,source=restored.decode()),)+proposal.stages[5:], proposal.manifest_json)
    expected = _derive(prepared, previous, recovered)
    require(diagnostic.manifest_json == expected.manifest_json and diagnostic.stages == expected.stages, 'closed completion manifest')
    relocation.validate_sources(prepared, previous, recovered, retained_copies=(actual.source,))
    return dict(marker_count=12, acceptance_eligible=False, authority='DENY_ALL',
                diagnostic_source_bytes=actual.source_bytes, retained_total_source_bytes=6206175)


def build_diagnostic_sources(prepared, previous, proposal):
    result = _derive(prepared, previous, proposal)
    validate_diagnostic_sources(prepared, previous, proposal, result)
    return result

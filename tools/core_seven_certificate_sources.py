"""Reversible seven-certificate SOURCE-ONLY experiment; no execution API.

Only original exact-eleven files and this proposal are retained. The previous
byte-fact generation is a temporary validation intermediate, never an artifact.
512 is a structural boundary, not a timing result. All proof gates stay closed.
"""
from dataclasses import dataclass, replace
import json
import re
from types import MappingProxyType

from tools import core_byte_facts_sources as facts
from tools import core_syntax_partition_sources as original
from tools.check_guarded_slice_lean import require

PROTOCOL = 'seven-certificate-source-v1'
SCHEMA = 'hepta.hia.seven-certificate-source.v1'
CUTS = (512, 783, 837, 1406, 2109, 2811, 3513, 4215)
ANCHORS = ('HiaCoreSyntaxSlice.linear_pl99_1', 'HiaCoreSyntaxSlice.linear_p154',
           'HiaCoreSyntaxSlice.linear_p0', 'HiaCoreSyntaxSlice.parallel_pl113_0',
           'HiaCoreSyntaxSlice.WrongPhi.mutated_kd87_0',
           'HiaCoreSyntaxSlice.LiteralTwo.mutated_p51',
           'HiaCoreSyntaxSlice.WrongCondition.mutated_kd29_3',
           'HiaCoreSyntaxSlice.WrongCondition.mutated_transport')
PARTS = tuple('CertPart%02d' % i for i in range(1, 8))
NAMES = ('Baseline', 'SyntaxData') + PARTS + ('ConnectionsTransportRejections', 'WrongArm')
COUNTS = (56, 547, 271, 54, 1164, 1298, 1297, 1297, 1297, 75, 1)
ROOT_OWNERS = dict(zip(original.ROOT_OWNERS, PARTS[2:]))
PREFIX_FRAME = '-- SEVEN_CERTIFICATE_PREFIX_V1\n'
CONNECTION_FRAME = '-- SEVEN_CERTIFICATE_CONNECTIONS_V1\n'
REJECTION_FRAME = '-- SEVEN_CERTIFICATE_REJECTIONS_V1\n'
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
MAX_MANIFEST = 32768
encode, digest = facts.encode, facts.digest


@dataclass(frozen=True)
class SevenCertificateSources:
    original_stages: tuple
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

    @property
    def retained_sources(self):
        return MappingProxyType({**{'original/' + s.name + '.lean': s.source for s in self.original_stages},
                                 **{'seven/' + s.name + '.lean': s.source for s in self.stages}})


def _aux(row):
    return row[1] == 'theorem' and re.fullmatch(r'.+_bf[0-9]{4}', row[2]) is not None


def _body(source):
    lines = source.splitlines(keepends=True)
    count = 0
    while count < len(lines) and lines[count].startswith('import '):
        count += 1
    require(count > 0, 'consumer leading import required')
    return ''.join(lines[:count]), ''.join(lines[count:])


def _prints(source):
    return tuple(re.findall(r'^#print axioms ([A-Za-z][A-Za-z0-9_.]*)$', source, re.M))


def _qualified_prints(source):
    """Resolve the frozen support's unqualified in-namespace print commands.

    Transport prints are absolute and outside namespaces; the authenticated
    Baseline also contains unqualified prints inside its namespace. Preserve
    literal print bytes separately in the manifest's sequence digest.
    """
    scopes, result = [], []
    for line in source.splitlines():
        if line.startswith('namespace '):
            scopes.append(line[10:].strip())
        elif line == 'mutual' or line == 'section' or line.startswith('section '):
            scopes.append(None)
        elif line == 'end' or line.startswith('end '):
            require(bool(scopes), 'print namespace stack')
            scopes.pop()
        elif line.startswith('#print axioms '):
            subject = line[len('#print axioms '):]
            if '.' not in subject:
                subject = '.'.join([n for n in scopes if n is not None] + [subject])
            result.append(subject)
    require(not scopes, 'closed print namespace stack')
    return tuple(result)


def _rows(stages):
    return tuple(row for stage in stages for row in original._parse(stage.source)[1])


def _cut(rows, cuts):
    blocks, cursor, count = [], 0, 0
    for stop in cuts:
        start = cursor
        while cursor < len(rows) and count < stop:
            row = rows[cursor]
            count += row[1] == 'theorem' and not _aux(row)
            cursor += 1
        require(count == stop, 'complete fixed cut')
        blocks.append(rows[start:cursor])
    require(cursor == len(rows), 'no unassigned declaration suffix')
    return tuple(blocks)


def _render(rows, parent):
    return original._render(rows, parent)


def _old_render(rows, parent):
    """Independent old print placement: original suffix, then auxiliary suffix."""
    text, names = _render(rows, parent)
    text = text[:text.index('#print axioms ')]
    originals = sorted(r[0] + '.' + r[2] for r in rows if r[1] == 'theorem' and not _aux(r))
    auxiliary = sorted(r[0] + '.' + r[2] for r in rows if _aux(r))
    return text + ''.join('#print axioms ' + n + '\n' for n in originals + auxiliary), names


def _stage(name, parent, source, names, rejections=()):
    return original._make_stage(name, parent, source, names, rejections)


def _derive_stages(old):
    blocks = _cut(_rows(old[2:8]), CUTS)
    stages = list(old[:2])
    prefix, names = _render(blocks[0], original.PREFIX + '.Baseline')
    prefix = prefix.split('\n', 1)[1]
    stages[1] = replace(old[1], source=old[1].source + PREFIX_FRAME + prefix,
                        expected_theorems=old[1].expected_theorems | names)
    for index, rows in enumerate(blocks[1:]):
        parent = original.PREFIX + '.' + ('SyntaxData' if index == 0 else PARTS[index - 1])
        source, names = _render(rows, parent)
        stages.append(_stage(PARTS[index], parent, source, names))
    parent = original.PREFIX + '.CertPart07'
    combined = 'import ' + parent + '\n' + CONNECTION_FRAME + _body(old[8].source)[1] + \
               REJECTION_FRAME + _body(old[9].source)[1]
    stages.append(_stage(NAMES[9], parent, combined, old[8].expected_theorems | old[9].expected_theorems,
                         old[8].rejection_names + old[9].rejection_names))
    parent = original.PREFIX + '.CertPart04'
    stages.append(_stage('WrongArm', parent, 'import ' + parent + '\n' + _body(old[10].source)[1],
                         old[10].expected_theorems, old[10].rejection_names))
    return tuple(stages)


def _extract(stages):
    require(stages[1].source.count(PREFIX_FRAME) == 1, 'unique prefix framing')
    syntax, prefix = stages[1].source.split(PREFIX_FRAME)
    imports, first, prints = original._parse('import ' + original.PREFIX + '.Baseline\n' + prefix)
    require(prints == tuple(sorted(r[0] + '.' + r[2] for r in first if r[1] == 'theorem')),
            'independent exact prefix print subjects and order')
    rendered, _ = _render(first, imports[0])
    require(rendered.split('\n', 1)[1] == prefix, 'exact prefix namespace and print framing')
    blocks = [first]
    for stage in stages[2:9]:
        imports, rows, prints = original._parse(stage.source)
        require(len(imports) == 1, 'one certificate parent')
        require(prints == tuple(sorted(r[0] + '.' + r[2] for r in rows if r[1] == 'theorem')),
                'independent exact certificate print subjects and order')
        require(_render(rows, imports[0])[0] == stage.source, 'canonical certificate namespace and print framing')
        blocks.append(rows)
    source = stages[9].source
    head = 'import ' + original.PREFIX + '.CertPart07\n' + CONNECTION_FRAME
    require(source.startswith(head) and source.count(CONNECTION_FRAME) == 1 and source.count(REJECTION_FRAME) == 1,
            'exact separate consumer framing')
    connections, rejections = source[len(head):].split(REJECTION_FRAME)
    return syntax, tuple(blocks), connections, rejections


def invert_sources(prepared, proposal):
    """Recover old transformed eleven from ACTUAL candidate declaration/body bytes.

    No serialized ownership row, byte digest, range, or caller-provided old
    transformed source is used to reconstruct the intermediate.
    """
    syntax, blocks, connections, rejections = _extract(proposal.stages)
    rows = tuple(r for block in blocks for r in block)
    old_blocks = _cut(rows, original.CUTS)
    stages = [proposal.stages[0], replace(prepared['stages'][1], source=syntax,
               expected_theorems=prepared['stages'][1].expected_theorems | facts.HELPER_NAMES)]
    for old, block in zip(prepared['stages'][2:8], old_blocks):
        source, names = _old_render(block, old.parents[0])
        stages.append(replace(old, source=source, expected_theorems=names))
    for old, body in zip(prepared['stages'][8:], (connections, rejections, _body(proposal.stages[10].source)[1])):
        stages.append(replace(old, source=_body(old.source)[0] + body))
    return tuple(stages)


def _transport_checks(blocks, stages):
    rows = tuple(r for b in blocks for r in b)
    require(sum(r[1] == 'def' for r in rows) == 7685 and sum(_aux(r) for r in rows) == 2975 and
            sum(r[1] == 'theorem' and not _aux(r) for r in rows) == 4215, 'complete transport declaration inventory')
    names = [r[0] + '.' + r[2] for r in rows]
    require(len(set(names)) == len(names), 'globally unique transport declarations')
    require(_cut(rows, CUTS) == blocks, 'fixed original-theorem cuts, not auxiliary counts')
    require(tuple(b[-1][0] + '.' + b[-1][2] for b in blocks) == ANCHORS, 'fixed end anchors')
    require(sum(r[1] == 'def' for r in blocks[0]) == 1257 and
            sum(len(r[3]) for r in blocks[0]) == 273199, 'exact structural prefix')
    # For this restricted generated language every transport reference is an
    # identifier token. Resolve local and qualified identifiers independently.
    positions = {n: i for i, n in enumerate(names)}
    owners = {r[0] + '.' + r[2]: stages[block_index + 1].module_name
              for block_index, block in enumerate(blocks) for r in block}
    ancestors = {}
    for stage in stages:
        inherited = set(stage.parents)
        for parent in stage.parents:
            inherited.update(ancestors.get(parent, set()))
        ancestors[stage.module_name] = inherited
    for i, (ns, kind, name, raw) in enumerate(rows):
        tail = raw.decode().split(name, 1)[1]
        for token in re.findall(r'[A-Za-z][A-Za-z0-9_.]*', tail):
            resolved = token if token in positions else ns + '.' + token
            if resolved in positions:
                require(positions[resolved] < i, 'forward or recursive transport reference')
                owner = owners[names[i]]
                require(owners[resolved] == owner or owners[resolved] in ancestors[owner],
                        'transport reference owner is not an imported ancestor')
    return rows


def _declared(source):
    """Names only, never consumer body parsing/re-emission.

    Authenticated old consumer/support bytes are also checked in full by the
    unchanged inverse validators. This scan detects environment collisions.
    """
    namespaces, names = [], []
    for line in source.splitlines():
        if line.startswith('namespace '):
            namespaces.append(line[10:].strip())
        elif line == 'mutual' or line == 'section' or line.startswith('section '):
            namespaces.append(None)
        elif line == 'end' or line.startswith('end '):
            require(bool(namespaces), 'unbalanced namespace')
            namespaces.pop()
        match = re.match(r'^(?:private |protected )?(?:def|theorem|abbrev|structure|inductive|class) ([A-Za-z][A-Za-z0-9_.]*)\b', line.strip())
        if match:
            names.append('.'.join([n for n in namespaces if n is not None] + [match[1]]))
    require(not namespaces and len(names) == len(set(names)), 'unique local declarations and closed namespaces')
    return set(names)


def _fixed_graph(prepared, stages):
    """Independent admission of source layout, not the emitter's proposed DAG."""
    require(stages[0] == prepared['stages'][0], 'unchanged baseline and locked external imports')
    expected_parent_names = ('Baseline', 'SyntaxData', 'CertPart01', 'CertPart02',
                             'CertPart03', 'CertPart04', 'CertPart05', 'CertPart06',
                             'CertPart07', 'CertPart04')
    for stage, name, parent_name in zip(stages[1:], NAMES[1:], expected_parent_names):
        parent = original.PREFIX + '.' + parent_name
        require(stage.name == name and stage.module_name == original.PREFIX + '.' + name,
                'fixed source module identity')
        require(stage.parents == (parent,) and stage.explicit_imports == (parent,) and
                stage.direct_imports == ('Init', parent), 'independent fixed parent DAG and implicit Init')
        require(tuple(re.findall(r'^import (.+)$', stage.source, re.M)) == (parent,),
                'independent literal source import graph')


def validate_retention(proposal, retained_copies=()):
    """Call before any future write/launch; all separate marker/execution/evidence
    copies must be supplied as actual serialized UTF-8 strings, even duplicates.
    This module itself writes and launches nothing and reserves no hidden copy.
    """
    require(type(retained_copies) is tuple and all(type(s) is str for s in retained_copies), 'explicit retained copy tuple')
    sources = tuple(proposal.retained_sources.values()) + retained_copies
    require(all(len(s.encode()) <= MAX_SOURCE for s in sources), 'retained module source limit')
    total = sum(len(s.encode()) for s in sources)
    require(total <= MAX_TOTAL_SOURCE, 'aggregate retained source limit including all copies')
    return total


def _manifest(prepared, stages, previous_manifest_hash):
    syntax, blocks, connections, rejections = _extract(stages)
    frames = {'syntax_prefix_start': len(syntax.encode()),
              'connections_body_bytes': len(connections.encode()),
              'rejections_body_bytes': len(rejections.encode()),
              'syntax_original_sha256': digest(syntax.encode()),
              'connections_body_sha256': digest(connections.encode()),
              'rejections_body_sha256': digest(rejections.encode())}
    locations = {}
    for stage in stages[9:]:
        for name in stage.rejection_names:
            local = prepared['negatives'][name]['certificate'].rsplit('.', 1)[1]
            lines = [i for i, line in enumerate(stage.source.splitlines(), 1) if line.startswith('theorem ' + local + ' :')]
            require(len(lines) == 1, 'unique actual negative declaration')
            locations[name] = dict(module=stage.module_name, line=lines[0])
    require(set(locations) == set(prepared['negatives']), 'complete ten current negative coordinates')
    result = dict(schema=SCHEMA, protocol=PROTOCOL, source_only=True, acceptance_eligible=False,
                  kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
                  python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                  all_edge_transfer_proved=False,
                  obligations=[dict(id=n, status='unproved') for n, _ in facts.OBLIGATIONS],
                  **facts.DENY, cuts=list(CUTS), anchors=list(ANCHORS), framing=frames,
                  original_manifest_sha256=prepared['manifest_sha256'],
                  previous_transform_manifest_sha256=previous_manifest_hash,
                  stages=[facts._compact(s) for s in stages],
                  parents=[list(s.parents) for s in stages],
                  print_sequence_sha256=[digest(encode(_prints(s.source)).encode()) for s in stages],
                  original_source_bytes=sum(s.source_bytes for s in prepared['stages']),
                  candidate_source_bytes=sum(s.source_bytes for s in stages),
                  retained_execution_copies=0, retained_marker_copies=0,
                  retained_source_bytes=sum(s.source_bytes for s in prepared['stages'] + stages),
                  negative_declaration_locations=locations,
                  historical_negatives=prepared['negatives'], expected_targets=sorted(prepared['expected_theorems']),
                  inputs_sha256=digest(encode(prepared['manifest']['inputs']).encode()),
                  transport_definitions=7685, transport_theorems=4215, auxiliary_theorems=2975,
                  root_owners=ROOT_OWNERS, timing_measured=False)
    require(len(encode(result).encode()) <= MAX_MANIFEST, 'compact manifest cap')
    return result


def build_sources(prepared):
    previous = facts.build_sources(prepared)
    stages = _derive_stages(previous.stages)
    previous_hash = previous.manifest_sha256
    del previous  # never retain a third full source generation in the proposal
    result = SevenCertificateSources(prepared['stages'], stages, encode(_manifest(prepared, stages, previous_hash)))
    validate_sources(prepared, result)
    return result


def build_inputs():
    return build_sources(original.build_inputs())


def validate_sources(prepared, proposal, retained_copies=()):
    facts._original(prepared)
    require(type(proposal) is SevenCertificateSources and type(proposal.stages) is tuple and
            proposal.original_stages == prepared['stages'] and tuple(s.name for s in proposal.stages) == NAMES,
            'distinct seven-certificate type and exact eleven stages')
    require(type(proposal.manifest_json) is str and len(proposal.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded manifest serialization')
    manifest = proposal.manifest
    require(type(manifest) is dict and manifest.get('schema') == SCHEMA and manifest.get('protocol') == PROTOCOL,
            'distinct source-only schema and protocol')
    require(type(manifest.get('cuts')) is list and all(type(n) is int for n in manifest['cuts']) and
            tuple(manifest['cuts']) == CUTS, 'exact integer cut vector')
    retained = validate_retention(proposal, retained_copies)
    syntax, blocks, _, _ = _extract(proposal.stages)
    _fixed_graph(prepared, proposal.stages)
    _transport_checks(blocks, proposal.stages)
    # The original generator is used only to obtain the authenticated old edit
    # ledger. Release its temporary source tuple before reconstructing our own.
    previous = facts._derive(prepared)
    old_manifest_json, previous_hash = previous.manifest_json, previous.manifest_sha256
    del previous
    recovered = invert_sources(prepared, proposal)
    restored = facts.ByteFactsSources(prepared['stages'], recovered, old_manifest_json)
    facts.validate_sources(prepared, restored)  # unchanged full byte/input/inverse checks
    expected_stages = _derive_stages(recovered)
    require(proposal.stages == expected_stages, 'exact source, imports, ownership, prints and rejection metadata')
    # Baseline imports are external support and already authenticated above.
    environments = {p: set() for p in proposal.stages[0].parents}
    for stage in proposal.stages:
        own = _declared(stage.source)
        require(all(p in environments for p in stage.parents), 'parent order and no forward imports')
        inherited = set().union(*(environments[p] for p in stage.parents))
        require(not own & inherited, 'transitive declaration collision')
        environments[stage.module_name] = inherited | own
    require(tuple(len(_prints(s.source)) for s in proposal.stages) == COUNTS and
            tuple(len(s.expected_theorems) for s in proposal.stages) == COUNTS, 'exact printed subject multiplicities')
    require(all(stage.expected_theorems == frozenset(_qualified_prints(stage.source)) for stage in proposal.stages),
            'independent inventory exactly matches actual print subjects')
    expected_manifest = _manifest(prepared, proposal.stages, previous_hash)
    require(proposal.manifest_json == encode(expected_manifest), 'independently derived compact manifest including exact integer types')
    del restored, recovered, expected_stages
    return dict(source_only=True, acceptance_eligible=False, authority='DENY_ALL', stage_counts=COUNTS,
                manifest_bytes=len(proposal.manifest_json.encode()), retained_source_bytes=retained,
                candidate_source_bytes=expected_manifest['candidate_source_bytes'])

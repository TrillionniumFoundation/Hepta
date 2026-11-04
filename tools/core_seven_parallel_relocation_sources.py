"""Reversible parallel-fact relocation, SOURCE ONLY; no execution API.

Move exactly parallel_bf0000..0490 from CertPart04 to the CertPart03 tail.
The old seven proposal is temporary validation context, never retained here.
This layout has no transferred proof receipts or measured runtime advantage.
"""
from collections import Counter
from dataclasses import dataclass, replace
import json
import re
from types import MappingProxyType

from tools import core_seven_certificate_sources as seven
from tools.check_guarded_slice_lean import require

PROTOCOL = 'seven-parallel-relocation-source-v1'
SCHEMA = 'hepta.hia.seven-parallel-relocation-source.v1'
COUNTS = (56, 547, 271, 54, 1655, 807, 1297, 1297, 1297, 75, 1)
MOVED_NAMES = tuple('HiaCoreSyntaxSlice.parallel_bf%04d' % i for i in range(491))
REMAINING_NAMES = tuple('HiaCoreSyntaxSlice.parallel_bf%04d' % i for i in range(491, 595))
ANCHOR = 'HiaCoreSyntaxSlice.parallel_pl113_0'
MOVED_BYTES = 100165
MAX_SOURCE, MAX_TOTAL_SOURCE, MAX_MANIFEST = seven.MAX_SOURCE, seven.MAX_TOTAL_SOURCE, seven.MAX_MANIFEST
encode, digest = seven.encode, seven.digest


@dataclass(frozen=True)
class ParallelRelocationSources:
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
                                 **{'relocated/' + s.name + '.lean': s.source for s in self.stages}})


def _name(row):
    return row[0] + '.' + row[2]


def _render_stage(stage, rows):
    source, names = seven.original._render(rows, stage.parents[0])
    return replace(stage, source=source, expected_theorems=names)


def _derive_stages(previous):
    stages = list(previous.stages)
    left = seven.original._parse(stages[4].source)[1]
    right = seven.original._parse(stages[5].source)[1]
    start = next(i for i, r in enumerate(right) if seven._aux(r))
    moved = right[start:start + len(MOVED_NAMES)]
    require(tuple(map(_name, moved)) == MOVED_NAMES, 'exact old moved range')
    stages[4] = _render_stage(stages[4], left + moved)
    stages[5] = _render_stage(stages[5], right[:start] + right[start + len(moved):])
    return tuple(stages)


def _recover(previous, stages):
    """Recover full old stages from ACTUAL candidate rows, not manifest snippets."""
    left = seven.original._parse(stages[4].source)[1]
    right = seven.original._parse(stages[5].source)[1]
    require(len(left) > len(MOVED_NAMES), 'complete Part03 tail and anchor')
    moved = left[-len(MOVED_NAMES):]
    require(tuple(map(_name, moved)) == MOVED_NAMES and all(seven._aux(r) for r in moved),
            'exact ordered 491 auxiliary tail')
    require(_name(left[-len(MOVED_NAMES) - 1]) == ANCHOR, 'fixed immediately preceding Part03 anchor')
    require(sum(len(r[3]) for r in moved) == MOVED_BYTES, 'exact moved raw byte count')
    auxiliary = tuple(r for r in right if seven._aux(r))
    require(tuple(map(_name, auxiliary)) == REMAINING_NAMES, 'exact 104 remaining Part04 facts')
    start = next(i for i, r in enumerate(right) if seven._aux(r))
    recovered = list(stages)
    recovered[4] = _render_stage(stages[4], left[:-len(MOVED_NAMES)])
    recovered[5] = _render_stage(stages[5], right[:start] + moved + right[start:])
    return seven.SevenCertificateSources(previous.original_stages, tuple(recovered), previous.manifest_json)


def _candidate_checks(prepared, previous, stages):
    # _extract checks actual canonical namespace framing and sorted print suffixes;
    # unlike _transport_checks it does not impose the old auxiliary placement.
    _, blocks, _, _ = seven._extract(stages)
    seven._fixed_graph(prepared, stages)
    for index, (actual, old) in enumerate(zip(stages, previous.stages)):
        if index not in (4, 5):
            require(actual == old, 'nine unchanged stages including actual metadata')
        else:
            rows = blocks[index - 1]
            names = frozenset(_name(r) for r in rows if r[1] == 'theorem')
            # Compare ACTUAL metadata before reconstruction can replace anything.
            require(actual == replace(old, source=actual.source, expected_theorems=names),
                    'actual stage identity, imports, parents, theorem and rejection metadata')
    rows = tuple(r for block in blocks for r in block)
    names = tuple(map(_name, rows))
    require(len(set(names)) == len(names), 'globally unique transport declarations')
    require(sum(r[1] == 'def' for r in rows) == 7685 and
            sum(seven._aux(r) for r in rows) == 2975 and
            sum(r[1] == 'theorem' and not seven._aux(r) for r in rows) == 4215,
            'exact definitions, original theorems and auxiliary inventory')
    # Separate actual candidate dependency scan: no invocation of the old fixed
    # cut/anchor transport checker, which correctly rejects this new layout.
    positions = {name: i for i, name in enumerate(names)}
    owners = {_name(r): stages[index + 1].module_name
              for index, block in enumerate(blocks) for r in block}
    ancestors = {}
    for stage in stages:
        inherited = set(stage.parents)
        for parent in stage.parents:
            inherited.update(ancestors.get(parent, set()))
        ancestors[stage.module_name] = inherited
    for i, (ns, kind, name, raw) in enumerate(rows):
        for token in re.findall(r'[A-Za-z][A-Za-z0-9_.]*', raw.decode().split(name, 1)[1]):
            resolved = token if token in positions else ns + '.' + token
            if resolved in positions:
                require(positions[resolved] < i, 'forward or recursive candidate dependency')
                owner = owners[names[i]]
                require(owners[resolved] == owner or owners[resolved] in ancestors[owner],
                        'candidate dependency is not in same module or ancestor')
    environments = {parent: set() for parent in stages[0].parents}
    for stage in stages:
        own = seven._declared(stage.source)
        require(all(p in environments for p in stage.parents), 'candidate parent order')
        inherited = set().union(*(environments[p] for p in stage.parents))
        require(not own & inherited, 'candidate transitive declaration collision')
        environments[stage.module_name] = inherited | own
    require(tuple(len(seven._prints(s.source)) for s in stages) == COUNTS and
            tuple(len(s.expected_theorems) for s in stages) == COUNTS,
            'fixed candidate stage counts')
    require(all(s.expected_theorems == frozenset(seven._qualified_prints(s.source)) for s in stages),
            'actual metadata exactly matches printed theorem inventory')
    require(Counter(n for s in stages for n in seven._qualified_prints(s.source)) ==
            Counter(n for s in previous.stages for n in seven._qualified_prints(s.source)),
            'unchanged combined printed inventory with multiplicities')


def validate_retention(proposal, retained_copies=()):
    """Every extra serialized source/marker/evidence copy must be charged."""
    require(type(retained_copies) is tuple and all(type(s) is str for s in retained_copies),
            'explicit retained copies')
    # Do not use a mapping whose duplicate names might hide retained bytes.
    sources = tuple(s.source for s in proposal.original_stages + proposal.stages) + retained_copies
    require(all(type(s) is str and len(s.encode()) <= MAX_SOURCE for s in sources), 'per-source cap')
    total = sum(len(s.encode()) for s in sources)
    require(total <= MAX_TOTAL_SOURCE, 'all retained copies aggregate cap')
    return total


def _manifest(prepared, previous, stages):
    moved = seven.original._parse(stages[4].source)[1][-len(MOVED_NAMES):]
    result = dict(schema=SCHEMA, protocol=PROTOCOL, source_only=True, acceptance_eligible=False,
                  kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
                  python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                  all_edge_transfer_proved=False, timing_measured=False,
                  obligations=[dict(id=n, status='unproved') for n, _ in seven.facts.OBLIGATIONS],
                  **seven.facts.DENY,
                  original_manifest_sha256=prepared['manifest_sha256'],
                  previous_seven_manifest_sha256=previous.manifest_sha256,
                  inputs_sha256=digest(encode(prepared['manifest']['inputs']).encode()),
                  stages=[seven.facts._compact(s) for s in stages],
                  parents=[list(s.parents) for s in stages],
                  print_sequence_sha256=[digest(encode(seven._prints(s.source)).encode()) for s in stages],
                  moved_names=list(MOVED_NAMES), moved_count=len(MOVED_NAMES), moved_raw_bytes=MOVED_BYTES,
                  moved_raw_sha256=digest(b''.join(r[3] for r in moved)),
                  from_stage='CertPart04', to_stage='CertPart03', anchor=ANCHOR,
                  remaining_auxiliaries=len(REMAINING_NAMES), stage_counts=list(COUNTS),
                  transport_definitions=7685, transport_theorems=4215, auxiliary_theorems=2975,
                  root_owners=seven.ROOT_OWNERS,
                  original_source_bytes=sum(s.source_bytes for s in prepared['stages']),
                  candidate_source_bytes=sum(s.source_bytes for s in stages),
                  retained_source_bytes=sum(s.source_bytes for s in prepared['stages'] + stages),
                  retained_execution_copies=0, retained_marker_copies=0)
    require(len(encode(result).encode()) <= MAX_MANIFEST, 'bounded derived manifest')
    return result


def build_sources(prepared, previous=None):
    """Return only original+candidate sources; old proposal is temporary context."""
    if previous is None:
        previous = seven.build_sources(prepared)
    stages = _derive_stages(previous)
    proposal = ParallelRelocationSources(prepared['stages'], stages, encode(_manifest(prepared, previous, stages)))
    validate_sources(prepared, previous, proposal)
    return proposal


def build_inputs():
    return build_sources(seven.original.build_inputs())


def validate_sources(prepared, previous, proposal, retained_copies=()):
    require(type(proposal) is ParallelRelocationSources and type(proposal.stages) is tuple and
            type(proposal.original_stages) is tuple and proposal.original_stages == prepared['stages'] and
            len(proposal.stages) == 11, 'distinct candidate type and exact original stages')
    require(type(proposal.manifest_json) is str and len(proposal.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded candidate manifest')
    # Both calls are mandatory; the second consumes reconstruction from actual
    # candidate bytes, not an emitter-side or serialized relocation ledger.
    seven.validate_sources(prepared, previous)
    retained = validate_retention(proposal, retained_copies)
    _candidate_checks(prepared, previous, proposal.stages)
    recovered = _recover(previous, proposal.stages)
    require(recovered == previous, 'full reconstructed old stage/source/metadata equality')
    seven.validate_sources(prepared, recovered)
    expected_manifest = _manifest(prepared, previous, proposal.stages)
    # Canonical JSON equality distinguishes every bool/int/float, duplicate key,
    # unexpected field and forged commitment without Python's True == 1 trap.
    require(proposal.manifest_json == encode(expected_manifest), 'strict independently derived manifest')
    return dict(source_only=True, acceptance_eligible=False, authority='DENY_ALL', stage_counts=COUNTS,
                manifest_bytes=len(proposal.manifest_json.encode()), retained_source_bytes=retained,
                candidate_source_bytes=expected_manifest['candidate_source_bytes'])

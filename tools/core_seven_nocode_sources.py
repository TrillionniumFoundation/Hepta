"""Suppress executable compilation of pure certificate data, preserving proofs.

This source-only proposal changes exactly the 7,685 transport ``def`` headers
to ``noncomputable def``.  In Lean 4.19 this suppresses executable compilation;
it does not replace kernel reduction or introduce a new axiom.  The complete
inverse must recover the previously validated relocated sources byte for byte.
The noncomputable environment metadata intentionally differs.
"""
from dataclasses import dataclass, replace
import json
import re
from types import MappingProxyType

from tools import core_seven_certificate_sources as seven
from tools import core_seven_parallel_relocation_sources as relocated
from tools.check_guarded_slice_lean import require

SCHEMA = 'hepta.hia.seven-data-nocode-source.v1'
PROTOCOL = 'seven-data-nocode-source-v1'
DEFINITION_COUNT = 7685
PREFIX = 'noncomputable '
COUNTS = relocated.COUNTS
MAX_SOURCE, MAX_TOTAL_SOURCE, MAX_MANIFEST = seven.MAX_SOURCE, seven.MAX_TOTAL_SOURCE, seven.MAX_MANIFEST
encode, digest = seven.encode, seven.digest


@dataclass(frozen=True)
class NoCodeSources:
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
                                 **{'nocode/' + s.name + '.lean': s.source for s in self.stages}})


def _relocated(prepared, previous):
    """Derive scaffolding only; the actual inverse is validated below."""
    stages = relocated._derive_stages(previous)
    return relocated.ParallelRelocationSources(
        prepared['stages'], stages, encode(relocated._manifest(prepared, previous, stages)))


def _definitions(previous):
    _, blocks, _, _ = seven._extract(previous.stages)
    result = {s.name: frozenset() for s in previous.stages}
    for i, rows in enumerate(blocks):
        names = tuple(ns + '.' + name for ns, kind, name, _ in rows if kind == 'def')
        require(len(names) == len(set(names)), 'unique transport definition names')
        result[previous.stages[i + 1].name] = frozenset(names)
    all_names = [n for names in result.values() for n in names]
    require(len(all_names) == DEFINITION_COUNT and len(set(all_names)) == DEFINITION_COUNT,
            'complete unique transport definition inventory')
    return result


def _transform(source, names, *, inverse=False):
    """Resolve actual command namespaces; never substitute by an untrusted ledger."""
    require(type(source) is str and type(names) is frozenset, 'exact source and name-set types')
    scopes, seen, result = [], set(), []
    for line in source.splitlines(keepends=True):
        bare = line.rstrip('\n')
        if bare.startswith('namespace '):
            scopes.append(bare[len('namespace '):].strip())
        elif bare == 'mutual' or bare == 'section' or bare.startswith('section '):
            scopes.append(None)
        elif bare == 'end' or bare.startswith('end '):
            require(bool(scopes), 'closed namespace/section stack')
            scopes.pop()
        match = re.match(r'^(noncomputable )?def ([A-Za-z][A-Za-z0-9_.]*)\b', line)
        if match:
            qualified = '.'.join([n for n in scopes if n is not None] + [match[2]])
            if qualified in names:
                require(qualified not in seen, 'duplicate marked definition')
                require(bool(match[1]) == inverse, 'required exact noncomputable header')
                seen.add(qualified)
                line = line[len(PREFIX):] if inverse else PREFIX + line
        result.append(line)
    require(not scopes and seen == names, 'all and only expected data definitions transformed')
    return ''.join(result)


def _derive_stages(prepared, previous):
    old = _relocated(prepared, previous)
    names = _definitions(old)
    return tuple(replace(s, source=_transform(s.source, names[s.name])) for s in old.stages)


def _manifest(prepared, previous, old, stages):
    names = _definitions(old)
    return dict(
        schema=SCHEMA, protocol=PROTOCOL, source_only=True, acceptance_eligible=False,
        kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
        python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
        all_edge_transfer_proved=False, timing_measured=False,
        obligations=[dict(id=n, status='unproved') for n, _ in seven.facts.OBLIGATIONS],
        **seven.facts.DENY,
        original_manifest_sha256=prepared['manifest_sha256'],
        previous_seven_manifest_sha256=previous.manifest_sha256,
        previous_relocation_manifest_sha256=old.manifest_sha256,
        inputs_sha256=digest(encode(prepared['manifest']['inputs']).encode()),
        root_owners=seven.ROOT_OWNERS, stage_counts=list(COUNTS),
        transport_definitions=DEFINITION_COUNT, transport_theorems=4215, auxiliary_theorems=2975,
        prefix=PREFIX, added_source_bytes=len(PREFIX) * DEFINITION_COUNT,
        stages=[dict(seven.facts._compact(s), original_source_sha256=o.source_sha256,
                     definition_count=len(names[s.name]),
                     definition_names_sha256=digest(encode(sorted(names[s.name])).encode()))
                for s, o in zip(stages, old.stages)],
        original_source_bytes=sum(s.source_bytes for s in prepared['stages']),
        candidate_source_bytes=sum(s.source_bytes for s in stages),
        retained_source_bytes=sum(s.source_bytes for s in prepared['stages'] + stages))


def validate_retention(proposal, retained_copies=()):
    return relocated.validate_retention(proposal, retained_copies)


def validate_sources(prepared, previous, proposal, retained_copies=()):
    require(type(proposal) is NoCodeSources and type(proposal.stages) is tuple and
            type(proposal.original_stages) is tuple and proposal.original_stages == prepared['stages'],
            'distinct candidate type and complete originals')
    require(type(proposal.manifest_json) is str and len(proposal.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded source manifest')
    require(tuple(s.name for s in proposal.stages) == seven.NAMES, 'exact eleven stage schedule')
    old = _relocated(prepared, previous)
    names = _definitions(old)
    recovered = []
    for actual, prior in zip(proposal.stages, old.stages):
        restored = _transform(actual.source, names[actual.name], inverse=True)
        require(actual == replace(prior, source=actual.source), 'unchanged actual metadata and inventory')
        require(restored == prior.source, 'complete byte-exact source inverse')
        require(actual.source == _transform(restored, names[actual.name]), 'unique forward transformation')
        recovered.append(replace(actual, source=restored))
    require(tuple(len(s.expected_theorems) for s in proposal.stages) == COUNTS, 'unchanged exact inventories')
    expected = _manifest(prepared, previous, old, proposal.stages)
    require(proposal.manifest_json == encode(expected), 'strict independently reconstructed source manifest')
    total = validate_retention(proposal, retained_copies)
    recovered = relocated.ParallelRelocationSources(prepared['stages'], tuple(recovered), old.manifest_json)
    relocated.validate_sources(prepared, previous, recovered)
    return dict(source_only=True, acceptance_eligible=False, authority='DENY_ALL',
                stage_counts=COUNTS, definition_count=DEFINITION_COUNT,
                retained_source_bytes=total, candidate_source_bytes=expected['candidate_source_bytes'],
                manifest_bytes=len(proposal.manifest_json.encode()))


def build_sources(prepared, previous=None):
    if previous is None:
        previous = seven.build_sources(prepared)
    old = _relocated(prepared, previous)
    names = _definitions(old)
    stages = tuple(replace(s, source=_transform(s.source, names[s.name])) for s in old.stages)
    proposal = NoCodeSources(prepared['stages'], stages,
                            encode(_manifest(prepared, previous, old, stages)))
    validate_sources(prepared, previous, proposal)
    return proposal


def build_inputs():
    return build_sources(seven.original.build_inputs())

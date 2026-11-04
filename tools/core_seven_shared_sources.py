"""Source-only symbolic composition proposal, with a byte-exact proof-edit inverse.

Data, theorem statements, inputs and original subject inventories are preserved.
Only explicitly derived proof bodies are replaced by shared theorem instances.
The new helper proofs still require the actual pinned Lean kernel; Python grants
no proof or admission authority. The inverse recovers and validates every prior
source byte before a candidate may be launched.
"""
from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
from types import MappingProxyType

from tools import core_seven_nocode_sources as nocode
from tools.check_guarded_slice_lean import require

seven = nocode.seven
encode, digest = nocode.encode, nocode.digest
SCHEMA = 'hepta.hia.seven-shared-composition-source.v3'
PROTOCOL = 'seven-shared-composition-source-v3'
HELPER_PATH = 'experiments/hia_initialization_frontiers_20261103/SharedTransport.lean'
NAMESPACE = 'HiaCoreSyntaxSlice.Shared'
HELPER_NAMES = frozenset(NAMESPACE + '.' + name for name in (
    'serialize_fields_single_packet', 'serialize_fields_cons_packet',
    'parse_fields_last_packet', 'parse_fields_cons_packet', 'parse_items_cons_bytes',
    'parse_array_bytes', 'parse_object_bytes', 'parse_root',
    'serialize_string_rebase', 'parse_string_rebase'))
GENERIC_FRAME = '-- SHARED_GENERIC_PARENT_V2\n'
PREFIX_CUTS = (256, 546, 837)
GENERIC_COUNT = 35 + len(HELPER_NAMES)
COUNTS = (nocode.COUNTS[0] + GENERIC_COUNT, 256, 290, 291, *nocode.COUNTS[4:])
MAX_SOURCE, MAX_TOTAL_SOURCE, MAX_MANIFEST = nocode.MAX_SOURCE, nocode.MAX_TOTAL_SOURCE, nocode.MAX_MANIFEST


@dataclass(frozen=True)
class SharedSources:
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
                                 **{'shared/' + s.name + '.lean': s.source for s in self.stages}})


def helper_source():
    source = (Path(__file__).resolve().parents[1] / HELPER_PATH).read_text()
    require(source.startswith('/-!') and source.endswith('end ' + NAMESPACE + '\n'),
            'closed shared helper framing')
    require(not re.search(r'(?m)^\s*(import|prelude|axiom|opaque|unsafe|initialize|run_cmd|run_elab|set_option)\b|\b(sorry|native_decide)\b',
                          source), 'no additional trust or options in helpers')
    names = tuple(NAMESPACE + '.' + x for x in re.findall(r'(?m)^theorem ([A-Za-z][A-Za-z0-9_]*)\b', source))
    require(len(names) == len(set(names)) and frozenset(names) == HELPER_NAMES,
            'exact additional helper subject inventory')
    return source + ''.join('#print axioms ' + name + '\n' for name in sorted(HELPER_NAMES))


def _arguments(text):
    """Tokenize the fixed generated application syntax without evaluating Lean."""
    result, start, stack = [], 0, []
    pairs = {')': '(', ']': '[', '}': '{'}
    for i, char in enumerate(text):
        if char in '([{':
            stack.append(char)
        elif char in ')]}':
            require(bool(stack) and stack.pop() == pairs[char], 'balanced application syntax')
        elif char == ' ' and not stack:
            if i > start:
                result.append(text[start:i])
            start = i + 1
    require(not stack, 'closed application syntax')
    if len(text) > start:
        result.append(text[start:])
    require(bool(result), 'nonempty theorem application')
    return result


def _simpa(proof):
    require(proof.startswith('by\n  simpa only [') and proof.endswith(')\n'),
            'fixed compositional proof form')
    rules, term = proof[len('by\n  simpa only ['):].split('] using (', 1)
    return rules.split(', '), term[:-2]


def _body(raw):
    text = raw.decode('utf-8')
    require(text.count(' := ') >= 1, 'declaration body delimiter')
    return text.split(' := ', 1)


def _literal_family(name):
    for family, pattern in (('byte_facts', r'.+_bf[0-9]{4}'),
                            ('key_domain', r'.+_kd[0-9]+_[0-9]+'),
                            ('key_parser', r'.+_kp[0-9]+_[0-9]+')):
        if re.fullmatch(pattern, name):
            return family
    return None


def _reuse_string(ns, name, raw, definitions, first_proofs):
    """Share atomic string proofs across positive fuel/depth values only."""
    if not re.fullmatch(r'.+_[sp][0-9]+', name):
        return None
    header, proof = _body(raw)
    serial = re.fullmatch(r'.+_s[0-9]+', name) is not None
    if proof != ('by decide +kernel\n' if serial else 'by rfl\n'):
        return None
    if serial:
        match = re.fullmatch(r'theorem [A-Za-z][A-Za-z0-9_]* : serializeRaw ([0-9]+) ([0-9]+) ([A-Za-z][A-Za-z0-9_]*) = some ([A-Za-z][A-Za-z0-9_]*)', header)
        require(match is not None, 'atomic serializer statement shape')
        raw_name, bytes_name = match[3], match[4]
    else:
        match = re.fullmatch(r'theorem [A-Za-z][A-Za-z0-9_]* \(tail : List Nat\) : parseRaw ([0-9]+) ([0-9]+) \(([A-Za-z][A-Za-z0-9_]*) \+\+ tail\) = some \(([A-Za-z][A-Za-z0-9_]*), tail\)', header)
        require(match is not None, 'atomic parser statement shape')
        raw_name, bytes_name = match[4], match[3]
    require(ns + '.' + raw_name in definitions and ns + '.' + bytes_name in definitions,
            'atomic proof references original data')
    value = re.fullmatch(r'\(\.str (\[[0-9, ]*\])\)', definitions[ns + '.' + raw_name])
    if value is None:
        return None  # no fuel rule for numbers, arrays, objects, or generic Raw
    literal = tuple(json.loads(value[1]))
    require(all(type(x) is int and x >= 0 for x in literal), 'exact atomic Nat literal values')
    fuel, depth = int(match[1]), int(match[2])
    require(fuel > 0 and depth > 0, 'atomic rebase explicitly excludes exhausted bounds')
    key = (serial, literal)
    if key not in first_proofs:
        first_proofs[key] = (ns + '.' + name, fuel, depth)
        return None
    reference, prior_fuel, prior_depth = first_proofs[key]
    args = [str(n - 1) for n in (prior_fuel, prior_depth, fuel, depth)]
    args += [value[1], bytes_name if serial else '(' + value[1] + ' ++ [34])', reference]
    helper = 'serialize_string_rebase' if serial else 'parse_string_rebase'
    if not serial:
        args.append('tail')
    return (header + ' := by\n  exact (' + NAMESPACE + '.' + helper + ' ' +
            ' '.join(args) + ')\n').encode()


def _reuse_literal(ns, name, raw, definitions, first_proofs):
    """Reference an earlier proof of the same literal proposition.

    This table selects proof text only. The complete target statement remains
    unchanged, and Lean must check the proposed reference against that statement.
    Never cache a Boolean answer, an axiom inventory, or a validation outcome.
    """
    family = _literal_family(name)
    if family is None:
        return None
    header, proof = _body(raw)
    if family == 'byte_facts':
        if proof != 'by unfold HiaCoreSyntaxSlice.ByteFactsResearch.facts; decide +kernel\n':
            return None
        match = re.fullmatch(r'theorem [A-Za-z][A-Za-z0-9_]* : HiaCoreSyntaxSlice\.ByteFactsResearch\.facts ([A-Za-z][A-Za-z0-9_]*) ([0-9]+)', header)
        require(match is not None, 'literal byte-fact statement shape')
        identifier, length = match[1], int(match[2])
    elif family == 'key_domain':
        require(proof == 'by decide +kernel\n', 'original key-domain proof form')
        match = re.fullmatch(r'theorem [A-Za-z][A-Za-z0-9_]* : stringBytes ([A-Za-z][A-Za-z0-9_]*) = true', header)
        require(match is not None, 'literal key-domain statement shape')
        identifier, length = match[1], None
    else:
        require(proof == 'by rfl\n', 'original key-parser proof form')
        match = re.fullmatch(r'theorem [A-Za-z][A-Za-z0-9_]* \(tail : List Nat\) : parseStringTail \(([A-Za-z][A-Za-z0-9_]*) \+\+ \(34 :: 58 :: tail\)\) \[\] = some \(([A-Za-z][A-Za-z0-9_]*), 58 :: tail\)', header)
        require(match is not None and match[1] == match[2], 'literal key-parser binding and suffix')
        identifier, length = match[1], None
    qualified = ns + '.' + identifier
    require(qualified in definitions, 'literal theorem references original data')
    value = definitions[qualified]
    require(re.fullmatch(r'\[\s*(?:[0-9]+\s*(?:,\s*[0-9]+\s*)*)?\]', value) is not None,
            'closed original Nat literal list')
    literal = tuple(json.loads(value))
    require(all(type(x) is int and x >= 0 for x in literal), 'exact nonnegative Nat literal values')
    require(length is None or length == len(literal), 'original literal length remains exact')
    key = (family, literal, length)
    if key not in first_proofs:
        first_proofs[key] = ns + '.' + name
        return None  # the first occurrence still receives its original proof
    reference = first_proofs[key]
    arguments = ' tail' if family == 'key_parser' else ''
    return (header + ' := by\n  exact (' + reference + arguments + ')\n').encode()


def _rewrite(ns, name, raw, definitions):
    if seven._aux((ns, 'theorem', name, raw)):
        return raw  # preserve every earlier byte-fact proof verbatim
    header, proof = _body(raw)
    if not proof.startswith('by\n  simpa only ['):
        return raw
    rules, term = _simpa(proof)
    args = _arguments(term)
    fn, args = args[0], args[1:]
    prefix = 'HiaCoreSyntaxSlice.Structured.'
    new = None

    def rhs(identifier):
        key = ns + '.' + identifier
        require(key in definitions, 'referenced concrete data definition exists')
        return definitions[key]

    def data(pattern, identifier):
        match = re.fullmatch(pattern, rhs(identifier))
        require(match is not None, 'exact original generated byte expression')
        return match.groups()

    def call(name, values):
        return NAMESPACE + '.' + name + ' ' + ' '.join(values)

    if fn == prefix + 'serialize_fields_single':
        require(len(args) == 7 and len(rules) >= 4 and rules[2] == args[2], 'single field inputs')
        packet, output = data(r'([A-Za-z][A-Za-z0-9_]*) \+\+ ([A-Za-z][A-Za-z0-9_]*)', rules[1])
        require(packet == rules[3] and output == args[4], 'single field packet and value binding')
        new = call('serialize_fields_single_packet', args[:5] + [packet, '(by rfl)'] + args[5:])
    elif fn == prefix + 'serialize_fields_cons':
        require(len(args) == 11 and len(rules) >= 4 and rules[2] == args[2], 'field cons inputs')
        packet, output, suffix = data(r'\(([A-Za-z][A-Za-z0-9_]*) \+\+ ([A-Za-z][A-Za-z0-9_]*)\) \+\+ \(44 :: ([A-Za-z][A-Za-z0-9_]*)\)', rules[1])
        require(packet == rules[3] and (output, suffix) == (args[6], args[7]), 'field cons byte binding')
        new = call('serialize_fields_cons_packet', args[:8] + [packet, '(by rfl)'] + args[8:])
    elif fn in {prefix + 'serialize_items_single', prefix + 'serialize_items_cons',
                prefix + 'serialize_array', prefix + 'serialize_object', prefix + 'parse_items_last'}:
        # These result spines are already definitionally equal. Avoid asking the
        # simplifier to traverse concrete child bytes or Raw terms again.
        new = term
    elif fn == prefix + 'parse_fields_last':
        require(len(args) == 9 and len(rules) >= 4, 'last field parser inputs')
        packet, output = data(r'([A-Za-z][A-Za-z0-9_]*) \+\+ ([A-Za-z][A-Za-z0-9_]*)', rules[1])
        require(packet == rules[3] and rules[2] == args[3], 'last field parser packet')
        new = call('parse_fields_last_packet', args[:2] + [args[3], args[6], output, packet, args[5],
                                                        '(by rfl)', args[7], args[8]])
    elif fn == prefix + 'parse_fields_cons':
        require(len(args) == 12 and len(rules) >= 4, 'field cons parser inputs')
        packet, output, suffix = data(r'\(([A-Za-z][A-Za-z0-9_]*) \+\+ ([A-Za-z][A-Za-z0-9_]*)\) \+\+ \(44 :: ([A-Za-z][A-Za-z0-9_]*)\)', rules[1])
        require(packet == rules[3] and rules[2] == args[3], 'field cons parser packet')
        new = call('parse_fields_cons_packet', args[:2] + [args[3], args[7], args[8], output,
                    suffix, packet, args[6], '(by rfl)', args[9], args[10], args[11]])
    elif fn == prefix + 'parse_items_cons':
        require(len(args) == 9, 'item cons parser inputs')
        output, suffix = data(r'\(([A-Za-z][A-Za-z0-9_]*)\) \+\+ \(44 :: ([A-Za-z][A-Za-z0-9_]*)\)', rules[1])
        new = call('parse_items_cons_bytes', args[:2] + [args[5], args[6], output, suffix,
                                                       args[4], args[7], args[8]])
    elif fn == prefix + 'parse_array':
        require(len(args) == 7, 'array parser inputs')
        _, body, _ = data(r'([A-Za-z][A-Za-z0-9_]*) \+\+ \(([A-Za-z][A-Za-z0-9_]*) \+\+ ([A-Za-z][A-Za-z0-9_]*)\)', rules[1])
        new = call('parse_array_bytes', args[:2] + [args[4], body, args[3], args[5], args[6]])
    elif fn == prefix + 'parse_object':
        require(len(args) == 7, 'object parser inputs')
        _, body, _ = data(r'([A-Za-z][A-Za-z0-9_]*) \+\+ \(([A-Za-z][A-Za-z0-9_]*) \+\+ ([A-Za-z][A-Za-z0-9_]*)\)', rules[1])
        require(args[6].startswith('(by simpa only [') and args[6].endswith(')'), 'old object bridge proof')
        bridge = args[6][len('(by simpa only ['):-1].split('] using (', 1)[1]
        require(bridge.endswith(')'), 'old object child theorem application')
        child = '(' + bridge[:-1] + ')'
        new = call('parse_object_bytes', args[:2] + [args[4], body, args[3], '(by rfl)', args[5], child])
    elif name.endswith('_parsed'):
        match = re.fullmatch(r'theorem ([A-Za-z][A-Za-z0-9_]*) : parseRaw transportFuel transportDepth ([A-Za-z][A-Za-z0-9_]*) = some \(([A-Za-z][A-Za-z0-9_]*), \[\]\)', header)
        require(match is not None and len(args) == 1 and args[0] == '[]', 'original root parse statement')
        new = call('parse_root', ['transportFuel', 'transportDepth', match[3], match[2], fn])
    else:
        return raw
    return (header + ' := by\n  exact (' + new + ')\n').encode()


def _context(prepared, previous):
    old = nocode._relocated(prepared, previous)
    syntax, blocks, _, _ = seven._extract(old.stages)
    definitions = {}
    for rows in blocks:
        for ns, kind, name, raw in rows:
            if kind == 'def':
                definitions[ns + '.' + name] = _body(raw)[1].rstrip('\n')
    changed, new_blocks, first_literals, first_strings = {}, [], {}, {}
    for rows in blocks:
        result = []
        for ns, kind, name, raw in rows:
            new = raw
            if kind == 'theorem':
                shared = _reuse_string(ns, name, raw, definitions, first_strings)
                if shared is None:
                    shared = _reuse_literal(ns, name, raw, definitions, first_literals)
                new = shared if shared is not None else _rewrite(ns, name, raw, definitions)
            if new != raw:
                key = ns + '.' + name
                require(key not in changed, 'unique authorized proof edit')
                changed[key] = (raw, new)
            result.append((ns, kind, name, new))
        new_blocks.append(tuple(result))
    return old, syntax, blocks, tuple(new_blocks), changed


def _render(old, syntax, blocks, *, helpers):
    stages = list(old.stages)
    prefix, names = seven._render(blocks[0], old.stages[1].parents[0])
    extra = helper_source() if helpers else ''
    stages[1] = replace(stages[1], source=syntax + extra + seven.PREFIX_FRAME + prefix.split('\n', 1)[1],
                        expected_theorems=stages[1].expected_theorems | (HELPER_NAMES if helpers else frozenset()))
    for index, rows in enumerate(blocks[1:], 2):
        text, names = seven._render(rows, old.stages[index].parents[0])
        stages[index] = replace(stages[index], source=text)
    return tuple(stages)


def _prefix_stages(stages, syntax, blocks):
    """Reframe actual declarations; each certificate keeps its existing parent."""
    result = list(stages)
    for index, rows in enumerate(blocks, 1):
        source, names = seven._render(rows, stages[index].parents[0])
        if index == 1:
            source = syntax + seven.PREFIX_FRAME + seven._body(source)[1]
            names |= frozenset(seven._qualified_prints(syntax))
        result[index] = replace(result[index], source=source, expected_theorems=names)
    return tuple(result)


def _repartition(stages):
    """Lift the complete generic layer and redistribute the first 837 proofs.

    No declaration moves after a dependent declaration. The original eleven
    processes and import graph remain unchanged. The inverse below obtains all
    recovered source bytes from the actual candidate, not this forward emitter.
    """
    syntax, blocks, _, _ = seven._extract(stages)
    imports, body = seven._body(syntax)
    require(imports == 'import ' + stages[0].module_name + '\n', 'one original generic parent')
    require(all(GENERIC_FRAME not in s.source for s in stages), 'fresh unique generic frame')
    generic = seven._qualified_prints(body)
    require(len(generic) == len(set(generic)) == GENERIC_COUNT and
            HELPER_NAMES <= frozenset(generic), 'complete generic and shared subject inventory')
    prefix = tuple(row for block in blocks[:3] for row in block)
    adjusted = seven._cut(prefix, PREFIX_CUTS) + blocks[3:]
    result = list(_prefix_stages(stages, imports, adjusted))
    result[0] = replace(stages[0], source=stages[0].source + GENERIC_FRAME + body,
                        expected_theorems=stages[0].expected_theorems | frozenset(generic))
    require(tuple(len(s.expected_theorems) for s in result) == COUNTS,
            'fixed repartition inventory without subject loss')
    return tuple(result)


def _undo_repartition(actual, original_layout):
    """Recover the previous layout from actual declarations and generic bytes."""
    require(actual[0].source.count(GENERIC_FRAME) == 1 and
            all(GENERIC_FRAME not in s.source for s in actual[1:]), 'unique actual generic relocation')
    baseline, generic = actual[0].source.split(GENERIC_FRAME)
    syntax, blocks, _, _ = seven._extract(actual)
    require(syntax == 'import ' + actual[0].module_name + '\n', 'no hidden syntax prefix after lifting')
    prefix = tuple(row for block in blocks[:3] for row in block)
    recovered = seven._cut(prefix, seven.CUTS[:3]) + blocks[3:]
    result = list(_prefix_stages(actual, syntax + generic, recovered))
    result[0] = replace(actual[0], source=baseline,
                        expected_theorems=actual[0].expected_theorems -
                                          frozenset(seven._qualified_prints(generic)))
    require(tuple(s.expected_theorems for s in result) ==
            tuple(s.expected_theorems for s in original_layout), 'actual old-layout subject reconstruction')
    return tuple(result)


def _derive_stages(prepared, previous):
    old, syntax, _, blocks, _ = _context(prepared, previous)
    adjusted = _repartition(_render(old, syntax, blocks, helpers=True))
    names = nocode._definitions(replace(old, stages=adjusted))
    return tuple(replace(s, source=nocode._transform(s.source, names[s.name]))
                 for s in adjusted)


def _manifest(prepared, previous, stages):
    old, _, _, _, changes = _context(prepared, previous)
    ledger = [dict(name=name, statement_sha256=digest(_body(before)[0].encode()),
                   before_sha256=digest(before), after_sha256=digest(after))
              for name, (before, after) in sorted(changes.items())]
    require(stages[0].source.count(GENERIC_FRAME) == 1, 'manifest actual generic frame')
    generic = stages[0].source.split(GENERIC_FRAME)[1]
    reuses = {family: sum(_literal_family(name.rsplit('.', 1)[1]) == family for name in changes)
              for family in ('byte_facts', 'key_domain', 'key_parser')}
    reuses.update({family: sum((NAMESPACE + '.' + helper + ' ').encode() in after
                              for _, after in changes.values())
                   for family, helper in (('string_serializer', 'serialize_string_rebase'),
                                          ('string_parser', 'parse_string_rebase'))})
    return dict(schema=SCHEMA, protocol=PROTOCOL, source_only=True, acceptance_eligible=False,
                kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
                python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                all_edge_transfer_proved=False, timing_measured=False,
                obligations=[dict(id=name, status='unproved') for name, _ in seven.facts.OBLIGATIONS],
                **seven.facts.DENY, original_manifest_sha256=prepared['manifest_sha256'],
                previous_seven_manifest_sha256=previous.manifest_sha256,
                previous_relocation_manifest_sha256=old.manifest_sha256,
                helper_sha256=digest(helper_source().encode()), helper_names=sorted(HELPER_NAMES),
                proof_changes=len(ledger), proof_changes_sha256=digest(encode(ledger).encode()),
                literal_proof_reuses=reuses,
                prefix_cuts=list(PREFIX_CUTS),
                generic_relocation=dict(source='SyntaxData', destination='Baseline',
                    body_sha256=digest(generic.encode()), subjects=sorted(seven._qualified_prints(generic))),
                inputs_sha256=digest(encode(prepared['manifest']['inputs']).encode()),
                root_owners=seven.ROOT_OWNERS, stage_counts=list(COUNTS),
                stages=[seven.facts._compact(s) for s in stages],
                original_source_bytes=sum(s.source_bytes for s in prepared['stages']),
                candidate_source_bytes=sum(s.source_bytes for s in stages),
                retained_source_bytes=sum(s.source_bytes for s in prepared['stages'] + stages))


def validate_retention(proposal, retained_copies=()):
    return nocode.validate_retention(proposal, retained_copies)


def validate_sources(prepared, previous, proposal, retained_copies=()):
    require(type(proposal) is SharedSources and type(proposal.stages) is tuple and
            type(proposal.original_stages) is tuple and proposal.original_stages == prepared['stages'] and
            tuple(s.name for s in proposal.stages) == seven.NAMES, 'exact originals and eleven-stage proposal')
    require(type(proposal.manifest_json) is str and len(proposal.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded source manifest')
    old, old_syntax, old_blocks, new_blocks, changes = _context(prepared, previous)
    original_layout = _render(old, old_syntax, new_blocks, helpers=True)
    adjusted = _repartition(original_layout)
    adjusted_names = nocode._definitions(replace(old, stages=adjusted))
    unmarked = tuple(replace(s, source=nocode._transform(s.source, adjusted_names[s.name], inverse=True))
                     for s in proposal.stages)
    unmarked = _undo_repartition(unmarked, original_layout)
    helper = helper_source()
    require(unmarked[1].source.count(helper) == 1, 'exact actual shared helper bytes')
    stripped = list(unmarked)
    stripped[1] = replace(stripped[1], source=stripped[1].source.replace(helper, '', 1),
                           expected_theorems=stripped[1].expected_theorems - HELPER_NAMES)
    syntax, actual_blocks, _, _ = seven._extract(tuple(stripped))
    recovered_blocks = []
    for actual_rows, old_rows in zip(actual_blocks, old_blocks):
        require(len(actual_rows) == len(old_rows), 'no original declarations added or removed')
        recovered = []
        for actual, before in zip(actual_rows, old_rows):
            require(actual[:3] == before[:3], 'unchanged declaration name, kind, namespace and order')
            ns, kind, name, raw = actual
            key = ns + '.' + name
            if key in changes:
                old_raw, new_raw = changes[key]
                require(raw == new_raw, 'only the fixed shared proof instance is allowed')
                head, _ = _body(raw)
                old_head, old_proof = _body(old_raw)
                require(head == old_head, 'complete original theorem statement retained')
                raw = (head + ' := ' + old_proof).encode()
            else:
                require(raw == before[3], 'all other complete declarations byte-identical')
            recovered.append((ns, kind, name, raw))
        recovered_blocks.append(tuple(recovered))
    recovered = _render(replace(old, stages=tuple(stripped)), syntax, tuple(recovered_blocks), helpers=False)
    names = nocode._definitions(old)
    marked = tuple(replace(s, source=nocode._transform(s.source, names[s.name])) for s in recovered)
    prior = nocode.NoCodeSources(prepared['stages'], marked,
              encode(nocode._manifest(prepared, previous, old, marked)))
    require(tuple(len(s.expected_theorems) for s in proposal.stages) == COUNTS,
            'every original subject plus all shared helpers')
    require(proposal.stages == _derive_stages(prepared, previous), 'unique full forward transformation')
    require(proposal.manifest_json == encode(_manifest(prepared, previous, proposal.stages)),
            'strict independently reconstructed source manifest')
    total = validate_retention(proposal, retained_copies)
    # This is the actual-byte reconstruction, not an independently generated old
    # candidate. It replays every previous inverse, including complete Raw/bytes.
    nocode.validate_sources(prepared, previous, prior)
    return dict(source_only=True, acceptance_eligible=False, authority='DENY_ALL',
                stage_counts=COUNTS, proof_changes=len(changes), helper_count=len(HELPER_NAMES),
                retained_source_bytes=total)


def build_sources(prepared, previous=None):
    if previous is None:
        previous = seven.build_sources(prepared)
    stages = _derive_stages(prepared, previous)
    proposal = SharedSources(prepared['stages'], stages, encode(_manifest(prepared, previous, stages)))
    validate_sources(prepared, previous, proposal)
    return proposal


def build_inputs():
    return build_sources(seven.original.build_inputs())

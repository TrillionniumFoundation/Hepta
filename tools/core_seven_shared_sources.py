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
from types import MappingProxyType, SimpleNamespace

from tools import core_seven_nocode_sources as nocode
from tools import core_byte_facts_dag as byte_dag
from tools.check_guarded_slice_lean import require

seven = nocode.seven
encode, digest = nocode.encode, nocode.digest
SCHEMA = 'hepta.hia.seven-shared-composition-source.v10'
PROTOCOL = 'seven-shared-composition-source-v10'
HELPER_PATH = 'experiments/hia_initialization_frontiers_20261103/SharedTransport.lean'
NAMESPACE = 'HiaCoreSyntaxSlice.Shared'
HELPER_NAMES = frozenset(NAMESPACE + '.' + name for name in (
    'serialize_fields_single_packet', 'serialize_fields_cons_packet',
    'parse_fields_last_packet', 'parse_fields_cons_packet', 'parse_items_cons_bytes',
    'parse_array_bytes', 'parse_object_bytes', 'parse_root',
    'serialize_string_rebase', 'parse_string_rebase', 'parse_string_rebase_bound'))
GENERIC_FRAME = '-- SHARED_GENERIC_PARENT_V2\n'
PREFIX_CUTS = (256, 546, 837)
EXTENDED_PREFIX_CUTS = (256, 700, 837)
GENERIC_COUNT = 35 + len(HELPER_NAMES)
V4_COUNTS = (nocode.COUNTS[0] + GENERIC_COUNT, 256, 290, 291, *nocode.COUNTS[4:])
COUNTS = (*V4_COUNTS[:2], 444, 735, 1057, *V4_COUNTS[5:])
PART02_PREFIX_NAMES = (
    ('def', 'linearRaw'), ('def', 'linearBytes'),
    ('theorem', 'linear_bounds'), ('theorem', 'linear_serialized'),
    ('theorem', 'linear_parsed'),
    *(('theorem', 'linear_bf%04d' % i) for i in range(595)))
MAX_SOURCE, MAX_TOTAL_SOURCE, MAX_MANIFEST = nocode.MAX_SOURCE, nocode.MAX_TOTAL_SOURCE, nocode.MAX_MANIFEST

# Actual frozen ce1/r5 generated module bytes, retained independently of v7.
V6_SOURCE_SHA256 = MappingProxyType({
    "Baseline": "e8b51eb4677048dce2dd53739f05835ee8e1b161454ed44b03a4b132231bf7fa",
    "CertPart01": "a9e903a71e8fdf1196959b925890d27da85f5ba241510ff4f8762f9d64f902d7",
    "CertPart02": "44207c10b01072b5e8ec4c95ecee8eb5d6f76e3ef264dd2d8d9c1202bd83780b",
    "CertPart03": "4cf44372e370a598a8f82bfb2c0317966ec5517f07e650b43e8e11583d10803f",
    "CertPart04": "c873cccacb0a38869b51092c553f1421184532c03002941e6c92d9fb0d345eef",
    "CertPart05": "e3820378bd398ab17aa8b1add32b3d9dadaf5b521c5d60d0f8ec90bed6a17fdc",
    "CertPart06": "ac9f251e52fdf15a59368e213d552226727002abc3bd200348cf09cc434fc2e5",
    "CertPart07": "ed8f274ed167c5467f0a595b6722576bf3896e105a9f768a669c6224915cbc25",
    "ConnectionsTransportRejections": "4a175bdb55f0a26c6bf8bafe20ddf72752d547f4241239490e8ecef906fe37eb",
    "SyntaxData": "27681bc2e4a9385af55f5b5903e3c32f83cab7462504430e83056d1b4ec893e5",
    "WrongArm": "19c5e8a8725026a2eed1910920a9c28d6e80436b3cdaa8afdd6fd4ce2b94c3cc"
})


# Complete generated v7 source bytes from the preserved first acceptance.
V7_SOURCE_SHA256 = MappingProxyType({
    "Baseline": "e8b51eb4677048dce2dd53739f05835ee8e1b161454ed44b03a4b132231bf7fa",
    "CertPart01": "a9e903a71e8fdf1196959b925890d27da85f5ba241510ff4f8762f9d64f902d7",
    "CertPart02": "44207c10b01072b5e8ec4c95ecee8eb5d6f76e3ef264dd2d8d9c1202bd83780b",
    "CertPart03": "21d929b6416c8d4f92b60726fc48d40ab5267d8ec9ff24c6defb3ecb499c8fc0",
    "CertPart04": "a5a45ffb7dc39499424723fa6a5b72b535d4842072f9a5e5705738bba1c4315b",
    "CertPart05": "2e0dcf8b2e38940eb06572f85451635ac3d3df303780e65ae91ba4ec8d4e4d6e",
    "CertPart06": "a9554d7e65ce7df6970152bb893ac42b2cebb5ff6ffae9560c5f0583e8f84666",
    "CertPart07": "625b5c44f0d5715729f7a12763288a76427e7fa84296a7531745deab6d838203",
    "ConnectionsTransportRejections": "4a175bdb55f0a26c6bf8bafe20ddf72752d547f4241239490e8ecef906fe37eb",
    "SyntaxData": "27681bc2e4a9385af55f5b5903e3c32f83cab7462504430e83056d1b4ec893e5",
    "WrongArm": "19c5e8a8725026a2eed1910920a9c28d6e80436b3cdaa8afdd6fd4ce2b94c3cc"
})
PRINT_SCHEDULE_MODULES = seven.NAMES[1:9]
PRINT_PATTERN = re.compile(r'^#print axioms ([A-Za-z][A-Za-z0-9_.]*)\n', re.M)


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
        first_proofs[key] = (ns + '.' + name, fuel, depth,
                             ns + '.' + raw_name, ns + '.' + bytes_name)
        return None
    reference, prior_fuel, prior_depth, prior_raw, prior_bytes = first_proofs[key]
    args = [str(n - 1) for n in (prior_fuel, prior_depth, fuel, depth)]
    if serial:
        helper = 'serialize_string_rebase'
        args += [value[1], bytes_name, reference]
    else:
        helper = 'parse_string_rebase_bound'
        # Keep the original parser theorem's actual aliases. Equality of Raw
        # literals is never allowed to stand in for a proof of byte encoding.
        args += [prior_raw, raw_name, prior_bytes, bytes_name, '(' + value[1] + ' ++ [34])',
                 '(by rfl)', '(by rfl)', '(by rfl)', reference, 'tail']
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
    require(tuple(len(s.expected_theorems) for s in result) == V4_COUNTS,
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


def _part02_prefix(rows):
    """The fixed contiguous 600-declaration boundary, independent of cost data."""
    require(tuple((ns, kind, name) for ns, kind, name, _ in rows) ==
            tuple(('HiaCoreSyntaxSlice', kind, name) for kind, name in PART02_PREFIX_NAMES),
            'exact Part02 extension names, kinds, order and multiplicities')
    return rows


def _partition_checks(stages, blocks):
    """Check references against the ACTUAL new layout and literal import DAG."""
    expected_parents = ('Baseline', 'SyntaxData', 'CertPart01', 'CertPart02',
                        'CertPart03', 'CertPart04', 'CertPart05', 'CertPart06',
                        'CertPart07', 'CertPart04')
    for stage, name, parent_name in zip(stages[1:], seven.NAMES[1:], expected_parents):
        parent = seven.original.PREFIX + '.' + parent_name
        require(stage.name == name and stage.module_name == seven.original.PREFIX + '.' + name and
                stage.parents == (parent,) and stage.explicit_imports == (parent,) and
                stage.direct_imports == ('Init', parent), 'unchanged eleven-module parent graph')
        require(tuple(re.findall(r'^import (.+)$', stage.source, re.M)) == (parent,),
                'actual source import graph agrees with fixed parent graph')
    rows = tuple(row for block in blocks for row in block)
    require(sum(r[1] == 'def' for r in rows) == 7685 and
            sum(seven._aux(r) for r in rows) == 2975 and
            sum(r[1] == 'theorem' and not seven._aux(r) for r in rows) == 4215,
            'complete transport inventory after fixed extension')
    names = [ns + '.' + name for ns, _, name, _ in rows]
    require(len(names) == len(set(names)), 'unique actual transport declarations')
    positions = {name: i for i, name in enumerate(names)}
    owners = {ns + '.' + name: stages[i + 1].module_name
              for i, block in enumerate(blocks) for ns, _, name, _ in block}
    ancestors = {}
    for stage in stages:
        inherited = set(stage.parents)
        for parent in stage.parents:
            inherited.update(ancestors.get(parent, set()))
        ancestors[stage.module_name] = inherited
    references = 0
    for i, (ns, _, name, raw) in enumerate(rows):
        for token in re.findall(r'[A-Za-z][A-Za-z0-9_.]*', raw.decode().split(name, 1)[1]):
            resolved = token if token in positions else ns + '.' + token
            if resolved in positions:
                require(positions[resolved] < i, 'forward or recursive actual transport reference')
                owner = owners[names[i]]
                require(owners[resolved] == owner or owners[resolved] in ancestors[owner],
                        'actual transport owner is not an imported ancestor')
                references += 1
    return references


def _extend_part02(stages):
    """Move two fixed contiguous boundaries; keep global order and root owners."""
    syntax, blocks, _, _ = seven._extract(stages)
    size = len(PART02_PREFIX_NAMES)
    moved = _part02_prefix(blocks[3][:size])
    require(blocks[3][size][:3] == ('HiaCoreSyntaxSlice', 'theorem', 'linear_length'),
            'fixed remaining Part03 first declaration')
    prefix = tuple(row for block in blocks[:3] for row in block)
    earlier = seven._cut(prefix, EXTENDED_PREFIX_CUTS)
    adjusted = (*earlier[:2], earlier[2] + moved, blocks[3][size:], *blocks[4:])
    require(tuple(row for b in adjusted for row in b) == tuple(row for b in blocks for row in b),
            'all actual declaration bytes and global order preserved')
    result = _prefix_stages(stages, syntax, adjusted)
    _partition_checks(result, adjusted)
    require(tuple(len(s.expected_theorems) for s in result) == COUNTS,
            'fixed eleven-stage extended inventory')
    return result


def _undo_extension(actual, v4_layout):
    """Recover v4 from candidate bytes before replaying its existing inverse."""
    syntax, blocks, _, _ = seven._extract(actual)
    _partition_checks(actual, blocks)
    size = len(PART02_PREFIX_NAMES)
    moved = _part02_prefix(blocks[2][-size:])
    require(blocks[3][0][:3] == ('HiaCoreSyntaxSlice', 'theorem', 'linear_length'),
            'actual remaining Part03 first declaration')
    prefix = tuple(row for block in (*blocks[:2], blocks[2][:-size]) for row in block)
    recovered = (*seven._cut(prefix, PREFIX_CUTS), moved + blocks[3], *blocks[4:])
    require(tuple(row for b in recovered for row in b) == tuple(row for b in blocks for row in b),
            'inverse preserves complete actual global declaration bytes')
    result = _prefix_stages(actual, syntax, recovered)
    require(result == v4_layout, 'actual inverse reconstructs every complete v4 source byte and subject')
    return result

def _literal_alias_bytes(ns, name, definitions):
    """Resolve only bounded local aliases ending in an exact Nat list."""
    seen = set()
    while True:
        key = name if '.' in name else ns + '.' + name
        if key not in definitions:
            return None
        require(key not in seen and len(seen) < 32, 'acyclic bounded concrete byte aliases')
        seen.add(key)
        value = definitions[key]
        if re.fullmatch(r'\[\s*(?:[0-9]+\s*(?:,\s*[0-9]+\s*)*)?\]', value):
            literal = tuple(json.loads(value))
            require(all(type(x) is int and x >= 0 for x in literal), 'exact concrete Nat bytes')
            return literal
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]*', value):
            return None
        ns, name = key.rsplit('.', 1)[0], value


def _reuse_compound(ns, name, raw, definitions, first_proofs, owner, ancestors):
    """Use a prior certificate only for the same closed data AND exact bounds.

    The table chooses proof text. No evaluator result, type assertion or axiom
    inventory is cached. Lean checks the original full target statement.
    """
    if not re.fullmatch(r'.+_[sp][0-9]+', name):
        return None
    header, proof = _body(raw)
    serial = re.fullmatch(r'.+_s[0-9]+', name) is not None
    if proof != ('by decide +kernel\n' if serial else 'by rfl\n'):
        return None
    if serial:
        match = re.fullmatch(r'theorem [A-Za-z][A-Za-z0-9_]* : serializeRaw ([0-9]+) ([0-9]+) ([A-Za-z][A-Za-z0-9_]*) = some ([A-Za-z][A-Za-z0-9_]*)', header)
        require(match is not None, 'compound serializer statement shape')
        raw_name, byte_name = match[3], match[4]
    else:
        match = re.fullmatch(r'theorem [A-Za-z][A-Za-z0-9_]* \(tail : List Nat\) : parseRaw ([0-9]+) ([0-9]+) \(([A-Za-z][A-Za-z0-9_]*) \+\+ tail\) = some \(([A-Za-z][A-Za-z0-9_]*), tail\)', header)
        require(match is not None, 'compound parser statement shape')
        raw_name, byte_name = match[4], match[3]
    value = definitions.get(ns + '.' + raw_name)
    if value is None or not value.startswith(('(.num ', '(.arr ', '(.obj ')):
        return None
    # A free identifier could denote different data in different namespaces.
    # Restrict this rule to constructor/numeral/delimiter text with no names.
    closed = re.sub(r'\.(?:str|num|arr|obj)\b', '', value)
    if re.fullmatch(r'[0-9\s()[\],]+', closed) is None:
        return None
    literal = _literal_alias_bytes(ns, byte_name, definitions)
    if literal is None:
        return None
    fuel, depth = int(match[1]), int(match[2])
    if fuel <= 0 or depth <= 0:
        return None
    key = (serial, fuel, depth, value, literal)
    candidates = first_proofs.setdefault(key, [])
    for reference, previous_owner in candidates:
        if previous_owner == owner or previous_owner in ancestors:
            arguments = ' tail' if not serial else ''
            return (header + ' := by\n  exact (' + reference + arguments + ')\n').encode()
    candidates.append((ns + '.' + name, owner))
    return None


def _compound_context(stages):
    """Derive a second, reversible proof-only layer over the complete v6 bytes."""
    syntax, blocks, _, _ = seven._extract(stages)
    definitions = {ns + '.' + name: _body(raw)[1].rstrip('\n')
                   for rows in blocks for ns, kind, name, raw in rows if kind == 'def'}
    inherited = {}
    for stage in stages:
        ancestors = set(stage.parents)
        for parent in stage.parents:
            ancestors.update(inherited.get(parent, set()))
        inherited[stage.module_name] = ancestors
    first, changes, rewritten = {}, {}, []
    for index, rows in enumerate(blocks, 1):
        owner = stages[index].module_name
        result = []
        for ns, kind, name, raw in rows:
            new = _reuse_compound(ns, name, raw, definitions, first, owner, inherited[owner]) if kind == 'theorem' else None
            new = raw if new is None else new
            if new != raw:
                key = ns + '.' + name
                require(key not in changes, 'unique compound proof replacement')
                changes[key] = (raw, new)
            result.append((ns, kind, name, new))
        rewritten.append(tuple(result))
    return syntax, blocks, tuple(rewritten), changes


def _share_compounds(v6):
    syntax, _, blocks, _ = _compound_context(v6)
    candidate = _prefix_stages(v6, syntax, blocks)
    _partition_checks(candidate, blocks)
    return candidate


def _v6_source_hashes(stages):
    names = nocode._definitions(SimpleNamespace(stages=stages))
    actual = {stage.name: digest(nocode._transform(stage.source, names[stage.name]).encode())
              for stage in stages}
    require(actual == dict(V6_SOURCE_SHA256), 'complete frozen ce1/v6 module bytes recovered')
    return actual


def _undo_compound_sharing(actual, v6):
    """Restore v6 from ACTUAL proof bytes, then all older inverses still run."""
    _, old_blocks, _, changes = _compound_context(v6)
    syntax, actual_blocks, _, _ = seven._extract(actual)
    _partition_checks(actual, actual_blocks)
    require(len(actual_blocks) == len(old_blocks), 'same compound layer module inventory')
    recovered = []
    for actual_rows, old_rows in zip(actual_blocks, old_blocks):
        require(len(actual_rows) == len(old_rows), 'no compound declaration added or removed')
        rows = []
        for current, before in zip(actual_rows, old_rows):
            require(current[:3] == before[:3], 'compound names, namespaces, kinds and order retained')
            ns, kind, name, raw = current
            key = ns + '.' + name
            if key in changes:
                old_raw, expected = changes[key]
                require(raw == expected, 'only exact-bound prior compound certificate allowed')
                header, _ = _body(raw)
                old_header, old_proof = _body(old_raw)
                require(header == old_header, 'entire compound target statement retained')
                raw = (header + ' := ' + old_proof).encode()
            else:
                require(raw == before[3], 'all noncompound declarations remain byte-exact')
            rows.append((ns, kind, name, raw))
        recovered.append(tuple(rows))
    result = _prefix_stages(actual, syntax, tuple(recovered))
    require(result == v6, 'actual inverse reconstructs every complete v6 source and subject')
    _v6_source_hashes(result)
    return result




def _move_prints_legacy(source, rows):
    """Force each existing dependency query after its original theorem.

    Every actual non-print byte is retained. No theorem, query or name is added.
    """
    names = tuple(ns + '.' + name for ns, kind, name, _ in rows if kind == 'theorem')
    actual = tuple(PRINT_PATTERN.findall(source))
    require(actual == tuple(sorted(names)) and len(names) == len(set(names)),
            'complete original sorted print inventory')
    result = PRINT_PATTERN.sub('', source)
    for ns, kind, name, raw in rows:
        if kind == 'theorem':
            text = raw.decode()
            require(result.count(text) == 1, 'unique exact declaration for print scheduling')
            result = result.replace(text, text + '#print axioms ' + ns + '.' + name + '\n', 1)
    require(tuple(PRINT_PATTERN.findall(result)) == names and len(result.encode()) == len(source.encode()),
            'same print multiplicities and source byte count')
    return result


def _move_prints(source, rows):
    """Insert queries at unique independent literal spans of the actual source."""
    if (type(source) is not str or not (type(rows) is tuple or type(rows) is list) or
        any(not (type(row) is tuple or type(row) is list) or len(row) != 4 or
            any(type(x) is not str for x in row[:3]) or type(row[3]) is not bytes
            for row in rows)):
        return _move_prints_legacy(source, rows)
    names = tuple(ns + '.' + name for ns, kind, name, _ in rows if kind == 'theorem')
    require(tuple(PRINT_PATTERN.findall(source)) == tuple(sorted(names)) and
            len(names) == len(set(names)), 'complete original sorted print inventory')
    declarations = []
    for ns, kind, name, raw in rows:
        if kind == 'theorem':
            text = raw.decode()
            query = '#print axioms ' + ns + '.' + name + '\n'
            # Such inputs need the original sequential count/replace semantics.
            # This is automatic input classification, never a caller-selected mode.
            if (not text.startswith('theorem ' + name + ' ') or
                not text.endswith('\n') or text.count('theorem ') != 1 or
                '#print axioms ' in text or 'theorem ' in query):
                return _move_prints_legacy(source, rows)
            declarations.append((text, query))
    original = PRINT_PATTERN.sub('', source)
    markers = seven.original._DeclarationMarkers(original)
    edits = []
    for text, query in declarations:
        positions = markers.positions(text)
        require(len(positions) == 1, 'unique exact declaration for print scheduling')
        edits.append((positions[0], positions[0] + len(text), query))
    edits.sort()
    if any(left[1] > right[0] for left, right in zip(edits, edits[1:])):
        return _move_prints_legacy(source, rows)
    chunks, cursor = [], 0
    for start, end, query in edits:
        chunks.extend((original[cursor:end], query))
        cursor = end
    chunks.append(original[cursor:])
    result = ''.join(chunks)
    require(tuple(PRINT_PATTERN.findall(result)) == names and
            len(result.encode()) == len(source.encode()),
            'same print multiplicities and source byte count')
    return result


def _restore_print_tail(source):
    """Use only actual query names and actual remaining bytes to restore v7."""
    names = tuple(PRINT_PATTERN.findall(source))
    require(len(names) == len(set(names)), 'no duplicated actual print subject')
    return PRINT_PATTERN.sub('', source) + ''.join('#print axioms ' + n + '\n' for n in sorted(names))


def _v7_source_hashes(stages):
    actual = {stage.name: digest(stage.source.encode()) for stage in stages}
    require(actual == dict(V7_SOURCE_SHA256), 'complete frozen v7 module bytes recovered')
    return actual


def _schedule_prints(stages):
    _v7_source_hashes(stages)
    unmarked = tuple(replace(stage, source=re.sub(r'(?m)^noncomputable def ', 'def ', stage.source))
                     for stage in stages)
    _, blocks, _, _ = seven._extract(unmarked)
    result = list(stages)
    for index, rows in enumerate(blocks, 1):
        require(stages[index].name == PRINT_SCHEDULE_MODULES[index - 1], 'fixed print schedule modules')
        result[index] = replace(stages[index], source=_move_prints(stages[index].source, rows))
    return tuple(result)


def _undo_scheduled_prints(stages):
    require(tuple(stage.name for stage in stages) == seven.NAMES, 'exact eleven actual print stages')
    restored = list(stages)
    for index, name in enumerate(PRINT_SCHEDULE_MODULES, 1):
        source = stages[index].source
        require(frozenset(PRINT_PATTERN.findall(source)) == stages[index].expected_theorems,
                'all and only actual scheduled subjects')
        restored[index] = replace(stages[index], source=_restore_print_tail(source))
    restored = tuple(restored)
    _v7_source_hashes(restored)
    require(_schedule_prints(restored) == stages, 'unique fixed query placement after each theorem')
    return restored


# This layer changes proofs of the existing consumer statements only. The
# original Raw equality definitions remain byte-exact: their well-founded
# recursion is not used as a kernel evaluator for string-tag decisions.
CONSUMER_NAMES = ('linear_extraction', 'parallel_extraction',
                  'reject_stale_descriptor', 'reject_wrong_phi',
                  'reject_literal_two', 'reject_wrong_condition')
CONSUMER_BASE_SHA256 = V7_SOURCE_SHA256['ConnectionsTransportRejections']
CHANGED_BYTE_NAMESPACE = 'namespace HiaCoreSyntaxSlice.ChangedByte\n'
CHANGED_BYTE_RHS = "HiaCoreSyntaxSlice.linear_g0 ++ (HiaCoreSyntaxSlice.linear_v0_0 ++ [93])"
CHANGED_BYTE_OLD_PROOF = 'by\n  rw [HiaCoreSyntaxSlice.linear_transport]\n  decide +kernel\n'
CHANGED_BYTE_PROOF = "by have cancel : ∀ (front left right : List Nat), front ++ left = front ++ right → left = right := (by intro front; induction front with | nil => intro left right same; exact same | cons head tail ih => intro left right same; exact ih left right (List.cons.inj same).2); intro encoded; have same := Option.some.inj (linear_transport.symm.trans encoded); change linear_g0 ++ (linear_v0_0 ++ [125]) = linear_g0 ++ (linear_v0_0 ++ [93]) at same; have last := cancel linear_v0_0 [125] [93] (cancel linear_g0 _ _ same); cases last\n\n\n"


def _positive_consumer(raw, hint, bounds):
    # Both local generic rewrites are ordinary universally quantified theorems.
    # Every actual closed relation atom is still kernel checked, including the
    # existing whole-tree bounds certificate and both arithmetic-tag cases.
    tag = "have tag {α : Type} (raw : Raw) (value : List Nat) (yes no : α) : (if raw = Raw.str value then yes else no) = (match raw with | .str actual => if actual = value then yes else no | _ => no) := (by cases raw <;> simp); "
    decision = "have tagDecision (raw : Raw) (value : List Nat) : decide (raw = Raw.str value) = (match raw with | .str actual => decide (actual = value) | _ => false) := (by cases raw <;> simp); "
    return ('by ' + tag + decision +
        f'have reconstructed : reconstruct {raw} {hint} = HiaGuardedUsizeSlice.linear_0 := '
        '(by simp only [reconstruct, addTag, tag]; decide +kernel); ' +
        f'have shape : goodProgram {raw} = true := '
        '(by simp only [goodProgram, tagDecision]; decide +kernel); ' +
        f'have accepted : SliceSyntaxRelation {raw} {hint} HiaGuardedUsizeSlice.linear_0 := '
        '(by dsimp only [SliceSyntaxRelation]; refine ⟨' + bounds + ', shape, ' +
        ', '.join('?' + '_' for _ in range(56)) +
        '⟩; all_goals first | rfl | (exact Or.inl ⟨rfl, rfl⟩) | '
        '(exact Or.inr ⟨rfl, rfl⟩) | decide +kernel); '
        'unfold extract; rw [reconstructed]; exact if_pos accepted')


def _negative_consumer(namespace, conjunct):
    # These are necessary clauses of the unchanged declarative relation, not
    # checks of a separate executable model. Constructor disjointness refutes
    # the actual wrong edge, constant, or branch-condition syntax.
    return (f'by intro success; have necessary := extract_sound {namespace}.linearRaw '
            f'{namespace}.linearHint HiaGuardedUsizeSlice.linear_0 success; '
            'have impossible := necessary' + '.2' * conjunct + '.1; cases impossible')


def _consumer_proofs():
    return dict(
        linear_extraction=_positive_consumer('linearRaw', 'linearHint', 'linear_bounds'),
        parallel_extraction=_positive_consumer('parallelRaw', 'parallelHint', 'parallel_bounds'),
        reject_stale_descriptor='by rw [linear_extraction]; decide +kernel',
        reject_wrong_phi=_negative_consumer('WrongPhi', 27),
        reject_literal_two=_negative_consumer('LiteralTwo', 46),
        reject_wrong_condition=_negative_consumer('WrongCondition', 17))


def _consumer_byte_values(stages):
    """Evaluate only ACTUAL prior linear byte definitions with the old reader.

    Their complete sources, declaration/import order and original byte bindings
    are subsequently authenticated by every existing v8-through-original inverse.
    This bounded source check creates no Lean theorem or admission authority.
    """
    require(tuple(stage.name for stage in stages) == seven.NAMES and
            all(type(stage.source) is str and stage.source_bytes <= MAX_SOURCE for stage in stages) and
            sum(stage.source_bytes for stage in stages) <= MAX_TOTAL_SOURCE,
            'bounded existing eleven byte-source modules')
    values = {}
    for stage in stages[1:9]:
        namespace = None
        for line in stage.source.splitlines():
            if line.startswith('namespace '):
                namespace = line[len('namespace '):]
            elif line.startswith('end '):
                namespace = None
            elif namespace == 'HiaCoreSyntaxSlice':
                match = re.fullmatch(r'noncomputable def (linear[A-Za-z0-9_]*) : List Nat := (.+)', line)
                if match is not None:
                    require(match[1] not in values and len(values) < byte_dag.MAX_VERTICES,
                            'unique ordered actual byte definitions')
                    ast = byte_dag.parse_rhs(match[2])
                    values[match[1]] = dict(value=byte_dag._evaluate(ast, values),
                                            dependencies=byte_dag._dependencies(ast))
    require('linearBytes' in values, 'actual prior linear byte root')
    reachable, pending = set(), ['linearBytes']
    while pending:
        name = pending.pop()
        if name not in reachable:
            reachable.add(name)
            pending.extend(values[name]['dependencies'])
    require(len(reachable) == 595 and
            len(values['linearBytes']['value']) == 14466 and
            values['linear_g0']['value'] == (123,) and values['linear_g406']['value'] == (125,),
            'complete original linear byte DAG and delimiters')
    return values


def _changed_byte_value(rhs, values):
    require(rhs == CHANGED_BYTE_RHS, 'fixed actual shared-prefix byte expression')
    actual = byte_dag._evaluate(byte_dag.parse_rhs(rhs.replace('HiaCoreSyntaxSlice.', '')), values)
    original = values['linearBytes']['value']
    require(len(actual) == len(original) == 14466 and actual[:-1] == original[:-1] and
            original[-1:] == (125,) and actual[-1:] == (93,),
            'all actual prefix bytes retained and only original final-byte mutation')
    return actual



def _consumer_source(source, values, *, inverse=False):
    """Restore actual complete v8 bytes, including every original target."""
    proofs, found, result, ledger = _consumer_proofs(), set(), [], []
    for line in source.splitlines(keepends=True):
        match = re.match(r'^theorem ([A-Za-z][A-Za-z0-9_]*) : ', line)
        if match is not None and match[1] in proofs:
            name = match[1]
            require(name not in found, 'one actual consumer declaration per fixed name')
            header, separator, _ = line.partition(' := by ')
            require(separator == ' := by ', 'consumer proof delimiter')
            before = header + ' := by decide +kernel\n'
            after = header + ' := ' + proofs[name] + '\n'
            require(line == (after if inverse else before), 'exact consumer proof body and target')
            result.append(before if inverse else after)
            ledger.append(dict(name='HiaCoreSyntaxSlice.' + name,
                               statement_sha256=digest(header.encode()),
                               before_sha256=digest(before.encode()),
                               after_sha256=digest(after.encode())))
            found.add(name)
        else:
            result.append(line)
    require(found == set(CONSUMER_NAMES), 'all six original consumer targets retained')
    result = ''.join(result)

    require(result.count(CHANGED_BYTE_NAMESPACE) == 1, 'one changed-byte namespace')
    prefix, rest = result.split(CHANGED_BYTE_NAMESPACE, 1)
    definition, rest = rest.split('\n', 1)
    actual_prefix = ('noncomputable def linearBytes : List Nat := ' if inverse else
                     'def linearBytes : List Nat := ')
    require(definition.startswith(actual_prefix), 'actual changed-byte header')
    actual_rhs = definition[len(actual_prefix):]
    if inverse:
        value = _changed_byte_value(actual_rhs, values)
    else:
        parsed = json.loads(actual_rhs)
        require(type(parsed) is list and len(parsed) == 14466 and
                all(type(byte) is int and 0 <= byte <= 255 for byte in parsed),
                'original actual changed-byte literal values')
        value = tuple(parsed)
        require(value == _changed_byte_value(CHANGED_BYTE_RHS, values),
                'actual complete original and shared-prefix byte values equal')
    old_definition = 'def linearBytes : List Nat := [' + ','.join(map(str, value)) + ']'
    new_definition = 'noncomputable def linearBytes : List Nat := ' + CHANGED_BYTE_RHS
    require(definition == (new_definition if inverse else old_definition),
            'actual changed-byte declaration exactly reconstructs original literal bytes')
    result = prefix + CHANGED_BYTE_NAMESPACE + (old_definition if inverse else new_definition) + '\n' + rest
    old, new = (CHANGED_BYTE_PROOF, CHANGED_BYTE_OLD_PROOF) if inverse else (
        CHANGED_BYTE_OLD_PROOF, CHANGED_BYTE_PROOF)
    require(result.count(old) == 1, 'one exact changed-byte rejection proof')
    result = result.replace(old, new, 1)
    require(source.count('\n') == result.count('\n'), 'original negative coordinates retained')
    original = result if inverse else source
    require(digest(original.encode()) == CONSUMER_BASE_SHA256,
            'all complete frozen v8 consumer bytes recovered')
    return result, tuple(sorted(ledger, key=lambda row: row['name']))


WRONG_ARM_BASE_SHA256 = V7_SOURCE_SHA256['WrongArm']
WRONG_ARM_NAME = 'reject_wrong_arm_implementation'
WRONG_ARM_PROOF = "by have proposed : ∀ (raw : Raw) (hint : Hint) (d : HiaGuardedUsizeSlice.Descriptor), extract raw hint = some d → reconstruct raw hint = d := (by intro raw hint d extracted; by_cases accepted : SliceSyntaxRelation raw hint (reconstruct raw hint) <;> simp_all [extract]); intro extracted; have mismatch : (reconstruct parallelRaw parallelHint).incoming ≠ HiaGuardedUsizeSlice.linear_0.incoming := (by decide +kernel); exact mismatch (congrArg (fun d : HiaGuardedUsizeSlice.Descriptor => d.incoming) (proposed _ _ _ extracted))"


def _wrong_arm_source(source, *, inverse=False):
    """Retain the complete original mutated extractor and exact negation."""
    matches = tuple(re.finditer(r'^theorem ' + WRONG_ARM_NAME + r' : [^\n]+\n', source, re.M))
    require(len(matches) == 1, 'one complete actual wrong-arm declaration')
    actual = matches[0].group()
    header, separator, _ = actual.partition(' := by ')
    require(separator == ' := by ', 'wrong-arm proof delimiter')
    before = header + ' := by decide +kernel\n'
    after = header + ' := ' + WRONG_ARM_PROOF + '\n'
    require(actual == (after if inverse else before), 'exact wrong-arm proof and target')
    result = source[:matches[0].start()] + (before if inverse else after) + source[matches[0].end():]
    require(result.count('\n') == source.count('\n'), 'original wrong-arm source coordinates')
    original = result if inverse else source
    require(digest(original.encode()) == WRONG_ARM_BASE_SHA256,
            'all original wrong-arm implementation, hint, target and source bytes recovered')
    return result, dict(name='HiaCoreSyntaxSlice.' + WRONG_ARM_NAME,
                        statement_sha256=digest(header.encode()),
                        before_sha256=digest(before.encode()),
                        after_sha256=digest(after.encode()))


def _repair_consumers(stages):
    require(tuple(stage.name for stage in stages) == seven.NAMES,
            'existing eleven consumer stage boundaries')
    result = list(stages)
    text, _ = _consumer_source(stages[9].source, _consumer_byte_values(stages))
    result[9] = replace(stages[9], source=text)
    wrong, _ = _wrong_arm_source(stages[10].source)
    result[10] = replace(stages[10], source=wrong)
    return tuple(result)


def _undo_consumer_repairs(stages):
    require(tuple(stage.name for stage in stages) == seven.NAMES,
            'exact eleven actual consumer stages')
    result = list(stages)
    text, _ = _consumer_source(stages[9].source, _consumer_byte_values(stages), inverse=True)
    result[9] = replace(stages[9], source=text)
    wrong, _ = _wrong_arm_source(stages[10].source, inverse=True)
    result[10] = replace(stages[10], source=wrong)
    result = tuple(result)
    require(_repair_consumers(result) == stages, 'unique complete consumer proof transformation')
    return result



def _derive_stages(prepared, previous):
    old, syntax, _, blocks, _ = _context(prepared, previous)
    v6 = _extend_part02(_repartition(_render(old, syntax, blocks, helpers=True)))
    _v6_source_hashes(v6)
    adjusted = _share_compounds(v6)
    names = nocode._definitions(replace(old, stages=adjusted))
    marked = tuple(replace(s, source=nocode._transform(s.source, names[s.name]))
                   for s in adjusted)
    return _repair_consumers(_schedule_prints(marked))


def _manifest(prepared, previous, stages):
    candidate = stages
    scheduled = _undo_consumer_repairs(stages)
    consumer_values = _consumer_byte_values(scheduled)
    _, consumer_ledger = _consumer_source(scheduled[9].source, consumer_values)
    _, wrong_arm_ledger = _wrong_arm_source(scheduled[10].source)
    stages = _undo_scheduled_prints(scheduled)
    moved_subjects = sum(len(seven._qualified_prints(stage.source)) for stage in stages[1:9])
    require(moved_subjects == 7190, 'complete original transport query count')
    old, syntax, _, blocks, changes = _context(prepared, previous)
    v6 = _extend_part02(_repartition(_render(old, syntax, blocks, helpers=True)))
    _, prior_blocks, _, compound_changes = _compound_context(v6)
    require(not (set(changes) & set(compound_changes)), 'disjoint original and compound proof edits')
    changes = {**changes, **compound_changes}
    prior_references = _partition_checks(v6, prior_blocks)
    candidate_references = _partition_checks(stages, seven._extract(tuple(
        replace(stage, source=re.sub(r'(?m)^noncomputable def ', 'def ', stage.source))
        for stage in stages))[1])
    require(prior_references == 45994 and candidate_references == prior_references + len(compound_changes),
            'every compound reuse adds exactly its explicit prior proof reference')
    ledger = [dict(name=name, statement_sha256=digest(_body(before)[0].encode()),
                   before_sha256=digest(before), after_sha256=digest(after))
              for name, (before, after) in sorted(changes.items())]
    require(stages[0].source.count(GENERIC_FRAME) == 1, 'manifest actual generic frame')
    generic = stages[0].source.split(GENERIC_FRAME)[1]
    _, rows, _ = seven.original._parse(re.sub(r'(?m)^noncomputable def ', 'def ', stages[3].source))
    moved = _part02_prefix(rows[-len(PART02_PREFIX_NAMES):])
    reuses = {family: sum(_literal_family(name.rsplit('.', 1)[1]) == family for name in changes)
              for family in ('byte_facts', 'key_domain', 'key_parser')}
    reuses.update({family: sum((NAMESPACE + '.' + helper + ' ').encode() in after
                              for _, after in changes.values())
                   for family, helper in (('string_serializer', 'serialize_string_rebase'),
                                          ('string_parser', 'parse_string_rebase_bound'))})
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
                compound_proof_reuses=dict(
                    serializer=sum(bool(re.fullmatch(r'.+_s[0-9]+', name)) for name in compound_changes),
                    parser=sum(bool(re.fullmatch(r'.+_p[0-9]+', name)) for name in compound_changes),
                    proofs=len(compound_changes), exact_bounds=True,
                    prior_v6_source_sha256=_v6_source_hashes(v6),
                    prior_v6_dependency_references=prior_references,
                    candidate_dependency_references=candidate_references),
                print_schedule=dict(
                    modules=list(PRINT_SCHEDULE_MODULES), moved_subjects=moved_subjects,
                    proof_or_declaration_changes=False, source_byte_delta=0,
                    prior_v7_source_sha256=_v7_source_hashes(stages),
                    sequences=[dict(name=before.name,
                        original_sha256=digest(encode(seven._qualified_prints(before.source)).encode()),
                        scheduled_sha256=digest(encode(seven._qualified_prints(after.source)).encode()))
                        for before, after in zip(stages[1:9], scheduled[1:9])]),
                consumer_proofs=dict(
                    original_source_sha256=CONSUMER_BASE_SHA256,
                    candidate_source_sha256=candidate[9].source_sha256,
                    proof_changes=8, relation_conjuncts=58,
                    selected_clause_indices=dict(wrong_phi=27, literal_two=46, wrong_condition=17),
                    original_generic_definitions_unchanged=True,
                    subjects_or_statements_changed=False,
                    executable_data_exclusions=['HiaCoreSyntaxSlice.ChangedByte.linearBytes'],
                    changed_byte_representation=dict(
                        definition='HiaCoreSyntaxSlice.ChangedByte.linearBytes', bytes=14466,
                        value_sha256=digest(bytes(_changed_byte_value(CHANGED_BYTE_RHS, consumer_values))),
                        prior_definitions=len(consumer_values), root_reachable_definitions=595,
                        actual_expression=CHANGED_BYTE_RHS,
                        recovered_complete_old_source_sha256=CONSUMER_BASE_SHA256),
                    ledger=list(consumer_ledger),
                    changed_byte_original_proof_sha256=digest(CHANGED_BYTE_OLD_PROOF.encode()),
                    changed_byte_candidate_proof_sha256=digest(CHANGED_BYTE_PROOF.encode()),
                    wrong_arm=dict(**wrong_arm_ledger,
                        original_source_sha256=WRONG_ARM_BASE_SHA256,
                        candidate_source_sha256=candidate[10].source_sha256,
                        projected_field='incoming', original_mutated_implementation_unchanged=True)),
                prefix_cuts=list(PREFIX_CUTS),
                part02_extension=dict(source='CertPart03', destination='CertPart02',
                    preceding_prefix_cuts=list(EXTENDED_PREFIX_CUTS),
                    first='HiaCoreSyntaxSlice.linearRaw', last='HiaCoreSyntaxSlice.linear_bf0594',
                    next='HiaCoreSyntaxSlice.linear_length', definitions=2,
                    original_theorems=3, auxiliary_theorems=595,
                    declaration_bytes=sum(len(r[3]) for r in moved),
                    declaration_sha256=digest(b''.join(r[3] for r in moved))),
                generic_relocation=dict(source='SyntaxData', destination='Baseline',
                    body_sha256=digest(generic.encode()), subjects=sorted(seven._qualified_prints(generic))),
                inputs_sha256=digest(encode(prepared['manifest']['inputs']).encode()),
                root_owners=seven.ROOT_OWNERS, stage_counts=list(COUNTS),
                stages=[seven.facts._compact(s) for s in candidate],
                original_source_bytes=sum(s.source_bytes for s in prepared['stages']),
                candidate_source_bytes=sum(s.source_bytes for s in candidate),
                retained_source_bytes=sum(s.source_bytes for s in prepared['stages'] + candidate))


def validate_retention(proposal, retained_copies=()):
    return nocode.validate_retention(proposal, retained_copies)


def validate_sources(prepared, previous, proposal, retained_copies=()):
    require(type(proposal) is SharedSources and type(proposal.stages) is tuple and
            type(proposal.original_stages) is tuple and proposal.original_stages == prepared['stages'] and
            tuple(s.name for s in proposal.stages) == seven.NAMES, 'exact originals and eleven-stage proposal')
    require(type(proposal.manifest_json) is str and len(proposal.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded source manifest')
    unscheduled = _undo_scheduled_prints(_undo_consumer_repairs(proposal.stages))
    old, old_syntax, old_blocks, new_blocks, changes = _context(prepared, previous)
    original_layout = _render(old, old_syntax, new_blocks, helpers=True)
    v4_layout = _repartition(original_layout)
    adjusted = _extend_part02(v4_layout)
    adjusted_names = nocode._definitions(replace(old, stages=adjusted))
    unmarked = tuple(replace(s, source=nocode._transform(s.source, adjusted_names[s.name], inverse=True))
                     for s in unscheduled)
    unmarked = _undo_compound_sharing(unmarked, adjusted)
    unmarked = _undo_repartition(_undo_extension(unmarked, v4_layout), original_layout)
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
    expected = _manifest(prepared, previous, proposal.stages)
    require(proposal.manifest_json == encode(expected),
            'strict independently reconstructed source manifest')
    total = validate_retention(proposal, retained_copies)
    # This is the actual-byte reconstruction, not an independently generated old
    # candidate. It replays every previous inverse, including complete Raw/bytes.
    nocode.validate_sources(prepared, previous, prior)
    return dict(source_only=True, acceptance_eligible=False, authority='DENY_ALL',
                stage_counts=COUNTS, proof_changes=expected['proof_changes'], helper_count=len(HELPER_NAMES),
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

"""Freeze the reviewed ten-stage source DAG, without executing or accepting Lean.

The old monolithic builder is the input oracle, not a proof oracle: its exact
literal payloads and not-P targets are preserved and mapped explicitly.  This
module deliberately does not import the staged runner (avoiding an import cycle).
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from types import MappingProxyType

from tools import check_core_syntax_lean as original
from tools import check_guarded_slice_lean as baseline_builder

MODULE_PREFIX = 'HiaSyntaxResearch'
NAMESPACE = original.NAMESPACE
MAX_PROOF_BYTES = original.MAX_PROOF_BYTES
MAX_TOTAL_PROOF_BYTES = original.MAX_TOTAL_PROOF_BYTES
require = baseline_builder.require
BOUNDARY = '\nnamespace HiaCoreSyntaxSlice\n\nopen HiaGuardedUsizeSlice\n'
SELECTOR = 'let edge := field (field header "term") "then" -- MUTATION_SITE_SELECT_THEN'
TRANSPORT_GENERIC = frozenset(NAMESPACE + '.' + n for n in (
    'checkedEncode_roundtrip', 'checkedEncode_determinate', 'checkedEncode_of_parts'))
COMPONENTS = ('bounds', 'serialized', 'parsed', 'length', 'byte_range', 'transport')
INPUT_LAYOUT = (
    ('linear', '', 'linear', 'LinearTransport'),
    ('parallel', '', 'parallel', 'ParallelTransport'),
    ('wrong_phi', 'WrongPhi', 'linear', 'WrongPhiTransport'),
    ('literal_two', 'LiteralTwo', 'linear', 'LiteralTwoTransport'),
    ('wrong_condition', 'WrongCondition', 'linear', 'WrongConditionTransport'),
)


def digest(data):
    return sha256(data).hexdigest()


@dataclass(frozen=True)
class Stage:
    name: str
    module_name: str
    source: str
    explicit_imports: tuple
    direct_imports: tuple
    parents: tuple
    expected_theorems: frozenset
    rejection_names: tuple = ()

    @property
    def source_sha256(self):
        return digest(self.source.encode('utf-8'))

    @property
    def source_bytes(self):
        return len(self.source.encode('utf-8'))

    def manifest(self):
        return {'name': self.name, 'module_name': self.module_name,
                'source_sha256': self.source_sha256, 'source_bytes': self.source_bytes,
                'source_relative_path': self.module_name.replace('.', '/') + '.lean',
                'olean_relative_path': self.module_name.replace('.', '/') + '.olean',
                'explicit_imports': list(self.explicit_imports),
                'implicit_imports': ['Init'], 'direct_imports': list(self.direct_imports),
                'parents': list(self.parents),
                'expected_theorems': sorted(self.expected_theorems),
                'rejection_names': list(self.rejection_names),
                'permitted_axioms': ['propext', 'Classical.choice', 'Quot.sound']}


def split_model(model):
    """Only the existing namespace boundary is an admissible partition."""
    require(model.count(BOUNDARY) == 1, 'syntax model namespace boundary changed')
    offset = model.index(BOUNDARY)
    prefix, suffix = model[:offset], model[offset:]
    require(prefix + suffix == model and prefix.endswith('end HiaCoreSyntaxSlice\n\n'),
            'model partition reconstruction')
    require(set(re.findall(r'(?m)^theorem (\w+)', prefix)) ==
            {n.rsplit('.', 1)[1] for n in TRANSPORT_GENERIC}, 'transport theorem partition')
    require(set(re.findall(r'(?m)^theorem (\w+)', suffix)) ==
            {'extract_sound', 'extracted_successor'}, 'extraction theorem partition')
    require(suffix.count(SELECTOR) == 1 and model.count(SELECTOR) == 1,
            'unique extraction mutation site')
    return prefix, suffix


def _definition(source, name, type_name):
    matches = re.findall(r'(?m)^def ' + re.escape(name) + r' : ' +
                         re.escape(type_name) + r' := ([^\n]+)\n', source)
    require(len(matches) == 1, 'exact single literal definition: ' + name)
    return matches[0]


def _bytes(literal):
    require(re.fullmatch(r'\[(?:[0-9]+(?:,[0-9]+)*)?\]', literal) is not None,
            'independent byte numeral payload')
    values = [] if literal == '[]' else [int(x) for x in literal[1:-1].split(',')]
    require(all(0 <= n < 256 for n in values), 'independent byte numeral range')
    return bytes(values)


def _wrapped(namespace, text):
    ns = NAMESPACE + ('.' + namespace if namespace else '')
    return '\nnamespace ' + ns + '\n' + text + 'end ' + ns + '\n'


def _printed(names):
    return ''.join('#print axioms ' + n + '\n' for n in sorted(names))


def build_inputs():
    """Return immutable sources/stages and a JSON manifest snapshot of their DAG.

    The manifest is also supplied as canonical ``manifest_json`` and its SHA256;
    callers should bind that snapshot before execution, not mutate the mapping.
    No successful proof or admission flag is produced by source preparation.
    """
    old = original.build_inputs()
    baseline = baseline_builder.build_inputs()
    require(len(baseline['expected_theorems']) == 56 and len(old['expected_theorems']) == 66,
            'unchanged positive inventories')
    require(len(old['negatives']) == 10, 'unchanged negative inventory')
    model = original._model()
    require(model.encode('utf-8') == original.MODEL.read_bytes(),
            'model bytes must reconstruct exactly without newline normalization')
    prefix, suffix = split_model(model)
    mutated_suffix = suffix.replace(SELECTOR, SELECTOR.replace('"then"', '"else"'))
    inputs, data_parts, hints = {}, {}, {}
    for key, namespace, stem, module in INPUT_LAYOUT:
        source = old['positive'] if key in ('linear', 'parallel') else old['negatives'][key]['source']
        raw = _definition(source, stem + 'Raw', 'Raw')
        literal = _definition(source, stem + 'Bytes', 'List Nat')
        hint = _definition(source, stem + 'Hint', 'Hint')
        byte_value = _bytes(literal)
        tree = original.strict_canonical(byte_value)
        # Rebuild from the complete independently checked byte list, not a slice.
        require(original.render_raw(tree) == raw, 'full Raw and byte payload diverged')
        require(original.render_bytes(byte_value) == literal, 'byte spelling changed')
        full_ns = NAMESPACE + ('.' + namespace if namespace else '')
        data = 'def ' + stem + 'Raw : Raw := ' + raw + '\n' + \
               'def ' + stem + 'Bytes : List Nat := ' + literal + '\n'
        data_parts[key] = _wrapped(namespace, data)
        hints[key] = _wrapped(namespace, 'def ' + stem + 'Hint : Hint := ' + hint + '\n')
        inputs[key] = {'canonical_sha256': digest(byte_value), 'canonical_bytes': len(byte_value),
                       'raw_literal_sha256': digest(raw.encode()),
                       'byte_literal_sha256': digest(literal.encode()),
                       'hint_literal_sha256': digest(hint.encode()),
                       'raw_name': full_ns + '.' + stem + 'Raw',
                       'bytes_name': full_ns + '.' + stem + 'Bytes',
                       'hint_name': full_ns + '.' + stem + 'Hint',
                       'definitions_sha256': digest(data.encode()),
                       'definition_module': MODULE_PREFIX + '.' + module}
    require(inputs['linear']['canonical_sha256'] == digest(old['canonical_bytes']),
            'real canonical input changed')
    stages = []

    def stage(name, imports, body, expected, rejection_names=(), baseline_source=False):
        module = MODULE_PREFIX + '.' + name
        imports = tuple(imports)
        source = body if baseline_source else ''.join('import ' + n + '\n' for n in imports) + body + _printed(expected)
        original.checked_source((source,))
        actual_imports = tuple(re.findall(r'(?m)^import ([A-Za-z0-9_.]+)\s*$', source))
        require(actual_imports == imports, 'exact ordered explicit imports')
        require(not re.search(r'(?m)^\s*(prelude|set_option)\b|\b(sorry|native_decide)\b', source),
                'forbidden generated source command')
        parents = tuple(n for n in imports if n.startswith(MODULE_PREFIX + '.'))
        require(set(parents) <= {s.module_name for s in stages}, 'stage parent order')
        item = Stage(name, module, source, imports, ('Init',) + imports,
                     parents, frozenset(expected), tuple(rejection_names))
        printed = re.findall(r'(?m)^#print axioms (\S+)\s*$', source)
        wanted = {n.rsplit('.', 1)[1] for n in expected} if baseline_source else set(expected)
        require(len(printed) == len(expected) and set(printed) == wanted,
                'printed theorem inventory')
        stages.append(item)
        return module

    base_imports = tuple(re.findall(r'(?m)^import ([A-Za-z0-9_.]+)\s*$', baseline['positive']))
    require(base_imports == ('Lean.Elab.Tactic.Omega',), 'pinned baseline imports')
    base_module = stage('Baseline', base_imports, baseline['positive'],
                        baseline['expected_theorems'], baseline_source=True)
    data_module = stage('SyntaxData', (base_module,), prefix, TRANSPORT_GENERIC)
    transport_modules, transport_blocks = {}, {}
    for key, namespace, stem, module in INPUT_LAYOUT:
        cert = stem if key in ('linear', 'parallel') else 'mutated'
        text = original.transport_certificates(cert, stem + 'Raw', stem + 'Bytes')
        full_ns = NAMESPACE + ('.' + namespace if namespace else '')
        names = {full_ns + '.' + cert + '_' + c for c in COMPONENTS}
        transport_blocks[key] = _wrapped(namespace, text)
        transport_modules[key] = stage(module, (data_module,),
                                       data_parts[key] + transport_blocks[key], names)

    negatives = {}

    def rejection(name, input_key=None, byte_name=None):
        prior = old['negatives'][name]
        p = prior['rejected_proposition']
        mapping = {'extract': NAMESPACE + '.extract', 'checkedEncode': NAMESPACE + '.checkedEncode',
                   'decode': NAMESPACE + '.decode'}
        if input_key is not None:
            stem = 'parallel' if input_key == 'parallel' else 'linear'
            mapping.update({stem + 'Raw': inputs[input_key]['raw_name'],
                            stem + 'Bytes': byte_name or inputs[input_key]['bytes_name'],
                            stem + 'Hint': inputs[input_key]['hint_name']})
        # Replace lexical identifiers only. The original P and exact substitution
        # are both recorded so reviewers can check alpha-renaming, not just shape.
        pattern = r'\b(' + '|'.join(map(re.escape, sorted(mapping, key=len, reverse=True))) + r')\b'
        qualified = re.sub(pattern, lambda m: mapping[m.group()], p)
        inverse = {v: k for k, v in mapping.items()}
        restored = qualified
        for new, old_name in sorted(inverse.items(), key=lambda kv: len(kv[0]), reverse=True):
            restored = restored.replace(new, old_name)
        require(restored == p, 'negative proposition alpha equivalence')
        cert = NAMESPACE + '.reject_' + name
        proof = 'by decide +kernel'
        if name == 'changed_exact_byte':
            proof = 'by\n  rw [HiaCoreSyntaxSlice.linear_transport]\n  decide +kernel'
        text = 'theorem reject_' + name + ' : ¬ (' + qualified + ') := ' + proof + '\n'
        negatives[name] = {'kind': prior['kind'], 'original_rejected_proposition': p,
                           'rejected_proposition': qualified, 'identifier_mapping': mapping,
                           'certificate': cert, 'input_key': input_key,
                           'original_source_sha256': digest(prior['source'].encode()),
                           'declaration_sha256': digest(text.encode())}
        return text

    connection_proofs = '''theorem linear_extraction : extract linearRaw linearHint = some HiaGuardedUsizeSlice.linear_0 := by decide +kernel
theorem linear_relation : SliceSyntaxRelation linearRaw linearHint HiaGuardedUsizeSlice.linear_0 :=
  extract_sound linearRaw linearHint HiaGuardedUsizeSlice.linear_0 linear_extraction
theorem parallel_extraction : extract parallelRaw parallelHint = some HiaGuardedUsizeSlice.linear_0 := by decide +kernel
'''
    syntax_names = ('stale_descriptor', 'wrong_phi', 'literal_two', 'wrong_condition')
    syntax_rejections = ''.join(rejection(n, 'linear' if n == 'stale_descriptor' else n) for n in syntax_names)
    syntax_expected = set(old['expected_theorems']) | {negatives[n]['certificate'] for n in syntax_names}
    connection_module = stage('Connections', tuple(transport_modules.values()),
                             suffix + ''.join(hints.values()) +
                             _wrapped('', connection_proofs + syntax_rejections),
                             syntax_expected, syntax_names)
    changed_source = old['negatives']['changed_exact_byte']['source']
    changed_literal = _definition(changed_source, 'linearBytes', 'List Nat')
    changed_bytes = _bytes(changed_literal)
    expected_changed = bytearray(old['canonical_bytes'])
    expected_changed[-1] = 93 if expected_changed[-1] != 93 else 125
    require(changed_bytes == bytes(expected_changed), 'exact original changed byte')
    require(_definition(changed_source, 'linearRaw', 'Raw') ==
            _definition(old['positive'], 'linearRaw', 'Raw'), 'changed-byte original Raw')
    transport_names = ('changed_exact_byte', 'duplicate_keys', 'unordered_keys', 'byte_modulo_alias', 'leading_zero')
    changed_name = NAMESPACE + '.ChangedByte.linearBytes'
    transport_rejections = rejection('changed_exact_byte', 'linear', changed_name)
    transport_rejections += ''.join(rejection(n) for n in transport_names[1:])
    transport_negative_module = stage('TransportRejections', (transport_modules['linear'],),
        _wrapped('ChangedByte', 'def linearBytes : List Nat := ' + changed_literal + '\n') +
        _wrapped('', transport_rejections),
        {negatives[n]['certificate'] for n in transport_names}, transport_names)
    wrong_arm = rejection('wrong_arm_implementation', 'parallel')
    wrong_arm_module = stage('WrongArm', (transport_modules['parallel'],),
        mutated_suffix + hints['parallel'] + _wrapped('', wrong_arm),
        {negatives['wrong_arm_implementation']['certificate']}, ('wrong_arm_implementation',))
    require(len(stages) == 10 and len(negatives) == 10, 'ten-stage exact negative inventory')
    # Module ownership is part of the frozen input binding. Each complete block
    # moves verbatim, without aliases or namespace changes, before its proofs.
    by_module = {item.module_name: item for item in stages}
    require(not re.search(r'(?m)^def \w+ : (Raw|List Nat) :=',
                          by_module[data_module].source),
            'common transport model must not own concrete input literals')
    for key, namespace, stem, module in INPUT_LAYOUT:
        owner = inputs[key]['definition_module']
        require(owner == transport_modules[key], 'input definition module differs')
        source = by_module[owner].source
        block = data_parts[key]
        require(sum(item.source.count(block) for item in stages) == 1 and
                source.count(block) == 1, 'input literal block must occur exactly once in its owner')
        require(source.index(block) + len(block) == source.index(transport_blocks[key]),
                'literal definitions must immediately precede transport certificate block')
        require(len(re.findall(r'(?m)^def \w+ : (Raw|List Nat) :=', source)) == 2,
                'transport module must own only its two input definitions')
        require(all(other == key or data_parts[other] not in source for other in data_parts),
                'transport module contains sibling input literals')
    total = sum(s.source_bytes for s in stages)
    require(total <= MAX_TOTAL_PROOF_BYTES, 'aggregate staged source budget')
    for item in stages:
        for name in item.rejection_names:
            negatives[name]['stage'] = item.module_name
            target = 'theorem reject_' + name + ' :'
            require(item.source.count(target) == 1, 'unique rejection declaration')
            negatives[name]['declaration_line'] = item.source[:item.source.index(target)].count('\n') + 1
    negatives['changed_exact_byte']['changed_bytes_sha256'] = digest(changed_bytes)
    negatives['changed_exact_byte']['changed_byte_literal_sha256'] = digest(changed_literal.encode())
    # The small policy counterexamples are deliberately NOT canonical Core.
    # Bind their exact numeral payloads too, including the byte256 Raw alias.
    policy_payloads = {
        'duplicate_keys': ('(.obj [([97],.num 0),([97],.num 1)])', '[123,34,97,34,58,48,44,34,97,34,58,49,125]'),
        'unordered_keys': ('(.obj [([98],.num 0),([97],.num 1)])', '[123,34,98,34,58,48,44,34,97,34,58,49,125]'),
        'byte_modulo_alias': ('(.str [256])', '[34,0,34]'),
        'leading_zero': ('(.num 1)', '[48,49]'),
    }
    for name, (raw_literal, byte_literal) in policy_payloads.items():
        p = negatives[name]['original_rejected_proposition']
        require(raw_literal in p and byte_literal in p, 'exact policy literal mapping')
        negatives[name]['literal_input'] = {
            'raw_literal': raw_literal, 'byte_literal': byte_literal,
            'raw_literal_sha256': digest(raw_literal.encode()),
            'byte_literal_sha256': digest(byte_literal.encode()),
            'bytes_sha256': digest(_bytes(byte_literal)),
            'byte_count': len(_bytes(byte_literal)),
        }
    partition = {'full_sha256': digest(model.encode()), 'prefix_sha256': digest(prefix.encode()),
                 'suffix_sha256': digest(suffix.encode()), 'mutated_suffix_sha256': digest(mutated_suffix.encode()),
                 'split_byte_offset': len(prefix.encode()),
                 'mutation_byte_offset': len(model[:model.index(SELECTOR)].encode()),
                 'mutation_original': SELECTOR, 'mutation_replacement': SELECTOR.replace('"then"', '"else"')}
    manifest = {'schema': 'hepta.hia.core-syntax-stage-sources.v1', 'module_prefix': MODULE_PREFIX,
                'stages': [s.manifest() for s in stages], 'inputs': inputs,
                'model_partition': partition, 'negatives': negatives,
                'expected_theorems': sorted(old['expected_theorems']),
                'baseline_source_sha256': digest(baseline['positive'].encode()),
                'original_positive_source_sha256': digest(old['positive'].encode()),
                'original_manifest': old['manifest'], 'proof_input_bytes': total,
                'connections_module': connection_module, 'wrong_arm_module': wrong_arm_module,
                'transport_rejections_module': transport_negative_module,
                'scope': 'staged source proposal only; twelve obligations unproved; DENY_ALL'}
    manifest_json = json.dumps(manifest, sort_keys=True, separators=(',', ':'))
    return {'stages': tuple(stages), 'sources': MappingProxyType({s.module_name: s.source for s in stages}),
            'manifest': manifest, 'manifest_json': manifest_json,
            'manifest_sha256': digest(manifest_json.encode()), 'negatives': negatives,
            'canonical_bytes': old['canonical_bytes'],
            'expected_theorems': frozenset(old['expected_theorems'])}

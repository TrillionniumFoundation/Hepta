"""Versioned, reversible eleven-module partition of the complete original O.

No evaluator, definition, proposition or proof is rewritten. Python validation
is source evidence only; same-run kernel receipts remain the runner's concern.
"""
from hashlib import sha256
import json
import re
from types import MappingProxyType

from tools import core_syntax_stage_sources as legacy
from tools import core_syntax_structured_stages as original
from tools.check_guarded_slice_lean import require

PROTOCOL = 'contiguous-transport-certificate-partitions-v1'
CUTS = (703, 1406, 2109, 2811, 3513, 4215)
PARTS = tuple(f'CertPart{i:02d}' for i in range(1, 7))
NAMES = ('Baseline', 'SyntaxData') + PARTS + ('Connections', 'TransportRejections', 'WrongArm')
ROOT_OWNERS = dict(zip(('linear','parallel','wrong_phi','literal_two','wrong_condition'), PARTS[1:]))
PART_COUNTS = (703, 703, 703, 702, 702, 702)
DEF_COUNTS = (1419, 1417, 1416, 1416, 1413, 604)
SOURCE_SIZES = (30632,27925,378135,394675,391198,389828,388958,310773,21498,51025,15735)
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
PREFIX = legacy.MODULE_PREFIX


def digest(raw):
    return sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def _original_check(prepared):
    from tools.check_core_syntax_staged import validate_plan
    require('original_prepared' not in prepared, 'nested or recursive original preparation')
    require(prepared['manifest'].get('protocol') == original.PROTOCOL, 'original O protocol required')
    require(type(prepared['stages']) is tuple and tuple(s.name for s in prepared['stages']) ==
            ('Baseline','SyntaxData','LinearTransport','ParallelTransport','WrongPhiTransport',
             'LiteralTwoTransport','WrongConditionTransport','Connections','TransportRejections','WrongArm'),
            'fixed original ten-stage inventory')
    validate_plan(prepared)
    require(encode(prepared['manifest']['stages']) == encode([s.manifest() for s in prepared['stages']]),
            'strict original stage metadata')


class _DeclarationMarkers:
    """Literal candidate positions from this exact source, with no word anchors.

    The key ends at the next ASCII space, not an identifier boundary. Exact
    startswith checks retain empty names, embedded markers and Unicode text.
    """
    def __init__(self, source):
        self.source = source
        self.all = {}
        self.tokens = {}
        for marker in ('def ', 'theorem '):
            positions = []
            start = source.find(marker)
            while start >= 0:
                positions.append(start)
                begin = start + len(marker)
                stop = source.find(' ', begin)
                if stop >= 0:
                    self.tokens.setdefault((marker, source[begin:stop]), []).append(start)
                start = source.find(marker, start + 1)
            self.all[marker] = tuple(positions)

    def positions(self, literal):
        marker = next((m for m in self.all if literal.startswith(m)), None)
        require(marker is not None, 'literal declaration marker required')
        stop = literal.find(' ', len(marker))
        candidates = (self.all[marker] if stop < 0 else
                      self.tokens.get((marker, literal[len(marker):stop]), ()))
        return tuple(pos for pos in candidates if self.source.startswith(literal, pos))


def _parse(source):
    """Independent restricted framing parser, preserving full declaration bytes.

    Only validated generator declarations may have continuation lines. Namespace
    wrappers cannot nest. Print commands occur only after all wrappers close.
    """
    raw = source.encode('utf-8')
    require(raw.endswith(b'\n') and b'\r' not in raw, 'partition newlines')
    imports, declarations, prints = [], [], []
    ns = None
    current = None
    printing = False
    for line in raw.splitlines(keepends=True):
        text = line[:-1].decode('utf-8')
        if text.startswith('  '):
            require(current is not None and current[1] == 'theorem' and ns is not None,
                    'split or unsupported declaration continuation')
            current[3] += line
            continue
        current = None
        match = re.fullmatch(r'import ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(not declarations and ns is None and not printing, 'late import')
            imports.append(match[1]); continue
        match = re.fullmatch(r'namespace ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(ns is None and not printing, 'nested or late namespace')
            ns = match[1]; continue
        match = re.fullmatch(r'end ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(ns is not None and ns == match[1], 'namespace close differs')
            ns = None; continue
        match = re.match(r'^(def|theorem) ([A-Za-z][A-Za-z0-9_]*)\b', text)
        if match:
            require(ns is not None and not printing and ' := ' in text, 'declaration framing')
            current = [ns, match[1], match[2], line]
            declarations.append(current); continue
        match = re.fullmatch(r'#print axioms ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(ns is None, 'print inside namespace')
            printing = True; prints.append(match[1]); continue
        require(False, 'unsupported partition command')
    require(ns is None and declarations, 'unclosed or empty declaration stream')
    return tuple(imports), tuple(tuple(d) for d in declarations), tuple(prints)


def _stream(prepared):
    rows = []
    per_input = {}
    for (key, namespace, stem, module), stage in zip(legacy.INPUT_LAYOUT, prepared['stages'][2:7]):
        require(stage.name == module, 'original input order')
        imports, declarations, prints = _parse(stage.source)
        ns = legacy.NAMESPACE + ('.' + namespace if namespace else '')
        require(imports == (PREFIX+'.SyntaxData',) and all(d[0] == ns for d in declarations),
                'original input namespace and import')
        names = tuple(d[0]+'.'+d[2] for d in declarations if d[1] == 'theorem')
        require(len(names) == 843 and len(set(names)) == 843 and prints == tuple(sorted(names)),
                'original 843 theorem inventory')
        rows.extend(declarations)
        per_input[key] = declarations
    require(sum(d[1] == 'def' for d in rows) == 7685, 'all 7685 data definitions')
    return tuple(rows), per_input


def _render(rows, parent):
    result = 'import '+parent+'\n'
    ns = None
    names = []
    for owner, kind, name, raw in rows:
        if owner != ns:
            if ns is not None:
                result += 'end '+ns+'\n'
            result += 'namespace '+owner+'\n'; ns = owner
        result += raw.decode('utf-8')
        if kind == 'theorem':
            names.append(owner+'.'+name)
    result += 'end '+ns+'\n'
    result += ''.join('#print axioms '+n+'\n' for n in sorted(names))
    return result, frozenset(names)


def _consumer_source(source, parent):
    # Strip only leading import lines; all remaining bytes are retained.
    lines = source.splitlines(keepends=True)
    while lines and lines[0].startswith('import '):
        lines.pop(0)
    return 'import '+parent+'\n'+''.join(lines)


def _make_stage(name, parent, source, names, rejections=()):
    return legacy.Stage(name, PREFIX+'.'+name, source, (parent,), ('Init', parent),
                        (parent,), frozenset(names), tuple(rejections))


def _partition_metadata(stages, original_prepared, per_input):
    owners = {}
    declared = {}
    for stage in stages[2:8]:
        _, rows, _ = _parse(stage.source)
        for ns, kind, name, raw in rows:
            full = ns+'.'+name
            require(full not in declared, 'duplicate declaration')
            declared[full] = stage.name
    for key, rows in per_input.items():
        counts = {name: sum(d[1] == 'theorem' and declared[d[0]+'.'+d[2]] == name for d in rows)
                  for name in PARTS}
        original_input = original_prepared['structured_certificates'][key]['manifest']
        ns, stem, cert = (original_input[k] for k in ('namespace','stem','cert'))
        root_names = [ns+'.'+stem+'Raw', ns+'.'+stem+'Bytes'] + [ns+'.'+cert+s for s in
                     ('_bounds','_serialized','_parsed','_length','_byte_range','_transport')]
        require(all(declared[n] == ROOT_OWNERS[key] for n in root_names), 'complete root ownership')
        owners[key] = {'theorem_counts': counts, 'root_owner': PREFIX+'.'+ROOT_OWNERS[key],
                       'root_declarations': root_names,
                       'declaration_stream_sha256': digest(b''.join(d[3] for d in rows)),
                       'original_input_binding': original_prepared['manifest']['inputs'][key]}
    return owners


def _manifest(stages, base, per_input):
    # The preserved negatives.declaration_line is an original-O coordinate.
    # Bind current consumer coordinates separately, from actual source bytes.
    locations = {}
    for stage in stages[8:]:
        for name in stage.rejection_names:
            certificate = base['negatives'][name]['certificate']
            local = certificate.rsplit('.', 1)[1]
            found = [i for i,line in enumerate(stage.source.splitlines(), 1)
                     if line.startswith('theorem '+local+' :')]
            require(len(found) == 1, 'unique actual negative declaration location')
            locations[name] = {'module': stage.module_name, 'line': found[0]}
    require(set(locations) == set(base['negatives']), 'all actual negative locations')
    return {'schema': 'hepta.hia.partition-sources.v1', 'protocol': PROTOCOL,
            'module_prefix': PREFIX, 'original_manifest_sha256': base['manifest_sha256'],
            'cuts': list(CUTS), 'stages': [s.manifest() for s in stages],
            'negative_declaration_locations': locations,
            'preserved_negative_coordinates': 'original-O',
            'inputs': _partition_metadata(stages, base, per_input),
            'expected_theorems': sorted(base['expected_theorems']), 'negatives': base['negatives'],
            'transport_theorem_count': 4215, 'transport_definition_count': 7685,
            'proof_input_bytes': sum(s.source_bytes for s in stages)}


def build_partition_sources(original_prepared):
    _original_check(original_prepared)
    rows, per_input = _stream(original_prepared)
    stages = list(original_prepared['stages'][:2])
    cursor = count = 0
    for name, stop in zip(PARTS, CUTS):
        start = cursor
        while count < stop:
            count += rows[cursor][1] == 'theorem'; cursor += 1
        parent = PREFIX+'.'+('SyntaxData' if name == PARTS[0] else PARTS[PARTS.index(name)-1])
        source, names = _render(rows[start:cursor], parent)
        stages.append(_make_stage(name,parent,source,names))
    require(cursor == len(rows), 'unassigned declaration suffix')
    for old_stage, owner in zip(original_prepared['stages'][7:], (PARTS[5],PARTS[1],PARTS[2])):
        parent = PREFIX+'.'+owner
        stages.append(_make_stage(old_stage.name,parent,_consumer_source(old_stage.source,parent),
                                  old_stage.expected_theorems,old_stage.rejection_names))
    stages = tuple(stages)
    manifest = _manifest(stages, original_prepared, per_input)
    encoded = encode(manifest)
    result = {**original_prepared, 'original_prepared': original_prepared,
              'stages': stages, 'sources': MappingProxyType({s.module_name:s.source for s in stages}),
              'manifest': manifest, 'manifest_json': encoded, 'manifest_sha256': digest(encoded.encode())}
    validate_bindings(result)
    return result


def build_inputs():
    return build_partition_sources(original.build_inputs())


def validate_bindings(prepared):
    """Validate O first, then independently undo new framing and every cut.

    The original frozen preparation is the source oracle. Its provenance must
    also be checked by the runner's fresh before/after build and file bindings.
    """
    base = prepared['original_prepared']
    _original_check(base)
    stages = prepared['stages']
    require(type(stages) is tuple and tuple(s.name for s in stages) == NAMES,
            'exact eleven modules, no fallback')
    require(stages[:2] == base['stages'][:2], 'unchanged baseline and syntax data')
    rows, per_input = _stream(base)
    restored = []
    cumulative = 0
    all_names = set()
    total = 0
    for index, stage in enumerate(stages):
        require(stage.module_name == PREFIX+'.'+stage.name, 'exact module identity')
        total += stage.source_bytes
        require(stage.source_bytes <= MAX_SOURCE and total <= MAX_TOTAL_SOURCE, 'partition source byte budget')
        if index < 2:
            continue
        parent_name = ('SyntaxData' if index == 2 else PARTS[index-3]) if index < 8 else (PARTS[5],PARTS[1],PARTS[2])[index-8]
        parent = PREFIX+'.'+parent_name
        require(stage.explicit_imports == (parent,) and stage.direct_imports == ('Init',parent)
                and stage.parents == (parent,), 'fixed parent and implicit Init')
        if index >= 8:
            old_stage = base['stages'][index-1]
            require(stage.source == _consumer_source(old_stage.source,parent) and
                    stage.expected_theorems == old_stage.expected_theorems and
                    stage.rejection_names == old_stage.rejection_names, 'unchanged consumer body and inventory')
            continue
        imports, declarations, prints = _parse(stage.source)
        require(imports == (parent,), 'literal import header')
        names = tuple(d[0]+'.'+d[2] for d in declarations if d[1] == 'theorem')
        require(len(names) == PART_COUNTS[index-2] and len(set(names)) == len(names) and
                not all_names.intersection(names), 'disjoint exact partition theorem count')
        all_names.update(names)
        require(prints == tuple(sorted(names)) and stage.expected_theorems == frozenset(names)
                and stage.rejection_names == (), 'owned prints and inventory')
        require(sum(d[1] == 'def' for d in declarations) == DEF_COUNTS[index-2], 'partition data count')
        require(declarations[-1][1] == 'theorem', 'cut immediately after theorem')
        restored.extend(declarations)
        cumulative += len(names)
        require(cumulative == CUTS[index-2], 'fixed cumulative cut')
        # Exact namespace framing too; parser equality alone could permit extra
        # empty wrappers that alter the proposal without altering declarations.
        rendered, _ = _render(declarations,parent)
        require(rendered == stage.source, 'canonical partition framing')
    require(tuple(restored) == rows, 'independent full declaration stream reconstruction')
    require(len(all_names) == 4215 and all_names == set().union(*(s.expected_theorems for s in base['stages'][2:7])),
            'all five complete 843 target sets')
    # This metadata is independently recomputed from actual parsed declarations,
    # fixed protocol constants and the validated original, not proposer hashes.
    expected = _manifest(stages,base,per_input)
    require(encode(prepared['manifest']) == encode(expected), 'strict independently derived partition manifest')
    require(prepared['manifest_json'] == encode(expected) and prepared['manifest_sha256'] == digest(encode(expected).encode()),
            'canonical manifest identity')
    require(dict(prepared['sources']) == {s.module_name:s.source for s in stages}, 'actual source map')
    for key in ('canonical_bytes','expected_theorems','negatives','binding_inputs','structured_certificates'):
        require(prepared[key] == base[key], 'unchanged complete original binding: '+key)
    require(tuple(s.source_bytes for s in stages) == SOURCE_SIZES and total == 2400382,
            'reviewed exact source sizes')
    return {'source_bytes': total, 'stage_count': 11, 'transport_theorem_count': 4215,
            'transport_definition_count': 7685, 'root_owners': dict(ROOT_OWNERS)}

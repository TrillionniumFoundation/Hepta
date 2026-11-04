"""Source-only reversible byte-fact proposals. No Lean, runner or admission API."""
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
from types import MappingProxyType

from tools import core_syntax_partition_sources as original
from tools import core_byte_facts_dag as dag
from tools.check_core_syntax_staged import validate_plan
from tools.check_guarded_slice_lean import require
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = 'compositional-byte-facts-source-v1'
HELPER_PATH = 'experiments/hia_initialization_frontiers_20261103/ByteFactsResearch.lean'
HELPER_SHA256 = 'ec04662991f9efd20e51fdb6f37a8178fa81c86e62818c2441f8c7762a98507b'
HELPER = 'HiaCoreSyntaxSlice.ByteFactsResearch.'
HELPER_NAMES = frozenset(HELPER+n for n in ('nil', 'cons', 'append'))
EXPECTED_COUNTS = (56, 35, 703, 1298, 1298, 1297, 1297, 1297)
MAX_MANIFEST = 32768
MAX_SOURCE = 2*1024*1024
MAX_TOTAL_SOURCE = 8*1024*1024
MAX_MARKER_RESERVE = 24*64  # No marker is generated or executed by this source-only layer.


def digest(raw):
    return sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


@dataclass(frozen=True)
class ByteFactsSources:
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
        return MappingProxyType({s.module_name:s.source for s in self.stages})

    @property
    def retained_sources(self):
        return MappingProxyType({**{'original/'+s.name+'.lean':s.source for s in self.original_stages},
                                 **{'transformed/'+s.name+'.lean':s.source for s in self.stages}})


def _original(prepared):
    require(prepared['manifest'].get('protocol') == original.PROTOCOL, 'complete exact11 source required')
    validate_plan(prepared)
    require(tuple(s.name for s in prepared['stages']) == original.NAMES, 'fixed original stages')


def helper_source():
    raw = (ROOT/HELPER_PATH).read_bytes()
    require(digest(raw) == HELPER_SHA256, 'fixed helper definition and theorem text changed')
    return raw.decode('utf-8')


def _plans(prepared):
    plans = {}
    for key, item in prepared['structured_certificates'].items():
        manifest = item['manifest']
        plan = dag.analyze(item['source'], manifest['namespace'], manifest['stem'],
                           prepared['binding_inputs'][key]['bytes'])
        require(len(plan['rows']) == 595 and sum(r['ast'][0] == 'literal' for r in plan['rows']) == 281,
                'fixed complete byte DAG inventory')
        plans[key] = plan
    require(set(plans) == set(original.ROOT_OWNERS), 'all five byte DAGs required')
    return plans


def _expr(ast):
    kind = ast[0]
    if kind == 'literal':
        return '['+', '.join(map(str,ast[1]))+']'
    if kind == 'ref':
        return ast[1]
    if kind == 'append':
        return '('+_expr(ast[1])+' ++ '+_expr(ast[2])+')'
    if kind == 'cons':
        return '('+str(ast[1])+' :: '+_expr(ast[2])+')'
    raise ValueError('unsupported checked byte AST')


def _proof(ast, known):
    """Explicit child proofs; only small literal/Nat decisions, no full-list decision."""
    kind = ast[0]
    if kind == 'literal':
        length = len(ast[1])
        return length, '(by unfold '+HELPER+'facts; decide +kernel : '+HELPER+'facts '+_expr(ast)+' '+str(length)+')'
    if kind == 'ref':
        require(ast[1] in known, 'fact dependency must already be named')
        return known[ast[1]]
    if kind == 'cons':
        length, proof = _proof(ast[2], known)
        return length+1, '('+HELPER+'cons '+str(ast[1])+' '+_expr(ast[2])+' '+str(length)+\
               ' (by decide +kernel) '+proof+')'
    if kind == 'append':
        left, lp = _proof(ast[1], known); right, rp = _proof(ast[2], known)
        return left+right, '('+HELPER+'append '+_expr(ast[1])+' '+_expr(ast[2])+' '+\
               str(left)+' '+str(right)+' '+lp+' '+rp+')'
    raise ValueError('unsupported proof AST')


def _facts(plan, stem):
    known, lines, names = {}, [], []
    for index, row in enumerate(plan['rows']):
        name = stem+'_bf%04d'%index
        require(name not in {r['name'] for r in plan['rows']}, 'auxiliary name collides with data')
        length, proof = _proof(row['ast'], known)
        require(type(length) is int and length == row['length'], 'independent byte length differs')
        statement = HELPER+'facts '+row['name']+' '+str(length)
        if row['ast'][0] == 'literal':
            body = 'by unfold '+HELPER+'facts; decide +kernel'
        else:
            body = 'by\n  simpa only ['+row['name']+'] using '+proof
        lines.append('theorem '+name+' : '+statement+' := '+body+'\n')
        names.append(plan['namespace']+'.'+name)
        known[row['name']] = (length, name)
    require(plan['root'] in known and len(names) == 595, 'exact root and fact inventory')
    return ''.join(lines), frozenset(names), known[plan['root']]


def _edit(start, end, new, kind, anchor, namespace):
    return dict(start=start, end=end, new=new.encode(), kind=kind, anchor=anchor, namespace=namespace)


def _apply(source, edits):
    raw = source.encode(); chunks, ledger, cursor, added = [], [], 0, 0
    for edit in sorted(edits,key=lambda e:(e['start'],e['end'])):
        start,end,new = edit['start'],edit['end'],edit['new']
        require(type(start) is int and type(end) is int and cursor <= start <= end <= len(raw),
                'ordered nonoverlapping source edits')
        require(start > cursor or not ledger or start == end and ledger[-1]['original_end'] < start,
                'ambiguous adjacent or duplicate edit')
        chunks.extend((raw[cursor:start],new))
        position = start+added
        ledger.append(dict(kind=edit['kind'], anchor=edit['anchor'], namespace=edit['namespace'],
                           original_start=start, original_end=end, transformed_start=position,
                           transformed_end=position+len(new), original_sha256=digest(raw[start:end]), original_bytes=end-start, transformed_bytes=len(new),
                           transformed_sha256=digest(new)))
        added += len(new)-(end-start); cursor = end
    chunks.append(raw[cursor:])
    return b''.join(chunks).decode(), ledger


def inverse_source(source, original_source, ledger):
    require(type(source) is str and type(original_source) is str and type(ledger) is list,
            'exact inverse source types')
    raw, old = source.encode(), original_source.encode()
    require(len(raw) <= MAX_SOURCE and len(old) <= MAX_SOURCE and len(ledger) <= 4,
            'inverse file and edit count bounds')
    chunks, cursor, old_cursor = [], 0, 0
    fields = {'kind','anchor','namespace','original_start','original_end','transformed_start',
              'transformed_end','original_sha256','transformed_sha256','original_bytes','transformed_bytes'}
    for item in ledger:
        require(type(item) is dict and set(item) == fields, 'exact edit schema')
        a,b,c,d = (item[k] for k in ('original_start','original_end','transformed_start','transformed_end'))
        require(all(type(x) is int for x in (a,b,c,d)) and old_cursor <= a <= b <= len(old) and
                cursor <= c <= d <= len(raw) and c-cursor == a-old_cursor,
                'inverse ordered exact UTF-8 intervals')
        require(type(item['original_bytes']) is int and type(item['transformed_bytes']) is int and
                item['original_bytes'] == b-a and item['transformed_bytes'] == d-c, 'exact edit byte counts')
        require(digest(old[a:b]) == item['original_sha256'] and
                digest(raw[c:d]) == item['transformed_sha256'], 'inverse edit hashes differ')
        chunks.extend((raw[cursor:c],old[a:b])); cursor = d; old_cursor = b
    chunks.append(raw[cursor:])
    restored = b''.join(chunks)
    require(restored == old, 'full original source recovery required')
    return restored


def _compact(stage):
    return dict(name=stage.name,module_name=stage.module_name,source_sha256=stage.source_sha256,
                source_bytes=stage.source_bytes,inventory_count=len(stage.expected_theorems),
                inventory_sha256=digest(encode(sorted(stage.expected_theorems)).encode()))


def _derive(prepared):
    helper = helper_source()
    plans = _plans(prepared)
    stages = list(prepared['stages'])
    edit_by_stage = {stage.name:[] for stage in stages}
    added_names = {stage.name:set() for stage in stages}
    helper_block = helper+''.join('#print axioms '+n+'\n' for n in sorted(HELPER_NAMES))
    syntax = stages[1]
    require(HELPER not in syntax.source, 'helper namespace already exists')
    edit_by_stage['SyntaxData'].append(_edit(len(syntax.source.encode()),len(syntax.source.encode()),
                                            helper_block,'helpers','fixed_helpers',HELPER[:-1]))
    added_names['SyntaxData'].update(HELPER_NAMES)
    summaries = {}
    for key,plan in plans.items():
        owner = original.ROOT_OWNERS[key]
        stage = next(s for s in stages if s.name == owner)
        data = prepared['structured_certificates'][key]['manifest']
        stem, cert, namespace = data['stem'], data['cert'], data['namespace']
        block, names, (length, root_fact) = _facts(plan,stem)
        require(not (names & set().union(*(s.expected_theorems for s in stages))), 'theorem name collision')
        for name in names:
            require(all(kind+' '+name.rsplit('.',1)[1]+' ' not in prepared['structured_certificates'][key]['source']
                        for kind in ('def','theorem')), 'auxiliary name collides with original declaration')
        targets = (
            (cert+'_length', stem+'Bytes.length ≤ transportByteLimit',
             'by\n  rw [('+root_fact+').1]\n  decide +kernel'),
            (cert+'_byte_range', stem+'Bytes.all (fun byte => decide (byte ≤ 255)) = true',
             'by exact ('+root_fact+').2'))
        raw = stage.source.encode()
        for index,(name,target,proof) in enumerate(targets):
            prefix = ('theorem '+name+' : '+target+' := ').encode()
            old = prefix+b'by decide +kernel\n'
            require(raw.count(old) == 1, 'exact original root proof target required')
            start = raw.index(old)
            if index == 0:
                edit_by_stage[owner].append(_edit(start,start,block,'facts',namespace+'.'+name,namespace))
            a = start+len(prefix); b = start+len(old)-1
            edit_by_stage[owner].append(_edit(a,b,proof,'root_proof',namespace+'.'+name,namespace))
        prints = ''.join('#print axioms '+name+'\n' for name in sorted(names))
        edit_by_stage[owner].append(_edit(len(raw),len(raw),prints,'prints','auxiliary_inventory',namespace))
        added_names[owner].update(names)
        summaries[key] = dict(namespace=namespace,stem=stem,owner=owner,root=plan['root'],fact_count=len(names),
            graph_sha256=plan['graph_digest'],input_source_sha256=plan['source_sha256'],
            bytes_sha256=digest(bytes(plan['rows'][-1]['value'])),bytes_length=length,
            auxiliary_source_sha256=digest(block.encode()),
            auxiliary_inventory_sha256=digest(encode(sorted(names)).encode()))
    ledger = {}
    for index,stage in enumerate(stages):
        source, edits = _apply(stage.source,edit_by_stage[stage.name])
        stages[index] = replace(stage,source=source,expected_theorems=stage.expected_theorems|frozenset(added_names[stage.name]))
        ledger[stage.name] = edits
    stages = tuple(stages)
    old_total = sum(s.source_bytes for s in prepared['stages'])
    total = sum(s.source_bytes for s in stages)
    # Retain every original and transformed file separately, even equal files.
    retained = old_total+total
    diagnostic_upper = retained+stages[3].source_bytes+MAX_MARKER_RESERVE
    require(all(s.source_bytes <= MAX_SOURCE for s in stages) and diagnostic_upper <= MAX_TOTAL_SOURCE,
            'complete retained source and future marker reserve budget')
    manifest = dict(schema='hepta.hia.byte-facts-source.v1',protocol=PROTOCOL,source_only=True,
        acceptance_eligible=False,kernel_core_syntax_connection_checked=False,
        actual_core_bridge_proved=False,python_exporter_refinement_proved=False,
        body_prefix_refinement_proved=False,all_edge_transfer_proved=False,
        obligations=[dict(id=n,status='unproved') for n,_ in OBLIGATIONS],**DENY,
        original_manifest_sha256=prepared['manifest_sha256'],helper_sha256=digest(helper.encode()),
        helper_definition=HELPER+'facts',helper_theorems=sorted(HELPER_NAMES),inputs=summaries,
        original_stages=[_compact(s) for s in prepared['stages']],stages=[_compact(s) for s in stages],
        edits=ledger,original_source_bytes=old_total,transformed_source_bytes=total,
        retained_source_bytes=retained,marked_part02_source_upper_bound=stages[3].source_bytes+MAX_MARKER_RESERVE,
        diagnostic_retained_source_upper_bound=diagnostic_upper,auxiliary_theorem_count=2975)
    encoded = encode(manifest)
    require(len(encoded.encode()) <= MAX_MANIFEST, 'compact transformation manifest cap')
    return ByteFactsSources(prepared['stages'],stages,encoded)


def build_sources(prepared):
    _original(prepared)
    result = _derive(prepared)
    validate_sources(prepared,result)
    return result


def build_inputs():
    return build_sources(original.build_inputs())


def validate_sources(prepared, proposal):
    _original(prepared)
    require(isinstance(proposal,ByteFactsSources) and type(proposal.stages) is tuple and
            proposal.original_stages == prepared['stages'] and
            tuple(s.name for s in proposal.stages) == original.NAMES, 'exact original and transformed stages')
    require(type(proposal.manifest_json) is str and len(proposal.manifest_json.encode()) <= MAX_MANIFEST,
            'bounded transformation manifest')
    manifest = proposal.manifest
    require(proposal.manifest_json == encode(manifest), 'canonical transformation manifest')
    require(set(manifest.get('edits',{})) == set(original.NAMES), 'complete stage edit ledger')
    for old,new in zip(prepared['stages'],proposal.stages):
        require(replace(new,source=old.source,expected_theorems=old.expected_theorems) == old,
                'imports parents names rejection ownership unchanged')
        inverse_source(new.source,old.source,manifest['edits'][old.name])
        require(old.expected_theorems <= new.expected_theorems, 'old theorem inventory omitted')
    from tools.core_byte_facts_verify import validate_insertions
    validate_insertions(prepared, proposal)
    expected = _derive(prepared)
    require(proposal == expected, 'independent DAG, targets, proof templates and edit anchors differ')
    counts = tuple(len(s.expected_theorems) for s in proposal.stages)
    # Unchanged consumer inventories are bound to the original rather than guessed.
    require(counts[:8] == EXPECTED_COUNTS[:8] and
            counts[8:] == tuple(len(s.expected_theorems) for s in prepared['stages'][8:]),
            'exact new stage inventories')
    require(sum(counts[2:8]) == 7190 and manifest['auxiliary_theorem_count'] == 2975,
            'complete original plus auxiliary transport inventory')
    return dict(source_only=True,acceptance_eligible=False,authority='DENY_ALL',
                stage_counts=counts,manifest_bytes=len(proposal.manifest_json.encode()),
                transformed_source_bytes=manifest['transformed_source_bytes'],
                diagnostic_retained_source_upper_bound=manifest['diagnostic_retained_source_upper_bound'])

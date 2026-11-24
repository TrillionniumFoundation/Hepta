"""Author the native-v2 cold report gate, preserving the old gate unchanged.

The executable validates the current source inventory, complete contract,
all exact phase-plan identities, real generation relationships, resource and
time bounds, and all nineteen paired qualification families.  It cannot turn
a legacy Python-isolation report into a native report.
"""
import argparse
import ast
import copy
import inspect
import json
import re
from pathlib import Path

from tools import generate_hia_source_release_cold_admit as legacy

ROOT=Path(__file__).resolve().parents[1]
FAMILIES=['capacity','cfg','elf','chain','owned','bulk','loan','resource','tail',
          'select','effects','multi','keyword','signed','scalar-casts',
          'explicit-traps','cli','names','exports']
CHECKS=['export_manifest_matches_qualification','native_hia_toolchain_only',
    'nested_full_qualification_pass','nested_process_exit_zero','no_ancestor_git_identity',
    'no_bytecode_cache_created','fresh_home_and_tmp','no_inherited_target_or_successor_images',
    'origin_hashes_preserved','owned_process_tree_cleanup_confirmed','source_export_hashes_preserved',
    'all_independent_references_before_B0','lossless_phase_archives_verified','all_19_families_both_compilers']
FIELDS=['modified_generation_sha256','seed_sha256','qualification_wall_limit_seconds',
    'cleanup_wall_limit_seconds','nested_wall_elapsed_ns','cleanup_wall_elapsed_ns','scheduler',
    'phase_workers','archive_workers','max_pending_archives','max_unsealed_phases',
    'peak_phase_workers','peak_archive_workers','peak_pending_archives','peak_unsealed_phases',
    'qualification_families','original','modified',*FAMILIES,'phases','kind','reference','base',
    'qualification','family','label','plan_sha256','journal_sha256','archive_sha256',
    'node_count','nodes_retained','cleanup_complete','sealed','id','native_flat_observer_hex',
    'native_cold_qualification','phase_plan_catalog','']

EXTRA=r'''def native_report(s:readbuf, o:mutbuf, w:mutbuf, root:u64, contract:u64) -> u64:
    native_constants(w)
    if valid_pin(s, o, field(s, o, w, root, F_seed_sha256)) == 0:
        return 0
    generations = field(s, o, w, root, F_modified_generation_sha256)
    if generations == 0 or kind(o, generations) != 4:
        return 0
    first = generations + 1
    second = following(o, first)
    third = following(o, second)
    if first >= following(o, generations) or second >= following(o, generations) or third >= following(o, generations) or following(o, third) != following(o, generations):
        return 0
    if valid_pin(s, o, first) == 0 or valid_pin(s, o, second) == 0 or valid_pin(s, o, third) == 0:
        return 0
    original = field(s, o, w, root, 5) + 1
    if string_compare(s, token_start(o, first), token_start(o, second)) == 0 or string_compare(s, token_start(o, second), token_start(o, third)) != 0 or string_compare(s, token_start(o, original), token_start(o, third)) == 0:
        return 0
    if integer_field(s, o, w, root, F_qualification_wall_limit_seconds, 180, 180) == 0 or integer_field(s, o, w, root, F_cleanup_wall_limit_seconds, 3, 3) == 0:
        return 0
    if integer_field(s, o, w, root, F_nested_wall_elapsed_ns, 1, 180000000000) == 0 or integer_field(s, o, w, root, F_cleanup_wall_elapsed_ns, 0, 3000000000) == 0:
        return 0
    scheduler = field(s, o, w, root, F_scheduler)
    if unique_object(s, o, scheduler) != 8:
        return 0
    if integer_field(s, o, w, scheduler, F_phase_workers, 2, 2) == 0 or integer_field(s, o, w, scheduler, F_archive_workers, 1, 1) == 0 or integer_field(s, o, w, scheduler, F_max_pending_archives, 2, 2) == 0 or integer_field(s, o, w, scheduler, F_max_unsealed_phases, 4, 4) == 0:
        return 0
    if integer_field(s, o, w, scheduler, F_peak_phase_workers, 1, 2) == 0 or integer_field(s, o, w, scheduler, F_peak_archive_workers, 1, 1) == 0 or integer_field(s, o, w, scheduler, F_peak_pending_archives, 0, 2) == 0 or integer_field(s, o, w, scheduler, F_peak_unsealed_phases, 1, 4) == 0:
        return 0
    families = field(s, o, w, root, F_qualification_families)
    if unique_object(s, o, families) != 19:
        return 0
    i = F_capacity
    while i <= F_exports:
        row = field(s, o, w, families, i)
        if unique_object(s, o, row) != 2 or true_field(s, o, w, row, F_original) == 0 or true_field(s, o, w, row, F_modified) == 0:
            return 0
        i = i + 1
    metadata = field(s, o, w, contract, F_native_cold_qualification)
    catalog = field(s, o, w, metadata, F_phase_plan_catalog)
    if native_phases(s, o, w, field(s, o, w, root, F_phases), catalog) == 0:
        return 0
    return hexadecimal(s, o, w, field(s, o, w, root, F_native_flat_observer_hex), 1170000, OBSERVER_BYTES)

def native_phases(s:readbuf, o:mutbuf, w:mutbuf, phases:u64, catalog:u64) -> u64:
    if phases == 0 or kind(o, phases) != 4 or catalog == 0 or kind(o, catalog) != 4:
        return 0
    i = 0
    while i < PHASE_COUNT:
        put(w, 1150000 + i * 8, 0)
        i = i + 1
    cursor = phases + 1
    count = 0
    base = 0
    while cursor < following(o, phases):
        if unique_object(s, o, cursor) < 12:
            return 0
        expected = phase_entry(s, o, w, field(s, o, w, cursor, F_id), catalog)
        index = get(w, 1152000)
        if expected == 0 or index >= PHASE_COUNT or get(w, 1150000 + index * 8) != 0:
            return 0
        put(w, 1150000 + index * 8, 1)
        if equal_field(s, o, w, cursor, expected, F_kind) == 0 or equal_field(s, o, w, cursor, expected, F_family) == 0 or equal_field(s, o, w, cursor, expected, F_label) == 0:
            return 0
        if equal_field(s, o, w, cursor, expected, F_plan_sha256) == 0:
            return 0
        if valid_pin(s, o, field(s, o, w, cursor, F_journal_sha256)) == 0 or valid_pin(s, o, field(s, o, w, cursor, F_archive_sha256)) == 0:
            return 0
        nodes = integer_value(s, o, field(s, o, w, expected, F_node_count))
        if nodes == 0 or nodes > 65536:
            return 0
        if integer_field(s, o, w, cursor, F_node_count, nodes, nodes) == 0 or integer_field(s, o, w, cursor, F_nodes_retained, nodes, nodes) == 0 or integer_field(s, o, w, cursor, 3, 0, 0) == 0:
            return 0
        if true_field(s, o, w, cursor, F_cleanup_complete) == 0 or true_field(s, o, w, cursor, F_sealed) == 0:
            return 0
        if text_field(s, o, w, expected, F_kind, F_reference) != 0 and base != 0:
            return 0
        if text_field(s, o, w, expected, F_kind, F_base) != 0:
            if base != 0:
                return 0
            base = 1
        if text_field(s, o, w, expected, F_kind, F_qualification) != 0 and base == 0:
            return 0
        count = count + 1
        cursor = following(o, cursor)
    return choose(count == PHASE_COUNT and base == 1, 1, 0)

def phase_entry(s:readbuf, o:mutbuf, w:mutbuf, node:u64, catalog:u64) -> u64:
    if node == 0 or kind(o, node) != 2:
        return 0
    i = 0
    cursor = catalog + 1
    while i < PHASE_COUNT and cursor < following(o, catalog):
        expected = field(s, o, w, cursor, F_id)
        if expected != 0 and kind(o, expected) == 2 and string_compare(s, token_start(o, node), token_start(o, expected)) == 0:
            put(w, 1152000, i)
            return cursor
        i = i + 1
        cursor = following(o, cursor)
    return 0

def equal_field(s:readbuf, o:mutbuf, w:mutbuf, first:u64, second:u64, name:u64) -> u64:
    a = field(s, o, w, first, name)
    b = field(s, o, w, second, name)
    if a == 0 or b == 0 or kind(o, a) != 2 or kind(o, b) != 2:
        return 0
    return choose(string_compare(s, token_start(o, a), token_start(o, b)) == 0, 1, 0)

def unique_object(s:readbuf, o:mutbuf, root:u64) -> u64:
    if root == 0 or kind(o, root) != 3:
        return 0
    cursor = root + 1
    count = 0
    while cursor < following(o, root):
        other = following(o, cursor + 1)
        while other < following(o, root):
            if string_compare(s, token_start(o, cursor), token_start(o, other)) == 0:
                return 0
            other = following(o, other + 1)
        count = count + 1
        cursor = following(o, cursor + 1)
    return count

def true_field(s:readbuf, o:mutbuf, w:mutbuf, root:u64, name:u64) -> u64:
    node = field(s, o, w, root, name)
    return choose(node != 0 and kind(o, node) == 6, 1, 0)

def integer_field(s:readbuf, o:mutbuf, w:mutbuf, root:u64, name:u64, minimum:u64, maximum:u64) -> u64:
    node = field(s, o, w, root, name)
    value = integer_value(s, o, node)
    return choose(value >= minimum and value <= maximum, 1, 0)

def integer_value(s:readbuf, o:mutbuf, node:u64) -> u64:
    if node == 0 or kind(o, node) != 5:
        return 18446744073709551615
    at = token_start(o, node)
    end = token_end(o, node)
    if at >= end or end - at > 20:
        return 18446744073709551615
    value = 0
    while at < end:
        c = byte(s, at)
        if c < 48 or c > 57 or value > 1844674407370955161 or (value == 1844674407370955161 and c > 53):
            return 18446744073709551615
        value = value * 10 + c - 48
        at = at + 1
    return value

def hexadecimal(s:readbuf, o:mutbuf, w:mutbuf, node:u64, at:u64, count:u64) -> u64:
    if node == 0 or kind(o, node) != 2:
        return 0
    source = token_start(o, node) + 1
    i = 0
    while i < count * 2:
        unit = decoded(s, source)
        source = unit >> 32
        cp = unit & 4294967295
        value = byte(w, at + (i >> 1))
        expected = choose((i & 1) == 0, hex_digit(value >> 4), hex_digit(value & 15))
        if cp != expected:
            return 0
        i = i + 1
    unit = decoded(s, source)
    return choose((unit & 4294967295) == 1114112, 1, 0)

def valid_pin(s:readbuf, o:mutbuf, node:u64) -> u64:
    if node == 0 or kind(o, node) != 2:
        return 0
    source = token_start(o, node) + 1
    i = 0
    nonzero = 0
    while i < 64:
        unit = decoded(s, source)
        source = unit >> 32
        cp = unit & 4294967295
        if (cp < 48 or cp > 57) and (cp < 97 or cp > 102):
            return 0
        if cp != 48:
            nonzero = 1
        i = i + 1
    unit = decoded(s, source)
    return choose(nonzero == 1 and (unit & 4294967295) == 1114112, 1, 0)
'''


def validate_catalog(catalog):
    if not isinstance(catalog,list) or not 40<=len(catalog)<=128:
        raise ValueError('complete cold phase catalog required')
    seen=set();paired=set();bases=0;references=0
    for row in catalog:
        if set(row)!={'id','kind','family','label','plan_sha256','node_count'}:
            raise ValueError('unexpected catalog fields')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,126}',row['id']) or row['id'] in seen:
            raise ValueError('phase identity is invalid or repeated')
        seen.add(row['id'])
        if not re.fullmatch(r'[0-9a-f]{64}',row['plan_sha256']) or set(row['plan_sha256'])=={'0'} or type(row['node_count']) is not int or not 1<=row['node_count']<=65536:
            raise ValueError('phase plan identity is invalid')
        if row['kind']=='qualification':
            key=row['family'],row['label']
            if key in paired or key[0] not in FAMILIES or key[1] not in ('original','modified'):
                raise ValueError('qualification pair is invalid or repeated')
            paired.add(key)
        elif row['kind'] in ('base','reference') and row['family']==row['label']=='':
            bases+=row['kind']=='base';references+=row['kind']=='reference'
        else:raise ValueError('phase kind is invalid')
    if bases!=1 or references==0 or paired!={(f,l) for f in FAMILIES for l in ('original','modified')}:
        raise ValueError('whole cold reference/base/qualification inventory differs')
    return copy.deepcopy(catalog)


def metadata(root,catalog):
    catalog=validate_catalog(catalog)
    contract=legacy.support_contract(root)
    contract['native_cold_qualification']={'schema':'hepta.hia.selfhost-cold-replay.v2',
        'runtime':'native HIA with explicit mechanical syscall and ELF ABI capsules',
        'phase_plan_catalog':catalog,'checks':CHECKS,
        'qualification_wall_limit_seconds':180,'cleanup_wall_limit_seconds':3,
        'scheduler':{'phase_workers':2,'archive_workers':1,'max_pending_archives':2,'max_unsealed_phases':4},
        'all_input_correctness_proved':False}
    return contract


def render(root,catalog):
    contract=metadata(root,catalog);catalog=contract['native_cold_qualification']['phase_plan_catalog']
    strings=['schema','profile','status','returncode','checks','generation_sha256','source_manifest',
        'source_identity','files',legacy.CONTRACT_PATH,'hepta.hia.selfhost-cold-replay.v2',
        contract['profile'],'NATIVE_COLD_SELFHOST_REPLAY_PASS',*CHECKS,*FIELDS]
    indices={name:i for i,name in enumerate(strings)}
    source=legacy.SOURCE
    nodes={n.name:ast.get_source_segment(source,n) for n in ast.parse(source).body}
    checks='''def checks(s:readbuf, o:mutbuf, w:mutbuf, root:u64) -> u64:
    if unique_object(s, o, root) != 14:
        return 0
    i = 13
    while i < 27:
        if true_field(s, o, w, root, i) == 0:
            return 0
        i = i + 1
    return 1'''
    source=source.replace(nodes['checks'],checks)
    source=source.replace('    put(w, 160, root)\n','    if unique_object(s, o, root) == 0:\n        return 0\n    put(w, 160, root)\n',1)
    admitted=nodes['admit']
    admitted=admitted.rsplit('    return 1',1)
    replacement=admitted[0]+'    return native_report(s, o, w, get(w, 160), root)'+admitted[1]
    replacement=replacement.replace('    put(w, 160, root)\n','    if unique_object(s, o, root) == 0:\n        return 0\n    put(w, 160, root)\n',1)
    current=nodes['admit'].replace('    put(w, 160, root)\n','    if unique_object(s, o, root) == 0:\n        return 0\n    put(w, 160, root)\n',1)
    source=source.replace(current,replacement,1)
    source=source.replace('        put(w, 196608 + index * 24 + 16, cursor + 1)',
        '        if get(w, 196608 + index * 24 + 16) != 0:\n            return 0\n        put(w, 196608 + index * 24 + 16, cursor + 1)',1)
    source=source.replace('1008192','1160000').replace('1008224','1160032')
    from tools.generate_hia_native_observer import reference_image
    observer=reference_image()
    extra=EXTRA.replace('PHASE_COUNT',str(len(catalog))).replace('OBSERVER_BYTES',str(len(observer)))
    for name,index in sorted(indices.items(),key=lambda item:-len(item[0])):
        if name:extra=re.sub(r'\bF_'+re.escape(name)+r'\b',str(index),extra)
    if 'F_' in extra:raise ValueError('unresolved native report field')
    constants='\ndef native_constants(w:mutbuf) -> u64:\n'
    def words(at,raw):
        nonlocal constants
        for offset in range(0,len(raw),8):
            part=raw[offset:offset+8]
            if len(part)==8:constants+=f'    put(w, {at+offset}, {int.from_bytes(part,"little")})\n'
            else:
                for j,c in enumerate(part):constants+=f'    store(w, {at+offset+j}, {c})\n'
    words(1170000,observer);constants+='    return 0\n'
    source+='\n'+extra+'\n'+constants
    tree=ast.parse(inspect.getsource(legacy.render))
    class Specialize(ast.NodeTransformer):
        def visit_Assign(self,node):
            if any(isinstance(t,ast.Name) and t.id=='strings' for t in node.targets):
                node.value=ast.Name(id='NATIVE_STRINGS',ctx=ast.Load())
                return node
            return self.generic_visit(node)
        def visit_Constant(self,node):
            if node.value==1008192:return ast.copy_location(ast.Constant(1160000),node)
            if node.value==1008224:return ast.copy_location(ast.Constant(1160032),node)
            if isinstance(node.value,str):
                return ast.copy_location(ast.Constant(node.value.replace('1008192','1160000').replace('1008224','1160032')),node)
            return node
    scope={**vars(legacy),'SOURCE':source,'NATIVE_STRINGS':strings,'support_contract':lambda _:copy.deepcopy(contract)}
    exec(compile(ast.fix_missing_locations(Specialize().visit(tree)),__file__,'exec'),scope)
    text,record=scope['render'](root)
    record.update(schema='hepta.hia.native_cold_report_admit.v2',phase_count=len(catalog),qualification_families=len(FAMILIES),native_checks=len(CHECKS))
    return text,record,contract


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog',type=Path,required=True)
    parser.add_argument('--contract-root',type=Path,default=ROOT)
    parser.add_argument('--output',type=Path,default=ROOT/'examples/hia_bootstrap/cold_report_admit.hepta')
    args=parser.parse_args()
    text,record,contract=render(args.contract_root.resolve(),json.loads(args.catalog.read_text()))
    args.output.write_text(text)
    print(json.dumps(record,sort_keys=True))

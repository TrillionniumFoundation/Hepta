"""Bind retained Evaluate dependencies and issue the next immutable input reads."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as artifact_authority
from tools.generate_hia_worker_build_custody import METADATA, POLICY as BUILD
from tools.generate_hia_worker_adopt_proof import reachable_policy
from tools.generate_hia_worker_evaluate_case import FIELDS as CASE_FIELDS, source_program as case_source
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_proof_scope import split_key_table

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_input_binding.hepta')
FIELDS = (*METADATA, 'sha256','catalog_sha256','baseline_core_sha256','workload','objective','budget',
          'max_total_wall_ms','max_native_wall_ms','max_memory_bytes','native_artifact','candidate_artifact',
          'verification_receipts','schema','candidate_core_sha256','native_build','artifact_sha256',
          'target_profile','base_program','base_core_sha256')

POLICY = r'''
# [actual installed identity, admitted arguments, Context, baseline and candidate
# native metadata, retained build, one retained receipt per requested reference].
# The returned references select further physical reads. The response neither
# authorizes a native effect nor stands in for the omitted proof observations.
def bind_evaluate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 8388608 or length(w) < 65536 or length(o) < 1100:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    fields = get(w, 96)
    if fields == 2:
        return check_workload(s,o,w)
    if fields == 3:
        return context_window(s,o,w)
    if fields < 7 or fields > 22:
        return INVALID
    install = 64 + 72 * get(w, 88)
    args = next(w, install)
    ctx = next(w, args)
    base = next(w, ctx)
    candidate = next(w, base)
    build = next(w, candidate)
    scope = lookup(w, args, K_context)
    if get(w, install) != 6 or get(w, args) != 6 or scope == NONE or get(w, scope) != 6:
        return INVALID
    if get(w, ctx) != 6 or context_schema(w, lookup(w, ctx, K_schema)) == False:
        return INVALID
    catalog = lookup(w, args, K_catalog_sha256)
    if field_matches(s, w, ctx, K_installation, install) == False or field_matches(s, w, ctx, K_catalog_sha256, catalog) == False or field_matches(s, w, install, K_catalog_sha256, catalog) == False:
        return INVALID
    if native_metadata(s, w, base, install, scope) == False or native_metadata(s, w, candidate, install, scope) == False:
        return INVALID
    exports = lookup(w, ctx, K_foreign_buffer_exports)
    if field_matches(s, w, base, K_foreign_buffer_exports, exports) == False or field_matches(s, w, candidate, K_foreign_buffer_exports, exports) == False:
        return INVALID
    expected = lookup(w, ctx, K_baseline_core_sha256)
    if expected == NONE:
        return INVALID
    if get(w, build) != 6 or build_schema(w, lookup(w, build, K_schema)) == False or matches_metadata(s, w, build, candidate) == False:
        return INVALID
    art = lookup(w, args, K_candidate_artifact)
    if field_matches(s, w, build, K_native_artifact, art) == False or field_matches(s, w, build, K_target_profile, lookup(w, ctx, K_target_profile)) == False:
        return INVALID
    built = lookup(w, build, K_native_build)
    if built == NONE or get(w, built) != 6 or field_matches(s, w, built, K_artifact_sha256, lookup(w, art, K_sha256)) == False:
        return INVALID
    if field_matches(s, w, built, K_core_sha256, lookup(w, candidate, K_core_sha256)) == False or field_matches(s, w, built, K_object_sha256, lookup(w, build, K_object_sha256)) == False:
        return INVALID
    if shared_kind(w,lookup(w,base,K_output_kind)) == False or shared_kind(w,lookup(w,candidate,K_output_kind)) == False:
        return business_status(o,24)
    if field_matches(s,w,base,K_signatures,lookup(w,candidate,K_signatures)) == False:
        return business_status(o,25)
    if get(w,expected) != 0 and field_matches(s,w,base,K_core_sha256,expected) == False:
        return business_status(o,1)
    receipts = lookup(w, args, K_verification_receipts)
    if receipts == NONE or get(w, receipts) != 5 or get(w, receipts + 32) != fields - 6:
        return INVALID
    receipt = next(w, build)
    index = 6
    while index < fields:
        if get(w, receipt) != 6 or field_matches(s, w, receipt, K_context, scope) == False or field_matches(s, w, receipt, K_installation, install) == False:
            return INVALID
        if field_matches(s, w, receipt, K_candidate, lookup(w, candidate, K_candidate)) == False or field_matches(s, w, receipt, K_candidate_core_sha256, lookup(w, candidate, K_core_sha256)) == False:
            return INVALID
        receipt = next(w, receipt)
        index = index + 1
    return runtime_inputs(s, o, w, ctx, base, candidate, build)

def context_window(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    installed = first(w,64)
    args = next(w,installed)
    ctx = next(w,args)
    if get(w,installed) != 6 or get(w,args) != 6 or get(w,ctx) != 6 or next(w,ctx) != NONE:
        return INVALID
    if context_schema(w,lookup(w,ctx,K_schema)) == False:
        return INVALID
    retained = lookup(w,ctx,K_installation)
    catalog = lookup(w,args,K_catalog_sha256)
    recorded_catalog = lookup(w,ctx,K_catalog_sha256)
    if retained == NONE or get(w,retained) != 6 or digest_text(w,recorded_catalog,False) == False:
        return INVALID
    if digest_text(w,catalog,False) == False or field_matches(s,w,installed,K_catalog_sha256,catalog) == False:
        return INVALID
    if field_matches(s,w,ctx,K_installation,installed) == False or field_matches(s,w,ctx,K_catalog_sha256,catalog) == False:
        return business_status(o,23)
    budget = lookup(w,ctx,K_budget)
    if budget == NONE or get(w,budget) != 6:
        return INVALID
    total = budget_integer(s,w,lookup(w,budget,K_max_total_wall_ms),1,86400000)
    if total == NONE:
        return INVALID
    put(o,0,CONTEXT_WINDOW)
    put(o,8,total)
    return 16

def business_status(o:mutbuf, reason:u64) -> u64:
    put(o,0,BUSINESS)
    put(o,8,reason)
    return 16

def check_workload(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    meta = 64+72*get(w,88)
    workload = next(w,meta)
    if get(w,meta) != 6 or workload == NONE or get(w,workload) != 6 or next(w,workload) != NONE:
        return INVALID
    sig = lookup(w,meta,K_signatures)
    cases = lookup(w,workload,K_cases)
    if sig == NONE or get(w,sig) != 6 or cases == NONE or get(w,cases) != 5 or length(o) < 6224:
        return INVALID
    count = get(w,cases+32)
    if count == 0 or count > 512:
        return INVALID
    case = first(w,cases)
    used = 0
    i = 0
    while i < count:
        if case == NONE or get(w,case) != 6:
            return INVALID
        width = plan_named_case(s,o,w,sig,case)
        if width == INVALID:
            return INVALID
        if width == 16:
            kind = get(o,8)
            if kind == 0 or kind > 10:
                return INVALID
            return business_status(o,choose(kind==2,2,10+kind))
        if width < 80 or width > 6224:
            return INVALID
        used = used+get(o,32)
        if used > 33554432:
            return business_status(o,19)
        case = next(w,case)
        i = i+1
    if case != NONE:
        return INVALID
    return business_status(o,0)

def native_metadata(s:readbuf, w:mutbuf, record:u64, install:u64, scope:u64) -> bool:
    if get(w, record) != 6 or field_matches(s, w, record, K_installation, install) == False or field_matches(s, w, record, K_context, scope) == False:
        return False
    kind = lookup(w,record,K_output_kind)
    if (shared_kind(w,kind) == False and object_kind(w,kind) == False) or digest_text(w, lookup(w, record, K_core_sha256), False) == False:
        return False
    signatures = lookup(w, record, K_signatures)
    return exact_reference(s, w, lookup(w, record, K_candidate)) and signatures != NONE and get(w, signatures) == 6

def runtime_inputs(s:readbuf, o:mutbuf, w:mutbuf, ctx:u64, base:u64, candidate:u64, build:u64) -> u64:
    budget = lookup(w, ctx, K_budget)
    if budget == NONE or get(w, budget) != 6:
        return INVALID
    total = budget_integer(s, w, lookup(w, budget, K_max_total_wall_ms), 1, 86400000)
    native = budget_integer(s, w, lookup(w, budget, K_max_native_wall_ms), 1, 3600000)
    memory = memory_limit(w, lookup(w, budget, K_max_memory_bytes))
    if total == NONE or native == NONE or memory < 67108864 or memory > 4294967296:
        return INVALID
    put(o, 0, RESULT)
    put(o, 8, total)
    put(o, 16, native)
    put(o, 24, memory)
    if binding_ref(s, w, o, base, K_candidate, 32) == False or binding_ref(s, w, o, candidate, K_candidate, 208) == False:
        return INVALID
    if binding_ref(s, w, o, build, K_object_artifact, 384) == False or binding_ref(s, w, o, ctx, K_objective, 560) == False or binding_ref(s, w, o, ctx, K_workload, 736) == False:
        return INVALID
    base_sha = lookup(w, base, K_core_sha256)
    candidate_sha = lookup(w, candidate, K_core_sha256)
    i = 0
    while i < 64:
        store(o, 912 + i, byte(w, get(w, base_sha + 24) + i))
        store(o, 976 + i, byte(w, get(w, candidate_sha + 24) + i))
        i = i + 1
    return 1040

def binding_ref(s:readbuf, w:mutbuf, o:mutbuf, obj:u64, field:u64, at:u64) -> bool:
    ref = lookup(w, obj, field)
    if exact_reference(s, w, ref) == False:
        return False
    copy_reference(s, o, get(w, ref + 56), at)
    return True

def memory_limit(w:mutbuf, node:u64) -> u64:
    if node == NONE or get(w, node) != 4:
        return NONE
    span = get(w, node + 32)
    if span == 0 or span > 10:
        return NONE
    where = get(w, node + 24)
    if span > 1 and byte(w, where) == 48:
        return NONE
    i = 0
    value = 0
    while i < span:
        c = byte(w, where + i)
        if c < 48 or c > 57:
            return NONE
        value = value * 10 + c - 48
        i = i + 1
    return value
'''


def program():
    fields = tuple(dict.fromkeys((*FIELDS,*CASE_FIELDS)))
    names = {f'K_{name}': i for i,name in enumerate(fields,1)}
    names.update(INVALID=4294967293, NONE=(1 << 64)-1, META_COUNT=len(METADATA),
                 RESULT=int.from_bytes(b'HIAEFB02','little'), BUSINESS=int.from_bytes(b'HIAEQB01','little'),
                 CONTEXT_WINDOW=int.from_bytes(b'HIAEWD01','little'))
    art = artifact_authority()
    controls = (POLICY,
                *(function(BUILD, name) for name in ('exact_reference','field_matches','matches_metadata','copy_reference')),
                *(function(CONTEXT, name) for name in ('equal_span','digest_text','budget_integer')),
                *(function(art, name) for name in ('artifact_reference','artifact_start','artifact_digest','artifact_uri','valid_hex','matches')),
                WIRE_HELPERS.split('\ndef signed_id',1)[0], split_key_table(fields[:16],fields[16:]),
                literal_match('context_schema','hepta.hia.agent.context.v1'),literal_match('shared_kind','shared'),literal_match('object_kind','object'),
                literal_match('build_schema','hepta.hia.agent.build.v1'))
    # The same case planner used at the public execution boundary supplies
    # the first typed case refusal. Its field numbers are private to its own
    # JSON dictionary; translate them to the combined binding dictionary.
    entry, case = reachable_policy(case_source(), 'plan_named_case')
    omit = {'lookup','match_word','key_id','get','put'}
    retained = [entry, *(t for t in case if t.lstrip().split('(',1)[0][4:] not in omit)]
    remap = lambda m: f"lookup(w, {m[1]}, K_{CASE_FIELDS[int(m[2])-1]})"
    planner = re.sub(r'lookup\(w, ([a-z_]+), ([0-9]+)\)',remap,'\n'.join(retained))
    body = '\n'.join((*controls,planner))
    return re.sub(r'\b('+'|'.join(names)+r')\b',lambda match:str(names[match[0]]),body)+'\n'+json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')

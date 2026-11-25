"""Original public dictionary construction order, independent of digest bytes.

This private action is embedded in the existing rank report role. It consumes
fresh native decoder arenas, copies them, and changes only sibling order in
the returned JSON. Original observations use the captured arguments' order.
"""
import ast,struct
from tools.generate_hia_ndu_rank_admission import source_program as admission_source

ORDERS={
1:("schema before_sha256 before_input_sha256 function generation objective objective_sha256 observations_sha256 selected_id admitted reason selected_program net_margin_ns costs candidate_reports selected_fresh_proof selected_proof_admission native_rank_admission native_request request_sha256 native_response bridge selection_resolution claims cost_model").split(),
2:("id action core_verified observation equivalence_proved proof preproof_cost_lower_bound_ns proof_remaining_budget_ns proof_remaining_margin_ns proof_timeout_ms proof_wall_ns reason detail").split(),
3:("supplied_search_ns actual_adapter_ns total_search_ns search_at_native_rank_ns publication_preparation_included").split(),
4:("schema objective_sha256 generation resource_cap_q32 candidates").split(),
5:("id cost_q32 uncertainty_q32 resource_q32 hard_violation support_sha256").split(),
6:("candidate_id spent_search_ns remaining_budget_ns remaining_margin_ns solver_started timeout_ms wall_ns").split(),
7:("invoked remaining_budget_ns timeout_s reason").split(),
8:("schema profile status function scope before_sha256 after_sha256 before_input_sha256 after_input_sha256 validator_sha256 structural_verification reason counterexample solver claims limits validation_error error_type wall_ns proof_scope_schema proved_meaning subject property assumptions unproved_obligations checker execution_authority").split(),
9:("schema profile request_sha256 native_response_sha256 native_disposition native_recommendation validated_pareto_frontier selected_id selection_source caller_tie_policy caller_tie_policy_applied scope assumptions native_identity_validated_here authority proves_program_safety forecast_is_observed_benefit incremental_ndu_advantage_established").split(),
10:("upstream_commit binary_sha256 build_receipt_sha256 build_inputs_sha256 source_attestation").split(),
11:("ndu_is_advisory unproved_candidate_admitted all_other_functions_unchanged resource_bounds_proved measurements_independently_attested native_backend_refinement_proved global_optimality_established incremental_advantage_established").split(),
13:("before after").split(),
14:("name version result timeout_ms identity discharge query_preprocessing reason_unknown error").split(),
15:("all_input_behavior_equivalence_proved first_trap_code_preserved canonical_core_reverified resource_bounds_proved encoder_refinement_machine_proved whole_language_soundness_proved backend_refinement_proved global_optimality_proved serialized_receipt_authorizes_execution").split(),
16:("id statement").split(),
17:("arguments parameter_types before after").split(),
18:("kind function selection before_sha256 after_sha256 before_input_sha256 after_input_sha256 call_closures call_closure").split(),
19:("name kind method source_identity source_identity_sha256 source_identity_error runtime solver machine_checked_implementation").split(),
20:("code message").split(),
21:("name version binding_sha256 library_path library_sha256").split(),
22:("method image_sha256 formula_sha256 variables clauses steps assignments_checked").split(),
23:("strategy parameter_index type value input_assumptions partition_count").split(),
24:("implementation version").split(),
25:("status values code").split(),
}
CHILDREN={
1:{"costs":3,"candidate_reports":100,"selected_fresh_proof":8,"selected_proof_admission":6,"native_rank_admission":7,"native_request":4,"bridge":10,"selection_resolution":9,"claims":11},
2:{"observation":12,"proof":8},
4:{"candidates":101},
8:{"structural_verification":13,"solver":14,"claims":15,"counterexample":17,"subject":18,"property":16,"assumptions":102,"unproved_obligations":102,"checker":19,"validation_error":20},
14:{"identity":21,"discharge":22,"query_preprocessing":23},
17:{"before":25,"after":25},
19:{"runtime":24,"solver":21},
}
KEYS=sorted(set(["id","observations"]+[k for values in ORDERS.values() for k in values]+[k for d in CHILDREN.values() for k in d]))
IDS={key:i+1 for i,key in enumerate(KEYS)}
SOURCE=r'''
def return_order(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<832 or length(o)<64 or length(w)<131072:
        return 4294967293
    if readword(s,0)!=3534426521539324232 or readword(s,8)!=11 or readword(s,16)>1 or readword(s,24)!=4:
        return 4294967293
    at=32
    while at<768:
        if readword(s,at)!=0:
            return 4294967293
        at=at+8
    at=832
    i=0
    while i<4:
        n=readword(s,776+i*16)
        if readword(s,768+i*16)!=at or n>length(s)-at:
            return 4294967293
        at=at+n
        i=i+1
    if at!=length(s):
        return 4294967293
    raw=readword(s,768)
    rn=readword(s,776)
    arena=readword(s,784)
    an=readword(s,792)
    argsraw=readword(s,800)
    argsn=readword(s,808)
    args=readword(s,816)
    argsan=readword(s,824)
    if rn==0 or argsn==0 or an<64 or argsan<64:
        return 4294967293
    if arena_valid(s,w,arena,an,rn)==False or arena_valid(s,w,args,argsan,argsn)==False:
        return 4294967293
    count=readword(s,arena+8)
    if nodeword(s,arena,0,0)!=6 or nodeword(s,args,0,0)!=6:
        return 4294967293
    if an>length(w)-16384 or count>(length(w)-16384-an)//16:
        return 4294967293
    zero(w,0,4096)
    put(w,24,raw)
    put(w,32,rn)
    put(w,40,16384)
    put(w,48,16384+an)
    put(w,56,count)
    put(w,64,args)
    put(w,72,argsraw)
    put(w,80,argsn)
    put(w,88,order_source_field(s,args,0,OBSERVATIONS_KEY))
    i=0
    while i<an:
        store(w,16384+i,byte(s,arena+i))
        i=i+1
    zero(w,16384+an,count*16)
    order_table(w)
    if order_contexts(s,w)==False:
        return 4294967293
    i=0
    while i<count:
        if order_node(w,i,0)==6 and get(w,get(w,48)+i*16)!=0:
            order_object(s,w,i)
        i=i+1
    order_render(s,o,w)
    if get(w,16)!=0:
        return 4294967293
    required=get(w,0)
    if readword(s,16)==1:
        if required>length(o)-64:
            return 4294967294
        put(w,0,0)
        put(w,8,1)
        order_render(s,o,w)
        if get(w,0)!=required or get(w,16)!=0:
            return 4294967293
    zero(o,0,64)
    put(o,0,3534414426914310472)
    put(o,8,required)
    put(o,16,11)
    return 0

def order_node(w:mutbuf,index:u64,slot:u64) -> u64:
    return get(w,get(w,40)+64+index*72+slot)

def order_next(w:mutbuf,index:u64,next:u64) -> u64:
    put(w,get(w,40)+64+index*72+16,next)
    return 0

def order_field(w:mutbuf,parent:u64,key:u64) -> u64:
    if order_node(w,parent,0)!=6:
        return 18446744073709551615
    child=order_node(w,parent,24)
    while child!=18446744073709551615:
        if order_label(w,get(w,40)+order_node(w,child,40),order_node(w,child,48))==key:
            return child
        child=order_node(w,child,16)
    return 18446744073709551615

def order_source_field(s:readbuf,a:u64,parent:u64,key:u64) -> u64:
    if nodeword(s,a,parent,0)!=6:
        return 18446744073709551615
    child=nodeword(s,a,parent,24)
    while child!=18446744073709551615:
        if order_source_label(s,a+nodeword(s,a,child,40),nodeword(s,a,child,48))==key:
            return child
        child=nodeword(s,a,child,16)
    return 18446744073709551615

def order_equal(s:readbuf,at:u64,n:u64,w:mutbuf,wa:u64,wn:u64) -> bool:
    if n!=wn:
        return False
    i=0
    while i<n:
        if byte(s,at+i)!=byte(w,wa+i):
            return False
        i=i+1
    return True

def order_observation(s:readbuf,w:mutbuf,candidate:u64) -> u64:
    id=order_field(w,candidate,ID_KEY)
    if id==18446744073709551615 or order_node(w,id,0)!=4:
        return 18446744073709551615
    a=get(w,64)
    observations=get(w,88)
    if observations==18446744073709551615 or nodeword(s,a,observations,0)!=6:
        return 18446744073709551615
    child=nodeword(s,a,observations,24)
    while child!=18446744073709551615:
        if order_equal(s,a+nodeword(s,a,child,40),nodeword(s,a,child,48),w,get(w,40)+order_node(w,id,24),order_node(w,id,32)):
            if nodeword(s,a,child,0)==6:
                return child
            return 18446744073709551615
        child=nodeword(s,a,child,16)
    return 18446744073709551615

def order_contexts(s:readbuf,w:mutbuf) -> bool:
    contexts=get(w,48)
    put(w,contexts,1)
    put(w,contexts+8,18446744073709551615)
    i=1
    while i<get(w,56):
        parent=order_node(w,i,8)
        pc=get(w,contexts+parent*16)
        label=0
        if pc!=0 and order_node(w,parent,0)==6:
            label=order_label(w,get(w,40)+order_node(w,i,40),order_node(w,i,48))
        kind=order_child(pc,label)
        aux=18446744073709551615
        if kind==2:
            aux=order_observation(s,w,i)
            if aux==18446744073709551615:
                return False
        elif kind==12:
            aux=get(w,contexts+parent*16+8)
        put(w,contexts+i*16,kind)
        put(w,contexts+i*16+8,aux)
        i=i+1
    return True

def order_priority(s:readbuf,w:mutbuf,parent:u64,child:u64) -> u64:
    base=get(w,48)+parent*16
    kind=get(w,base)
    keyat=get(w,40)+order_node(w,child,40)
    keyn=order_node(w,child,48)
    if kind==12:
        a=get(w,64)
        original=get(w,base+8)
        if original==18446744073709551615:
            put(w,16,1)
            return 65535
        node=nodeword(s,a,original,24)
        index=1
        while node!=18446744073709551615:
            if order_equal(s,a+nodeword(s,a,node,40),nodeword(s,a,node,48),w,keyat,keyn):
                return index
            index=index+1
            node=nodeword(s,a,node,16)
        put(w,16,1)
        return 65535
    return order_fixed_priority(kind,order_label(w,keyat,keyn))

def order_object(s:readbuf,w:mutbuf,parent:u64) -> u64:
    child=order_node(w,parent,24)
    first=18446744073709551615
    last=18446744073709551615
    last_rank=0
    while child!=18446744073709551615:
        following=order_node(w,child,16)
        priority=order_priority(s,w,parent,child)
        order_next(w,child,18446744073709551615)
        if first==18446744073709551615:
            first=child
            last=child
            last_rank=priority
        elif priority>=last_rank:
            order_next(w,last,child)
            last=child
            last_rank=priority
        else:
            previous=18446744073709551615
            current=first
            while current!=18446744073709551615 and order_priority(s,w,parent,current)<=priority:
                previous=current
                current=order_node(w,current,16)
            order_next(w,child,current)
            if previous==18446744073709551615:
                first=child
            else:
                order_next(w,previous,child)
        child=following
    put(w,get(w,40)+64+parent*72+24,first)
    return 0

def order_raw(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        emit(o,w,byte(s,at+i))
        i=i+1
    return 0

def order_key(o:mutbuf,w:mutbuf,node:u64) -> u64:
    emit(o,w,34)
    at=get(w,40)+order_node(w,node,40)
    n=order_node(w,node,48)
    i=0
    while i<n:
        quote_byte(o,w,byte(w,at+i))
        i=i+1
    emit(o,w,34)
    emit(o,w,58)
    return 0

def order_render(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    node=0
    while True:
        parent=order_node(w,node,8)
        if node!=0 and order_node(w,parent,0)==6:
            order_key(o,w,node)
        kind=order_node(w,node,0)
        complete=True
        if kind==5 or kind==6:
            emit(o,w,choose(kind==5,91,123))
            child=order_node(w,node,24)
            if child!=18446744073709551615:
                node=child
                complete=False
            else:
                emit(o,w,choose(kind==5,93,125))
        else:
            slot=24
            if kind==4:
                slot=56
            order_raw(s,o,w,get(w,24)+order_node(w,node,slot),order_node(w,node,slot+8))
        if complete:
            climbing=True
            while climbing:
                if node==0:
                    return 0
                following=order_node(w,node,16)
                if following!=18446744073709551615:
                    emit(o,w,44)
                    node=following
                    climbing=False
                else:
                    node=order_node(w,node,8)
                    emit(o,w,choose(order_node(w,node,0)==5,93,125))
    return 0

def order_read(w:mutbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value
'''
def source_program():
    text=SOURCE.replace('OBSERVATIONS_KEY',str(IDS['observations'])).replace('ID_KEY',str(IDS['id']))
    text=text.replace('3534426521539324232',str(int.from_bytes(b'HIANRP01','little'))).replace('3534414426914310472',str(int.from_bytes(b'HIANPR01','little')))
    text+='\ndef order_child(parent:u64,key:u64) -> u64:\n'
    for p,c in ((100,2),(101,5),(102,16)):
        text+=f'    if parent=={p}:\n        return {c}\n'
    for parent,mapping in CHILDREN.items():
        text+=f'    if parent=={parent}:\n'
        for key,kind in mapping.items():text+=f'        if key=={IDS[key]}:\n            return {kind}\n'
        text+='        return 0\n'
    text+='    return 0\n'
    text+='\ndef order_fixed_priority(kind:u64,key:u64) -> u64:\n'
    for group,upper in enumerate((7,14,21,25)):
        text+=f'    if kind<={upper}:\n        return order_fixed_priority_{group}(kind,key)\n'
    text+='    return 65535\n'
    for group,(low,high)in enumerate(((1,7),(8,14),(15,21),(22,25))):
        text+=f'\ndef order_fixed_priority_{group}(kind:u64,key:u64) -> u64:\n'
        for kind,keys in ORDERS.items():
            if not low<=kind<=high:continue
            text+=f'    if kind=={kind}:\n'
            for i,key in enumerate(keys):text+=f'        if key=={IDS[key]}:\n            return {i+1}\n'
            text+='        return 65535\n'
        text+='    return 65535\n'
    table=bytearray(1024+8*len(KEYS))
    for key,ident in IDS.items():
        raw=key.encode();h=14695981039346656037
        for ch in raw:h=((h^ch)*1099511628211)&((1<<64)-1)
        slot=h&511
        while int.from_bytes(table[slot*2:slot*2+2],'little'):slot=(slot+1)&511
        struct.pack_into('<H',table,slot*2,ident)
        struct.pack_into('<Q',table,1024+(ident-1)*8,(len(raw)<<32)|(512+len(table)))
        table.extend(raw)
    table.extend(bytes((-len(table))%8))
    assert 512+len(table)<16384
    text+='\ndef order_table(w:mutbuf) -> u64:\n'
    for i in range(0,len(table),1024):text+=f'    order_table_{i//1024}(w)\n'
    text+='    return 0\n'
    for i in range(0,len(table),1024):
        text+=f'\ndef order_table_{i//1024}(w:mutbuf) -> u64:\n'
        for j in range(i,min(i+1024,len(table)),8):text+=f'    put(w,{512+j},{int.from_bytes(table[j:j+8],"little")})\n'
        text+='    return 0\n'
    text+=r'''
def order_label(w:mutbuf,at:u64,n:u64) -> u64:
    h=14695981039346656037
    i=0
    while i<n:
        h=(h^byte(w,at+i))*1099511628211
        i=i+1
    slot=h&511
    count=0
    while count<512:
        id=order_read(w,512+slot*2,2)
        if id==0:
            return 0
        entry=get(w,1536+(id-1)*8)
        size=entry>>32
        start=entry&4294967295
        if size==n:
            i=0
            equal=True
            while i<n:
                if byte(w,start+i)!=byte(w,at+i):
                    equal=False
                i=i+1
            if equal:
                return id
        count=count+1
        slot=(slot+1)&511
    return 0
'''
    raw=b'observations'
    parts=[f'n=={len(raw)}']+[f'readn(s,at+{i},{len(raw[i:i+8])})=={int.from_bytes(raw[i:i+8],"little")}'for i in range(0,len(raw),8)]
    text+='\ndef order_source_label(s:readbuf,at:u64,n:u64) -> u64:\n    if '+' and '.join(parts)+f':\n        return {IDS["observations"]}\n    return 0\n'
    wanted={'arena_valid','nodeword','read64','readn'}
    text+='\n'+'\n'.join(ast.unparse(n)for n in ast.parse(admission_source()).body if n.name in wanted)+'\n'
    return text

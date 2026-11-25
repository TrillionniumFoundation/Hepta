"""Fixed scalar caller selection after an independently admitted HIA evaluator."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_native_public_proof_receipt import POLICY
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIANSQ01','little'),'REPLY':int.from_bytes(b'HIANSR01','little'),'BAD':4294967293,'SHORT':4294967294,'NONE':(1<<64)-1,'MAX':(1<<63)-1,'ROWS':4096,'ORDER':24576,'JSON':65536,'SEEN':4194304}
LABELS={1:'schema',2:'objective_sha256',3:'generation',4:'resource_cap_q32',5:'candidates',6:'id',7:'cost_q32',8:'uncertainty_q32',9:'resource_q32',10:'hard_violation',11:'support_sha256',12:'request_sha256',13:'advisory_recommendation',14:'pareto_frontier',15:'rejected',16:'reasons',17:'disposition',101:'hepta.hia.ndu-request.v1',102:'abstain',103:'InfeasibleExplicitAbstain',104:'UniqueParetoRecommendation',105:'ParetoSetRequiresSlowPath'}
ERRORS={1:'closed scalar request required',2:'unsupported request schema',3:'invalid objective digest',4:'invalid generation',5:'invalid resource cap',6:'candidate bound',7:'closed scalar row required',8:'invalid or duplicate candidate ID',9:'invalid scalar row values',10:'invalid support digest',11:'a feasible native incumbent is required',12:'native response must be an object',13:'response/request binding',14:'missing native recommendation field',15:'invalid native recommendation',16:'native frontier differs from the fixed scalar profile',17:'invalid native rejected rows',18:'invalid native rejected row',19:'native feasibility partition differs',20:'native explicit-abstain disposition differs',21:'native unique recommendation differs',22:'native ambiguous-frontier disposition differs'}
LITERALS={
1:'{"assumptions":["caller already admitted the unchanged native bridge source and executable","request uses hia-total-cost-ms-v1 with zero Pareto tolerance and no scalarization"],"authority":"ADVISORY_ONLY","caller_tie_policy":"incumbent-if-on-frontier-else-lexicographic-id.v1","caller_tie_policy_applied":',
2:',"forecast_is_observed_benefit":false,"incremental_ndu_advantage_established":false,"native_disposition":',
3:',"native_identity_validated_here":false,"native_recommendation":',
4:',"native_response_sha256":',
5:',"profile":"hia-total-cost-ms-v1","proves_program_safety":false,"request_sha256":',
6:',"schema":"hepta.hia.ndu-scalar-selection.v1","scope":"fixed scalar supplied-cost profile and caller tie policy only","selected_id":',
7:',"selection_source":',
8:',"validated_pareto_frontier":[',
9:']}',
10:'"native_explicit_abstain"',11:'"native_unique_pareto"',12:'"caller_pareto_tie_policy"',
13:'"InfeasibleExplicitAbstain"',14:'"UniqueParetoRecommendation"',15:'"ParetoSetRequiresSlowPath"',
16:'null',17:'true',18:'false',19:'{"type":"ScalarSelectionRejected","message":"E_HIA_NDU_SELECTION: ',20:'"}'}
SOURCE=r'''
def rank_selection(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<8388608 or read64(s,0)!=REQUEST:
        return BAD
    i=40
    while i<64:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    at=128
    i=0
    while i<2:
        jn=read64(s,8+i*16)
        an=read64(s,16+i*16)
        if jn==0 or jn>1048576 or an==0 or an>83886080 or jn>length(s)-at:
            return BAD
        put(w,i*16,at)
        at=at+jn
        put(w,i*16+8,at)
        if an>length(s)-at or arena_valid(s,w,at,an,jn)==False:
            return BAD
        at=at+an
        i=i+1
    if at!=length(s):
        return BAD
    put(w,256,0)
    put(w,264,0)
    put(w,272,0)
    error=validate_request(s,w)
    if error==0:
        error=validate_response(s,w)
    put(w,512,0)
    if error!=0:
        literal(w,19)
        error_literal(w,error)
        literal(w,20)
    else:
        selection_json(s,w)
    n=get(w,512)
    if n>32768 or n>length(o) or length(o)-n<64:
        return SHORT
    zero(o,64)
    put(o,0,REPLY)
    put(o,8,choose(error!=0,1,0))
    put(o,16,n)
    put(o,24,choose(error!=0,NONE,get(w,280)))
    put(o,32,choose(error!=0,0,get(w,256)))
    put(o,40,choose(error!=0,0,get(w,264)))
    put(o,48,choose(error!=0,0,get(w,272)))
    i=0
    while i<n:
        store(o,64+i,byte(w,JSON+i))
        i=i+1
    return 64+n

def validate_request(s:readbuf,w:mutbuf) -> u64:
    a=get(w,8)
    if nodeword(s,a,0,0)!=6 or nodeword(s,a,0,32)!=5:
        return 1
    key=1
    while key<=5:
        if field(s,a,0,key)==NONE:
            return 1
        key=key+1
    if string_id(s,a,field(s,a,0,1))!=101:
        return 2
    objective=field(s,a,0,2)
    if digest(s,a,objective)==False:
        return 3
    generation=integer(s,get(w,0),a,field(s,a,0,3),NONE)
    if get(w,520)==0 or generation==0:
        return 4
    put(w,288,generation)
    cap=integer(s,get(w,0),a,field(s,a,0,4),MAX)
    if get(w,520)==0:
        return 5
    put(w,296,cap)
    candidates=field(s,a,0,5)
    count=nodeword(s,a,candidates,32)
    if nodeword(s,a,candidates,0)!=5 or count==0 or count>128:
        return 6
    put(w,304,count)
    node=nodeword(s,a,candidates,24)
    index=0
    while index<count:
        code=admit_row(s,w,a,node,index)
        if code!=0:
            return code
        node=nodeword(s,a,node,16)
        index=index+1
    index=0
    feasible=0
    minimum=NONE
    incumbent=NONE
    while index<count:
        row=ROWS+index*128
        good=get(w,row+48)==0 and get(w,row+40)<=cap
        put(w,row+64,choose(good,1,0))
        if good:
            feasible=feasible+1
            if get(w,row+24)<minimum:
                minimum=get(w,row+24)
            if string_id(s,a,get(w,row))==102:
                incumbent=index
        put(w,ORDER+index*8,index)
        index=index+1
    if incumbent==NONE:
        return 11
    put(w,312,incumbent)
    put(w,256,feasible)
    index=0
    while index<count:
        j=index+1
        while j<count:
            left=get(w,ORDER+index*8)
            right=get(w,ORDER+j*8)
            if less_id(s,w,right,left):
                put(w,ORDER+index*8,right)
                put(w,ORDER+j*8,left)
            j=j+1
        index=index+1
    frontier=0
    index=0
    first=NONE
    while index<count:
        rowindex=get(w,ORDER+index*8)
        row=ROWS+rowindex*128
        yes=get(w,row+64)==1 and get(w,row+24)==minimum
        put(w,row+72,choose(yes,1,0))
        if yes:
            if first==NONE:
                first=rowindex
            frontier=frontier+1
        index=index+1
    put(w,264,frontier)
    put(w,320,first)
    return 0

def admit_row(s:readbuf,w:mutbuf,a:u64,node:u64,index:u64) -> u64:
    if nodeword(s,a,node,0)!=6 or nodeword(s,a,node,32)!=6:
        return 7
    key=6
    while key<=11:
        if field(s,a,node,key)==NONE:
            return 7
        key=key+1
    id=field(s,a,node,6)
    if valid_id(s,a,id)==False:
        return 8
    row=ROWS+index*128
    put(w,row,id)
    put(w,row+8,a+nodeword(s,a,id,24))
    put(w,row+16,nodeword(s,a,id,32))
    old=0
    while old<index:
        if same(s,get(w,ROWS+old*128+8),get(w,ROWS+old*128+16),get(w,row+8),get(w,row+16)):
            return 8
        old=old+1
    key=7
    while key<=9:
        value=integer(s,get(w,0),a,field(s,a,node,key),MAX)
        if get(w,520)==0:
            return 9
        put(w,row+24+(key-7)*8,value)
        key=key+1
    hard=nodeword(s,a,field(s,a,node,10),0)
    if hard!=1 and hard!=2:
        return 9
    put(w,row+48,choose(hard==2,1,0))
    if digest(s,a,field(s,a,node,11))==False:
        return 10
    return 0

def validate_response(s:readbuf,w:mutbuf) -> u64:
    a=get(w,24)
    q=get(w,8)
    if nodeword(s,a,0,0)!=6:
        return 12
    generation=integer(s,get(w,16),a,field(s,a,0,3),NONE)
    if get(w,520)==0 or generation!=get(w,288):
        return 13
    if digest_binding(s,a,field(s,a,0,12),64)==False or same_node(s,a,field(s,a,0,2),q,field(s,q,0,2))==False:
        return 13
    recommendation=field(s,a,0,13)
    if recommendation==NONE:
        return 14
    if nodeword(s,a,recommendation,0)!=0 and valid_id(s,a,recommendation)==False:
        return 15
    frontier=field(s,a,0,14)
    if nodeword(s,a,frontier,0)!=5 or nodeword(s,a,frontier,32)!=get(w,264):
        return 16
    node=nodeword(s,a,frontier,24)
    index=0
    while index<get(w,304):
        rowindex=get(w,ORDER+index*8)
        if get(w,ROWS+rowindex*128+72)==1:
            if same_node(s,a,node,q,get(w,ROWS+rowindex*128))==False:
                return 16
            node=nodeword(s,a,node,16)
        index=index+1
    rejected=field(s,a,0,15)
    count=nodeword(s,a,rejected,32)
    if nodeword(s,a,rejected,0)!=5 or count>128:
        return 17
    node=nodeword(s,a,rejected,24)
    i=0
    while i<count:
        if nodeword(s,a,node,0)!=6 or nodeword(s,a,node,32)!=2:
            return 18
        id=field(s,a,node,6)
        reasons=field(s,a,node,16)
        if valid_id(s,a,id)==False or nodeword(s,a,reasons,0)!=4 or nodeword(s,a,reasons,32)==0:
            return 18
        node=nodeword(s,a,node,16)
        i=i+1
    if count!=get(w,304)-get(w,256):
        return 19
    node=nodeword(s,a,rejected,24)
    index=0
    while index<get(w,304):
        rowindex=get(w,ORDER+index*8)
        if get(w,ROWS+rowindex*128+64)==0:
            if same_node(s,a,field(s,a,node,6),q,get(w,ROWS+rowindex*128))==False:
                return 19
            node=nodeword(s,a,node,16)
        index=index+1
    disposition=string_id(s,a,field(s,a,0,17))
    selected=get(w,320)
    source=2
    if get(w,256)==1:
        if disposition!=103 or string_id(s,a,recommendation)!=102:
            return 20
        selected=get(w,312)
        source=1
    elif get(w,264)==1:
        if disposition!=104 or same_node(s,a,recommendation,q,get(w,ROWS+selected*128))==False:
            return 21
    else:
        if disposition!=105 or nodeword(s,a,recommendation,0)!=0:
            return 22
        source=3
        if get(w,ROWS+get(w,312)*128+72)==1:
            selected=get(w,312)
    put(w,272,source)
    put(w,280,selected)
    return 0

def selection_json(s:readbuf,w:mutbuf) -> u64:
    source=get(w,272)
    literal(w,1)
    literal(w,choose(source==3,17,18))
    literal(w,2)
    literal(w,12+source)
    literal(w,3)
    if source==3:
        literal(w,16)
    else:
        emit_id(s,w,get(w,280))
    literal(w,4)
    emit_digest(s,w,96)
    literal(w,5)
    emit_digest(s,w,64)
    literal(w,6)
    emit_id(s,w,get(w,280))
    literal(w,7)
    literal(w,9+source)
    literal(w,8)
    index=0
    added=0
    while index<get(w,304):
        selected=get(w,ORDER+index*8)
        if get(w,ROWS+selected*128+72)==1:
            if added!=0:
                emit(w,44)
            emit_id(s,w,selected)
            added=added+1
        index=index+1
    literal(w,9)
    return 0

def emit_id(s:readbuf,w:mutbuf,index:u64) -> u64:
    emit(w,34)
    at=get(w,ROWS+index*128+8)
    n=get(w,ROWS+index*128+16)
    i=0
    while i<n:
        emit(w,byte(s,at+i))
        i=i+1
    emit(w,34)
    return 0

def emit_digest(s:readbuf,w:mutbuf,at:u64) -> u64:
    emit(w,34)
    i=0
    while i<32:
        value=byte(s,at+i)
        high=value>>4
        low=value&15
        emit(w,high+choose(high<10,48,87))
        emit(w,low+choose(low<10,48,87))
        i=i+1
    emit(w,34)
    return 0

def emit(w:mutbuf,value:u64) -> u64:
    position=get(w,512)
    if position<32768:
        store(w,JSON+position,value)
    put(w,512,position+1)
    return 0

def less_id(s:readbuf,w:mutbuf,a:u64,b:u64) -> bool:
    at=get(w,ROWS+a*128+8)
    bt=get(w,ROWS+b*128+8)
    an=get(w,ROWS+a*128+16)
    bn=get(w,ROWS+b*128+16)
    i=0
    while i<an and i<bn:
        x=byte(s,at+i)
        y=byte(s,bt+i)
        if x!=y:
            return x<y
        i=i+1
    return an<bn

def valid_id(s:readbuf,a:u64,node:u64) -> bool:
    if nodeword(s,a,node,0)!=4:
        return False
    at=a+nodeword(s,a,node,24)
    n=nodeword(s,a,node,32)
    if n==0 or n>64:
        return False
    i=0
    while i<n:
        c=byte(s,at+i)
        alpha=(c>=65 and c<=90) or (c>=97 and c<=122)
        if alpha==False:
            if i==0 or ((c>=48 and c<=57) or c==95 or c==46 or c==58 or c==45)==False:
                return False
        i=i+1
    return True

def digest(s:readbuf,a:u64,node:u64) -> bool:
    if nodeword(s,a,node,0)!=4 or nodeword(s,a,node,32)!=64:
        return False
    at=a+nodeword(s,a,node,24)
    i=0
    while i<64:
        c=byte(s,at+i)
        if ((c>=48 and c<=57) or (c>=97 and c<=102))==False:
            return False
        i=i+1
    return True

def digest_binding(s:readbuf,a:u64,node:u64,at:u64) -> bool:
    if digest(s,a,node)==False:
        return False
    start=a+nodeword(s,a,node,24)
    i=0
    while i<32:
        b=byte(s,at+i)
        h=b>>4
        l=b&15
        if byte(s,start+i*2)!=h+choose(h<10,48,87) or byte(s,start+i*2+1)!=l+choose(l<10,48,87):
            return False
        i=i+1
    return True

def integer(s:readbuf,j:u64,a:u64,node:u64,maximum:u64) -> u64:
    put_dummy=0
    return integer_value(s,j,a,node,maximum)

def integer_value(s:readbuf,j:u64,a:u64,node:u64,maximum:u64) -> u64:
    return 0

def same_node(s:readbuf,a:u64,x:u64,b:u64,y:u64) -> bool:
    return nodeword(s,a,x,0)==4 and nodeword(s,b,y,0)==4 and same(s,a+nodeword(s,a,x,24),nodeword(s,a,x,32),b+nodeword(s,b,y,24),nodeword(s,b,y,32))

def same(s:readbuf,a:u64,an:u64,b:u64,bn:u64) -> bool:
    if an!=bn:
        return False
    i=0
    while i<an:
        if byte(s,a+i)!=byte(s,b+i):
            return False
        i=i+1
    return True

def field(s:readbuf,a:u64,node:u64,key:u64) -> u64:
    if nodeword(s,a,node,0)!=6:
        return NONE
    child=nodeword(s,a,node,24)
    while child!=NONE:
        if label(s,a+nodeword(s,a,child,40),nodeword(s,a,child,48))==key:
            return child
        child=nodeword(s,a,child,16)
    return NONE

def string_id(s:readbuf,a:u64,node:u64) -> u64:
    if nodeword(s,a,node,0)!=4:
        return 0
    return label(s,a+nodeword(s,a,node,24),nodeword(s,a,node,32))

def nodeword(s:readbuf,a:u64,node:u64,slot:u64) -> u64:
    if node==NONE or node>=read64(s,a+8):
        return NONE
    return read64(s,a+64+node*72+slot)

def read64(s:readbuf,at:u64) -> u64:
    return readn(s,at,8)

def readn(s:readbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def zero(w:mutbuf,n:u64) -> u64:
    i=0
    while i<n:
        store(w,i,0)
        i=i+1
    return 0

def choose(test:bool,a:u64,b:u64) -> u64:
    if test:
        return a
    return b
'''
# Numeric classification is private scratch, never a trusted caller type tag.
INTEGER=r'''
def integer(s:readbuf,w:mutbuf,j:u64,a:u64,node:u64,maximum:u64) -> u64:
    put(w,520,0)
    if nodeword(s,a,node,0)!=3:
        return 0
    at=j+nodeword(s,a,node,24)
    n=nodeword(s,a,node,32)
    i=0
    negative=False
    if n!=0 and byte(s,at)==45:
        negative=True
        i=1
    value=0
    if i==n:
        return 0
    while i<n:
        c=byte(s,at+i)
        if c<48 or c>57:
            return 0
        digit=c-48
        if value>maximum//10 or (value==maximum//10 and digit>maximum%10):
            return 0
        value=value*10+digit
        i=i+1
    if negative and value!=0:
        return 0
    put(w,520,1)
    return value
'''
def literal_function(name,rows):
    lines=['def '+name+'(w:mutbuf,id:u64) -> u64:']
    for ident,text in rows.items():
        lines.append('    if id=='+str(ident)+':')
        for value in text.encode():lines.append('        emit(w,'+str(value)+')')
        lines.append('        return 0')
    lines.append('    return 0')
    return '\n'.join(lines)+'\n'
def source_program():
    text=SOURCE
    start=text.index('\ndef integer(');end=text.index('\ndef same_node(',start)
    text=text[:start]+'\n'+INTEGER+text[end:]
    text=text.replace('integer(s,get(w,','integer(s,w,get(w,')
    arena='def arena_valid('+POLICY.split('def arena_valid(',1)[1].split('\ndef nodeword(',1)[0]
    arena=arena.replace('count>131073','count>1048577')
    text+='\n'+arena
    lines=['def label(s:readbuf,at:u64,n:u64) -> u64:']
    for ident,label in LABELS.items():
        raw=label.encode();parts=[f'n=={len(raw)}']+[f'readn(s,at+{i},{len(raw[i:i+8])})=={int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8)]
        lines+=['    if '+' and '.join(parts)+':',f'        return {ident}']
    lines.append('    return 0');text+='\n'+'\n'.join(lines)+'\n'
    text+=literal_function('literal',LITERALS)+literal_function('error_literal',ERRORS)
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'ndu_rank_selection')
if __name__=='__main__':
    target=ROOT/'examples/hia_bootstrap/ndu_rank_selection.hepta';target.write_text(render_assembly(program()));print(target.name,target.stat().st_size,flush=True)

"""Resumable watched-literal CDCL with explicit 32-bit clause and trail indices."""
SOLVER=r'''def literal_value(w:mutbuf,literal:u64) -> u64:
    value=byte(w,ASSIGN_BASE+(literal>>1)-1)
    if value == 0:
        return 0
    return choose(value == 2-(literal&1),2,1)

def enqueue(w:mutbuf,literal:u64,reason:u64) -> u64:
    variable=literal>>1
    if literal < 2 or variable > bget(w,0):
        stop(w,4,6)
        return 0
    previous=literal_value(w,literal)
    if previous != 0:
        return choose(previous == 2,1,0)
    count=get(w,488)
    if count >= VAR_CAP:
        stop(w,0,2)
        return 0
    store(w,ASSIGN_BASE+variable-1,2-(literal&1))
    put32(w,LEVEL_BASE+4*(variable-1),get(w,504))
    put32(w,REASON_BASE+4*(variable-1),reason)
    put32(w,TRAIL_BASE+4*count,literal)
    put(w,488,count+1)
    return 1

def link_watch(w:mutbuf,clause:u64,side:u64,position:u64) -> u64:
    row=CLAUSE_BASE+32*clause
    token=get32(w,CNF_BASE+4*(get32(w,row)+position))
    at=HEAD_BASE+4*token
    put32(w,row+8+4*side,position)
    put32(w,row+16+4*side,get32(w,at))
    put32(w,at,1+2*clause+side)
    return 0

def solver_step(w:mutbuf) -> u64:
    state=get(w,440)
    if state == 0:
        return solver_clear_heads(w)
    if state == 1:
        return solver_clear_variables(w)
    if state == 2:
        return solver_seed(w)
    if state == 3:
        if get(w,496) < get(w,488):
            token=get32(w,TRAIL_BASE+4*get(w,496))^1
            put(w,528,token)
            put(w,536,HEAD_BASE+4*token)
            put(w,440,4)
        else:
            put(w,440,6)
        return 0
    if state == 4:
        return solver_watch(w)
    if state == 5:
        return solver_replacement(w)
    if state == 6:
        return solver_decide(w)
    if state == 7:
        return solver_analyze_clause(w)
    if state == 8:
        return solver_analyze_trail(w)
    if state == 9:
        return solver_analyze_finish(w)
    if state == 10:
        return solver_backtrack(w)
    if state == 11:
        return solver_learn_copy(w)
    if state == 12:
        return solver_learn_publish(w)
    return stop(w,4,5)

def solver_clear_heads(w:mutbuf) -> u64:
    index=get(w,472)
    total=8*(bget(w,0)+1)
    if index < total:
        amount=choose(total-index < 65536,total-index,65536)
        fill_range(w,HEAD_BASE+index,amount,0)
        put(w,472,index+amount)
    else:
        put(w,800,0)
        put(w,472,0)
        put(w,440,1)
    return 0

def solver_clear_variables(w:mutbuf) -> u64:
    region=get(w,800)
    index=get(w,472)
    size=bget(w,0)
    base=ASSIGN_BASE
    if region == 1:
        size=size*4
        base=LEVEL_BASE
    elif region == 2:
        size=size*4
        base=REASON_BASE
    elif region == 3:
        base=SEEN_BASE
    if index < size:
        amount=choose(size-index < 65536,size-index,65536)
        fill_range(w,base+index,amount,0)
        put(w,472,index+amount)
        return 0
    if region < 3:
        put(w,800,region+1)
        put(w,472,0)
        return 0
    put(w,488,0)
    put(w,496,0)
    put(w,504,0)
    put(w,512,1)
    put(w,472,0)
    put(w,440,2)
    return 0

def solver_seed(w:mutbuf) -> u64:
    clause=get(w,472)
    if clause == bget(w,8):
        put(w,440,3)
        return 0
    row=CLAUSE_BASE+32*clause
    amount=get32(w,row+4)
    if amount == 0:
        return stop(w,2,0)
    if amount == 1:
        token=get32(w,CNF_BASE+4*get32(w,row))
        if enqueue(w,token,clause+1) == 0:
            if get(w,16) == 3:
                stop(w,2,0)
            return 0
    else:
        link_watch(w,clause,0,0)
        link_watch(w,clause,1,1)
    put(w,472,clause+1)
    return 0

def solver_watch(w:mutbuf) -> u64:
    code=get32(w,get(w,536))
    if code == 0:
        put(w,496,get(w,496)+1)
        put(w,440,3)
        return 0
    clause=(code-1)>>1
    side=(code-1)&1
    if clause >= bget(w,8):
        return stop(w,4,6)
    row=CLAUSE_BASE+32*clause
    position=get32(w,row+8+4*side)
    other=get32(w,row+8+4*(side^1))
    amount=get32(w,row+4)
    if position >= amount or other >= amount or position == other:
        return stop(w,4,6)
    start=get32(w,row)
    if get32(w,CNF_BASE+4*(start+position)) != get(w,528):
        return stop(w,4,6)
    token=get32(w,CNF_BASE+4*(start+other))
    if literal_value(w,token) == 2:
        put(w,536,row+16+4*side)
        return 0
    put(w,544,side)
    put(w,552,clause)
    put(w,560,token)
    put(w,568,0)
    put(w,576,other)
    put(w,440,5)
    return 0

def solver_replacement(w:mutbuf) -> u64:
    clause=get(w,552)
    side=get(w,544)
    row=CLAUSE_BASE+32*clause
    index=get(w,568)
    amount=get32(w,row+4)
    if index < amount:
        put(w,568,index+1)
        if index == get(w,576):
            return 0
        token=get32(w,CNF_BASE+4*(get32(w,row)+index))
        if literal_value(w,token) == 1:
            return 0
        old_next=get32(w,row+16+4*side)
        put32(w,get(w,536),old_next)
        put32(w,row+8+4*side,index)
        put32(w,row+16+4*side,get32(w,HEAD_BASE+4*token))
        put32(w,HEAD_BASE+4*token,1+2*clause+side)
        put(w,440,4)
        return 0
    token=get(w,560)
    if literal_value(w,token) == 1:
        return solver_conflict(w,clause)
    if enqueue(w,token,clause+1) == 0:
        if get(w,16) == 3:
            return solver_conflict(w,clause)
        return 0
    put(w,536,row+16+4*side)
    put(w,440,4)
    return 0

def solver_decide(w:mutbuf) -> u64:
    variable=get(w,512)
    if variable > bget(w,0):
        put(w,24,6)
        put(w,800,0)
        put(w,680,0)
        put(w,688,0)
        put(w,696,0)
        return 0
    put(w,512,variable+1)
    if byte(w,ASSIGN_BASE+variable-1) != 0:
        return 0
    level=get(w,504)
    if level >= VAR_CAP:
        return stop(w,0,2)
    put32(w,LIMIT_BASE+4*level,get(w,488))
    put(w,504,level+1)
    if enqueue(w,(variable<<1)|1,0) == 0:
        return stop(w,4,6)
    put(w,440,3)
    return 0

def solver_conflict(w:mutbuf,clause:u64) -> u64:
    if get(w,504) == 0:
        return stop(w,2,0)
    put(w,608,clause)
    put(w,616,0)
    put(w,624,0)
    put(w,632,0)
    put(w,640,get(w,488))
    put(w,648,1)
    put(w,440,7)
    return 0

def solver_analyze_clause(w:mutbuf) -> u64:
    clause=get(w,608)
    row=CLAUSE_BASE+32*clause
    index=get(w,616)
    if index == get32(w,row+4):
        put(w,440,8)
        return 0
    token=get32(w,CNF_BASE+4*(get32(w,row)+index))
    variable=token>>1
    put(w,616,index+1)
    if variable == get(w,624):
        return 0
    level=get32(w,LEVEL_BASE+4*(variable-1))
    if level == 0 or byte(w,SEEN_BASE+variable-1) != 0:
        return 0
    store(w,SEEN_BASE+variable-1,1)
    if level == get(w,504):
        put(w,632,get(w,632)+1)
    else:
        count=get(w,648)
        if count >= VAR_CAP:
            return stop(w,0,2)
        put32(w,LEARN_BASE+4*count,token)
        put(w,648,count+1)
    return 0

def solver_analyze_trail(w:mutbuf) -> u64:
    index=get(w,640)
    if index == 0:
        return stop(w,4,6)
    index=index-1
    put(w,640,index)
    token=get32(w,TRAIL_BASE+4*index)
    variable=token>>1
    if byte(w,SEEN_BASE+variable-1) == 0:
        return 0
    store(w,SEEN_BASE+variable-1,0)
    count=get(w,632)
    if count == 0:
        return stop(w,4,6)
    put(w,632,count-1)
    if count == 1:
        put32(w,LEARN_BASE,token^1)
        put(w,656,0)
        put(w,664,1)
        put(w,672,1)
        put(w,440,9)
        return 0
    reason=get32(w,REASON_BASE+4*(variable-1))
    if reason == 0 or reason > bget(w,8):
        return stop(w,4,6)
    put(w,608,reason-1)
    put(w,616,0)
    put(w,624,variable)
    put(w,440,7)
    return 0

def solver_analyze_finish(w:mutbuf) -> u64:
    index=get(w,672)
    count=get(w,648)
    if index < count:
        token=get32(w,LEARN_BASE+4*index)
        variable=token>>1
        level=get32(w,LEVEL_BASE+4*(variable-1))
        store(w,SEEN_BASE+variable-1,0)
        if level > get(w,656):
            put(w,656,level)
            put(w,664,index)
        put(w,672,index+1)
        return 0
    if count > 1:
        first=get32(w,LEARN_BASE+4)
        best=get(w,664)
        put32(w,LEARN_BASE+4,get32(w,LEARN_BASE+4*best))
        put32(w,LEARN_BASE+4*best,first)
    target=get(w,656)
    if target >= get(w,504):
        return stop(w,4,6)
    cut=get32(w,LIMIT_BASE+4*target)
    if cut > get(w,488):
        return stop(w,4,6)
    put(w,864,cut)
    put(w,440,10)
    return 0

def solver_backtrack(w:mutbuf) -> u64:
    count=get(w,488)
    cut=get(w,864)
    if count > cut:
        count=count-1
        token=get32(w,TRAIL_BASE+4*count)
        variable=token>>1
        store(w,ASSIGN_BASE+variable-1,0)
        put32(w,LEVEL_BASE+4*(variable-1),0)
        put32(w,REASON_BASE+4*(variable-1),0)
        put(w,512,choose(variable < get(w,512),variable,get(w,512)))
        put(w,488,count)
        return 0
    put(w,504,get(w,656))
    put(w,496,choose(get(w,496) < count,get(w,496),count))
    needed=get(w,648)
    if bget(w,8) >= CLAUSE_CAP or bget(w,16) > TOKEN_CAP-needed-1:
        return stop(w,0,2)
    put(w,672,0)
    put(w,440,11)
    return 0

def solver_learn_copy(w:mutbuf) -> u64:
    index=get(w,672)
    amount=get(w,648)
    entries=bget(w,16)
    if index < amount:
        put32(w,CNF_BASE+4*(entries+index),get32(w,LEARN_BASE+4*index))
        put(w,672,index+1)
        return 0
    put32(w,CNF_BASE+4*(entries+amount),0)
    clause=bget(w,8)
    row=CLAUSE_BASE+32*clause
    put32(w,row,entries)
    put32(w,row+4,amount)
    put(w,row+8,0)
    put(w,row+16,0)
    put(w,row+24,1)
    bput(w,8,clause+1)
    bput(w,16,entries+amount+1)
    put(w,440,12)
    return 0

def solver_learn_publish(w:mutbuf) -> u64:
    clause=bget(w,8)-1
    if get(w,648) > 1:
        link_watch(w,clause,0,0)
        link_watch(w,clause,1,1)
    token=get32(w,LEARN_BASE)
    if enqueue(w,token,clause+1) == 0:
        if get(w,16) == 3:
            return solver_conflict(w,clause)
        return 0
    put(w,440,3)
    return 0
'''

WITNESS=r'''def witness_step(w:mutbuf) -> u64:
    state=get(w,800)
    if state == 0:
        clause=get(w,680)
        if clause == bget(w,8):
            put(w,800,1)
            put(w,712,0)
            return 0
        row=CLAUSE_BASE+32*clause
        index=get(w,688)
        amount=get32(w,row+4)
        if index < amount:
            token=get32(w,CNF_BASE+4*(get32(w,row)+index))
            if token < 2 or token>>1 > bget(w,0):
                return stop(w,4,6)
            if literal_value(w,token) == 2:
                put(w,696,1)
            put(w,688,index+1)
        else:
            if get(w,696) == 0 or get32(w,CNF_BASE+4*(get32(w,row)+amount)) != 0:
                return stop(w,4,6)
            put(w,680,clause+1)
            put(w,688,0)
            put(w,696,0)
        return 0
    if state == 1:
        node=get(w,712)
        if node == pget(w,0):
            put(w,800,2)
            put(w,712,0)
            put(w,696,0)
            return 0
        value=0
        if node < get(w,88):
            width=node_width(w,node)
            bit=0
            while bit < width:
                token=load_token(w,32+128*node+2*bit)
                if literal_value(w,token) == 2:
                    value=value|(1<<bit)
                bit=bit+1
        elif byte(w,MARK_BASE+node) != 0:
            value=evaluate_general_word(w,node)
        put(w,PHI_BASE+8*node,value)
        put(w,712,node+1)
        put(w,760,1)
        return 0
    if state == 2:
        index=get(w,712)
        if index < get(w,384):
            a=get(w,PAIR_BASE+16*index)
            b=get(w,PAIR_BASE+16*index+8)
            if get(w,PHI_BASE+8*a) != get(w,PHI_BASE+8*b):
                put(w,696,1)
            put(w,712,index+1)
            return 0
        if get(w,696) == 0:
            return stop(w,4,6)
        return stop(w,1,0)
    return stop(w,4,5)
'''

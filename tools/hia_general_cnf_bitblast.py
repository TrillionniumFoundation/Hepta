"""Independent 32-bit CNF storage and bounded word bitblast transitions."""
import ast,copy
from tools.generate_hia_cnf import BODY

LOGIC=r'''def allocate_variable(w:mutbuf) -> u64:
    if get(w,16) != 3:
        return 0
    count=bget(w,0)
    if count >= VAR_CAP:
        stop(w,0,2)
        return 0
    bput(w,0,count+1)
    return (count+1)<<1

def gate_slot(w:mutbuf,operation:u64,a:u64,b:u64) -> u64:
    hash=(a*11400714819323198485)^(b*14029467366897019727)^(operation*1609587929392839161)
    slot=(hash^(hash>>31))&(GATE_SLOTS-1)
    first=slot
    count=0
    while count < 16:
        at=GATE_BASE+16*slot
        op=get32(w,at)
        if op == 0 or (op == operation and get32(w,at+4) == a and get32(w,at+8) == b):
            return at
        slot=(slot+1)&(GATE_SLOTS-1)
        count=count+1
    return GATE_BASE+16*first

def logic_and(w:mutbuf,a:u64,b:u64) -> u64:
    if a == 0 or b == 0:
        return 0
    if a == 3 or b == 3 or a == (b^1):
        return 3
    if a == 2 or a == b:
        return b
    if b == 2:
        return a
    left=choose(a<b,a,b)
    right=choose(a<b,b,a)
    slot=gate_slot(w,1,left,right)
    if get32(w,slot) == 1 and get32(w,slot+4) == left and get32(w,slot+8) == right:
        return get32(w,slot+12)
    token=allocate_variable(w)
    if token != 0:
        put32(w,slot,1)
        put32(w,slot+4,left)
        put32(w,slot+8,right)
        put32(w,slot+12,token)
        emit_clause(w,a^1,b^1,token)
        emit_clause(w,a,token^1,0)
        emit_clause(w,b,token^1,0)
    return token

def logic_or(w:mutbuf,a:u64,b:u64) -> u64:
    if a == 0 or b == 0:
        return 0
    token=logic_and(w,a^1,b^1)
    return choose(token == 0,0,token^1)

def logic_xor(w:mutbuf,a:u64,b:u64) -> u64:
    if a == 0 or b == 0:
        return 0
    if a == b:
        return 3
    if a == (b^1):
        return 2
    if a == 3:
        return b
    if b == 3:
        return a
    if a == 2:
        return b^1
    if b == 2:
        return a^1
    polarity=(a^b)&1
    av=a&4294967294
    bv=b&4294967294
    left=choose(av<bv,av,bv)
    right=choose(av<bv,bv,av)
    slot=gate_slot(w,2,left,right)
    if get32(w,slot) == 2 and get32(w,slot+4) == left and get32(w,slot+8) == right:
        return get32(w,slot+12)^polarity
    token=allocate_variable(w)
    if token == 0:
        return 0
    put32(w,slot,2)
    put32(w,slot+4,left)
    put32(w,slot+8,right)
    put32(w,slot+12,token)
    emit_clause(w,left,right,token^1)
    emit_clause(w,left^1,right^1,token^1)
    emit_clause(w,left,right^1,token)
    emit_clause(w,left^1,right,token)
    return token^polarity

def emit_clause(w:mutbuf,a:u64,b:u64,c:u64) -> u64:
    if get(w,16) != 3:
        return 0
    amount=1+choose(b != 0,1,0)+choose(c != 0,1,0)
    clauses=bget(w,8)
    entries=bget(w,16)
    if a < 2 or a>>1 > bget(w,0) or (b != 0 and (b < 2 or b>>1 > bget(w,0))) or (c != 0 and (b == 0 or c < 2 or c>>1 > bget(w,0))):
        return stop(w,4,6)
    if clauses >= CLAUSE_CAP or entries > TOKEN_CAP-amount-1:
        return stop(w,0,2)
    put32(w,CNF_BASE+4*entries,a)
    if b != 0:
        put32(w,CNF_BASE+4*(entries+1),b)
    if c != 0:
        put32(w,CNF_BASE+4*(entries+2),c)
    put32(w,CNF_BASE+4*(entries+amount),0)
    row=CLAUSE_BASE+32*clauses
    put32(w,row,entries)
    put32(w,row+4,amount)
    put(w,row+8,0)
    put(w,row+16,0)
    put(w,row+24,0)
    bput(w,8,clauses+1)
    bput(w,16,entries+amount+1)
    return 1
'''

DRIVER=r'''def mark_step(w:mutbuf) -> u64:
    state=get(w,392)
    index=get(w,400)
    nodes=pget(w,0)
    if state == 0:
        if index < nodes:
            row=32+40*index
            if valid_node(w,32,index,nget(w,row),nget(w,row+8),nget(w,row+16),nget(w,row+24),nget(w,row+32)) == 0:
                return stop(w,4,1)
            store(w,MARK_BASE+index,0)
            put(w,400,index+1)
        else:
            put(w,400,0)
            put(w,392,1)
        return 0
    if state == 1:
        if index < get(w,384):
            a=get(w,PAIR_BASE+16*index)
            b=get(w,PAIR_BASE+16*index+8)
            if a >= nodes or b >= nodes or node_width(w,a) != node_width(w,b):
                return stop(w,4,1)
            store(w,MARK_BASE+a,1)
            store(w,MARK_BASE+b,1)
            put(w,400,index+1)
        else:
            put(w,400,nodes)
            put(w,392,2)
        return 0
    if state == 2:
        if index != 0:
            index=index-1
            row=32+40*index
            if byte(w,MARK_BASE+index) != 0:
                amount=word_arguments(nget(w,row))
                i=0
                while i < amount:
                    node=nget(w,row+16+8*i)
                    if node >= index:
                        return stop(w,4,1)
                    store(w,MARK_BASE+node,1)
                    i=i+1
            put(w,400,index)
        else:
            put(w,400,0)
            put(w,392,3)
        return 0
    if state == 3:
        fill_range(w,GATE_BASE+index,65536,0)
        index=index+65536
        put(w,400,index)
        if index == 16777216:
            bput(w,0,1)
            bput(w,8,0)
            bput(w,16,0)
            emit_clause(w,2,0,0)
            put(w,408,0)
            put(w,416,0)
            put(w,424,3)
            put(w,24,4)
        return 0
    return stop(w,4,5)

def bitblast_step(w:mutbuf) -> u64:
    if get(w,1000) != 0:
        return formula_hash_step(w)
    node=get(w,408)
    if node < pget(w,0):
        if node < get(w,88) or byte(w,MARK_BASE+node) != 0:
            if encode_word(w,node) == 0:
                if get(w,16) == 3:
                    stop(w,0,2)
                return 0
        put(w,408,node+1)
        put(w,760,1)
        return 0
    index=get(w,416)
    if index < get(w,384):
        a=get(w,PAIR_BASE+16*index)
        b=get(w,PAIR_BASE+16*index+8)
        delta=unequal_bits(w,a,b,node_width(w,a))
        result=logic_or(w,get(w,424),delta)
        if result == 0:
            if get(w,16) == 3:
                stop(w,0,2)
            return 0
        put(w,424,result)
        put(w,416,index+1)
        put(w,760,1)
        return 0
    emit_clause(w,get(w,424),0,0)
    if get(w,16) == 3:
        formula_begin(w)
    return 0

def encode_word(w:mutbuf,node:u64) -> u64:
    origin=32+40*node
    operation=nget(w,origin)
    width=nget(w,origin+8)
    left=nget(w,origin+16)
    right=nget(w,origin+24)
    immediate=nget(w,origin+32)
    if operation == WORD_PRODUCT_EXCEEDS:
        return encode_product_limit(w,node,left,right,immediate,node_width(w,left))
    if operation == WORD_UNSIGNED_DIV or operation == WORD_UNSIGNED_REM:
        return encode_division(w,32+128*node,32+128*left,32+128*right,width,operation == WORD_UNSIGNED_DIV)
    if operation == WORD_SIGNED_DIV or operation == WORD_SIGNED_REM:
        return encode_signed_division(w,node,left,right,width,operation == WORD_SIGNED_DIV)
    if operation == WORD_VARIABLE_SHL or operation == WORD_VARIABLE_SHR or operation == WORD_ARITHMETIC_SHR:
        return encode_variable_shift(w,node,left,right,width,operation)
    if operation == 32:
        return encode_product(w,node,choose(left<right,left,right),choose(left<right,right,left),width)
    if operation >= 26:
        return encode_projection(w,node,operation,width,left,right,immediate)
    if operation == 7 or operation == 8:
        delta=unequal_bits(w,left,right,node_width(w,left))
        if delta == 0:
            return 0
        put_token(w,32+128*node,delta^(operation&1))
        return 1
    if operation == 9 or operation == 10:
        return encode_sum(w,node,left,right,width,operation)
    if operation >= 22:
        return encode_sum(w,node,left,right,node_width(w,left),operation)
    if operation >= 12 and operation <= 19:
        digit=ordered_comparison(w,operation,left,right)
        if digit == 0:
            return 0
        put_token(w,32+128*node,digit)
        return 1
    if operation >= 20:
        return encode_wrapping_cast(w,node,left,width,node_width(w,left),operation == 21)
    bit=0
    while bit < width:
        token=encode_bit(w,operation,left,right,immediate,bit)
        if token == 0:
            return 0
        put_token(w,32+128*node+2*bit,token)
        bit=bit+1
    return 1
'''

def lifted_bitblast():
    selected={'valid_node','word_graph_width','word_arguments','encode_projection','encode_bit','encode_wrapping_cast','ordered_comparison','logic_select','encode_sum','carry_after_digit','encode_variable_shift','shift_stage','encode_division','division_trial','division_restore','encode_signed_division','conditional_negation','encode_product','accumulate_product','encode_product_limit','unequal_bits'}
    fns={n.name:n for n in ast.parse(BODY).body if isinstance(n,ast.FunctionDef)}
    argnames={name:[(a.arg,a.annotation.id) for a in n.args.args] for name,n in fns.items()}
    class Lift(ast.NodeTransformer):
        def visit_FunctionDef(self,n):
            self.views={a.arg for a in n.args.args if a.annotation.id in ('readbuf','mutbuf')}
            args=[];placed=False
            for a in n.args.args:
                if a.arg in self.views:
                    if not placed:a.arg='w';a.annotation=ast.Name('mutbuf',ast.Load());args.append(a);placed=True
                else:args.append(a)
            n.args.args=args
            return self.generic_visit(n)
        def visit_Name(self,n):
            if n.id in self.views:return ast.copy_location(ast.Name('w',n.ctx),n)
            return n
        def visit_Call(self,n):
            original=n.func.id if isinstance(n.func,ast.Name) else ''
            names=argnames.get(original)
            n=self.generic_visit(n)
            if original=='read64':
                n.func.id='nget'
            elif names:
                kept=[];placed=False
                for (key,typ),value in zip(names,n.args):
                    if typ in ('readbuf','mutbuf'):
                        if not placed:kept.append(ast.Name('w',ast.Load()));placed=True
                    else:kept.append(value)
                n.args=kept
            return n
    out=[]
    for name in fns:
        if name in selected:
            out.append(ast.unparse(ast.fix_missing_locations(Lift().visit(copy.deepcopy(fns[name])))))
    return '\n\n'.join(out)+'\n'

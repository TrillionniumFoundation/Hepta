"""Wide, resumable projection. Original scalar operation semantics are lifted exactly."""
import ast,copy
from tools.generate_hia_cnf import BODY,PROJECTION

NODES=r'''def p_node(w:mutbuf,op:u64,width:u64,a:u64,b:u64,c:u64) -> u64:
    if get(w,16) != 3:
        return NIL
    index=pget(w,0)
    if (op == 9 or op == 10) and a < index and b < index:
        left=32+40*a
        right=32+40*b
        if nget(w,left+8) == width and nget(w,right+8) == width:
            if nget(w,left) == 2 and nget(w,right) == 2:
                av=nget(w,left+32)
                bv=nget(w,right+32)
                c=choose(op == 9,av+bv,av-bv)&word_mask(width)
                op=2
                a=0
                b=0
            else:
                reduced=p_cancel_wrapping(w,op,a,b)
                if reduced < index and nget(w,40+40*reduced) == width:
                    return reduced
    if op > 2:
        folded=p_fold(w,op,width,a,b,c,index)
        if folded < index:
            return folded
        if folded != NIL:
            return choose(folded == 4294967296,pget(w,40),pget(w,32))
    if op == 1:
        return p_append_node(w,op,width,a,b,c)
    if (op == 3 or op == 4 or op == 5 or op == 7 or op == 8 or op == 9 or op == 32) and b < a:
        swap=a
        a=b
        b=swap
    hash=(op*11400714819323198485)^(width*14029467366897019727)^(a*1609587929392839161)^(b*9650029242287828579)^(c*2870177450012600261)
    slot=(hash^(hash>>29))&(NODE_HASH_SLOTS-1)
    first=slot
    count=0
    while count < 16:
        prior=get(w,NODE_HASH+8*slot)
        if prior == 0:
            node=p_append_node(w,op,width,a,b,c)
            if node != NIL:
                put(w,NODE_HASH+8*slot,node+1)
            return node
        if prior <= index:
            row=32+40*(prior-1)
            if nget(w,row) == op and nget(w,row+8) == width and nget(w,row+16) == a and nget(w,row+24) == b and nget(w,row+32) == c:
                return prior-1
        slot=(slot+1)&(NODE_HASH_SLOTS-1)
        count=count+1
    node=p_append_node(w,op,width,a,b,c)
    if node != NIL:
        put(w,NODE_HASH+8*first,node+1)
    return node

def p_append_node(w:mutbuf,op:u64,width:u64,a:u64,b:u64,c:u64) -> u64:
    index=pget(w,0)
    if index >= NODE_CAP:
        stop(w,0,2)
        return NIL
    row=32+40*index
    nput(w,row,op)
    nput(w,row+8,width)
    nput(w,row+16,a)
    nput(w,row+24,b)
    nput(w,row+32,c)
    pput(w,0,index+1)
    return index

def p_var(w:mutbuf,index:u64) -> u64:
    if index >= pget(w,96):
        return 0
    return get(w,LOCAL_BASE+8*index)

def p_bind(w:mutbuf,typ:u64,node:u64) -> u64:
    index=pget(w,96)
    if index >= 1048576 or node == NIL:
        stop(w,0,2)
        return 0
    put(w,LOCAL_BASE+8*index,(typ<<32)|node)
    pput(w,96,index+1)
    return 1
'''

DRIVER=r'''def projection_step(w:mutbuf) -> u64:
    state=get(w,192)
    if state == 0:
        return projection_begin(w)
    if state == 1:
        cursor=get(w,200)
        fill_range(w,NODE_HASH+cursor,65536,0)
        cursor=cursor+65536
        put(w,200,cursor)
        if cursor == 8388608:
            put(w,192,2)
            put(w,240,0)
        return 0
    if state == 2:
        return projection_types(w)
    if state == 3:
        return projection_function(w)
    if state == 4:
        return projection_inventory(w)
    if state == 5:
        return projection_entry(w)
    if state == 6:
        index=get(w,240)
        if index < get(w,96):
            typ=graph(w,32+8*(get(w,88)+index))
            pput(w,128+8*index,p_node(w,2,p_width(typ),0,0,0))
            put(w,240,index+1)
        else:
            put(w,232,0)
            put(w,192,7)
        return 0
    if state == 7:
        return projection_block(w)
    if state == 8:
        return projection_parameter(w)
    if state == 9:
        index=get(w,240)
        if index < get(w,288):
            row=get(w,272)+64+8*get(w,280)+48*index
            if p_operation(w,row,get(w,288)-index) != 1:
                if get(w,16) == 3:
                    stop(w,4,1)
                return 0
            put(w,240,index+1)
        else:
            put(w,192,10)
        return 0
    if state == 10:
        return projection_terminal(w)
    if state == 11:
        return projection_return(w)
    if state == 12:
        return projection_edge_begin(w)
    if state == 13:
        return projection_edge_argument(w)
    if state == 14:
        return projection_function_end(w)
    return stop(w,4,5)

def projection_begin(w:mutbuf) -> u64:
    mode=graph(w,8)
    inputs=graph(w,16)
    outputs=graph(w,24)
    if graph(w,0) != GRAPH_MAGIC or (mode != 1 and mode != 2 and mode != 4) or inputs > 32 or outputs > 16:
        return stop(w,4,1)
    if get(w,64) < 32+8*(inputs+outputs):
        return stop(w,4,1)
    if mode == 4 and (outputs != 1 or graph(w,32+8*inputs) != 1):
        return stop(w,4,1)
    put(w,80,mode)
    put(w,88,inputs)
    put(w,96,outputs)
    put(w,112,0)
    pput(w,0,0)
    pput(w,8,mode)
    pput(w,16,inputs)
    pput(w,24,outputs)
    pput(w,72,32)
    pput(w,120,get(w,64))
    put(w,200,0)
    put(w,192,1)
    return 0

def projection_types(w:mutbuf) -> u64:
    index=get(w,240)
    inputs=get(w,88)
    if index < inputs+get(w,96):
        typ=graph(w,32+8*index)
        width=p_width(typ)
        if width == 0:
            return stop(w,4,1)
        if index < inputs:
            p_append_node(w,choose(typ == PROJECT_UNIT_TYPE,2,1),width,0,0,0)
        put(w,240,index+1)
        return 0
    pput(w,32,p_node(w,2,1,0,0,1))
    pput(w,40,p_node(w,2,1,0,0,0))
    put(w,104,32+8*(inputs+get(w,96)))
    put(w,192,3)
    return 0

def projection_function(w:mutbuf) -> u64:
    cursor=get(w,104)
    end=get(w,64)
    if cursor > end or end-cursor < 24:
        return stop(w,4,1)
    extent=graph(w,cursor)
    count=graph(w,cursor+8)
    entry=graph(w,cursor+16)
    if extent < 24 or extent > end-cursor or count == 0 or count > 128 or entry >= count:
        return stop(w,4,1)
    put(w,208,count)
    put(w,216,entry)
    put(w,224,cursor+extent)
    put(w,200,cursor+24)
    put(w,232,0)
    put(w,248,0)
    put(w,256,0)
    put(w,192,4)
    return 0

def projection_inventory(w:mutbuf) -> u64:
    index=get(w,232)
    cursor=get(w,200)
    end=get(w,224)
    if index == get(w,208):
        if cursor != end:
            return stop(w,4,1)
        origin=pget(w,512+8*get(w,216))
        if graph(w,origin) != get(w,88):
            return stop(w,4,1)
        pput(w,1536+8*get(w,216),pget(w,32))
        put(w,240,0)
        put(w,192,5)
        return 0
    if cursor > end or end-cursor < 64:
        return stop(w,4,1)
    params=graph(w,cursor)
    ops=graph(w,cursor+8)
    argc=graph(w,cursor+40)
    argd=graph(w,cursor+56)
    remaining=end-cursor-64
    if params > (remaining>>3) or argc > (remaining>>3) or argd > (remaining>>3) or ops > 2048-get(w,256):
        return stop(w,4,1)
    amount=8*(params+argc+argd)+48*ops
    if amount > remaining:
        return stop(w,4,1)
    if params > 1048576-get(w,248):
        return stop(w,0,2)
    pput(w,512+8*index,cursor)
    pput(w,1536+8*index,NIL)
    pput(w,4096+8*index,get(w,248))
    put(w,248,get(w,248)+params)
    put(w,256,get(w,256)+ops)
    put(w,200,cursor+64+amount)
    put(w,232,index+1)
    return 0

def projection_entry(w:mutbuf) -> u64:
    index=get(w,240)
    entry=get(w,216)
    row=pget(w,512+8*entry)
    if index < get(w,88):
        typ=graph(w,32+8*index)
        if graph(w,row+64+8*index) != typ:
            return stop(w,4,1)
        put(w,PHI_BASE+8*(pget(w,4096+8*entry)+index),index)
        put(w,240,index+1)
        return 0
    pput(w,64,pget(w,40))
    pput(w,80,pget(w,40))
    pput(w,56,p_node(w,2,8,0,0,0))
    put(w,240,0)
    put(w,192,6)
    return 0

def projection_block(w:mutbuf) -> u64:
    index=get(w,232)
    if index == get(w,208):
        put(w,192,14)
        return 0
    inherited=pget(w,1536+8*index)
    if inherited == NIL:
        put(w,232,index+1)
        return 0
    row=pget(w,512+8*index)
    params=graph(w,row)
    ops=graph(w,row+8)
    if params+ops > 1048576:
        return stop(w,0,2)
    put(w,272,row)
    put(w,280,params)
    put(w,288,ops)
    put(w,296,row+64+8*params+48*ops)
    pput(w,88,pget(w,40))
    pput(w,96,params)
    pput(w,104,pget(w,40))
    pput(w,112,inherited)
    put(w,240,0)
    put(w,192,8)
    return 0

def projection_parameter(w:mutbuf) -> u64:
    index=get(w,240)
    if index < get(w,280):
        typ=graph(w,get(w,272)+64+8*index)
        if p_width(typ) == 0:
            return stop(w,4,1)
        node=get(w,PHI_BASE+8*(pget(w,4096+8*get(w,232))+index))
        if node >= pget(w,0):
            return stop(w,4,1)
        put(w,LOCAL_BASE+8*index,(typ<<32)|node)
        put(w,240,index+1)
    else:
        put(w,240,0)
        put(w,192,9)
    return 0

def projection_terminal(w:mutbuf) -> u64:
    row=get(w,272)
    reach=p_flush_faults(w)
    kind=graph(w,row+16)
    argc=graph(w,row+40)
    argd=graph(w,row+56)
    put(w,304,reach)
    put(w,312,kind)
    if kind == 1:
        if argd != 0 or argc != get(w,96):
            return stop(w,4,1)
        p_complete(w,reach)
        if get(w,80) == 4:
            pput(w,80,p_logic(w,4,reach,pget(w,80)))
        put(w,240,0)
        put(w,192,11)
        return 0
    if kind == 2:
        code=graph(w,row+24)
        if argc != 0 or argd != 0 or code == 0 or code > PROJECT_TRAP_CODE_MAX:
            return stop(w,4,1)
        if get(w,80) == 4:
            p_complete(w,reach)
        elif get(w,80) != 1:
            p_trap(w,reach,code)
        return projection_next_block(w)
    if kind == 3:
        if argd != 0:
            return stop(w,4,1)
    elif kind == 4:
        flag=p_var(w,graph(w,row+24))
        if flag>>32 != 1:
            return stop(w,4,1)
        put(w,784,p_logic(w,3,reach,flag&4294967295))
        put(w,792,p_logic(w,3,reach,p_logic(w,6,flag&4294967295,0)))
    else:
        return stop(w,4,1)
    put(w,320,0)
    put(w,192,12)
    return 0

def projection_return(w:mutbuf) -> u64:
    index=get(w,240)
    if index < get(w,96):
        value=p_var(w,graph(w,get(w,296)+8*index))
        typ=graph(w,32+8*(get(w,88)+index))
        if value>>32 != typ:
            return stop(w,4,1)
        if get(w,80) != 1:
            previous=pget(w,128+8*index)
            pput(w,128+8*index,p_node(w,11,p_width(typ),get(w,304),value&4294967295,previous))
        put(w,240,index+1)
        return 0
    return projection_next_block(w)

def projection_edge_begin(w:mutbuf) -> u64:
    row=get(w,272)
    arm=get(w,320)
    target=graph(w,row+32+16*arm)
    count=graph(w,row+40+16*arm)
    cursor=get(w,296)
    reach=get(w,304)
    if get(w,312) == 4:
        reach=get(w,784+8*arm)
    if arm == 1:
        cursor=cursor+8*graph(w,row+40)
    if target >= get(w,208) or target <= get(w,232):
        return stop(w,4,1)
    if graph(w,pget(w,512+8*target)) != count:
        return stop(w,4,1)
    prior=pget(w,1536+8*target)
    merge=reach
    if prior != NIL:
        merge=p_logic(w,4,reach,prior)
    put(w,328,target)
    put(w,336,count)
    put(w,344,cursor)
    put(w,352,reach)
    put(w,360,prior)
    put(w,368,merge)
    put(w,240,0)
    put(w,192,13)
    return 0

def projection_edge_argument(w:mutbuf) -> u64:
    index=get(w,240)
    target=get(w,328)
    if index < get(w,336):
        value=p_var(w,graph(w,get(w,344)+8*index))
        typ=graph(w,pget(w,512+8*target)+64+8*index)
        if value == 0 or value>>32 != typ:
            return stop(w,4,1)
        node=value&4294967295
        at=PHI_BASE+8*(pget(w,4096+8*target)+index)
        if get(w,360) != NIL:
            node=p_node(w,11,p_width(typ),get(w,352),node,get(w,at))
        put(w,at,node)
        put(w,240,index+1)
        return 0
    pput(w,1536+8*target,get(w,368))
    if get(w,312) == 4 and get(w,320) == 0:
        put(w,320,1)
        put(w,192,12)
        return 0
    return projection_next_block(w)

def projection_next_block(w:mutbuf) -> u64:
    put(w,232,get(w,232)+1)
    put(w,192,7)
    return 0

def projection_function_end(w:mutbuf) -> u64:
    mode=get(w,80)
    outputs=get(w,96)
    if mode == 2 and get(w,112) == 0:
        pput(w,256,pget(w,56))
        pput(w,264,pget(w,64))
        i=0
        while i < outputs:
            pput(w,272+8*i,pget(w,128+8*i))
            i=i+1
        put(w,112,1)
        put(w,104,get(w,224))
        put(w,192,3)
        return 0
    if get(w,224) != get(w,64):
        return stop(w,4,1)
    pairs=1
    both=pget(w,64)
    if mode == 2:
        both=p_logic(w,3,both,pget(w,264))
        pairs=outputs+2
    put(w,PAIR_BASE,both)
    put(w,PAIR_BASE+8,pget(w,32))
    if mode == 4:
        pairs=2
        put(w,PAIR_BASE+16,p_logic(w,3,pget(w,80),pget(w,128)))
        put(w,PAIR_BASE+24,pget(w,40))
    if mode == 2:
        put(w,PAIR_BASE+16,pget(w,256))
        put(w,PAIR_BASE+24,pget(w,56))
        i=0
        while i < outputs:
            put(w,PAIR_BASE+32+16*i,pget(w,272+8*i))
            put(w,PAIR_BASE+40+16*i,pget(w,128+8*i))
            i=i+1
    put(w,384,pairs)
    put(w,400,0)
    put(w,392,0)
    put(w,24,3)
    return 0
'''

def lifted_projection():
    selected={'p_width','p_cancel_wrapping','p_fold','p_logic','p_flush_faults','p_complete','p_trap','p_trap_tag','p_operation','p_checked_shift','p_fault','p_checked_division','p_magnitude','p_checked_mul','p_checked_cast'}
    fns={n.name:n for n in ast.parse(PROJECTION).body if isinstance(n,ast.FunctionDef)}
    argnames={name:[a.arg for a in n.args.args] for name,n in fns.items()}
    argnames.update({'p_node':['o','w','op','width','a','b','c'],'p_append_node':['o','w','op','width','a','b','c']})
    class Lift(ast.NodeTransformer):
        def visit_FunctionDef(self,n):
            args=[];placed=False
            for a in n.args.args:
                if a.arg in ('s','o','w'):
                    if not placed:a.arg='w';a.annotation=ast.Name('mutbuf',ast.Load());args.append(a);placed=True
                else:args.append(a)
            n.args.args=args
            return self.generic_visit(n)
        def visit_Call(self,n):
            n=self.generic_visit(n)
            if not isinstance(n.func,ast.Name):return n
            name=n.func.id
            if name=='read64' and isinstance(n.args[0],ast.Name) and n.args[0].id=='s':
                return ast.Call(ast.Name('graph',ast.Load()),[ast.Name('w',ast.Load()),n.args[1]],[])
            if name in ('read_stack','write64'):
                assert isinstance(n.args[0],ast.Name)
                plane=n.args[0].id
                assert plane in ('o','w')
                n.func.id=('nget' if name=='read_stack' else 'nput') if plane=='o' else ('pget' if name=='read_stack' else 'pput')
                n.args[0]=ast.Name('w',ast.Load())
            elif name in argnames:
                args=[];placed=False
                for k,v in zip(argnames[name],n.args):
                    if k in ('s','o','w'):
                        if not placed:args.append(ast.Name('w',ast.Load()));placed=True
                    else:args.append(v)
                n.args=args
            return n
        def visit_BinOp(self,n):
            n=self.generic_visit(n)
            if isinstance(n.op,ast.RShift) and isinstance(n.right,ast.Constant):
                if n.right.value==16:n.right.value=32
                elif n.right.value==23:n.right.value=39
            return n
        def visit_Constant(self,n):
            if n.value==65535:return ast.copy_location(ast.Constant((1<<32)-1),n)
            if n.value==65536:return ast.copy_location(ast.Constant(1<<32),n)
            return n
    out=[]
    for name in (name for name in fns if name in selected):
        n=copy.deepcopy(fns[name])
        if name=='p_operation':
            branch=next(x for x in n.body if isinstance(x,ast.If) and 'PROJECT_DIRECT_CALL' in ast.unparse(x.test))
            branch.test=ast.parse('role == 40 or role == 41',mode='eval').body
            branch.body=[ast.Return(ast.Constant(0))]
        out.append(ast.unparse(ast.fix_missing_locations(Lift().visit(n))))
    bodies={n.name:n for n in ast.parse(BODY).body if isinstance(n,ast.FunctionDef)}
    out.extend(ast.unparse(bodies[n]) for n in ('word_mask','evaluate_word_order'))
    return '\n\n'.join(out)+'\n'

"""Author shared native LLVM rendering algorithms; development input only.

The generated policies retain JSON structure, SSA identities, exact integer
lexemes and bounded IR output in caller-owned memory. No Python evaluator,
template interpreter or source-language runtime is linked into the image.
"""
from pathlib import Path
import ast
from tools.generate_hia_system_jobctl_request import RequestBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_core_json_frontend import KEYS as CORE_KEYS, packed
from hepta.hia_agent_assembly import render_assembly

ROOT=Path(__file__).resolve().parents[1]
KEYS=CORE_KEYS+('value','function','mode')
C=dict(WORK=128<<20,CTRL=24<<20,META=25<<20,HASH=58<<20,BODY=72<<20,FINAL=88<<20,
       FUNCS=(24<<20)+4096,BLOCKS=(24<<20)+16384,NUMBUF=(24<<20)+1024,
       PHASE=(24<<20),ERROR=(24<<20)+8,POS=(24<<20)+16,DEST=(24<<20)+24,
       SERIAL=(24<<20)+32,FN=(24<<20)+40,FN_INDEX=(24<<20)+48,
       BLOCK=(24<<20)+56,BLOCK_INDEX=(24<<20)+64,INS=(24<<20)+72,
       SLOTS=(24<<20)+80,FUNCTION_COUNT=(24<<20)+88,BLOCK_COUNT=(24<<20)+96,
       EDGE_COUNT=(24<<20)+104,TARGET=(24<<20)+112,LAYOUT=(24<<20)+120,
       VERSION=(24<<20)+128,FEATURES=(24<<20)+136,INTRINSICS=(24<<20)+144,
       OUTPUT_SIZE=(24<<20)+152,ZERO_BYTES=(24<<20)+160,FINAL_POS=(24<<20)+168,
       BODY_POS=(24<<20)+176,BLOCK_NEXT=(24<<20)+184,INS_NEXT=(24<<20)+192,
       EDGE_NEXT=(24<<20)+200,ROOT_RESULT=(24<<20)+208,ENTRY_INDEX=(24<<20)+216,ORDER_INDEX=(24<<20)+224,
       FN_CURSOR=(24<<20)+232,WRAPPER_COUNT=(24<<20)+240,WRAPPER_CURSOR=(24<<20)+248,
       HELPER_NEXT=(24<<20)+256,OUTLINED=(24<<20)+264,COMPONENT=(24<<20)+272,
       AUX=104<<20,IGRAPH=(104<<20)+4096,INAMES=(104<<20)+65536,ICONSTS=(104<<20)+262144,
       IQUEUE=(104<<20)+524288,IQUEUED=(104<<20)+525312,
       ARG_HEADER=64,
       NONE=(1<<64)-1,TEMP=1<<63,MAX_IR=16<<20,MAX_NODES=262144)
TYPE_NAMES=('i8','u8','i16','u16','i32','u32','i64','u64','isize','usize','bool','unit','buffer','readbuf','mutbuf','chain')
OP_NAMES=('const','int.add.checked','int.sub.checked','int.mul.checked','int.add.wrap','int.sub.wrap','int.mul.wrap',
          'int.div.checked','int.rem.checked','int.shl.checked','int.shr.checked','int.neg.checked',
          'bit.and','bit.or','bit.xor','bit.not','compare.eq','compare.ne','compare.lt','compare.le','compare.gt','compare.ge',
          'bool.not','bool.and','bool.or','int.cast','select','call','buffer.new','buffer.try_new','buffer.len',
          'chain.empty','chain.is_empty','chain.try_push','chain.pop','chain.head_read','chain.head_mut',
          'owner.move','borrow.read','borrow.mut','loan.end','owner.drop',
          'buffer.load.u64.le','buffer.load.u64.be','buffer.store.u64.le','buffer.store.u64.be',
          'buffer.load','buffer.store','buffer.fill','buffer.copy','buffer.move_within','buffer.fill_range','buffer.copy_range','buffer.swap')

COMMON=r'''
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def meta(w:mutbuf,node:u64,at:u64) -> u64:
    if node==NONE or node>=get(w,8):
        fail(w,4294967291)
        return 0
    return get(w,META+node*128+at)

def setmeta(w:mutbuf,node:u64,at:u64,value:u64) -> u64:
    if node==NONE or node>=get(w,8):
        return fail(w,4294967291)
    return put(w,META+node*128+at,value)

def fail(w:mutbuf,code:u64) -> u64:
    if get(w,ERROR)==0:
        put(w,ERROR,code)
    return 0

def kind(w:mutbuf,node:u64) -> u64:
    if node==NONE or node>=get(w,8):
        return NONE
    return get(w,64+node*56)

def count(w:mutbuf,node:u64) -> u64:
    if node==NONE or node>=get(w,8):
        return 0
    return get(w,64+node*56+32)

def first(w:mutbuf,node:u64) -> u64:
    k=kind(w,node)
    if k!=5 and k!=6:
        return NONE
    return get(w,64+node*56+24)

def next(w:mutbuf,node:u64) -> u64:
    if node==NONE or node>=get(w,8):
        return NONE
    return get(w,64+node*56+16)

def nth(w:mutbuf,node:u64,index:u64) -> u64:
    at=first(w,node)
    i=0
    while at!=NONE and i<index:
        at=next(w,at)
        i=i+1
    return at

def text_equal(w:mutbuf,a:u64,b:u64) -> u64:
    if kind(w,a)!=4 or kind(w,b)!=4 or count(w,a)!=count(w,b):
        return 0
    left=get(w,64+a*56+24)
    right=get(w,64+b*56+24)
    i=0
    while i<count(w,a):
        if byte(w,left+i)!=byte(w,right+i):
            return 0
        i=i+1
    return 1

def same(w:mutbuf,start:u64,size:u64,n:u64,a:u64,b:u64,c:u64) -> u64:
    if size!=n:
        return 0
    i=0
    while i<n:
        value=a
        shift=i*8
        if i>=8:
            value=b
            shift=(i-8)*8
        if i>=16:
            value=c
            shift=(i-16)*8
        if byte(w,start+i)!=((value>>shift)&255):
            return 0
        i=i+1
    return 1

def is_text(w:mutbuf,node:u64,n:u64,a:u64,b:u64,c:u64) -> u64:
    if kind(w,node)!=4:
        return 0
    return same(w,get(w,64+node*56+24),count(w,node),n,a,b,c)

def field(w:mutbuf,node:u64,key:u64) -> u64:
    if kind(w,node)!=6:
        return NONE
    at=first(w,node)
    while at!=NONE:
        if key_id(w,at)==key:
            return at
        at=next(w,at)
    return NONE

def append(w:mutbuf,value:u64) -> u64:
    at=get(w,POS)
    if at>=MAX_IR:
        return fail(w,4294967290)
    store(w,get(w,DEST)+at,value)
    put(w,POS,at+1)
    return 0

def emit24(w:mutbuf,n:u64,a:u64,b:u64,c:u64) -> u64:
    i=0
    while i<n:
        value=a
        shift=i*8
        if i>=8:
            value=b
            shift=(i-8)*8
        if i>=16:
            value=c
            shift=(i-16)*8
        append(w,(value>>shift)&255)
        i=i+1
    return 0

def emit_number(w:mutbuf,value:u64) -> u64:
    n=0
    rest=value
    while rest>=10:
        store(w,NUMBUF+n,48+rest%10)
        rest=rest//10
        n=n+1
    append(w,48+rest)
    while n>0:
        n=n-1
        append(w,byte(w,NUMBUF+n))
    return 0

def emit_text(w:mutbuf,node:u64) -> u64:
    if kind(w,node)!=4:
        return fail(w,4294967291)
    at=get(w,64+node*56+24)
    n=count(w,node)
    i=0
    while i<n:
        append(w,byte(w,at+i))
        i=i+1
    return 0

def identifier(w:mutbuf,node:u64) -> u64:
    if kind(w,node)!=4 or count(w,node)==0 or count(w,node)>128:
        return 0
    p=get(w,64+node*56+24)
    i=0
    while i<count(w,node):
        c=byte(w,p+i)
        ok=(c>=65 and c<=90) or (c>=97 and c<=122) or c==95
        if i>0:
            ok=ok or (c>=48 and c<=57)
        if ok==False:
            return 0
        i=i+1
    return 1

def hash_text(w:mutbuf,node:u64) -> u64:
    p=get(w,64+node*56+24)
    n=count(w,node)
    value=1469598103934665603
    i=0
    while i<n:
        value=(value^byte(w,p+i))*1099511628211
        i=i+1
    return value

def symbol(w:mutbuf,name:u64,definition:u64,insert:u64) -> u64:
    if identifier(w,name)==0:
        fail(w,4294967291)
        return NONE
    slots=get(w,SLOTS)
    at=hash_text(w,name)&(slots-1)
    scope=get(w,BLOCK)+1
    seen=0
    while seen<slots:
        p=HASH+at*24
        tag=get(w,p)
        if tag==0:
            if insert==0:
                fail(w,4294967291)
                return NONE
            put(w,p,scope)
            put(w,p+8,name)
            put(w,p+16,definition)
            return definition
        if tag==scope and text_equal(w,get(w,p+8),name)==1:
            if insert==1 and get(w,p+16)!=definition:
                fail(w,4294967291)
            return get(w,p+16)
        at=(at+1)&(slots-1)
        seen=seen+1
    fail(w,4294967291)
    return NONE

def argument(w:mutbuf,ins:u64,index:u64) -> u64:
    name=nth(w,field(w,ins,K_args),index)
    value=symbol(w,name,0,0)
    setmeta(w,name,112,value)
    return value

def reference_type(w:mutbuf,value:u64) -> u64:
    if value>=TEMP:
        return 0
    return meta(w,value,24)

def reference(s:readbuf,w:mutbuf,value:u64) -> u64:
    n=0
    while value<TEMP and meta(w,value,0)==0:
        value=meta(w,value,8)
        n=n+1
        if n>get(w,8):
            return fail(w,4294967291)
    if value>=TEMP:
        emit(w,"%t")
        emit_number(w,value-TEMP)
        return 0
    tag=meta(w,value,0)
    if tag==1:
        emit(w,"%p_")
        emit_number(w,meta(w,value,8))
        emit(w,"_")
        emit_number(w,meta(w,value,16))
    elif tag==3:
        node=meta(w,value,8)
        k=kind(w,node)
        if k==1:
            emit(w,"false")
        elif k==2:
            emit(w,"true")
        elif k==3:
            start=get(w,64+node*56+24)
            size=count(w,node)
            i=0
            if size==0:
                return fail(w,4294967291)
            while i<size:
                c=byte(s,ARG_HEADER+start+i)
                if (c<48 or c>57) and (i!=0 or c!=45):
                    return fail(w,4294967291)
                append(w,c)
                i=i+1
        else:
            return fail(w,4294967291)
    elif tag==4:
        emit(w,"0")
    elif tag==5:
        emit(w,"null")
    elif tag==6:
        emit(w,"zeroinitializer")
    else:
        return fail(w,4294967291)
    return 0

def typed_reference(s:readbuf,w:mutbuf,value:u64) -> u64:
    emit_type(w,reference_type(w,value))
    emit(w," ")
    reference(s,w,value)
    return 0

def new_temp(w:mutbuf) -> u64:
    n=get(w,SERIAL)+1
    put(w,SERIAL,n)
    return TEMP+n

def instruction_start(s:readbuf,w:mutbuf) -> u64:
    value=new_temp(w)
    emit(w,"  ")
    reference(s,w,value)
    emit(w," = ")
    return value

def end_line(w:mutbuf) -> u64:
    emit(w,"\n")
    return 0

def output_value(w:mutbuf,ins:u64,index:u64,value:u64) -> u64:
    node=nth(w,field(w,ins,K_out),index)
    t=typecode(w,field(w,node,K_type))
    if t==0:
        return fail(w,4294967291)
    setmeta(w,node,0,0)
    setmeta(w,node,8,value)
    setmeta(w,node,24,t)
    setmeta(w,node,32,ins)
    setmeta(w,node,40,get(w,BLOCK))
    return symbol(w,field(w,node,K_name),node,1)

def output_constant(w:mutbuf,ins:u64,tag:u64,node:u64) -> u64:
    out=nth(w,field(w,ins,K_out),0)
    t=typecode(w,field(w,out,K_type))
    if t==0:
        return fail(w,4294967291)
    setmeta(w,out,0,tag)
    setmeta(w,out,8,node)
    setmeta(w,out,24,t)
    setmeta(w,out,32,ins)
    setmeta(w,out,40,get(w,BLOCK))
    return symbol(w,field(w,out,K_name),out,1)

def guard(s:readbuf,w:mutbuf,condition:u64) -> u64:
    index=new_temp(w)-TEMP
    emit(w,"  br i1 ")
    reference(s,w,condition)
    emit(w,", label %ok_")
    emit_number(w,index)
    emit(w,", label %trap_")
    emit_number(w,index)
    emit(w,"\ntrap_")
    emit_number(w,index)
    emit(w,":\n  call void @abort()\n  unreachable\nok_")
    emit_number(w,index)
    emit(w,":\n")
    return 0

def bits(w:mutbuf,t:u64) -> u64:
    if t==1 or t==2 or t==12:
        return 8
    if t==3 or t==4:
        return 16
    if t==5 or t==6:
        return 32
    if t>=7 and t<=10:
        return 64
    if t==11:
        return 1
    return fail(w,4294967291)

def signed_type(t:u64) -> u64:
    return choose(t==1 or t==3 or t==5 or t==7 or t==9,1,0)

def emit_type(w:mutbuf,t:u64) -> u64:
    if t>=13 and t<=15:
        emit(w,"%hia.buffer")
    elif t==16:
        emit(w,"ptr")
    elif t>=1 and t<=12:
        emit(w,"i")
        emit_number(w,bits(w,t))
    else:
        fail(w,4294967291)
    return 0

def abi_attr(w:mutbuf,t:u64) -> u64:
    if get(w,TARGET)==1:
        return 0
    if get(w,TARGET)==2 and (t==5 or t==6):
        emit(w,"signext ")
    elif t==1 or t==3:
        emit(w,"signext ")
    elif t==2 or t==4 or t==11:
        emit(w,"zeroext ")
    return 0

def return_type(w:mutbuf,array:u64) -> u64:
    n=count(w,array)
    if n==0:
        emit(w,"void")
    elif n==1:
        emit_type(w,typecode(w,first(w,array)))
    else:
        emit(w,"{ ")
        p=first(w,array)
        while p!=NONE:
            emit_type(w,typecode(w,p))
            p=next(w,p)
            if p!=NONE:
                emit(w,", ")
        emit(w," }")
    return 0

def cast_value(s:readbuf,w:mutbuf,value:u64,source:u64,destination:u64) -> u64:
    a=bits(w,source)
    b=bits(w,destination)
    if a==b:
        return value
    result=instruction_start(s,w)
    if a>b:
        emit(w,"trunc")
    elif signed_type(source)==1:
        emit(w,"sext")
    else:
        emit(w,"zext")
    emit(w," i")
    emit_number(w,a)
    emit(w," ")
    reference(s,w,value)
    emit(w," to i")
    emit_number(w,b)
    end_line(w)
    return result

def buffer_part(s:readbuf,w:mutbuf,value:u64,index:u64) -> u64:
    result=instruction_start(s,w)
    emit(w,"extractvalue %hia.buffer ")
    reference(s,w,value)
    emit(w,", ")
    emit_number(w,index)
    end_line(w)
    return result

def binary(s:readbuf,w:mutbuf,op:u64,t:u64,a:u64,b:u64) -> u64:
    value=instruction_start(s,w)
    emit_binary_name(w,op)
    emit(w," ")
    emit_type(w,t)
    emit(w," ")
    reference(s,w,a)
    emit(w,", ")
    reference(s,w,b)
    end_line(w)
    return value

def compare(s:readbuf,w:mutbuf,predicate:u64,t:u64,a:u64,b:u64) -> u64:
    value=instruction_start(s,w)
    emit(w,"icmp ")
    emit_predicate(w,predicate)
    emit(w," ")
    emit_type(w,t)
    emit(w," ")
    reference(s,w,a)
    emit(w,", ")
    reference(s,w,b)
    end_line(w)
    return value

def compare_literal(s:readbuf,w:mutbuf,predicate:u64,t:u64,a:u64,value:u64) -> u64:
    result=instruction_start(s,w)
    emit(w,"icmp ")
    emit_predicate(w,predicate)
    emit(w," ")
    emit_type(w,t)
    emit(w," ")
    reference(s,w,a)
    emit(w,", ")
    emit_number(w,value)
    end_line(w)
    return result

def boolean_not(s:readbuf,w:mutbuf,value:u64) -> u64:
    result=instruction_start(s,w)
    emit(w,"xor i1 ")
    reference(s,w,value)
    emit(w,", true")
    end_line(w)
    return result

def function_index(w:mutbuf,name:u64) -> u64:
    n=get(w,FUNCTION_COUNT)
    i=0
    while i<n:
        f=get(w,FUNCS+i*8)
        if text_equal(w,field(w,f,K_name),name)==1:
            return i
        i=i+1
    fail(w,4294967291)
    return 0

def block_index(w:mutbuf,name:u64) -> u64:
    n=get(w,BLOCK_COUNT)
    i=0
    while i<n:
        b=get(w,BLOCKS+i*8)
        if text_equal(w,field(w,b,K_id),name)==1:
            return i
        i=i+1
    fail(w,4294967291)
    return 0

def copy_output(w:mutbuf,start:u64,n:u64) -> u64:
    i=0
    while i<n:
        append(w,byte(w,start+i))
        i=i+1
    return 0
'''

BINARIES=('add','sub','mul','sdiv','udiv','srem','urem','shl','ashr','lshr','and','or','xor')
PREDICATES=('eq','ne','slt','ult','sle','ule','sgt','ugt','sge','uge')
def classifier(name,values):
    lines=['def '+name+'(w:mutbuf,node:u64) -> u64:']
    for i,value in enumerate(values,1):
        lines+=['    if is_text(w,node,'+repr(value)+')==1:','        return '+str(i)]
    return '\n'.join(lines+['    return 0'])+'\n'

def token_emitter(name,values):
    lines=['def '+name+'(w:mutbuf,which:u64) -> u64:']
    for i,value in enumerate(values,1):
        lines+=['    if which=='+str(i)+':','        emit(w,'+repr(value)+')','        return 0']
    return '\n'.join(lines+['    return fail(w,4294967291)'])+'\n'

def helper_source():
    key=['def key_id(w:mutbuf,node:u64) -> u64:',
         '    start=get(w,64+node*56+40)','    size=get(w,64+node*56+48)']
    for i,name in enumerate(KEYS):
        key+=['    if same(w,start,size,'+','.join(map(str,packed(name)))+')==1:',
              '        return '+str(1<<i)]
    key+=['    return 0']
    return (COMMON+'\n'+'\n'.join(key)+'\n'+classifier('typecode',TYPE_NAMES)
            +classifier('opcode',OP_NAMES)+token_emitter('emit_binary_name',BINARIES)
            +token_emitter('emit_predicate',PREDICATES))

def expand(source,entry):
    tree=ast.parse(source+'\n'+helper_source())
    constants={**C,**{'K_'+name:1<<i for i,name in enumerate(KEYS)},
               **{'OP_'+name.replace('.','_'):i for i,name in enumerate(OP_NAMES,1)}}
    class Expand(ast.NodeTransformer):
        def visit_Expr(self,node):
            node=self.generic_visit(node)
            call=node.value
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='emit':
                assert len(call.args)==2 and isinstance(call.args[1],ast.Constant) and isinstance(call.args[1].value,str)
                raw=call.args[1].value
                raw.encode('ascii')
                return [ast.Expr(ast.Call(func=ast.Name(id='emit24',ctx=ast.Load()),
                        args=[call.args[0],*[ast.Constant(v) for v in packed(raw[i:i+24])]],keywords=[]))
                        for i in range(0,len(raw),24)]
            return node
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Name) and node.func.id=='is_text' and len(node.args)==3:
                assert isinstance(node.args[2],ast.Constant) and isinstance(node.args[2].value,str)
                node.args=node.args[:2]+[ast.Constant(v) for v in packed(node.args[2].value)]
            return node
        def visit_Name(self,node):
            if node.id in constants:return ast.Constant(constants[node.id])
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    nodes={node.name:node for node in tree.body}
    assert len(nodes)==len(tree.body)
    selected={entry};pending=[entry]
    while pending:
        fn=pending.pop()
        for call in ast.walk(nodes[fn]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id in nodes and call.func.id not in selected:
                selected.add(call.func.id);pending.append(call.func.id)
    ordered=[nodes[entry]]+[n for n in tree.body if n.name in selected and n.name!=entry]
    return ast.unparse(ast.Module(body=ordered,type_ignores=[]))

class LLVMBuilder(RequestBuilder):
    def expr(self,node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='word_load':
            args=[self.expr(value) for value in node.args]
            return self.op('buffer.load.u64.le',[args[0],self.cast(args[1],'usize')],'u64')
        return super().expr(node)

def document(source,module):
    nodes=ast.parse(source).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=LLVMBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})

def write_module(module,source,entry):
    text=expand(source,entry)
    doc=document(text,module)
    functions=len(doc['functions'])
    blocks=sum(len(fn['blocks'])for fn in doc['functions'])
    ops=sum(len(block['ops'])for fn in doc['functions']for block in fn['blocks'])
    assert functions<=128 and blocks<=1536 and ops<=8192,(module,functions,blocks,ops)
    path=ROOT/'examples/hia_bootstrap'/(module+'.hepta')
    path.write_text(render_assembly(doc))
    print(module,path.stat().st_size,functions,blocks,ops,flush=True)
    return doc

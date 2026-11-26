"""Development author for the native Linux bounded compiler-capture policies."""
from pathlib import Path
import ast
from tools.generate_hia_system_jobctl_request import RequestBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
C=dict(PHASE=0,RESULT=8,ERROR=16,ERROR_NO=24,CLEAN_ERROR=32,CLEAN_ERRNO=40,
 PID=48,RETURN_KNOWN=56,RETURN_CODE=64,GROUP_ATTEMPTED=72,GROUP_ERRNO=80,
 INPUT_FD=88,OUTPUT_FD=96,ERROR_FD=104,PIPE_READ=112,PIPE_WRITE=120,
 OUTPUT_TOTAL=128,ERROR_TOTAL=136,DEADLINE=144,NOW=152,TIMEOUT=160,
 OUTPUT_LIMIT=168,ERROR_LIMIT=176,INPUT_LIMIT=184,ARGC=192,ENVC=200,
 EXPLICIT_ENV=208,ARGV=216,ENVP=224,INPUT_AT=232,INPUT_N=240,CWD_AT=248,CWD_N=256,
 CWD_PRESENT=264,ARG0_AT=272,ARG0_N=280,PATH_PTR=288,PATH_N=296,PATH_CURSOR=304,
 PATH_WORK=312,PATH_CAP=320,FIRST_EXEC_ERR=328,ITER=336,IO_AT=344,
 SELF=352,SOURCE_PTR=360,OUTPUT_PTR=368,WORK_PTR=376,WORK_N=384,SPAWNED=392,
 RAW_OUT=400,RAW_OUT_N=408,RAW_OUT_CAP=416,RAW_ERR=424,RAW_ERR_N=432,RAW_ERR_CAP=440,
 NORM_OUT=448,NORM_OUT_N=456,NORM_OUT_CAP=464,NORM_ERR=472,NORM_ERR_N=480,NORM_ERR_CAP=488,
 READ_INDEX=496,READ_LIMIT=504,READ_TARGET=512,READ_AMOUNT=520,READ_GROW=528,
 ENV_SOURCE=536,ENV_INDEX=544,ENV_PATH_CAPTURE=552,ENV_PATH_IN_SOURCE=560,
 CLEAN_INDEX=568,CLEAN_PENDING=576,RELEASE_INDEX=584,REAP_DEADLINE=592,
 RETIRE_ERROR=600,RETIRE_ERRNO=608,CONTEXT_MAGIC=616,ERROR_PIPE_USED=624,
 EXEC_ERROR=632,EXEC_STAGE=640,ENV_PATH_BUFFER=648,ENV_PATH_ALLOC=656,
 ENV_ELEMENT=664,ENV_CHARACTER=672,ENV_MATCH=680,PARENT_PID=688,
 PATH_LAST=696,PATH_BYTES=704,STREAM_RESULT=712,STREAM_N=720,
 CLOSE_STAGE=728,EVIDENCE_ERROR=736,EVIDENCE_ERRNO=744,
 CHILD_DIR=1600,DENT_AT=1608,DENT_N=1616,FD_LIMIT=1624,FD_INDEX=1632,CLOSE_MODE=1640,PROC_FD_NAME=1664,DENTS=2048,
 FAILURE_PASS=1776,ERROR_STREAM=1784,RELEASE_SLOT=1792,RELEASE_CAP_SLOT=1800,
 AUX_FD=1808,FD_RETRY_PENDING=1816,CLOSE_METHOD=1824,CLOSE_AFTER=1832,CLOSE_INDEX=1840,UNKNOWN_FDS=1848,CLOSE_TARGET=1856,E_OVERFLOW=17,
 SIGACTION=768,SIGINFO=832,STAT=1024,CLOCK=1200,SLEEP=1216,PIPE_FDS=1232,
 ERROR_PIPE_DATA=1248,TEMP_NAME=1280,DEFAULT_PATH=1320,TABLE_BASE=4096,
 NONE=(1<<64)-1,SSIZE_MAX=(1<<63)-1,MAX_TIMEOUT=3600000000000,
 REQUEST=int.from_bytes(b'HIACAP01','little'),REPLY=int.from_bytes(b'HIACAR01','little'),
 CTXMAGIC=int.from_bytes(b'HIACAW01','little'),
 E_ARGV=1,E_BUDGET=2,E_ENV=3,E_INPUT=4,E_INPUT_SIZE=5,E_OWNERSHIP=6,
 E_EXEC=7,E_OUTPUT_SIZE=8,E_TIMEOUT=9,E_ENCODING=10,E_CLEANUP=11,E_OS=12,
 E_MEMORY=13,E_CONTEXT=14,E_OUTPUT_CAPACITY=15,E_PENDING=16)
COMMON=r'''
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def failed(result:u64) -> bool:
    return result>=18446744073709547521

def errno(result:u64) -> u64:
    return 0-result

def choose(condition:bool,left:u64,right:u64) -> u64:
    if condition:
        return left
    return right

def jump(w:mutbuf,phase:u64) -> u32:
    put(w,PHASE,phase)
    return 10

def call(o:mutbuf,w:mutbuf,phase:u64,number:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64,selectors:u64) -> u32:
    put(w,PHASE,phase)
    put(o,0,number)
    put(o,8,a)
    put(o,16,b)
    put(o,24,c)
    put(o,32,d)
    put(o,40,e)
    put(o,48,f)
    put(o,56,selectors)
    return 1

def close_fd(o:mutbuf,w:mutbuf,next:u64,fd:u64,index:u64) -> u32:
    put(w,CLOSE_AFTER,next)
    put(w,CLOSE_INDEX,index)
    put(w,CLOSE_TARGET,fd)
    if get(w,CLOSE_METHOD)==1:
        return call(o,w,31,3,fd,0,0,0,0,0,0)
    return call(o,w,30,436,fd,fd,0,0,0,0,0)

def first_error(w:mutbuf,code:u64,number:u64) -> u64:
    if get(w,ERROR)==0:
        put(w,ERROR,code)
        put(w,ERROR_NO,number)
    return 0

def cleanup_error(w:mutbuf,code:u64,number:u64) -> u64:
    if get(w,CLEAN_ERROR)==0:
        put(w,CLEAN_ERROR,code)
        put(w,CLEAN_ERRNO,number)
    return 0

def utf8(s:readbuf,at:u64,n:u64) -> u64:
    if at>length(s) or n>length(s)-at:
        return 0
    i=0
    while i<n:
        a=byte(s,at+i)
        if a<128:
            i=i+1
        else:
            need=0
            low=128
            high=191
            if a>=194 and a<=223:
                need=1
            elif a>=224 and a<=239:
                need=2
                if a==224:
                    low=160
                if a==237:
                    high=159
            elif a>=240 and a<=244:
                need=3
                if a==240:
                    low=144
                if a==244:
                    high=143
            else:
                return 0
            if n-i<=need:
                return 0
            b=byte(s,at+i+1)
            if b<low or b>high:
                return 0
            j=2
            while j<=need:
                b=byte(s,at+i+j)
                if b<128 or b>191:
                    return 0
                j=j+1
            i=i+need+1
    return 1

def clear(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def reply(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,256)
    put(o,0,REPLY)
    put(o,8,get(w,ERROR))
    put(o,16,get(w,ERROR_NO))
    put(o,24,get(w,RETURN_KNOWN))
    put(o,32,get(w,RETURN_CODE))
    put(o,40,get(w,CLEAN_ERROR))
    put(o,48,get(w,CLEAN_ERRNO))
    put(o,56,get(w,OUTPUT_TOTAL))
    put(o,64,get(w,ERROR_TOTAL))
    put(o,72,get(w,RAW_OUT))
    put(o,80,get(w,RAW_OUT_N))
    put(o,88,get(w,RAW_ERR))
    put(o,96,get(w,RAW_ERR_N))
    put(o,104,get(w,NORM_OUT))
    put(o,112,get(w,NORM_OUT_N))
    put(o,120,get(w,NORM_ERR))
    put(o,128,get(w,NORM_ERR_N))
    put(o,136,choose(get(w,CLEAN_PENDING)!=0,1,0))
    put(o,144,get(w,PID))
    put(o,152,get(w,GROUP_ATTEMPTED))
    put(o,160,get(w,RAW_OUT_CAP))
    put(o,168,get(w,RAW_ERR_CAP))
    put(o,176,get(w,NORM_OUT_CAP))
    put(o,184,get(w,NORM_ERR_CAP))
    put(o,192,get(w,EXEC_STAGE))
    put(o,200,get(w,EVIDENCE_ERROR))
    put(o,208,get(w,EVIDENCE_ERRNO))
    put(o,216,get(w,RETIRE_ERROR))
    put(o,224,get(w,RETIRE_ERRNO))
    put(o,232,get(w,ERROR_STREAM))
    put(o,240,get(w,UNKNOWN_FDS))
    return 0
'''
class CaptureBuilder(RequestBuilder):
 def expr(self,node):
  if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='word_load':
   args=[self.expr(value)for value in node.args]
   return self.op('buffer.load.u64.le',[args[0],self.cast(args[1],'usize')],'u64')
  return super().expr(node)
def document(source,module,entry):
 tree=ast.parse(source+'\n'+COMMON)
 class Constants(ast.NodeTransformer):
  def visit_Name(self,node):
   if node.id in C:return ast.Constant(C[node.id])
   return node
 tree=ast.fix_missing_locations(Constants().visit(tree));nodes={n.name:n for n in tree.body}
 assert len(nodes)==len(tree.body)
 selected={entry};pending=[entry]
 while pending:
  for node in ast.walk(nodes[pending.pop()]):
   if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id in nodes and node.func.id not in selected:
    selected.add(node.func.id);pending.append(node.func.id)
 ordered=[nodes[entry]]+[n for n in tree.body if n.name in selected and n.name!=entry]
 names={n.name:'f'+str(i)for i,n in enumerate(ordered)}
 sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id)for n in ordered}
 total=total_scalar_functions(ordered);functions=[]
 for n in ordered:
  b=CaptureBuilder(n,names,sigs,total);b.statements(n.body)
  functions.append(dict(name=names[n.name],params=[b.param(p)for p in b.params],returns=[b.returns],effects=['read','write','trap'],entry='b0',blocks=b.blocks))
 doc=compact_authoring_cfg(dict(schema='hepta.hia.program.v9',module=module,functions=functions))
 assert len(functions)<=128 and sum(len(f['blocks'])for f in functions)<=1536 and sum(len(b['ops'])for f in functions for b in f['blocks'])<=8192
 return doc
def write_module(name,source,entry):
 doc=document(source,name,entry);p=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
 p.write_text(render_assembly(doc))
 print(name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
 return doc

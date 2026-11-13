"""Isolated DEVELOPMENT Linux stdio compiler profile, never a default target.

The common compiler is read-only. Constant emitter grouping is a private
space-saving transformation over its authoring AST. The new target has two
fixed physical effects: fd0 read into a mutable borrow and fd1 write from a
borrow. It does not contain an assembler blob or invoke host code generation.
"""
from pathlib import Path
import ast, copy, hashlib, json, sys, types
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT
sys.path.insert(0,str(BASE))
from tools import generate_hia_selfhost as original
from hepta.hia_agent_assembly import render_assembly
PINS={
 'tools/generate_hia_selfhost.py':'7a8f100e32bd9475948712a61b8cf166531f4314ca1d203f1ee41e0c1f19ca48',
 'examples/hia_bootstrap/selfhost.hepta':'388b182e42675f11435867dd99520e9452a4ff48e23c0766a3952b662acc7627',
 'tools/hia_selfhost_effects.py':'7e4297659c6108767e593e43c36f247fb8dfd1b192b95e80ccea72ca0b9709cf',
 'tools/hia_selfhost_cli.py':'bad278f878746841f284a290bcaef473b309b4eb13ef126f81e7de0c88c6d02f',
}
PROFILE='selfhost_linux_stdio'
READ='linux.stdin.read';WRITE='linux.stdout.write';EFFECT='linux_io'
HELPER=r'''
def linux_stdio(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    loan_access(w, a)
    if get(w, 232) != 3 or n != 3 or t != 11 or bt != 2:
        return fail(w, 91)
    c = get(w, ARGS + 16)
    if variable(w, c) != 2:
        return fail(w, 91)
    if op == @linux.stdin.read@:
        if at != 7:
            return fail(w, 91)
    else:
        if at != 6 and at != 7:
            return fail(w, 91)
    bulk_range_guard(o, w, a, b, c)
    load_var(o, w, 6, a, 0)
    load_var(o, w, 0, b, 0)
    # add rsi,rax: derive address only after offset/count checked against extent.
    emit_bytes(o, w, 12976456, 3)
    load_var(o, w, 2, c, 0)
    number = op - @linux.stdin.read@
    # Fixed syscall0/fd0 or syscall1/fd1, no caller-supplied number or descriptor.
    emit_bytes(o, w, 184 + (number << 8), 5)
    emit_bytes(o, w, 191 + (number << 8), 5)
    # The two-byte ISA primitive. Result is the unchanged signed kernel word.
    # rcx/r11 are scratch; all live HIA values are in their original stack slots.
    emit_bytes(o, w, 1295, 2)
    return 0
'''
def strict(text,before,after):
 if text.count(before)!=1:raise AssertionError(('exact preimage',before[:100],text.count(before)))
 return text.replace(before,after,1)
def extension_source():
 words=dict(original.W)
 for name in (PROFILE,EFFECT,READ,WRITE):
  assert name not in words;words[name]=300+len(words)
 assert words[WRITE]==words[READ]+1
 source=original.SOURCE
 anchor='''            else:
                # A module identifier is a Core label, not a source dispatch
                # key. Only the two explicit historical output profiles above
                # select a different ABI; all other admitted names emit flat.
                next_token(s, w)
'''
 after='''            else:
                if get(w, 8) == @selfhost_linux_stdio@:
                    put(w, 232, 3)
                    expect(s, w, @selfhost_linux_stdio@)
                else:
                    # All other labels retain the original flat target.
                    next_token(s, w)
'''
 source=strict(source,anchor,after)
 anchor='''        flag = 1
        if token != @alloc@:
            if token < @read@ or token > @trap@:
                return fail(w, 65)
            flag = 2 << (token - @read@)
'''
 after='''        flag = 1
        if token == @linux_io@:
            if get(w, 232) != 3:
                return fail(w, 65)
            flag = 16
        else:
            if token != @alloc@:
                if token < @read@ or token > @trap@:
                    return fail(w, 65)
                flag = 2 << (token - @read@)
'''
 source=strict(source,anchor,after)
 source=strict(source,'def instruction_effects(op:u64) -> u64:\n','''def instruction_effects(op:u64) -> u64:
    if op == @linux.stdin.read@:
        return 28
    if op == @linux.stdout.write@:
        return 26
''')
 source=strict(source,'def operation_dispatch(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:\n','''def operation_dispatch(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if op == @linux.stdin.read@ or op == @linux.stdout.write@:
        return linux_stdio(o, w, op, n, a, b, at, bt, t)
''')
 source+=HELPER
 globals_=dict(vars(original));globals_['SOURCE']=source;globals_['W']=words
 function=types.FunctionType(original.source_program.__code__,globals_)
 return function(),words
class GroupConstants(ast.NodeTransformer):
 def __init__(self):self.groups=[]
 @staticmethod
 def byte(node):
  if not isinstance(node,ast.Expr) or not isinstance(node.value,ast.Call):return None
  n=node.value
  if not isinstance(n.func,ast.Name) or n.func.id!='emit' or n.keywords or len(n.args)!=3:return None
  a,b,v=n.args
  if not isinstance(a,ast.Name) or a.id!='o' or not isinstance(b,ast.Name) or b.id!='w':return None
  if not isinstance(v,ast.Constant) or type(v.value)is not int or not 0<=v.value<=255:return None
  return v.value
 def generic_visit(self,node):
  node=super().generic_visit(node)
  for field,value in ast.iter_fields(node):
   if not isinstance(value,list) or not value or not all(isinstance(n,ast.stmt) for n in value):continue
   out=[];i=0
   while i<len(value):
    j=i;values=[]
    while j<len(value) and len(values)<8:
     v=self.byte(value[j])
     if v is None:break
     values.append(v);j+=1
    if len(values)<2:out.append(value[i]);i+=1;continue
    word=sum(v<<(8*k) for k,v in enumerate(values))
    new=ast.Expr(value=ast.Call(func=ast.Name(id='emit_bytes',ctx=ast.Load()),args=[ast.Name(id='o',ctx=ast.Load()),ast.Name(id='w',ctx=ast.Load()),ast.Constant(word),ast.Constant(len(values))],keywords=[]))
    ast.copy_location(new,value[i]);out.append(new)
    self.groups.append({'line':value[i].lineno,'bytes':values,'little_word':word,'count':len(values),'before':[ast.dump(n,include_attributes=False) for n in value[i:j]],'after':ast.dump(new,include_attributes=False)})
    i=j
   setattr(node,field,out)
  return node
def build(text,grouped):
 tree=ast.parse(text);group=GroupConstants()
 if grouped:tree=group.visit(tree)
 ast.fix_missing_locations(tree);nodes=tree.body
 names=original._source_function_names(nodes)
 signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes};total=original.total_scalar_functions(nodes)
 functions=[]
 for n in nodes:
  b=original.Builder(n,names,signatures,total);b.statements(n.body)
  functions.append({'name':names[n.name],'params':[b.param(x) for x in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
 doc={'schema':'hepta.hia.program.v8','module':'selfhost','functions':functions}
 # Check original maxima explicitly before the existing compact verifier.
 def counts(d):return {'functions':len(d['functions']),'blocks':sum(len(f['blocks']) for f in d['functions']),'operations':sum(len(b['ops']) for f in d['functions'] for b in f['blocks'])}
 before=counts(doc)
 doc=original.compact_authoring_cfg(doc);stats=counts(doc)
 if stats['functions']>128 or stats['blocks']>1536 or stats['operations']>8192:raise ValueError(('unchanged compiler limits',stats))
 return render_assembly(doc),ast.unparse(tree)+'\n',{'pre_compaction':before,'counts':stats,'constant_groups':group.groups,'function_names':names}
def generated():
 return build(extension_source()[0],True)[0]
def main():
 import argparse
 parser=argparse.ArgumentParser(description='Generate the explicit fixed Linux stdio compiler')
 parser.add_argument('--check',action='store_true');args=parser.parse_args()
 target=ROOT/'examples/hia_bootstrap/selfhost_linux_stdio.hepta'
 text=generated()
 if args.check:
  if target.read_text()!=text:raise SystemExit('Linux stdio compiler source differs')
 else:target.write_text(text)
 print(json.dumps({'source':str(target.relative_to(ROOT)),'sha256':hashlib.sha256(text.encode()).hexdigest(),'bytes':len(text.encode()),'default_core_changed':False,'matching_cold':False,'whole':False},sort_keys=True))
if __name__=='__main__':main()

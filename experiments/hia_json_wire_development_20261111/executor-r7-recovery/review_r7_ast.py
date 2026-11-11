import ast
import copy
from hashlib import sha256
import json
from pathlib import Path

ROOT=Path('/tmp/hia-wire-e26e-controller')
def dump(node): return ast.dump(node,include_attributes=False)
def source(path):
 raw=path.read_bytes();module=ast.parse(raw)
 values={node.targets[0].id:node.value for node in module.body if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)}
 fields=eval(compile(ast.Expression(values['FIELDS']),'<fields>','eval'),{'MAGIC':int.from_bytes(b'HIAWIR02','little')})
 literals={name:ast.literal_eval(values[name]) for name in ('SOURCE','ENCODER')}
 definition=next(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name=='source_program')
 scope={'ast':ast,'FIELDS':fields,**literals,'format_program':lambda:''}
 exec(compile(ast.Module([copy.deepcopy(definition)],type_ignores=[]),'<source-program-only>','exec'),scope)
 program=ast.parse(scope['source_program']())
 outside=ast.Module([node for node in module.body if node is not definition],type_ignores=[])
 return {'raw':raw,'module':module,'outside':outside,'fields':fields,'literals':literals,'program':program}

before=source(ROOT/'base-22d-generator.py');after=source(ROOT/'r7-recovery-generator.py')
assert dump(before['outside'])==dump(after['outside'])
assert before['fields']==after['fields'] and before['literals']==after['literals']
assert [f.name for f in before['program'].body]==[f.name for f in after['program'].body]
changed=[a.name for a,b in zip(before['program'].body,after['program'].body) if dump(a)!=dump(b)]
assert set(changed)=={'ask','text_begin','normalize','text_byte','emit','commit_fragment','escaped'},changed

class Inverse(ast.NodeTransformer):
 def __init__(self):self.reads={};self.stores={}
 def visit_FunctionDef(self,node):
  self.function=node.name
  self.buffer_types={arg.arg:arg.annotation.id for arg in node.args.args if isinstance(arg.annotation,ast.Name)}
  node.body=self.collapse_stores(node.body) if node.name in {'ask','text_byte','emit'} else node.body
  return self.generic_visit(node)
 def collapse_stores(self,body):
  result=[];index=0
  while index<len(body):
   assignment=body[index]
   if not (isinstance(assignment,ast.Assign) and len(assignment.targets)==1 and isinstance(assignment.targets[0],ast.Name) and assignment.targets[0].id.startswith('wire_store_value_')):
    result.append(assignment);index+=1;continue
   name=assignment.targets[0].id;writes=body[index+1:index+9];assert len(writes)==8
   first=writes[0].value;assert isinstance(first,ast.Call)
   buffer=first.args[0];address=first.args[1]
   assert isinstance(buffer,ast.Name) and isinstance(address,ast.Constant) and type(address.value) is int
   for offset,statement in enumerate(writes):
    expected=ast.Expr(ast.Call(ast.Name('store',ast.Load()),[ast.Name(buffer.id,ast.Load()),ast.Constant(address.value+offset),ast.BinOp(ast.BinOp(ast.Name(name,ast.Load()),ast.RShift(),ast.Constant(offset*8)),ast.BitAnd(),ast.Constant(255))],[]))
    assert dump(statement)==dump(expected),(self.function,offset)
   occurrences=sum(isinstance(n,ast.Name) and n.id==name for statement in body for n in ast.walk(statement))
   assert occurrences==9,(self.function,name,occurrences)
   result.append(ast.Expr(ast.Call(ast.Name('put',ast.Load()),[buffer,address,assignment.value],[])))
   self.stores[self.function]=self.stores.get(self.function,0)+1
   index+=9
  return result
 def visit_BinOp(self,node):
  terms=[];cursor=node
  while isinstance(cursor,ast.BinOp) and isinstance(cursor.op,ast.BitOr):
   terms.append(cursor.right);cursor=cursor.left
  terms.reverse()
  if len(terms) not in (4,8) or not isinstance(cursor,ast.Constant) or cursor.value!=0:
   return self.generic_visit(node)
  buffer=None;start=None
  for index,term in enumerate(terms):
   if not (isinstance(term,ast.BinOp) and isinstance(term.op,ast.LShift) and isinstance(term.right,ast.Constant) and type(term.right.value) is int and term.right.value==index*8):return self.generic_visit(node)
   call=term.left
   if not (isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='byte' and len(call.args)==2 and not call.keywords and isinstance(call.args[0],ast.Name) and isinstance(call.args[1],ast.Constant) and type(call.args[1].value) is int):return self.generic_visit(node)
   if buffer is None:buffer=call.args[0].id;start=call.args[1].value
   if call.args[0].id!=buffer or call.args[1].value!=start+index:return self.generic_visit(node)
  kind=self.buffer_types.get(buffer)
  assert kind in ('readbuf','mutbuf'),(self.function,buffer,kind)
  name=('read64' if kind=='readbuf' else 'get') if len(terms)==8 else ('read32' if kind=='readbuf' else 'get32')
  self.reads[self.function]=self.reads.get(self.function,0)+1
  return ast.Call(ast.Name(name,ast.Load()),[ast.Name(buffer,ast.Load()),ast.Constant(start)],[])

old_inverse,new_inverse=Inverse(),Inverse()
old_recovered=old_inverse.visit(copy.deepcopy(before['program']))
new_recovered=new_inverse.visit(copy.deepcopy(after['program']))
assert dump(old_recovered)==dump(new_recovered)
assert new_inverse.stores=={'ask':7,'text_byte':1,'emit':1}
report={'schema':'hepta.hia.wire-r7-mechanical-ast-review.v1','scope':'EXACT_PUBLISHED_22D_VERSUS_RECOVERY_TEXT_NO_ORIGINAL_LOCAL_BYTE_OR_NATIVE_QUALIFICATION_CLAIM','base_generator_sha256':sha256(before['raw']).hexdigest(),'recovery_generator_sha256':sha256(after['raw']).hexdigest(),'generator_module_ast_outside_source_program_unchanged':True,'policy_source_encoder_literal_bytes_unchanged':True,'field_offsets_unchanged':True,'wire_function_count_without_unchanged_imported_formatter':len(before['program'].body),'wire_function_names_order_unchanged':True,'changed_functions':changed,'inverted_reads_before':old_inverse.reads,'inverted_reads_after':new_inverse.reads,'inverted_stores_after':new_inverse.stores,'inversion_checks':'Every expanded read has exact low-to-high address/shift order. Each expanded store evaluates one unique temporary, then has exactly eight ordered byte stores and no other temporary use. Reversing only these mechanical expansions yields identical complete wire-program ASTs.','complete_wire_program_ast_after_inverse_equal':True,'status':'PASS_SCOPED_STATIC_MECHANICAL_REVIEW'}
(ROOT/'r7-mechanical-ast-review.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))

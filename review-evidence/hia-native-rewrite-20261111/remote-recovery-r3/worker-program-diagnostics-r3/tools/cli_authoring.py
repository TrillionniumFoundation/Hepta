"""Development authoring only; CLI argument policy executes as HIA."""
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.hia_agent_edit_source_views import CopyBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions

def document(body,module):
 nodes=ast.parse(body).body;two_read=nodes[0].args.args[1].annotation.id=='readbuf';names={n.name:'f'+str(i+int(two_read)) for i,n in enumerate(nodes)}
 signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
 total=total_scalar_functions(nodes);functions=[]
 if two_read:
  params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
  functions.append(dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',blocks=[dict(id='b0',params=params,ops=[dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],attrs=dict(function=names[nodes[0].name])),dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))]))
 for n in nodes:
  b=CopyBuilder(n,names,signatures,total);b.statements(n.body)
  functions.append(dict(name=names[n.name],params=[b.param(p) for p in b.params],returns=[b.returns],effects=['read','write','trap'],entry='b0',blocks=b.blocks))
 return compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module=module,functions=functions))

def expanded(body,constants):
 class Expand(ast.NodeTransformer):
  def visit_Name(self,n):
   return ast.copy_location(ast.Constant(constants[n.id]),n) if isinstance(n.ctx,ast.Load) and n.id in constants else n
 return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.parse(body))))+'\n'

def profile(doc):
 return dict(functions=len(doc['functions']),blocks=sum(len(f['blocks']) for f in doc['functions']),ops=sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),max_blocks=max(len(f['blocks']) for f in doc['functions']),max_params=max(len(b['params']) for f in doc['functions'] for b in f['blocks']))

"""Bounded pure-read authoring for the exact DMS8 f0 source.

This is an authoring optimization, not a runtime authentication mechanism. It
keeps the whole original DSL and all runtime checks. Only f0-reachable functions
may use the facts established by the exact pinned f0 header guards: original
workspace >= 8192 bytes; source >= 320 bytes before other source-taking helpers.
Dynamic offsets, output reads and unknown buffer aliases retain short circuit.
"""
from __future__ import annotations
import ast
import hashlib
from tools.generate_hia_agent_namespace_objects import ObjectBuilder

SOURCE_SHA256='7fe09da5b8d59c14d1b5cd6fbc65b4c937677e410356d843a74affc62770d310'

def fixed_header_origins(source,nodes):
    # The source digest pins the actual guards, reader bodies and lack of buffer
    # rebinding/resizing. A changed source needs a new explicit proof/revision.
    if hashlib.sha256(source.encode('utf-8')).hexdigest()!=SOURCE_SHA256:
        raise ValueError('DMS fixed-header proof requires the exact reviewed source')
    if not nodes or nodes[0].name!='dms_entry':
        raise ValueError('DMS fixed-header proof requires the original f0')
    byname={n.name:n for n in nodes}
    if len(byname)!=len(nodes):raise ValueError('duplicate DMS symbol')
    origins={n.name:{a.arg:set() for a in n.args.args
                    if a.annotation.id in ('readbuf','mutbuf')} for n in nodes}
    origins['dms_entry']={'s':{'input'},'o':{'output'},'w':{'workspace'}}
    bindings=[]
    for node in nodes:
        for item in ast.walk(node):
            if isinstance(item,ast.Call) and isinstance(item.func,ast.Name) and item.func.id in byname:
                target=byname[item.func.id]
                if item.keywords or len(item.args)!=len(target.args.args):
                    raise ValueError('DMS buffer proof requires direct positional calls')
                for formal,actual in zip(target.args.args,item.args,strict=True):
                    if formal.annotation.id in ('readbuf','mutbuf'):
                        if not isinstance(actual,ast.Name) or actual.id not in origins[node.name]:
                            raise ValueError('DMS buffer proof requires an unchanged buffer parameter')
                        bindings.append((node.name,actual.id,item.func.id,formal.arg))
            if isinstance(item,ast.Name) and isinstance(item.ctx,ast.Store) and item.id in origins[node.name]:
                raise ValueError('DMS buffer parameter cannot be rebound')
    while True:
        old={n:{k:set(v) for k,v in bs.items()} for n,bs in origins.items()}
        for caller,actual,target,formal in bindings:
            origins[target][formal].update(origins[caller][actual])
        if origins==old:return origins,bindings

class FixedHeaderBuilder(ObjectBuilder):
    def __init__(self,node,names,signatures,total_calls,origins):
        self.source_function=node.name
        self.buffer_origins=origins[node.name]
        super().__init__(node,names,signatures,total_calls)

    def _scalar_type(self,e):
        if isinstance(e,ast.Name):
            value=self.env.get(e.id)
            return value[1] if value is not None else None
        if isinstance(e,ast.Constant):return 'bool' if type(e.value) is bool else 'u64'
        if isinstance(e,ast.BinOp):return self._scalar_type(e.left)
        if isinstance(e,(ast.Compare,ast.BoolOp)):return 'bool'
        if isinstance(e,ast.Call) and isinstance(e.func,ast.Name):
            if e.func.id in ('length','byte'):return 'u64'
            signature=self.signatures.get(e.func.id)
            return signature[1] if signature is not None else None
        return None

    def total_scalar_expression(self,e):
        if isinstance(e,ast.Call) and isinstance(e.func,ast.Name) and not e.keywords:
            name=e.func.id
            if name=='length' and len(e.args)==1 and isinstance(e.args[0],ast.Name) and e.args[0].id in self.buffer_origins:
                return True
            if name=='dms_length' and len(e.args)==1 and isinstance(e.args[0],ast.Name) and e.args[0].id=='s':
                return True
            if len(e.args)==2 and isinstance(e.args[0],ast.Name) and isinstance(e.args[1],ast.Constant) and type(e.args[1].value) is int:
                buf=e.args[0].id;at=e.args[1].value
                if name=='get' and buf=='w' and self.buffer_origins.get('w')=={'workspace'} and 0<=at<=8184:
                    return True
                # f0's first source length check must remain short circuit.
                if self.source_function!='dms_entry' and self.buffer_origins.get('s')=={'input'}:
                    if name=='read64' and buf=='s' and 0<=at<=312:return True
                    if name=='dms_read' and buf=='s' and 0<=at<=248:return True
        if isinstance(e,ast.BinOp) and isinstance(e.op,(ast.LShift,ast.RShift)) and isinstance(e.right,ast.Constant) and type(e.right.value) is int and 0<=e.right.value<64:
            return self._scalar_type(e.left)=='u64' and self.total_scalar_expression(e.left)
        return super().total_scalar_expression(e)

"""Offline HIA continuation authoring for the complete native build coordinator.

The original nine bodies, their closures and rejection helper are fixed inputs.
All business flow is emitted into HIA. With regions use separate HIA frames
sharing the original named cells; the runtime port supplies only the actual
CPython context-manager protocol, never a retained Python policy body.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from types import CodeType

from tools.hia_core_lowering_control import Function as _Function
from tools.hia_machine_plan_control import Compiler as _Compiler, OPS, PACK, COMPARE

ENTRIES=('_implementation_hash','validate_block_layout_plan','emit_program_machine',
         '_inspect_object','_read_artifact','_run_logged','_host',
         'compile_program_machine','build_program_machine','_reject')
WITH_REGION=250
RERAISE=251
DICT_UPDATE=253
MAPPING_PREPARE=254
MAPPING_CALL=255


class Compiler(_Compiler):
    def __init__(self,source):
        self.source,self.tree=source,ast.parse(source)
        self.lexical_codes={}
        def remember(code):
            for item in code.co_consts:
                if isinstance(item,CodeType):
                    key=(item.co_firstlineno,item.co_name)
                    if key in self.lexical_codes:
                        raise ValueError('ambiguous native-build lexical frame')
                    self.lexical_codes[key]=item
                    remember(item)
        remember(compile(source,'<native-build-lexical-layout>','exec'))
        self.imports={}
        for node in ast.walk(self.tree):
            if isinstance(node,ast.ImportFrom):
                if node.level!=1:raise ValueError('native-build import must be package-relative')
                self.imports.setdefault(node.module,set()).update(a.name for a in node.names)
        self.literals,self.literal_indices=[],{}
        self.functions,self.by_name=[],{}
        for node in self.tree.body:
            if isinstance(node,ast.Expr) and isinstance(node.value,ast.Constant) and type(node.value.value) is str:
                continue
            if not isinstance(node,ast.FunctionDef) or node.decorator_list:
                raise ValueError('unreviewed native-build policy declaration')
            function=Function(self,node.name,node)
            self.functions.append(function); self.by_name[node.name]=function
        if tuple(self.by_name)!=ENTRIES:
            raise ValueError('complete native-build entry inventory differs')
        index=0
        while index<len(self.functions):
            self.functions[index].compile(); index+=1
        for mode,function in enumerate(self.functions,1):function.mode=mode
        for function in self.functions:function.resolve()
        self._validate_calls()

    def literal(self,value):
        if type(value) is bytes:
            key=(bytes,value)
            if key not in self.literal_indices:
                self.literal_indices[key]=len(self.literals); self.literals.append(value)
            return self.literal_indices[key]
        return super().literal(value)

    def nested(self,parent,node,kind):
        function=Function(self,parent.name+':'+kind+':'+str(len(self.functions)),
                          node,parent=parent,kind=kind)
        self.functions.append(function)
        return function

    def region(self,parent,node):
        # All original named locals remain in the original physical order.
        # The region holds the same cells, including locals not yet assigned,
        # so a retained traceback sees subsequent binding changes as before.
        function=Function(self,parent.name+':with:'+str(len(self.functions)),
                          node,parent=parent,kind='with_region')
        self.functions.append(function)
        return function

    def _validate_calls(self):
        for fn in self.functions:
            for instruction in fn.instructions:
                if instruction['kind']!='effect' or instruction['opcode']!=OPS['CALL']:
                    continue
                raw,args=instruction['raw'],instruction['arguments']
                if len(raw)>=2 and raw[1] in (WITH_REGION,RERAISE,DICT_UPDATE,MAPPING_PREPARE,MAPPING_CALL):
                    continue
                if (len(raw)<2 or len(raw)!=2+raw[1] or len(args)!=1+raw[0]+raw[1]
                        or instruction['consume']!=args or len({r.slot for r in args})!=len(args)
                        or any(not r.temporary or r.slot in fn.cell_slots for r in args)):
                    raise ValueError('native-build CALL lacks unique consumed stack operands')


class Function(_Function):
    def __init__(self,compiler,name,node,*,parent=None,kind='function'):
        if kind=='with_region':
            empty=ast.FunctionDef(name='_with_region',args=ast.arguments(posonlyargs=[],args=[],
                vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),
                body=[],decorator_list=[])
            ast.copy_location(empty,node); ast.fix_missing_locations(empty)
            super().__init__(compiler,name,empty,parent=parent,kind='function')
            self.kind,self.node='with_region',node
            original={**parent.locals,**{key:pair[0] for key,pair in parent.captures.items()}}
            for local_name,outer in original.items():
                parent.cell_slots.add(outer.slot)
                own=self.slot(False)
                self.captures[local_name]=(own,outer)
            self.lexical_names=tuple(original)
            self.lexical_cells=()
            self.lexical_freevars=tuple(original)
            self.read_kinds={own.slot:parent.read_kinds[outer.slot]
                             for own,outer in self.captures.values()}
            return
        scanned=deepcopy(node)
        class ScopeScan(ast.NodeTransformer):
            def visit_FunctionDef(self,value):
                if value is scanned:return self.generic_visit(value)
                return ast.copy_location(ast.Assign(targets=[ast.Name(id=value.name,ctx=ast.Store())],
                    value=ast.Constant(None)),value)
        if kind=='function':scanned=ast.fix_missing_locations(ScopeScan().visit(scanned))
        if getattr(scanned,'args',None) and scanned.args.kwarg:
            scanned.args.kwonlyargs.append(scanned.args.kwarg)
            scanned.args.kw_defaults.append(None)
            scanned.args.kwarg=None
        super().__init__(compiler,name,scanned,parent=parent,kind=kind)
        self.node=node
        lexical_name={'generator':'<genexpr>','lambda':'<lambda>'}.get(kind,getattr(node,'name',None))
        code=compiler.lexical_codes[(node.lineno,lexical_name)]
        names=tuple(dict.fromkeys((*code.co_varnames,*code.co_cellvars)))
        if names[:len(self.parameters)]!=tuple(self.parameters):
            raise ValueError('native-build physical parameter order differs')
        self.locals,self.next_slot={},0
        self.temporary_slots,self.cell_slots=set(),set()
        handler_names={n.name for n in ast.walk(node) if isinstance(n,ast.ExceptHandler) and n.name}
        for local_name in names:
            slot=self.local(local_name)
            if local_name in handler_names:self.temporary_slots.add(slot.slot)
        for local_name in code.co_cellvars:self.cell_slots.add(self.locals[local_name].slot)
        for free_name in code.co_freevars:
            if parent is None:raise ValueError('native-build top-level entry has a free cell')
            outer=parent.variable(free_name)
            if outer is None:raise ValueError('native-build closure has no original cell')
            parent.cell_slots.add(outer.slot)
            self.captures[free_name]=(self.slot(False),outer)
        self.lexical_names,self.lexical_cells,self.lexical_freevars=names,code.co_cellvars,code.co_freevars
        self.read_kinds={ref.slot:(name,0) for name,ref in self.locals.items()}
        self.read_kinds.update({pair[0].slot:(name,1) for name,pair in self.captures.items()})

    def copy(self,value):
        if value.slot in self.read_kinds:
            name,role=self.read_kinds[value.slot]
            return self.effect('STORE',(value,),raw=(self.compiler.literal(name),role))
        return super().copy(value)

    def comp_scope(self,generators,*,generator=False):
        if generator:
            names={n.id for value in generators for n in ast.walk(value.target)
                   if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}
            return {name:self.local(name) for name in sorted(names)}
        return super().comp_scope(generators,generator=generator)

    def condition(self,node,yes,no):
        if isinstance(node,ast.Compare) and len(node.ops)>1:
            left=self.expression(node.left)
            for index,(operation,expression) in enumerate(zip(node.ops,node.comparators)):
                right=self.expression(expression); last=index==len(node.ops)-1
                value=self.effect('COMPARE',(left,right),raw=(COMPARE[type(operation).__name__],),
                                  consume=(left,right) if last else (left,))
                if last:self.truth(value,yes,no)
                else:
                    onward,failed=self.label(),self.label()
                    self.truth(value,onward,failed); self.mark(failed)
                    self.release((right,)); self.jump(no); self.mark(onward); left=right
            return
        return super().condition(node,yes,no)

    def expression(self,node):
        if isinstance(node,ast.BoolOp):
            result,done=self.slot(),self.label()
            for index,child in enumerate(node.values):
                self.store(result,self.expression(child))
                if index!=len(node.values)-1:
                    onward=self.label()
                    self.truth(self.copy(result),onward if isinstance(node.op,ast.And) else done,
                               done if isinstance(node.op,ast.And) else onward)
                    self.mark(onward); self.release((result,))
            self.mark(done); return result
        if isinstance(node,ast.Call):
            if any(isinstance(arg,ast.Starred) for arg in node.args):
                raise ValueError('native-build policy has no starred positional CALL')
            callee=self.expression(node.func)
            args=[self.expression(arg) for arg in node.args]
            if any(k.arg is None for k in node.keywords):
                if len(node.keywords)!=1 or node.keywords[0].arg is not None:
                    raise ValueError('native-build CALL has one final mapping only')
                positional=self.effect('PACK',raw=(PACK['Tuple'],),vector=args,consume=reversed(args))
                mapping=self.expression(node.keywords[0].value)
                prepared=self.effect('CALL',(callee,positional,mapping),raw=(0,MAPPING_PREPARE),consume=(mapping,))
                return self.effect('CALL',(callee,positional,prepared),raw=(0,MAPPING_CALL),
                                   consume=(callee,positional,prepared))
            keys=[self.compiler.literal(k.arg) for k in node.keywords]
            values=[self.expression(k.value) for k in node.keywords]
            return self.effect('CALL',(callee,*args,*values),raw=(len(args),len(keys),*keys),
                               consume=(callee,*args,*values))
        if isinstance(node,ast.Dict) and any(key is None for key in node.keys):
            result=self.effect('PACK',raw=(PACK['Dict'],),vector=())
            keys,values=[],[]
            def flush():
                if keys:
                    block=super(Function,self).expression(ast.Dict(keys=list(keys),values=list(values)))
                    self.effect('CALL',(result,block),raw=(0,DICT_UPDATE),destination=result,consume=(block,))
                    keys.clear(); values.clear()
            for key,value in zip(node.keys,node.values):
                if key is None:
                    flush(); mapping=self.expression(value)
                    self.effect('CALL',(result,mapping),raw=(0,DICT_UPDATE),destination=result,consume=(mapping,))
                else:
                    if not isinstance(key,ast.Constant) or type(key.value) is not str:
                        raise ValueError('native-build expanded dictionary key differs')
                    keys.append(key); values.append(value)
            flush(); return result
        return super().expression(node)

    def region_return(self,value,tag):
        marker=self.constant(tag)
        result=self.effect('PACK',raw=(PACK['Tuple'],),vector=(marker,value),consume=(value,marker))
        self.emit('return',value=result)

    def statements(self,statements):
        for node in statements:
            if isinstance(node,ast.ImportFrom):
                if node.level!=1 or node.module not in self.compiler.imports:
                    raise ValueError('native-build import outside fixed inventory')
                names=tuple(alias.name for alias in node.names)
                if any(name not in self.compiler.imports[node.module] for name in names):
                    raise ValueError('unreviewed import name')
                module=self.effect('IMPORT',raw=(0,self.compiler.literal(node.module),
                    *(self.compiler.literal(name) for name in names)))
                for alias in node.names:
                    value=self.effect('IMPORT',(module,),raw=(1,self.compiler.literal(alias.name)))
                    self.assign(ast.Name(id=alias.asname or alias.name,ctx=ast.Store()),value)
                self.release((module,))
            elif isinstance(node,ast.FunctionDef):
                if node.decorator_list or node.args.defaults or node.args.kw_defaults or node.args.kwarg or node.args.vararg:
                    raise ValueError('unreviewed native-build named closure')
                nested=self.compiler.nested(self,node,'function'); nested.compile()
                value=self.effect('FUNCTION',raw=(nested,0),vector=[p[1] for p in nested.captures.values()])
                self.assign(ast.Name(id=node.name,ctx=ast.Store()),value)
            elif isinstance(node,ast.Raise) and node.exc is None:
                self.effect('CALL',raw=(0,RERAISE),count=0)
            elif isinstance(node,ast.With):
                first=node.items[0]
                if first.optional_vars is not None and not isinstance(first.optional_vars,ast.Name):
                    raise ValueError('native-build with target must be one original local')
                body=node.body
                if len(node.items)>1:
                    nested_with=ast.With(items=node.items[1:],body=body,type_comment=None)
                    ast.copy_location(nested_with,node); body=[nested_with]
                region_node=ast.With(items=[first],body=body,type_comment=None); ast.copy_location(region_node,node)
                manager=self.expression(first.context_expr)
                nested=self.compiler.region(self,region_node); nested.compile()
                target=self.variable(first.optional_vars.id).slot if first.optional_vars else 65535
                envelope=self.effect('CALL',(manager,),raw=(nested,WITH_REGION,target),
                    vector=[p[1] for p in nested.captures.values()],consume=(manager,))
                acknowledged,result=self.effect('UNPACK',(envelope,),raw=(2,),count=2,consume=(envelope,))
                normal,suppressed,done=self.label(),self.label(),self.label()
                self.truth(acknowledged,normal,suppressed); self.mark(normal)
                tag,value=self.effect('UNPACK',(result,),raw=(2,),count=2,consume=(result,))
                returned,fallthrough=self.label(),self.label()
                self.truth(tag,returned,fallthrough); self.mark(returned)
                if self.kind=='with_region':self.region_return(value,1)
                else:self.emit('return',value=value)
                self.mark(fallthrough); self.release((value,)); self.jump(done)
                self.mark(suppressed); self.release((result,)); self.mark(done)
            elif isinstance(node,ast.Return) and self.kind=='with_region':
                self.region_return(self.expression(node.value) if node.value else self.constant(None),1)
            elif isinstance(node,ast.Continue):
                if not self.loop_stack:raise ValueError('continue has no native-build loop')
                self.jump(self.loop_stack[-1][0])
            else:
                super().statements((node,))

    def compile(self):
        if self.kind!='with_region':return super().compile()
        if getattr(self,'_compiled',False):return
        self._compiled=True
        self.statements(self.node.body)
        self.region_return(self.constant(None),0)


def compile_policy(source):
    return Compiler(source)

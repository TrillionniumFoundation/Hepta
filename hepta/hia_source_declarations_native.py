"""Selected native complete source syntax with an ownership-validated AST bridge.

Recognition runs in the composed actual HIA application; host objects, transport,
validation, namespace/tree-depth guards and semantic/module/runtime/build
chains remain foreign. This is not a whole-stack completion claim or sandbox.
"""
from __future__ import annotations
from dataclasses import dataclass
import ctypes
from pathlib import Path
import struct
from .ast import (Diagnostic, Enum, EnumVariant, Function, HeptaError, Import,
                  Param, Program, Span, Struct)
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_lexer_native import installed_source_lexer
from .hia_source_expressions_native import MAX_BYTES, MAX_NODES, _parse_application, materialize as expression_materialize
from .hia_source_statements_native import Block, _StatementArena, _children as statement_children, _error as statement_error

SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_declarations.hiaasm'
SCHEMA='hepta.hia.source-declarations-native.v1'
MAGIC=int.from_bytes(b'HIADEC01','little')
WORKSPACE=92416


@dataclass(frozen=True)
class _Generic:
    name: str
    bound: str


@dataclass(frozen=True)
class _Return:
    type: object
    mode: str
    lifetime: str | None


@dataclass
class ProgramBundle:
    name: str
    structs: list
    enums: list
    functions: list
    imports: list
    span: Span


class _DeclarationArena:
    MAGIC=MAGIC
    KINDS=_StatementArena.KINDS|set(range(48,65))
    TEXT=_StatementArena.TEXT|{49,50,51,52,53,54,55,56,57,58,59,61,62,63}
    TAGS=_StatementArena.TAGS|{52,53,54,57,60}
    QUALIFIED={49,50}
    ROOTS={48}
    ALLOW_EMPTY=True
    EMPTY_SPANS={48,64}

    @staticmethod
    def decode(index,kind,row,kids,rows,values,text):
        if kind in _StatementArena.KINDS:
            return _StatementArena.decode(index,kind,row,kids,rows,values,text)
        tags=[rows[c][0] for c in kids];args=[values[c] for c in kids];span=Span(*row[10:14])
        def require(ok):
            if not ok:raise ValueError('invalid HIA declaration graph metadata/children')
        def generics(allowed):
            cursor=0
            while cursor<len(tags) and tags[cursor] in allowed:cursor+=1
            return cursor
        if kind in (49,51,56,58,61,63):
            require(not kids);return text[index]
        if kind==55:
            require(not tags or tags==[56]);return _Generic(text[index],args[0] if args else 'Copy')
        if kind==62:
            require(all(1<=tag<=7 for tag in tags));return EnumVariant(text[index],args,span)
        if kind in (57,60):
            cursor=1 if tags and tags[0]==8 else 0
            require(len(tags)==cursor+1 and 1<=tags[-1]<=7 and row[9] in ((0,1,2,3) if kind==57 else (0,1,2)))
            lifetime=args[0] if cursor else None;typ=args[-1];mode=('value','read','mut','take')[row[9]]
            if kind==60:return _Return(typ,mode,lifetime)
            return Param(text[index],typ,mode,span,lifetime)
        if kind==59:
            require(len(tags)==1 and tags[0] in (16,17,18));return (text[index],args[0].value)
        if kind==64:
            require(not kids and row[10]==row[11]);return span
        if kind==50:
            require(not tags or tags==[51]);name=text[index];return Import(name,args[0] if args else name.split('::')[-1],span)
        if kind==52:
            cursor=generics((55,63));require(row[9] in (0,1,2,3) and all(tag==57 for tag in tags[cursor:]))
            gs=[value for tag,value in zip(tags[:cursor],args[:cursor]) if tag==55]
            bounds={g.name:g.bound for g in gs};require(all(value=='Copy' for value in bounds.values()))
            require(all(param.mode=='value' and param.lifetime is None for param in args[cursor:]))
            return Struct(text[index],args[cursor:],bool(row[9]&2),span,tuple(g.name for g in gs),bool(row[9]&1),
                tuple(value for tag,value in zip(tags[:cursor],args[:cursor]) if tag==63))
        if kind==53:
            cursor=generics((55,));require(row[9] in (0,1) and all(tag==62 for tag in tags[cursor:]))
            require(all(rows[c][2]==((1<<64)-1) for c in kids[:cursor]))
            return Enum(text[index],args[cursor:],tuple(g.name for g in args[:cursor]),bool(row[9]),span)
        if kind==54:
            require(row[9] in (0,1,2,4,5))
            cursor=generics((55,63));gs=[value for tag,value in zip(tags[:cursor],args[:cursor]) if tag==55]
            lives=tuple(value for tag,value in zip(tags[:cursor],args[:cursor]) if tag==63)
            params=[]
            while cursor<len(tags) and tags[cursor]==57:params.append(args[cursor]);cursor+=1
            require(cursor<len(tags) and tags[cursor]==60);ret=args[cursor];cursor+=1
            origin=None
            if cursor<len(tags) and tags[cursor]==61:origin=args[cursor];cursor+=1
            effects=[]
            while cursor<len(tags) and tags[cursor]==58:effects.append(args[cursor]);cursor+=1
            require(len(effects)==len(set(effects)))
            resources={}
            while cursor<len(tags) and tags[cursor]==59:
                key,value=args[cursor];require(key not in resources);resources[key]=value;cursor+=1
            extern=bool(row[9]&2)
            require(cursor==len(tags)-1 and tags[cursor]==(64 if extern else 32) and (not extern or not resources))
            body=None if extern else args[cursor].body;body_span=args[cursor] if extern else args[cursor].span
            return Function(text[index],params,ret.type,set(effects),body,bool(row[9]&1),extern,bool(row[9]&4),
                resources,span,body_span,tuple(g.name for g in gs),ret.mode,{g.name:g.bound for g in gs},origin,lives,ret.lifetime)
        if kind==48:
            cursor=0;name='main'
            if tags and tags[0]==49:name=args[0];cursor=1
            imports=[]
            while cursor<len(tags) and tags[cursor]==50:imports.append(args[cursor]);cursor+=1
            require(all(tag in (52,53,54) for tag in tags[cursor:]))
            return ProgramBundle(name,[v for t,v in zip(tags[cursor:],args[cursor:]) if t==52],
                [v for t,v in zip(tags[cursor:],args[cursor:]) if t==53],
                [v for t,v in zip(tags[cursor:],args[cursor:]) if t==54],imports,span)
        raise ValueError('invalid HIA declaration kind')

    @staticmethod
    def translate_extra_spans(node,origin):
        if isinstance(node,Function):
            p=node.body_span
            node.body_span=Span(origin.start+p.start,origin.start+p.end,origin.line+p.line-1,
                p.column+(origin.column-1 if p.line==1 else 0),origin.path)


def materialize(raw,wire,integer_value,literal_value):
    return expression_materialize(raw,wire,integer_value,literal_value,_extension=_DeclarationArena)


class NativeSourceDeclarations(NativeHiaJsonImage):
    def run(self,wire:bytes,*,max_depth:int,initial_kind:int=0,diagnostic_trace:bool=False):
        if (type(wire)is not bytes or len(wire)>MAX_BYTES or type(max_depth)is not int or not 1<=max_depth<=128
                or type(diagnostic_trace)is not bool or initial_kind not in (0,317,318)):
            raise ValueError('outside native HIA declaration profile')
        capacity=64+min(3*(len(wire)+1),MAX_NODES)*128+len(wire)
        source=ctypes.create_string_buffer(wire,max(1,len(wire)));output=ctypes.create_string_buffer(capacity)
        workspace=WORKSPACE+((len(wire)+7)>>3);state=ctypes.create_string_buffer(workspace)
        for offset,value in ((25040,max_depth),(8600,initial_kind),(8616,diagnostic_trace)):
            struct.pack_into('<Q',state,offset,value)
        result=self._entry(source,len(wire),output,capacity,state,workspace)
        if result==0xffffffff:return None,state.raw
        if not 64<=result<=capacity:raise RuntimeError('HIA declaration rejected declared buffers')
        return output.raw[:result],state.raw


def installed_source_declarations(path:str):
    image=_installed_json_image(path,SOURCE,SCHEMA,NativeSourceDeclarations)
    lexer=installed_source_lexer(str(Path(path).resolve(strict=True).parent/'source-lexer/manifest.json'))
    return image,lexer


def _error(state,wire,source,origin,nesting_limit,current_kind):
    code=struct.unpack_from('<Q',state,216)[0]
    if code<300 or struct.unpack_from('<Q',state,48)[0]:
        return statement_error(state,wire,source,origin,nesting_limit,current_kind)
    messages={301:'Expected a struct, enum, or function declaration',302:f"Expected '(', found {current_kind!r}",
        304:'Expected the ABI literal "C"',305:'Only the ABI literal "C" is supported',
        306:'Expected a type or lifetime parameter',307:'Expected a generic parameter',308:'Expected Copy or Owned constraint',
        310:'Expected C in repr(C)',311:'Only repr(C) is supported',312:f"Expected 'struct', found {current_kind!r}",
        313:'Expected a struct name',314:'Struct parameters do not accept ownership bounds',315:"Expected ',' or '}' after a struct field",
        316:f"Expected 'enum', found {current_kind!r}",317:'Expected an enum name',318:'Expected an enum variant',
        319:"Expected ',' or '}' after an enum variant",320:'Every function requires an explicit effects clause',321:'Expected an effect name',
        322:"Expected ',' or '}' after an effect",323:f"Expected 'fn', found {current_kind!r}",324:'Expected a function name',325:'Expected a parameter name',
        326:"Expected ',' or ')' after a parameter",327:"Functions require an explicit return type after '->'",328:"Expected a borrowed parameter after 'from'",
        329:"An extern function declaration must end with ';'",332:'Expected a resource constraint name',
        333:'Resource constraints require an integer, float, or boolean literal',334:"A resource constraint must end with ';'",
        335:f"Expected '}}', found {current_kind!r}",336:f"Expected ';', found {current_kind!r}",337:'Expected an import alias'}
    if code in (330,331):
        begin,end=struct.unpack_from('<2Q',state,90792)
        if not 0<=begin<end<=len(wire):raise RuntimeError('invalid HIA duplicate name range')
        name=wire[begin:end].decode('ascii')
        if not name.isidentifier():raise RuntimeError('invalid HIA duplicate name')
        message=f"Duplicate {'effect' if code==330 else 'resource constraint'} {name!r}"
    elif code in messages:message=messages[code]
    else:raise RuntimeError('invalid HIA declaration diagnostic')
    present=struct.unpack_from('<Q',state,8560)[0];a,z,line,col=struct.unpack_from('<4Q',state,8568 if present else 152)
    if not 0<=a<=z<=len(source) or line<1 or col<1:raise RuntimeError('invalid HIA declaration diagnostic span')
    tag={305:'E_PARSE_ABI',314:'E_PARSE_GENERIC',330:'E_PARSE_DUPLICATE',331:'E_PARSE_DUPLICATE'}.get(code,'E_PARSE')
    return HeptaError(Diagnostic(tag,message,Span(origin.start+a,origin.start+z,origin.line+line-1,
        col+(origin.column-1 if line==1 else 0),origin.path),phase='parse'))


def _children(node):
    if isinstance(node,ProgramBundle):return [*node.imports,*node.structs,*node.enums,*node.functions]
    if isinstance(node,Import):return []
    if isinstance(node,Struct):return node.fields
    if isinstance(node,Enum):return node.variants
    if isinstance(node,EnumVariant):return []
    if isinstance(node,Param):return []
    if isinstance(node,Function):return [*node.params,*(node.body or [])]
    return statement_children(node)


def parse_program(parser,native,lexer,nesting_limit):
    value=_parse_application(parser,native,lexer,nesting_limit,dict(max_depth=nesting_limit),WORKSPACE,
        _error,_DeclarationArena,_children)
    if not isinstance(value,ProgramBundle):raise ValueError('HIA program root mismatch')
    return Program(value.name,value.structs,value.functions,parser.source,parser.path,value.enums,value.imports)

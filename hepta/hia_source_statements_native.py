"""Selected HIA blocks/statements with an ownership-validated object bridge.

All statement, expression, type and token recognition executes in HIA. Host
objects, transport, validation, declarations, checker and module loader remain
foreign. The image is trusted local executable code, not a hostile-code sandbox.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from dataclasses import dataclass
from .ast import Diagnostic, Expr, HeptaError, MatchArm, Pattern, Span, Stmt
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_lexer_native import installed_source_lexer
from .hia_source_expressions_native import (MAX_BYTES, MAX_NODES, _error as expression_error,
    _parse_application, materialize as expression_materialize)

SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_statements.hiaasm'
SCHEMA='hepta.hia.source-statements-native.v1'
MAGIC=int.from_bytes(b'HIASTM01','little')
WORKSPACE=90688


@dataclass
class Block:
    body: list[Stmt]
    span: Span


class _StatementArena:
    MAGIC=MAGIC
    KINDS=set(range(32,45))
    TEXT={33,35,43,44}
    TAGS={33}
    ROOTS={32,*range(33,42)}

    @staticmethod
    def decode(index,kind,row,kids,rows,values,text):
        tags=[rows[c][0] for c in kids]; args=[values[c] for c in kids]
        def require(ok):
            if not ok: raise ValueError('invalid HIA statement children/metadata')
        span=Span(*row[10:14]); expr=lambda tag:16<=tag<=27
        if kind==32:
            require(all(33<=tag<=41 for tag in tags));return Block(args,span)
        if kind==44:
            require(not kids);return text[index]
        if kind==43:
            require(all(tag==44 for tag in tags))
            name=text[index]
            pieces=name.rsplit('::',1);require(len(pieces)==2)
            return Pattern(pieces[0],pieces[1],args,span)
        if kind==42:
            require(tags==[43,32]);return MatchArm(args[0],args[1].body,span)
        if kind==33:
            require(row[9] in (0,1) and (len(tags)==1 and expr(tags[0]) or len(tags)==2 and 1<=tags[0]<=7 and expr(tags[1])))
            name=text[index]
            data={'name':name,'mutable':bool(row[9]),'type':args[0] if len(args)==2 else None,'expr':args[-1]};name='let'
        elif kind==34:
            require(not tags or len(tags)==1 and expr(tags[0]));name='return';data={'expr':args[0] if args else None}
        elif kind==35:
            require(len(tags)==3 and expr(tags[0]) and expr(tags[1]) and tags[2]==32)
            name=text[index]
            data={'name':name,'start':args[0],'end':args[1],'body':args[2].body};name='for'
        elif kind==36:
            require(len(tags)==2 and expr(tags[0]) and tags[1]==32);name='while';data={'condition':args[0],'body':args[1].body}
        elif kind==37:
            require(len(tags) in (2,3) and expr(tags[0]) and all(tag==32 for tag in tags[1:]));name='if';data={'condition':args[0],'then':args[1].body,'else':args[2].body if len(args)==3 else []}
        elif kind==38:
            require(tags==[32]);name='unsafe';data={'body':args[0].body}
        elif kind==39:
            require(tags and expr(tags[0]) and all(tag==42 for tag in tags[1:]));name='match';data={'expr':args[0],'arms':args[1:]}
        elif kind==40:
            require(len(tags)==2 and tags[0] in (20,22,23) and expr(tags[1]));name='assign';data={'target':args[0],'expr':args[1]}
        elif kind==41:
            require(len(tags)==1 and expr(tags[0]));name='expr';data={'expr':args[0]}
        else:raise ValueError('invalid HIA statement kind')
        return Stmt(name,data,span)


def materialize(raw,wire,integer_value,literal_value):
    return expression_materialize(raw,wire,integer_value,literal_value,_extension=_StatementArena)


class NativeSourceStatements(NativeHiaJsonImage):
    def run(self,wire:bytes,*,max_depth:int,block:bool=True,initial_kind:int=0,diagnostic_trace:bool=False):
        if (type(wire)is not bytes or len(wire)>MAX_BYTES or type(max_depth)is not int
                or not 0<=max_depth<=128 or type(block)is not bool or type(diagnostic_trace)is not bool
                or initial_kind not in (0,317,318)):
            raise ValueError('outside native HIA statement profile')
        capacity=64+min(3*(len(wire)+1),MAX_NODES)*128+len(wire)
        source=ctypes.create_string_buffer(wire,max(1,len(wire)));output=ctypes.create_string_buffer(capacity)
        workspace=WORKSPACE+((len(wire)+7)>>3);state=ctypes.create_string_buffer(workspace)
        for offset,value in ((25040,max_depth),(25048,not block),(8600,initial_kind),(8616,diagnostic_trace)):
            struct.pack_into('<Q',state,offset,value)
        result=self._entry(source,len(wire),output,capacity,state,workspace)
        if result==0xffffffff:return None,state.raw
        if not 64<=result<=capacity:raise RuntimeError('HIA statement rejected declared buffers')
        return output.raw[:result],state.raw


def installed_source_statements(path:str):
    image=_installed_json_image(path,SOURCE,SCHEMA,NativeSourceStatements)
    lexer=installed_source_lexer(str(Path(path).resolve(strict=True).parent/'source-lexer/manifest.json'))
    return image,lexer


def _error(state,wire,source,origin,nesting_limit,current_kind):
    code=struct.unpack_from('<Q',state,216)[0]
    if code<200 or struct.unpack_from('<Q',state,48)[0]:
        return expression_error(state,wire,source,origin,nesting_limit,current_kind)
    messages={201:f"Expected '{{', found {current_kind!r}",202:"Unterminated block: expected '}'",
        203:'Expected a binding name',204:f"Expected '=', found {current_kind!r}",
        205:"A let statement must end with ';'",206:"A return statement must end with ';'",
        207:'Expected a loop variable',208:f"Expected 'in', found {current_kind!r}",
        209:'For loops require a half-open start..end range',210:"An expression statement must end with ';'",
        211:'Assignment requires a name, field, or index target',212:"An assignment must end with ';'",
        213:'Match patterns require Enum::Variant',214:"Expected a payload binding or '_'",
        215:f"Expected '=>', found {current_kind!r}",216:"Expected ',' or '}' after a match arm"}
    if code not in messages:raise RuntimeError('invalid HIA statement diagnostic')
    present=struct.unpack_from('<Q',state,8560)[0]
    a,z,line,col=struct.unpack_from('<4Q',state,8568 if present else 152)
    if not 0<=a<=z<=len(source) or line<1 or col<1:raise RuntimeError('invalid HIA statement diagnostic span')
    return HeptaError(Diagnostic('E_PARSE_ASSIGNMENT' if code==211 else 'E_PARSE',messages[code],
        Span(origin.start+a,origin.start+z,origin.line+line-1,col+(origin.column-1 if line==1 else 0),origin.path),phase='parse'))


def _children(node):
    if isinstance(node,Expr):return node.children
    if isinstance(node,Block):return node.body
    if isinstance(node,MatchArm):return [node.pattern,*node.body]
    if isinstance(node,Pattern):return []
    if isinstance(node,Stmt):
        result=[]
        for value in node.data.values():
            if isinstance(value,(Expr,Stmt,MatchArm)):result.append(value)
            elif isinstance(value,list):result.extend(item for item in value if isinstance(item,(Expr,Stmt,MatchArm)))
        return result
    raise ValueError('unexpected HIA syntax object')


def parse_statement(parser,native,lexer,max_depth,nesting_limit,*,block):
    result=_parse_application(parser,native,lexer,nesting_limit,dict(max_depth=max_depth,block=block),
        WORKSPACE,_error,_StatementArena,_children)
    if block:
        if not isinstance(result,Block):raise ValueError('HIA block root mismatch')
        return result.body,result.span
    if not isinstance(result,Stmt):raise ValueError('HIA statement root mismatch')
    return result

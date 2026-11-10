"""Whole-source HIA grammar candidate, with lexical/AST object transport.

Grammar, namespace and depth decisions are native; this module only encodes
validated tokens and materializes typed arena records. Default is not switched.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from .ast import (Diagnostic,HeptaError,Type,Span,Program,Import,Struct,Enum,
                  EnumVariant,Function,Param,Expr,Stmt,Pattern,MatchArm)
from .lexer import Token
from .hia_type_parser_native import KINDS,MAGIC
from .hia_json_preflight_native import NativeHiaJsonImage,_installed_json_image

SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_parser.hiaasm'
SCHEMA='hepta.hia.source-parser-native.v1'
WORKSPACE=3158016
MAX_TOKENS=4096
MESSAGES={1:'Expected a name',2:"Expected a name after '::'",
3:"Stored references require an explicit lifetime: read 'a T",
4:"A raw pointer type requires 'const' or 'mut'",5:"Expected '>' after a generic element type",
6:'Array lengths must be nonnegative integer literals',7:'Syntax exceeds the bootstrap nesting limit of 96',
10:'Expected a struct, enum, or function declaration',11:'Expected an import alias',12:'Expected a field name',
13:'Expected a generic parameter',14:'Expected a type or lifetime parameter',15:'Expected Copy or Owned constraint',
16:'Struct parameters do not accept ownership bounds',17:'Every function requires an explicit effects clause',
18:'Expected an effect name',20:"Expected ',' or '}' after an effect",21:'Expected a resource constraint name',
23:'Resource constraints require an integer, float, or boolean literal',24:"A resource constraint must end with ';'",
25:'Expected a struct name',26:"Expected ',' or '}' after a struct field",27:'Expected an enum name',
28:'Expected an enum variant',29:"Expected ',' or '}' after an enum variant",30:'Expected the ABI literal "C"',
31:'Only the ABI literal "C" is supported',32:'Expected a function name',33:'Expected a parameter name',
34:"Expected ',' or ')' after a parameter",35:"Functions require an explicit return type after '->'",
36:"Expected a borrowed parameter after 'from'",37:"An extern function declaration must end with ';'",
38:"Unterminated block: expected '}'",39:'Expected a binding name',40:"A let statement must end with ';'",
41:"A return statement must end with ';'",42:'Expected a loop variable',43:'For loops require a half-open start..end range',
44:'Match patterns require Enum::Variant',45:"Expected a payload binding or '_'",46:"Expected ',' or '}' after a match arm",
47:'Assignment requires a name, field, or index target',48:"An assignment must end with ';'",
49:"An expression statement must end with ';'",50:'Only ordinary named function calls are supported',
51:"Expected a name or '<' after '::'",52:'Only one explicit generic argument list is supported',
53:"Expected ',' or '}' after a field value",54:'Strings are supported only as the ABI literal "C"',
55:'Expected an expression',57:'Syntax tree exceeds the bootstrap nesting limit of 96',
58:'Expected C in repr(C)',59:'Only repr(C) is supported'}
CODES={7:'E_PARSE_DEPTH',16:'E_PARSE_GENERIC',19:'E_PARSE_DUPLICATE',22:'E_PARSE_DUPLICATE',
       31:'E_PARSE_ABI',47:'E_PARSE_ASSIGNMENT',54:'E_PARSE_STRING',56:'E_PARSE_NAMESPACE',57:'E_PARSE_DEPTH'}


def packet(parser):
    tokens=parser.tokens
    if (not 0<len(tokens)<=MAX_TOKENS or not 0<=parser.position<len(tokens)
            or not 0<=parser.depth<=96 or parser.qualified_expressions):
        raise ValueError('outside native whole-source parser token/state profile')
    rows=bytearray();payload=bytearray()
    for token in tokens:
        begin=len(payload)
        if type(token.value) is str:payload.extend(token.value.encode('utf-8'))
        span=token.span
        rows.extend(struct.pack('<7Q',KINDS[token.kind],span.start,span.end,span.line,span.column,begin,len(payload)))
    wire=struct.pack('<6Q',MAGIC,len(tokens),parser.position,parser.depth,48+len(rows),len(payload))+rows+payload
    if len(wire)>1<<20:raise ValueError('outside native whole-source parser byte profile')
    return wire


class Arena:
    def __init__(self,raw,parser):
        if len(raw)<128:raise RuntimeError('short native source parser header')
        h=struct.unpack_from('<16Q',raw)
        magic,count,splits,position,virtual,root,error,begin,end,arg,arg1,ref,*reserved=h
        if magic!=MAGIC+1 or len(raw)!=128+count*128+splits*16:
            raise RuntimeError('invalid native source parser result size')
        self.parser=parser;self.original=list(parser.tokens);self.split_ids=set()
        self.rows=[None]+[struct.unpack_from('<16Q',raw,128+i*128) for i in range(count)]
        self.memo={};self.active=set();self.header=h
        previous=-1;shift=0
        for at in range(128+count*128,len(raw),16):
            index,kind=struct.unpack_from('<2Q',raw,at)
            if not (previous<index<len(self.original) and kind in (KINDS['>>'],KINDS['>='])
                    and KINDS[self.original[index].kind]==kind):
                raise RuntimeError('invalid native whole-source split action')
            previous=index;self.split_ids.add(index);old=self.original[index];s=old.span
            parser.tokens[index+shift:index+shift+1]=[
                Token('>','>',Span(s.start,s.start+1,s.line,s.column,s.path)),
                Token(old.kind[1],old.kind[1],Span(s.start+1,s.end,s.line,s.column+1,s.path))]
            shift+=1
        if position>=len(self.original) or virtual not in (0,KINDS['>'],KINDS['=']):
            raise RuntimeError('invalid native source parser cursor')
        parser.position=position+sum(i<position for i in self.split_ids)+(1 if virtual else 0)
        rootrow=self.row(root,20)
        for q in self.items(rootrow[8]):
            row=self.row(q,4)
            parser.qualified_expressions.append((self.name(row[3]),self.span(q)))
        if error:
            message=MESSAGES.get(error)
            if error==8:
                name=self.value(arg);message=f'{name} requires exactly one element type: {name}<T>'
            elif error==9:
                names={v:k for k,v in KINDS.items()}
                message=f'Expected {names[arg]!r}, found {self.token(begin).kind!r}'
            elif error==19:message=f'Duplicate effect {self.value(arg)!r}'
            elif error==22:message=f'Duplicate resource constraint {self.value(arg)!r}'
            elif error==56:
                q=self.row(ref,4);message=f'Qualified name {self.name(q[3])} requires a declared import or enum namespace'
            if message is None:raise RuntimeError('invalid native source grammar error code')
            a=self.token(begin).span;b=self.token(end).span
            raise HeptaError(Diagnostic(CODES.get(error,'E_PARSE'),message,
                Span(a.start,b.end,a.line,a.column,a.path),phase='parse'))
        self.root=root

    def row(self,index,tag=None):
        if not 1<=index<len(self.rows):raise RuntimeError('invalid native source arena reference')
        r=self.rows[index]
        if tag is not None and r[0]!=tag:raise RuntimeError('invalid native source arena record tag')
        return r

    def token(self,mark):
        index,half=divmod(mark,2)
        if index>=len(self.original) or (half and index not in self.split_ids):
            raise RuntimeError('invalid native source span mark')
        t=self.original[index]
        if index not in self.split_ids:return t
        s=t.span
        if half:return Token(t.kind[1],t.kind[1],Span(s.start+1,s.end,s.line,s.column+1,s.path))
        return Token('>','>',Span(s.start,s.start+1,s.line,s.column,s.path))

    def value(self,ref):
        if not ref:return None
        return self.token(ref-1).value

    def span(self,index):
        r=self.row(index);a=self.token(r[1]).span;b=self.token(r[2]).span
        return Span(a.start,b.end,a.line,a.column,a.path)

    def items(self,index):
        seen=set();result=[]
        while index:
            if index in seen:raise RuntimeError('cycle in native source list')
            seen.add(index);r=self.row(index,1);result.append(r[3]);index=r[4]
        return result

    def parts(self,index):
        seen=set();result=[]
        while index:
            if index in seen:raise RuntimeError('cycle in native source path')
            seen.add(index);r=self.row(index,2);result.append(self.value(r[3]));index=r[4]
        return result

    def name(self,index):return '::'.join(self.parts(index))
    def strings(self,index):return [self.value(i) for i in self.items(index)]
    def objects(self,index):return [self.build(i) for i in self.items(index)]
    def body(self,index):return self.build(index) if index else []
    def parameters(self,index):
        r=self.row(index,5)
        names=tuple(self.strings(r[4]));life=tuple(self.strings(r[5]));bounds={}
        for item in self.items(r[6]):
            b=self.row(item,6);bounds[self.value(b[3])]=self.value(b[4]) if b[4] else 'Copy'
        return names,bounds,life

    def build(self,index):
        if not index:return None
        if index in self.memo:return self.memo[index]
        if index in self.active:raise RuntimeError('cycle in native source AST')
        self.active.add(index);r=self.row(index);tag=r[0];result=None
        if tag==10:result=Type(self.name(r[3]),tuple(self.objects(r[4])),lifetimes=tuple(self.strings(r[5])))
        elif tag in (11,12):result=Type('array' if tag==11 else 'slice',(self.build(r[3]),),self.value(r[4]) if tag==11 else None)
        elif tag in (13,14):result=Type('raw_const' if tag==13 else 'raw_mut',(self.build(r[3]),))
        elif tag in (15,16):result=Type('ref_read' if tag==15 else 'ref_mut',(self.build(r[3]),),lifetimes=(self.value(r[4]),))
        elif tag==20:result=Program(self.name(r[3]) if r[3] else 'main',self.objects(r[5]),self.objects(r[7]),self.parser.source,self.parser.path,self.objects(r[6]),self.objects(r[4]))
        elif tag==21:result=Import(self.name(r[3]),self.value(r[4]),self.span(index))
        elif tag==22:
            names,bounds,life=self.parameters(r[6]);result=Struct(self.value(r[3]),self.objects(r[4]),bool(r[5]),self.span(index),names,bool(r[7]),life)
        elif tag==23:
            names,bounds,life=self.parameters(r[5]);result=Enum(self.value(r[3]),self.objects(r[4]),names,bool(r[6]),self.span(index))
        elif tag==24:
            names,bounds,life=self.parameters(r[10]);resources={}
            for item in self.items(r[9]):
                v=self.row(item,7);resources[self.value(v[3])]=self.value(v[5]) if v[4] in (3,4) else v[4]==KINDS['true']
            body=self.body(r[7]) if r[7] else None
            end=self.span(index)
            if r[7]:body_span=self.span(r[7])
            else:
                e=self.token(r[2]).span;body_span=Span(e.start,e.start,e.line,e.column,e.path)
            result=Function(self.value(r[3]),self.objects(r[4]),self.build(r[5]),set(self.strings(r[6])),body,
                bool(r[8]&1),bool(r[8]&2),bool(r[8]&4),resources,end,body_span,names,
                ('value','read','mut')[r[11]],bounds,self.value(r[12]),life,self.value(r[13]))
        elif tag==25:result=Param(self.value(r[3]),self.build(r[4]),('value','read','mut','take')[r[5]],self.span(index),self.value(r[6]))
        elif tag==26:result=EnumVariant(self.value(r[3]),self.objects(r[4]),self.span(index))
        elif tag==27:
            parts=self.parts(r[3]);result=Pattern('::'.join(parts[:-1]),parts[-1],self.strings(r[4]),self.span(index))
        elif tag==28:result=MatchArm(self.build(r[3]),self.body(r[4]),self.span(index))
        elif tag==30:result=self.objects(r[3])
        elif 40<=tag<=51:
            name={40:'int',41:'float',42:'bool',43:'unary',44:'name',45:'call',46:'index',47:'field',48:'cast',49:'binary',50:'struct',51:'array'}[tag]
            value=None
            if tag in (40,41,43,47,49):value=self.value(r[3])
            elif tag==42:value=bool(r[3])
            elif tag in (44,45):value=self.name(r[3])
            elif tag==48:value=self.build(r[3])
            elif tag==50:value={'name':self.name(r[3]),'fields':self.strings(r[6])}
            result=Expr(name,value,self.objects(r[5]),self.span(index),tuple(self.objects(r[4])))
        elif 60<=tag<=68:
            name={60:'let',61:'return',62:'for',63:'while',64:'if',65:'unsafe',66:'match',67:'assign',68:'expr'}[tag]
            if tag==60:data={'name':self.value(r[3]),'type':self.build(r[4]),'mutable':bool(r[5]),'expr':self.build(r[6])}
            elif tag==61:data={'expr':self.build(r[3])}
            elif tag==62:data={'name':self.value(r[3]),'start':self.build(r[4]),'end':self.build(r[5]),'body':self.body(r[6])}
            elif tag==63:data={'condition':self.build(r[3]),'body':self.body(r[4])}
            elif tag==64:data={'condition':self.build(r[3]),'then':self.body(r[4]),'else':self.body(r[5])}
            elif tag==65:data={'body':self.body(r[3])}
            elif tag==66:data={'expr':self.build(r[3]),'arms':self.objects(r[4])}
            elif tag==67:data={'target':self.build(r[3]),'expr':self.build(r[4])}
            else:data={'expr':self.build(r[3])}
            result=Stmt(name,data,self.span(index))
        else:raise RuntimeError('invalid native source AST tag')
        self.active.remove(index);self.memo[index]=result
        return result


class NativeSourceParser(NativeHiaJsonImage):
    def parse(self,parser,wire=None):
        if wire is None:wire=packet(parser)
        s=ctypes.create_string_buffer(wire,len(wire))
        capacity=128+(5*len(parser.tokens)+64)*128+len(parser.tokens)*16
        o=ctypes.create_string_buffer(capacity);w=ctypes.create_string_buffer(WORKSPACE)
        size=self._entry(s,len(wire),o,capacity,w,WORKSPACE)
        if not 128<=size<=capacity:raise RuntimeError('native source parser rejected declared buffers: '+hex(size))
        arena=Arena(o.raw[:size],parser)
        return arena.build(arena.root)


def installed_source_parser(path):return _installed_json_image(path,SOURCE,SCHEMA,NativeSourceParser)

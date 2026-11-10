"""Explicit HIA type-grammar candidate; token/object transport is still foreign.

The byte ABI consumes validated lexical tokens, not untrusted source directly.
All grammar decisions and split actions are made by HIA. The operator-only
selector leaves the default grammar unchanged.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from .ast import Type, Span
from .lexer import Token
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_lexer_native import KEYWORD_ORDER, PAIR_ORDER

SOURCE = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_type_parser.hiaasm'
MAGIC = 3549479791681612104
WORKSPACE = 9472
SCHEMA = 'hepta.hia.type-parser-native.v1'
MAX_TOKENS = 4096
KINDS = {'EOF':0, 'IDENT':1, 'LIFETIME':2, 'INT':3, 'FLOAT':4, 'STRING':5}
KINDS.update({name:128+i for i,name in enumerate(KEYWORD_ORDER)})
KINDS.update({name:512+i for i,name in enumerate(PAIR_ORDER)})
KINDS.update({name:256+ord(name) for name in '{}()[],:;=+-*/%!<>.&|^'})


def packet(tokens, start=0, depth=0):
    """Mechanical lexical-row transport, not a host grammar recognizer."""
    if not (0<len(tokens)<=MAX_TOKENS and 0<=start<len(tokens) and 0<=depth<=96):
        raise ValueError('outside native type parser token/depth profile')
    rows = bytearray(); payload=bytearray()
    for token in tokens:
        begin=len(payload)
        if token.kind in ('IDENT','LIFETIME'):
            payload.extend(token.value.encode('utf-8'))
        span=token.span
        rows.extend(struct.pack('<7Q',KINDS[token.kind],span.start,span.end,span.line,span.column,begin,len(payload)))
    result=struct.pack('<6Q',MAGIC,len(tokens),start,depth,48+len(rows),len(payload))+rows+payload
    if len(result)>1<<20:raise ValueError('outside native type parser byte profile')
    return result


def materialize(raw, parser):
    """Build Type objects from a typed arena; never inspect source grammar."""
    if len(raw)<80:raise RuntimeError('short native type parser result')
    count,split_count,position,virtual,root,error,error_pos,error_virtual,expected,special=struct.unpack_from('<10Q',raw)
    if len(raw)!=80+count*64+split_count*16:
        raise RuntimeError('invalid native type parser result size')
    original=list(parser.tokens); split_ids=[]; shifted=0
    for at in range(80+count*64,len(raw),16):
        index,kind=struct.unpack_from('<2Q',raw,at)
        if index>=len(original) or kind not in (KINDS['>>'],KINDS['>=']) or original[index].kind not in ('>>','>=') or KINDS[original[index].kind]!=kind or (split_ids and index<=split_ids[-1]):
            raise RuntimeError('invalid native type split action')
        split_ids.append(index)
        old=original[index];s=old.span
        parser.tokens[index+shifted:index+shifted+1]=[
            Token('>','>',Span(s.start,s.start+1,s.line,s.column,s.path)),
            Token(old.kind[1],old.kind[1],Span(s.start+1,s.end,s.line,s.column+1,s.path))]
        shifted+=1
    if position>=len(original) or virtual not in (0,KINDS['>'],KINDS['=']):
        raise RuntimeError('invalid native type cursor')
    parser.position=position+sum(index<position for index in split_ids)+(1 if virtual else 0)
    if error:
        if (error_pos,error_virtual)!=(position,virtual):raise RuntimeError('inconsistent native type error cursor')
        messages={1:'Expected a name',2:"Expected a name after '::'",
            3:"Stored references require an explicit lifetime: read 'a T",
            4:"A raw pointer type requires 'const' or 'mut'",
            5:"Expected '>' after a generic element type",
            6:'Array lengths must be nonnegative integer literals',
            7:'Syntax exceeds the bootstrap nesting limit of 96'}
        if error==8:
            if special>=len(original):raise RuntimeError('invalid native type special name')
            name=original[special].value
            parser._error(f'{name} requires exactly one element type: {name}<T>')
        if error==9:
            names={value:key for key,value in KINDS.items()}
            parser._error(f'Expected {names[expected]!r}, found {parser.current.kind!r}')
        if error not in messages:raise RuntimeError('invalid native type error code')
        parser._error(messages[error],code='E_PARSE_DEPTH' if error==7 else 'E_PARSE')
    if not 1<=root<=count:raise RuntimeError('invalid native type root')
    rows=[None]+[struct.unpack_from('<8Q',raw,80+i*64) for i in range(count)]
    seen=set()
    def visit(index):
        if not 1<=index<=count or index in seen:raise RuntimeError('invalid native type arena edge')
        seen.add(index);row=rows[index]
        if row[1]>=len(original):raise RuntimeError('invalid native type token index')
        return row
    def items(index,tag):
        values=[]
        while index:
            row=visit(index)
            if row[0]!=tag:raise RuntimeError('invalid native type auxiliary tag')
            values.append(original[row[1]].value);index=row[6]
        return values
    def build(index):
        tag,token,names,args,lifetimes,element,sibling,reserved=visit(index)
        life=tuple(items(lifetimes,8))
        if tag==0:
            name='::'.join(items(names,7));children=[]
            while args:
                children.append(build(args));args=rows[args][6]
            return Type(name,tuple(children),lifetimes=life)
        names_by_tag={1:'slice',2:'array',3:'raw_const',4:'raw_mut',5:'ref_read',6:'ref_mut'}
        if tag not in names_by_tag:raise RuntimeError('invalid native type node tag')
        return Type(names_by_tag[tag],(build(element),),original[token].value if tag==2 else None,lifetimes=life)
    result=build(root)
    if len(seen)!=count:raise RuntimeError('orphan native type arena nodes')
    return result


class NativeTypeParser(NativeHiaJsonImage):
    def parse_type(self,parser,wire=None):
        if wire is None:wire=packet(parser.tokens,parser.position,parser.depth)
        source=ctypes.create_string_buffer(wire,len(wire))
        capacity=80+len(parser.tokens)*144
        output=ctypes.create_string_buffer(capacity)
        state=ctypes.create_string_buffer(WORKSPACE)
        size=self._entry(source,len(wire),output,capacity,state,WORKSPACE)
        if not 80<=size<=capacity:raise RuntimeError('native type parser rejected declared buffers')
        return materialize(output.raw[:size],parser)


def installed_type_parser(path: str) -> NativeTypeParser:
    return _installed_json_image(path,SOURCE,SCHEMA,NativeTypeParser)

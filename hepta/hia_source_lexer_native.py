"""Operator-selected HIA source token recognition, with a Python value bridge.

The actual HIA image scans source, comments, identifiers, operator/number
grammar, UTF-8 positions and integer magnitudes. Python constructs Token/Span
and integer objects and converts finite floats. This is not the source
parser, a compiler default switch, or a whole-frontend rewrite claim.
"""
from __future__ import annotations
import ctypes
import math
from pathlib import Path
import struct
from .ast import Diagnostic,HeptaError,Span
from .hia_json_preflight_native import NativeHiaJsonImage,_installed_json_image

SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_lexer.hiaasm'
SCHEMA='hepta.hia.source-lexer-native.v2'
MAX_BYTES=8<<20
MAX_TOKENS=1<<20
KEYWORD_ORDER=('as','const','effects','else','enum','export','extern','false','fn',
    'for','if','import','in','let','match','module','move','mut','pub','raw','read',
    'repr','resources','return','struct','take','true','unsafe','while')
PAIR_ORDER=('->','..','==','!=','<=','>=','&&','||','<<','>>','::','=>')
ERRORS={
    1:('E_LEX_COMMENT','Unterminated block comment'),
    2:('E_LEX_NUMBER','Misplaced numeric separator'),
    3:('E_LEX_NUMBER','Expected digits without a trailing separator'),
    4:('E_LEX_NUMBER','Invalid numeric digit or unsupported literal suffix'),
    5:('E_LEX_NUMBER','Numeric literal exceeds the bootstrap limit of 4096 digits'),
    6:('E_LEX_STRING_ESCAPE','ABI strings do not support escape sequences'),
    7:('E_LEX_STRING','ABI strings must remain on one line'),
    8:('E_LEX_STRING','Unterminated string literal'),
    9:('E_LEX_CHARACTER','A lifetime requires an ASCII identifier after apostrophe'),
}


def _error(code,message,span):
    raise HeptaError(Diagnostic(code,message,span,phase='lex'))


def materialize(source,path,wire,raw,integer_value):
    """Bridge a native token table; no host token recognition is performed."""
    from .lexer import Token
    if len(raw)%56:raise RuntimeError('invalid native source token table size')
    result=[];last=0
    for offset in range(0,len(raw),56):
        kind,start,end,line,column,begin,finish=struct.unpack_from('<7Q',raw,offset)
        if not (last<=start<=end<=len(source) and 0<=begin<=finish<=len(wire)
                and line>=1 and column>=1):
            raise RuntimeError('invalid native source token span')
        span=Span(start,end,line,column,path);last=end
        value=wire[begin:finish].decode('utf-8')
        if kind==0:
            name='EOF';value=None
            if offset+56!=len(raw):raise RuntimeError('native source EOF must be final')
        elif kind==1:name='IDENT'
        elif kind==2:name='LIFETIME'
        elif kind==3:
            name='INT';value=integer_value(wire[begin:finish])
        elif kind==4:
            name='FLOAT';literal=value.replace('_','')
            try:
                value=float(literal)
            except (ValueError,OverflowError):_error('E_LEX_NUMBER','Invalid numeric literal',span)
            if not math.isfinite(value):
                _error('E_LEX_NUMBER','Floating-point literal must be finite',span)
        elif kind==5:name='STRING'
        elif 128<=kind<128+len(KEYWORD_ORDER):name=KEYWORD_ORDER[kind-128]
        elif 512<=kind<512+len(PAIR_ORDER):name=PAIR_ORDER[kind-512]
        elif 256<=kind<384 and chr(kind-256) in '{}()[],:;=+-*/%!<>.&|^':name=chr(kind-256)
        else:raise RuntimeError('invalid native source token kind')
        result.append(Token(name,value,span))
    if not result or result[-1].kind!='EOF':raise RuntimeError('native source tokens omit EOF')
    return result


class NativeSourceLexer(NativeHiaJsonImage):
    def integer_value(self,wire: bytes):
        """Only object materialization is foreign; literal parsing is HIA."""
        if type(wire) is not bytes:raise TypeError('HIA integer parser requires bytes')
        if len(wire)>8192:raise ValueError('outside native source integer byte profile')
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(2048)
        state=ctypes.create_string_buffer(2176)
        struct.pack_into('<Q',state,120,1)
        size=self._entry(source,len(wire),output,2048,state,2176)
        if size==0xffffffff:raise ValueError('invalid native source integer literal')
        if not (1<=size<=2048):raise RuntimeError('native source integer rejected declared buffers')
        magnitude=output.raw[:size]
        if size>1 and magnitude[-1]==0:raise RuntimeError('non-minimal native integer magnitude')
        return int.from_bytes(magnitude,'little')

    def tokenize(self,source: str,path: str='<input>'):
        if type(source) is not str:raise TypeError('HIA source lexer requires str')
        try:wire=source.encode('utf-8')
        except UnicodeEncodeError as error:
            raise ValueError('outside native source lexer scalar Unicode profile') from error
        if len(wire)>MAX_BYTES:raise ValueError('outside native source lexer 8 MiB profile')
        source_buffer=ctypes.create_string_buffer(wire,max(1,len(wire)))
        capacity=min(len(source)+1,MAX_TOKENS)*56
        output=ctypes.create_string_buffer(capacity)
        state=ctypes.create_string_buffer(128)
        status=self._entry(source_buffer,len(wire),output,capacity,state,128)
        if status==0xffffffff:
            code=struct.unpack_from('<Q',state,48)[0]
            start,line,column=struct.unpack_from('<3Q',state,64)
            end=struct.unpack_from('<Q',state,112)[0]
            if code==12:raise OverflowError('native source lexer exceeds 1M-token profile')
            if code==11:raise RuntimeError('native source lexer rejected scalar UTF-8')
            if not (0<=start<=end<=len(source)):raise RuntimeError('invalid native source error span')
            if code==10:kind,message='E_LEX_CHARACTER',f'Unsupported character {source[start]!r}'
            elif code in ERRORS:kind,message=ERRORS[code]
            else:raise RuntimeError('invalid native source lexer diagnostic')
            _error(kind,message,Span(start,end,line,column,path))
        if not (0<status<=capacity and status%56==0):
            raise RuntimeError('native source lexer rejected declared buffers')
        return materialize(source,path,wire,output.raw[:status],self.integer_value)


def installed_source_lexer(path: str) -> NativeSourceLexer:
    return _installed_json_image(path,SOURCE,SCHEMA,NativeSourceLexer)

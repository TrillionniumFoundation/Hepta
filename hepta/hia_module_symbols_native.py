"""Explicit HIA module-symbol policy with a passive AST-fact transport.

HIA owns duplicate/alias admission, local and imported name resolution,
namespace selection, type-versus-term roles and imported visibility checks.
Filesystem/package loading, source hashes/prefixes and AST traversal remain host
code. A selected image never falls back to the host policy on an error.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from .ast import Diagnostic, HeptaError
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

MAGIC=5208780291693556277
SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/module_symbols.hiaasm'
SCHEMA='hepta.hia.module-symbols-native.v1'
MAX_BYTES=8<<20


def packet(operation, declarations, imports=(), name='', role='term'):
    """Encode facts; do not select declarations, visibility or name outcomes."""
    if operation not in (1,2,3) or role not in ('term','type'):
        raise ValueError('invalid HIA module-symbol operation')
    base=64+len(declarations)*48+len(imports)*24
    payload=bytearray()
    def text(value):
        if type(value) is not str:raise TypeError('module name is not text')
        raw=value.encode('utf-8');at=base+len(payload);payload.extend(raw)
        return at,len(raw)
    query=text(name)
    rows=[]
    for scope,original,renamed,flags in declarations:
        rows.append(struct.pack('<6Q',scope,*text(original),*text(renamed),flags))
    edges=[struct.pack('<3Q',*text(alias),scope) for alias,scope in imports]
    wire=struct.pack('<8Q',MAGIC,operation,len(rows),len(edges),*query,role=='type',0)+b''.join(rows)+b''.join(edges)+payload
    if len(wire)>MAX_BYTES:raise OverflowError('HIA module-symbol packet exceeds 8 MiB transport')
    return bytes(wire)


def _facts(unit,scope):
    for name in unit.types:
        value=unit.types[name]
        yield scope,name,unit.names[name],1|4*bool(getattr(value,'public',False))|8*bool(getattr(value,'extern_c',False) or getattr(value,'export_c',False))
    for name in unit.functions:
        value=unit.functions[name]
        yield scope,name,unit.names[name],2|4*bool(getattr(value,'public',False))|8*bool(getattr(value,'extern_c',False) or getattr(value,'export_c',False))


def context(unit):
    declarations=list(_facts(unit,0));imports=[]
    for scope,(alias,imported) in enumerate(unit.imports.items(),1):
        imports.append((alias,scope));declarations.extend(_facts(imported,scope))
    return declarations,imports


def _raise(code,name,span):
    messages={1:('E_MODULE_DUPLICATE','Duplicate declaration name in module'),
        2:('E_MODULE_ALIAS','Import alias collides with an existing name: '+name),
        3:('E_MODULE_SYMBOL','Unknown imported symbol: '+name),
        4:('E_MODULE_PRIVATE','Imported symbol is private: '+name),
        5:('E_MODULE_NAMESPACE','Unknown namespace: '+name.split('::')[0])}
    if code not in messages:raise RuntimeError('invalid HIA module-symbol result code')
    tag,message=messages[code]
    raise HeptaError(Diagnostic(tag,message,span,phase='module'))


class NativeModuleSymbols(NativeHiaJsonImage):
    def run(self,wire:bytes,*,capacity=None):
        if type(wire) is not bytes or len(wire)>MAX_BYTES:
            raise ValueError('invalid HIA module-symbol wire')
        capacity=len(wire)+16 if capacity is None else capacity
        if type(capacity) is not int or not 0<=capacity<=MAX_BYTES+16:
            raise ValueError('invalid HIA module-symbol output capacity')
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(max(1,capacity))
        state=ctypes.create_string_buffer(1)
        code=self._entry(source,len(wire),output,capacity,state,1)
        if code in (0xfffffffd,0xfffffffe):return code,None
        if not 16<=code<=capacity:raise RuntimeError('invalid HIA module-symbol native return')
        raw=output.raw[:code];status,size=struct.unpack_from('<2Q',raw)
        if status>5 or size!=len(raw)-16 or (status and size):
            raise RuntimeError('invalid HIA module-symbol result header')
        return status,raw[16:].decode('utf-8')

    def admit(self,program,span):
        declarations=[]
        for values,kind in ((program.structs,1),(getattr(program,'enums',()),1),(program.functions,2)):
            for value in values:declarations.append((0,value.name,value.name,kind))
        code,_=self.run(packet(1,declarations))
        if code:_raise(code,'',span)

    def alias(self,unit,name,span):
        declarations,imports=context(unit)
        code,_=self.run(packet(2,declarations,imports,name))
        if code:_raise(code,name,span)

    def resolve(self,unit,name,role,span):
        declarations,imports=context(unit)
        code,value=self.run(packet(3,declarations,imports,name,role))
        if code:_raise(code,name,span)
        return value


def installed_module_symbols(path:str):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeModuleSymbols)

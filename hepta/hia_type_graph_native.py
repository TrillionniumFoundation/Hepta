"""Native nominal/generic graph queries; other semantic checker phases remain foreign.

The bridge serializes existing type/declaration identities. All graph traversal,
substitution, cycle/seen decisions and reference boundaries execute in HIA.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from pathlib import Path
import struct
from .ast import Type,Struct,Enum
from .hia_json_preflight_native import NativeHiaJsonImage,_installed_json_image
SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/type_graph.hiaasm'
SCHEMA='hepta.hia.type-graph-native.v1'
MAGIC=3549479791681612108
WORKSPACE=680256

class GraphProfileLimit(ValueError):
    """An explicitly declared type graph/transport/scratch profile boundary."""

@dataclass(frozen=True)
class GraphPacket:
    wire:bytes
    mode:int


def packet(typ,structs,enums=None,*,names=frozenset(),seen=frozenset(),mode=1):
    if (type(structs) is not dict or (enums is not None and type(enums) is not dict)
            or type(names) not in (set,frozenset) or type(seen) not in (set,frozenset)
            or mode not in (1,2)):
        raise GraphProfileLimit('outside native type graph transport profile')
    enums=enums or {};declarations=[]
    for name,decl in [*structs.items(),*((n,d) for n,d in enums.items() if n not in structs)]:
        if type(name) is not str or not isinstance(decl,(Struct,Enum)):
            raise GraphProfileLimit('outside native nominal declaration profile')
        if isinstance(decl,Struct):members=[f.type for f in decl.fields]
        else:members=[t for variant in decl.variants for t in variant.fields]
        declarations.append((name,decl.type_params,members,getattr(decl,'lifetime_params',())))
    if len(declarations)>512 or len(names)>8192 or len(seen)>8192:
        raise GraphProfileLimit('outside native type graph count profile')
    if any(type(s) is not str for s in (*names,*seen)):
        raise GraphProfileLimit('outside native type graph symbol profile')
    symbols=[];symbol_ids={}
    def symbol(value):
        if type(value) is not str:raise GraphProfileLimit('outside native type graph symbol profile')
        if value not in symbol_ids:
            if len(symbols)>=8192:raise GraphProfileLimit('outside native type graph symbol profile')
            symbol_ids[value]=len(symbols);symbols.append(value)
        return symbol_ids[value]
    nodes=[];ids={};open_nodes=set();edges=[]
    for root in [t for _,_,members,_ in declarations for t in members]+[typ]:
        stack=[(root,False)]
        while stack:
            node,exiting=stack.pop();key=id(node)
            if key in ids:continue
            if type(node) is not Type or type(node.args) is not tuple or type(node.lifetimes) is not tuple:
                raise GraphProfileLimit('outside native type graph node profile')
            if not exiting:
                if key in open_nodes:raise GraphProfileLimit('cyclic physical type object graph')
                open_nodes.add(key);stack.append((node,True));stack.extend((a,False) for a in reversed(node.args));continue
            if len(nodes)>=8192:raise GraphProfileLimit('outside native type graph node profile')
            first=len(edges);edges.extend(ids[id(a)] for a in node.args)
            life=len(edges);edges.extend(symbol(s) for s in node.lifetimes)
            length_kind=0;length_symbol=0
            if node.length is not None:
                if type(node.length) not in (int,bool):raise GraphProfileLimit('outside native type graph length transport')
                length_kind=2 if type(node.length) is bool else 1
                try:length_text=str(node.length)
                except ValueError as exc:raise GraphProfileLimit('outside native length text transport') from exc
                length_symbol=symbol(length_text)
            nodes.append((symbol(node.name),first,len(node.args),life,len(node.lifetimes),length_kind,length_symbol,0))
            ids[key]=len(nodes)-1;open_nodes.remove(key)
            if len(edges)>32768:raise GraphProfileLimit('outside native type graph edge profile')
    rows=[];params=[];members=[]
    for name,type_params,payload,lifetimes in declarations:
        start=len(params);params.extend(symbol(s) for s in type_params)
        first=len(members);members.extend(ids[id(t)] for t in payload)
        rows.append((symbol(name),start,len(type_params),first,len(payload),len(lifetimes)))
    query=[symbol(s) for s in sorted(names)];prior=[symbol(s) for s in sorted(seen)]
    if len(params)>4096 or len(members)>8192:raise GraphProfileLimit('outside native declaration table profile')
    type_at=128;decl_at=type_at+len(nodes)*64;edge_at=decl_at+len(rows)*48
    symbol_at=edge_at+(len(edges)+len(params)+len(members)+len(query)+len(prior))*8
    payload_at=symbol_at+len(symbols)*16
    payload=bytearray();ranges=[]
    for value in symbols:
        start=len(payload);payload.extend(value.encode('utf-8'));ranges.append((start,len(payload)))
    wire=struct.pack('<16Q',MAGIC,mode,len(nodes),len(rows),len(edges),len(symbols),len(params),len(members),len(query),len(prior),ids[id(typ)],type_at,decl_at,edge_at,symbol_at,payload_at)
    wire+=b''.join(struct.pack('<8Q',*row) for row in nodes)
    wire+=b''.join(struct.pack('<6Q',*row) for row in rows)
    wire+=b''.join(struct.pack('<Q',value) for value in edges+params+members+query+prior)
    wire+=b''.join(struct.pack('<2Q',*r) for r in ranges)+payload
    if len(wire)>1<<20:raise GraphProfileLimit('outside native type graph byte profile')
    return GraphPacket(bytes(wire),mode)


def materialize(raw,mode):
    if len(raw)!=32:raise RuntimeError('invalid native type graph result size')
    magic,value,actual_mode,reserved=struct.unpack('<4Q',raw)
    if magic!=MAGIC+1 or value not in (0,1) or actual_mode!=mode or reserved:
        raise RuntimeError('invalid native type graph result record')
    return bool(value)


class NativeTypeGraph(NativeHiaJsonImage):
    def query(self,graph):
        s=ctypes.create_string_buffer(graph.wire,len(graph.wire));o=ctypes.create_string_buffer(32);w=ctypes.create_string_buffer(WORKSPACE)
        size=self._entry(s,len(graph.wire),o,32,w,WORKSPACE)
        if size==0xfffffffc:raise GraphProfileLimit('native contextual graph scratch profile exceeded')
        if size!=32:raise RuntimeError('native type graph rejected declared buffers')
        return materialize(o.raw,graph.mode)


def installed_type_graph(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeTypeGraph)

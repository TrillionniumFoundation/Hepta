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
SCHEMA='hepta.hia.type-graph-native.v3'
MAGIC=3549479791681612108
WORKSPACE=680256
OWNED_WORKSPACE=4932240
OWNED_OUTPUT=1376288
VALIDATION_WORKSPACE=6374032
VALIDATION_OUTPUT=2424896

class GraphProfileLimit(ValueError):
    """An explicitly declared type graph/transport/scratch profile boundary."""

@dataclass(frozen=True)
class GraphPacket:
    wire:bytes
    mode:int
    node_types:tuple[Type,...]=()
    generic_params:tuple[str,...]=()


def packet(typ,structs,enums=None,*,names=frozenset(),seen=frozenset(),mode=1,
           type_params=frozenset(),lifetime_params=frozenset(),in_body=False,flags=0,
           generic_params=(),bounds=None,allow_owned=False):
    if (type(structs) is not dict or (enums is not None and type(enums) is not dict)
            or type(names) not in (set,frozenset) or type(seen) not in (set,frozenset)
            or mode not in (1,2,3,4,5) or (mode>=3 and seen)):
        raise GraphProfileLimit('outside native type graph transport profile')
    if (type(type_params) not in (set,frozenset) or type(lifetime_params) not in (set,frozenset)
            or type(in_body) is not bool or type(flags) is not int or not 0<=flags<16
            or type(generic_params) is not tuple or len(generic_params)>4096
            or type(allow_owned) is not bool or (bounds is not None and type(bounds) is not dict)
            or any(type(n) is not str for n in (*type_params,*lifetime_params,*generic_params))
            or any(type(k) is not str or type(v) is not str for k,v in (bounds or {}).items())
            or (mode==4 and (generic_params or allow_owned))):
        raise GraphProfileLimit('outside native type-validity transport profile')
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
    nodes=[];node_types=[];ids={};open_nodes=set();edges=[]
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
            node_types.append(node)
            ids[key]=len(nodes)-1;open_nodes.remove(key)
            if len(edges)>32768:raise GraphProfileLimit('outside native type graph edge profile')
    rows=[];params=[];members=[]
    for name,decl_params,payload,lifetimes in declarations:
        start=len(params);params.extend(symbol(s) for s in decl_params)
        first=len(members);members.extend(ids[id(t)] for t in payload)
        rows.append((symbol(name),start,len(decl_params),first,len(payload),len(lifetimes)))
    query=[symbol(s) for s in sorted(names)];prior=[symbol(s) for s in sorted(seen)]
    if mode>=4:
        prior=[len(type_params),len(lifetime_params),int(in_body),flags,len(structs),len(generic_params),int(allow_owned)]
        prior.extend(symbol(s) for s in sorted(type_params))
        prior.extend(symbol(s) for s in sorted(lifetime_params))
        prior.extend(symbol(s) for s in generic_params)
        # Missing bounds have no symbol value; the HIA controller, not this
        # transport, chooses the Copy/Owned rule and missing-argument mapping.
        prior.extend(symbol((bounds or {}).get(s,'')) for s in generic_params)
        if len(prior)>8192:raise GraphProfileLimit('outside native type-validity configuration profile')
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
    return GraphPacket(bytes(wire),mode,tuple(node_types),generic_params)


def materialize(raw,mode):
    if len(raw)!=32:raise RuntimeError('invalid native type graph result size')
    magic,value,actual_mode,reserved=struct.unpack('<4Q',raw)
    if magic!=MAGIC+1 or value not in (0,1) or actual_mode!=mode or reserved:
        raise RuntimeError('invalid native type graph result record')
    return bool(value)


def materialize_owned(raw,graph):
    """Construct the native-selected postorder types; never resolve contexts here."""
    if graph.mode!=3 or len(raw)<32 or len(raw)>OWNED_OUTPUT:
        raise RuntimeError('invalid native owned-shape result size/mode')
    magic,diagnostics,nodes,edges=struct.unpack_from('<4Q',raw)
    if (magic!=MAGIC+2 or diagnostics>8192 or nodes>32768 or edges>65536
            or len(raw)!=32+diagnostics*8+nodes*24+edges*8):
        raise RuntimeError('invalid native owned-shape result header')
    roots=struct.unpack_from('<'+str(diagnostics)+'Q',raw,32)
    return _materialize_types(raw,graph,roots,32+diagnostics*8,nodes,32+diagnostics*8+nodes*24,edges)


def _materialize_types(raw,graph,roots,node_at,nodes,edge_at,edges):
    values=[];cursor=0;children=[]
    for i in range(nodes):
        source,first,count=struct.unpack_from('<3Q',raw,node_at+i*24)
        if (source>=len(graph.node_types) or first!=cursor or count>edges-cursor
                or count!=len(graph.node_types[source].args)):
            raise RuntimeError('invalid native diagnostic type node record')
        indexes=struct.unpack_from('<'+str(count)+'Q',raw,edge_at+first*8)
        if any(index>=i for index in indexes):raise RuntimeError('non-postorder native diagnostic type graph')
        node=graph.node_types[source]
        values.append(Type(node.name,tuple(values[index] for index in indexes),node.length,node.lifetimes))
        children.append(indexes);cursor+=count
    if cursor!=edges:raise RuntimeError('extra native diagnostic type edges')
    if any(index>=nodes for index in roots):raise RuntimeError('invalid native diagnostic type index')
    seen=set();pending=list(roots)
    while pending:
        i=pending.pop()
        if i in seen:continue
        seen.add(i);pending.extend(children[i])
    if len(seen)!=nodes:raise RuntimeError('orphan native diagnostic type node')
    return [values[index] for index in roots]


def _type_diagnostic(kind,typ,first,second):
    # Message selection and semantic auxiliary values are native decisions.
    # This table only renders the existing diagnostic ABI into host objects.
    messages={
        1:('E_LIFETIME_ARITY',lambda:f'{typ.name} expects {first} lifetime argument(s)'),
        2:('E_LIFETIME_SCOPE',lambda:f"undeclared or unsupported lifetime '{typ.lifetimes[first]}"),
        3:('E_BORROW_STORAGE_PROFILE',lambda:'stored references are supported only as fields of lifetime-parameterized records'),
        4:('E_BORROW_STORAGE_PROFILE',lambda:'async I/O reactor/request capabilities cannot be stored in references in this profile'),
        5:('E_BORROW_STORAGE_PROFILE',lambda:'stored references to another view/reference or raw pointer are not supported'),
        6:('E_TYPE_FORM',lambda:f'generic parameter {typ.name} cannot take type arguments'),
        7:('E_IO_TYPE',lambda:f'{typ.name} does not take type arguments or a length'),
        8:('E_GROUP_TYPE',lambda:'TaskGroup does not take type parameters'),
        9:('E_SENDER_TYPE',lambda:'Sender<u64> is an unconstructible capability supported only as a read parameter'),
        10:('E_CANCELLATION_TYPE',lambda:'Cancellation is an unconstructible control capability supported only as a read parameter'),
        11:('E_TYPE_FORM',lambda:f'{typ.name} does not take type arguments or a length'),
        12:('E_TYPE_FORM',lambda:f'{typ.name} requires exactly one element type'),
        13:('E_ARRAY_LENGTH',lambda:'array length must be a nonnegative integer'),
        14:('E_TYPE_FORM',lambda:f'{typ.name} does not take an array length'),
        15:('E_UNSIZED',lambda:'slice types are supported only as read/mut parameters'),
        16:('E_BORROW_STORAGE_PROFILE',lambda:'stored-borrow values cannot be nested in arrays, buffers, raw pointers or task types'),
        17:('E_TASK_TYPE',lambda:'the bootstrap supports Task<u64> only'),
        18:('E_NESTED_LINEAR',lambda:'nested linear values are unsupported; keep Buffer and Task as top-level owners'),
        19:('E_GENERIC_ARITY',lambda:f'expected {first} explicit type argument(s), found {second}'),
        20:('E_BORROW_STORAGE_PROFILE',lambda:'stored-borrow records cannot instantiate type generics in this profile'),
        21:('E_GENERIC_COPY',lambda:'generic arguments must be '+('sized Copy values','sized Owned values without scoped runtime capabilities','sized values without scoped runtime capabilities')[first]+f'; {typ} is not supported'),
        22:('E_GENERIC_OWNED',lambda:f'Owned parameter requires a sized owned resource value; {typ} is not owned'),
        23:('E_TYPE_FORM',lambda:f'{typ.name} cannot take an array length'),
        24:('E_NESTED_LINEAR',lambda:f'type {typ.name} contains a scoped task or I/O resource'),
        25:('E_CANCELLATION_TYPE',lambda:f'type {typ.name} contains a Cancellation capability'),
        26:('E_SENDER_TYPE',lambda:f'type {typ.name} contains a Sender capability'),
        27:('E_NESTED_LINEAR',lambda:f'instantiated payload {typ} hides resources in an unsupported container'),
        28:('E_UNKNOWN_TYPE',lambda:f'unknown type {typ}'),
    }
    if kind not in messages or (kind==2 and first>=len(typ.lifetimes)) or (kind==21 and first>2):
        raise RuntimeError('invalid native type diagnostic tag/auxiliary value')
    code,render=messages[kind]
    return code,render()


def materialize_validation(raw,graph):
    if graph.mode not in (4,5) or len(raw)<64 or len(raw)>VALIDATION_OUTPUT:
        raise RuntimeError('invalid native type-validity result size/mode')
    magic,good,diagnostics,nodes,edges,mode,mappings,reserved=struct.unpack_from('<8Q',raw)
    if (magic!=MAGIC+3 or good not in (0,1) or mode!=graph.mode or reserved
            or diagnostics>32768 or nodes>32768 or edges>65536
            or mappings!=(len(graph.generic_params) if mode==5 else 0)
            or len(raw)!=64+diagnostics*32+mappings*16+nodes*24+edges*8):
        raise RuntimeError('invalid native type-validity result header')
    records=[struct.unpack_from('<4Q',raw,64+i*32) for i in range(diagnostics)]
    node_at=64+diagnostics*32+mappings*16
    types=_materialize_types(raw,graph,[r[1] for r in records],node_at,nodes,node_at+nodes*24,edges)
    messages=[_type_diagnostic(r[0],t,r[2],r[3]) for r,t in zip(records,types)]
    mapping=[]
    for i in range(mappings):
        parameter,node=struct.unpack_from('<2Q',raw,64+diagnostics*32+i*16)
        if parameter!=i or (node!=0xffffffffffffffff and node>=len(graph.node_types)):
            raise RuntimeError('invalid native generic mapping record')
        mapping.append((graph.generic_params[parameter],None if node==0xffffffffffffffff else graph.node_types[node]))
    return bool(good),messages,mapping


class NativeTypeGraph(NativeHiaJsonImage):
    def query(self,graph):
        if graph.mode not in (1,2):raise ValueError('Boolean query requires capability/storage mode')
        s=ctypes.create_string_buffer(graph.wire,len(graph.wire));o=ctypes.create_string_buffer(32);w=ctypes.create_string_buffer(WORKSPACE)
        size=self._entry(s,len(graph.wire),o,32,w,WORKSPACE)
        if size==0xfffffffc:raise GraphProfileLimit('native contextual graph scratch profile exceeded')
        if size!=32:raise RuntimeError('native type graph rejected declared buffers')
        return materialize(o.raw,graph.mode)

    def owned_shapes(self,graph):
        if graph.mode!=3:raise ValueError('owned-shape query requires mode3')
        s=ctypes.create_string_buffer(graph.wire,len(graph.wire))
        o=ctypes.create_string_buffer(OWNED_OUTPUT);w=ctypes.create_string_buffer(OWNED_WORKSPACE)
        size=self._entry(s,len(graph.wire),o,OWNED_OUTPUT,w,OWNED_WORKSPACE)
        if size==0xfffffffc:raise GraphProfileLimit('native owned-shape context/mask/diagnostic profile exceeded')
        if size>OWNED_OUTPUT or size<32:raise RuntimeError('native owned-shape query rejected declared buffers')
        return materialize_owned(o.raw[:size],graph)


    def validate_type(self,graph):
        if graph.mode not in (4,5):raise ValueError('type-validity query requires mode4/5')
        s=ctypes.create_string_buffer(graph.wire,len(graph.wire))
        o=ctypes.create_string_buffer(VALIDATION_OUTPUT);w=ctypes.create_string_buffer(VALIDATION_WORKSPACE)
        size=self._entry(s,len(graph.wire),o,VALIDATION_OUTPUT,w,VALIDATION_WORKSPACE)
        if size==0xfffffffc:raise GraphProfileLimit('native type-validity continuation/context/diagnostic profile exceeded')
        if size>VALIDATION_OUTPUT or size<64:raise RuntimeError('native type-validity query rejected declared buffers')
        return materialize_validation(o.raw[:size],graph)


def installed_type_graph(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeTypeGraph)

"""Selected HIA call-effect fixed point and final resource/worker diagnostics.

This is one semantic checker phase, not the complete checker. Python transports
its already-resolved graph and materializes native decisions; declaration,
type, ownership and control-flow checking remain in the existing checker.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from pathlib import Path
import struct
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_effects.hiaasm'
SCHEMA = 'hepta.hia.source-effects-native.v1'
MAGIC = 3549479791681612106


@dataclass(frozen=True)
class GraphPacket:
    wire: bytes
    names: tuple[str, ...]
    effects: tuple[str, ...]
    workers: tuple[str, ...]
    resource_count: int

    @property
    def workspace(self):
        return 64 + len(self.names)*8

    @property
    def capacity(self):
        return 32 + len(self.names)*8 + (len(self.workers)+4*len(self.names))*24


def packet(checker):
    """Mechanical graph/bit-identity transport; no semantic closure or filtering."""
    functions, local, calls = checker.functions, checker.local_effects, checker.calls
    if (type(functions) is not dict or type(local) is not dict or type(calls) is not dict
            or list(functions) != list(local) or len(functions)>2048
            or any(type(name) is not str for name in functions)
            or any(name not in functions for name in calls)):
        raise ValueError('outside native source effects graph profile')
    names=tuple(functions); ids={name:i for i,name in enumerate(names)}
    effects=set(); resources=set()
    for name,fn in functions.items():
        if (type(local[name]) is not set or type(fn.effects) is not set
                or type(fn.resources) is not dict
                or any(type(s) is not str for s in local[name]|fn.effects)
                or any(type(s) is not str for s in fn.resources)
                or type(calls.get(name,set())) is not set
                or any(callee not in ids for callee in calls.get(name,set()))):
            raise ValueError('outside native source effects graph profile')
        effects.update(local[name]);effects.update(fn.effects);resources.update(fn.resources)
    effects=tuple(sorted(effects))
    if len(effects)>64:raise ValueError('outside native source effects symbol profile')
    symbols=effects+tuple(sorted(resources-set(effects)))
    if len(symbols)>8256:raise ValueError('outside native source effects symbol profile')
    symbol_ids={s:i for i,s in enumerate(symbols)}
    bits={s:1<<i for i,s in enumerate(effects)}
    rows=bytearray();edges=[];resource_rows=[];workers=[]
    for name,fn in functions.items():
        first=len(edges);edges.extend(ids[s] for s in sorted(calls.get(name,set())))
        start=len(resource_rows);resource_rows.extend(symbol_ids[s] for s in fn.resources)
        rows.extend(struct.pack('<6Q',sum(bits[s] for s in local[name]),
            sum(bits[s] for s in fn.effects),first,len(edges)-first,start,len(resource_rows)-start))
    for worker,span in checker.worker_sites:
        if worker not in ids:raise ValueError('outside native source effects worker profile')
        workers.append(worker)
    if len(edges)>16384 or len(resource_rows)>8192 or len(workers)>4096:
        raise ValueError('outside native source effects graph profile')
    payload=bytearray();symbol_rows=bytearray()
    for symbol in symbols:
        start=len(payload);payload.extend(symbol.encode('utf-8'))
        symbol_rows.extend(struct.pack('<2Q',start,len(payload)))
    f_at=112;e_at=f_at+len(rows);r_at=e_at+len(edges)*8
    w_at=r_at+len(resource_rows)*8;y_at=w_at+len(workers)*8;p_at=y_at+len(symbol_rows)
    header=struct.pack('<14Q',MAGIC,len(names),len(effects),len(edges),len(resource_rows),
        len(workers),len(symbols),f_at,e_at,r_at,w_at,y_at,p_at,len(payload))
    wire=header+rows+b''.join(struct.pack('<Q',s) for s in edges+resource_rows+[ids[s] for s in workers])+symbol_rows+payload
    if len(wire)>1<<20:raise ValueError('outside native source effects byte profile')
    return GraphPacket(bytes(wire),names,effects,tuple(workers),len(resource_rows))


def materialize(raw,graph,checker):
    """Decode native sets and diagnostic records; never recompute effect decisions."""
    n=len(graph.names)
    if len(raw)<32:raise RuntimeError('short native source effects result')
    magic,functions,count,reserved=struct.unpack_from('<4Q',raw)
    if (magic!=MAGIC+1 or functions!=n or reserved or count>len(graph.workers)+4*n
            or len(raw)!=32+n*8+count*24):
        raise RuntimeError('invalid native source effects result size')
    mask=(1<<len(graph.effects))-1
    def decode(value):
        if value & ~mask:raise RuntimeError('invalid native source effects bit identity')
        return {s for i,s in enumerate(graph.effects) if value & (1<<i)}
    inferred={name:decode(struct.unpack_from('<Q',raw,32+i*8)[0]) for i,name in enumerate(graph.names)}
    diagnostics=[]
    for at in range(32+n*8,len(raw),24):
        code,ref,value=struct.unpack_from('<3Q',raw,at)
        if code==1 and ref<len(graph.workers) and value:
            name=graph.workers[ref];span=checker.worker_sites[ref][1]
            diagnostics.append(('E_TASK_WORKER_EFFECT',f"worker {name} has unsupported transitive effect(s): {', '.join(sorted(decode(value)))}",span,
                'bootstrap workers cannot spawn nested tasks or perform unchecked unsafe/foreign operations; cancellation is cooperative and termination is not proved'))
        elif code==2 and ref<n and value:
            name=graph.names[ref]
            diagnostics.append(('E_EFFECT',f"function {name} does not declare inferred effect(s): {', '.join(sorted(decode(value)))}",checker.functions[name].span,None))
        elif code==3 and ref<n and value in (1,2,3):
            name=graph.names[ref];clause,effect=(('heap_allocations','alloc'),('may_block','block'),('may_spawn','spawn'))[value-1]
            diagnostics.append(('E_RESOURCE',f'resource clause {clause} conflicts with {effect} effect in {name}',checker.functions[name].span,None))
        else:raise RuntimeError('invalid native source effects diagnostic record')
    checker.result.effects=inferred
    for code,message,span,note in diagnostics:
        if note is None:checker.error(code,message,span)
        else:checker.error(code,message,span,note)


class NativeSourceEffects(NativeHiaJsonImage):
    def finish(self,checker,graph=None):
        if graph is None:graph=packet(checker)
        source=ctypes.create_string_buffer(graph.wire,len(graph.wire))
        output=ctypes.create_string_buffer(graph.capacity)
        state=ctypes.create_string_buffer(graph.workspace)
        size=self._entry(source,len(graph.wire),output,graph.capacity,state,graph.workspace)
        if not 32<=size<=graph.capacity:raise RuntimeError('native source effects rejected declared buffers')
        materialize(output.raw[:size],graph,checker)


def installed_source_effects(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeSourceEffects)

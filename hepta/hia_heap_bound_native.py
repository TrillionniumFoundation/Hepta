"""Fixed object/syscall bridge for the complete native heap controller.

The HIA image owns every admission, arithmetic predicate, analysis request,
exception category and report field. This module transports exact foreign
objects and fixed pinned native results under one consumed permission each.
It never calls the retained heap policy or a hosted static-analysis fallback.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import struct
import sys

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_native_value_graph import NativeObjectPool, decode_bound_native_graph, decode_native_graph
from .hia_static_budget_native import NativeStaticBudget, BudgetContext, installed_static_budget

SELECTOR='HEPTA_HIA_HEAP_BOUND_MANIFEST'
LIVE_SELECTOR='HEPTA_HIA_HEAP_LIVE_ENGINE_MANIFEST'
PAYLOAD_SELECTOR='HEPTA_HIA_HEAP_PAYLOAD_MANIFEST'
STATIC_SELECTOR='HEPTA_HIA_STATIC_BUDGET_MANIFEST'
SCHEMA='hepta.hia.heap-bound-native.v1'
LIVE_SCHEMA='hepta.hia.heap-live-engine-native.v1'
PAYLOAD_SCHEMA='hepta.hia.heap-payload-native.v1'
MAGIC=int.from_bytes(b'HIAHEP01','little')
ABI=0xfffffff1
BASE=8192
MASK=(1<<64)-1
QUERIES=frozenset((22,23,24,25,27))
REQUESTS=frozenset((*range(1,11),20,21,22,23,24,25,26,27,28,100,101))
EMPTY=transport(None)
PAYLOAD_MAGIC=int.from_bytes(b'HIAPAL01','little')
SOURCE=_source_resource_path('examples/hia_bootstrap/heap_bound.hiaasm')


def rejected(detail):
    from .hia_heap_bound import HIAHeapBoundRejected
    raise HIAHeapBoundRejected('E_HIA_BUDGET_NATIVE','native heap transport: '+detail)

def _pointer(value):
    return ctypes.addressof(ctypes.c_char.from_buffer(value)) if len(value) else 0

def _metadata(value):
    typ=type(value)
    if value is None:return [0,0,0,0]
    if typ is bool:return [1,0,0,int(value)]
    if typ is int:
        width=value.bit_length()
        # Only the fixed-width transport is materialized. The HIA image owns
        # every sign/width/type admission; a huge negative value must not
        # allocate a two's-complement temporary before its policy refusal.
        return [2,int(value<0),width,(value&MASK) if width<=64 else 0]
    if typ is str:return [4,0,0,0]
    if typ is list:return [5,0,0,0]
    if typ is dict:return [6,0,0,0]
    return [7,0,0,0]

def _wire(value):
    """Encode representation only, without decimalizing arbitrary integers."""
    typ=type(value)
    if value is None:return struct.pack('<2Q',0,0)
    if typ is bool:return struct.pack('<2Q',1,1)+bytes((value,))
    if typ is int:
        magnitude=abs(value)
        raw=magnitude.to_bytes((magnitude.bit_length()+7)//8,'little')
        return struct.pack('<2Q',12,len(raw)+1)+bytes((value<0,))+raw
    if typ is str:
        raw=value.encode('utf-8','surrogatepass')
        return struct.pack('<2Q',4,len(raw))+raw
    if typ in (tuple,list):
        raw=struct.pack('<Q',len(value))+b''.join(_wire(item) for item in value)
        return struct.pack('<2Q',5,len(raw))+raw
    if typ is dict:
        raw=struct.pack('<Q',len(value))+b''.join(_wire(k)+_wire(v) for k,v in value.items())
        return struct.pack('<2Q',6,len(raw))+raw
    rejected('foreign reply has no declared transport representation')

def _kernel_packet(value, objects, *, source_bindings=False):
    """Bind native-selected source occurrences to the held canonical objects.

    The image emits both its admitted immutable snapshot and its held document
    capability. This primitive checks byte equality; it neither changes graph
    edges nor chooses which source occurrence the report will reference.
    """
    if type(value) is not list or len(value)!=5:
        rejected('heap dependency packet differs')
    mode,snapshot,function,arguments,document=value
    expected=transport([mode,snapshot,function,arguments])
    if not source_bindings:
        packet=transport([mode,document,function,arguments])
        if packet!=expected:
            rejected('held heap document differs from the issued snapshot')
        return packet,document
    raw=bytearray()
    bindings=[]
    def append(item):
        at=len(raw)
        typ=type(item)
        if typ in (list,tuple):
            raw.extend(struct.pack('<3Q',5,0,len(item)))
            for child in item:append(child)
            struct.pack_into('<Q',raw,at+8,len(raw)-at-16)
        elif typ is dict:
            raw.extend(struct.pack('<3Q',6,0,len(item)))
            for key,child in item.items():
                append(key);append(child)
            struct.pack_into('<Q',raw,at+8,len(raw)-at-16)
        else:
            atom=transport(item)
            if struct.unpack_from('<Q',atom)[0]>4:
                rejected('heap source atom has a noncanonical representation')
            raw.extend(atom)
            bindings.append([at,objects.add(item)])
    append([mode,document,function,arguments])
    if bytes(raw)!=expected:
        rejected('held heap document differs from the issued snapshot')
    table=transport(bindings)
    struct.pack_into('<Q',raw,8,len(raw)-16+len(table))
    struct.pack_into('<Q',raw,16,5)
    raw.extend(table)
    return bytes(raw),document

@dataclass(frozen=True)
class HeapFrame:
    sequence:int
    request:int
    words:tuple[int,int,int,int]
    status:int
    value:object

@dataclass(frozen=True)
class HeapDependencies:
    live:object
    static:object
    payload:object

class _HeapStaticContext(BudgetContext):
    def _invoke(self,frame):
        if frame.request in (10,11):
            rejected('the pinned structural dependency requested a hosted heap callback')
        return super()._invoke(frame)

def _run_static(image,*args,**kwargs):
    context=_HeapStaticContext(*args,**kwargs)
    try:
        while True:
            frame=image.step(context)
            if frame.request:
                context.service(frame)
            else:
                return context.accept(frame)
    finally:
        if sys.exc_info()[0] is None:context.close()
        else:context._close_preserving_error()

class HeapContext:
    """Single invocation, exact issued frames, retained object identities."""
    def __init__(self,mode,program,function,arguments,limit,dependencies):
        self.closed=False
        self.workspace=self.output=None
        self._created_arena=self._previous_arena=None
        self._created_output=self._previous_output=None
        self.pool=NativeObjectPool()
        self.input=self.source_wire=None
        self.pending=self.terminal=self.binding=None
        self.fields=None
        self.sequence=self.executed=self.completed=0
        self.accepted=False
        self.cleanup_error=None
        self.dependencies=dependencies
        try:
            none_id=self.pool.add(None)
            program_id=self.pool.add(program)
            function_id=self.pool.add(function)
            arguments_id=self.pool.add(arguments)
            limit_id=self.pool.add(limit)
            raw=transport([mode,program_id,function_id,arguments_id,limit_id,none_id])
            self.workspace=mmap.mmap(-1,max(1<<20,(BASE+len(raw)+4095)&~4095))
            self.output=mmap.mmap(-1,1<<16)
            self.input=bytearray(raw)
            self.source_wire=raw
        except BaseException:
            self._close_preserving_error()
            raise

    def close(self, *, release_objects=True):
        self.closed = True
        self.pending = self.terminal = self.binding = self.fields = None
        self.input = self.source_wire = None
        first = None
        for name in ('_created_arena', '_previous_arena', 'workspace',
                     '_created_output', '_previous_output', 'output'):
            arena = getattr(self, name)
            if arena is not None:
                try:
                    arena.close()
                    setattr(self, name, None)
                except BaseException as exc:
                    if first is None:
                        first = exc
        if release_objects:
            try:
                self.pool.clear()
            except BaseException as exc:
                if first is None:
                    first = exc
        self.cleanup_error = first
        if first is not None:
            raise first

    def _close_preserving_error(self):
        try:
            # Original Python locals remain alive in a retained exception
            # traceback. Keep still-live foreign identities with this context;
            # only explicitly completed temporaries were already released.
            # Owned arenas and all execution permissions close immediately.
            self.close(release_objects=False)
        except BaseException:
            pass

    def _grow(self, needed, *, output=False):
        name = 'output' if output else 'workspace'
        created = '_created_output' if output else '_created_arena'
        previous = '_previous_output' if output else '_previous_arena'
        current = getattr(self, name)
        if type(needed) is not int or needed <= len(current):
            rejected('growth request does not increase an arena')
        size = (max(needed, len(current) * 2) + 4095) & ~4095
        setattr(self, created, mmap.mmap(-1, size))
        ctypes.memmove(_pointer(getattr(self, created)), _pointer(current), len(current))
        setattr(self, previous, current)
        setattr(self, name, getattr(self, created))
        setattr(self, created, None)
        getattr(self, previous).close()
        setattr(self, previous, None)

    @staticmethod
    def _fields(frame):
        if (type(frame) is not HeapFrame or type(frame.sequence) is not int
                or type(frame.request) is not int or type(frame.status) is not int
                or type(frame.words) is not tuple or len(frame.words) != 4
                or any(type(value) is not int for value in frame.words)):
            rejected('issued frame has a changed exact representation')
        return (frame.sequence, frame.request, frame.words, frame.status)

    def _check(self, frame, *, terminal):
        if (self.closed or frame is not (self.terminal if terminal else self.pending)
                or self._fields(frame) != self.fields):
            rejected('frame is not the current exact issued result')
        if self.binding is not None:
            try:
                self.binding.validate(frame.value)
            except (ValueError, TypeError) as exc:
                rejected('issued graph changed: ' + str(exc))
        elif frame.value is not None:
            rejected('empty continuation payload changed')

    def service(self, frame):
        try:
            self._check(frame, terminal=False)
            if frame.sequence != self.sequence or self.executed == self.sequence:
                rejected('foreign permission has already been consumed')
            self.executed = self.sequence
            self.pending = None
            raw = self._invoke(frame)
            if raw is not None:
                used = struct.unpack_from('<Q', self.workspace, 64)[0]
                needed = (used + len(raw) + 7) & ~7
                if needed > len(self.workspace):
                    self._grow(needed)
                self.input = bytearray(raw)
                self.source_wire = raw
            struct.pack_into('<Q', self.workspace, 88, frame.sequence)
            self.completed = frame.sequence
            self.binding = self.fields = None
        except BaseException:
            self._close_preserving_error()
            raise


    def _invoke(self,frame):
        request=frame.request
        a,b,_c,_d=frame.words
        pool=self.pool
        value=frame.value
        if request==100:
            self._grow(a)
            return None
        if request==101:
            self._grow(a,output=True)
            return None
        if request==1:
            result=_metadata(pool.get(a))
        elif request==2:
            from .hia_heap_bound import verify_program
            result=pool.add(verify_program(pool.get(a)))
        elif request==28:
            document=pool.get(a).as_dict()
            result=[pool.add(document),document]
        elif request==3:
            checked=pool.get(a)
            if b==0:result=pool.add(checked.sha256)
            elif b==1:result=pool.add(checked.input_sha256)
            elif b==2:result=pool.add(checked.scalar_entrypoints)
            else:result=checked.structured_bytes is not None
        elif request==4:
            result=pool.get(a) in pool.get(b)
        elif request==5:
            result=pool.get(a)
            if type(result) is not str:
                rejected('string transfer was not admitted for an exact string')
        elif request==6:
            # Keep the real CPython tuple-membership primitive: a metaclass
            # equality hook is in the original public input domain.
            result=type(pool.get(a)) in (list,tuple)
        elif request==7:
            result=pool.add(tuple(pool.get(a)))
        elif request==8:
            result=len(pool.get(a))
        elif request==9:
            result=pool.add(pool.get(a)[b])
        elif request==10:
            pool.release(a)
            result=None
        elif request in (20,21):
            from .hia_static_budget import HIAStaticBudgetRejected
            try:
                if request==20:
                    reply=_run_static(self.dependencies.static,4,document=pool.get(a),
                        schema={7:'hepta.hia.program.v7',8:'hepta.hia.program.v8'}[b],allow_chain=False)
                else:
                    reply=_run_static(self.dependencies.static,2,pool.get(a),
                                      (None,None,None,None))
            except HIAStaticBudgetRejected as error:
                result=[1,pool.add(error)]
            else:
                result=[0,reply]
        elif request==22:
            result=self.dependencies.live.run(value,pool)
        elif request==23:
            data=self.dependencies.payload.run(value,pool)
            result=[pool.add(data),data]
        elif request==24:
            ident=pool.add(value)
            raw=json.dumps(value,sort_keys=True,separators=(',',':'),
                           ensure_ascii=False,allow_nan=False).encode('utf-8')
            result=[ident,sha256(raw).hexdigest()]
        elif request==25:
            pool.get(a)[value[0]]=value[1]
            result=None
        elif request==26:
            result=pool.add(pool.get(a)[b])
        elif request==27:
            result=pool.add(pool.get(a)[value])
        else:
            rejected('unrecognized foreign request')
        return _wire(result)

    def accept(self,frame):
        try:
            self._check(frame,terminal=True)
            if self.accepted or frame.request:
                rejected('terminal permission has already been consumed')
            self.accepted=True
            self.terminal=self.binding=self.fields=None
            from .hia_heap_bound import HIAHeapBoundRejected
            from .hia_static_budget import HIAStaticBudgetRejected
            if frame.status in (2,3,6):
                if (type(frame.value) is not list or len(frame.value)!=2
                        or any(type(v) is not str for v in frame.value)):
                    rejected('semantic refusal has an invalid representation')
                if frame.status==2:raise HIAHeapBoundRejected(*frame.value)
                if frame.status==3:raise HIAStaticBudgetRejected(*frame.value)
                try:
                    raise HIAStaticBudgetRejected(*frame.value)
                except HIAStaticBudgetRejected as error:
                    raise HIAHeapBoundRejected(error.code,str(error)) from error
            if frame.status in (4,5):
                identifier=frame.value
                if type(identifier) is not int:
                    rejected('retained exception receipt is not an exact identifier')
                error=self.pool.get(identifier)
                if not isinstance(error,HIAStaticBudgetRejected):
                    rejected('retained exception receipt changed its foreign type')
                self.pool.release(identifier)
                try:
                    if frame.status==4:raise error
                    raise HIAHeapBoundRejected(error.code,str(error)) from error
                finally:
                    # The context and terminal frame must not form a new
                    # retained error -> traceback -> context -> error cycle.
                    del error
            return frame.value
        except BaseException:
            self._close_preserving_error()
            raise

class NativeHeapController(NativeHiaJsonImage):

    def step(self, context):
        try:
            if (context.closed or context.pending is not None or context.terminal is not None
                    or context.completed != context.sequence):
                rejected('closed or incomplete context cannot enter the image')
            returned = self._entry(_pointer(context.input), len(context.input),
                _pointer(context.output), len(context.output),
                _pointer(context.workspace), len(context.workspace))
            if bytes(context.input) != context.source_wire:
                rejected('immutable foreign reply/source bytes changed')
            if returned == ABI:
                rejected('HIA ABI refused its private representation')
            words = struct.unpack_from('<16Q', context.workspace)
            magic, _phase, sequence, request, a, b, c, d = words[:8]
            status, length = words[12:14]
            if (magic != MAGIC or sequence != context.sequence + 1 or returned != request
                    or request not in REQUESTS | {0} or status not in (0, 1, 2, 3, 4, 5, 6)
                    or bool(request) == bool(status) or length > len(context.output)
                    or request and request not in QUERIES and length):
                rejected('native result header differs')
            if request and (c or d or request == 3 and b not in (0, 1, 2, 3)
                    or request == 20 and b not in (7, 8)
                    or request not in (3, 4, 9, 20, 26) and b
                    or request in (22, 23, 24) and a):
                rejected('foreign request words are not canonical')
            value = binding = None
            if length:
                value, binding = decode_bound_native_graph(bytes(context.output[:length]), EMPTY,
                    binary_integers=True, objects=context.pool, extent_bounds=True)
            elif status or request in QUERIES:
                rejected('native result omitted its complete graph')
            frame = HeapFrame(sequence, request, (a, b, c, d), status, value)
            context.sequence = sequence
            context.fields = context._fields(frame)
            context.binding = binding
            if request:
                context.pending = frame
            else:
                context.terminal = frame
            return frame
        except BaseException:
            context._close_preserving_error()
            raise


    def run(self,mode,program,function,arguments,limit,dependencies):
        context=HeapContext(mode,program,function,arguments,limit,dependencies)
        del program,function,arguments,limit
        try:
            while True:
                frame=self.step(context)
                if frame.request:
                    context.service(frame)
                else:
                    return context.accept(frame)
        finally:
            if sys.exc_info()[0] is None:context.close()
            else:context._close_preserving_error()


class _ArenaReader:
    """Bounds-checked fixed-layout transport, with no admission semantics."""
    def __init__(self,workspace,used):
        if type(used) is not int or not 0<=used<=len(workspace):
            rejected('kernel arena extent differs')
        self.raw=workspace
        self.used=used

    def word(self,at):
        if type(at) is not int or not 0<=at<=self.used-8:
            rejected('kernel word is outside its attested arena')
        return struct.unpack_from('<Q',self.raw,at)[0]

    def text(self,at):
        if at in (0,MASK):return None
        if self.word(at)!=4:rejected('kernel text tag differs')
        size=self.word(at+8)
        if size>self.used-at-16:rejected('kernel text extent differs')
        return self.raw[at+16:at+16+size].decode('utf-8','surrogatepass')

    def bigint(self,at):
        sign,count,capacity=(self.word(at+i*8) for i in range(3))
        if sign or count>capacity or capacity>(self.used-at-24)//8:
            rejected('kernel bigint header differs')
        result=0
        for index in range(count):
            limb=self.word(at+24+index*8)
            if limb>0xffffffff or index==count-1 and limb==0:
                rejected('kernel bigint limb differs')
            result|=limb<<(index*32)
        return result


class NativeLiveHeap(NativeHiaJsonImage):
    def run(self,value,objects):
        packet,document=_kernel_packet(value,objects)
        mode,_snapshot,function,arguments,_document=value
        source=bytearray(packet)
        output=mmap.mmap(-1,32)
        workspace=None
        try:
            size=max(1<<20,65536+len(packet)*16)
            while True:
                workspace=mmap.mmap(-1,size)
                status=self._entry(_pointer(source),len(source),_pointer(output),len(output),
                                   _pointer(workspace),len(workspace))
                if bytes(source)!=packet:rejected('live dependency input changed')
                needed,abi,semantic=struct.unpack_from('<3Q',workspace,72)
                if status==1:
                    if abi or semantic or needed<=size:
                        rejected('live dependency growth is not attested')
                    workspace.close();workspace=None
                    size=(max(needed,size*2)+4095)&~4095
                    continue
                used=struct.unpack_from('<Q',workspace,64)[0]
                reader=_ArenaReader(workspace,used)
                if status==3:
                    if abi:rejected('live dependency combined ABI and semantic outcomes')
                    return [1,semantic,*(reader.text(reader.word(at)) for at in (96,104,112))]
                if status!=0 or needed or abi or semantic:
                    rejected('live dependency refused its ABI')
                analysis,graph,selected,reported_mode=struct.unpack('<4Q',output)
                if (reported_mode!=mode or reader.word(analysis)!=graph
                        or reader.word(analysis+8)!=mode or reader.word(analysis+16)
                        or reader.word(analysis+40)):
                    rejected('live dependency result header differs')
                count=reader.word(graph);nodes=reader.word(graph+8)
                if count>(used-nodes)//48 or count!=len(document['functions']):
                    rejected('live dependency function inventory differs')
                rows=[]
                for index,fn in enumerate(document['functions']):
                    node=nodes+index*48
                    name=reader.text(reader.word(node))
                    if name!=fn['name']:rejected('live dependency function order differs')
                    if mode<2:
                        bound=reader.bigint(reader.word(node+32))
                        rows.append([name,bound,objects.add(fn['name']),objects.add(bound)])
                if mode<2:
                    if selected!=MASK or any(reader.word(analysis+at) for at in (24,32,40,48,56)):
                        rejected('legacy dependency exposed a finite invocation state')
                    return [0,rows,None,0,0,0]
                if selected>=count or document['functions'][selected]['name']!=function:
                    rejected('finite dependency selected a different function')
                result=reader.word(analysis+64)
                peak=reader.bigint(reader.word(result))
                contexts=reader.word(analysis+24)
                steps=reader.word(analysis+32)
                depth=reader.word(analysis+48)
                return [0,[],peak,contexts,steps,depth,objects.add(peak),
                        objects.add(contexts),objects.add(steps),objects.add(depth)]
        finally:
            if workspace is not None:workspace.close()
            output.close()


class NativePayloadHeap(NativeHiaJsonImage):
    def run(self,value,objects):
        packet,_document=_kernel_packet(value,objects,source_bindings=True)
        source=bytearray(packet)
        workspace=output=None
        size=max(1<<20,65536+len(packet)*16)
        output_size=1<<16
        try:
            while True:
                workspace=mmap.mmap(-1,size)
                output=mmap.mmap(-1,output_size)
                status=self._entry(_pointer(source),len(source),_pointer(output),len(output),
                                   _pointer(workspace),len(workspace))
                if bytes(source)!=packet:rejected('payload dependency input changed')
                needed,abi=struct.unpack_from('<2Q',workspace,72)
                length=struct.unpack_from('<Q',workspace,104)[0]
                if status==1:
                    if abi or needed<=size:rejected('payload arena growth is not attested')
                    size=(max(needed,size*2)+4095)&~4095
                elif status==2:
                    if abi or length<=output_size:rejected('payload output growth is not attested')
                    output_size=(max(length,output_size*2)+4095)&~4095
                elif status==0:
                    if abi or not 0<length<=output_size:rejected('payload result extent differs')
                    if length<32:
                        rejected('payload result envelope is truncated')
                    magic,pool_size,result_size,flags=struct.unpack_from('<4Q',output)
                    if (magic!=PAYLOAD_MAGIC or flags or pool_size>length-32
                            or result_size!=length-32-pool_size):
                        rejected('payload result envelope differs')
                    synthetic=bytes(output[32:32+pool_size])
                    encoded=bytes(output[32+pool_size:length])
                    return decode_native_graph(encoded,synthetic,
                        binary_integers=True,objects=objects,extent_bounds=True)
                else:
                    rejected('payload dependency refused its ABI')
                workspace.close();workspace=None
                output.close();output=None
        finally:
            if workspace is not None:workspace.close()
            if output is not None:output.close()


@dataclass(frozen=True)
class SelectedHeap:
    controller:NativeHeapController
    dependencies:HeapDependencies
    def call(self,mode,program,function=None,arguments=None,limit=None):
        return self.controller.run(mode,program,function,arguments,limit,self.dependencies)


class _ComposedStaticContext(BudgetContext):
    def __init__(self,*args,heap,**kwargs):
        self.heap=heap
        super().__init__(*args,**kwargs)

    def _invoke(self,frame):
        if frame.request==10:
            result=self.heap.call(0,self.pool.get(frame.words[0]))
            return transport(self.pool.add(result))
        if frame.request==11:
            result=self.heap.call(2,self.pool.get(frame.words[0]),frame.value,
                                  limit=self.pool.get(frame.words[1]))
            return transport(self.pool.add(result))
        return super()._invoke(frame)


@dataclass(frozen=True)
class _PinnedStaticHeap:
    image:NativeStaticBudget
    heap:SelectedHeap

    def _run(self,*args,**kwargs):
        context=_ComposedStaticContext(*args,heap=self.heap,**kwargs)
        try:
            while True:
                frame=self.image.step(context)
                if frame.request:
                    context.service(frame)
                else:
                    return context.accept(frame)
        finally:
            if sys.exc_info()[0] is None:context.close()
            else:context._close_preserving_error()

    def qualify_vm_call_depth(self,program,*,max_call_depth):
        return self._run(1,program,(None,None,max_call_depth,None))

    def analyze_static_budget(self,program,*,max_allocator_interactions=None,
                              max_vm_ticks=None,max_call_depth=None,max_live_heap_bytes=None):
        return self._run(2,program,(max_allocator_interactions,max_vm_ticks,
                                    max_call_depth,max_live_heap_bytes))

    def qualify_bounded_resources(self,program,*,limits):
        return self._run(3,program,policy=limits)

    def audit_resource_profile(self,document,*,schema,allow_chain):
        return self._run(4,document=document,schema=schema,allow_chain=allow_chain)


def _pin_heap_images(paths,static_image=None):
    path,live_path,static_path,payload_path=paths
    if any(not path for path in paths):
        rejected('selected heap controller requires its three pinned native dependencies')
    from .hia_heap_live_native import installed_heap_live
    from .hia_heap_payload_native import installed_heap_payload
    controller=installed_heap_controller(path)
    live=installed_heap_live(live_path)
    if static_image is None:
        static_image=installed_static_budget(static_path)
    elif type(static_image) is not NativeStaticBudget:
        rejected('composed structural dependency is not the admitted image')
    payload=installed_heap_payload(payload_path)
    return SelectedHeap(controller,HeapDependencies(live,static_image,payload))


def installed_heap_controller(path):
    """Admit one immutable controller image for explicit worker/checker custody."""
    return _installed_json_image(path,SOURCE,SCHEMA,NativeHeapController)


def installed_heap_bound(path,live_path,static_path,payload_path):
    # Every selection validates current source bytes; immutable executable
    # mappings and all three dependency identities then stay held together.
    return _pin_heap_images((path,live_path,static_path,payload_path))


def compose_static_heap(image,paths):
    # The outer static entry already admitted this exact immutable image.
    # Reuse it for heap -> static requests; never reselect from the environment.
    heap=_pin_heap_images(paths,image)
    return _PinnedStaticHeap(image,heap)


def selected_heap_bound():
    paths=tuple(os.environ.get(key) for key in (SELECTOR,LIVE_SELECTOR,STATIC_SELECTOR,PAYLOAD_SELECTOR))
    if not paths[0]:return None
    if any(not path for path in paths):
        rejected('selected heap controller requires its three pinned native dependencies')
    try:
        return installed_heap_bound(*paths)
    except (ValueError,OSError,UnicodeError,RuntimeError) as error:
        from .hia_heap_bound import HIAHeapBoundRejected
        raise HIAHeapBoundRejected('E_HIA_BUDGET_NATIVE',
                                  'selected native heap image refused: '+str(error)) from error

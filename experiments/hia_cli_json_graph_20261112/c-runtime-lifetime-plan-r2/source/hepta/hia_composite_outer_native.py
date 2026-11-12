"""Complete HIA outer lowering; Python retains only issued Core object handles.

Borrowed workspace fields are interpreted by HIA. The bridge forwards fixed
leases and never counts blocks, classifies exports, sorts names or plans Core.
"""
from __future__ import annotations
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct

from .hia_composite_constructor_native import _custody_index
from .hia_composite_function_tokens import ObjectTokenDecoder, TokenProtocolError, detached_packet_index
from .hia_composite_functions_native import (NativeFunctionSession, SOURCES as FUNCTION_SOURCES,
                                            WORKSPACE_BYTES as FUNCTION_BYTES)
from .hia_composite_types_native import SOURCE as TYPE_SOURCE, SESSION_BYTES as TYPE_BYTES
from .hia_task_helpers_native import NativeTaskHelpers, SOURCE as HELPER_SOURCE, WORKSPACE_BYTES as HELPER_BYTES
from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program import HIAProgramRejected

SCHEMA = 'hepta.hia.composite-outer-native.v1'
SELECTOR = 'HEPTA_HIA_COMPOSITE_OUTER_MANIFEST'
KERNELS = ('owner', 'render')
SOURCES = {name:_source_resource_path('examples/hia_bootstrap/composite_outer_'+name+'.hiaasm') for name in KERNELS}
WORKSPACE_BYTES, INPUT_BYTES, OUTPUT_BYTES = 80 << 20, 64 << 20, 64 << 10
MAGIC = int.from_bytes(b'HIAOTK01','little')
OUTER_MAGIC = int.from_bytes(b'HIAOTR01','little')
ACK_MAGIC = int.from_bytes(b'HIAOTA01','little')
FAIL_MAGIC = int.from_bytes(b'HIAOTF01','little')
HEADER_MAGIC = int.from_bytes(b'HIAOTH01','little')
OBJECTS = 1 << 63


def _pairs(rows):
    value = {}
    for key,item in rows:
        if key in value:
            raise ValueError('duplicate outer bundle field')
        value[key] = item
    return value


class NativeCompositeOuter:
    def __init__(self, images, *, types_source_sha256, helpers_source_sha256, function_sources_sha256):
        if set(images) != set(KERNELS) or set(function_sources_sha256) != set(FUNCTION_SOURCES):
            raise ValueError('complete outer owner requires every kernel and dependency identity')
        self.images = dict(images)
        self.dependencies = {TYPE_SOURCE:types_source_sha256, HELPER_SOURCE:helpers_source_sha256,
                             **{FUNCTION_SOURCES[name]:digest for name,digest in function_sources_sha256.items()}}

    def lower(self, owner):
        bound = {path:path.read_bytes() for path in self.dependencies}
        if any(sha256(data).hexdigest() != self.dependencies[path] for path,data in bound.items()):
            raise HIAProgramRejected('selected native outer dependency source changed', 'E_HIA_TYPE')
        result = NativeOuterInvocation(self.images,owner).lower()
        if any(path.read_bytes() != data for path,data in bound.items()):
            raise HIAProgramRejected('selected native outer dependency changed during lowering', 'E_HIA_TYPE')
        return result


class _LeasedHelpers(NativeTaskHelpers):
    """Per-session transport proxy; no shared image is patched or recompiled."""
    def __init__(self, invocation, original):
        self.invocation, self.original = invocation, original
        self._entry = self._borrowed_entry
        self._active = False
        self._result_frame = None

    def _borrowed_entry(self, source, size, output, capacity, workspace, workspace_size):
        invocation = self.invocation
        if not self._active or self._result_frame is not None or workspace_size != HELPER_BYTES:
            invocation._refuse('helper entry has no fresh issued lease')
        before = invocation._borrow_function()
        if before[1:4] != (3,0,20):
            invocation._refuse('function did not issue a helper workspace lease')
        extent = self.original._entry(source,size,output,capacity,workspace,workspace_size)
        measured = invocation._borrow_helper(workspace)
        if measured[1:4] != (7,0,22):
            invocation._refuse('helper workspace did not issue a header verification lease')
        if type(extent) is not int or not 0 <= extent < 1 << 64:
            invocation._refuse('helper returned an invalid extent representation')
        self._result_frame = invocation._invoke(struct.pack('<4Q',HEADER_MAGIC,invocation._request,
            extent,capacity) + ctypes.string_at(output,64))
        return extent

    def generate(self, *args, **kwargs):
        if self._active:
            self.invocation._refuse('reentrant helper lease')
        self._active, self._result_frame = True, None
        try:
            result = super().generate(*args,**kwargs)
            frame = self._result_frame
            if frame is None:
                self.invocation._refuse('helper returned without its real native entry')
            if frame[1] == 5:
                if result.error or result.helper is None:
                    self.invocation._refuse('native helper object disagrees with its issued lease')
                self.invocation._bind(frame[5],result.helper,2)
            elif frame[1] != 6 or not result.error or result.helper is not None:
                self.invocation._refuse('native helper refusal disagrees with its lease')
            return result
        finally:
            self._active, self._result_frame = False, None


class NativeOuterInvocation:
    def __init__(self, images, owner):
        self.images, self.owner = dict(images), owner
        self.session = getattr(owner,'_native_function_session',None)
        if not isinstance(self.session,NativeFunctionSession) or self.session.types is not owner.native_types:
            raise HIAProgramRejected('selected native outer requires the complete native function/type session', 'E_HIA_TYPE')
        self.types = owner.native_types
        self._function_workspace = None
        self._phase = None
        self._request = self._functions = self._helpers = 0
        self._broken = self._completed = False
        self._delegate_error = None
        registry = [[name,[[pname,self.session._type_id(typ)] for pname,typ in params],
                     [self.session._type_id(typ) for typ in returns]]
                    for name,(params,returns) in owner.signatures.items()]
        self._packet = [owner.document,registry,owner.serial,owner.value_slots,
                        list(owner.helpers),list(owner.helper_names.values())]
        self._wire = transport(self._packet)
        if len(self._wire) > INPUT_BYTES:
            self._refuse('initial packet exceeds the derived source capacity')
        try:
            detached_packet_index(self._wire)
            self._source_index = _custody_index(self._wire,self._packet)
        except (TokenProtocolError,ValueError,UnicodeError) as exc:
            self._refuse('invalid exact source custody packet: '+str(exc))
        if transport(self._packet) != self._wire:
            self._refuse('source changed while taking its custody index')
        self._workspace = self._output = self._empty = self._leased_helpers = None
        try:
            self._workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
            self._output = ctypes.create_string_buffer(OUTPUT_BYTES)
            self._empty = ctypes.create_string_buffer(1)
            self._function_workspace = self.session._workspace
            self._original_helpers = self.session.helpers
            self._leased_helpers = _LeasedHelpers(self,self._original_helpers)
        except BaseException:
            self._workspace = self._output = self._empty = None
            self._function_workspace = None
            if self._leased_helpers is not None:
                self._leased_helpers.invocation = None
            raise

    def _refuse(self,message):
        self._broken = True
        raise HIAProgramRejected('native composite outer transport: '+message,'E_HIA_TYPE')

    def _frame(self,size):
        if self._broken:
            self._refuse('protocol has already refused')
        if type(size) is not int or size != 64:
            self._refuse('invalid continuation extent/status '+str(size))
        value = struct.unpack_from('<8Q',self._output)
        magic,action,error,phase,request,handle,functions,helpers = value
        if (self._completed or magic != OUTER_MAGIC or error not in (0,1,999)
                or not self._functions <= functions <= 1024 or not self._helpers <= helpers <= 720):
            self._refuse('invalid native frame or issued inventory correlation')
        previous = self._phase
        accepted = False
        if error:
            accepted = (action == 1 and phase == 2000 and not handle and request == self._request
                and functions == self._functions and helpers == self._helpers
                and ((error == 1 and previous == 0) or (error == 999 and previous == 10)))
        elif action == 0 and not handle and request == self._request:
            accepted = ((previous is None and phase == 0 and request == functions == helpers == 0)
                or (previous == 11 and phase == 0 and functions == self._functions and helpers == self._helpers)
                or (previous == 21 and phase == 10 and functions == self._functions and helpers == self._helpers))
        elif action == 2 and not handle and previous == 0:
            accepted = (functions == self._functions and helpers == self._helpers and
                ((phase == 10 and request == self._request+1) or (phase == 2000 and request == self._request)))
        elif action == 3 and previous == 10 and phase == 20 and not handle:
            accepted = (request == self._request and functions == self._functions and helpers == self._helpers)
        elif action == 4 and previous == 10 and phase == 11:
            accepted = (request == self._request and functions == self._functions+1
                and helpers == self._helpers and handle == OBJECTS+self._functions)
        elif action == 7 and previous == 20 and phase == 22 and not handle:
            accepted = (request == self._request and functions == self._functions and helpers == self._helpers)
        elif action == 5 and previous == 22 and phase == 21:
            accepted = (request == self._request and functions == self._functions and helpers == self._helpers+1
                and handle == OBJECTS+1024+self._helpers)
        elif action == 6 and previous == 22 and phase == 10 and not handle:
            accepted = (request == self._request and functions == self._functions and helpers == self._helpers)
        if not accepted:
            self._refuse('unissued/replayed native transition, phase or handle')
        self._phase,self._request,self._functions,self._helpers = phase,request,functions,helpers
        self._completed = phase == 2000
        return value

    def _invoke(self,wire):
        if self._broken:
            self._refuse('protocol has already refused')
        source = ctypes.create_string_buffer(wire,max(1,len(wire)))
        result = self.images['owner']._entry(source,len(wire),self._output,OUTPUT_BYTES,self._workspace,WORKSPACE_BYTES)
        if ctypes.string_at(source,len(wire)) != wire:
            self._refuse('native command input changed')
        return self._frame(result)

    def _borrow_function(self):
        if self._broken:
            self._refuse('protocol has already refused')
        if (self.session._closed or self.session._broken or self.session._workspace is not self._function_workspace
                or self.session is not self.owner._native_function_session):
            self._refuse('function workspace is outside its issued session lease')
        result = self.images['owner']._entry(self._function_workspace,FUNCTION_BYTES,self._output,
            OUTPUT_BYTES,self._workspace,WORKSPACE_BYTES)
        return self._frame(result)

    def _borrow_helper(self,workspace):
        if self._broken:
            self._refuse('protocol has already refused')
        if not self._leased_helpers._active or self._phase != 20:
            self._refuse('helper workspace has no active one-use lease')
        result = self.images['owner']._entry(workspace,HELPER_BYTES,self._output,
            OUTPUT_BYTES,self._workspace,WORKSPACE_BYTES)
        return self._frame(result)

    def _next(self):
        if self._broken:
            self._refuse('protocol has already refused')
        if self.types._closed or self.types._broken or self.types is not self.session.types:
            self._refuse('type workspace is outside its issued session lease')
        result = self.images['owner']._entry(self.types._state,TYPE_BYTES,self._output,
            OUTPUT_BYTES,self._workspace,WORKSPACE_BYTES)
        return self._frame(result)

    def _bind(self,handle,value,kind):
        if self._broken:
            self._refuse('protocol has already refused')
        if type(handle) is not int or handle < OBJECTS or handle in self._source_index or type(value) is not dict:
            self._refuse('unissued/replaced complete Core object identity')
        self._source_index[handle] = value
        return self._invoke(struct.pack('<4Q',ACK_MAGIC,self._request,kind,handle))

    def _stream(self,action):
        if self._broken:
            self._refuse('protocol has already refused')
        decoder = ObjectTokenDecoder(self._source_index)
        sequence = 0
        while not decoder.complete:
            size = self.images['render']._entry(self._empty,0,self._output,OUTPUT_BYTES,self._workspace,WORKSPACE_BYTES)
            if type(size) is not int or not 64 <= size <= OUTPUT_BYTES:
                self._refuse('invalid native object stream extent/status '+str(size))
            magic,kind,serial,final,fresh,slots,request,payload = struct.unpack_from('<8Q',self._output)
            if (magic != MAGIC or kind != action or serial != sequence or final not in (0,1)
                    or fresh or slots or request != self._request or payload != size-64):
                self._refuse('object stream changed its issued request identity')
            try:
                decoder.feed(ctypes.string_at(ctypes.addressof(self._output)+64,payload),final=bool(final))
            except TokenProtocolError as exc:
                self._refuse('malformed complete object stream: '+str(exc))
            sequence += 1
        return decoder.root

    def lower(self):
        try:
            with self.session._lock,self.types._lock:
                if self.session.helpers is not self._original_helpers:
                    self._refuse('native helper dependency changed before lease installation')
                self.session.helpers = self._leased_helpers
                frame = self._invoke(self._wire)
                while True:
                    if frame[3] == 2000:
                        if frame[2] == 999:
                            if self._delegate_error is None:
                                self._refuse('unissued delegated function refusal')
                            raise self._delegate_error
                        if frame[2] == 1:
                            raise HIAProgramRejected('elaborated program exceeds core inventory budget','E_HIA_LIMIT')
                        result = self._stream(0)
                        if type(result) is not dict or set(result) != {'schema','module','exports','functions'}:
                            self._refuse('native result is not the complete program envelope')
                        if transport(self._packet) != self._wire:
                            self._refuse('original source representation changed during lowering')
                        return result
                    if frame[1] == 0:
                        frame = self._next()
                        continue
                    if frame[1] != 2 or frame[3] != 10:
                        self._refuse('unexpected outer continuation')
                    command = self._stream(1)
                    if type(command) is not list or len(command) != 2 or type(command[0]) is not int or command[0] != 1:
                        self._refuse('unknown native function request')
                    try:
                        result = self.session.function(command[1])
                    except HIAProgramRejected as exc:
                        if self._broken or self.session._broken or self.types._broken:
                            self._refuse('native function dependency failed its transport: '+str(exc))
                        self._delegate_error = exc
                        frame = self._invoke(struct.pack('<4Q',FAIL_MAGIC,self._request,0,0))
                        continue
                    frame = self._borrow_function()
                    if frame[1] != 4:
                        self._refuse('completed native function did not issue its object identity')
                    frame = self._bind(frame[5],result,1)
        finally:
            with self.session._lock:
                if self.session.helpers is self._leased_helpers:
                    self.session.helpers = self._original_helpers
            self._workspace = self._output = self._empty = None
            self._function_workspace = None
            self._delegate_error = None
            self._source_index.clear()
            self._leased_helpers.invocation = None


def installed_composite_outer(path):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError('outer bundle exceeds fixed framing')
    value = json.loads(raw,object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {'schema','kernels','types_source_sha256',
            'helpers_source_sha256','function_sources_sha256'} or value['schema'] != SCHEMA
            or type(value['kernels']) is not dict or set(value['kernels']) != set(KERNELS)
            or type(value['function_sources_sha256']) is not dict
            or set(value['function_sources_sha256']) != set(FUNCTION_SOURCES)):
        raise ValueError('invalid complete outer bundle manifest')
    for digest in (value['types_source_sha256'],value['helpers_source_sha256'],*value['function_sources_sha256'].values()):
        if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid outer dependency source identity')
    images = {}
    for name in KERNELS:
        component = value['kernels'][name]
        if type(component) is not str:
            raise ValueError('invalid outer kernel manifest path')
        images[name] = _installed_json_image(str(path.parent/component),SOURCES[name],
            'hepta.hia.composite-outer-'+name+'-native.v1',NativeHiaJsonImage)
    return NativeCompositeOuter(images,types_source_sha256=value['types_source_sha256'],
        helpers_source_sha256=value['helpers_source_sha256'],function_sources_sha256=value['function_sources_sha256'])


def selected_composite_outer():
    path = os.environ.get(SELECTOR)
    if not path:
        return None
    try:
        return installed_composite_outer(path)
    except (ValueError,OSError,UnicodeError,RuntimeError) as exc:
        raise HIAProgramRejected('selected native composite outer refused: '+str(exc),'E_HIA_TYPE') from exc

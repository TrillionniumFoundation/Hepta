"""Raw JSON declaration/SSA/CFG policy candidate; full body checking stays host.

Only allocation and the pinned image ABI occur here. No JSON parser, identifier
classifier, CFG traversal or foreign function-shape checker is called here.
Not selected by production admission until exact-source qualification succeeds.
"""
import ctypes
import json
import os
from pathlib import Path
import struct
from .hia_json_preflight_native import NativeHiaJsonImage,_installed_json_image

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/function_shape.hiaasm')
MAX_BYTES=8388608
MAX_NODES=262144
MAX_DEPTH=64
MAX_BLOCKS=4096
SCHEMA='hepta.hia.function-shape-native.v1'
SELECTOR='HEPTA_HIA_FUNCTION_SHAPE_MANIFEST'
ERROR_CODES={0xfffffffb:'E_HIA_FORMAT',0xfffffffa:'E_HIA_NAME',
             0xfffffff9:'E_HIA_TYPE',0xfffffff8:'E_HIA_LOAN',
             0xfffffff7:'E_HIA_EFFECT',0xfffffff6:'E_HIA_CFG',0xfffffff5:'E_HIA_SSA',
             0xffffffff:'E_HIA_FORMAT',0xfffffffe:'E_HIA_LIMIT',0xfffffffc:'E_HIA_FORMAT'}


def scratch_sizes(size):
    # JSON has at most ceil(bytes/2)+1 value nodes. This allocation bound does
    # not reduce the independently enforced full node/depth/input ceilings.
    bound=min(MAX_NODES,(size+1)//2+1)
    slots=2
    while slots<bound*4:slots*=2
    # The decoder temporarily uses this buffer for the complete configured
    # preflight stack even when submitted JSON is a one-node wrong-kind root.
    arena=max(128+(MAX_DEPTH+1)*32,64+bound*56+size)
    state=max(128+slots*24+MAX_BLOCKS*40,128+(MAX_DEPTH+1)*48)
    return state,arena


class NativeFunctionShape(NativeHiaJsonImage):
    def status(self,wire,*,recursive_chain=False,parameter_loan_returns=False):
        if type(wire) is not bytes or type(recursive_chain) is not bool or type(parameter_loan_returns) is not bool:
            raise TypeError('exact JSON bytes and explicit boolean schema features required')
        if len(wire)>MAX_BYTES:return 0xfffffffe
        state_size,arena_size=scratch_sizes(len(wire))
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        state=ctypes.create_string_buffer(state_size)
        arena=ctypes.create_string_buffer(arena_size)
        struct.pack_into('<Q',arena,40,int(recursive_chain)+2*int(parameter_loan_returns))
        result=self._entry(source,len(wire),state,state_size,arena,arena_size)
        if result not in {0,0xfffffffd,*ERROR_CODES}:raise RuntimeError('invalid native shape result')
        return result

    def admit(self,wire,**features):
        from .hia_program import HIAProgramRejected
        result=self.status(wire,**features)
        if result==0xfffffffd:raise RuntimeError('native shape scratch/ABI refusal')
        if result:raise HIAProgramRejected('native function declaration/SSA/CFG rejected',ERROR_CODES[result])


def installed_function_shape(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeFunctionShape)


def selected_function_shape(fn,*,recursive_chain=False,parameter_loan_returns=False):
    """Return None when unselected; selected refusal never calls old policy.

    The existing bounded exact-JSON snapshot is a HOST transport boundary.
    It protects caller-owned types/cycles/races, not declaration/SSA/CFG policy.
    Production admission has already detached the complete bounded Core tree.
    """
    path=os.environ.get(SELECTOR)
    if not path:return None
    image=installed_function_shape(path)
    from .hia_program import _bounded_detached_snapshot,_structure
    snapshot=_bounded_detached_snapshot(fn)
    _structure(snapshot)
    raw=json.dumps(snapshot,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
    image.admit(raw,recursive_chain=recursive_chain,parameter_loan_returns=parameter_loan_returns)
    # Materialize only after native admission. This is not a second resolver.
    return {block['id']:block for block in snapshot['blocks']}

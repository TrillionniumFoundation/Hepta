"""Native whole primitive declaration/SSA/CFG/export policy; not body checking."""
import ctypes
import json
import os
from pathlib import Path
from .hia_json_preflight_native import NativeHiaJsonImage,_installed_json_image
from .hia_function_shape_native import ERROR_CODES as FUNCTION_ERRORS,scratch_sizes

SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/program_shape.hiaasm'
SCHEMA='hepta.hia.program-shape-native.v1'
SELECTOR='HEPTA_HIA_PROGRAM_SHAPE_MANIFEST'
ERROR_CODES={**FUNCTION_ERRORS,0xfffffff4:'E_HIA_SCHEMA',0xfffffff3:'E_HIA_CALL',0xfffffff2:'E_HIA_TYPE'}
ERROR_MESSAGES={0xfffffff4:'unsupported program schema',
                0xfffffff3:'explicit export names a missing function',
                0xfffffff2:'public exports cannot carry resource descriptors'}


class NativeProgramShape(NativeHiaJsonImage):
    def status(self,wire):
        if type(wire) is not bytes:raise TypeError('exact JSON bytes required')
        if len(wire)>8388608:return 0xfffffffe
        state_size,arena_size=scratch_sizes(len(wire))
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        state=ctypes.create_string_buffer(state_size)
        arena=ctypes.create_string_buffer(arena_size)
        result=self._entry(source,len(wire),state,state_size,arena,arena_size)
        if result not in {0,0xfffffffd,*ERROR_CODES}:raise RuntimeError('invalid native program-shape result')
        return result

    def admit(self,wire):
        from .hia_program import HIAProgramRejected
        result=self.status(wire)
        if result==0xfffffffd:raise RuntimeError('native program-shape scratch/ABI refusal')
        if result:raise HIAProgramRejected(ERROR_MESSAGES.get(result,'native primitive program declaration/SSA/CFG/export rejected'),ERROR_CODES[result])


def installed_program_shape(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeProgramShape)


def selected_program_shape(data):
    path=os.environ.get(SELECTOR)
    if not path:return None
    image=installed_program_shape(path)
    from .hia_program import _bounded_detached_snapshot,_structure
    snapshot=_bounded_detached_snapshot(data)
    _structure(snapshot)
    wire=json.dumps(snapshot,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
    image.admit(wire)
    # Foreign object materialization only; the image has checked every key,
    # name, declaration, edge and export before any result map is published.
    functions={fn['name']:fn for fn in snapshot['functions']}
    blocks={fn['name']:{block['id']:block for block in fn['blocks']} for fn in snapshot['functions']}
    return functions,blocks

"""Operator-selected HIA scalar identities and frozen-context budget rules.

The service binds inputs to Store authority before passing bounded scalar values
to this policy. It retains its existing public rejection codes and messages.
"""
from __future__ import annotations
import ctypes
import struct
from .hia_agent_store import _agent_resource_path, reject
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE=_agent_resource_path('examples/hia_bootstrap/agent_identity.hepta')
SCHEMA='hepta.hia.agent-identity-native.v1'
MAGIC=int.from_bytes(b'HIAIDP01','little')
RESULT_MAGIC=int.from_bytes(b'HIAIDR01','little')
SELECTOR='HEPTA_HIA_AGENT_IDENTITY_MANIFEST'
CONTEXT_REFUSALS = {
    1: ('E_HIA_BUDGET', 'execution profile admits 64 MiB..4 GiB address-space budgets'),
    2: ('E_HIA_BUDGET', 'native wall budget exceeds total wall budget'),
    3: ('E_HIA_BUDGET', 'reported model tokens exceed the frozen budget'),
    4: ('E_HIA_COST', 'complete external cost report cannot contain unknown fields'),
    5: ('E_HIA_BUFFER_BUDGET', 'frozen workload exceeds 32 MiB of external byte snapshots'),
}

class NativeAgentIdentity(NativeHiaJsonImage):
    def scalar(self, value, kind):
        if type(kind)is not int or kind not in (0,1):
            raise ValueError('unknown native Agent identity operation')
        # Value-kind and bounded transport, not a numeric/hex fallback.
        if type(value)is not str or len(value)>64:
            return None
        try: payload=value.encode('ascii')
        except UnicodeEncodeError:return None
        wire=struct.pack('<2Q',MAGIC,kind)+payload
        valid, number = self._request(wire)
        if (not valid and number != 0) or (kind == 1 and number != 0):
            raise RuntimeError('invalid HIA Agent scalar result')
        return number if valid else None

    def _request(self, wire):
        source=ctypes.create_string_buffer(wire,len(wire))
        output=ctypes.create_string_buffer(24)
        unused=ctypes.create_string_buffer(1)
        status=self._entry(source,len(wire),output,24,unused,0)
        if status!=24:raise RuntimeError('HIA Agent identity rejected owned packet')
        magic,valid,number=struct.unpack('<3Q',output.raw)
        if magic != RESULT_MAGIC or valid not in (0, 1):
            raise RuntimeError('invalid HIA Agent identity result')
        return valid, number

    def _context(self, kind, fields, allowed):
        wire = struct.pack(f'<{2 + len(fields)}Q', MAGIC, kind, *fields)
        valid, decision = self._request(wire)
        if valid != 1 or decision not in (0, *allowed):
            raise RuntimeError('invalid HIA Agent context budget result')
        if decision:
            code, message = CONTEXT_REFUSALS[decision]
            reject(code, message, 'context')

    def context_limits(self, memory, total_wall, native_wall):
        self._context(2, (memory, total_wall, native_wall), (1, 2))

    def context_cost(self, limit, external, complete):
        fields = ('model_tokens', 'model_wall_ns', 'discovery_wall_ns')
        missing = sum(1 << index for index, field in enumerate(fields) if external[field] is None)
        self._context(3, (limit, int(external['model_tokens'] or 0), missing, int(complete)), (3, 4))

    def context_snapshots(self, sizes):
        self._context(4, tuple(sizes), (5,))

    def uint64(self,value):return self.scalar(value,0)
    def digest(self,value):return self.scalar(value,1)is not None


def installed_agent_identity(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeAgentIdentity)

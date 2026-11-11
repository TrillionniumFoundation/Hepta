"""Operator-selected HIA scalar Agent identities; trusted image, not a sandbox.

Only byte grammar and u64 conversion are native here. Host JSON values, worker
correlation/digest computation, authorization, persistence and I/O remain host.
"""
from __future__ import annotations
import ctypes
import struct
from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE=_agent_resource_path('examples/hia_bootstrap/agent_identity.hepta')
SCHEMA='hepta.hia.agent-identity-native.v1'
MAGIC=int.from_bytes(b'HIAIDP01','little')
RESULT_MAGIC=int.from_bytes(b'HIAIDR01','little')
SELECTOR='HEPTA_HIA_AGENT_IDENTITY_MANIFEST'

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
        source=ctypes.create_string_buffer(wire,len(wire))
        output=ctypes.create_string_buffer(24)
        unused=ctypes.create_string_buffer(1)
        status=self._entry(source,len(wire),output,24,unused,0)
        if status!=24:raise RuntimeError('HIA Agent identity rejected owned packet')
        magic,valid,number=struct.unpack('<3Q',output.raw)
        if (magic!=RESULT_MAGIC or valid not in (0,1)
                or (not valid and number!=0) or (kind==1 and number!=0)):
            raise RuntimeError('invalid HIA Agent identity result')
        return number if valid else None

    def uint64(self,value):return self.scalar(value,0)
    def digest(self,value):return self.scalar(value,1)is not None


def installed_agent_identity(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeAgentIdentity)

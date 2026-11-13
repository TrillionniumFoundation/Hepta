"""Explicit source-bound HIA decimal conversion; Python only boxes IEEE bits."""
import ctypes
import struct

from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_binary64.hiaasm')
SCHEMA = 'hepta.hia.agent-binary64-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_BINARY64_MANIFEST'


class NativeAgentBinary64(NativeHiaJsonImage):
    def bits(self, wire):
        if type(wire) is not bytes or not 1 <= len(wire) <= 8388608:
            raise ValueError('outside native decimal binary64 byte profile')
        source = ctypes.create_string_buffer(wire, len(wire))
        output = ctypes.create_string_buffer(8)
        workspace = ctypes.create_string_buffer(4096)
        status = self._entry(source, len(wire), output, 8, workspace, 4096)
        if status == 0xffffffff:
            raise ValueError('invalid JSON number syntax')
        if status == 0xfffffffc:
            raise ValueError('nonfinite JSON number')
        if status != 8:
            raise RuntimeError('native decimal conversion private profile refused')
        return output.raw

    def convert(self, text):
        if type(text) is not str:
            raise ValueError('JSON numeric lexeme must be text')
        # Binary boxing is not decimal conversion. No float()/strtod, decimal
        # parser, host arbitrary integer arithmetic or host rounding is used.
        return struct.unpack('<d', self.bits(text.encode('ascii')))[0]


def installed_agent_binary64(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentBinary64)

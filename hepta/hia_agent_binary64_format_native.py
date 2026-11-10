"""Explicit HIA shortest finite binary64 printer; foreign IEEE bit transport only."""
import ctypes
import struct

from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_binary64_format.hiaasm')
SCHEMA = 'hepta.hia.agent-binary64-format-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST'


class NativeAgentBinary64Format(NativeHiaJsonImage):
    def render_bits(self, wire):
        if type(wire) is not bytes or len(wire) != 8:
            raise ValueError('binary64 printer requires exactly eight IEEE bytes')
        source = ctypes.create_string_buffer(wire, 8)
        output = ctypes.create_string_buffer(32)
        workspace = ctypes.create_string_buffer(8192)
        status = self._entry(source, 8, output, 32, workspace, 8192)
        if status == 0xffffffff:
            raise ValueError('nonfinite JSON number')
        if not 1 <= status <= 32:
            raise RuntimeError('native binary64 printer private profile refused')
        return output.raw[:status]

    def render(self, value):
        if type(value) is not float:
            raise ValueError('binary64 printer requires a float object')
        # Object representation transport, not decimal conversion/formatting.
        return self.render_bits(struct.pack('<d', value))


def installed_agent_binary64_format(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentBinary64Format)

"""Render the selected Agent discovery answer from exact issued references."""

import ctypes
import struct

from .hia_agent_discovery_native import RESOURCE_ROLES
from .hia_agent_store import _agent_resource_path, decode_data, wire
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE_NAME = 'examples/hia_bootstrap/agent_describe_answer.hepta'
SOURCE = _agent_resource_path(SOURCE_NAME)
SCHEMA = 'hepta.hia.agent-describe-answer-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_DESCRIBE_ANSWER_MANIFEST'
MAGIC = b'HIADISAN'
BASE_FIELDS = 5
REFERENCE_COUNT = len(RESOURCE_ROLES)
MAX_ANSWER = 65536


class NativeAgentDescribeAnswer(NativeHiaJsonImage):
    def render(self, catalog_pin, manifest, language, backend, artifact, roles, references):
        if len(references) != REFERENCE_COUNT:
            raise ValueError('incomplete HIA discovery references')
        route = len(roles) | sum(role << (4 + index * 5) for index, role in enumerate(roles))
        fields = (artifact, backend, catalog_pin, language, manifest, *references)
        fragments = tuple(wire(value, maximum=MAX_ANSWER) for value in fields)
        packet = struct.pack(f'<8s{1 + BASE_FIELDS + REFERENCE_COUNT}Q',
                             MAGIC, route, *map(len, fragments)) + b''.join(fragments)
        source = ctypes.create_string_buffer(packet)
        result = ctypes.create_string_buffer(MAX_ANSWER)
        size = self._entry(source, len(packet), result, len(result), result, 0)
        if not 1 <= size <= len(result):
            raise ValueError('HIA rejected the discovery answer packet')
        return decode_data(result.raw[:size])


def installed_agent_describe_answer(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentDescribeAnswer)

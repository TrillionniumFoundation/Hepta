"""One-image custody binding for the HIA entry-payload dependency.

This module provides no payload policy or decoding fallback. The public heap
owner pins this exact image together with its other three immutable mappings.
"""
from . import hia_heap_bound_native as _bridge
from .hia_json_preflight_native import _source_resource_path

SELECTOR = _bridge.PAYLOAD_SELECTOR
SCHEMA = _bridge.PAYLOAD_SCHEMA
SOURCE = _source_resource_path('examples/hia_bootstrap/heap_payload.hiaasm')
NativePayloadHeap = _bridge.NativePayloadHeap


def installed_heap_payload(path):
    return _bridge._installed_json_image(path, SOURCE, SCHEMA, NativePayloadHeap)

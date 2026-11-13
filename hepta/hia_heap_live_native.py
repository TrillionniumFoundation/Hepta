"""One-image custody binding for the HIA live-heap dependency.

All analysis remains in the native kernel; public calls pin this image together
with the heap controller, structural owner and payload dependency.
"""
from . import hia_heap_bound_native as _bridge
from .hia_json_preflight_native import _source_resource_path

SELECTOR = _bridge.LIVE_SELECTOR
SCHEMA = _bridge.LIVE_SCHEMA
SOURCE = _source_resource_path('examples/hia_bootstrap/heap_live_engine.hepta')
NativeLiveHeap = _bridge.NativeLiveHeap


def installed_heap_live(path):
    return _bridge._installed_json_image(path, SOURCE, SCHEMA, NativeLiveHeap)

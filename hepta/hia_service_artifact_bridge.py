"""Named Artifact compatibility edge to the current bounded host primitives.

The actual provider retains its descriptor-finally behavior. Both this exact
edge and its provider are captured by the v6 source and compiler receipt.
"""
from .hia_native_host_support import _global_value, _regular_bytes

from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)

"""Explicit bounded HIA SHA-256 payload hashing, not whole-runtime replacement.

Code custody still uses the existing host trust root. Only selected payload
hashing is native HIA; no Python/OpenSSL hash routine receives that payload.
"""
from __future__ import annotations
import ctypes
from hashlib import sha256 as _foreign_sha256
import os
from pathlib import Path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/sha256.hiaasm')
SCHEMA='hepta.hia.sha256-native.v1'
MAX_BYTES=8<<20
WORKSPACE_BYTES=1088


class NativeSha256(NativeHiaJsonImage):
    """Reuse only the existing disjoint six-argument immutable-code ABI loader."""
    def digest(self, wire: bytes) -> bytes:
        if type(wire) is not bytes or len(wire)>MAX_BYTES:
            raise ValueError('outside native HIA SHA-256 profile')
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(32)
        workspace=ctypes.create_string_buffer(WORKSPACE_BYTES)
        result=self._entry(source,len(wire),output,32,workspace,WORKSPACE_BYTES)
        if result!=32:
            raise RuntimeError('native HIA SHA-256 rejected its declared buffers')
        return output.raw


def installed_hasher(manifest_path: str) -> NativeSha256:
    return _installed_json_image(manifest_path,SOURCE,SCHEMA,NativeSha256)


def payload_sha256(wire) -> bytes:
    """Preserve the reference unless this bounded bytes backend is selected.

    The manifest names operator-selected local executable code. Invalid selected
    artifacts fail closed; unsupported inputs retain the existing foreign API.
    No service, installation or compiler trust root is changed by selection.
    """
    stream_manifest=os.environ.get('HEPTA_HIA_SHA256_STREAM_MANIFEST')
    if stream_manifest and type(wire) is bytes:
        from .hia_sha256_stream_native import installed_stream_hasher
        return installed_stream_hasher(stream_manifest).digest(wire)
    manifest=os.environ.get('HEPTA_HIA_SHA256_MANIFEST')
    if manifest and type(wire) is bytes and len(wire)<=MAX_BYTES:
        return installed_hasher(manifest).digest(wire)
    return _foreign_sha256(wire).digest()

"""Pinned HIA-owned ELF64 shared linkage for the direct emitter."""

from __future__ import annotations

import ctypes
from hashlib import sha256
import os

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_loaded_source import loaded_source_identity, register_loaded_module

SOURCE = _source_resource_path('examples/hia_bootstrap/elf_shared_linker.hepta')
SCHEMA = 'hepta.hia.elf-shared-linker-native.v1'
SELECTOR = 'HEPTA_HIA_ELF_SHARED_LINKER_MANIFEST'
MAX_ELF_BYTES = 64 << 20
WORKSPACE_BYTES = 1 << 20


class NativeSharedLinker(NativeHiaJsonImage):
    def link(self, object_bytes):
        if type(object_bytes) is not bytes or not 0 < len(object_bytes) <= MAX_ELF_BYTES:
            raise ValueError('HIA shared linkage requires a bounded immutable direct object')
        # Only the text and original string table are copied. The replacement
        # loader metadata and segment/section alignment add less than 64 KiB.
        capacity = min(MAX_ELF_BYTES, len(object_bytes) + (64 << 10))
        source = ctypes.create_string_buffer(object_bytes, len(object_bytes))
        output = ctypes.create_string_buffer(capacity)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        size = self._entry(source, len(object_bytes), output, capacity, workspace, len(workspace))
        if size == 0xffffffff:
            raise ValueError('HIA shared linkage refused the direct object')
        if not 64 <= size <= capacity:
            raise ValueError('HIA shared linkage could not produce the bounded ELF')
        linked = output.raw
        if source.raw != object_bytes or any(linked[size:]):
            raise ValueError('HIA shared linkage violated its bounded byte transport')
        return linked[:size]

    def identity(self):
        adapter = loaded_source_identity(__name__, ('hia_elf_shared_linker_native.py',))
        source_digest = sha256(SOURCE.read_bytes()).hexdigest()
        if source_digest != self.admitted_source_sha256:
            raise ValueError('HIA shared linker source changed after image admission')
        return self.image_sha256, source_digest, adapter


def selected_shared_linker():
    path = os.environ.get(SELECTOR)
    return None if not path else _installed_json_image(path, SOURCE, SCHEMA, NativeSharedLinker)


def shared_linker_matches(identity):
    selected = selected_shared_linker()
    return selected is not None and selected.identity() == identity


register_loaded_module(__name__)

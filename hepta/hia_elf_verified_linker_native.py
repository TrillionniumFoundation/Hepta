"""Pinned HIA shared linkage for the independently validated one-abort profile."""

from __future__ import annotations

import ctypes
from hashlib import sha256
import os

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_loaded_source import loaded_source_identity, register_loaded_module


SOURCE = _source_resource_path('examples/hia_bootstrap/elf_verified_linker.hepta')
SCHEMA = 'hepta.hia.elf-verified-linker-native.v1'
SELECTOR = 'HEPTA_HIA_ELF_VERIFIED_LINKER_MANIFEST'
MAX_OBJECT_BYTES = 72 << 10
MAX_OUTPUT_BYTES = 88 << 10
WORKSPACE_BYTES = 512


class NativeVerifiedLinker(NativeHiaJsonImage):
    def link(self, object_bytes, destination):
        """Emit private candidate bytes only; never certify or publish them."""
        if type(object_bytes) is not bytes or not 512 <= len(object_bytes) <= MAX_OBJECT_BYTES:
            raise ValueError('verified HIA linkage requires a bounded immutable ET_REL object')
        source = ctypes.create_string_buffer(object_bytes, len(object_bytes))
        output = ctypes.create_string_buffer(MAX_OUTPUT_BYTES)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        size = self._entry(source, len(source), output, len(output), workspace, len(workspace))
        if size == 0xffffffff:
            raise ValueError('verified HIA linkage refused the one-abort object')
        if not 64 <= size <= len(output) or source.raw != object_bytes or any(output.raw[size:]):
            raise ValueError('verified HIA linkage violated its bounded byte transport')
        with destination.open('xb') as stream:
            stream.write(output.raw[:size])

    def identity(self):
        adapter = loaded_source_identity(__name__, ('hia_elf_verified_linker_native.py',))
        source_digest = sha256(SOURCE.read_bytes()).hexdigest()
        if source_digest != self.admitted_source_sha256:
            raise ValueError('verified HIA linker source changed after image admission')
        return (self.image_sha256, source_digest, adapter)

    def toolchain(self, identity):
        return {"path": None, "sha256": identity[0], "source_sha256": identity[1],
                "version": "hia-elf-verified-linker.v1", "flags": [], "mode": "hia"}


def selected_verified_linker():
    path = os.environ.get(SELECTOR)
    return None if not path else _installed_json_image(path, SOURCE, SCHEMA, NativeVerifiedLinker)


def verified_linker_matches(identity):
    selected = selected_verified_linker()
    return selected is not None and selected.identity() == identity


register_loaded_module(__name__)

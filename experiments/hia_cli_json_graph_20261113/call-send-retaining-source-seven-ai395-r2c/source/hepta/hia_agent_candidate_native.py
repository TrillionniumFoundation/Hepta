"""Raw-byte Agent patches and HIA-authored diagnostics, with full admission.

Only the two immutable payloads cross this bridge. The HIA images own JSON,
snapshot identity, edits, interface changes and diagnostic serialization.
Agent request/context authority, artifact references and persistence stay with
their existing owners. Matching-source image admission is not publication.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import struct

from .hia_core_patch_native import (ERROR_MESSAGES, MAX_COMPONENT, MAX_WIRE,
    NativeCorePatch, SCHEMA, SOURCE, envelope, scratch_sizes)
from .hia_json_preflight_native import _installed_json_image


RESULT_MAGIC = int.from_bytes(b'HIAPAR01', 'little')
MAX_RESULT = 32 + 2 * MAX_COMPONENT
DECLARED_SCHEMA_ERROR = 0xfffffff1


def result_payloads(output):
    """Validate only framing; never parse either HIA-owned JSON payload."""
    from .hia_program_tools import HIAEditRejected
    if type(output) is not bytes or not 36 <= len(output) <= MAX_RESULT:
        raise HIAEditRejected('E_HIA_EDIT: invalid native Agent patch result extent')
    magic, candidate_size, diagnostics_size, reserved = struct.unpack_from('<4Q', output)
    if (magic != RESULT_MAGIC or reserved != 0
            or not 2 <= candidate_size <= MAX_COMPONENT
            or not 2 <= diagnostics_size <= MAX_COMPONENT
            or 32 + candidate_size + diagnostics_size != len(output)):
        raise HIAEditRejected('E_HIA_EDIT: invalid native Agent patch result header')
    end = 32 + candidate_size
    return output[32:end], output[end:]


class NativeAgentCandidatePatch(NativeCorePatch):
    def result(self, wire, declared_schema):
        """Private transformation result; callers must admit both programs."""
        from .hia_program_tools import HIAEditRejected
        if type(wire) is not bytes or type(declared_schema) is not int or declared_schema not in (1, 2):
            raise TypeError('exact envelope bytes and declared schema 1 or 2 required')
        if len(wire) > MAX_WIRE:
            raise HIAEditRejected('E_HIA_EDIT: patch envelope exceeds 16 MiB framing budget')
        _, arena_size = scratch_sizes(len(wire))
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(MAX_RESULT)
        arena = ctypes.create_string_buffer(arena_size)
        struct.pack_into('<2Q', arena, 0, 2, declared_schema)
        code = self._entry(source, len(wire), output, MAX_RESULT, arena, arena_size)
        if code == DECLARED_SCHEMA_ERROR:
            from .hia_agent_store import AgentRejected
            raise AgentRejected('E_HIA_PATCH_SCHEMA', 'patch artifact differs from declared patch schema')
        if code in ERROR_MESSAGES:
            raise HIAEditRejected('E_HIA_EDIT: ' + ERROR_MESSAGES[code])
        if not 36 <= code <= MAX_RESULT:
            raise HIAEditRejected('E_HIA_EDIT: invalid native Agent patch result extent')
        return result_payloads(ctypes.string_at(output, code))


def installed_agent_candidate_patch(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeAgentCandidatePatch)


def apply_candidate_patch(manifest, original, request, patch_schema):
    """Return opaque candidate/diagnostic bytes after two full native checks.

    The caller has already authorized the artifact references and frozen the
    selected manifest path for this operation. The adjacent admission image is
    independently bound to its exact current source; adjacency is not a common
    build or cold-qualification claim. No selected failure invokes host policy.
    """
    from .hia_agent_store import AgentRejected
    from .hia_core_admission_native import installed_core_admission
    from .hia_program import HIAProgramRejected
    from .hia_program_tools import HIAEditRejected
    versions = {'hepta.hia.patch.v1': 1, 'hepta.hia.patch.v2': 2}
    if type(patch_schema) is not str or patch_schema not in versions:
        raise AgentRejected('E_HIA_PATCH_SCHEMA', 'unsupported declared patch schema')
    try:
        image = installed_agent_candidate_patch(manifest)
        admission = installed_core_admission(str(Path(manifest).resolve(strict=True).parent / 'admission-manifest.json'))
        combined = envelope(original, request)
        canonical_base, _, _, _ = image.transform(combined, extract=True)
        admission.admit(canonical_base)
        candidate, diagnostics = image.result(combined, versions[patch_schema])
        admission.admit(candidate)
        return candidate, diagnostics
    except (AgentRejected, HIAEditRejected, HIAProgramRejected):
        raise
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAEditRejected('E_HIA_EDIT: selected native Agent patch refused: ' + str(exc)) from exc

"""Explicit complete native enum-match lowering with descriptor-only transport.

The surrounding elaborator resolves nominal types and owns its environments.
This bridge copies that admitted state without deciding cases, transfers,
padding, generated names or Core CFG. The HIA image returns complete Core
objects and the final fresh-name counter, including semantic refusals.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import json
import os
import struct

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/enum_match.hiaasm')
SCHEMA = 'hepta.hia.enum-match-native.v1'
SELECTOR = 'HEPTA_HIA_ENUM_MATCH_MANIFEST'
MAGIC = int.from_bytes(b'HIAMAT01', 'little')
HEADER_BYTES = 64
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 64 << 20
WORKSPACE_BYTES = 32 << 20
ERRORS = {
    1: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    2: ('E_HIA_FORMAT', 'enum match: expected exactly cases, op, value'),
    3: ('E_HIA_NAME', 'value reference: invalid/reserved ASCII identifier'),
    4: ('E_HIA_NAME', 'value reference: identifier uses the elaborator namespace'),
    5: ('E_HIA_SSA', 'undefined/nonlocal nominal value'),
    6: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    7: ('E_HIA_TYPE', 'match requires a nominal enum'),
    8: ('E_HIA_CFG', 'match cases must be a list'),
    9: ('E_HIA_FORMAT', 'match case: expected exactly args, target, variant'),
    10: ('E_HIA_NAME', 'matched variant: invalid/reserved ASCII identifier'),
    11: ('E_HIA_NAME', 'matched variant: identifier uses the elaborator namespace'),
    12: ('E_HIA_FORMAT', 'match case arguments: expected value list'),
    13: ('E_HIA_NAME', 'match case arguments: invalid/reserved ASCII identifier'),
    14: ('E_HIA_CFG', 'duplicate match case'),
    15: ('E_HIA_RESOURCE', 'matched linear enum cannot also escape on its case edge'),
    16: ('E_HIA_CFG', 'enum match must be exhaustive'),
    17: ('E_HIA_NAME', 'edge target: invalid/reserved ASCII identifier'),
    18: ('E_HIA_NAME', 'edge target: identifier uses the elaborator namespace'),
    19: ('E_HIA_CFG', 'nominal edge names a missing block'),
    20: ('E_HIA_RESOURCE', 'nominal linear value duplicated on edge'),
    21: ('E_HIA_RESOURCE', 'edge drops a live nominal value'),
    22: ('E_HIA_TYPE', 'nominal edge types differ'),
    23: ('E_HIA_LOAN', 'inactive padding contains a loan'),
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate native enum-match output field')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-JSON constant in native enum-match result')


def packet(term, environment, signatures, serial):
    """Preserve already-interned descriptor objects and all source values.

    Both type owners intern every nominal descriptor within one elaboration.
    Object IDs only preserve that graph sharing: no Python equality, flattened
    type decision, source-key expansion or hash-as-identity enters this packet.
    Primitive descriptors may be separately materialized; HIA compares their
    transported primitive names. Holding the graph prevents address reuse.
    """
    held, identifiers, descriptors = [], {}, []

    def reference(typ):
        identity = id(typ)
        if identity not in identifiers:
            identifiers[identity] = len(held)
            held.append(typ)
        return identifiers[identity]

    values = [[name, reference(item.typ), item.names, item.external, item.consumed]
              for name, item in environment.items()]
    targets = [[name, [reference(typ) for _, typ in parameters]]
               for name, parameters in signatures.items()]
    index = 0
    while index < len(held):
        typ = held[index]
        descriptors.append([typ.kind, typ.flat, typ.linear,
            [[name, [reference(nested) for _, nested in fields]]
             for name, fields in typ.variants]])
        index += 1
    return transport([serial, term, descriptors, values, targets])


@dataclass(frozen=True)
class MatchResult:
    serial: int
    error: int
    first: dict | None
    blocks: list | None

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


class NativeEnumMatch(NativeHiaJsonImage):
    def lower(self, term, environment, signatures, serial):
        return self.lower_packet(packet(term, environment, signatures, serial), serial=serial)

    def lower_packet(self, wire, *, serial):
        def reject(message):
            raise HIAProgramRejected('native enum-match transport: ' + message, 'E_HIA_TYPE')
        if (type(wire) is not bytes or len(wire) > INPUT_BYTES
                or type(serial) is not int or not 0 <= serial <= 8192):
            reject('invalid packet or starting counter')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(OUTPUT_BYTES)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        extent = self._entry(source, len(wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            reject('input bytes changed')
        if type(extent) is not int or not HEADER_BYTES <= extent <= OUTPUT_BYTES:
            reject('invalid result extent/status ' + str(extent))
        magic, error, final, size, r0, r1, r2, r3 = struct.unpack_from('<8Q', output)
        if (magic != MAGIC or error not in {0, *ERRORS} or r0 or r1 or r2 or r3
                or size != extent - HEADER_BYTES or not serial <= final <= 8192
                or error == 1 and final != 8192):
            reject('invalid header or fresh-state correlation')
        try:
            payload = json.loads(ctypes.string_at(ctypes.addressof(output) + HEADER_BYTES, size),
                object_pairs_hook=_pairs, parse_constant=_constant)
            if type(payload) is not dict or set(payload) != {'first', 'blocks'}:
                raise ValueError('invalid complete CFG envelope')
            first, blocks = payload['first'], payload['blocks']
            if error:
                if first is not None or blocks is not None:
                    raise ValueError('semantic refusal supplied a CFG')
            else:
                if (type(first) is not dict or set(first) != {'ops', 'term'}
                        or type(first['ops']) is not list or type(first['term']) is not dict
                        or type(blocks) is not list or not 2 <= len(blocks) <= 64):
                    raise ValueError('invalid first block suffix or generated block inventory')
                for block in blocks:
                    if (type(block) is not dict or set(block) != {'id', 'params', 'ops', 'term'}
                            or type(block['id']) is not str or type(block['params']) is not list
                            or type(block['ops']) is not list or type(block['term']) is not dict):
                        raise ValueError('invalid complete generated Core block')
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            reject('invalid payload: ' + str(exc))
        return MatchResult(final, error, first, blocks)


def installed_enum_match(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeEnumMatch)


def selected_enum_match():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_enum_match(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native enum match refused: ' + str(exc),
                                 'E_HIA_TYPE') from exc

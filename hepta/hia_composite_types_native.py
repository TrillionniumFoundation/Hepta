"""Explicit HIA nominal-type sessions and descriptor-only object transport.

The HIA image owns declarations, reference resolution, layout, exact type
interning, partial records, symbolic loan analysis and their stateful budgets.
This bridge never invokes the hosted type resolver.  The surrounding nominal
elaborator, primitive verifier, JSON object custody and installation remain
separate owners.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import json
import os
import struct
from threading import RLock

from .hia_json_preflight_native import (NativeHiaJsonImage, _installed_json_image,
                                         _source_resource_path)
from .hia_program import HIAProgramRejected


SOURCE = _source_resource_path('examples/hia_bootstrap/composite_types.hiaasm')
SCHEMA = 'hepta.hia.composite-types-native.v1'
SELECTOR = 'HEPTA_HIA_COMPOSITE_TYPES_MANIFEST'
MAGIC = int.from_bytes(b'HIATYP01', 'little')
HEADER_BYTES = 64
MAX_COMMAND_BYTES = (8 << 20) + 128
OUTPUT_BYTES = 64 << 20
SESSION_BYTES = 128 << 20
PRIMITIVES = ('bool', 'unit', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16',
              'u32', 'u64', 'isize', 'usize', 'buffer', 'readbuf', 'mutbuf', 'chain')
DESCRIPTOR_FIELDS = frozenset({'id', 'kind', 'name', 'args', 'flat', 'fields',
    'variants', 'state', 'result', 'poll', 'cancel', 'linear', 'record'})

# Versioned native statuses; installed callers never import authoring tools.
# An unrecognized error is a transport failure, never permission to fall back.
ERRORS = {
    1: ('E_HIA_FORMAT', 'nominal type object has an unexpected field inventory'),
    2: ('E_HIA_LIMIT', 'invalid nominal type inventory'),
    3: ('E_HIA_TYPE', 'nominal type requires a kind'),
    4: ('E_HIA_TYPE', 'unknown nominal type kind'),
    5: ('E_HIA_NAME', 'invalid/reserved ASCII identifier'),
    6: ('E_HIA_NAME', 'identifier uses the elaborator namespace'),
    7: ('E_HIA_TYPE', 'duplicate/reserved nominal type'),
    8: ('E_HIA_TYPE', 'invalid type parameter list'),
    9: ('E_HIA_TYPE', 'reserved type parameter'),
    10: ('E_HIA_TYPE', 'duplicate type parameter'),
    11: ('E_HIA_TYPE', 'task protocols have concrete state/result signatures'),
    12: ('E_HIA_TYPE', 'enum requires 1..32 variants'),
    13: ('E_HIA_TYPE', 'duplicate enum variant'),
    14: ('E_HIA_LIMIT', 'nominal fields exceed the finite profile'),
    15: ('E_HIA_TYPE', 'duplicate nominal field'),
    16: ('E_HIA_LIMIT', 'type reference nesting exceeds budget'),
    17: ('E_HIA_TYPE', 'recursive chain types require composite v2'),
    18: ('E_HIA_TYPE', 'unknown or unapplied nominal type'),
    19: ('E_HIA_LIMIT', 'invalid partial-record field inventory'),
    20: ('E_HIA_INIT', 'duplicate initialized record field'),
    21: ('E_HIA_TYPE', 'partial type requires a declared nominal record'),
    22: ('E_HIA_INIT', 'initialized fields must exist in declaration order'),
    23: ('E_HIA_TYPE', 'generic type arity mismatch'),
    24: ('E_HIA_TYPE', 'recursive by-value nominal declarations'),
    25: ('E_HIA_LIMIT', 'partial declaration analysis budget exceeded'),
    26: ('E_HIA_LIMIT', 'nominal layout nesting exceeds budget'),
    27: ('E_HIA_LIMIT', 'symbolic type argument nesting exceeds budget'),
    28: ('E_HIA_LOAN', 'partial record fields may not contain stored loans'),
    29: ('E_HIA_TYPE', 'recursive by-value nominal layout'),
    30: ('E_HIA_LIMIT', 'generic instantiation budget exceeded'),
    31: ('E_HIA_LOAN', 'enum payloads cannot contain loans in composite v1'),
    32: ('E_HIA_LOAN', 'task state/results may not retain loans'),
    33: ('E_HIA_LIMIT', 'flattened nominal layout exceeds budget'),
    34: ('E_HIA_TYPE', 'partial type requires a nominal record in composite v3/v4'),
    35: ('E_HIA_LIMIT', 'generic/partial instantiation budget exceeded'),
    36: ('E_HIA_LIMIT', 'flattened partial-record layout exceeds budget'),
}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate native composite descriptor field')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-JSON constant in native composite descriptor')


def _identifier(value):
    # This validates the transport's unsigned ID, not a language identifier.
    return type(value) is int and 0 < value <= 0xffffffff


@dataclass(frozen=True)
class _NativeTypeIdentity:
    """An exact HIA-issued identity in one live, uniquely owned session.

    Keeping the nonce object alive prevents reuse of a Python object's address
    from identifying a later session. Hash collisions have ordinary dictionary
    equality handling; hashes are never the native type identity.
    """
    session: object
    identifier: int


class NativeCompositeTypes(NativeHiaJsonImage):
    """Immutable shared code; every resolver receives private persistent state."""

    def session(self, definitions, *, recursive_chain=False, partial_records=False):
        return NativeCompositeTypeSession(self, definitions,
            recursive_chain=recursive_chain, partial_records=partial_records)


class NativeCompositeTypeSession:
    """Transport a stateful HIA resolver without repeating its type semantics."""

    def __init__(self, image, definitions, *, recursive_chain=False, partial_records=False):
        self._image = image
        self._lock = RLock()
        self._nonce = object()
        self._types = {}
        self._ids = {}
        self._descriptors = {}
        self._observations = {}
        self._broken = False
        self._closed = False
        self._output = ctypes.create_string_buffer(OUTPUT_BYTES)
        self._state = ctypes.create_string_buffer(SESSION_BYTES)
        self._command({'op': 'init', 'definitions': definitions,
            'recursive_chain': recursive_chain, 'partial_records': partial_records}, result=False)

    @property
    def observations(self):
        """Counters supplied by HIA, including a completed semantic refusal."""
        with self._lock:
            return dict(self._observations)

    def close(self):
        with self._lock:
            self._closed = True
            self._output = self._state = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _refuse_abi(self, message):
        self._broken = True
        raise HIAProgramRejected('native composite type transport: ' + message, 'E_HIA_TYPE')

    @staticmethod
    def _field_pairs(value):
        if type(value) is not list:
            raise ValueError('field descriptor is not a list')
        result = []
        for item in value:
            if (type(item) is not list or len(item) != 2 or type(item[0]) is not str
                    or not _identifier(item[1])):
                raise ValueError('invalid field descriptor')
            result.append((item[0], item[1]))
        return tuple(result)

    def _materialize(self, payload):
        """Decode the native DAG ABI; never compute layouts or type identities."""
        from .hia_program_composite import _Type
        value = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant)
        if type(value) is not dict or set(value) != {'types'} or type(value['types']) is not list:
            raise ValueError('invalid descriptor envelope')
        pending = {}
        for item in value['types']:
            if type(item) is not dict or set(item) != DESCRIPTOR_FIELDS:
                raise ValueError('invalid descriptor fields')
            identifier, kind = item['id'], item['kind']
            if (not _identifier(identifier) or identifier in pending or identifier in self._types
                    or type(kind) is not str or kind not in
                    {'primitive', 'record', 'enum', 'task', 'partial_record'}):
                raise ValueError('invalid/repeated descriptor identity')
            if ((kind == 'partial_record' and item['name'] is not None)
                    or (kind != 'partial_record' and type(item['name']) is not str)):
                raise ValueError('invalid descriptor name')
            if (identifier <= len(PRIMITIVES)) != (kind == 'primitive'):
                raise ValueError('invalid primitive descriptor identity')
            if kind == 'primitive' and item['name'] != PRIMITIVES[identifier - 1]:
                raise ValueError('invalid primitive descriptor name')
            args, flat = item['args'], item['flat']
            if type(args) is not list or any(not _identifier(x) for x in args):
                raise ValueError('invalid descriptor arguments')
            if (type(flat) is not list or any(type(x) is not int or not 1 <= x <= len(PRIMITIVES)
                                            for x in flat)):
                raise ValueError('invalid flat descriptor slots')
            fields = self._field_pairs(item['fields'])
            if type(item['variants']) is not list:
                raise ValueError('invalid variant descriptor list')
            variants = []
            for variant in item['variants']:
                if type(variant) is not list or len(variant) != 2 or type(variant[0]) is not str:
                    raise ValueError('invalid variant descriptor')
                variants.append((variant[0], self._field_pairs(variant[1])))
            for name in ('state', 'result', 'record'):
                if item[name] is not None and not _identifier(item[name]):
                    raise ValueError('invalid descriptor reference')
            if (type(item['linear']) is not bool
                    or any(item[name] is not None and type(item[name]) is not str
                           for name in ('poll', 'cancel'))):
                raise ValueError('invalid descriptor attributes')
            references = set(args)
            references.update(identifier for _, identifier in fields)
            references.update(identifier for _, nested in variants for _, identifier in nested)
            references.update(item[name] for name in ('state', 'result', 'record')
                              if item[name] is not None)
            pending[identifier] = (item, fields, tuple(variants), references)
        available = dict(self._types)
        materialized = {}
        while pending:
            progressed = False
            for identifier, (item, fields, variants, references) in tuple(pending.items()):
                if not references.issubset(available):
                    continue
                kind = item['kind']
                typ = _Type(
                    key=item['name'] if kind == 'primitive' else _NativeTypeIdentity(self._nonce, identifier),
                    kind=kind, flat=tuple(PRIMITIVES[x - 1] for x in item['flat']),
                    fields=tuple((name, available[target]) for name, target in fields),
                    variants=tuple((name, tuple((field, available[target]) for field, target in nested))
                                   for name, nested in variants),
                    state=available[item['state']] if item['state'] is not None else None,
                    result=available[item['result']] if item['result'] is not None else None,
                    poll=item['poll'], cancel=item['cancel'], linear=item['linear'],
                    record=available[item['record']] if item['record'] is not None else None)
                available[identifier] = typ
                materialized[identifier] = (typ, item)
                del pending[identifier]
                progressed = True
            if not progressed:
                raise ValueError('unknown or cyclic descriptor reference')
        for identifier, (typ, descriptor) in materialized.items():
            self._types[identifier] = typ
            self._ids[id(typ)] = identifier
            self._descriptors[identifier] = descriptor

    def _command(self, command, *, result=True):
        with self._lock:
            if self._closed or self._broken:
                self._refuse_abi('session is closed or has a failed transport')
            try:
                raw = json.dumps(command, ensure_ascii=False, allow_nan=False,
                                 separators=(',', ':')).encode('utf-8')
            except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError) as exc:
                self._refuse_abi('invalid command JSON: ' + str(exc))
            if len(raw) > MAX_COMMAND_BYTES:
                self._refuse_abi('command exceeds the bounded transport')
            source = ctypes.create_string_buffer(raw, max(1, len(raw)))
            extent = self._image._entry(source, len(raw), self._output, OUTPUT_BYTES,
                                         self._state, SESSION_BYTES)
            if type(extent) is not int or not HEADER_BYTES <= extent <= OUTPUT_BYTES:
                self._refuse_abi('invalid native frame extent/status ' + str(extent))
            magic, error, identifier, size, cached, active, steps, reserved = struct.unpack_from(
                '<8Q', self._output)
            if magic != MAGIC or reserved or HEADER_BYTES + size != extent:
                self._refuse_abi('invalid native frame header')
            if error and (error not in ERRORS or identifier != 0):
                self._refuse_abi('unrecognized/inconsistent native semantic status ' + str(error))
            try:
                self._materialize(ctypes.string_at(ctypes.addressof(self._output) + HEADER_BYTES, size))
            except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
                self._refuse_abi('invalid native descriptors: ' + str(exc))
            self._observations = {'cache_count': cached, 'active_count': active,
                                  'partial_declaration_steps': steps}
            if error:
                code, message = ERRORS[error]
                raise HIAProgramRejected(message, code)
            if (result and identifier not in self._types) or (not result and identifier != 0):
                self._refuse_abi('invalid native result identity')
            return self._types[identifier] if result else None

    def resolve(self, reference):
        return self._command({'op': 'resolve', 'ref': reference})

    def partial_record(self, base, initialized):
        with self._lock:
            identifier = self._ids.get(id(base))
            if identifier is None or self._types[identifier] is not base:
                self._refuse_abi('partial base does not belong to this session')
            return self._command({'op': 'partial', 'base': identifier, 'initialized': list(initialized)})


def installed_composite_types(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeCompositeTypes)


def selected_composite_types(definitions, *, recursive_chain=False, partial_records=False):
    """Select one ordinary resolver; every selected failure is final."""
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_composite_types(manifest).session(definitions,
            recursive_chain=recursive_chain, partial_records=partial_records)
    except HIAProgramRejected:
        raise
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native composite types refused: ' + str(exc),
                                 'E_HIA_TYPE') from exc

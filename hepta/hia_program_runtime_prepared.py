"""Explicit read-only program metadata for repeated independent VM entries.

The public verifier and default runtime are unchanged. This is a local execution
plan, not a verification receipt, executable image, global cache, or source
authority. A caller still performs its original verification and source checks.
Only ordinary already immutable VerifiedProgram metadata is prepared. Every
entry still constructs an ordinary fresh _Machine and executes every old tick.
"""
from __future__ import annotations

import os
from types import MappingProxyType, MemberDescriptorType

from . import hia_json_decode as _decoder_module
from . import hia_program as _program_module
from .hia_program import HIAProgramRejected, VerifiedProgram

_PROGRAM_TYPE = VerifiedProgram
_MISSING = object()
_REFERENCE_AS_DICT = vars(_PROGRAM_TYPE)['as_dict']
_REFERENCE_DECODE = _program_module.decode_internal_canonical
_REFERENCE_JSON = _decoder_module.json
_REFERENCE_LOADS = _REFERENCE_JSON.loads
_REFERENCE_ENCODING = _REFERENCE_JSON.detect_encoding
_REFERENCE_DEFAULT_DECODER = _REFERENCE_JSON._default_decoder
_REFERENCE_DECODER_TYPE = type(_REFERENCE_DEFAULT_DECODER)
_REFERENCE_DECODER_DECODE = vars(_REFERENCE_DECODER_TYPE).get('decode', _MISSING)
_REFERENCE_DECODER_RAW_DECODE = vars(_REFERENCE_DECODER_TYPE).get('raw_decode', _MISSING)
_REFERENCE_DECODER_SCAN_FIELD = vars(_REFERENCE_DECODER_TYPE).get('scan_once', _MISSING)
_REFERENCE_SCAN_ONCE = object.__getattribute__(_REFERENCE_DEFAULT_DECODER, '__dict__').get('scan_once', _MISSING)
_REFERENCE_GETATTRIBUTE = object.__getattribute__
_REFERENCE_SLOTS = vars(_PROGRAM_TYPE).get('__slots__', _MISSING)
_REFERENCE_CANONICAL_FIELD = vars(_PROGRAM_TYPE).get('canonical_bytes', _MISSING)
_REFERENCE_STRUCTURED_FIELD = vars(_PROGRAM_TYPE).get('structured_bytes', _MISSING)
_REFERENCE_LIMITS = (_program_module.MAX_NODES, _program_module.MAX_DEPTH)
_SELECTOR = 'HEPTA_HIA_JSON_DECODE_MANIFEST'


def _default_decoder_unchanged():
    if (_REFERENCE_JSON._default_decoder is not _REFERENCE_DEFAULT_DECODER
            or _REFERENCE_JSON.detect_encoding is not _REFERENCE_ENCODING
            or type(_REFERENCE_DEFAULT_DECODER) is not _REFERENCE_DECODER_TYPE):
        return False
    namespace = vars(_REFERENCE_DECODER_TYPE)
    if (namespace.get('__getattribute__', object.__getattribute__) is not object.__getattribute__
            or '__getattr__' in namespace
            or namespace.get('decode', _MISSING) is not _REFERENCE_DECODER_DECODE
            or namespace.get('raw_decode', _MISSING) is not _REFERENCE_DECODER_RAW_DECODE
            or namespace.get('scan_once', _MISSING) is not _REFERENCE_DECODER_SCAN_FIELD):
        return False
    values = object.__getattribute__(_REFERENCE_DEFAULT_DECODER, '__dict__')
    return (type(values) is dict and 'decode' not in values and 'raw_decode' not in values
            and values.get('scan_once', _MISSING) is _REFERENCE_SCAN_ONCE)


def _ordinary_default_program(program):
    # These are metadata-only checks on our fixed class, never lookups on a
    # caller's custom provider. Any customization keeps the original path.
    if type(program) is not _PROGRAM_TYPE:
        return False
    namespace = vars(_PROGRAM_TYPE)
    if (_PROGRAM_TYPE.__bases__ != (object,)
            or namespace.get('__getattribute__', object.__getattribute__)
                is not _REFERENCE_GETATTRIBUTE
            or '__getattr__' in namespace
            or namespace.get('as_dict') is not _REFERENCE_AS_DICT
            or namespace.get('canonical_bytes', _MISSING) is not _REFERENCE_CANONICAL_FIELD
            or namespace.get('structured_bytes', _MISSING) is not _REFERENCE_STRUCTURED_FIELD):
        return False
    # The actual verified class is @dataclass(frozen=True, slots=True).
    # Inspect only its unchanged native member slots; a replaced descriptor,
    # unset slot, or non-bytes value keeps the original dynamic as_dict path.
    if (namespace.get('__slots__', _MISSING) is not _REFERENCE_SLOTS
            or type(_REFERENCE_CANONICAL_FIELD) is not MemberDescriptorType
            or type(_REFERENCE_STRUCTURED_FIELD) is not MemberDescriptorType
            or _REFERENCE_CANONICAL_FIELD.__objclass__ is not _PROGRAM_TYPE
            or _REFERENCE_STRUCTURED_FIELD.__objclass__ is not _PROGRAM_TYPE):
        return False
    try:
        canonical = _REFERENCE_CANONICAL_FIELD.__get__(program, _PROGRAM_TYPE)
        structured = _REFERENCE_STRUCTURED_FIELD.__get__(program, _PROGRAM_TYPE)
    except AttributeError:
        return False
    if (type(canonical) is not bytes
            or structured is not None and type(structured) is not bytes):
        return False
    if (_program_module.decode_internal_canonical is not _REFERENCE_DECODE
            or _decoder_module.decode_internal_canonical is not _REFERENCE_DECODE
            or _decoder_module.json is not _REFERENCE_JSON
            or _REFERENCE_JSON.loads is not _REFERENCE_LOADS
            or not _default_decoder_unchanged()
            or (_program_module.MAX_NODES, _program_module.MAX_DEPTH) != _REFERENCE_LIMITS):
        return False
    # Selected decoding is an actual effect. Never replace it with old metadata.
    # Empty selection must still raise at the original as_dict call.
    return os.environ.get(_SELECTOR) is None


def _freeze(value):
    typ = type(value)
    if typ is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if typ is list:
        return tuple(_freeze(item) for item in value)
    if value is None or typ in (str, int, bool, float):
        return value
    raise HIAProgramRejected('non-JSON prepared VM metadata', 'E_HIA_RUNTIME_INVARIANT')


class _PreparedRuntimeProgram:
    # A fixed module-level type; no per-entry class, closure, or back-reference.
    __slots__ = ('_program', '_canonical', '_structured', '_document')

    def __init__(self, program, canonical, structured, document):
        object.__setattr__(self, '_program', program)
        object.__setattr__(self, '_canonical', canonical)
        object.__setattr__(self, '_structured', structured)
        object.__setattr__(self, '_document', document)

    def __setattr__(self, name, value):
        raise AttributeError('prepared VM metadata is read-only')

    def __delattr__(self, name):
        raise AttributeError('prepared VM metadata is read-only')

    def as_dict(self):
        program = self._program
        if _ordinary_default_program(program):
            canonical = _REFERENCE_CANONICAL_FIELD.__get__(program, _PROGRAM_TYPE)
            structured = _REFERENCE_STRUCTURED_FIELD.__get__(program, _PROGRAM_TYPE)
            if (canonical == self._canonical and structured == self._structured):
                return self._document
        # Preserve the literal dynamic call on all later binding/byte/selector
        # changes; never silently execute a stale prepared document.
        return program.as_dict()

    @property
    def sha256(self):
        return self._program.sha256

    @property
    def input_sha256(self):
        return self._program.input_sha256


def prepare_runtime_program(program):
    """Prepare immutable metadata; preserve custom/default legacy paths.

    No verification is omitted: the existing public execute_program still
    verifies each invocation, and existing _Machine callers are unchanged.
    The independent ABI fixture has already assembled and verified its fixed
    program before explicitly requesting this local metadata snapshot.
    """
    if not _ordinary_default_program(program):
        return program
    canonical = _REFERENCE_CANONICAL_FIELD.__get__(program, _PROGRAM_TYPE)
    structured = _REFERENCE_STRUCTURED_FIELD.__get__(program, _PROGRAM_TYPE)
    document = program.as_dict()
    frozen = _freeze(document)
    # A changed immutable byte binding or decoder during preparation does not
    # authorize the just-built snapshot. Keep the original object/path.
    if not _ordinary_default_program(program):
        return program
    if (_REFERENCE_CANONICAL_FIELD.__get__(program, _PROGRAM_TYPE) != canonical
            or _REFERENCE_STRUCTURED_FIELD.__get__(program, _PROGRAM_TYPE) != structured):
        return program
    return _PreparedRuntimeProgram(program, canonical, structured, frozen)

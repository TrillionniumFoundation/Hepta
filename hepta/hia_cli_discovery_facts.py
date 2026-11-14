"""Bounded, non-calling observations for the optional discovery expression.

This adapter transports exact Python object/code facts. The HIA controller
compares their digest with its authoring-time facts and selects a native or a
real foreign expression. An unrecognised object is never coerced, compared,
iterated or passed through its attributes to try to obtain admission.
"""
from __future__ import annotations

import _thread
import builtins
import dataclasses
from hashlib import sha256 as _sha256
import json
import json.encoder
import struct
import sys
import types

_TYPE = ().__class__.__class__
_NONE = None.__class__
_BOOL = True.__class__
_INT = (0).__class__
_FLOAT = (0.0).__class__
_STR = ''.__class__
_BYTES = b''.__class__
_TUPLE = ().__class__
_LIST = [].__class__
_DICT = {}.__class__
_SET = {0}.__class__
_FROZENSET = (lambda value: value in {0, 1}).__code__.co_consts[1].__class__
_CODE = (lambda: None).__code__.__class__
_FUNCTION = (lambda: None).__class__
_MISSING = object()
_BUILTIN_TYPES = (_NONE, _BOOL, _INT, _FLOAT, _STR, _BYTES, _TUPLE,
                  _LIST, _DICT, _SET, _FROZENSET, _TYPE, object, complex,
                  range, slice, Ellipsis.__class__, NotImplemented.__class__,
                  types.CodeType, types.FunctionType, types.BuiltinFunctionType,
                  types.MethodType, property, BaseException, Exception, ValueError,
                  TypeError, RuntimeError, OverflowError)
_MAX_BYTES = 1 << 20

# These are mechanical observer intrinsics, never a replacement for the
# provider's live globals/builtins. Check the live table first; a changed
# builtin selects the genuine foreign expression without calling it here.
_BUILTINS = builtins.__dict__
_MECHANICAL_FUNCTIONS = (('len', len), ('any', any), ('id', id), ('sorted', sorted))
_MECHANICAL_CLASSES = (('str', _STR), ('tuple', _TUPLE), ('dict', _DICT),
                       ('set', _SET), ('frozenset', _FROZENSET), ('type', _TYPE),
                       ('object', _TYPE.__mro__[-1]), ('enumerate', enumerate))
len, any, id, sorted = (row[1] for row in _MECHANICAL_FUNCTIONS)
str, tuple, dict, set, frozenset, type, object, enumerate = (row[1] for row in _MECHANICAL_CLASSES)
_PACK = struct.pack
_GETTRACE, _GETPROFILE, _THREAD_COUNT = sys.gettrace, sys.getprofile, _thread._count


def _oneof(value, choices):
    for choice in choices:
        if value is choice:
            return True
    return False


def _mechanics_unchanged():
    if _DICT.__len__(_BUILTINS) > 4096:
        return False
    for key in _BUILTINS:
        if _TYPE(key) is not _STR:
            return False
    for name, value in _MECHANICAL_FUNCTIONS:
        if (_DICT.get(_BUILTINS, name) is not value
                or _TYPE(value) is not types.BuiltinFunctionType
                or value.__self__ is not builtins or value.__name__ != name):
            return False
    for name, value in _MECHANICAL_CLASSES:
        if (_DICT.get(_BUILTINS, name) is not value or _TYPE(value) is not _TYPE
                or _TYPE.__getattribute__(value, '__flags__') & 512):
            return False
    for value, name, module in ((_PACK, 'pack', '_struct'), (_GETTRACE, 'gettrace', 'sys'),
                                (_GETPROFILE, 'getprofile', 'sys'), (_THREAD_COUNT, '_count', '_thread')):
        if (_TYPE(value) is not types.BuiltinFunctionType
                or value.__name__ != name or value.__module__ != module):
            return False
    if _TYPE(_sha256) is not types.BuiltinFunctionType:
        return False
    return True


class Unobserved(Exception):
    pass


def _module(module, name):
    if _TYPE(module) is not types.ModuleType:
        raise Unobserved('nonordinary module')
    namespace = types.ModuleType.__getattribute__(module, '__dict__')
    if _TYPE(namespace) is not _DICT:
        raise Unobserved('module identity')
    if len(namespace) > 4096 or any(_TYPE(key) is not _STR for key in namespace):
        raise Unobserved('non-string or unbounded namespace')
    observed = namespace.get('__name__')
    if _TYPE(observed) is not _STR or observed != name:
        raise Unobserved('module identity')
    return namespace


def _name(value):
    if _TYPE(value) is _TYPE:
        namespace = type.__getattribute__(value, '__dict__')
        module = (type.__getattribute__(value, '__module__')
                  if _oneof(value, _BUILTIN_TYPES) else namespace.get('__module__', 'builtins'))
        qualname = type.__getattribute__(value, '__qualname__')
        if _TYPE(module) is not _STR or _TYPE(qualname) is not _STR:
            raise Unobserved('class name facts are not ordinary strings')
        return module, qualname
    raise Unobserved('not an ordinary class')


def _slot(value, name):
    cls = _TYPE(value)
    if _TYPE(cls) is not _TYPE:
        raise Unobserved('custom metaclass')
    descriptor = type.__getattribute__(cls, '__dict__').get(name)
    if (_TYPE(descriptor) is not types.MemberDescriptorType
            or descriptor.__objclass__ is not cls):
        raise Unobserved('not an original C slot')
    return descriptor.__get__(value, cls)


class _Encoder:
    def __init__(self):
        self.parts = []
        self.size = 0
        self.active = set()

    def raw(self, value):
        self.size += len(value)
        if self.size > _MAX_BYTES:
            raise Unobserved('facts exceed mechanical transport')
        self.parts.append(value)

    def scalar(self, tag, value):
        self.raw(tag + _PACK('<Q', len(value)) + value)

    def data(self, value, depth=0):
        if depth > 64:
            raise Unobserved('facts depth')
        t = _TYPE(value)
        if t is _NONE:
            self.raw(b'n'); return
        if t is _BOOL:
            self.raw(b't' if value else b'f'); return
        if t is _INT:
            if value.bit_length() > 128:
                raise Unobserved('unexpected metadata integer')
            self.scalar(b'i', str(value).encode('ascii')); return
        if t is _FLOAT:
            self.scalar(b'd', _PACK('<d', value)); return
        if t is _STR:
            self.scalar(b's', value.encode('utf-8', 'surrogatepass')); return
        if t is _BYTES:
            self.scalar(b'b', value); return
        if value is Ellipsis:
            self.raw(b'e'); return
        if t is _CODE:
            self.raw(b'c')
            # Semantic code fields are portable across wheel locations. The
            # project provider anchors separately retain the actual definition
            # code objects, including their nonsemantic source locations.
            for field in ('co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount',
                          'co_nlocals', 'co_stacksize', 'co_flags', 'co_code',
                          'co_consts', 'co_names', 'co_varnames', 'co_freevars',
                          'co_cellvars', 'co_exceptiontable', 'co_name', 'co_qualname'):
                self.data(object.__getattribute__(value, field), depth + 1)
            return
        if _oneof(t, (_TUPLE, _LIST, _DICT, _SET, _FROZENSET)):
            identity = id(value)
            if identity in self.active or len(value) > 4096:
                raise Unobserved('cycle or oversized metadata container')
            self.active.add(identity)
            try:
                if t is _DICT:
                    if any(_TYPE(key) is not _STR for key in value):
                        raise Unobserved('non-string dictionary key')
                    self.raw(b'm' + _PACK('<Q', len(value)))
                    for key, item in value.items():
                        self.data(key, depth + 1); self.data(item, depth + 1)
                elif _oneof(t, (_SET, _FROZENSET)):
                    items = []
                    for item in value:
                        child = _Encoder(); child.data(item, depth + 1)
                        items.append(b''.join(child.parts))
                    self.raw((b'r' if t is _FROZENSET else b'q') + _PACK('<Q', len(items)))
                    for item in sorted(items):
                        self.scalar(b'v', item)
                else:
                    self.raw((b'a' if t is _LIST else b'u') + _PACK('<Q', len(value)))
                    for item in value:
                        self.data(item, depth + 1)
            finally:
                self.active.remove(identity)
            return
        if t is types.BuiltinFunctionType:
            self.raw(b'B'); self.data((value.__module__, value.__name__), depth + 1)
            return
        if _oneof(t, (types.GetSetDescriptorType, types.MemberDescriptorType,
                      types.MethodDescriptorType, types.WrapperDescriptorType)):
            self.raw(b'D'); self.data((t.__name__, value.__name__, _name(value.__objclass__)), depth + 1)
            return
        if t is _TYPE and any(value is item for item in _BUILTIN_TYPES):
            self.raw(b'T'); self.data(_name(value), depth + 1); return
        raise Unobserved('unsupported fact object')

    def function(self, value, namespace):
        if (_TYPE(value) is not _FUNCTION or value.__globals__ is not namespace
                or value.__closure__ is not None):
            raise Unobserved('function ownership')
        self.data((value.__code__, value.__defaults__, value.__kwdefaults__))
        globals_dict = value.__globals__
        builtins_dict = value.__builtins__
        if (_TYPE(builtins_dict) is not _DICT
                or any(_TYPE(key) is not _STR for key in builtins_dict)):
            raise Unobserved('function builtins ownership')
        for name in value.__code__.co_names:
            self.data(name)
            item = globals_dict.get(name, _MISSING)
            if item is _MISSING:
                item = builtins_dict.get(name, _MISSING)
            if item is _MISSING:
                self.raw(b'-')
            elif _TYPE(item) is _FUNCTION:
                self.raw(b'F'); self.data((item.__module__, item.__qualname__, item.__code__))
            elif _TYPE(item) is types.ModuleType:
                self.raw(b'M'); self.data(types.ModuleType.__getattribute__(item, '__dict__').get('__name__'))
            elif _TYPE(item) is types.MappingProxyType:
                # Each reachable intrinsic metadata map is checked below by
                # its definition-time anchor and its complete typed entries.
                self.raw(b'P')
            elif _TYPE(item) is _TYPE:
                if any(item is value for value in _BUILTIN_TYPES):
                    self.data(item)
                else:
                    self.raw(b'C'); self.ordinary_class(item)
            elif _TYPE(item) is _NONE or _oneof(_TYPE(item), (_BOOL, _INT, _FLOAT, _STR, _BYTES,
                                                        _TUPLE, _LIST, _DICT, _SET, _FROZENSET,
                                                        types.BuiltinFunctionType)):
                self.data(item)
            elif name in ('_default_encoder', '_FIELD'):
                # _default_encoder is not used by either fixed output shape.
                # _FIELD identity is separately checked for every dataclass field.
                self.raw(b'O'); self.data(_name(_TYPE(item)))
            else:
                raise Unobserved('unmodelled global dependency')

    def ordinary_class(self, cls):
        if _TYPE(cls) is not _TYPE:
            raise Unobserved('class metaprotocol')
        self.data(_name(cls))
        namespace = type.__getattribute__(cls, '__dict__')
        if any(_TYPE(key) is not _STR for key in namespace):
            raise Unobserved('class keys')
        for key, value in namespace.items():
            if key == '__dataclass_fields__':
                continue
            self.data(key)
            t = _TYPE(value)
            if t is _FUNCTION:
                self.data((value.__code__, value.__defaults__, value.__kwdefaults__))
            elif _oneof(t, (types.GetSetDescriptorType, types.MemberDescriptorType,
                            types.MethodDescriptorType, types.WrapperDescriptorType)):
                self.data((t.__name__, value.__name__, _name(value.__objclass__)))
            elif _oneof(t, (staticmethod, classmethod)):
                function = value.__func__
                self.data((t.__name__, function.__code__, function.__defaults__))
            elif key == '__dataclass_params__':
                if _TYPE(value).__module__ != 'dataclasses':
                    raise Unobserved('dataclass parameters')
                self.data(tuple(_slot(value, name) for name in ('init', 'repr', 'eq', 'order', 'unsafe_hash', 'frozen')))
            else:
                self.data(value)


def _json_facts(encoder, cli_namespace):
    module = cli_namespace.get('json')
    if module is not json:
        raise Unobserved('output JSON module replacement')
    namespace = _module(module, 'json')
    implementation = _module(json.encoder, 'json.encoder')
    encoder.function(namespace['dumps'], namespace)
    cls = namespace['JSONEncoder']
    if cls is not implementation.get('JSONEncoder'):
        raise Unobserved('encoder class split')
    encoder.ordinary_class(cls)
    class_namespace = type.__getattribute__(cls, '__dict__')
    for name in ('__init__', 'encode', 'iterencode', 'default'):
        encoder.function(class_namespace[name], implementation)
    encoder.function(implementation['_make_iterencode'], implementation)
    for name in ('encode_basestring', 'encode_basestring_ascii', 'c_make_encoder', 'INFINITY'):
        value = implementation[name]
        if name == 'c_make_encoder':
            if _TYPE(value) is not _TYPE or _name(value) != ('_json', 'Encoder'):
                raise Unobserved('nonordinary C encoder')
            encoder.ordinary_class(value)
        else:
            encoder.data(value)


def observation(action, cli, output, provider, opcode_module=None, *, diagnostics=None):
    """Return safe facts or None; never run any candidate provider/encoder.

    The HIA controller decides whether an exact digest is admitted. Replacement
    or nonordinary values are a foreign-route observation, not a CLI rejection.
    """
    if not _mechanics_unchanged():
        return None
    try:
        namespace = _module(cli, 'hepta.cli')
        definitions = namespace.get('_HIA_DISCOVERY_DEFINITIONS')
        if (_TYPE(definitions) is not _TUPLE or len(definitions) != 6
                or output is not definitions[1] or _TYPE(definitions[2]) is not _FUNCTION
                or _TYPE(output) is not _FUNCTION or output.__code__ is not definitions[4]):
            raise Unobserved('output definition anchor')
        if _GETTRACE() is not None or _GETPROFILE() is not None or _THREAD_COUNT() != 0:
            raise Unobserved('observable interpreter callbacks or threads')
        result = _Encoder()
        result.data(('hia.discovery.standard-provider-facts.v1', action,
                     sys.implementation.name, tuple(sys.version_info[:3])))
        result.function(output, namespace)
        _json_facts(result, namespace)
        if action == 1:
            if (provider is not definitions[0] or _TYPE(provider) is not _FUNCTION
                    or provider.__code__ is not definitions[3]):
                raise Unobserved('capabilities definition anchor')
            result.function(provider, namespace)
            result.data(namespace['HIA_AGENT_ACTIONS'])
        elif action == 2:
            op = _module(opcode_module, 'hepta.hia_opcodes')
            anchors = op.get('_HIA_DISCOVERY_DEFINITIONS')
            if (_TYPE(anchors) is not _TUPLE or len(anchors) != 8 or provider is not anchors[0]
                    or _TYPE(provider) is not _FUNCTION or provider.__code__ is not anchors[7]
                    or op.get('json') is not json):
                raise Unobserved('catalog definition anchor')
            result.function(provider, op)
            cls = anchors[1]
            if op.get('OpcodeSpec') is not cls:
                raise Unobserved('opcode class replacement')
            result.ordinary_class(cls)
            for index, name in enumerate(('OPCODES', 'PRIMITIVE_PROFILES', 'TYPES', '_GROUPS', 'TERMINATORS'), 2):
                if op.get(name) is not anchors[index]:
                    raise Unobserved('metadata object replacement')
            result.data(op['LATEST_CORE_SCHEMA'])
            result.data(op['TYPES'])
            for name in ('PRIMITIVE_PROFILES', '_GROUPS', 'TERMINATORS'):
                value = op[name]
                if _TYPE(value) is not types.MappingProxyType:
                    raise Unobserved('metadata map type')
                result.data(dict(value.items()))
            dc = _module(dataclasses, 'dataclasses')
            if op.get('asdict') is not dc['asdict']:
                raise Unobserved('asdict replacement')
            for name in ('asdict', '_asdict_inner', 'fields', '_is_dataclass_instance'):
                result.function(dc[name], dc)
            result.data(dc.get('_ATOMIC_TYPES'))
            fields = type.__getattribute__(cls, '__dict__').get('__dataclass_fields__')
            if _TYPE(fields) is not _DICT or any(_TYPE(key) is not _STR for key in fields):
                raise Unobserved('dataclass field map')
            names = []
            for name, field in fields.items():
                if _TYPE(field) is not dataclasses.Field or _slot(field, '_field_type') is not dc['_FIELD']:
                    raise Unobserved('dataclass field kind')
                actual = _slot(field, 'name')
                if _TYPE(actual) is not _STR or actual != name:
                    raise Unobserved('dataclass field name')
                names.append(name)
            result.data(tuple(names))
            values = op['OPCODES']
            if _TYPE(values) is not types.MappingProxyType:
                raise Unobserved('opcode table type')
            rows = []
            for key, spec in values.items():
                if _TYPE(key) is not _STR or _TYPE(spec) is not cls:
                    raise Unobserved('opcode record type')
                rows.append((key, tuple(_slot(spec, name) for name in names)))
            result.data(rows)
            result.data(op['sha256'])
        else:
            raise Unobserved('not a discovery action')
        raw = b''.join(result.parts)
        return raw, _sha256(raw).digest()
    except (Unobserved, KeyError, AttributeError, TypeError, ValueError, RuntimeError) as error:
        if diagnostics is not None:
            diagnostics.append((type(error).__name__, str(error)))
        return None

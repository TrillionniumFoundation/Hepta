"""Fixed CPython object-layout ports for an explicitly admitted parser graph.

No parser constructor, argument scanner, action body, or retained CLI body is
executed here. The HIA image owns all allocation/link/release instructions.
Definition fingerprints are admission data, not executable Python payloads.
"""
from __future__ import annotations

import argparse
from abc import ABCMeta
from hashlib import sha256
import re
import struct
import sys
import types

_TYPE = type
_OBJECT = object
_DICT = dict
_TUPLE = tuple
_LIST = list
_STR = str
_BYTES = bytes
_INT = int
_BOOL = bool
_SET = set
_FUNCTION = types.FunctionType
_CODE = types.CodeType
_EMPTY = object()
if sys.version_info[:2] == (3, 14):
    # 3.14 argparse imports this module only while constructing a formatter.
    # A selected native call must bind the same real stdlib objects even in a
    # fresh process where no retained parser constructor has run.
    import _colorize as _COLORIZE
else:
    _COLORIZE = sys.modules.get('_colorize')
_COLORIZE_ARGPARSE = (None if _COLORIZE is None else
    types.ModuleType.__getattribute__(_COLORIZE, '__dict__')['Argparse'])
_COLORIZE_THEME = (None if _COLORIZE is None else
    types.ModuleType.__getattribute__(_COLORIZE, '__dict__')['Theme'])


def _definition(value):
    """Encode exact built-in layout facts without coercion or user lookup."""
    t = _TYPE(value)
    if value is None:
        return b'n'
    if value is Ellipsis:
        return b'e'
    if t is _BOOL:
        return b't' if value else b'f'
    if t is _INT:
        return b'i' + _STR(value).encode('ascii') + b';'
    if t is float:
        return b'd' + struct.pack('<d', value)
    if t is _STR:
        raw = _STR.encode(value, 'utf-8', 'surrogatepass')
        return b's' + struct.pack('<Q', len(raw)) + raw
    if t is _BYTES:
        return b'b' + struct.pack('<Q', len(value)) + value
    if t is _TUPLE:
        return b'(' + b''.join(_definition(item) for item in value) + b')'
    if t is _LIST:
        return b'[' + b''.join(_definition(item) for item in value) + b']'
    if t is _DICT:
        return b'{' + b''.join(_definition(key) + _definition(item)
                               for key, item in _DICT.items(value)) + b'}'
    if t is frozenset:
        return b'<' + b''.join(sorted(_definition(item) for item in value)) + b'>'
    if t is slice:
        return b'/' + _definition((value.start, value.stop, value.step))
    if t is _CODE:
        return b'c' + _definition((value.co_argcount, value.co_posonlyargcount,
            value.co_kwonlyargcount, value.co_nlocals, value.co_flags, value.co_code,
            value.co_consts, value.co_names, value.co_varnames, value.co_freevars,
            value.co_cellvars, value.co_exceptiontable))
    if t is _FUNCTION:
        return b'F' + _definition((value.__module__, value.__name__, value.__qualname__,
                                   value.__code__, value.__defaults__))
    if t is _TYPE or (t is ABCMeta and value is _COLORIZE_ARGPARSE):
        namespace = _TYPE.__getattribute__(value, '__dict__')
        methods = []
        for name, item in namespace.items():
            if _TYPE(item) is _FUNCTION:
                methods.append((name, _definition(item)))
            elif _TYPE(item) in (staticmethod, classmethod):
                methods.append((name, _definition(item.__func__)))
            elif _TYPE(item) is property:
                methods.append((name, _definition((item.fget, item.fset, item.fdel))))
        return b'T' + _definition((_TYPE.__getattribute__(value, '__module__'),
            _TYPE.__getattribute__(value, '__qualname__'), _TUPLE(methods)))
    if t is _COLORIZE_ARGPARSE:
        # A formatter borrows this actual stdlib-global palette.  Do not copy
        # it: its dict-bound getter and external identity are observable.
        return b'P' + _definition(t) + _definition(
            _OBJECT.__getattribute__(value, '__dict__'))
    if t is types.BuiltinMethodType:
        owner = _OBJECT.__getattribute__(value, '__self__')
        if (_TYPE(owner) is not _DICT
                or _OBJECT.__getattribute__(value, '__name__') != '__getitem__'):
            raise ValueError('unsupported parser palette bound method')
        return b'M' + _definition(('dict.__getitem__', owner))
    raise ValueError('unsupported physical definition fingerprint type')


def definition_sha(value):
    return sha256(_definition(value)).hexdigest()


def _parser_type():
    # An explicit selected-native test may poison the public constructor name.
    # Locate the genuine, still-live built-in-metaclass type, but never invoke
    # its __init__ or a cached constructor. Its entire layout is fingerprinted.
    matches = []
    for value in _TYPE.__subclasses__(argparse._ActionsContainer):
        if (_TYPE(value) is _TYPE
                and _TYPE.__getattribute__(value, '__module__') == 'argparse'
                and _TYPE.__getattribute__(value, '__qualname__') == 'ArgumentParser'):
            matches.append(value)
    if len(matches) != 1:
        raise ValueError('ambiguous physical ArgumentParser type')
    return matches[0]


def shared_objects(cli, paths, signatures):
    from . import hia_schema
    modules = {'argparse': argparse, 'cli': cli, 'schema': hia_schema}
    if '_colorize' in sys.modules:
        modules['_colorize'] = sys.modules['_colorize']
    result = []
    parser_type = _parser_type()
    for path, signature in zip(paths, signatures, strict=True):
        value = _EMPTY
        for operation, operand in path:
            if operation == 'module-item':
                module, name = operand
                namespace = types.ModuleType.__getattribute__(modules[module], '__dict__')
                value = (parser_type if module == 'argparse' and name == 'ArgumentParser'
                         else _DICT.__getitem__(namespace, name))
            elif operation == 'item':
                if _TYPE(value) is not _TUPLE:
                    raise ValueError('shared parser tuple layout changed')
                value = _TUPLE.__getitem__(value, operand)
            elif operation == 'function-code':
                if _TYPE(value) is not _FUNCTION:
                    raise ValueError('shared parser function layout changed')
                value = _OBJECT.__getattribute__(value, '__code__')
            elif operation == 'function-defaults':
                if _TYPE(value) is not _FUNCTION:
                    raise ValueError('shared parser defaults layout changed')
                value = _OBJECT.__getattribute__(value, '__defaults__')
            elif operation == 'code-consts':
                if _TYPE(value) is not _CODE:
                    raise ValueError('shared parser code layout changed')
                value = _OBJECT.__getattribute__(value, 'co_consts')
            elif operation == 'class-item':
                if _TYPE(value) is not _TYPE:
                    raise ValueError('shared parser class metatype changed')
                value = _TYPE.__getattribute__(value, '__dict__')[operand]
            elif operation == 'theme-item':
                if _TYPE(value) is not _COLORIZE_THEME or operand != 'argparse':
                    raise ValueError('shared parser theme layout changed')
                value = _DICT.__getitem__(_OBJECT.__getattribute__(value, '__dict__'), operand)
            elif operation == 'schema-key':
                mapping = types.ModuleType.__getattribute__(hia_schema, '__dict__')['PRIMITIVE_PROFILES']
                if _TYPE(mapping) is not types.MappingProxyType:
                    raise ValueError('shared parser schema registry changed')
                value = _TUPLE(mapping)[operand]
            else:
                raise ValueError('unknown shared physical path operation')
        if definition_sha(value) != signature:
            raise ValueError('shared parser definition differs from the admitted graph')
        result.append(value)
    return _TUPLE(result)


class PhysicalObjects:
    def __init__(self, shared, node_count, version, original_input):
        self.shared = shared
        self.handles = [_EMPTY] * (node_count + 2)
        self.version = version
        self.original_input = original_input

    def get(self, index):
        if _TYPE(index) is not _INT or not 0 <= index < len(self.handles):
            raise RuntimeError('parser object handle outside its arena')
        value = self.handles[index]
        if value is _EMPTY:
            raise RuntimeError('parser object handle is absent or consumed')
        return value

    def take(self, index):
        value = self.get(index)
        self.handles[index] = _EMPTY
        return value

    def put(self, index, value):
        if (_TYPE(index) is not _INT or not 0 <= index < len(self.handles)
                or self.handles[index] is not _EMPTY):
            raise RuntimeError('parser object destination is already occupied')
        self.handles[index] = value

    def effect(self, operation, destination, a, b, payload):
        if operation == 1:
            self.put(destination, {})
        elif operation == 2:
            self.put(destination, [])
        elif operation == 3:
            cls = self.shared[a]
            if _TYPE(cls) is not _TYPE:
                raise RuntimeError('parser object allocator lacks its exact class')
            self.put(destination, _OBJECT.__new__(cls))
        elif operation == 4:
            self.put(destination, self.shared[a])
        elif operation == 5:
            code = self.shared[a]
            if _TYPE(code) is not _CODE:
                raise RuntimeError('parser identity function code layout changed')
            self.put(destination, _FUNCTION(code, vars(argparse)))
        elif operation == 6:
            self.put(destination, self.version)
        elif operation == 7:
            if len(payload) < 3 or struct.unpack_from('<H', payload, 1)[0] != len(payload) - 3:
                raise RuntimeError('invalid parser scalar envelope')
            tag, raw = payload[0], payload[3:]
            if tag == 0 and not raw:
                value = None
            elif tag == 1 and raw in (b'\0', b'\1'):
                value = raw == b'\1'
            elif tag == 2 and len(raw) == 8:
                value = _INT.from_bytes(raw, 'little', signed=True)
            elif tag == 3:
                value = _BYTES.decode(raw, 'utf-8', 'surrogatepass')
            elif tag == 4:
                value = raw
            elif tag == 5 and not raw:
                value = _SET()
            else:
                raise RuntimeError('unknown parser scalar layout')
            self.put(destination, value)
        elif operation == 8:
            value = self.get(destination)
            if _TYPE(value) is not _LIST:
                raise RuntimeError('parser list link has the wrong physical type')
            _LIST.append(value, self.get(a))
        elif operation == 9:
            value = self.take(destination)
            if _TYPE(value) is not _LIST:
                raise RuntimeError('parser tuple operands have the wrong physical type')
            cls = _TUPLE if a == 65535 else self.shared[a]
            self.put(destination, _TUPLE.__new__(cls, value))
        elif operation == 10:
            self.put(destination, re.compile(self.get(a), self.get(b)))
        elif operation == 11:
            target = self.get(destination)
            if _TYPE(target) is not _DICT:
                raise RuntimeError('parser dict link has the wrong physical type')
            _DICT.__setitem__(target, self.get(a), self.get(b))
        elif operation == 12:
            target, namespace = self.get(destination), self.get(a)
            if _TYPE(namespace) is not _DICT or _TYPE(_TYPE(target)) is not _TYPE:
                raise RuntimeError('parser object dictionary layout changed')
            _OBJECT.__setattr__(target, '__dict__', namespace)
        elif operation == 13:
            self.take(destination)
        elif operation == 14:
            if a % 4 or a > len(self.original_input) or b > (len(self.original_input) - a) // 4:
                raise RuntimeError('parser error string span left its retained input')
            self.put(destination, self.original_input[a:a+b*4].decode('utf-32-le', 'surrogatepass'))
        elif operation == 15:
            if a % 4 or a > len(self.original_input) or b > (len(self.original_input) - a) // 4:
                raise RuntimeError('parser integer span left its retained input')
            text = self.original_input[a:a+b*4].decode('utf-32-le', 'surrogatepass')
            try:
                value = _INT(text)
            except ValueError:
                self.put(destination, None)
                return 1
            self.put(destination, value)
            return 0
        elif operation == 16:
            value = self.get(destination)
            if _TYPE(value) is not _INT:
                raise RuntimeError('parser integer comparison lacks an exact integer')
            return 1 if _INT.__gt__(value, a) else 0
        elif operation == 17:
            value = self.get(a)
            if _TYPE(value) is not _INT:
                raise RuntimeError('parser integer subtraction lacks an exact integer')
            self.put(destination, _INT.__sub__(value, b))
        else:
            raise RuntimeError('unknown physical parser object instruction')

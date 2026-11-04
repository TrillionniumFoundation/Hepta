"""Validated deepcopy invocation attempts, not bytes or a hard resource bound.

Only CPython 3.11/3.12 POSIX and exact canonical Package/PosixPath graphs.
3.12 paths must already have parsed caches. The real one-argument deepcopy
remains the copier, preserving memoized aliases, cycles and partial states.
Trusts ordinary private/runtime integrity throughout the callback-free phase.
"""
import copy
import copyreg
from dataclasses import dataclass
import inspect
import os
import pathlib
import sys
import types

from hepta import packages
from experiments.shallow_authority.owner import (
    Owner as ShallowOwner, Limits as ShallowLimits, _Context as ShallowContext, _Ops,
)
from experiments.owned_loader import owner as owned

_MISSING = object()
_CLASS = packages.Package
_PATH = pathlib.PosixPath
_VERSION = sys.version_info[:2]
_SUPPORTED = sys.implementation.name == 'cpython' and _VERSION in ((3, 11), (3, 12)) and os.name == 'posix'
_COPY = copy.deepcopy
_SEAM = owned.Owner._authority_copy
_FIELDS = ('root', 'name', 'version', 'entry', 'kind', 'source_root', 'dependencies', 'manifest_bytes')
_PATH_FIELDS = ('root', 'entry', 'source_root')
_HOOKS = ('__deepcopy__', '__reduce__', '__reduce_ex__', '__getstate__',
          '__setstate__', '__getnewargs__', '__getnewargs_ex__', '__new__',
          '__class__', '__getattribute__', '__getattr__', '__setattr__', '__dict__')
_PATH_CLASSES = (pathlib.PosixPath, pathlib.Path, pathlib.PurePosixPath, pathlib.PurePath)
_CLASS_NAMES = ('PosixPath', 'Path', 'PurePosixPath', 'PurePath')
_MROS = tuple((cls, type.__getattribute__(cls, '__mro__')) for cls in (_CLASS,) + _PATH_CLASSES)
_DISPATCH = copy._deepcopy_dispatch
_REDUCERS = copy.dispatch_table
_COPY_TYPES = (_CLASS, _PATH, dict, str, bytes, type(None), type)
_DISPATCH_PINS = tuple((_DISPATCH.get(cls, _MISSING), _REDUCERS.get(cls, _MISSING)) for cls in _COPY_TYPES)

# Static descriptors avoid invoking replacement hooks, properties or classmethods.
_PINS = []
_FUNCTIONS = []

def _pin(namespace, name):
    value = inspect.getattr_static(namespace, name, _MISSING)
    _PINS.append((namespace, name, value))
    function = value
    if type(value) in (classmethod, staticmethod):
        function = value.__func__
    elif type(value) is property:
        function = value.fget
    if type(function) is types.FunctionType and not any(function is f[0] for f in _FUNCTIONS):
        defaults = function.__defaults__
        keywords = function.__kwdefaults__
        _FUNCTIONS.append((function, defaults,
                           None if keywords is None else tuple(keywords.items())))
    return value

for cls in (_CLASS,) + _PATH_CLASSES:
    for name in _HOOKS + ('__init__', '__mro__', '__bases__'):
        _pin(cls, name)
for name in _CLASS_NAMES:
    _pin(pathlib, name)
for namespace, names in (
    (packages, ('Package',)), (owned, ('copy',)),
    (copy, ('deepcopy', '_deepcopy_dict', '_deepcopy_atomic', '_reconstruct', '_keep_alive')),
    (copyreg, ('__newobj__', '__newobj_ex__', '_slotnames')),
    (pathlib, ('os',)), (os, ('fspath',)),
):
    for name in names:
        _pin(namespace, name)
_STATE_DESCRIPTOR = inspect.getattr_static(_CLASS, '__dict__')
_SLOT_NAMES = ('_parts', '_drv', '_root') if _VERSION == (3, 11) else ('_drv', '_root', '_tail_cached', '_raw_paths')
_SLOTS = {name: inspect.getattr_static(_PATH, name, _MISSING) for name in _SLOT_NAMES}
for cls in _PATH_CLASSES:
    for name in _SLOT_NAMES:
        _pin(cls, name)
if _VERSION == (3, 12):
    for cls in _PATH_CLASSES:
        for name in ('parts', 'drive', 'root', '_tail'):
            _pin(cls, name)
elif _VERSION == (3, 11):
    for cls in _PATH_CLASSES:
        for name in ('_from_parts', '_parse_args', '_flavour'):
            _pin(cls, name)
    _FLAVOUR = inspect.getattr_static(_PATH, '_flavour')
    _FLAVOUR_CLASS = type(_FLAVOUR)
    _MROS += ((_FLAVOUR_CLASS, type.__getattribute__(_FLAVOUR_CLASS, '__mro__')),)
    for target in (_FLAVOUR, _FLAVOUR_CLASS):
        for name in ('parse_parts', 'splitroot', 'sep', 'altsep', 'is_supported',
                     '__getattribute__', '__getattr__', '__class__'):
            _pin(target, name)
    for name in ('__mro__', '__bases__'):
        _pin(_FLAVOUR_CLASS, name)
    _pin(pathlib, 'sys')
    _pin(sys, 'intern')


@dataclass(frozen=True)
class Limits(ShallowLimits):
    package_copy_calls: int = 200_000
    package_copy_depth: int = 128


class _Context(ShallowContext):
    def __init__(self, limits, checkpoint):
        super().__init__(limits, checkpoint)
        self.counts['package_copy_calls'] = 0

    def admit_package_call(self, depth):
        if self.closed:
            self.reject('request context is terminal')
        if depth > self.limits.package_copy_depth:
            self.reject('package_copy_depth quota exceeded')
        if self.counts['package_copy_calls'] >= self.limits.package_copy_calls:
            self.reject('package_copy_calls quota exceeded')
        self.counts['package_copy_calls'] += 1


def _hooks(context):
    if not _SUPPORTED:
        context.reject('unsupported Package copy runtime')
    if (copy._deepcopy_dispatch is not _DISPATCH or type(_DISPATCH) is not dict
            or copy.dispatch_table is not _REDUCERS or copyreg.dispatch_table is not _REDUCERS
            or type(_REDUCERS) is not dict or owned.Owner._authority_copy is not _SEAM):
        context.reject('replacement Package copy dispatch or seam')
    for cls, (dispatch, reducer) in zip(_COPY_TYPES, _DISPATCH_PINS):
        if (_DISPATCH.get(cls, _MISSING) is not dispatch
                or _REDUCERS.get(cls, _MISSING) is not reducer):
            context.reject('replacement Package copy dispatch entry')
    for cls in (_CLASS,) + _PATH_CLASSES:
        if type(cls) is not type:
            context.reject('replacement Package copy metaclass')
    for cls, mro in _MROS:
        actual = type.__getattribute__(cls, '__mro__')
        if len(actual) != len(mro) or any(a is not b for a, b in zip(actual, mro)):
            context.reject('replacement Package copy class hierarchy')
    if _VERSION == (3, 11) and type(_FLAVOUR) is not _FLAVOUR_CLASS:
        context.reject('replacement Path flavour class')
    for namespace, name, original in _PINS:
        if inspect.getattr_static(namespace, name, _MISSING) is not original:
            context.reject('replacement Package copy hook: ' + name)
    for function, defaults, keywords in _FUNCTIONS:
        actual = function.__defaults__
        if (actual is not defaults and (type(actual) is not tuple or type(defaults) is not tuple
                or len(actual) != len(defaults) or any(a is not b for a, b in zip(actual, defaults)))):
            context.reject('replacement Package copy function defaults')
        actual = function.__kwdefaults__
        if keywords is None:
            if actual is not None:
                context.reject('replacement Package copy keyword defaults')
        elif type(actual) is not dict or len(actual) != len(keywords):
            context.reject('replacement Package copy keyword defaults')
        else:
            # Validate key types before dictionary lookups can invoke foreign equality.
            if any(type(key) is not str for key in actual):
                context.reject('replacement Package copy keyword defaults')
            for key, expected in keywords:
                if actual.get(key, _MISSING) is not expected:
                    context.reject('replacement Package copy keyword defaults')
    if inspect.getattr_static(_CLASS, '__slots__', _MISSING) is not _MISSING:
        context.reject('replacement Package slot metadata')
    slots = inspect.getattr_static(_CLASS, '__slotnames__', _MISSING)
    if slots is not _MISSING and slots is not None and not (type(slots) is list and not slots):
        context.reject('replacement Package slot metadata')


def _slot(path, name, context):
    try:
        return _SLOTS[name].__get__(path, _PATH)
    except AttributeError:
        context.reject('cold or partial Path is not admitted')


def _path_children(value, context):
    if _VERSION == (3, 11):
        tail = _slot(value, '_parts', context)
    else:
        drive = _slot(value, '_drv', context)
        root = _slot(value, '_root', context)
        tail = _slot(value, '_tail_cached', context)
        if type(drive) is not str or type(root) is not str:
            context.reject('Path drive/root must be exact strings')
        if drive or root:
            # Virtual atomic anchor event; do not concatenate or create parts.
            yield '', 'string'
    if type(tail) is not list:
        context.reject('Path components must be an exact list')
    for component in tail:
        yield component, 'string'


def _state_children(state, context):
    if len(state) != len(_FIELDS):
        context.reject('noncanonical Package state shape')
    for key in state:
        if type(key) is not str or key not in _FIELDS:
            context.reject('noncanonical Package state key')
    for key, value in state.items():
        role = ('path' if key in _PATH_FIELDS else 'dependencies' if key == 'dependencies'
                else 'manifest' if key == 'manifest_bytes' else 'string')
        # Real _deepcopy_dict copies the value before the key.
        yield value, role
        yield key, 'string'


def _dependency_children(value):
    for key, child in value.items():
        # Validate keys before exposing them to copying. No hashing here.
        if type(key) is not str:
            yield key, 'invalid'
        yield child, 'package'
        yield key, 'string'


def _children(value, role, memo, roles, context):
    cls = type(value)
    if role == 'root' and value is None:
        return None
    if role in ('root', 'package'):
        if cls is not _CLASS:
            context.reject('Package must have exact canonical type')
    elif role == 'class':
        if value is not _CLASS:
            context.reject('unknown Package class argument')
        return None
    elif role == 'string':
        if cls is not str:
            context.reject('Package strings must have exact type')
        return None
    elif role == 'manifest':
        if cls is not bytes and value is not None:
            context.reject('Package manifest must be bytes or None')
        return None
    elif role == 'path':
        if cls is not _PATH:
            context.reject('Package paths must be exact native PosixPath')
    elif role in ('state', 'dependencies'):
        if cls is not dict:
            context.reject('Package dictionaries must have exact type')
        old = roles.setdefault(id(value), role)
        if old != role:
            context.reject('Package dictionary reused across roles')
    else:
        context.reject('noncanonical Package dependency key')
    identity = id(value)
    if identity in memo:
        return None
    memo.add(identity)
    if cls is _CLASS:
        state = _STATE_DESCRIPTOR.__get__(value, _CLASS)
        return iter(((_CLASS, 'class'), (state, 'state')))
    if cls is dict:
        return _state_children(value, context) if role == 'state' else _dependency_children(value)
    return _path_children(value, context)


def _preflight(value, context):
    # Per-operation memo; counters alone accumulate across loads.
    memo, roles, stack = set(), {}, []
    role, depth = 'root', 1
    while True:
        context.admit_package_call(depth)
        children = _children(value, role, memo, roles, context)
        if children is not None:
            stack.append((children, depth))
        while stack:
            children, parent_depth = stack[-1]
            try:
                value, role = next(children)
            except StopIteration:
                stack.pop()
            else:
                depth = parent_depth + 1
                break
        else:
            return


class Owner(ShallowOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

    def _authority_copy(self, deepcopy, value, name):
        try:
            if self.context.closed:
                self.context.reject('request context is terminal')
            if type(name) is not str or name != 'package':
                return super()._authority_copy(deepcopy, value, name)
            self.context.check()
            if deepcopy is not _COPY:
                self.context.reject('replacement captured Package copier')
            _hooks(self.context)
            _preflight(value, self.context)
            result = deepcopy(value)
            self.context.check()
            return result
        except BaseException:
            self.context.closed = True
            raise
        finally:
            del deepcopy, value

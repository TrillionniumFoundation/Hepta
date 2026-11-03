"""Finite callback-free preflight of canonical assembly deepcopy inputs.

Trusts ordinary runtime execution without concurrent/signal/tracing/finalizer or
private graph/class mutation during preflight and copy. This is not a sandbox,
byte accounting, a complete copy implementation or a hard memory/CPU bound.
"""
import copy
import copyreg
from dataclasses import dataclass, fields
import inspect

from hepta import ast, modules
from hepta._loader_ops import LegacyLoaderOps
from experiments.parser_appends.owner import (
    Limits as AppendLimits, Owner as AppendOwner, _Context as AppendContext,
    _Ops as AppendOps,
)

_NAMES = ('Span', 'Type', 'Expr', 'Stmt', 'Param', 'Struct', 'EnumVariant',
          'Enum', 'Pattern', 'MatchArm', 'Import', 'Function', 'Program')
_CLASSES = tuple(getattr(ast, name) for name in _NAMES)
_FIELDS = tuple(tuple(field.name for field in fields(cls)) for cls in _CLASSES)
_SCALARS = (type(None), bool, int, float, str)
_CONTAINERS = (list, tuple, dict, set)
_MISSING = object()
_HOOK_NAMES = ('__deepcopy__', '__reduce__', '__reduce_ex__', '__getstate__',
               '__setstate__', '__getnewargs__', '__getnewargs_ex__', '__new__',
               '__getattribute__', '__getattr__', '__dict__', '__setattr__')
_CLASS_HOOKS = tuple(tuple(inspect.getattr_static(cls, name, _MISSING)
                           for name in _HOOK_NAMES) for cls in _CLASSES)
_DEEPCOPY = copy.deepcopy
_SEAM = LegacyLoaderOps.deepcopy
_DISPATCH, _REDUCERS = copy._deepcopy_dispatch, copy.dispatch_table
_COPY_TYPES = _SCALARS + _CONTAINERS + _CLASSES + (type,)
_DISPATCH_VALUES = tuple(_DISPATCH.get(cls, _MISSING) for cls in _COPY_TYPES)
_REDUCER_VALUES = tuple(_REDUCERS.get(cls, _MISSING) for cls in _COPY_TYPES)
_HELPERS = ((copy, '_reconstruct', copy._reconstruct),
            (copy, '_keep_alive', copy._keep_alive),
            (copyreg, '__newobj__', copyreg.__newobj__),
            (copyreg, '__newobj_ex__', copyreg.__newobj_ex__),
            (copyreg, '_slotnames', copyreg._slotnames))


@dataclass(frozen=True)
class Limits(AppendLimits):
    copy_visits: int = 1_000_000
    copy_depth: int = 256


class _Context(AppendContext):
    def __init__(self, limits, checkpoint):
        super().__init__(limits, checkpoint)
        self.counts['copy_visits'] = 0

    def check(self):
        super().check()
        if (modules.copy is not copy or copy.deepcopy is not _DEEPCOPY
                or LegacyLoaderOps.deepcopy is not _SEAM):
            self.reject('replacement assembly copy hook is not admitted')

    def admit_copy_visit(self, depth):
        # Deliberately no user callback: a callback could mutate already visited
        # children and invalidate preflight. Entry and exit check separately.
        if self.closed:
            self.reject('request context is terminal')
        if depth > self.limits.copy_depth:
            self.reject('copy_depth quota exceeded')
        if self.counts['copy_visits'] >= self.limits.copy_visits:
            self.reject('copy_visits quota exceeded')
        self.counts['copy_visits'] += 1


def _copy_hooks(context):
    if (copy._deepcopy_dispatch is not _DISPATCH or type(_DISPATCH) is not dict
            or copy.dispatch_table is not _REDUCERS or type(_REDUCERS) is not dict):
        context.reject('replacement copy dispatch table')
    for namespace, name, expected in _HELPERS:
        if getattr(namespace, name, _MISSING) is not expected:
            context.reject('replacement copy helper: ' + name)
    for cls, copier, reducer in zip(_COPY_TYPES, _DISPATCH_VALUES, _REDUCER_VALUES):
        if (_DISPATCH.get(cls, _MISSING) is not copier
                or _REDUCERS.get(cls, _MISSING) is not reducer):
            context.reject('replacement canonical copy dispatch')
    for name, cls, expected in zip(_NAMES, _CLASSES, _CLASS_HOOKS):
        if getattr(ast, name, _MISSING) is not cls:
            context.reject('replacement canonical AST class')
        if inspect.getattr_static(cls, '__slots__', _MISSING) is not _MISSING:
            context.reject('replacement AST slot metadata')
        slots = inspect.getattr_static(cls, '__slotnames__', _MISSING)
        if (slots is not _MISSING and slots is not None
                and not (type(slots) is list and len(slots) == 0)):
            context.reject('replacement AST slot metadata')
        for hook, original in zip(_HOOK_NAMES, expected):
            if inspect.getattr_static(cls, hook, _MISSING) is not original:
                context.reject('replacement AST copy hook: ' + hook)


def _dictionary_children(value, context):
    for key, child in value.items():
        if type(key) is not str:
            context.reject('copy dictionary keys must be exact strings')
        yield key
        yield child


def _set_children(value, context):
    for child in value:
        if type(child) is not str:
            context.reject('copy set members must be exact strings')
        yield child


def _children(value, context):
    cls = type(value)
    if any(cls is scalar for scalar in _SCALARS):
        return None
    if cls is list or cls is tuple:
        return iter(value)
    if cls is dict:
        return _dictionary_children(value, context)
    if cls is set:
        return _set_children(value, context)
    for expected, names in zip(_CLASSES, _FIELDS):
        if cls is expected:
            state = object.__getattribute__(value, '__dict__')
            if type(state) is not dict or len(state) != len(names):
                context.reject('noncanonical AST field shape')
            for name in state:
                if type(name) is not str or name not in names:
                    context.reject('noncanonical AST field shape')
            return iter((state,))
    # No hashing/equality/attribute lookup on the unknown object or its class.
    context.reject('unknown copy graph object')


def _preflight(value, context):
    # Expanded occurrences, not a permanent visited set: immutable tuple DAGs
    # can be revisited by deepcopy when their children are unchanged. Cycles
    # are refused; shared acyclic subgraphs are conservatively visited again.
    context.admit_copy_visit(1)
    stack = []
    active = set()
    depth = 1
    while True:
        children = _children(value, context)
        if children is not None:
            identity = id(value)
            if identity in active:
                context.reject('cyclic copy graph is not admitted')
            active.add(identity)
            stack.append((identity, children, depth))
        while stack:
            identity, children, parent_depth = stack[-1]
            try:
                value = next(children)
            except StopIteration:
                stack.pop()
                active.remove(identity)
            else:
                depth = parent_depth + 1
                context.admit_copy_visit(depth)
                break
        else:
            return


class _Ops(AppendOps):
    def deepcopy(self, deepcopy, value):
        try:
            self.context.check()
            if deepcopy is not _DEEPCOPY:
                self.context.reject('replacement captured copy callable')
            _copy_hooks(self.context)
            _preflight(value, self.context)
            # No checkpoint after validation and before dispatch.
            result = deepcopy(value)
            self.context.check()
            return result
        except BaseException:
            self.context.closed = True
            raise


class Owner(AppendOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

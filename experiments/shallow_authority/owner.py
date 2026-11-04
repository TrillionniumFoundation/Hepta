"""Admit shallow state entries, not recursively reachable objects or bytes.

Package/Path deepcopy remains excluded. Canonical field values, including
cycles, are not inspected: ordinary shallow-copy identity semantics remain.
"""
import copy
import copyreg
from dataclasses import dataclass, fields
import inspect

from hepta import modules
from experiments.owned_loader import owner as owned
from experiments.authority_maps.owner import (
    Limits as MapLimits, Owner as MapOwner, _Context as MapContext, _Ops,
)

_CLASS = modules.LoadedProject
_FIELDS = tuple(field.name for field in fields(_CLASS))
_COPY = copy.copy
_SEAM = owned.Owner._authority_shallow
_MISSING = object()
_HOOK_NAMES = ('__copy__', '__reduce__', '__reduce_ex__', '__getstate__',
               '__setstate__', '__getnewargs__', '__getnewargs_ex__', '__new__',
               '__dict__', '__getattribute__', '__getattr__', '__setattr__')
_HOOKS = tuple(inspect.getattr_static(_CLASS, name, _MISSING) for name in _HOOK_NAMES)
_DISPATCH, _REDUCERS = copy._copy_dispatch, copy.dispatch_table
_DISPATCH_VALUE = _DISPATCH.get(_CLASS, _MISSING)
_REDUCER_VALUE = _REDUCERS.get(_CLASS, _MISSING)
_HELPERS = ((copy, '_reconstruct', copy._reconstruct),
            (copyreg, '__newobj__', copyreg.__newobj__),
            (copyreg, '__newobj_ex__', copyreg.__newobj_ex__),
            (copyreg, '_slotnames', copyreg._slotnames))


@dataclass(frozen=True)
class Limits(MapLimits):
    shallow_fields: int = 4096


class _Context(MapContext):
    def __init__(self, limits, checkpoint):
        super().__init__(limits, checkpoint)
        self.counts['shallow_fields'] = 0

    def check(self):
        super().check()
        if (copy.copy is not _COPY or modules.LoadedProject is not _CLASS
                or getattr(owned.Owner, '_authority_shallow', None) is not _SEAM):
            self.reject('replacement shallow authority hook', category='replacement_hook', phase='shallow_authority')

    def admit_shallow_field(self):
        # No checkpoint between inspecting canonical state and copying it.
        if self.closed:
            self.reject('request context is terminal', category='terminal', phase='shallow_authority')
        if self.counts['shallow_fields'] >= self.limits.shallow_fields:
            self.reject('shallow_fields quota exceeded', category='budget', phase='shallow_authority', dimension='shallow_fields', limit=self.limits.shallow_fields, admitted=self.counts['shallow_fields'], attempted=self.counts['shallow_fields'] + 1)
        self.counts['shallow_fields'] += 1


def _hooks(context):
    if (copy._copy_dispatch is not _DISPATCH or type(_DISPATCH) is not dict
            or copy.dispatch_table is not _REDUCERS or type(_REDUCERS) is not dict
            or _DISPATCH.get(_CLASS, _MISSING) is not _DISPATCH_VALUE
            or _REDUCERS.get(_CLASS, _MISSING) is not _REDUCER_VALUE):
        context.reject('replacement shallow copy dispatch', category='replacement_hook', phase='shallow_authority')
    for namespace, name, original in _HELPERS:
        if getattr(namespace, name, _MISSING) is not original:
            context.reject('replacement shallow copy helper: ' + name, category='replacement_hook', phase='shallow_authority')
    if inspect.getattr_static(_CLASS, '__slots__', _MISSING) is not _MISSING:
        context.reject('replacement shallow class slot metadata', category='replacement_hook', phase='shallow_authority')
    slots = inspect.getattr_static(_CLASS, '__slotnames__', _MISSING)
    if (slots is not _MISSING and slots is not None
            and not (type(slots) is list and len(slots) == 0)):
        context.reject('replacement shallow class slot metadata', category='replacement_hook', phase='shallow_authority')
    for name, original in zip(_HOOK_NAMES, _HOOKS):
        if inspect.getattr_static(_CLASS, name, _MISSING) is not original:
            context.reject('replacement shallow class hook: ' + name, category='replacement_hook', phase='shallow_authority')


def _preflight(value, context):
    if type(value) is not _CLASS:
        context.reject('shallow authority must be an exact LoadedProject', category='schema', phase='shallow_authority')
    state = object.__getattribute__(value, '__dict__')
    if type(state) is not dict or len(state) != len(_FIELDS):
        context.reject('noncanonical shallow state shape', category='schema', phase='shallow_authority')
    for name in state:
        if type(name) is not str or name not in _FIELDS:
            context.reject('noncanonical shallow state key', category='schema', phase='shallow_authority')
        context.admit_shallow_field()
    # No access to any field value, including aliases and cycles.


class Owner(MapOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

    def _authority_shallow(self, copier, value):
        try:
            self.context.check()
            if copier is not _COPY:
                self.context.reject('replacement captured shallow copier', category='replacement_hook', phase='shallow_authority')
            _hooks(self.context)
            _preflight(value, self.context)
            result = copier(value)
            self.context.check()
            return result
        except BaseException:
            self.context.closed = True
            raise
        finally:
            del copier, value

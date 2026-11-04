"""Preflight three exact plain maps, not Package/Path or shallow-copy work.

Occurrence units do not count bytes, allocations or all deepcopy operations.
Assumes trusted private/runtime integrity during the callback-free phase.
"""
import copy
from dataclasses import dataclass

from experiments.owned_loader import owner as owned
from experiments.assembly_copy.owner import _copy_hooks, _DEEPCOPY, _MISSING
from experiments.loader_transform.owner import (
    Limits as TransformLimits, Owner as TransformOwner,
    _Context as TransformContext, _Ops,
)

_SEAM = owned.Owner._authority_copy
_BYTES_COPY = copy._deepcopy_dispatch.get(bytes, _MISSING)
_BYTES_REDUCER = copy.dispatch_table.get(bytes, _MISSING)


@dataclass(frozen=True)
class Limits(TransformLimits):
    authority_visits: int = 200_000
    authority_depth: int = 64


class _Context(TransformContext):
    def __init__(self, limits, checkpoint):
        super().__init__(limits, checkpoint)
        self.counts['authority_visits'] = 0

    def check(self):
        super().check()
        if (owned.copy is not copy
                or getattr(owned.Owner, '_authority_copy', None) is not _SEAM):
            self.reject('replacement authority copy seam', category='replacement_hook', phase='authority_maps')

    def admit_authority(self, depth):
        # No callback between inspecting an input and using the actual copier.
        if self.closed:
            self.reject('request context is terminal', category='terminal', phase='authority_maps')
        if depth > self.limits.authority_depth:
            self.reject('authority_depth quota exceeded', category='budget', phase='authority_maps', dimension='authority_depth', limit=self.limits.authority_depth, admitted=None, attempted=depth)
        if self.counts['authority_visits'] >= self.limits.authority_visits:
            self.reject('authority_visits quota exceeded', category='budget', phase='authority_maps', dimension='authority_visits', limit=self.limits.authority_visits, admitted=self.counts['authority_visits'], attempted=self.counts['authority_visits'] + 1)
        self.counts['authority_visits'] += 1


def _children(value, context, name, depth):
    cls = type(value)
    if depth == 1:
        if name == 'package_state' and value is None:
            return None
        if cls is not dict:
            context.reject('authority map root must be an exact dictionary', category='schema', phase='authority_maps')
    elif cls is str:
        return None
    elif name == 'source_bytes' and cls is bytes:
        return None
    elif name != 'package_state' or cls is not dict:
        context.reject('unknown authority map object', category='schema', phase='authority_maps')
    return _entries(value, context, name)


def _entries(value, context, name):
    for key, child in value.items():
        if type(key) is not str:
            context.reject('authority map keys must be exact strings', category='schema', phase='authority_maps')
        yield key
        if name == 'source_bytes' and type(child) is not bytes:
            context.reject('source_bytes values must be exact bytes', category='schema', phase='authority_maps')
        if name == 'bindings' and type(child) is not str:
            context.reject('bindings values must be exact strings', category='schema', phase='authority_maps')
        yield child


def _preflight(value, context, name):
    context.admit_authority(1)
    stack, active, depth = [], set(), 1
    while True:
        children = _children(value, context, name, depth)
        if children is not None:
            identity = id(value)
            if identity in active:
                context.reject('cyclic authority map is not admitted', category='schema', phase='authority_maps')
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
                context.admit_authority(depth)
                break
        else:
            return


class Owner(TransformOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

    def _authority_copy(self, deepcopy, value, name):
        try:
            if self.context.closed:
                self.context.reject('request context is terminal', category='terminal', phase='authority_maps')
            if type(name) is not str:
                self.context.reject('unknown authority map name', category='schema', phase='authority_maps')
            if name == 'package':
                # Separate fresh-memo call, deliberately outside map admission.
                return super()._authority_copy(deepcopy, value, name)
            self.context.check()
            if name not in ('source_bytes', 'bindings', 'package_state'):
                self.context.reject('unknown authority map name', category='schema', phase='authority_maps')
            if deepcopy is not _DEEPCOPY:
                self.context.reject('replacement captured authority copier', category='replacement_hook', phase='authority_maps')
            _copy_hooks(self.context)
            if (copy._deepcopy_dispatch.get(bytes, _MISSING) is not _BYTES_COPY
                    or copy.dispatch_table.get(bytes, _MISSING) is not _BYTES_REDUCER):
                self.context.reject('replacement bytes copy dispatch', category='replacement_hook', phase='authority_maps')
            _preflight(value, self.context, name)
            result = deepcopy(value)
            self.context.check()
            return result
        except BaseException:
            self.context.closed = True
            raise
        finally:
            del deepcopy, value

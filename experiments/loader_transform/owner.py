"""Admit each normal loader transform body before its reconstruction work.

Resolution maps, argument evaluation and private authority copies are separate
work. Ordinary private/runtime integrity is assumed; this is not a sandbox.
"""
from dataclasses import dataclass

from hepta import modules
from hepta._loader_ops import LegacyLoaderOps
from experiments.assembly_copy.owner import (
    Limits as CopyLimits, Owner as CopyOwner, _Context as CopyContext,
    _Ops as CopyOps,
)

_TRANSFORM = LegacyLoaderOps.transform_visit
_BINDINGS = tuple((name, getattr(modules, name)) for name in
                  ('Type', 'Expr', 'Span', 'fields', 'is_dataclass'))


@dataclass(frozen=True)
class Limits(CopyLimits):
    transform_visits: int = 200_000
    transform_depth: int = 128


class _Context(CopyContext):
    def __init__(self, limits, checkpoint):
        super().__init__(limits, checkpoint)
        self.counts['transform_visits'] = 0

    def check(self):
        super().check()
        if getattr(LegacyLoaderOps, 'transform_visit', None) is not _TRANSFORM:
            self.reject('replacement transform admission hook', category='replacement_hook', phase='loader_transform')
        for name, expected in _BINDINGS:
            if getattr(modules, name, None) is not expected:
                self.reject('replacement transform alias: ' + name, category='replacement_hook', phase='loader_transform')

    def admit_transform(self, depth):
        self.check()
        if type(depth) is not int or depth < 1:
            self.reject('invalid transform depth', category='schema', phase='loader_transform')
        if depth > self.limits.transform_depth:
            self.reject('transform_depth quota exceeded', category='budget', phase='loader_transform', dimension='transform_depth', limit=self.limits.transform_depth, admitted=None, attempted=depth)
        if self.counts['transform_visits'] >= self.limits.transform_visits:
            self.reject('transform_visits quota exceeded', category='budget', phase='loader_transform', dimension='transform_visits', limit=self.limits.transform_visits, admitted=self.counts['transform_visits'], attempted=self.counts['transform_visits'] + 1)
        self.counts['transform_visits'] += 1


class _Ops(CopyOps):
    def transform_visit(self, depth):
        self.context.admit_transform(depth)


class Owner(CopyOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

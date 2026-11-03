"""Finite graph-work admission over the real normal loader; no production default."""
from experiments.owned_loader.owner import Owner as ReadOwner, _Ops as ReadOps, _Context
from experiments.request_load.context import Limits


class _Ops(ReadOps):
    def edge(self, kind, depth):
        self.context.depth(depth, getattr(self.context.limits, kind + '_depth'))
        self.context.charge(kind + '_edges')

    def node(self, kind):
        self.context.charge({'package': 'packages', 'module': 'modules'}[kind])

    def path(self, path, operation):
        self.context.charge('path_checks')
        return super().path(path, operation)


class Owner(ReadOwner):
    """Opt-in experimental graph profile; original owner still rejects graph limits."""
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

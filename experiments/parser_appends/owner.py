"""Cumulative grammar append attempts, not bytes or full container coverage."""
from dataclasses import dataclass
from types import BuiltinMethodType

from hepta import parser
from experiments.ast_structure.owner import (
    Limits as AstLimits, Owner as AstOwner, _Context as AstContext,
    _Parser as AstParser, _Ops as AstOps,
)

_ADMIT_APPEND = parser.Parser._admit_append


@dataclass(frozen=True)
class Limits(AstLimits):
    parser_appends: int = 20_000


class _Context(AstContext):
    def __init__(self, limits, checkpoint):
        super().__init__(limits, checkpoint)
        self.counts['parser_appends'] = 0

    def check(self):
        super().check()
        if getattr(parser.Parser, '_admit_append', None) is not _ADMIT_APPEND:
            self.reject('replacement parser append hook is not admitted')


class _Parser(AstParser):
    def _admit_append(self, operation):
        if (type(operation) is not BuiltinMethodType
                or type(operation.__self__) is not list
                or operation.__name__ != 'append'):
            self.context.reject('unknown parser append operation')
        self.context.charge('parser_appends')
        return operation


class _Ops(AstOps):
    def _make_parser(self, text, path, tokens):
        return _Parser(text, path, tokens, self.context)


class Owner(AstOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

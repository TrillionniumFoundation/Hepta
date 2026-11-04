"""Finite parser constructor-attempt admission, not an AST memory bound."""
from dataclasses import dataclass

from hepta import ast, parser
from experiments.owned_tokens.owner import Owner as TokenOwner, _Ops as TokenOps
from experiments.owned_tokens.owner import _Context as TokenContext, _Parser as TokenParser
from experiments.request_load.context import Limits as TokenLimits

_NAMES = ('Type', 'Expr', 'Stmt', 'Param', 'Struct', 'EnumVariant', 'Enum',
          'Pattern', 'MatchArm', 'Import', 'Function', 'Program')
_CONSTRUCTORS = tuple(getattr(ast, name) for name in _NAMES)
_ADMIT = parser.Parser._admit_node


@dataclass(frozen=True)
class Limits(TokenLimits):
    ast_nodes: int = 20_000


class _Context(TokenContext):
    def __init__(self, limits, checkpoint):
        super().__init__(limits, checkpoint)
        self.counts['ast_nodes'] = 0

    def check(self):
        super().check()
        for name, constructor in zip(_NAMES, _CONSTRUCTORS):
            if (getattr(parser, name, None) is not constructor
                    or getattr(ast, name, None) is not constructor):
                self.reject('replacement AST constructor is not admitted: ' + name, category='replacement_hook', phase='ast_structure')
        if getattr(parser.Parser, '_admit_node', None) is not _ADMIT:
            self.reject('replacement AST admission hook is not admitted', category='replacement_hook', phase='ast_structure')


class _Parser(TokenParser):
    def _admit_node(self, constructor):
        if not any(constructor is expected for expected in _CONSTRUCTORS):
            self.context.reject('unknown AST constructor', category='schema', phase='ast_structure')
        # Admission precedes arguments and construction. A failed argument or
        # constructor still consumes this conservative work-attempt admission.
        self.context.charge('ast_nodes')
        return constructor


class _Ops(TokenOps):
    def _make_parser(self, text, path, tokens):
        return _Parser(text, path, tokens, self.context)


class Owner(TokenOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

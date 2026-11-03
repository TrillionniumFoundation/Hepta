"""Experimental single-lex profile. Token provenance is not a Python sandbox."""
from contextlib import contextmanager
from dataclasses import dataclass

from hepta import lexer, parser
from hepta.ast import Span
from experiments.graph_loader.owner import Owner as GraphOwner, _Ops as GraphOps
from experiments.owned_loader.owner import _Context as ReadContext, _PARSE, _TOKENIZE
from experiments.request_load.context import Limits, TokenList

_TOKEN, _SPAN = lexer.Token, Span
_LEXER, _PARSER = lexer.Lexer, parser.Parser
_LEX_LOOP = _LEXER._tokenize
_PARSE_INIT = _PARSER._initialize_tokens
_LEX_INIT, _LEX_ADVANCE = _LEXER.__init__, _LEXER._advance
_PARSE_ADVANCE, _PARSE_BODY = _PARSER._advance, _PARSER.parse
# Finite entry seams; arbitrary private/runtime/AST method mutation is excluded.
_BINDINGS = ((lexer, 'Lexer', _LEXER), (parser, 'Parser', _PARSER),
             (lexer, 'Token', _TOKEN), (lexer, 'Span', _SPAN),
             (parser, 'Token', _TOKEN), (parser, 'Span', _SPAN),
             (parser, 'tokenize', _TOKENIZE),
             (_LEXER, 'tokenize', _LEXER.tokenize),
             (_LEXER, '_tokenize', _LEX_LOOP), (_LEXER, '__init__', _LEX_INIT),
             (_LEXER, '_advance', _LEX_ADVANCE),
             (_PARSER, '_initialize_tokens', _PARSE_INIT),
             (_PARSER, '_advance', _PARSE_ADVANCE), (_PARSER, 'parse', _PARSE_BODY))


class _Context(ReadContext):
    def check(self):
        super().check()
        for namespace, name, expected in _BINDINGS:
            if getattr(namespace, name, None) is not expected:
                self.reject('replacement token hook is not admitted: ' + name)


class _Lexer(_LEXER):
    def __init__(self, source, path, context):
        super().__init__(source, path)
        self.context = context

    def _advance(self):
        if self.position % 1024 == 0:
            self.context.check()
        return _LEX_ADVANCE(self)

    def tokenize(self):
        return _LEX_LOOP(self, TokenList(self.context))


class _Parser(_PARSER):
    def __init__(self, source, path, tokens, context):
        self.source, self.path, self.context = source, path, context
        _PARSE_INIT(self, tokens)

    def _advance(self):
        if self.position % 256 == 0:
            self.context.check()
        return _PARSE_ADVANCE(self)

    @contextmanager
    def _nested(self):
        self.depth += 1
        try:
            self.context.depth(self.depth, self.context.limits.parser_depth)
            yield
        finally:
            self.depth -= 1


@dataclass(frozen=True, eq=False)
class _Batch:
    tokens: tuple

    def __iter__(self):
        return iter(self.tokens)


def _fingerprint(tokens, context):
    if type(tokens) is not tuple:
        context.reject('modified token collection')
    rows = []
    for token in tokens:
        if type(token) is not _TOKEN or type(token.span) is not _SPAN:
            context.reject('modified token type')
        span = token.span
        if (type(token.kind) is not str or type(token.value) not in (str, int, float, type(None))
                or any(type(v) is not int for v in (span.start, span.end, span.line, span.column))
                or type(span.path) is not str):
            context.reject('modified token fields')
        value = token.value.hex() if type(token.value) is float else token.value
        rows.append((token.kind, type(token.value).__name__, value, span.start, span.end, span.line, span.column, span.path))
    return tuple(rows)


class _Ops(GraphOps):
    def __init__(self, context):
        super().__init__(context)
        self._pending = {}
        self._scan_batch = None

    def tokenize(self, tokenize, text, path):
        try:
            self.hook(tokenize, _TOKENIZE)
            if type(text) is not str or type(path) is not str:
                self.context.reject('token source and path must be exact strings')
            if len(text.encode('utf-8')) > self.context.limits.source:
                self.context.reject('parser input byte quota exceeded')
            tokens = tuple(_Lexer(text, path, self.context).tokenize())
            self.context.check()
            batch = _Batch(tokens)
            self._pending[id(batch)] = (batch, text, path, tokens, _fingerprint(tokens, self.context))
            self._scan_batch = batch
            return batch
        except BaseException:
            self.context.closed = True
            self._pending.clear()
            self._scan_batch = None
            raise

    def scan_receipt(self):
        batch = self._scan_batch
        self._scan_batch = None
        return batch

    def parse_admitted(self, parse, text, path, batch):
        try:
            self.hook(parse, _PARSE)
            # Charge/check callbacks before validating and consuming provenance.
            self.context.charge('parses')
            record = self._pending.get(id(batch))
            if type(batch) is not _Batch or record is None or record[0] is not batch:
                self.context.reject('token batch does not belong or was consumed')
            _, source, source_path, tokens, fingerprint = record
            if type(text) is not str or type(path) is not str or text != source or path != source_path:
                self.context.reject('token source or path mismatch')
            if batch.tokens is not tokens or _fingerprint(tokens, self.context) != fingerprint:
                self.context.reject('modified admitted tokens')
            # Consume before parser/checkpoint callbacks. Parser owns a separate
            # private snapshot, so later mutation of exposed batch tokens is inert.
            del self._pending[id(batch)]
            if self._scan_batch is batch:
                self._scan_batch = None
            private = [_TOKEN(kind, float.fromhex(value) if tag == 'float' else value,
                                   _SPAN(start, end, line, column, token_path))
                            for kind, tag, value, start, end, line, column, token_path in fingerprint]
            result = self._make_parser(text, path, private).parse()
            self.context.check()
            return result
        except BaseException:
            self.context.closed = True
            self._pending.clear()
            self._scan_batch = None
            raise

    def _make_parser(self, text, path, tokens):
        return _Parser(text, path, tokens, self.context)

    def parse(self, parse, text, path):
        self.context.reject('single-lex parsing requires an admitted batch')


class Owner(GraphOwner):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

    def load(self, entry, *, locked=False, source_overrides=None):
        try:
            return super().load(entry, locked=locked, source_overrides=source_overrides)
        except BaseException:
            self._ops._pending.clear()
            self._ops._scan_batch = None
            raise

    def unchanged(self, handle):
        try:
            return super().unchanged(handle)
        except BaseException:
            self._ops._pending.clear()
            self._ops._scan_batch = None
            raise

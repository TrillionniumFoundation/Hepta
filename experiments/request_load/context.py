"""Explicit, request-owned admission for an isolated copy of the loader.

No process sandbox, hard real-time guarantee, or production default is provided.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import threading
import tomllib

from hepta.lexer import Lexer, Token, KEYWORDS
from hepta.parser import Parser
from experiments.loader_budget.prototype import Reader, Limits as ReadLimits, Rejected as ReadRejected


class Rejected(RuntimeError):
    """Not a ValueError/HeptaError: existing parse/race catches must not hide it."""


@dataclass(frozen=True)
class Limits:
    source: int = 1_000_000
    manifest: int = 64_000
    lock: int = 1_000_000
    sidecar: int = 1_000_000
    header: int = 1_000_000
    total_bytes: int = 32_000_000
    reads: int = 1024
    inventory_entries: int = 4096
    directory_depth: int = 16
    packages: int = 128
    package_depth: int = 16
    package_edges: int = 512
    module_edges: int = 1024
    path_checks: int = 1024
    modules: int = 256
    module_depth: int = 16
    tokens_per_parse: int = 20_000
    total_tokens: int = 200_000
    parses: int = 256
    parser_depth: int = 48
    metadata_parses: int = 256
    json_depth: int = 32

    def __post_init__(self):
        for name, value in vars(self).items():
            if type(value) is not int or value <= 0:
                raise ValueError(f'{name} must be a positive integer')
        if self.parser_depth > 96:
            raise ValueError('cannot relax the existing parser nesting limit')


class Context:
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        self.limits, self.checkpoint = limits, checkpoint
        self.closed = False
        self.owner = threading.get_ident()
        self._checkpoint_guard = threading.Lock()
        self._loading = False
        self._role_caps = {}
        self.counts = dict(inventory_entries=0, packages=0, modules=0,
                           parses=0, total_tokens=0, metadata_parses=0,
                           package_edges=0, module_edges=0, path_checks=0)
        self.reader = Reader(ReadLimits(max(limits.source, limits.manifest,
                            limits.lock, limits.sidecar, limits.header),
                            limits.total_bytes, limits.reads), self.check)

    def reject(self, message, **provenance):
        self.closed = True
        raise Rejected(message)

    def check(self):
        if self.closed:
            raise Rejected('request context is terminal')
        if threading.get_ident() != self.owner:
            self.reject('request context cannot cross threads', category='thread', phase='request_load')
        if not self._checkpoint_guard.acquire(blocking=False):
            self.reject('reentrant checkpoint is not admitted', category='reentrancy', phase='request_load')
        try:
            self.checkpoint()
        except BaseException:
            self.closed = True
            raise
        finally:
            self._checkpoint_guard.release()

    def charge(self, name, amount=1):
        self.check()
        if self.counts[name] + amount > getattr(self.limits, name):
            self.reject(name + ' quota exceeded', category='budget', phase='charge', dimension=name, limit=getattr(self.limits, name), admitted=self.counts[name], attempted=self.counts[name] + amount)
        self.counts[name] += amount

    def depth(self, actual, maximum, *, dimension=None):
        self.check()
        if actual > maximum:
            self.reject('depth quota exceeded', category='budget', phase='depth', dimension=dimension, limit=maximum, admitted=None, attempted=actual)

    def admit(self, name, depth, maximum):
        self.depth(depth, maximum)
        self.charge(name)

    @staticmethod
    def role(path):
        name = Path(path).name
        if name == 'hepta.toml': return 'manifest'
        if name == 'Hepta.lock': return 'lock'
        if name.endswith('.imports.json'): return 'sidecar'
        if name.endswith('.hepta'): return 'source'
        return 'header'

    def _cap(self, path, role):
        role = self.role(path) if role is None else role
        if role not in {'source', 'manifest', 'lock', 'sidecar', 'header'}:
            self.reject('unknown input role', category='schema', phase='request_load')
        key = str(Path(path).resolve())
        cap = min(getattr(self.limits, role), self._role_caps.get(key, getattr(self.limits, role)))
        self._role_caps[key] = cap
        return cap

    def read(self, path, role=None):
        self.check()
        cap = self._cap(path, role)
        try:
            return self.reader.read(path, max_bytes=cap)
        except ReadRejected as error:
            self.reject(str(error), category='schema', phase='request_load')
        except BaseException:
            self.closed = True
            raise

    def digest(self, path, role):
        self.check()
        try:
            return self.reader.digest(path, max_bytes=self._cap(path, role))
        except ReadRejected as error:
            self.reject(str(error), category='schema', phase='request_load')
        except BaseException:
            self.closed = True
            raise

    def inventory(self, root):
        # Count each directory entry before retaining/sorting it. Directory
        # symlinks are yielded to the loader's existing rejection policy only.
        pending = [(Path(root), 1)]
        while pending:
            directory, depth = pending.pop()
            self.depth(depth, self.limits.directory_depth, dimension='directory_depth')
            with os.scandir(directory) as entries:
                for entry in entries:
                    self.charge('inventory_entries')
                    path = Path(entry.path)
                    yield path
                    if entry.is_dir(follow_symlinks=False):
                        self.depth(depth + 1, self.limits.directory_depth, dimension='directory_depth')
                        pending.append((path, depth + 1))

    def json(self, data, path):
        self.charge('metadata_parses')
        # Check structural nesting before the standard recursive decoder. Quoted
        # delimiters/escapes do not change nesting. Decoder still checks syntax.
        text = data.decode(json.detect_encoding(data), 'surrogatepass')
        depth = 0
        quoted = escaped = False
        for index, char in enumerate(text):
            byte = ord(char)
            if index % 1024 == 0: self.check()
            if quoted:
                if escaped: escaped = False
                elif byte == 92: escaped = True
                elif byte == 34: quoted = False
            elif byte == 34: quoted = True
            elif byte in (91, 123):
                depth += 1
                self.depth(depth, self.limits.json_depth, dimension='json_depth')
            elif byte in (93, 125): depth -= 1
        result = json.loads(text)
        self.check()
        return result

    def toml(self, data, path):
        # Byte and invocation admission only. No TOML AST/CPU bound is claimed.
        self.charge('metadata_parses')
        result = tomllib.loads(data.decode('utf-8'))
        self.check()
        return result

    def tokenize(self, text, path='<input>'):
        self.check()
        input_bytes = len(text.encode('utf-8'))
        if input_bytes > self.limits.source:
            self.reject('parser input byte quota exceeded', category='budget', phase='request_load', dimension='source', limit=self.limits.source, admitted=0, attempted=input_bytes)
        return BoundedLexer(text, path, self).tokenize()

    def parse(self, text, path='<input>', *, tokens=None):
        self.charge('parses')
        if tokens is None:
            tokens = self.tokenize(text, path)
        parser = BoundedParser(text, path, tokens, self)
        result = parser.parse()
        self.check()
        return result

    def load(self, entry, *, locked=False, source_overrides=None):
        from .modules import load_project
        self.check()
        if self._loading:
            self.reject('reentrant graph load is not admitted', category='reentrancy', phase='request_load')
        self._loading = True
        try:
            return load_project(entry, context=self, locked=locked,
                                source_overrides=source_overrides)
        except BaseException:
            self.closed = True
            raise
        finally:
            self._loading = False


class TokenList(list):
    def __init__(self, context):
        self.context = context

    def append(self, token):
        # The next token exists, but no unbounded token list is built first.
        if len(self) >= self.context.limits.tokens_per_parse:
            self.context.reject('tokens per parse quota exceeded', category='budget', phase='request_load', dimension='tokens_per_parse', limit=self.context.limits.tokens_per_parse, admitted=len(self), attempted=len(self) + 1)
        self.context.charge('total_tokens')
        super().append(token)


class BoundedLexer(Lexer):
    def __init__(self, text, path, context):
        super().__init__(text, path)
        self.context = context

    def _advance(self):
        if self.position % 1024 == 0:
            self.context.check()
        return super()._advance()

    def tokenize(self) -> list[Token]:
        result: list[Token] = TokenList(self.context)
        pairs = {"->", "..", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "::", "=>"}
        singles = set("{}()[],:;=+-*/%!<>.&|^")
        while self.position < len(self.source):
            ch = self._peek()
            if ch in " \t\r\n":
                self._advance()
                continue
            if ch == "/" and self._peek(1) in ("/", "*"):
                self._comment()
                continue
            mark = self._mark()
            if self._identifier_start(ch):
                self._advance()
                while self._identifier_continue(self._peek()):
                    self._advance()
                value = self.source[mark[0]:self.position]
                result.append(Token(value if value in KEYWORDS else "IDENT", value,
                                    self._span(mark)))
            elif ch == "'":
                self._advance()
                if not self._identifier_start(self._peek()):
                    self._error("E_LEX_CHARACTER", "A lifetime requires an ASCII identifier after apostrophe", mark)
                start = self.position
                while self._identifier_continue(self._peek()):
                    self._advance()
                result.append(Token("LIFETIME", self.source[start:self.position], self._span(mark)))
            elif "0" <= ch <= "9":
                result.append(self._number())
            elif ch == '"':
                result.append(self._string())
            elif ch + self._peek(1) in pairs:
                value = self._advance() + self._advance()
                result.append(Token(value, value, self._span(mark)))
            elif ch in singles:
                value = self._advance()
                result.append(Token(value, value, self._span(mark)))
            else:
                self._advance()
                self._error("E_LEX_CHARACTER", f"Unsupported character {ch!r}", mark)
        result.append(Token("EOF", None, self._span(self._mark())))
        return result


class BoundedParser(Parser):
    def __init__(self, source, path, tokens, context):
        # Avoid production Parser.__init__ tokenizing the same input again.
        self.source, self.path, self.tokens = source, path, tokens
        self.position, self.depth = 0, 0
        self.qualified_expressions = []
        self.context = context

    def _advance(self):
        if self.position % 256 == 0:
            self.context.check()
        return super()._advance()

    @contextmanager
    def _nested(self):
        self.depth += 1
        try:
            self.context.depth(self.depth, self.context.limits.parser_depth, dimension='parser_depth')
            yield
        finally:
            self.depth -= 1

"""Strict, position-preserving tokens for the Hepta v0.1 bootstrap grammar.

Offsets are zero-based Python string offsets (Unicode code points); lines and
columns are one-based.  Comments are discarded, but never rewritten into code.
Only ASCII identifiers are accepted.  Strings are tokens solely so the parser
can recognize the literal ABI name ``"C"``; escape sequences are unsupported.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from .ast import Diagnostic, HeptaError, Span


KEYWORDS = frozenset({
    "module", "struct", "repr", "pub", "export", "extern", "fn",
    "effects", "resources", "let", "return", "for", "in", "while",
    "if", "else", "unsafe", "read", "mut", "take", "move", "as",
    "raw", "const", "true", "false", "enum", "match", "import",
})


@dataclass(frozen=True)
class Token:
    kind: str
    value: Any
    span: Span


class Lexer:
    def __init__(self, source: str, path: str = "<input>") -> None:
        self.source = source
        self.path = path
        self.position = 0
        self.line = 1
        self.column = 1
        self._previous_cr = False

    def _mark(self) -> tuple[int, int, int]:
        return self.position, self.line, self.column

    def _span(self, mark: tuple[int, int, int], end: int | None = None) -> Span:
        start, line, column = mark
        return Span(start, self.position if end is None else end,
                    line, column, self.path)

    def _advance(self) -> str:
        ch = self.source[self.position]
        self.position += 1
        if ch == "\r":
            self.line += 1
            self.column = 1
            self._previous_cr = True
        elif ch == "\n":
            if not self._previous_cr:
                self.line += 1
            self.column = 1
            self._previous_cr = False
        else:
            self.column += 1
            self._previous_cr = False
        return ch

    def _peek(self, distance: int = 0) -> str:
        index = self.position + distance
        return self.source[index] if index < len(self.source) else ""

    def _error(self, code: str, message: str,
               mark: tuple[int, int, int], end: int | None = None) -> None:
        raise HeptaError(Diagnostic(code, message, self._span(mark, end),
                                    phase="lex"))

    @staticmethod
    def _identifier_start(ch: str) -> bool:
        return bool(ch) and ("a" <= ch <= "z" or "A" <= ch <= "Z" or ch == "_")

    @classmethod
    def _identifier_continue(cls, ch: str) -> bool:
        return cls._identifier_start(ch) or bool(ch) and "0" <= ch <= "9"

    def _comment(self) -> None:
        mark = self._mark()
        self._advance()
        second = self._advance()
        if second == "/":
            while self._peek() and self._peek() not in "\r\n":
                self._advance()
            return
        depth = 1
        while self._peek():
            if self._peek() == "/" and self._peek(1) == "*":
                self._advance()
                self._advance()
                depth += 1
            elif self._peek() == "*" and self._peek(1) == "/":
                self._advance()
                self._advance()
                depth -= 1
                if not depth:
                    return
            else:
                self._advance()
        self._error("E_LEX_COMMENT", "Unterminated block comment", mark)

    def _digit_sequence(self, valid: str,
                        number_mark: tuple[int, int, int]) -> None:
        start = self.position
        previous_separator = False
        while self._peek() and (self._peek() in valid or self._peek() == "_"):
            ch = self._advance()
            if ch == "_":
                if self.position == start + 1 or previous_separator:
                    self._error("E_LEX_NUMBER", "Misplaced numeric separator", number_mark)
                previous_separator = True
            else:
                previous_separator = False
        if self.position == start or previous_separator:
            self._error("E_LEX_NUMBER", "Expected digits without a trailing separator", number_mark)

    def _number(self) -> Token:
        mark = self._mark()
        base = 10
        floating = False
        if self._peek() == "0" and self._peek(1) in ("x", "X", "b", "B", "o", "O"):
            marker = self._peek(1).lower()
            base, digits = {"x": (16, "0123456789abcdefABCDEF"),
                            "b": (2, "01"), "o": (8, "01234567")}[marker]
            self._advance()
            self._advance()
            self._digit_sequence(digits, mark)
        else:
            self._digit_sequence("0123456789", mark)
            # A range (0..n) and field punctuation (1.foo) are not floats.
            if self._peek() == "." and self._peek(1) and "0" <= self._peek(1) <= "9":
                floating = True
                self._advance()
                self._digit_sequence("0123456789", mark)
            if self._peek() in ("e", "E"):
                floating = True
                self._advance()
                if self._peek() in ("+", "-"):
                    self._advance()
                self._digit_sequence("0123456789", mark)
        if self._identifier_continue(self._peek()):
            while self._identifier_continue(self._peek()):
                self._advance()
            self._error("E_LEX_NUMBER", "Invalid numeric digit or unsupported literal suffix", mark)
        raw = self.source[mark[0]:self.position].replace("_", "")
        if len(raw) > 4096:
            self._error("E_LEX_NUMBER", "Numeric literal exceeds the bootstrap limit of 4096 digits", mark)
        try:
            value = float(raw) if floating else int(raw, base)
        except (ValueError, OverflowError):
            self._error("E_LEX_NUMBER", "Invalid numeric literal", mark)
        if floating and not math.isfinite(value):
            self._error("E_LEX_NUMBER", "Floating-point literal must be finite", mark)
        return Token("FLOAT" if floating else "INT", value, self._span(mark))

    def _string(self) -> Token:
        mark = self._mark()
        self._advance()
        start = self.position
        while self._peek() and self._peek() != '"':
            if self._peek() == "\\":
                self._error("E_LEX_STRING_ESCAPE", "ABI strings do not support escape sequences",
                            self._mark(), self.position + 1)
            if self._peek() in "\r\n" or ord(self._peek()) < 32:
                self._error("E_LEX_STRING", "ABI strings must remain on one line", mark,
                            self.position + 1)
            self._advance()
        if not self._peek():
            self._error("E_LEX_STRING", "Unterminated string literal", mark)
        value = self.source[start:self.position]
        self._advance()
        return Token("STRING", value, self._span(mark))

    def tokenize(self) -> list[Token]:
        result: list[Token] = []
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


def tokenize(source: str, path: str = "<input>") -> list[Token]:
    return Lexer(source, path).tokenize()

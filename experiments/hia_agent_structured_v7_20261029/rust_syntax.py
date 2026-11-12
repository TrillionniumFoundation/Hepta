"""A bounded parser for the disclosed Rust study syntax, not general Rust.

The parser produces actual expression/type source spans. It never infers spans
from correct answers, fixed templates or text replacement markers. Whole-source
admission and real rustc remain mandatory before a candidate is admitted.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


class SyntaxRejected(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int


TOKEN = re.compile(r"\s+|[A-Za-z_][A-Za-z_0-9]*|[0-9]+(?:u8|u16|u32|u64|usize)?|::|->|==|!=|<=|>=|&&|\|\||<<|>>|[(){}\[\],;:.+*/%&|^!<>=?-]")
SCALARS = {"u8", "u16", "u32", "u64", "usize", "bool"}
PRECEDENCE = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5,
              "==": 6, "!=": 6, "<": 6, "<=": 6, ">": 6, ">=": 6,
              "<<": 7, ">>": 7, "+": 8, "-": 8, "*": 9, "/": 9, "%": 9}
MAX_BYTES = 16384
MAX_NODES = 1024
MAX_DEPTH = 64


def tokens(source):
    if type(source) is not str or not source.isascii() or len(source) > MAX_BYTES:
        raise SyntaxRejected("E_STRUCTURED_RUST: bounded ASCII source required")
    if any(x in source for x in ('//', '/*', '*/', '$', '"', "'", '#', '`', '\\')):
        raise SyntaxRejected("E_STRUCTURED_RUST: comments, macros, strings and attributes outside finite syntax")
    result = []
    position = 0
    while position < len(source):
        match = TOKEN.match(source, position)
        if match is None:
            raise SyntaxRejected("E_STRUCTURED_RUST: unknown token at " + str(position))
        if not match[0].isspace():
            result.append(Token(match[0], match.start(), match.end()))
        position = match.end()
    return result


class Parser:
    def __init__(self, source):
        self.source = source
        self.tokens = tokens(source)
        self.index = 0
        self.nodes = []
        self.depth = 0
        self.signature = None

    def peek(self):
        return self.tokens[self.index].text if self.index < len(self.tokens) else None

    def take(self, expected=None):
        if self.index >= len(self.tokens):
            raise SyntaxRejected("E_STRUCTURED_RUST: unexpected end")
        token = self.tokens[self.index]
        if expected is not None and token.text != expected:
            raise SyntaxRejected("E_STRUCTURED_RUST: expected " + expected + " at " + str(token.start))
        self.index += 1
        return token

    def identifier(self):
        token = self.take()
        if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", token.text) is None:
            raise SyntaxRejected("E_STRUCTURED_RUST: identifier required")
        return token

    def node(self, start, end, category, shape, anchor=None):
        if len(self.nodes) >= MAX_NODES:
            raise SyntaxRejected("E_STRUCTURED_RUST: node budget")
        tree_depth = 1 + max((n["tree_depth"] for n in self.nodes
                              if start <= n["start"] and n["end"] <= end), default=0)
        if tree_depth > MAX_DEPTH:
            raise SyntaxRejected("E_STRUCTURED_RUST: AST depth")
        item = {"start": start, "end": end, "category": category, "shape": shape,
                "anchor": start if anchor is None else anchor, "tree_depth": tree_depth}
        self.nodes.append(item)
        return item

    def typ(self):
        first = self.take()
        if first.text == "Vec":
            self.take("<"); self.take("u8"); end = self.take(">").end
        elif first.text in SCALARS:
            end = first.end
        else:
            raise SyntaxRejected("E_STRUCTURED_RUST: only disclosed scalar/Vec<u8> types")
        return self.node(first.start, end, "type", "declared_type")

    def expression(self, minimum=0):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise SyntaxRejected("E_STRUCTURED_RUST: expression depth")
        try:
            value = self.prefix()
            while True:
                token = self.peek()
                if token == "(":
                    operator = self.take("(")
                    if self.peek() != ")":
                        self.expression()
                        while self.peek() == ",":
                            self.take(",")
                            if self.peek() == ")":
                                break
                            self.expression()
                    value = self.node(value["start"], self.take(")").end, "expression", "call", operator.start)
                elif token == ".":
                    operator = self.take("."); self.identifier(); self.take("(")
                    if self.peek() != ")":
                        self.expression()
                        while self.peek() == ",":
                            self.take(",")
                            if self.peek() == ")":
                                break
                            self.expression()
                    value = self.node(value["start"], self.take(")").end, "expression", "method_call", operator.start)
                elif token == "[":
                    operator = self.take("["); self.expression()
                    value = self.node(value["start"], self.take("]").end, "expression", "index", operator.start)
                elif token == "as" and 10 >= minimum:
                    operator = self.take("as"); target = self.typ()
                    value = self.node(value["start"], target["end"], "expression", "cast", operator.start)
                elif token in PRECEDENCE and PRECEDENCE[token] >= minimum:
                    operator = self.take(); rhs = self.expression(PRECEDENCE[token] + 1)
                    value = self.node(value["start"], rhs["end"], "expression", "binary:" + token, operator.start)
                else:
                    return value
        finally:
            self.depth -= 1

    def prefix(self):
        token = self.peek()
        if token in {"!", "-", "*", "&"}:
            first = self.take()
            if first.text == "&" and self.peek() == "mut":
                self.take("mut")
            inner = self.expression(11)
            return self.node(first.start, inner["end"], "expression", "unary")
        if token == "(":
            first = self.take("("); self.expression(); end = self.take(")")
            return self.node(first.start, end.end, "expression", "group")
        if token == "{":
            start, end = self.block()
            return self.node(start, end, "expression", "block")
        if token == "if":
            first = self.take("if"); self.expression(); _, end = self.block()
            if self.peek() == "else":
                self.take("else")
                if self.peek() == "if":
                    self.depth += 1
                    try:
                        if self.depth > MAX_DEPTH:
                            raise SyntaxRejected("E_STRUCTURED_RUST: expression depth")
                        end = self.prefix()["end"]
                    finally:
                        self.depth -= 1
                else:
                    _, end = self.block()
            return self.node(first.start, end, "expression", "if")
        if token == "vec":
            first = self.take("vec"); self.take("!"); self.take("[")
            self.expression(); self.take(";"); self.expression()
            return self.node(first.start, self.take("]").end, "expression", "vector")
        first = self.take()
        if re.fullmatch(r"[0-9]+(?:u8|u16|u32|u64|usize)?", first.text):
            return self.node(first.start, first.end, "expression", "literal")
        if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", first.text) is None or first.text in {
            "fn", "pub", "let", "return", "else", "use", "macro_rules", "while", "for", "loop", "match", "unsafe", "impl", "trait", "mod", "struct", "enum", "const", "static", "type", "async", "await", "move", "dyn"}:
            raise SyntaxRejected("E_STRUCTURED_RUST: expression atom required")
        end = first.end
        while self.peek() == "::":
            self.take("::"); end = self.identifier().end
        return self.node(first.start, end, "expression", "path")

    def block(self):
        first = self.take("{")
        while self.peek() != "}":
            if self.peek() is None:
                raise SyntaxRejected("E_STRUCTURED_RUST: unterminated block")
            if self.peek() == "let":
                self.take("let")
                if self.peek() == "mut":
                    self.take("mut")
                self.identifier()
                if self.peek() == ":":
                    self.take(":"); self.typ()
                self.take("="); self.expression(); self.take(";")
            elif self.peek() == "return":
                self.take("return"); self.expression(); self.take(";")
            else:
                value = self.expression()
                if self.peek() == "=":
                    self.take("="); self.expression(); self.take(";")
                elif self.peek() == ";":
                    self.take(";")
                elif self.peek() != "}":
                    # Rust permits if/block statements without a trailing ';'.
                    if value["shape"] not in {"if", "block"}:
                        raise SyntaxRejected("E_STRUCTURED_RUST: statement delimiter required")
        return first.start, self.take("}").end

    def function(self):
        if self.peek() == "use":
            for token in ("use", "crate", "::", "api", ";"):
                self.take(token)
        self.take("pub"); self.take("fn"); name = self.identifier().text
        self.take("(")
        parameters = []
        parameter_types = []
        if self.peek() != ")":
            while True:
                if self.peek() == "mut":
                    self.take("mut")
                param = self.identifier().text
                if param in parameters:
                    raise SyntaxRejected("E_STRUCTURED_RUST: duplicate parameter")
                parameters.append(param)
                self.take(":"); typ = self.typ()
                typ.update(role="parameter_type", parameter=param)
                parameter_types.append([param, "".join(self.source[typ["start"]:typ["end"]].split())])
                if self.peek() != ",":
                    break
                self.take(",")
                if self.peek() == ")":
                    break
        self.take(")"); self.take("->"); returned = self.typ(); returned["role"] = "return_type"
        self.signature = {"name": name, "params": parameter_types,
                          "returns": "".join(self.source[returned["start"]:returned["end"]].split())}
        self.block()
        self.eof()
        return name

    def eof(self):
        if self.peek() is not None:
            raise SyntaxRejected("E_STRUCTURED_RUST: trailing tokens outside selected fragment")


def parse_function(source):
    parser = Parser(source)
    name = parser.function()
    nodes = sorted(parser.nodes, key=lambda item: (item["start"], item["end"], item["category"]))
    if len({(n["start"], n["end"], n["category"]) for n in nodes}) != len(nodes):
        raise SyntaxRejected("E_STRUCTURED_RUST: ambiguous node spans")
    return name, nodes


def validate_fragment(source, category):
    parser = Parser(source)
    if category == "expression":
        parser.expression()
    elif category == "type":
        parser.typ()
    else:
        raise SyntaxRejected("E_STRUCTURED_RUST: unknown fragment category")
    parser.eof()


def parsed_signature(source):
    parser = Parser(source)
    parser.function()
    return parser.signature

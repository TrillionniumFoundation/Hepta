"""Recursive-descent declarations/statements and Pratt expressions for Hepta.

The parser constructs only the shared AST.  It never forwards source fragments
to a target language.  Semantic names and effects are resolved by the checker.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from .ast import Diagnostic, Expr, Function, HeptaError, Param, Program, Span, Stmt, Struct, Type
from .lexer import Token, tokenize


# Increasing numbers bind more tightly.  All binary operators associate left.
_BINARY = {
    "||": 1, "&&": 2, "|": 3, "^": 4, "&": 5,
    "==": 6, "!=": 6, "<": 7, "<=": 7, ">": 7, ">=": 7,
    "<<": 8, ">>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10,
}
_CAST = 11
_UNARY = 12
_MAX_NESTING = 96


def _cover(first: Span, last: Span) -> Span:
    return Span(first.start, last.end, first.line, first.column, first.path)


class Parser:
    def __init__(self, source: str, path: str = "<input>") -> None:
        self.source = source
        self.path = path
        self.tokens = tokenize(source, path)
        self.position = 0
        self.depth = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.position]

    @property
    def previous(self) -> Token:
        return self.tokens[max(0, self.position - 1)]

    def _at(self, kind: str) -> bool:
        return self.current.kind == kind

    def _advance(self) -> Token:
        token = self.current
        if token.kind != "EOF":
            self.position += 1
        return token

    def _take(self, kind: str) -> Token | None:
        return self._advance() if self._at(kind) else None

    def _error(self, message: str, token: Token | None = None,
               code: str = "E_PARSE") -> None:
        raise HeptaError(Diagnostic(code, message, (token or self.current).span,
                                    phase="parse"))

    def _expect(self, kind: str, message: str | None = None) -> Token:
        if not self._at(kind):
            self._error(message or f"Expected {kind!r}, found {self.current.kind!r}")
        return self._advance()

    @contextmanager
    def _nested(self) -> Iterator[None]:
        self.depth += 1
        try:
            if self.depth > _MAX_NESTING:
                self._error(f"Syntax exceeds the bootstrap nesting limit of {_MAX_NESTING}",
                            code="E_PARSE_DEPTH")
            yield
        finally:
            self.depth -= 1

    def parse(self) -> Program:
        name = "main"
        if self._take("module"):
            name = self._expect("IDENT", "Expected a module name").value
            self._expect(";")
        structs: list[Struct] = []
        functions: list[Function] = []
        while not self._at("EOF"):
            if self.current.kind in ("struct", "repr"):
                structs.append(self._struct())
            elif self.current.kind in ("pub", "export", "fn", "extern"):
                functions.append(self._function())
            else:
                self._error("Expected a struct or function declaration")
        self._validate_tree_depth(functions)
        return Program(name, structs, functions, self.source, self.path)

    def _validate_tree_depth(self, functions: list[Function]) -> None:
        # Pratt parsing handles a long left-associative chain iteratively, so
        # parser call depth alone cannot protect recursive downstream passes.
        # Walk the completed syntax tree iteratively before exposing it.
        pending: list[tuple[Stmt | Expr, int]] = [
            (stmt, 1) for fn in functions for stmt in (fn.body or [])
        ]
        while pending:
            node, depth = pending.pop()
            if depth > _MAX_NESTING:
                self._error(f"Syntax tree exceeds the bootstrap nesting limit of {_MAX_NESTING}",
                            Token("", None, node.span), "E_PARSE_DEPTH")
            if isinstance(node, Expr):
                pending.extend((child, depth + 1) for child in node.children)
            else:
                for value in node.data.values():
                    if isinstance(value, Expr):
                        pending.append((value, depth + 1))
                    elif isinstance(value, list):
                        pending.extend((child, depth + 1) for child in value
                                       if isinstance(child, (Stmt, Expr)))

    def _struct(self) -> Struct:
        start = self.current.span
        repr_c = False
        if self._take("repr"):
            self._expect("(")
            representation = self._expect("IDENT", "Expected C in repr(C)")
            if representation.value != "C":
                self._error("Only repr(C) is supported", representation)
            self._expect(")")
            repr_c = True
        self._expect("struct")
        name = self._expect("IDENT", "Expected a struct name").value
        self._expect("{")
        fields: list[Param] = []
        while not self._at("}"):
            field = self._expect("IDENT", "Expected a field name")
            self._expect(":")
            field_type = self._type()
            fields.append(Param(field.value, field_type, span=_cover(field.span, self.previous.span)))
            if not self._take(","):
                break
        end = self._expect("}", "Expected ',' or '}' after a struct field").span
        return Struct(name, fields, repr_c, _cover(start, end))

    def _abi(self) -> None:
        abi = self._expect("STRING", 'Expected the ABI literal "C"')
        if abi.value != "C":
            self._error('Only the ABI literal "C" is supported', abi, "E_PARSE_ABI")

    def _function(self) -> Function:
        start = self.current.span
        public = False
        export_c = False
        extern_c = bool(self._take("extern"))
        if extern_c:
            self._abi()
        else:
            public = bool(self._take("pub"))
            export_c = bool(self._take("export"))
            if export_c:
                self._abi()
        self._expect("fn")
        name = self._expect("IDENT", "Expected a function name").value
        self._expect("(")
        params: list[Param] = []
        while not self._at(")"):
            param = self._expect("IDENT", "Expected a parameter name")
            self._expect(":")
            mode = "value"
            if self.current.kind in ("read", "mut", "take"):
                mode = self._advance().value
            parameter_type = self._type()
            params.append(Param(param.value, parameter_type, mode,
                                _cover(param.span, self.previous.span)))
            if not self._take(","):
                break
        self._expect(")", "Expected ',' or ')' after a parameter")
        self._expect("->", "Functions require an explicit return type after '->'")
        return_type = self._type()
        effects = self._effects()
        resources: dict = {}
        if extern_c:
            end = self._expect(";", "An extern function declaration must end with ';'").span
            body = None
            body_span = Span(end.start, end.start, end.line, end.column, end.path)
        else:
            if self._at("resources"):
                resources = self._resources()
            body, body_span = self._block()
            end = body_span
        return Function(name, params, return_type, effects, body, public, extern_c,
                        export_c, resources, _cover(start, end), body_span)

    def _effects(self) -> set[str]:
        self._expect("effects", "Every function requires an explicit effects clause")
        self._expect("{")
        effects: set[str] = set()
        while not self._at("}"):
            if self.current.kind not in ("IDENT", "unsafe"):
                self._error("Expected an effect name")
            effect = self._advance()
            if effect.value in effects:
                self._error(f"Duplicate effect {effect.value!r}", effect, "E_PARSE_DUPLICATE")
            effects.add(effect.value)
            if not self._take(","):
                break
        self._expect("}", "Expected ',' or '}' after an effect")
        return effects

    def _resources(self) -> dict:
        self._expect("resources")
        self._expect("{")
        resources: dict = {}
        while not self._at("}"):
            key = self._expect("IDENT", "Expected a resource constraint name")
            if key.value in resources:
                self._error(f"Duplicate resource constraint {key.value!r}", key,
                            "E_PARSE_DUPLICATE")
            self._expect("=")
            literal = self.current
            if literal.kind in ("INT", "FLOAT"):
                resources[key.value] = self._advance().value
            elif literal.kind in ("true", "false"):
                resources[key.value] = self._advance().kind == "true"
            else:
                self._error("Resource constraints require an integer, float, or boolean literal")
            self._expect(";", "A resource constraint must end with ';'")
        self._expect("}")
        return resources

    def _type_close(self) -> None:
        # The lexer recognizes >> and >= as operators.  A generic type's
        # closing angle may directly precede another angle or an assignment.
        if self.current.kind in {">>", ">="}:
            span = self.current.span
            second = self.current.kind[1]
            self.tokens[self.position:self.position + 1] = [
                Token(">", ">", Span(span.start, span.start + 1, span.line, span.column, span.path)),
                Token(second, second, Span(span.start + 1, span.end, span.line, span.column + 1, span.path)),
            ]
        self._expect(">", "Expected '>' after a generic element type")

    def _type(self) -> Type:
        with self._nested():
            if self._take("["):
                element = self._type()
                if self._take(";"):
                    length = self._expect("INT", "Array lengths must be nonnegative integer literals").value
                    self._expect("]")
                    return Type("array", (element,), length)
                self._expect("]")
                return Type("slice", (element,))
            if self._take("raw"):
                if self.current.kind not in ("const", "mut"):
                    self._error("A raw pointer type requires 'const' or 'mut'")
                mode = self._advance().value
                return Type("raw_" + mode, (self._type(),))
            name = self._expect("IDENT", "Expected a type name")
            if name.value in {"Buffer", "Task"}:
                self._expect("<", f"{name.value} requires an element type: {name.value}<T>")
                element = self._type()
                self._type_close()
                return Type(name.value, (element,))
            return Type(name.value)

    def _block(self) -> tuple[list[Stmt], Span]:
        with self._nested():
            start = self._expect("{").span
            statements: list[Stmt] = []
            while not self._at("}"):
                if self._at("EOF"):
                    self._error("Unterminated block: expected '}'")
                statements.append(self._statement())
            return statements, _cover(start, self._expect("}").span)

    def _statement(self) -> Stmt:
        start = self.current.span
        if self._take("let"):
            mutable = bool(self._take("mut"))
            name = self._expect("IDENT", "Expected a binding name").value
            binding_type = self._type() if self._take(":") else None
            self._expect("=")
            expr = self._expr()
            end = self._expect(";", "A let statement must end with ';'").span
            return Stmt("let", {"name": name, "type": binding_type,
                                "mutable": mutable, "expr": expr}, _cover(start, end))
        if self._take("return"):
            expr = None if self._at(";") else self._expr()
            end = self._expect(";", "A return statement must end with ';'").span
            return Stmt("return", {"expr": expr}, _cover(start, end))
        if self._take("for"):
            name = self._expect("IDENT", "Expected a loop variable").value
            self._expect("in")
            lower = self._expr(allow_struct=False)
            self._expect("..", "For loops require a half-open start..end range")
            upper = self._expr(allow_struct=False)
            body, end = self._block()
            return Stmt("for", {"name": name, "start": lower, "end": upper,
                                "body": body}, _cover(start, end))
        if self._take("while"):
            condition = self._expr(allow_struct=False)
            body, end = self._block()
            return Stmt("while", {"condition": condition, "body": body}, _cover(start, end))
        if self._take("if"):
            condition = self._expr(allow_struct=False)
            then_body, end = self._block()
            else_body: list[Stmt] = []
            if self._take("else"):
                else_body, end = self._block()
            return Stmt("if", {"condition": condition, "then": then_body,
                               "else": else_body}, _cover(start, end))
        if self._take("unsafe"):
            body, end = self._block()
            return Stmt("unsafe", {"body": body}, _cover(start, end))
        target = self._expr()
        if self._take("="):
            if target.kind not in ("name", "field", "index"):
                self._error("Assignment requires a name, field, or index target",
                            Token("", None, target.span), "E_PARSE_ASSIGNMENT")
            expr = self._expr()
            end = self._expect(";", "An assignment must end with ';'").span
            return Stmt("assign", {"target": target, "expr": expr}, _cover(start, end))
        end = self._expect(";", "An expression statement must end with ';'").span
        return Stmt("expr", {"expr": target}, _cover(start, end))

    def _expr(self, minimum: int = 0, allow_struct: bool = True) -> Expr:
        with self._nested():
            left = self._prefix(allow_struct)
            while True:
                if self._at("("):
                    if left.kind != "name":
                        self._error("Only ordinary named function calls are supported")
                    self._advance()
                    args = self._expressions(")")
                    end = self._expect(")").span
                    left = Expr("call", left.value, args, _cover(left.span, end))
                    continue
                if self._take("["):
                    index = self._expr()
                    end = self._expect("]").span
                    left = Expr("index", children=[left, index], span=_cover(left.span, end))
                    continue
                if self._take("."):
                    field = self._expect("IDENT", "Expected a field name after '.'")
                    left = Expr("field", field.value, [left], _cover(left.span, field.span))
                    continue
                if self._at("as") and _CAST >= minimum:
                    self._advance()
                    target = self._type()
                    left = Expr("cast", target, [left], _cover(left.span, self.previous.span))
                    continue
                operator = self.current.kind
                precedence = _BINARY.get(operator, -1)
                if precedence < minimum:
                    break
                self._advance()
                right = self._expr(precedence + 1, allow_struct)
                left = Expr("binary", operator, [left, right], _cover(left.span, right.span))
            return left

    def _expressions(self, closer: str) -> list[Expr]:
        result: list[Expr] = []
        if self._at(closer):
            return result
        while True:
            result.append(self._expr())
            if not self._take(",") or self._at(closer):
                return result

    def _prefix(self, allow_struct: bool) -> Expr:
        token = self._advance()
        if token.kind == "INT":
            return Expr("int", token.value, span=token.span)
        if token.kind == "FLOAT":
            return Expr("float", token.value, span=token.span)
        if token.kind in ("true", "false"):
            return Expr("bool", token.kind == "true", span=token.span)
        if token.kind in ("-", "!", "read", "mut", "move"):
            operand = self._expr(_UNARY, allow_struct)
            return Expr("unary", token.value, [operand], _cover(token.span, operand.span))
        if token.kind == "IDENT":
            if allow_struct and self._take("{"):
                fields: list[str] = []
                values: list[Expr] = []
                while not self._at("}"):
                    field = self._expect("IDENT", "Expected a struct field name")
                    self._expect(":")
                    fields.append(field.value)
                    values.append(self._expr())
                    if not self._take(","):
                        break
                end = self._expect("}", "Expected ',' or '}' after a field value").span
                return Expr("struct", {"name": token.value, "fields": fields},
                            values, _cover(token.span, end))
            return Expr("name", token.value, span=token.span)
        if token.kind == "(":
            expr = self._expr()
            end = self._expect(")").span
            # Parentheses have no AST node, but their full source extent belongs
            # to this expression for diagnostics and structured replacement.
            expr.span = _cover(token.span, end)
            return expr
        if token.kind == "[":
            values = self._expressions("]")
            end = self._expect("]").span
            return Expr("array", children=values, span=_cover(token.span, end))
        if token.kind == "STRING":
            self._error('Strings are supported only as the ABI literal "C"', token,
                        "E_PARSE_STRING")
        self._error("Expected an expression", token)


def parse(source: str, path: str = "<input>") -> Program:
    """Parse a complete Hepta module or raise a positioned ``HeptaError``."""
    return Parser(source, path).parse()

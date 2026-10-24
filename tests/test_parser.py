"""Boundary and syntax tests for the actual Hepta tokenizer and parser."""
import unittest

from hepta.ast import HeptaError, Type
from hepta.lexer import tokenize
from hepta.parser import parse


def function(body: str, return_type: str = "Unit") -> str:
    return f"fn f() -> {return_type} effects {{}} {{ {body} }}"


class LexerTests(unittest.TestCase):
    def test_comments_are_not_code_and_nest(self):
        tokens = tokenize("// fn evil() {}\n/* outer /* nested */ end */ fn good")
        self.assertEqual([t.kind for t in tokens], ["fn", "IDENT", "EOF"])
        self.assertEqual(tokens[1].value, "good")

    def test_comment_between_tokens_does_not_join_identifiers(self):
        self.assertEqual([t.value for t in tokenize("ab/* x */cd")[:-1]], ["ab", "cd"])

    def test_comment_spans_survive_unicode_and_crlf(self):
        source = "/* π */\r\n  fn f\r\n"
        tokens = tokenize(source, "positions.hepta")
        first = tokens[0].span
        self.assertEqual((first.start, first.end), (source.index("fn"), source.index("fn") + 2))
        self.assertEqual((first.line, first.column, first.path), (2, 3, "positions.hepta"))
        self.assertEqual((tokens[-1].span.line, tokens[-1].span.column), (3, 1))

    def test_cr_only_and_tabs_have_documented_columns(self):
        token = tokenize("\r\tfn")[0]
        self.assertEqual((token.span.line, token.span.column), (2, 2))

    def test_numeric_values_and_range_disambiguation(self):
        tokens = tokenize("0..8 1.5 2e-3 1_024 0xff 0b101 0o17")[:-1]
        self.assertEqual([t.kind for t in tokens],
                         ["INT", "..", "INT", "FLOAT", "FLOAT", "INT", "INT", "INT", "INT"])
        self.assertEqual([t.value for t in tokens], [0, "..", 8, 1.5, .002, 1024, 255, 5, 15])

    def test_longest_operators(self):
        text = "-> <= >= == != && || << >> .. + - * / % & | ^"
        self.assertEqual([t.kind for t in tokenize(text)[:-1]], text.split())

    def test_invalid_characters_are_positioned(self):
        for character in ("#", "@", "`", "'", "$", "π", "\x00", "\u00a0"):
            with self.subTest(character=character), self.assertRaises(HeptaError) as caught:
                tokenize(" \n " + character, "bad.hepta")
            diagnostic = caught.exception.diagnostic
            self.assertEqual((diagnostic.phase, diagnostic.code), ("lex", "E_LEX_CHARACTER"))
            self.assertEqual((diagnostic.span.start, diagnostic.span.end,
                              diagnostic.span.line, diagnostic.span.column), (3, 4, 2, 2))

    def test_malformed_numbers_fail_closed(self):
        for literal in ("0x", "0b102", "0o9", "12u32", "1__2", "1_", "0x_ff",
                        "1e", "1e+", "1e999", "1.0f64", "9" * 5000):
            with self.subTest(literal=literal[:30]), self.assertRaises(HeptaError) as caught:
                tokenize(literal)
            self.assertEqual(caught.exception.diagnostic.code, "E_LEX_NUMBER")

    def test_unterminated_block_comment_has_opening_location(self):
        source = "\n  /* unterminated /* nesting */"
        with self.assertRaises(HeptaError) as caught:
            tokenize(source)
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic.code, "E_LEX_COMMENT")
        self.assertEqual((diagnostic.span.start, diagnostic.span.end,
                          diagnostic.span.line, diagnostic.span.column), (3, len(source), 2, 3))

    def test_strings_are_not_escape_channels(self):
        for source in ('"C\\x00"', '"\\x43"', '"\\n"'):
            with self.subTest(source=source), self.assertRaises(HeptaError) as caught:
                tokenize(source)
            self.assertEqual(caught.exception.diagnostic.code, "E_LEX_STRING_ESCAPE")
        for source in ('"C', '"C\n"', '"C\x00"'):
            with self.subTest(source=source), self.assertRaises(HeptaError) as caught:
                tokenize(source)
            self.assertEqual(caught.exception.diagnostic.code, "E_LEX_STRING")


class ParserTests(unittest.TestCase):
    def assert_rejected(self, source: str, code: str | None = None):
        with self.assertRaises(HeptaError) as caught:
            parse(source, "bad.hepta")
        diagnostic = caught.exception.diagnostic
        if code:
            self.assertEqual(diagnostic.code, code)
        self.assertEqual(diagnostic.span.path, "bad.hepta")
        self.assertGreaterEqual(diagnostic.span.start, 0)
        self.assertLessEqual(diagnostic.span.end, len(source))
        return diagnostic

    def expr(self, source: str):
        return parse(function(f"return {source};", "i64")).functions[0].body[0].data["expr"]

    def test_complete_module_abi_and_resource_shapes(self):
        source = '''module demo;
repr(C) struct Pair { first: i32, second: u64, }
extern "C" fn consume(p: raw const Pair, n: usize) -> i32 effects { ffi, unsafe };
pub export "C" fn answer() -> i32 effects {} resources {
    heap_allocations = 0;
    may_block = false;
    may_suspend = false;
    may_spawn = false;
} { return 42; }
'''
        program = parse(source, "demo.hepta")
        self.assertEqual((program.name, program.path, program.source), ("demo", "demo.hepta", source))
        self.assertTrue(program.structs[0].repr_c)
        self.assertEqual([p.name for p in program.structs[0].fields], ["first", "second"])
        external, exported = program.functions
        self.assertTrue(external.extern_c)
        self.assertIsNone(external.body)
        self.assertEqual(external.effects, {"ffi", "unsafe"})
        self.assertTrue(exported.public and exported.export_c)
        self.assertIs(type(exported.resources["heap_allocations"]), int)
        self.assertIs(type(exported.resources["may_block"]), bool)
        self.assertEqual(exported.body[0].data["expr"].value, 42)

    def test_default_module_and_empty_file(self):
        program = parse("// empty")
        self.assertEqual((program.name, program.structs, program.functions), ("main", [], []))

    def test_types_parameter_modes_and_nested_closing_angles(self):
        source = """fn types(a: read [i32], b: mut [u8; 4], c: take Buffer<Buffer<u8>>,
                              d: raw const raw mut u8, e: bool,) -> Unit effects {} {}"""
        params = parse(source).functions[0].params
        self.assertEqual([p.mode for p in params], ["read", "mut", "take", "value", "value"])
        self.assertEqual(params[0].type, Type("slice", (Type("i32"),)))
        self.assertEqual(params[1].type, Type("array", (Type("u8"),), 4))
        self.assertEqual(str(params[2].type), "Buffer<Buffer<u8>>")
        self.assertEqual(str(params[3].type), "raw const raw mut u8")

    def test_task_generic_type_uses_shared_ast_without_new_expression_syntax(self):
        source = "fn f(t: take Task<Buffer<u8>>) -> Task<i64> effects {spawn} { return spawn(worker); }"
        declaration = parse(source).functions[0]
        self.assertEqual(declaration.params[0].type,
                         Type("Task", (Type("Buffer", (Type("u8"),)),)))
        self.assertEqual(declaration.return_type, Type("Task", (Type("i64"),)))
        call = declaration.body[0].data["expr"]
        self.assertEqual((call.kind, call.value), ("call", "spawn"))
        self.assertEqual((call.children[0].kind, call.children[0].value), ("name", "worker"))
        for annotation in ("Task", "Task<>", "Task<i32, u8>"):
            with self.subTest(annotation=annotation):
                self.assert_rejected(f"fn f(t: {annotation}) -> Unit effects {{}} {{}}")

    def test_generic_closing_angle_can_touch_assignment(self):
        body = "let b:Buffer<u8>=buffer(1); let t:Task<u64>=spawn(worker,move b);"
        bindings = parse(function(body)).functions[0].body
        self.assertEqual(bindings[0].data["type"], Type("Buffer", (Type("u8"),)))
        self.assertEqual(bindings[1].data["type"], Type("Task", (Type("u64"),)))
        self.assertEqual(bindings[1].data["expr"].value, "spawn")
        self.assertEqual(self.expr("x >= y").value, ">=")

    def test_function_and_body_spans_include_full_delimiters(self):
        source = '// lead\n  pub export "C" fn f() -> i32 effects {} {\n return 7;\n}\n// tail'
        fn = parse(source, "span.hepta").functions[0]
        self.assertEqual(source[fn.span.start:fn.span.end],
                         'pub export "C" fn f() -> i32 effects {} {\n return 7;\n}')
        self.assertEqual(source[fn.body_span.start:fn.body_span.end], '{\n return 7;\n}')
        self.assertEqual((fn.span.line, fn.span.column), (2, 3))
        statement = fn.body[0]
        self.assertEqual(source[statement.span.start:statement.span.end], "return 7;")
        expr = statement.data["expr"]
        self.assertEqual((source[expr.span.start:expr.span.end], expr.span.line, expr.span.column),
                         ("7", 3, 9))

    def test_extern_span_includes_semicolon(self):
        source = 'extern "C" fn f() -> Unit effects {ffi};'
        declaration = parse(source).functions[0]
        self.assertEqual(source[declaration.span.start:declaration.span.end], source)
        self.assertEqual(declaration.body_span.start, declaration.body_span.end)

    def test_arithmetic_precedence_and_left_associativity(self):
        expr = self.expr("1 + 2 * 3 - 4 / 2")
        self.assertEqual(expr.value, "-")
        left, right = expr.children
        self.assertEqual((left.value, left.children[1].value, right.value), ("+", "*", "/"))
        subtraction = self.expr("8 - 3 - 1")
        self.assertEqual(subtraction.children[0].value, "-")

    def test_all_binary_precedence_levels(self):
        expr = self.expr("a || b && c | d ^ e & f == g < h << i + j * k")
        for operator in ("||", "&&", "|", "^", "&", "==", "<", "<<", "+", "*"):
            self.assertEqual(expr.value, operator)
            expr = expr.children[1]
        self.assertEqual(expr.value, "k")

    def test_unary_cast_postfix_and_group_spans(self):
        expr = self.expr("-(f(1,)[0].x as i64)")
        self.assertEqual((expr.kind, expr.value), ("unary", "-"))
        cast = expr.children[0]
        self.assertEqual((cast.kind, cast.value), ("cast", Type("i64")))
        field = cast.children[0]
        self.assertEqual((field.kind, field.value), ("field", "x"))
        self.assertEqual(field.children[0].kind, "index")
        self.assertEqual(field.children[0].children[0].kind, "call")
        whole_source = function("return -(f(1,)[0].x as i64);", "i64")
        self.assertEqual(whole_source[cast.span.start:cast.span.end], "(f(1,)[0].x as i64)")

    def test_unary_borrow_and_move_do_not_consume_binary_expression(self):
        expr = self.expr("read xs[0] + 1")
        self.assertEqual(expr.value, "+")
        self.assertEqual((expr.children[0].kind, expr.children[0].value), ("unary", "read"))
        for operator in ("mut", "move", "!"):
            expr = self.expr(f"{operator} x")
            self.assertEqual((expr.kind, expr.value), ("unary", operator))

    def test_arrays_and_struct_literals(self):
        expr = self.expr("Pair { first: [1, 2,], second: Other { flag: true }, }")
        self.assertEqual((expr.kind, expr.value),
                         ("struct", {"name": "Pair", "fields": ["first", "second"]}))
        self.assertEqual(expr.children[0].kind, "array")
        self.assertEqual([e.value for e in expr.children[0].children], [1, 2])
        self.assertEqual(expr.children[1].children[0].value, True)
        self.assertEqual(self.expr("[]").children, [])

    def test_statement_shapes_and_block_boundaries(self):
        body = '''let mut x: i64 = 0;
        let data = [1, 2];
        data[0] = 3;
        pair.value = 4;
        for i in 0..len(read data) { x = wrapping_add(x, i); }
        while x < 10 { x = wrapping_add(x, 1); }
        if ready { print_i64(x); } else { return; }
        unsafe { store(p, 0, 1); }
        return;'''
        statements = parse(function(body)).functions[0].body
        self.assertEqual([s.kind for s in statements],
                         ["let", "let", "assign", "assign", "for", "while", "if", "unsafe", "return"])
        self.assertTrue(statements[0].data["mutable"])
        self.assertEqual(statements[2].data["target"].kind, "index")
        self.assertEqual(statements[3].data["target"].kind, "field")
        self.assertEqual(statements[4].data["name"], "i")
        self.assertEqual(statements[6].data["condition"].value, "ready")
        self.assertEqual(statements[6].data["else"][0].kind, "return")
        self.assertIsNone(statements[-1].data["expr"])

    def test_if_and_while_names_are_not_mistaken_for_structs(self):
        program = parse(function("if ready {} while active {} for i in start..end {}"))
        conditional, loop, range_loop = program.functions[0].body
        self.assertEqual(conditional.data["condition"].kind, "name")
        self.assertEqual(loop.data["condition"].kind, "name")
        self.assertEqual(range_loop.data["end"].value, "end")

    def test_parenthesized_structs_work_in_conditions(self):
        program = parse(function("if (Flag { value: true }).value {}"))
        condition = program.functions[0].body[0].data["condition"]
        self.assertEqual(condition.kind, "field")
        self.assertEqual(condition.children[0].kind, "struct")
        self.assert_rejected(function("if Flag { value: true }.value {}"))

    def test_missing_effects_and_modifiers_fail(self):
        for source in ("fn f() -> Unit {}", "fn f() effects {} {}",
                       'export "C" pub fn f() -> Unit effects {} {}',
                       'pub extern "C" fn f() -> Unit effects {};'):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_duplicate_effects_and_resources_are_not_silently_collapsed(self):
        self.assert_rejected("fn f() -> Unit effects {ffi, ffi} {}", "E_PARSE_DUPLICATE")
        self.assert_rejected("fn f() -> Unit effects {} resources {may_block=false; may_block=true;} {}",
                             "E_PARSE_DUPLICATE")

    def test_abi_is_exact_and_strings_cannot_be_expressions(self):
        self.assert_rejected('extern "Rust" fn f() -> Unit effects {};', "E_PARSE_ABI")
        self.assert_rejected('export "system" fn f() -> Unit effects {} {}', "E_PARSE_ABI")
        self.assert_rejected(function('let x = "C";'), "E_PARSE_STRING")
        self.assert_rejected('fn f() -> Unit effects {} resources {may_block = "false";} {}')

    def test_methods_and_indirect_calls_fail(self):
        for expression in ("x.method(1)", "f()(2)", "xs[0](1)"):
            with self.subTest(expression=expression):
                diagnostic = self.assert_rejected(function(expression + ";"))
                self.assertIn("ordinary named", diagnostic.message)

    def test_invalid_assignment_and_missing_semicolons(self):
        self.assert_rejected(function("1 + 2 = 3;"), "E_PARSE_ASSIGNMENT")
        for body in ("let x = 1", "return 2", "f()", "x = 2"):
            with self.subTest(body=body):
                self.assert_rejected(function(body))

    def test_source_injection_and_unsupported_syntax_fail(self):
        attacks = [
            '#[no_mangle] fn f() -> Unit effects {} {}',
            function('std::process::exit(0);'),
            function('panic!("owned");'),
            function("let x = include_bytes!(evil);"),
            function("let x = |a| a;"),
            function("let x = &mut y;"),
            function("for i in 0..=10 {}"),
            function("let x = [0; 16];"),
            function("x += 1;"),
            function("if true {} else if false {}"),
            'fn f() -> Unit effects {} {} fn injected!() {}',
        ]
        for source in attacks:
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_trailing_tokens_and_unbalanced_blocks_fail(self):
        for source in (function("") + " rubbish", function("") + "}",
                       "fn f() -> Unit effects {} {", "module m; module n;"):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_error_span_points_to_actual_missing_delimiter_location(self):
        source = "fn f() -> Unit effects {} {\n  let x = 1\n}"
        diagnostic = self.assert_rejected(source)
        self.assertEqual((diagnostic.span.start, diagnostic.span.end), (len(source) - 1, len(source)))
        self.assertEqual((diagnostic.span.line, diagnostic.span.column), (3, 1))
        self.assertIn("let statement", diagnostic.message)

    def test_nested_syntax_fails_with_diagnostic_not_recursion_crash(self):
        source = function("return " + "(" * 200 + "1" + ")" * 200 + ";")
        self.assert_rejected(source, "E_PARSE_DEPTH")
        source = "fn f(x: " + "[" * 200 + "u8" + "]" * 200 + ") -> Unit effects {} {}"
        self.assert_rejected(source, "E_PARSE_DEPTH")

    def test_iteratively_parsed_chains_cannot_overflow_downstream_passes(self):
        self.assert_rejected(function("return " + " + ".join(["1"] * 1500) + ";"),
                             "E_PARSE_DEPTH")
        self.assert_rejected(function("return x" + ".field" * 1500 + ";"),
                             "E_PARSE_DEPTH")


if __name__ == "__main__":
    unittest.main()

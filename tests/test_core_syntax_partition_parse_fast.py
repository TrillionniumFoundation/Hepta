"""Independent finite equivalence checks for partition framing dispatch.

The reference below is the unchanged _parse body from frozen66e0b699, with only
the function name changed. These tests do not amend the original46/207/705 gates.
"""
import random
import re
import unittest

from tools import core_syntax_partition_sources as parser
from tools.check_guarded_slice_lean import require

def reference_parse(source):
    """Independent restricted framing parser, preserving full declaration bytes.

    Only validated generator declarations may have continuation lines. Namespace
    wrappers cannot nest. Print commands occur only after all wrappers close.
    """
    raw = source.encode('utf-8')
    require(raw.endswith(b'\n') and b'\r' not in raw, 'partition newlines')
    imports, declarations, prints = [], [], []
    ns = None
    current = None
    printing = False
    for line in raw.splitlines(keepends=True):
        text = line[:-1].decode('utf-8')
        if text.startswith('  '):
            require(current is not None and current[1] == 'theorem' and ns is not None,
                    'split or unsupported declaration continuation')
            current[3] += line
            continue
        current = None
        match = re.fullmatch(r'import ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(not declarations and ns is None and not printing, 'late import')
            imports.append(match[1]); continue
        match = re.fullmatch(r'namespace ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(ns is None and not printing, 'nested or late namespace')
            ns = match[1]; continue
        match = re.fullmatch(r'end ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(ns is not None and ns == match[1], 'namespace close differs')
            ns = None; continue
        match = re.match(r'^(def|theorem) ([A-Za-z][A-Za-z0-9_]*)\b', text)
        if match:
            require(ns is not None and not printing and ' := ' in text, 'declaration framing')
            current = [ns, match[1], match[2], line]
            declarations.append(current); continue
        match = re.fullmatch(r'#print axioms ([A-Za-z][A-Za-z0-9_.]*)', text)
        if match:
            require(ns is None, 'print inside namespace')
            printing = True; prints.append(match[1]); continue
        require(False, 'unsupported partition command')
    require(ns is None and declarations, 'unclosed or empty declaration stream')
    return tuple(imports), tuple(tuple(d) for d in declarations), tuple(prints)


def outcome(function, source):
    try:
        return ("returned", function(source))
    except Exception as error:
        return ("raised", type(error), error.args)


class PartitionParseDispatchTests(unittest.TestCase):
    def same(self, source):
        self.assertEqual(outcome(parser._parse, source), outcome(reference_parse, source))

    def test_import_namespace_and_print_state_machine(self):
        cases = [
            "namespace N\ndef x : Nat := 1\nend N\n",
            "import Init\nnamespace A.B\ndef x : Nat := 1\nend A.B\n#print axioms A.B.x\n",
            "end N\n", "namespace N\ndef x : Nat := 1\nend M\n",
            "namespace N\nnamespace M\ndef x : Nat := 1\nend M\nend N\n",
            "namespace N\nimport Init\ndef x : Nat := 1\nend N\n",
            "namespace N\ndef x : Nat := 1\nend N\nimport Init\n",
            "namespace N\ndef x : Nat := 1\n#print axioms N.x\nend N\n",
            "#print axioms N.x\nnamespace N\ndef x : Nat := 1\nend N\n",
            "def x : Nat := 1\n", "namespace N\ndef x : Nat := 1\n",
        ]
        for source in cases:
            with self.subTest(source=source):
                self.same(source)

    def test_continuation_retains_exact_utf8_bytes(self):
        theorem = "theorem sound : True := by\n  exact True.intro -- µ🙂  \n  -- keep these bytes\n"
        source = "import Init\nnamespace N\ndef value : Nat := 1\n" + theorem + "end N\n#print axioms N.sound\n"
        self.same(source)
        self.assertEqual(parser._parse(source)[1][1][3], theorem.encode("utf-8"))
        for source in (
            "  orphan\n", "namespace N\n  orphan\nend N\n",
            "namespace N\ndef x : Nat := 1\n  bad continuation\nend N\n",
            "namespace N\ntheorem t : True := by\nend N\n  orphan\n",
            "namespace N\ntheorem t : True := by\n  namespace looks_like_a_command\nend N\n",
            "namespace N\ntheorem t : True := by\n  #print axioms N.t\nend N\n",
        ):
            with self.subTest(source=source):
                self.same(source)

    def test_ascii_names_and_unicode_word_boundaries_remain_exact(self):
        names = ["x", "X9", "x_1", "x.", "x'", "xβ", "xé", "x\u0301", "x🙂", "Å", "_x", "1x", "x\u200d"]
        for name in names:
            for kind in ("def", "theorem"):
                source = f"namespace N\n{kind} {name} : Nat := 1\nend N\n"
                with self.subTest(name=name, kind=kind):
                    self.same(source)
            for command in ("import", "namespace", "end", "#print axioms"):
                with self.subTest(name=name, command=command):
                    self.same(command + " " + name + "\nnamespace N\ndef x : Nat := 1\nend N\n")
        # Restricted framing is not a Lean identifier validator. Preserve the
        # existing ASCII-prefix/Unicode-word-boundary behavior, including quirks.
        self.assertEqual(parser._parse("namespace N\ndef x🙂 : Nat := 1\nend N\n")[1][0][2], "x")

    def test_duplicate_commands_and_print_positions_are_not_strengthened(self):
        source = ("import Init\nimport Init\nnamespace Empty\nend Empty\nnamespace N\n"
                  "def x : Nat := 1\nend N\n#print axioms N.x\n#print axioms N.x\n")
        self.same(source)
        imports, declarations, prints = parser._parse(source)
        self.assertEqual(imports, ("Init", "Init"))
        self.assertEqual(prints, ("N.x", "N.x"))
        lines = ["import Init\n", "namespace N\n", "theorem x : True := by\n", "  trivial\n", "end N\n"]
        for at in range(len(lines) + 1):
            for inserted in ("#print axioms N.x\n", "import Init\n", "namespace N\n", "end N\n"):
                with self.subTest(at=at, inserted=inserted):
                    self.same("".join(lines[:at] + [inserted] + lines[at:]))

    def test_newlines_malformed_prefixes_and_non_sources_keep_rejection(self):
        for source in (None, b"", 0, False, "", "\n", "namespace N", "namespace N\r\n",
                       "namespace N\ndef x : Nat := 1\nend N\n\n", "\ud800\n"):
            with self.subTest(source=source):
                self.same(source)
        for line in ("import\tInit", "import  Init", "namespace\tN", "namespace  N",
                     "end\tN", "end  N", "definition x := 1", "def\tx := 1",
                     "theorem\tx := 1", "#print axioms\tN.x", "#print  axioms N.x",
                     " def x := 1", "\tdef x := 1", "-- comment", "",
                     "import Init trailing", "namespace N trailing", "end N trailing",
                     "#print axioms N.x trailing", "def x:Nat:=1", "theorem x"):
            with self.subTest(line=line):
                self.same("namespace N\n" + line + "\nend N\n")
        for control in ("\v", "\f", "\x85", "\u2028", "\u2029", "\x00"):
            self.same("namespace N\ndef x : String := \"" + control + "\"\nend N\n")

    def test_deterministic_mutations_match_value_bytes_or_exact_error(self):
        rng = random.Random(0x66E0)
        base = ["import Init\n", "namespace N\n", "def x : Nat := 1\n",
                "theorem t : True := by\n", "  exact True.intro\n", "end N\n",
                "#print axioms N.t\n"]
        tokens = ["import ", "namespace ", "end ", "def ", "theorem ", "#print axioms ",
                  "  ", " ", "\t", "\r", "\n", "β", "é", "🙂", "_", ".", "\x00"]
        for index in range(1024):
            lines = list(base)
            at = rng.randrange(len(lines))
            operation = index % 4
            if operation == 0:
                text = lines[at]
                pos = rng.randrange(len(text) + 1)
                lines[at] = text[:pos] + rng.choice(tokens) + text[pos:]
            elif operation == 1:
                lines.insert(at, rng.choice(tokens) + rng.choice(("N", "x", "")) + "\n")
            elif operation == 2:
                lines.pop(at)
            else:
                lines.insert(at, lines[at])
            with self.subTest(case=index):
                self.same("".join(lines))


if __name__ == "__main__":
    unittest.main()

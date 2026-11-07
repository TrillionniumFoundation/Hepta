"""Author the checked HIA source for two real bootstrap components.

This file is an authoring aid for the B0 seed, not a parser/generator used by the
native components.  The checked-in .hiaasm file is their executable source.
The components deliberately do not claim to compile their own complete source.
"""
from __future__ import annotations

from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program


def p(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [p(*x) for x in out], "attrs": attrs}


def const(name, typ, value):
    return ins("const", out=[(name, typ)], value=value)


def block(name, params, ops, term):
    return {"id": name, "params": [p(*x) for x in params], "ops": ops, "term": term}


def fn(name, params, returns, effects, blocks):
    return {"name": name, "params": [p(*x) for x in params], "returns": list(returns),
            "effects": list(effects), "entry": blocks[0]["id"], "blocks": blocks}


def ret(*names):
    return {"op": "ret", "values": list(names)}


def jump(target, *args):
    return {"op": "jump", "target": target, "args": list(args)}


def branch(condition, yes, no):
    return {"op": "branch", "cond": condition,
            "then": {"target": yes[0], "args": list(yes[1:])},
            "else": {"target": no[0], "args": list(no[1:])}}


class Ops:
    def __init__(self, prefix):
        self.prefix, self.ops, self.serial = prefix, [], 0

    def add(self, opcode, args=(), typ=None, **attrs):
        if typ is None:
            self.ops.append(ins(opcode, args, **attrs)); return None
        self.serial += 1
        name = self.prefix + "_v" + str(self.serial)
        self.ops.append(ins(opcode, args, [(name, typ)], **attrs)); return name

    def c(self, value, typ="usize"):
        return self.add("const", typ=typ, value=value)

    def cmp(self, mode, a, b):
        return self.add("compare." + mode, [a, b], "bool")

    def both(self, a, b):
        return self.add("bool.and", [a, b], "bool")

    def either(self, a, b):
        return self.add("bool.or", [a, b], "bool")

    def call(self, function, args, types):
        names = []
        for typ in types:
            self.serial += 1; names.append(self.prefix + "_v" + str(self.serial))
        self.ops.append(ins("call", args, list(zip(names, types)), function=function))
        return names


def ascii_predicate(name, ranges=(), singles=()):
    ops = Ops(name)
    result = ops.c(False, "bool")
    for lo, hi in ranges:
        part = ops.both(ops.cmp("ge", "ch", ops.c(lo, "u8")), ops.cmp("le", "ch", ops.c(hi, "u8")))
        result = ops.either(result, part)
    for char in singles:
        result = ops.either(result, ops.cmp("eq", "ch", ops.c(char, "u8")))
    return fn(name, [("ch", "u8")], ["bool"], [], [block("entry", [("ch", "u8")], ops.ops, ret(result))])


def token_scanner():
    blocks = []
    o = Ops("start"); n = o.add("buffer.len", ["source"], "usize")
    valid = o.cmp("le", "offset", n)
    blocks.append(block("entry", [("source", "readbuf"), ("offset", "usize")], o.ops,
                        branch(valid, ("space", "source", "offset", n), ("bad",))))
    o = Ops("space"); more = o.cmp("lt", "sp", "sn")
    blocks.append(block("space", [("ss", "readbuf"), ("sp", "usize"), ("sn", "usize")], o.ops,
                        branch(more, ("classify", "ss", "sp", "sn"), ("eof", "sn"))))
    o = Ops("classify"); ch = o.add("buffer.load", ["cs", "cp"], "u8")
    white, = o.call("ascii_space", [ch], ["bool"])
    nextp = o.add("int.add.wrap", ["cp", o.c(1)], "usize")
    blocks.append(block("classify", [("cs", "readbuf"), ("cp", "usize"), ("cn", "usize")], o.ops,
                        branch(white, ("space", "cs", nextp, "cn"), ("name_test", "cs", "cp", "cn", ch, nextp))))
    o = Ops("name_test"); yes, = o.call("ascii_name_first", ["nc"], ["bool"])
    params = [("ns", "readbuf"), ("np", "usize"), ("nn", "usize"), ("nc", "u8"), ("nx", "usize")]
    blocks.append(block("name_test", params, o.ops,
                        branch(yes, ("name", "ns", "np", "nx", "nn"), ("digit_test", "ns", "np", "nn", "nc", "nx"))))
    o = Ops("digit_test"); yes, = o.call("ascii_digit", ["dc"], ["bool"])
    params = [("ds", "readbuf"), ("dp", "usize"), ("dn", "usize"), ("dc", "u8"), ("dx", "usize")]
    blocks.append(block("digit_test", params, o.ops,
                        branch(yes, ("digit", "ds", "dp", "dx", "dn"), ("quote_test", "ds", "dp", "dn", "dc", "dx"))))
    o = Ops("quote_test"); yes = o.cmp("eq", "qc", o.c(34, "u8"))
    params = [("qs", "readbuf"), ("qp", "usize"), ("qn", "usize"), ("qc", "u8"), ("qx", "usize")]
    blocks.append(block("quote_test", params, o.ops,
                        branch(yes, ("string", "qs", "qp", "qx", "qn"), ("punct", "qp", "qc", "qx"))))
    o = Ops("punct"); yes, = o.call("ascii_punct", ["pc"], ["bool"])
    ch32 = o.add("int.cast", ["pc"], "u32", mode="wrap")
    kind = o.add("int.add.wrap", [ch32, o.c(128, "u32")], "u32")
    blocks.append(block("punct", [("pp", "usize"), ("pc", "u8"), ("px", "usize")], o.ops,
                        branch(yes, ("token", kind, "pp", "px"), ("bad",))))
    for label, predicate, kind in (("name", "ascii_name_continue", 1), ("digit", "ascii_digit", 2)):
        names = [label + k for k in ("s", "a", "p", "n")]
        s, a, pos, n = names
        o = Ops(label); more = o.cmp("lt", pos, n); k = o.c(kind, "u32")
        blocks.append(block(label, list(zip(names, ("readbuf", "usize", "usize", "usize"))), o.ops,
                            branch(more, (label + "_read", *names), ("token", k, a, pos))))
        names2 = [label + "r" + k for k in ("s", "a", "p", "n")]; s, a, pos, n = names2
        o = Ops(label + "r"); ch = o.add("buffer.load", [s, pos], "u8")
        yes, = o.call(predicate, [ch], ["bool"]); nextp = o.add("int.add.wrap", [pos, o.c(1)], "usize"); k = o.c(kind, "u32")
        blocks.append(block(label + "_read", list(zip(names2, ("readbuf", "usize", "usize", "usize"))), o.ops,
                            branch(yes, (label, s, a, nextp, n), ("token", k, a, pos))))
    o = Ops("string"); more = o.cmp("lt", "tp", "tn")
    blocks.append(block("string", [("ts", "readbuf"), ("ta", "usize"), ("tp", "usize"), ("tn", "usize")], o.ops,
                        branch(more, ("string_read", "ts", "ta", "tp", "tn"), ("bad",))))
    o = Ops("string_read"); ch = o.add("buffer.load", ["trs", "trp"], "u8")
    quote = o.cmp("eq", ch, o.c(34, "u8")); nextp = o.add("int.add.wrap", ["trp", o.c(1)], "usize"); k = o.c(3, "u32")
    blocks.append(block("string_read", [("trs", "readbuf"), ("tra", "usize"), ("trp", "usize"), ("trn", "usize")], o.ops,
                        branch(quote, ("token", k, "tra", nextp), ("string_escape_test", "trs", "tra", nextp, "trn", ch))))
    o = Ops("string_escape_test"); escape = o.cmp("eq", "ec", o.c(92, "u8"))
    blocks.append(block("string_escape_test", [("es", "readbuf"), ("ea", "usize"), ("ep", "usize"), ("en", "usize"), ("ec", "u8")], o.ops,
                        branch(escape, ("escape", "es", "ea", "ep", "en"), ("string_plain", "es", "ea", "ep", "en", "ec"))))
    o = Ops("string_plain"); good = o.both(o.cmp("ge", "uc", o.c(32, "u8")), o.cmp("le", "uc", o.c(126, "u8")))
    blocks.append(block("string_plain", [("us", "readbuf"), ("ua", "usize"), ("up", "usize"), ("un", "usize"), ("uc", "u8")], o.ops,
                        branch(good, ("string", "us", "ua", "up", "un"), ("bad",))))
    o = Ops("escape"); more = o.cmp("lt", "xp", "xn")
    blocks.append(block("escape", [("xs", "readbuf"), ("xa", "usize"), ("xp", "usize"), ("xn", "usize")], o.ops,
                        branch(more, ("escape_read", "xs", "xa", "xp", "xn"), ("bad",))))
    o = Ops("escape_read"); ch = o.add("buffer.load", ["xrs", "xrp"], "u8")
    yes, = o.call("ascii_escape", [ch], ["bool"]); nextp = o.add("int.add.wrap", ["xrp", o.c(1)], "usize")
    blocks.append(block("escape_read", [("xrs", "readbuf"), ("xra", "usize"), ("xrp", "usize"), ("xrn", "usize")], o.ops,
                        branch(yes, ("string", "xrs", "xra", nextp, "xrn"), ("bad",))))
    blocks += [block("token", [("kind", "u32"), ("begin", "usize"), ("end", "usize")], [], ret("kind", "begin", "end")),
               block("eof", [("length", "usize")], [const("eof_kind", "u32", 0)], ret("eof_kind", "length", "length")),
               block("bad", [], [const("invalid", "u32", 255), const("bad_at", "usize", 0)], ret("invalid", "bad_at", "bad_at"))]
    return fn("next_token", [("source", "readbuf"), ("offset", "usize")], ["u32", "usize", "usize"], ["read", "trap"], blocks)


def byte_writer(bits):
    name = "write_u" + str(bits); o = Ops(name)
    for j in range(bits // 8):
        value = "value" if j == 0 else o.add("int.shr.checked", ["value", o.c(j * 8, "u" + str(bits))], "u" + str(bits))
        byte = o.add("int.cast", [value], "u8", mode="wrap")
        offset = "offset" if j == 0 else o.add("int.add.wrap", ["offset", o.c(j)], "usize")
        o.add("buffer.store", ["target", offset, byte])
    params = [("target", "mutbuf"), ("offset", "usize"), ("value", "u" + str(bits))]
    return fn(name, params, [], ["write", "trap"], [block("entry", params, o.ops, ret())])


def token_count():
    o = Ops("begin"); zero = o.c(0); count = o.c(0, "u32")
    blocks = [block("entry", [("source", "readbuf")], o.ops, jump("loop", "source", zero, count))]
    o = Ops("count"); kind, start, end = o.call("next_token", ["ls", "lp"], ["u32", "usize", "usize"])
    eof = o.cmp("eq", kind, o.c(0, "u32"))
    blocks.append(block("loop", [("ls", "readbuf"), ("lp", "usize"), ("lc", "u32")], o.ops,
                        branch(eof, ("done", "lc"), ("check", "ls", end, "lc", kind))))
    o = Ops("check"); bad = o.cmp("eq", "ck", o.c(255, "u32")); nextc = o.add("int.add.wrap", ["cc", o.c(1, "u32")], "u32")
    blocks.append(block("check", [("cs", "readbuf"), ("cp", "usize"), ("cc", "u32"), ("ck", "u32")], o.ops,
                        branch(bad, ("bad",), ("loop", "cs", "cp", nextc))))
    blocks += [block("done", [("total", "u32")], [], ret("total")),
               block("bad", [], [const("error", "u32", 0xffffffff)], ret("error"))]
    return fn("count_tokens", [("source", "readbuf")], ["u32"], ["read", "trap"], blocks)


def lexer():
    params = [("source", "readbuf"), ("target", "mutbuf")]
    o = Ops("begin"); count, = o.call("count_tokens", ["source"], ["u32"])
    bad = o.cmp("eq", count, o.c(0xffffffff, "u32"))
    blocks = [block("entry", params, o.ops, branch(bad, ("invalid",), ("capacity", "source", "target", count)))]
    o = Ops("capacity"); countw = o.add("int.cast", ["cc"], "usize", mode="wrap")
    need = o.add("int.mul.wrap", [countw, o.c(12)], "usize"); size = o.add("buffer.len", ["ct"], "usize")
    fits = o.cmp("le", need, size); zero = o.c(0); zi = o.c(0, "u32")
    blocks.append(block("capacity", [("cs", "readbuf"), ("ct", "mutbuf"), ("cc", "u32")], o.ops,
                        branch(fits, ("loop", "cs", "ct", zero, zi, "cc"), ("short",))))
    o = Ops("loop"); more = o.cmp("lt", "li", "lc")
    loop_params = [("ls", "readbuf"), ("lt", "mutbuf"), ("lp", "usize"), ("li", "u32"), ("lc", "u32")]
    blocks.append(block("loop", loop_params, o.ops,
                        branch(more, ("write", "ls", "lt", "lp", "li", "lc"), ("done", "lc"))))
    o = Ops("write"); kind, start, end = o.call("next_token", ["ws", "wp"], ["u32", "usize", "usize"])
    iwide = o.add("int.cast", ["wi"], "usize", mode="wrap"); offset = o.add("int.mul.wrap", [iwide, o.c(12)], "usize")
    for j, value in enumerate((kind, o.add("int.cast", [start], "u32", mode="wrap"), o.add("int.cast", [end], "u32", mode="wrap"))):
        at = offset if j == 0 else o.add("int.add.wrap", [offset, o.c(4 * j)], "usize")
        o.call("write_u32", ["wt", at, value], [])
    nexti = o.add("int.add.wrap", ["wi", o.c(1, "u32")], "u32")
    write_params = [("ws", "readbuf"), ("wt", "mutbuf"), ("wp", "usize"), ("wi", "u32"), ("wc", "u32")]
    blocks.append(block("write", write_params, o.ops, jump("loop", "ws", "wt", end, nexti, "wc")))
    blocks += [block("done", [("count", "u32")], [], ret("count")),
               block("invalid", [], [const("syntax_error", "u32", 0xffffffff)], ret("syntax_error")),
               block("short", [], [const("space_error", "u32", 0xfffffffe)], ret("space_error"))]
    return fn("lex_assembly", params, ["u32"], ["read", "write", "trap"], blocks)


def match_word(index, word):
    name = "word_" + str(index); params = [("source", "readbuf"), ("begin", "usize"), ("end", "usize")]
    o = Ops("len"); length = o.add("int.sub.wrap", ["end", "begin"], "usize"); size = o.c(len(word))
    equal = o.cmp("eq", length, size)
    blocks = [block("entry", params, o.ops, branch(equal, ("check", "source", "begin"), ("false",)))]
    o = Ops("word"); result = o.c(True, "bool")
    for j, char in enumerate(word.encode("ascii")):
        at = "start" if j == 0 else o.add("int.add.wrap", ["start", o.c(j)], "usize")
        byte = o.add("buffer.load", ["s", at], "u8")
        result = o.both(result, o.cmp("eq", byte, o.c(char, "u8")))
    blocks += [block("check", [("s", "readbuf"), ("start", "usize")], o.ops, ret(result)),
               block("false", [], [const("no", "bool", False)], ret("no"))]
    return fn(name, params, ["bool"], ["read", "trap"], blocks)


def identifier_check():
    params = [("source", "readbuf"), ("start", "usize"), ("end", "usize")]
    o = Ops("begin"); size = o.add("int.sub.wrap", ["end", "start"], "usize")
    has = o.both(o.cmp("lt", "start", "end"), o.cmp("le", size, o.c(128)))
    blocks = [block("entry", params, o.ops, branch(has, ("first", "source", "start", "end"), ("false",)))]
    o = Ops("first"); ch = o.add("buffer.load", ["fs", "fp"], "u8"); yes, = o.call("ascii_name_first", [ch], ["bool"])
    nextp = o.add("int.add.wrap", ["fp", o.c(1)], "usize")
    blocks.append(block("first", [("fs", "readbuf"), ("fp", "usize"), ("fe", "usize")], o.ops,
                        branch(yes, ("loop", "fs", nextp, "fe"), ("false",))))
    o = Ops("loop"); more = o.cmp("lt", "lp", "le")
    blocks.append(block("loop", [("ls", "readbuf"), ("lp", "usize"), ("le", "usize")], o.ops,
                        branch(more, ("check", "ls", "lp", "le"), ("true",))))
    o = Ops("check"); ch = o.add("buffer.load", ["cs", "cp"], "u8"); yes, = o.call("ascii_ident_continue", [ch], ["bool"])
    nextp = o.add("int.add.wrap", ["cp", o.c(1)], "usize")
    blocks.append(block("check", [("cs", "readbuf"), ("cp", "usize"), ("ce", "usize")], o.ops,
                        branch(yes, ("loop", "cs", nextp, "ce"), ("false",))))
    blocks += [block("true", [], [const("yes", "bool", True)], ret("yes")), block("false", [], [const("no", "bool", False)], ret("no"))]
    return fn("simple_identifier", params, ["bool"], ["read", "trap"], blocks)


def span_equal():
    params = [("source", "readbuf"), ("a", "usize"), ("ae", "usize"), ("z", "usize"), ("ze", "usize")]
    o = Ops("begin"); al = o.add("int.sub.wrap", ["ae", "a"], "usize"); zl = o.add("int.sub.wrap", ["ze", "z"], "usize")
    eq = o.cmp("eq", al, zl); zero = o.c(0)
    blocks = [block("entry", params, o.ops, branch(eq, ("loop", "source", "a", "z", al, zero), ("false",)))]
    params = [("ls", "readbuf"), ("la", "usize"), ("lz", "usize"), ("ln", "usize"), ("li", "usize")]
    o = Ops("loop"); more = o.cmp("lt", "li", "ln")
    blocks.append(block("loop", params, o.ops, branch(more, ("compare", "ls", "la", "lz", "ln", "li"), ("true",))))
    params = [("cs", "readbuf"), ("ca", "usize"), ("cz", "usize"), ("cn", "usize"), ("ci", "usize")]
    o = Ops("compare"); ap = o.add("int.add.wrap", ["ca", "ci"], "usize"); zp = o.add("int.add.wrap", ["cz", "ci"], "usize")
    av = o.add("buffer.load", ["cs", ap], "u8"); zv = o.add("buffer.load", ["cs", zp], "u8"); equal = o.cmp("eq", av, zv)
    nexti = o.add("int.add.wrap", ["ci", o.c(1)], "usize")
    blocks.append(block("compare", params, o.ops, branch(equal, ("loop", "cs", "ca", "cz", "cn", nexti), ("false",))))
    blocks += [block("true", [], [const("yes", "bool", True)], ret("yes")), block("false", [], [const("no", "bool", False)], ret("no"))]
    return fn("span_equal", [("source", "readbuf"), ("a", "usize"), ("ae", "usize"), ("z", "usize"), ("ze", "usize")], ["bool"], ["read", "trap"], blocks)


def gap_lines():
    """Count LF in lexer-skipped whitespace; CR is outside canonical subset."""
    params = [("source", "readbuf"), ("begin", "usize"), ("end", "usize")]
    o = Ops("start"); zero = o.c(0, "u32")
    blocks = [block("entry", params, o.ops, jump("loop", "source", "begin", "end", zero))]
    o = Ops("loop"); more = o.cmp("lt", "lp", "le")
    blocks.append(block("loop", [("ls", "readbuf"), ("lp", "usize"), ("le", "usize"), ("lc", "u32")], o.ops,
                        branch(more, ("read", "ls", "lp", "le", "lc"), ("done", "lc"))))
    o = Ops("read"); ch = o.add("buffer.load", ["rs", "rp"], "u8")
    cr = o.cmp("eq", ch, o.c(13, "u8")); lf = o.cmp("eq", ch, o.c(10, "u8"))
    delta = o.add("select", [lf, o.c(1, "u32"), o.c(0, "u32")], "u32")
    count = o.add("int.add.wrap", ["rc", delta], "u32"); nextp = o.add("int.add.wrap", ["rp", o.c(1)], "usize")
    blocks.append(block("read", [("rs", "readbuf"), ("rp", "usize"), ("re", "usize"), ("rc", "u32")], o.ops,
                        branch(cr, ("bad",), ("loop", "rs", nextp, "re", count))))
    blocks += [block("done", [("count", "u32")], [], ret("count")),
               block("bad", [], [const("error", "u32", 0xffffffff)], ret("error"))]
    return fn("gap_lines", params, ["u32"], ["read", "trap"], blocks)


def unsigned_decimal():
    params = [("source", "readbuf"), ("begin", "usize"), ("end", "usize")]
    o = Ops("start"); size = o.add("int.sub.wrap", ["end", "begin"], "usize"); nonempty = o.cmp("gt", size, o.c(0))
    blocks = [block("entry", params, o.ops, branch(nonempty, ("leading", "source", "begin", "end", size), ("bad",)))]
    o = Ops("leading"); ch = o.add("buffer.load", ["ss", "sa"], "u8")
    multiple = o.cmp("gt", "sn", o.c(1)); zerochar = o.cmp("eq", ch, o.c(48, "u8")); bad = o.both(multiple, zerochar)
    zero = o.c(0, "u64")
    blocks.append(block("leading", [("ss", "readbuf"), ("sa", "usize"), ("se", "usize"), ("sn", "usize")], o.ops,
                        branch(bad, ("bad",), ("loop", "ss", "sa", "se", zero))))
    o = Ops("loop"); more = o.cmp("lt", "lp", "le")
    blocks.append(block("loop", [("ls", "readbuf"), ("lp", "usize"), ("le", "usize"), ("lv", "u64")], o.ops,
                        branch(more, ("digit", "ls", "lp", "le", "lv"), ("done", "lv"))))
    o = Ops("digit"); ch = o.add("buffer.load", ["ds", "dp"], "u8"); isdigit, = o.call("ascii_digit", [ch], ["bool"])
    digit8 = o.add("int.sub.wrap", [ch, o.c(48, "u8")], "u8"); digit = o.add("int.cast", [digit8], "u64", mode="wrap")
    less = o.cmp("lt", "dv", o.c(1844674407370955161, "u64")); equal = o.cmp("eq", "dv", o.c(1844674407370955161, "u64"))
    small = o.cmp("le", digit, o.c(5, "u64")); allowed = o.both(isdigit, o.either(less, o.both(equal, small)))
    value = o.add("int.add.wrap", [o.add("int.mul.wrap", ["dv", o.c(10, "u64")], "u64"), digit], "u64")
    nextp = o.add("int.add.wrap", ["dp", o.c(1)], "usize")
    blocks.append(block("digit", [("ds", "readbuf"), ("dp", "usize"), ("de", "usize"), ("dv", "u64")], o.ops,
                        branch(allowed, ("loop", "ds", nextp, "de", value), ("bad",))))
    blocks += [block("done", [("answer", "u64")], [const("good", "bool", True)], ret("good", "answer")),
               block("bad", [], [const("no", "bool", False), const("zero", "u64", 0)], ret("no", "zero"))]
    return fn("unsigned_decimal", params, ["bool", "u64"], ["read", "trap"], blocks)


def constant_compiler(words):
    # Tuple: token kind, literal or identifier capture/match, LF count before.
    sequence = [
        (1, "hia", 0), (173, None, 0), (1, "asm.v1", 0), (1, "hepta.hia.program.v8", 0), (1, "+module", 0),
        (1, "exports", 1), (168, None, 0), (1, "+export", 0), (169, None, 0),
        (1, "fn", 1), (1, "=export", 0), (168, None, 0), (169, None, 0), (173, None, 0), (190, None, 0),
        (168, None, 0), (1, "u64", 0), (169, None, 0), (1, "effects", 0), (168, None, 0), (169, None, 0),
        (1, "entry", 0), (168, None, 0), (1, "+block", 0), (169, None, 0),
        (1, "block", 1), (1, "=block", 0), (168, None, 0), (169, None, 0),
        (1, "+value", 1), (186, None, 0), (1, "u64", 0), (189, None, 0), (1, "const", 0), (168, None, 0),
        (169, None, 0), (251, None, 0), (3, '"value"', 0), (186, None, 0), (2, "number", 0), (253, None, 0),
        (1, "ret", 1), (168, None, 0), (1, "=value", 0), (169, None, 0), (1, "end", 1), (0, None, -1),
    ]
    initial = [("source", "readbuf"), ("target", "mutbuf")]
    blocks = [block("entry", initial, [const("zero", "usize", 0)], jump("step0", "source", "target", "zero"))]
    fields = {"s": "readbuf", "d": "mutbuf", "at": "usize"}
    for number, (kind, value, newlines) in enumerate(sequence):
        prefix = "step" + str(number); names = {key: prefix + "_" + key for key in fields}
        params = [(names[key], typ) for key, typ in fields.items()]
        o = Ops(prefix); tk, a, z = o.call("next_token", [names["s"], names["at"]], ["u32", "usize", "usize"])
        ok = o.cmp("eq", tk, o.c(kind, "u32"))
        gap, = o.call("gap_lines", [names["s"], names["at"], a], ["u32"])
        line_ok = o.cmp("le" if newlines == -1 else "eq", gap, o.c(1 if newlines == -1 else newlines, "u32"))
        ok = o.both(ok, line_ok)
        # These spellings are adjacent in the existing line-based hia-asm.v1
        # grammar.  Tokenization alone must not admit e.g. "hia - asm.v1",
        # "- >", "const ()" or "ret (value)" as an alternate language.
        if number in {1, 2, 6, 11, 14, 19, 22, 27, 34, 42}:
            ok = o.both(ok, o.cmp("eq", a, names["at"]))
        if number == 36:  # Attributes require whitespace after const().
            ok = o.both(ok, o.cmp("gt", a, names["at"]))
        updated = dict(names); updated["at"] = z
        if value and value[0] in "+=":
            valid, = o.call("simple_identifier", [names["s"], a, z], ["bool"]); ok = o.both(ok, valid)
            key = value[1:]
            if value[0] == "+":
                if key != "module":
                    updated[key + "a"], updated[key + "z"] = a, z
            else:
                eq, = o.call("span_equal", [names["s"], names[key + "a"], names[key + "z"], a, z], ["bool"])
                ok = o.both(ok, eq)
        elif value == "number":
            valid, literal = o.call("unsigned_decimal", [names["s"], a, z], ["bool", "u64"])
            ok = o.both(ok, valid); updated["literal"] = literal
        elif value:
            eq, = o.call("word_" + str(words.index(value)), [names["s"], a, z], ["bool"])
            ok = o.both(ok, eq)
        nextfields = {key: fields.get(key, "u64" if key == "literal" else "usize") for key in updated}
        destination = "capacity" if number == len(sequence) - 1 else "step" + str(number + 1)
        args = [updated[key] for key in nextfields] if destination != "capacity" else [names["d"], updated["literal"]]
        blocks.append(block(prefix, params, o.ops, branch(ok, (destination, *args), ("invalid",))))
        fields = nextfields
    o = Ops("capacity"); size = o.add("buffer.len", ["output"], "usize"); fits = o.cmp("ge", size, o.c(11))
    blocks.append(block("capacity", [("output", "mutbuf"), ("literal", "u64")], o.ops,
                        branch(fits, ("emit", "output", "literal"), ("short",))))
    o = Ops("emit")
    for offset, byte in ((0, 0x48), (1, 0xb8), (10, 0xc3)):
        o.add("buffer.store", ["out", o.c(offset), o.c(byte, "u8")])
    o.call("write_u64", ["out", o.c(2), "number"], [])
    size = o.c(11, "u32")
    blocks.append(block("emit", [("out", "mutbuf"), ("number", "u64")], o.ops, ret(size)))
    blocks += [block("invalid", [], [const("invalid_source", "u32", 0xffffffff)], ret("invalid_source")),
               block("short", [], [const("capacity_error", "u32", 0xfffffffe)], ret("capacity_error"))]
    return fn("compile_constant", initial, ["u32"], ["read", "write", "trap"], blocks)


def component_document():
    words = ["hia", "asm.v1", "hepta.hia.program.v8", "exports", "fn", "u64", "effects", "entry", "block", "const", '"value"', "ret", "end"]
    functions = [
        ascii_predicate("ascii_space", singles=(9, 10, 13, 32)),
        ascii_predicate("ascii_name_first", ranges=((65, 90), (97, 122)), singles=(95,)),
        ascii_predicate("ascii_name_continue", ranges=((65, 90), (97, 122), (48, 57)), singles=(95, 46)),
        ascii_predicate("ascii_ident_continue", ranges=((65, 90), (97, 122), (48, 57)), singles=(95,)),
        ascii_predicate("ascii_digit", ranges=((48, 57),)),
        ascii_predicate("ascii_punct", singles=tuple(map(ord, "(){}[],:=->"))),
        ascii_predicate("ascii_escape", singles=tuple(map(ord, '\\"/bfnrt'))),
        token_scanner(), byte_writer(32), byte_writer(64), token_count(), lexer(),
        identifier_check(), span_equal(), gap_lines(), unsigned_decimal(),
        *[match_word(index, word) for index, word in enumerate(words)], constant_compiler(words),
    ]
    return {"schema": "hepta.hia.program.v8", "module": "bootstrap_components", "functions": functions}


def main():
    program = verify_program(component_document())
    source = render_assembly(program)
    output = Path(__file__).resolve().parents[1] / "examples" / "hia_bootstrap" / "components.hiaasm"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(source, encoding="utf-8")
    print(f"{len(source.encode())} source bytes; {len(program.as_dict()['functions'])} HIA functions")


if __name__ == "__main__":
    main()

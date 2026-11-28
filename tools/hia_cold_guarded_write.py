"""Guard complete native controller stores without changing short-view effects.

Only explicitly selected cold authors use these transforms. Every invalid span
executes the complete original byte-store helper. The fixed syscall frame keeps
its original write order, including when its two writable views overlap.
"""
import ast
from hashlib import sha256

from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_cold_document import document as _document, bulk_word_document as _bulk_word_document

PUT_SHA256 = frozenset((
    "08d77969966025f4954c8fa0f24ebb10b6c04aa2f41cb9ec585718ac9b931ce3",
    "ebe6d797aecf1c2de8186c01f66a22e3900d628c3eaeec75d770e12ea6137656",
    "25755dfc7f0d0476934c4b78366bf6da862f350e54d474c168047b090aeae852",
))
_ORIGINAL_CALL = """def call(o:mutbuf, w:mutbuf, phase:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, mask:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, mask)
    return 1"""


def guarded_controller_stores(source):
    nodes = ast.parse(source).body
    selected = {}
    for name in ("put", "call"):
        matches = [n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name]
        if len(matches) != 1:
            raise ValueError("guarded controller stores require one original " + name)
        selected[name] = ast.get_source_segment(source, matches[0])
    original = selected["put"]
    if sha256(original.encode()).hexdigest() not in PUT_SHA256:
        raise ValueError("original cold put helper changed or was already guarded")
    if ast.dump(ast.parse(selected["call"])) != ast.dump(ast.parse(_ORIGINAL_CALL)):
        raise ValueError("original fixed syscall-frame helper changed or was already guarded")
    lines = original.splitlines()
    guard = ("    if at <= length(w) and 8 <= length(w) - at:\n"
             "        word_store(w, at, value)\n"
             "        return 0\n")
    put = lines[0] + "\n" + guard + "\n".join(lines[1:])
    original = selected["call"]
    lines = original.splitlines()
    # All scalar arguments are already captured function parameters. Keeping
    # the nine stores in order preserves even overlapping foreign ABI views.
    fast = "\n".join("    " + line.replace("put(", "word_store(", 1)
                     for line in lines[1:])
    call = (lines[0] + "\n"
            "    if length(w) >= 8 and length(o) >= 64:\n" +
            fast + "\n" + "\n".join(lines[1:]))
    return source.replace(selected["put"], put, 1).replace(selected["call"], call, 1)


class GuardedWordBuilder(LinkerBuilder):
    def expr(self, value):
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == "word_store"):
            args = [self.expr(item) for item in value.args]
            if len(args) != 3 or args[0][1] != "mutbuf":
                raise ValueError("guarded word store requires one writable view and two scalars")
            return self.op("buffer.store.u64.le", [
                args[0], self.cast(args[1], "usize"), self.cast(args[2], "u64")])
        return super().expr(value)


def document(source, module="cold_allocator_witness"):
    return _document(guarded_controller_stores(source), module, builder_type=GuardedWordBuilder)


def bulk_document(source, module):
    return _bulk_word_document(guarded_controller_stores(source), module)

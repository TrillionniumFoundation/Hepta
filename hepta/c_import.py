"""Conservative native C-header import with real GCC type/layout probes.

This is a documented C subset parser, not a replacement for Clang. Unsupported
constructs are errors; they are never silently dropped or assigned guessed ABIs.
Header facts and caller-supplied semantic contracts remain separate in reports.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import platform
import struct
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .ast import Diagnostic, HeptaError, Type
from .checker import EFFECTS, check
from .parser import parse

PRIMITIVES = ["char", "signed char", "unsigned char", "short", "unsigned short", "int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long", "float", "double", "size_t", "ptrdiff_t", "intptr_t", "uintptr_t", "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t"]
WORDS = {"void", "char", "signed", "unsigned", "short", "int", "long", "float", "double"}
MACRO_TYPES = ["char", "signed char", "unsigned char", "short", "unsigned short", "int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long"]


def reject(code, message):
    raise HeptaError(Diagnostic("E_C_IMPORT_" + code, message, phase="c_import"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


@dataclass
class ImportResult:
    source: str
    manifest: dict


def tokens(text):
    pattern = re.compile(r"\s+|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[{}();,*\[\]]")
    result, position = [], 0
    for match in pattern.finditer(text):
        if match.start() != position:
            reject("SYNTAX", f"Unsupported C token near {text[position:position+40]!r}; attributes, bitfields, varargs and function pointers are not supported")
        position = match.end()
        if not match.group().isspace():
            result.append(match.group())
    if position != len(text):
        reject("SYNTAX", f"Unsupported C text near {text[position:position+40]!r}")
    return result


def split_top(items, delimiter):
    chunks, chunk, depth = [], [], 0
    for item in items:
        if item in {"{", "(", "["}:
            depth += 1
        elif item in {"}", ")", "]"}:
            depth -= 1
            if depth < 0:
                reject("SYNTAX", "Unbalanced C delimiters")
        if item == delimiter and depth == 0:
            chunks.append(chunk)
            chunk = []
        else:
            chunk.append(item)
    if depth:
        reject("SYNTAX", "Unbalanced C delimiters")
    if chunk:
        chunks.append(chunk)
    return chunks


def preprocess_subset(text):
    text = re.sub(r"/\*.*?\*/|//[^\n]*", " ", text, flags=re.S)
    declarations, macros, guard = [], {}, None
    guard_open = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            declarations.append(line)
            continue
        if re.fullmatch(r"#\s*pragma\s+once", stripped):
            continue
        include = re.fullmatch(r"#\s*include\s*<([^>]+)>", stripped)
        if include:
            if include.group(1) not in {"stdint.h", "stddef.h", "limits.h"}:
                reject("INCLUDE", "Only stdint.h, stddef.h and limits.h includes are supported; flatten or simplify other headers explicitly")
            continue
        opening = re.fullmatch(r"#\s*ifndef\s+([A-Za-z_]\w*)", stripped)
        if opening and guard is None and not any(x.strip() for x in declarations):
            guard, guard_open = opening.group(1), True
            continue
        if re.fullmatch(r"#\s*endif", stripped) and guard_open:
            guard_open = False
            continue
        define = re.fullmatch(r"#\s*define\s+([A-Za-z_]\w*)(.*)", stripped)
        if define:
            name, rest = define.groups()
            if name == guard and not rest.strip():
                continue
            if rest.startswith("("):
                reject("MACRO", f"Function-like macro {name} is unsupported")
            value = rest.strip()
            if not value or "\\" in value or any(x in value for x in ['"', "'", "?", ":", "=", ".", "{"]):
                reject("MACRO", f"Macro {name} is not a supported integer constant expression")
            if not re.fullmatch(r"[A-Za-z_0-9\s()+\-*/%<>&|^~]+", value):
                reject("MACRO", f"Unsupported expression in macro {name}")
            if name in macros:
                reject("MACRO", f"Macro {name} is redefined")
            macros[name] = value
            continue
        reject("PREPROCESSOR", f"Unsupported directive: {stripped}; conditional configuration is not guessed")
    if guard_open:
        reject("PREPROCESSOR", "Unclosed include guard")
    if text.rstrip() and not "\n".join(declarations).rstrip().endswith(";") and any(x.strip() for x in declarations):
        reject("SYNTAX", "Only semicolon-terminated declarations are supported")
    return "\n".join(declarations), macros


class HeaderParser:
    def __init__(self, text):
        declarations, self.macros = preprocess_subset(text)
        self.structs, self.tags, self.aliases, self.prototypes = {}, {}, {}, []
        for chunk in split_top(tokens(declarations), ";"):
            if not chunk:
                continue
            if "{" in chunk:
                typedef = chunk[0] == "typedef"
                leading = chunk[1:] if typedef else chunk
                if not leading or leading[0] != "struct":
                    reject("DECLARATION", "Function definitions, unions and enums are unsupported")
                opening, closing = leading.index("{"), leading.index("}")
                if "{" in leading[opening+1:closing] or "}" in leading[closing+1:]:
                    reject("DECLARATION", "Inline anonymous nested records are unsupported; name each record separately")
                tag = leading[1] if opening == 2 else None
                if opening not in {1, 2}:
                    reject("DECLARATION", "Unsupported struct declaration")
                trailing = leading[closing+1:]
                name = trailing[0] if typedef and len(trailing) == 1 else tag if not typedef and not trailing else None
                if not name or name in self.structs:
                    reject("DECLARATION", "A struct must have one unique named type")
                fields = split_top(leading[opening+1:closing], ";")
                if not fields:
                    reject("LAYOUT", "Empty structs have no portable supported C layout")
                self.structs[name] = {"c_name": name if typedef else "struct " + tag, "fields": fields}
                if tag:
                    self.tags[tag] = name
            elif chunk[0] == "typedef":
                if len(chunk) < 3 or "(" in chunk or "," in chunk or "[" in chunk:
                    reject("TYPEDEF", "Only simple scalar or pointer typedefs are supported")
                self.aliases[chunk[-1]] = chunk[1:-1]
            elif "(" in chunk:
                if chunk[0] == "extern":
                    chunk = chunk[1:]
                if chunk[0] in {"static", "inline"}:
                    reject("LINKAGE", "Static/inline functions have no imported external ABI symbol")
                opening = chunk.index("(")
                if chunk[-1] != ")" or "(" in chunk[opening+1:]:
                    reject("PROTOTYPE", "Function-pointer parameters and complex declarators are unsupported")
                if chunk[opening+1:-1] == []:
                    reject("PROTOTYPE", "Old-style unspecified parameters () are rejected; use (void)")
                self.prototypes.append((chunk[:opening], split_top(chunk[opening+1:-1], ",")))
            else:
                reject("DECLARATION", "Only plain function prototypes, typedefs and named structs are supported")
        self.primitive_types = {}
        self.constant_values = {}
        self.resolving = set()

    def declaration(self, items, *, field=False, allow_unnamed=False):
        items = list(items)
        if any(x in items for x in {"volatile", "restrict", "_Atomic", "_Bool", "bool"}):
            reject("QUALIFIER", "volatile/restrict/atomic/bool types require semantics not supported by this importer")
        base_const = False
        if items and items[0] == "const":
            base_const = True
            items.pop(0)
        if not items:
            reject("TYPE", "Missing C type")
        if items[0] == "struct":
            if len(items) < 2 or items[1] not in self.tags:
                reject("TYPE", "Opaque/undefined struct tags are not supported")
            base = Type(self.tags[items[1]])
            items = items[2:]
        elif items[0] in WORDS:
            words = []
            while items and items[0] in WORDS:
                words.append(items.pop(0))
            spelling = " ".join(words)
            spelling = {"signed": "int", "unsigned": "unsigned int", "short int": "short", "signed short": "short", "signed short int": "short", "long int": "long", "signed long": "long", "signed long int": "long", "unsigned long int": "unsigned long", "long long int": "long long", "signed long long": "long long", "signed long long int": "long long", "unsigned long long int": "unsigned long long", "signed int": "int", "unsigned short int": "unsigned short"}.get(spelling, spelling)
            if spelling == "void":
                base = Type("Unit")
            elif spelling not in self.primitive_types:
                reject("TYPE", f"Unsupported fundamental C type {spelling}")
            else:
                base = self.primitive_types[spelling]
        else:
            name = items.pop(0)
            if name in self.structs:
                base = Type(name)
            elif name in self.primitive_types:
                base = self.primitive_types[name]
            elif name in self.aliases:
                if name in self.resolving:
                    reject("TYPEDEF", "Recursive typedef")
                self.resolving.add(name)
                _, base = self.declaration(self.aliases[name], allow_unnamed=True)
                self.resolving.remove(name)
            else:
                reject("TYPE", f"Unknown C type {name}")
        if items and items[0] == "const":
            base_const = True
            items.pop(0)
        while items and items[0] == "*":
            items.pop(0)
            base = Type("raw_const" if base_const else "raw_mut", (base,))
            base_const = bool(items and items[0] == "const")
            if base_const:
                items.pop(0)
        name = None
        if items and re.fullmatch(r"[A-Za-z_]\w*", items[0]):
            name = items.pop(0)
        dimensions = []
        while items and items[0] == "[":
            if not field:
                reject("ARRAY_PARAMETER", "C array-parameter decay is not guessed; spell an explicit pointer")
            size = int(items[1]) if len(items) > 1 and items[1].isdigit() else self.constant_values.get(items[1] if len(items) > 1 else "")
            if len(items) < 3 or not isinstance(size, int) or items[2] != "]" or size <= 0:
                reject("ARRAY", "Only positive literal or probed integer-macro array dimensions are supported")
            dimensions.append(size)
            items = items[3:]
        if items or (not name and not allow_unnamed):
            reject("DECLARATOR", "Unsupported or ambiguous declarator: " + " ".join(items))
        for size in reversed(dimensions):
            base = Type("array", (base,), size)
        return name, base


def import_header(path, *, cc=None, module="c_imported", contracts=None) -> ImportResult:
    header = Path(path).resolve()
    original = header.read_bytes()
    parser = HeaderParser(original.decode("utf-8"))
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", module):
        reject("MODULE", "Module name must be an ASCII identifier")
    compiler = shutil.which(cc or "gcc")
    if not compiler:
        reject("TOOLCHAIN", "GCC is required for native C type and layout probes")
    version = subprocess.run([compiler, "--version"], capture_output=True, text=True, timeout=30)
    target = subprocess.run([compiler, "-dumpmachine"], capture_output=True, text=True, timeout=30)
    if version.returncode or target.returncode:
        reject("TOOLCHAIN", "Cannot identify the C compiler")
    probe = ["#include <stdint.h>", "#include <stddef.h>", "#include <limits.h>", "#include <stdio.h>",
             "#include " + json.dumps(str(header)), "int main(void) {"]
    for spelling in PRIMITIVES:
        signed = f"(({spelling})-1 < ({spelling})0)"
        probe.append(f'printf("P|{spelling}|%zu|%zu|%d\\n", sizeof({spelling}), _Alignof({spelling}), {signed});')
    for name in parser.macros:
        selection = "_Generic((" + name + "), " + ", ".join(t + ": " + str(i + 1) for i, t in enumerate(MACRO_TYPES)) + ", default: 0)"
        probe += [f'_Static_assert(__builtin_constant_p({name}), "macro is not constant");',
                  f'_Static_assert({selection} != 0, "macro is not a supported integer type");',
                  f'printf("M|{name}|%d|%lld|%llu\\n", {selection}, (long long)({name}), (unsigned long long)({name}));']
    # The original C compiler knows all original spelling/packing/target facts.
    for name, st in parser.structs.items():
        c_name = st["c_name"]
        probe.append(f'printf("S|{name}|%zu|%zu\\n", sizeof({c_name}), _Alignof({c_name}));')
        for field in st["fields"]:
            # A simple lexical name is sufficient for offsetof; full type parsing follows the probe.
            if "[" in field:
                field_name = field[field.index("[") - 1]
            else:
                field_name = field[-1]
            if not re.fullmatch(r"[A-Za-z_]\w*", field_name):
                reject("FIELD", "Unsupported struct field declarator")
            probe.append(f'printf("F|{name}|{field_name}|%zu|%zu\\n", offsetof({c_name}, {field_name}), sizeof((({c_name}*)0)->{field_name}));')
    probe += ["return 0;", "}"]
    source = "\n".join(probe) + "\n"
    with tempfile.TemporaryDirectory(prefix="hepta-c-import-") as td:
        cfile, binary = Path(td) / "probe.c", Path(td) / "probe"
        cfile.write_text(source)
        p = subprocess.run([compiler, "-std=c11", "-Werror", str(cfile), "-o", str(binary)], capture_output=True, text=True, timeout=120)
        if p.returncode:
            reject("PROBE", "Native header/type probe was rejected: " + p.stderr[-6000:])
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        if run.returncode:
            reject("PROBE", "Native C probe execution failed")
        executable_hash = sha(binary.read_bytes())
    primitive_facts, layouts, macro_values = {}, {}, {}
    for line in run.stdout.splitlines():
        parts = line.split("|")
        if parts[0] == "P":
            name, size, align, signed = parts[1], int(parts[2]), int(parts[3]), bool(int(parts[4]))
            if name in {"float", "double"}:
                if size != (4 if name == "float" else 8):
                    reject("DATA_MODEL", "Only binary32 float and binary64 double storage are supported")
                mapped = "f32" if name == "float" else "f64"
            else:
                if size not in {1, 2, 4, 8}:
                    reject("DATA_MODEL", f"Unsupported integer width for {name}: {size}")
                mapped = ("i" if signed else "u") + str(size * 8)
                if name == "size_t":
                    mapped = "usize"
                elif name in {"ptrdiff_t", "intptr_t"}:
                    mapped = "isize"
                elif name == "uintptr_t":
                    mapped = "usize"
            parser.primitive_types[name] = Type(mapped)
            primitive_facts[name] = {"size": size, "align": align, "signed": signed, "hepta": mapped}
        elif parts[0] == "S":
            layouts[parts[1]] = {"size": int(parts[2]), "align": int(parts[3]), "fields": {}}
        elif parts[0] == "F":
            layouts[parts[1]]["fields"][parts[2]] = {"offset": int(parts[3]), "size": int(parts[4])}
        elif parts[0] == "M":
            spelling = MACRO_TYPES[int(parts[2]) - 1]
            signed = primitive_facts[spelling]["signed"]
            macro_values[parts[1]] = {"c_type": spelling, "hepta_type": primitive_facts[spelling]["hepta"],
                                      "value": int(parts[3] if signed else parts[4]), "expression": parser.macros[parts[1]]}
        else:
            reject("PROBE", "Unexpected probe output; header side effects are not accepted")
    output = ["module " + module + ";"]
    parser.constant_values = {name: fact["value"] for name, fact in macro_values.items()}
    typedefs = {}
    for name, declaration in parser.aliases.items():
        _, resolved = parser.declaration(declaration, allow_unnamed=True)
        typedefs[name] = str(resolved)
    for name, st in parser.structs.items():
        fields = [parser.declaration(f, field=True) for f in st["fields"]]
        output.append(f"pub repr(C) struct {name} {{ " + ", ".join(n + ": " + str(t) for n, t in fields) + " }")
    functions = []
    for declaration, parameters in parser.prototypes:
        name, result = parser.declaration(declaration)
        params = [] if parameters == [["void"]] else [parser.declaration(p, allow_unnamed=True) for p in parameters]
        effects = set((contracts or {}).get(name, EFFECTS)) | {"ffi", "unsafe"}
        if effects - EFFECTS:
            reject("CONTRACT", "Unknown effect in explicit import contract for " + name)
        output.append(f'extern "C" fn {name}(' + ", ".join(f"arg{i}: {typ}" for i, (_, typ) in enumerate(params)) + ") -> " + str(result) + " effects { " + ", ".join(sorted(effects)) + " };")
        functions.append({"name": name, "effects": sorted(effects), "semantic_contract": "caller_supplied_assumption" if name in (contracts or {}) else "conservative_unknown_foreign_effects", "c_parameter_names": [n for n, _ in params]})
    for name, fact in macro_values.items():
        # The current checker conservatively marks signed negation as panic.
        effects = "panic" if fact["value"] < 0 else ""
        output.append(f"pub fn cconst_{name}() -> {fact['hepta_type']} effects {{ {effects} }} {{ return {fact['value']}; }}")
    generated = "// hepta:c-import:v1\n" + "\n".join(output) + "\n"
    try:
        checked = check(parse(generated, str(header) + ".imported.hepta"))
    except HeptaError as e:
        reject("REPRESENTATION", "C declaration cannot be represented in Hepta: " + e.diagnostic.message)
    if not checked.ok:
        reject("REPRESENTATION", "; ".join(d.code + ": " + d.message for d in checked.diagnostics))
    if header.read_bytes() != original:
        reject("SOURCE_CHANGED", "Header changed while importing; retry a fixed source snapshot")
    return ImportResult(generated, {"schema": "hepta.c-import.v1", "status": "imported_native_host_facts",
        "header": str(header), "header_sha256": sha(original), "source_sha256": sha(generated.encode()),
        "target": target.stdout.strip(), "host": {"system": platform.system(), "machine": platform.machine(), "pointer_bits": struct.calcsize("P") * 8}, "compiler": {"path": compiler, "version": version.stdout.strip(), "executable_sha256": sha(Path(compiler).read_bytes())},
        "probe_source_sha256": sha(source.encode()), "probe_artifact_sha256": executable_hash,
        "primitive_types": primitive_facts, "typedefs": typedefs, "layouts": layouts, "constants": macro_values, "functions": functions,
        "limitations": ["Only the recorded native host ABI was probed.", "No ownership, lifetimes, thread safety, device ordering or foreign implementation correctness is inferred from a header.", "Effects are conservative or caller-supplied assumptions.", "Attributes, packing, bitfields, unions, enums, varargs, function pointers, opaque records, complex preprocessing and array-parameter decay are explicitly unsupported."]})

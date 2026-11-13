"""Translate a complete, public scalar C++ value class into real Hepta code.

The admitted lifecycle is trivially destructible and trivially copyable.
There is no C++ bridge, fallback body, hidden extern or resource-owning RAII
translation. Scalar expressions reuse hepta.c_migrate's existing lowerer.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from .c_migrate import MigrationRejected, _expr, _load_bounded_clang_ast, _predicate, _run, _stmt
from .cpp2hepta import _model
from .pipeline import analyze

PROFILE = "cpp20-public-scalar-value-class-trivial-lifecycle-v1"
SCALARS = {"int": "i32", "unsigned int": "u32", "long long": "i64", "unsigned long long": "u64"}
_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_SIGNATURE = re.compile(r"(void|int|unsigned int|long long|unsigned long long) \(([^()]*)\)( const)? noexcept\Z")
_RESOURCES = "resources {heap_allocations=0;may_block=false;may_suspend=false;may_spawn=false;}"


def _reject(message: str, code: str = "E_CPP_CLASS_PROFILE") -> None:
    raise MigrationRejected(code, message)


def _name(value: object) -> str:
    if not isinstance(value, str) or len(value) > 128 or not _IDENT.fullmatch(value) or value.startswith("__"):
        _reject("Unsupported source identifier")
    return value


def _scalar(node: dict) -> str:
    spelling = node.get("type", {}).get("qualType")
    if spelling not in SCALARS:
        _reject(f"Only plain i32/u32/i64/u64 value types are supported: {spelling}", "E_CPP_CLASS_TYPE")
    return SCALARS[spelling]


def _children(node: dict) -> list[dict]:
    children = node.get("inner", [])
    if not isinstance(children, list) or any(not isinstance(child, dict) for child in children):
        _reject("Malformed Clang declaration children", "E_CPP_CLASS_AST")
    return children


def _parameters(node: dict) -> tuple[list[dict], dict[str, dict]]:
    params = [child for child in _children(node) if child.get("kind") == "ParmVarDecl"]
    if len(params) > 16:
        _reject("At most sixteen scalar parameters are supported")
    by_id = {}
    names = set()
    for index, param in enumerate(params):
        name = _name(param.get("name"))
        ident = param.get("id")
        if (not isinstance(ident, str) or ident in by_id or name in names
                or param.get("init") is not None or _children(param)):
            _reject("Parameters need distinct Clang identities, without defaults or attributes")
        names.add(name)
        by_id[ident] = {"name": name, "hepta_name": f"arg{index}", "type": _scalar(param),
                       "cpp_type": param["type"]["qualType"]}
    return params, by_id


def _signature(node: dict, *, constructor: bool = False) -> tuple[str, bool, dict[str, dict]]:
    if any(node.get(flag) for flag in ("storageClass", "virtual", "pure", "variadic", "constexpr",
                                       "consteval", "inline", "explicitlyDeleted", "isDeleted")):
        _reject("Static, virtual, constexpr, inline-spelled or special members are outside this profile")
    signature = _SIGNATURE.fullmatch(node.get("type", {}).get("qualType", ""))
    if signature is None:
        _reject("Methods and the constructor require exact scalar value signatures and noexcept")
    params, by_id = _parameters(node)
    actual = ", ".join(param["type"]["qualType"] for param in params)
    if actual != signature[2] or (constructor and (signature[1] != "void" or signature[3])):
        _reject("Clang parameter declarations disagree with the method signature", "E_CPP_CLASS_AST")
    return ("Unit" if signature[1] == "void" else SCALARS[signature[1]]), bool(signature[3]), by_id


def _local_bindings(body: dict) -> dict[str, dict]:
    """Bind automatic scalar declarations by identity before rewriting uses.

    Source spelling never identifies a variable: shadowed for indices receive
    different bindings. The shared C statement lowerer still owns scope and
    declaration-placement acceptance, so collecting an identity is not a claim
    that its declaration is legal in every position.
    """
    found = {}
    pending = [body]
    while pending:
        node = pending.pop()
        if node.get("kind") == "VarDecl":
            ident = node.get("id")
            if (not isinstance(ident, str) or ident in found or len(found) >= 64
                    or node.get("storageClass") is not None or node.get("tls") is not None
                    or node.get("constexpr") or node.get("isConstexpr") or node.get("inline")
                    or node.get("init") is None or len(_children(node)) != 1):
                _reject("Method locals need one initialized automatic scalar and a distinct identity",
                        "E_CPP_CLASS_LOCAL")
            found[ident] = {"name": _name(node.get("name")), "type": _scalar(node),
                            "cpp_type": node["type"]["qualType"],
                            "binding": "localbinding" + str(len(found))}
        pending.extend(reversed(_children(node)))
    return found


def _rewrite(node: dict, params: dict[str, dict], fields: dict[str, dict], class_name: str,
             *, const: bool, allow_fields: bool = True,
             local_bindings: dict[str, dict] | None = None) -> dict:
    """Bind each accepted source field to one checked scalar-lowerer place.

    A MemberExpr is admitted only when it refers by Clang identity to one of
    this class's fields on the actual this receiver. Its synthetic local name
    is mapped by the canonical scalar lowerer to receiver.<field>, not pasted
    into the resulting expression by textual replacement.
    """
    kind = node.get("kind")
    if kind == "MemberExpr":
        field = fields.get(node.get("referencedMemberDecl"))
        children = _children(node)
        expected_receiver = ("const " if const else "") + class_name + " *"
        if (not allow_fields or field is None or node.get("name") != field["name"]
                or node.get("isArrow") is not True or len(children) != 1
                or children[0].get("kind") != "CXXThisExpr"
                or children[0].get("type", {}).get("qualType") != expected_receiver
                or _children(children[0])):
            _reject("Only this class's scalar fields on its own receiver are supported", "E_CPP_CLASS_MEMBER")
        expected_type = ("const " if const else "") + field["cpp_type"]
        if node.get("type", {}).get("qualType") != expected_type:
            _reject("Member field type or receiver qualifiers differ", "E_CPP_CLASS_MEMBER")
        return {"kind": "DeclRefExpr", "type": {"qualType": field["cpp_type"]},
                "valueCategory": "lvalue", "referencedDecl": {
                    "kind": "VarDecl", "id": field["id"], "name": field["binding"],
                    "type": {"qualType": field["cpp_type"]}}}
    if kind == "DeclRefExpr":
        decl = node.get("referencedDecl", {})
        binding = (params.get(decl.get("id")) if decl.get("kind") == "ParmVarDecl"
                   else (local_bindings or {}).get(decl.get("id")) if decl.get("kind") == "VarDecl"
                   else None)
        if (binding is None or decl.get("name") != binding["name"]
                or decl.get("type", {}).get("qualType") != binding["cpp_type"]
                or node.get("type", {}).get("qualType") != binding["cpp_type"] or _children(node)):
            _reject("Expression refers to something other than its own bound scalar parameter/local", "E_CPP_CLASS_REFERENCE")
        rewritten = copy.deepcopy(node)
        rewritten["referencedDecl"]["name"] = binding.get("hepta_name", binding.get("binding"))
        return rewritten
    if kind == "CXXThisExpr":
        _reject("The this pointer cannot escape or be used as a scalar", "E_CPP_CLASS_MEMBER")
    rewritten = {key: copy.deepcopy(value) for key, value in node.items() if key != "inner"}
    if kind == "VarDecl":
        binding = (local_bindings or {}).get(node.get("id"))
        if binding is None or binding["name"] != node.get("name"):
            _reject("Local declaration is not inventoried", "E_CPP_CLASS_LOCAL")
        rewritten["name"] = binding["binding"]
    if "inner" in node:
        rewritten["inner"] = [_rewrite(child, params, fields, class_name, const=const, allow_fields=allow_fields,
                                         local_bindings=local_bindings)
                              for child in _children(node)]
    return rewritten


def _body(node: dict, args: dict[str, str], places: dict, model: dict, returns: str,
          *, const: bool, depth: int = 1, reserved_names: set[str] | None = None,
          allow_local_prefix: bool = False) -> list[str]:
    kind, children = node.get("kind"), _children(node)
    indent = "    " * depth
    if kind == "CompoundStmt":
        lines = []
        saw_executable = False
        for child in children:
            if child.get("kind") == "DeclStmt":
                if not allow_local_prefix or saw_executable:
                    _reject("Method scalar locals must be a top-level prefix", "E_CPP_CLASS_LOCAL_SCOPE")
                declarations = _children(child)
                if len(declarations) != 1 or declarations[0].get("kind") != "VarDecl":
                    _reject("Local statements require one scalar declaration", "E_CPP_CLASS_LOCAL")
                var = declarations[0]
                name, ident, typ = var.get("name"), var.get("id"), _scalar(var)
                if name in args or name in places or not isinstance(ident, str) or len(_children(var)) != 1:
                    _reject("Conflicting or incomplete local declaration", "E_CPP_CLASS_LOCAL")
                initial, actual = _expr(_children(var)[0], args, model, typ, places)
                if actual != typ:
                    _reject("Local initializer changes scalar type", "E_CPP_CLASS_LOCAL")
                lines.append(f"{indent}let mut {name}: {typ} = {initial};")
                places[name] = (typ, ident, name)
            else:
                saw_executable = True
                lines += _body(child, args, places, model, returns, const=const, depth=depth,
                               reserved_names=reserved_names)
        return lines
    if kind == "IfStmt" and len(children) in {2, 3}:
        predicate, typ = _predicate(children[0], args, model, places)
        if typ != "bool":
            _reject("Unsupported method condition")
        lines = [indent + "if " + predicate + " {"]
        lines += _body(children[1], args, places, model, returns, const=const, depth=depth + 1,
                       reserved_names=reserved_names)
        lines += [indent + "}"]
        if len(children) == 3:
            lines += [indent + "else {"]
            lines += _body(children[2], args, places, model, returns, const=const, depth=depth + 1,
                           reserved_names=reserved_names)
            lines += [indent + "}"]
        return lines
    if kind == "ReturnStmt":
        if returns == "Unit":
            if children:
                _reject("Unit methods may return only without a value")
            return [indent + "return;"]
        if len(children) != 1:
            _reject("Scalar methods require one return value")
        return _stmt(node, args, model, returns, depth=depth, locals=places, reserved_names=reserved_names)
    if kind == "BinaryOperator" and node.get("opcode") == "=" and len(children) == 2:
        if const and children[0].get("referencedDecl", {}).get("name", "").startswith("fieldbinding"):
            _reject("Const methods cannot update fields")
        return _stmt(node, args, model, returns, depth=depth, locals=places, reserved_names=reserved_names)
    if kind in {"ForStmt", "WhileStmt", "DoStmt", "UnaryOperator"}:
        # This uses the same typed statement lowering as C and scalar C++.
        # No break/continue/goto or in-loop declaration is silently erased.
        pending = [node]
        while pending:
            current = pending.pop()
            operands = _children(current)
            if (const and current.get("opcode") in {"=", "++", "--"} and operands
                    and operands[0].get("referencedDecl", {}).get("name", "").startswith("fieldbinding")):
                _reject("Const methods cannot update fields")
            pending.extend(operands)
        return _stmt(node, args, model, returns, depth=depth, locals=places, reserved_names=reserved_names)
    _reject(f"Unsupported method statement: {kind}", "E_CPP_CLASS_STATEMENT")


def _translate(record: dict, model: dict) -> tuple[str, dict]:
    name = _name(record.get("name"))
    data = record.get("definitionData", {})
    if (record.get("tagUsed") not in {"struct", "class"} or not record.get("completeDefinition")
            or record.get("bases") or not data.get("isStandardLayout")
            or not data.get("isTriviallyCopyable") or not data.get("dtor", {}).get("trivial")):
        _reject("Need a complete standard-layout, trivially copyable/destructible value class without bases", "E_CPP_CLASS_LIFECYCLE")
    fields, methods, constructors, destructors, inventory = {}, [], [], [], []
    access = "public" if record["tagUsed"] == "struct" else "private"
    for node in _children(record):
        kind = node.get("kind")
        if node.get("isImplicit"):
            if kind == "CXXRecordDecl" and node.get("name") == name and not node.get("completeDefinition"):
                inventory.append({"kind": kind, "name": name, "disposition": "implicit_injected_class_name"})
                continue
            if kind == "CXXDestructorDecl" and node.get("explicitlyDefaulted") == "default" and not _children(node):
                inventory.append({"kind": kind, "name": node.get("name"), "disposition": "implicit_trivial_destructor"})
                continue
            _reject(f"Unmodeled implicit member: {kind}")
        if kind == "AccessSpecDecl":
            access = node.get("access")
            if access != "public" or _children(node):
                _reject("Private/protected member visibility is not modeled", "E_CPP_CLASS_ACCESS")
            inventory.append({"kind": kind, "disposition": "public_visibility_preserved"})
            continue
        if access != "public":
            _reject("Only public fields and operations are supported", "E_CPP_CLASS_ACCESS")
        if kind == "FieldDecl":
            field_name = _name(node.get("name"))
            field_id = node.get("id")
            if (not isinstance(field_id, str) or field_id in fields or len(fields) >= 16
                    or node.get("isBitfield") or node.get("mutable") or node.get("isMutable")
                    or node.get("hasInClassInitializer") or _children(node)):
                _reject("Fields must be plain scalars without bitfields, mutable, defaults or attributes")
            fields[field_id] = {"id": field_id, "name": field_name, "type": _scalar(node),
                                "cpp_type": node["type"]["qualType"], "binding": "fieldbinding" + str(len(fields))}
        elif kind == "CXXConstructorDecl":
            constructors.append(node)
        elif kind == "CXXDestructorDecl":
            if (node.get("explicitlyDefaulted") != "default" or _children(node)
                    or node.get("type", {}).get("qualType") not in {"void ()", "void () noexcept"}):
                _reject("Only an implicit or explicitly defaulted trivial destructor is supported", "E_CPP_CLASS_LIFECYCLE")
            destructors.append(node)
        elif kind == "CXXMethodDecl":
            methods.append(node)
        else:
            _reject(f"Unconverted class member: {kind}", "E_CPP_CLASS_INVENTORY")
        inventory.append({"kind": kind, "name": node.get("name"),
                          "disposition": "trivial_destruction_no_action" if kind == "CXXDestructorDecl" else "translated"})
    if not fields or len(constructors) != 1 or not 1 <= len(methods) <= 32 or len(destructors) > 1:
        _reject("Need 1..16 scalar fields, one explicit constructor and 1..32 methods")
    lines = ["module cpp_class_migrated;", "", "// Actual implementation migration; no foreign calls or C++ class ABI.",
             "pub struct " + name + " {"]
    lines += ["    " + f["name"] + ": " + f["type"] + "," for f in fields.values()]
    lines += ["}", ""]
    ctor = constructors[0]
    _, _, ctor_params = _signature(ctor, constructor=True)
    children = _children(ctor)
    if any(n.get("kind") not in {"ParmVarDecl", "CXXCtorInitializer", "CompoundStmt"} for n in children):
        _reject("Constructor contains unsupported declarations/attributes")
    bodies = [n for n in children if n.get("kind") == "CompoundStmt"]
    initializers = [n for n in children if n.get("kind") == "CXXCtorInitializer"]
    if len(bodies) != 1 or _children(bodies[0]) or len(initializers) != len(fields):
        _reject("Constructor needs an empty body and one explicit initializer for every field")
    args = {p["hepta_name"]: p["type"] for p in ctor_params.values()}
    init_values = []
    for initializer, field in zip(initializers, fields.values()):
        target = initializer.get("anyInit", {})
        if (target.get("kind") != "FieldDecl" or target.get("id") != field["id"]
                or target.get("name") != field["name"] or len(_children(initializer)) != 1):
            _reject("Constructor initialization must account for every own field by identity")
        expression = _rewrite(_children(initializer)[0], ctor_params, fields, name, const=False, allow_fields=False)
        value, typ = _expr(expression, args, model, field["type"])
        if typ != field["type"]:
            _reject("Constructor initializer changes field type")
        init_values.append(field["name"] + ": " + value)
    signature = ", ".join(p["hepta_name"] + ": " + p["type"] for p in ctor_params.values())
    lines += [f"pub fn {name}_new({signature}) -> {name} effects {{panic}} {_RESOURCES} {{",
              "    return " + name + " {" + ", ".join(init_values) + "};", "}", ""]
    places = {f["binding"]: (f["type"], f["id"], "receiver." + f["name"]) for f in fields.values()}
    used = {"new"}
    mappings = []
    for method in methods:
        method_name = _name(method.get("name"))
        if method_name in used:
            _reject("Overloaded or conflicting methods are unsupported")
        used.add(method_name)
        returns, const, params = _signature(method)
        children = _children(method)
        if any(n.get("kind") not in {"ParmVarDecl", "CompoundStmt"} for n in children):
            _reject("Method contains unsupported declarations/attributes")
        bodies = [n for n in children if n.get("kind") == "CompoundStmt"]
        if len(bodies) != 1:
            _reject("Every method must be defined in the class")
        locals_ = _local_bindings(bodies[0])
        body = _rewrite(bodies[0], params, fields, name, const=const, local_bindings=locals_)
        args = {p["hepta_name"]: p["type"] for p in params.values()}
        reserved = set(args) | set(places) | {entry["binding"] for entry in locals_.values()}
        rendered = _body(body, args, dict(places), model, returns, const=const,
                         reserved_names=reserved, allow_local_prefix=True)
        signature = ", ".join(["receiver: " + ("read " if const else "mut ") + name,
                               *[p["hepta_name"] + ": " + p["type"] for p in params.values()]])
        effects = "panic" if const else "panic, write"
        lines += [f"pub fn {name}_{method_name}({signature}) -> {returns} effects {{{effects}}} {_RESOURCES} {{",
                  *rendered, "}", ""]
        mappings.append({"cpp_method": method_name, "hepta_function": name + "_" + method_name,
                         "receiver": "read" if const else "mut", "returns": returns,
                         "parameters": list(params.values()), "automatic_scalar_locals": len(locals_),
                         "scalar_statement_authority": "hepta.c_migrate._stmt"})
    return "\n".join(lines), {"name": name,
                              "fields": [{k: f[k] for k in ("name", "type", "cpp_type")} for f in fields.values()],
                              "constructor": {"hepta_function": name + "_new", "parameters": list(ctor_params.values())},
                              "methods": mappings, "declaration_inventory": inventory,
                              "destructor": "explicit_defaulted_trivial" if destructors else "implicit_trivial",
                              "copy_semantics": "trivial_scalar_value_copy", "unconverted_members": []}



def _verify_published_class(staged: Path, output: Path, content: bytes) -> None:
    """Reject output replacement or byte changes after atomic no-overwrite link.

    The generated Hepta text has been checked in memory. Certification must
    reference precisely those bytes, not unrelated bytes at the output path.
    """
    try:
        source = staged.stat()
        target = output.lstat()
        identity = (target.st_dev, target.st_ino, target.st_mode,
                    target.st_size, target.st_mtime_ns, target.st_ctime_ns)
        if (not stat.S_ISREG(target.st_mode)
                or (source.st_dev, source.st_ino) != (target.st_dev, target.st_ino)
                or source.st_size != len(content)):
            _reject("Published C++ migration is not its validated staged file", "E_CPP_CLASS_RACE")
        fd = os.open(output, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if ((opened.st_dev, opened.st_ino, opened.st_mode,
                 opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != identity):
                _reject("Published C++ migration changed before opening", "E_CPP_CLASS_RACE")
            observed = stream.read(len(content) + 1)
            after = os.fstat(stream.fileno())
            if (observed != content or (after.st_dev, after.st_ino, after.st_mode,
                     after.st_size, after.st_mtime_ns, after.st_ctime_ns) != identity):
                _reject("Published C++ migration bytes or inode differ", "E_CPP_CLASS_RACE")
        latest = output.lstat()
        if (latest.st_dev, latest.st_ino, latest.st_mode,
                latest.st_size, latest.st_mtime_ns, latest.st_ctime_ns) != identity:
            _reject("Published C++ migration path was replaced", "E_CPP_CLASS_RACE")
    except OSError as exc:
        _reject(f"Published C++ migration cannot be read reliably: {exc}", "E_CPP_CLASS_RACE")


def migrate_cpp_class(source_file: str | Path, destination_file: str | Path, *, clangxx: str = "clang++") -> dict:
    source, output = Path(source_file).resolve(), Path(os.path.abspath(destination_file))
    report = {"schema": "hepta.cpp-class-migration.v1", "profile": PROFILE, "tier": "L1",
              "ok": False, "status": "rejected", "source": str(source), "output": str(output),
              "rejected": [], "cpp_abi_preserved": False, "source_equivalence_proved": False,
              "whole_language_memory_safety_proved": False, "resource_owning_raii_translated": False,
              "native_validation": "not_run", "differential_validation": "not_run"}
    try:
        if (source.suffix not in {".cc", ".cpp", ".cxx"} or not source.is_file()
                or output.suffix != ".hepta" or source == output or output.is_symlink()
                or output.exists() or not output.parent.is_dir()):
            _reject("Need an existing C++ file and a distinct new ordinary .hepta output", "E_CPP_CLASS_PATH")
        original = source.read_bytes()
        if len(original) > 256000:
            _reject("Source exceeds the bounded 256 KB profile")
        text = original.decode("utf-8")
        if "#" in text or "%:" in text or re.search(r"\\\r?\n", text):
            _reject("Preprocessing requires a separate project migration profile", "E_CPP_CLASS_PREPROCESSOR")
        selected = shutil.which(clangxx)
        if selected is None:
            _reject("C++ Clang is unavailable", "E_CPP_CLASS_TOOLCHAIN")
        compiler = Path(selected).resolve(strict=True)
        compiler_hash = hashlib.sha256(compiler.read_bytes()).hexdigest()
        model = _model(str(compiler))
        version = re.search(r"clang version (\d+)\.", model["clang_version"])
        if version is None or int(version[1]) < 20:
            _reject("This C++ class AST profile requires Clang 20 or newer", "E_CPP_CLASS_TOOLCHAIN")
        tree = _load_bounded_clang_ast(_run([str(compiler), "-x", "c++", "-std=c++20", "-Werror",
                                           "-fsyntax-only", "-Xclang", "-ast-dump=json", str(source)]))
        records = []
        for node in _children(tree):
            offset = node.get("loc", {}).get("offset")
            if offset is None:
                if node.get("isImplicit") and node.get("kind") == "TypedefDecl":
                    continue
                _reject("Unaccounted translation-unit declaration", "E_CPP_CLASS_INVENTORY")
            begin = node.get("range", {}).get("begin", {}).get("offset")
            end = node.get("range", {}).get("end", {}).get("offset")
            if (type(offset) is not int or type(begin) is not int or type(end) is not int
                    or not 0 <= begin <= offset <= end < len(original)):
                _reject("Declaration lacks a valid source identity", "E_CPP_CLASS_AST")
            if node.get("kind") != "CXXRecordDecl" or not node.get("completeDefinition") or node.get("isImplicit"):
                _reject(f"Unconverted top-level declaration: {node.get('kind')}", "E_CPP_CLASS_INVENTORY")
            records.append(node)
        if len(records) != 1:
            _reject("Exactly one complete scalar value class is supported")
        rendered, mapping = _translate(records[0], model)
        # These checks use the real source again; a translated constructor is
        # not evidence that a foreign resource destructor was preserved.
        cls = mapping["name"]
        _run([str(compiler), "-x", "c++", "-std=c++20", "-Werror", "-fsyntax-only", "-"],
             input_text=text + f"\nstatic_assert(__is_trivially_destructible({cls}));\n"
                              f"static_assert(__is_trivially_copyable({cls}));\n"
                              f"static_assert(__is_standard_layout({cls}));\n")
        checked = analyze(rendered, str(output), native=False)
        if not checked.report["ok"]:
            report.update(status="hepta_frontend_rejected", rejected=checked.report["diagnostics"])
            return report
        if checked.report["assumptions"]:
            _reject("Translated class unexpectedly contains foreign assumptions")
        if (source.read_bytes() != original or hashlib.sha256(compiler.read_bytes()).hexdigest() != compiler_hash):
            _reject("Source/compiler changed during migration", "E_CPP_CLASS_RACE")
        staged = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, prefix=".cpp-class-", delete=False) as f:
                staged = Path(f.name)
                f.write(rendered)
                f.flush()
                os.fsync(f.fileno())
            if (source.read_bytes() != original
                    or hashlib.sha256(compiler.read_bytes()).hexdigest() != compiler_hash):
                _reject("Source/compiler changed before publication", "E_CPP_CLASS_RACE")
            os.link(staged, output)
            # A subsequent verification cannot rely on the bytes used for
            # emit/check if a competing writer altered the published entry.
            publication_ok = False
            try:
                _verify_published_class(staged, output, rendered.encode("utf-8"))
                if (source.read_bytes() != original
                        or hashlib.sha256(compiler.read_bytes()).hexdigest() != compiler_hash):
                    _reject("Source or compiler changed during publication", "E_CPP_CLASS_RACE")
                publication_ok = True
            finally:
                if not publication_ok:
                    try:
                        stage_info, output_info = staged.stat(), output.lstat()
                        if (stat.S_ISREG(output_info.st_mode)
                                and (stage_info.st_dev, stage_info.st_ino) ==
                                (output_info.st_dev, output_info.st_ino)):
                            output.unlink()
                    except OSError:
                        pass
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
        report.update(ok=True, status="class_implementation_translated_frontend_checked",
                      source_sha256=hashlib.sha256(original).hexdigest(),
                      output_sha256=hashlib.sha256(rendered.encode()).hexdigest(),
                      target_model={**model, "compiler_sha256": compiler_hash}, translated_class=mapping,
                      native_trivial_lifecycle_checked=True, foreign_calls_introduced=0,
                      foreign_cpp_implementation_retained=False, hepta_frontend=checked.report,
                      limitations=["Only the fully inventoried public scalar class is translated.",
                                   "Original C++ undefined arithmetic inputs are outside the equivalence domain.",
                                   "Class layout, mangled ABI, whole-program equivalence and resource RAII migration are not claimed."])
        return report
    except (MigrationRejected, OSError, ValueError, UnicodeError) as exc:
        report["rejected"].append({"code": getattr(exc, "code", "E_CPP_CLASS_INPUT"), "message": str(exc)})
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clangxx", default="clang++")
    args = parser.parse_args()
    result = migrate_cpp_class(args.source, args.output, clangxx=args.clangxx)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

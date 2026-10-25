"""Recognize and translate a complete, closed C++ exclusive-byte-owner protocol.

The compiler checks the entire native AST against explicit allocation, move,
borrow and cleanup rules. The lifecycle operation is translated too; accepted
output owns a real Hepta Buffer and never links the original C++ class.
This is not a general C++ RAII, arbitrary destructor or project migration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from .c_migrate import MigrationRejected, _load_bounded_clang_ast, _run
from .cpp2hepta import _model
from .pipeline import analyze, compiler_hash
from .resource_lowering import lower_resource_ir
from .resource_ir import ResourceIRError, verify_resource_ir

PROFILE = "cpp20-exclusive-zeroed-u8-array-move-and-lifecycle-v1"
SCHEMA = "hepta.cpp-owned-migration.v1"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _reject(message, code="E_CPP_OWNED_PROTOCOL"):
    raise MigrationRejected(code, message)


def _nodes(tree, path=()):
    if not isinstance(tree, dict) or not isinstance(tree.get("inner", []), list):
        _reject("Malformed native AST", "E_CPP_OWNED_AST")
    yield tree, path
    for index, child in enumerate(tree.get("inner", [])):
        yield from _nodes(child, (*path, index))


def _normalized(tree, class_name):
    """Remove source coordinates/opaque addresses, never semantic operations.

    Declaration identities are bound before any reference is visited. Thus
    exchanging two same-type fields/locals does not become equivalent merely
    because their spellings or first reference order have changed. All other
    AST members remain, including implicit conversions, cleanup temporaries,
    exception handlers, literal values, qualifiers and storage specifiers.
    """
    declarations = {}
    for node, path in _nodes(tree):
        if str(node.get("kind", "")).endswith("Decl") and isinstance(node.get("id"), str):
            ident = node["id"]
            if ident in declarations:
                _reject("Native AST repeats a declaration identity", "E_CPP_OWNED_AST")
            declarations[ident] = "declaration:" + "/".join(map(str, path))
    typename = re.compile(r"\b" + re.escape(class_name) + r"\b")

    def visit(value):
        if isinstance(value, list):
            return [visit(item) for item in value]
        if not isinstance(value, dict):
            return value
        kind, ident = value.get("kind", ""), value.get("id")
        result = {}
        for key, child in value.items():
            if key in {"loc", "range", "mangledName"}:
                continue
            if key == "id":
                if str(kind).endswith("Decl"):
                    # A builtin type's minimal declaration can appear only in
                    # type metadata; its name and complete type still remain.
                    result[key] = declarations.get(child, "builtin:" + str(value.get("name")))
                continue
            if key == "referencedMemberDecl":
                if child not in declarations:
                    _reject("Member reference is not an inventoried declaration", "E_CPP_OWNED_AST")
                result[key] = declarations[child]
                continue
            if key == "name":
                if str(kind).endswith("Decl") and ident in declarations:
                    result[key] = child if str(child).startswith("operator") else declarations[ident]
                    continue
                if kind == "MemberExpr" and value.get("referencedMemberDecl") in declarations:
                    result[key] = declarations[value["referencedMemberDecl"]]
                    continue
            if key in {"qualType", "desugaredQualType"} and isinstance(child, str):
                result[key] = typename.sub("HeptaProtocolOwner", child)
                continue
            result[key] = visit(child)
        return result

    return visit(tree)


def _source_unit(tree, original):
    declarations = []
    for node in tree.get("inner", []):
        if node.get("isImplicit") is True:
            continue  # Fully checked against the native protocol AST below.
        begin = node.get("range", {}).get("begin", {}).get("offset")
        end = node.get("range", {}).get("end", {}).get("offset")
        if type(begin) is not int or type(end) is not int or not 0 <= begin <= end < len(original):
            _reject("Source declaration lacks an exact file position", "E_CPP_OWNED_AST")
        declarations.append(node)
    if (len(declarations) != 2 or declarations[0].get("kind") != "CXXRecordDecl"
            or not declarations[0].get("completeDefinition") or declarations[1].get("kind") != "FunctionDecl"):
        _reject("Need exactly one complete owner class and one complete lifecycle function; no hidden declarations")
    cls, operation = declarations
    for node in declarations:
        name = node.get("name")
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z][A-Za-z_0-9]{0,127}", name) is None:
            _reject("Unsupported class or lifecycle function name")
    if cls["name"] == operation["name"]:
        _reject("Class and lifecycle operation need distinct names")
    return cls, operation


def migrate_cpp_owned(source_file, destination_file, *, clangxx="clang++"):
    source = Path(source_file).resolve()
    output = Path(os.path.abspath(destination_file))
    report = {"schema": SCHEMA, "profile": PROFILE, "tier": "L1", "ok": False, "status": "rejected",
              "source": str(source), "output": str(output), "diagnostics": [],
              "whole_cpp_raii_supported": False, "source_equivalence_proved": False,
              "cpp_class_abi_preserved": False, "whole_language_memory_safety_proved": False,
              "foreign_cpp_implementation_retained": False, "native_execution": "not_run"}
    try:
        if (source.suffix not in {".cpp", ".cc", ".cxx"} or not source.is_file()
                or output.suffix != ".hepta" or output.is_symlink() or output.exists()
                or not output.parent.is_dir()):
            _reject("Need an existing C++ source and distinct new ordinary .hepta output", "E_CPP_OWNED_PATH")
        original = source.read_bytes()
        if len(original) > 256000:
            _reject("Source exceeds the bounded 256 KB profile")
        text = original.decode("utf-8")
        if "#" in text or "%:" in text or re.search(r"\\\r?\n", text):
            _reject("Preprocessing/includes need a separately inventoried project profile", "E_CPP_OWNED_PREPROCESSOR")
        selected = shutil.which(clangxx)
        if selected is None:
            _reject("Clang C++ compiler unavailable", "E_CPP_OWNED_TOOLCHAIN")
        compiler = Path(selected).resolve(strict=True)
        native_hash, hepta_hash = _sha(compiler.read_bytes()), compiler_hash()
        model = _model(str(compiler))
        version = re.search(r"clang version (\d+)\.", model["clang_version"])
        if version is None or int(version[1]) < 20 or model["sizeof_long"] != 8:
            _reject("Owner protocol requires Clang 20+ and the checked native LP64 model", "E_CPP_OWNED_TOOLCHAIN")
        command = [str(compiler), "-x", "c++", "-std=c++20", "-Werror", "-fsyntax-only", "-Xclang", "-ast-dump=json"]
        tree = _load_bounded_clang_ast(_run([*command, str(source)]))
        cls, operation = _source_unit(tree, original)
        names = {"OwnedBytes": cls["name"], "run_owned": operation["name"]}

        def substitute(template):
            return re.sub(r"\b(OwnedBytes|run_owned)\b", lambda found: names[found[0]], template)

        # Generate the native rule AST independently from compiler-owned text,
        # never from editable examples or the proposed source being migrated.
        protocol_cpp = substitute(_CPP_PROTOCOL)
        protocol = _load_bounded_clang_ast(_run([*command, "-"], input_text=protocol_cpp))
        normalized, expected = _normalized(tree, cls["name"]), _normalized(protocol, cls["name"])
        if normalized != expected:
            _reject("Complete native AST differs from the owned allocation/move/borrow/cleanup protocol; no body is skipped")
        if len(cls.get("inner", [])) != 15:
            _reject("Native compiler added an unmodeled owner member; declaration inventory is incomplete")
        name = cls["name"]
        _run([str(compiler), "-x", "c++", "-std=c++20", "-Werror", "-fsyntax-only", "-"],
             input_text=text + f"\nstatic_assert(__is_standard_layout({name}));\n"
                 f"static_assert(!__is_constructible({name}, const {name}&));\n"
                 f"static_assert(__is_nothrow_constructible({name}, {name}&&));\n"
                 f"static_assert(__is_nothrow_destructible({name}));\n"
                 f"static_assert(!__is_trivially_destructible({name}));\n")
        # Prefix renaming also applies to each generated free function.
        rendered = _HEPTA_PROTOCOL.replace("OwnedBytes", name)
        rendered = re.sub(r"\brun_owned\b", operation["name"], rendered)
        checks = {}
        for backend in ("rust", "c"):
            checked = analyze(rendered, str(output), backend=backend, native=False, crate_type="obj")
            checks[backend] = checked.report
            if checked.report["ok"] is not True or checked.report["assumptions"]:
                _reject("Generated owner failed checked Hepta lowering: " + json.dumps(checked.report))
        graph = lower_resource_ir(checked.program, checked.checked)
        verification = verify_resource_ir(json.loads(json.dumps(graph)))
        if verification["ok"] is not True or graph["obligations"]:
            _reject("Independent owner resource verification did not pass")
        if (source.read_bytes() != original or _sha(compiler.read_bytes()) != native_hash
                or compiler_hash() != hepta_hash):
            _reject("Source/compiler changed during migration", "E_CPP_OWNED_RACE")
        staged = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent,
                                             prefix=".cpp-owned-", delete=False) as handle:
                staged = Path(handle.name)
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            if (source.read_bytes() != original or _sha(compiler.read_bytes()) != native_hash
                    or compiler_hash() != hepta_hash):
                _reject("Source/compiler changed before publication", "E_CPP_OWNED_RACE")
            os.link(staged, output)
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
        roles = ["injected_class_name", "exclusive_byte_pointer", "buffer_extent", "public_access",
                 "fallible_zeroed_allocation_with_post_allocation_rejection", "exclusive_move_and_source_reset",
                 "deleted_copy_constructor", "deleted_copy_assignment", "deleted_move_assignment",
                 "array_destructor", "extent_read", "borrowed_read_view", "byte_fill", "byte_get", "byte_set"]
        members = cls.get("inner", [])
        inventory = [{"kind": member["kind"], "name": member.get("name"), "clang_id": member.get("id"),
                      "role": role, "disposition": "translated" if role not in {
                          "injected_class_name", "public_access", "deleted_copy_constructor",
                          "deleted_copy_assignment", "deleted_move_assignment"} else "checked_protocol_constraint"}
                     for member, role in zip(members, roles)]
        if len(members) != len(roles):
            raise AssertionError("Compiler-owned protocol inventory mismatch")
        report.update(ok=True, status="owned_implementation_and_lifecycle_translated", source_sha256=_sha(original),
                      output_sha256=_sha(rendered.encode()), hepta_compiler_sha256=hepta_hash,
                      target_model={**model, "compiler_sha256": native_hash}, class_name=name,
                      lifecycle_function=operation["name"], declaration_inventory=inventory,
                      source_declarations=2, converted_source_declarations=2, unconverted_members=[],
                      complete_ast_nodes=sum(1 for _ in _nodes(tree)), complete_ast_sha256=_sha(_canonical(normalized)),
                      protocol_ast_sha256=_sha(_canonical(expected)), protocol_source_sha256=_sha(protocol_cpp.encode()),
                      protocol_verified=True, hepta_checks=checks, resource_ir=graph, resource_verification=verification,
                      moved_from_policy="source_reset_to_null_zero_is_not_observable_in_accepted_lifecycle;_Hepta_source_is_consumed",
                      exception_mapping={"allocation_failure": 1, "post_allocation_constructor_rejection": 2},
                      selected_resource_raii_translated=True, lifecycle_early_exits_translated=True,
                      foreign_cpp_calls=0, native_traits={"copy_constructible": False, "nothrow_move_constructible": True,
                          "nothrow_destructible": True, "trivially_destructible": False},
                      limitations=["Only the complete closed owner and lifecycle protocol is admitted.",
                          "Source moved-from inspection, pointer escape, custom allocators and arbitrary cleanup code are rejected.",
                          "C++ exceptions become explicit Result errors; C++ class ABI and general source equivalence are not claimed.",
                          "Output uses checked Buffer bounds; undefined source out-of-bounds access is outside the domain."])
        return report
    except (MigrationRejected, ResourceIRError, OSError, ValueError, UnicodeError) as error:
        report["diagnostics"].append({"code": getattr(error, "code", "E_CPP_OWNED_INPUT"), "message": str(error)})
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clangxx", default="clang++")
    args = parser.parse_args()
    report = migrate_cpp_owned(args.source, args.output, clangxx=args.clangxx)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 2

# Versioned compiler rules, deliberately independent of editable examples.
# The complete native AST of these rules is compared, including every body,
# declaration reference, operator, cast, literal, qualifier and cleanup edge.
_CPP_PROTOCOL = r'''// Complete source profile: one exclusive zero-initialized byte-array owner.
class OwnedBytes {
    unsigned char* data_;
    unsigned long size_;
public:
    OwnedBytes(unsigned long size, bool reject)
        : data_(size == 0 ? nullptr : new unsigned char[size]{}), size_(size) {
        if (reject) {
            delete[] data_;
            data_ = nullptr;
            size_ = 0;
            throw 2;
        }
    }
    OwnedBytes(OwnedBytes&& other) noexcept : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }
    OwnedBytes(const OwnedBytes&) = delete;
    OwnedBytes& operator=(const OwnedBytes&) = delete;
    OwnedBytes& operator=(OwnedBytes&&) = delete;
    ~OwnedBytes() noexcept { delete[] data_; }

    unsigned long size() const noexcept { return size_; }
    const unsigned char* data() const noexcept { return data_; }
    void fill(unsigned char value) noexcept {
        for (unsigned long i = 0; i < size_; ++i) { data_[i] = value; }
    }
    unsigned char get(unsigned long index) const noexcept { return data_[index]; }
    void set(unsigned long index, unsigned char value) noexcept { data_[index] = value; }
};

unsigned long long run_owned(unsigned long size, unsigned char value, unsigned long index,
                             bool reject_constructor, bool early) noexcept {
    try {
        OwnedBytes first(size, reject_constructor);
        first.fill(value);
        if (size != 0) { first.set(0, value ^ 90); }
        OwnedBytes second(static_cast<OwnedBytes&&>(first));
        if (early) { return 2002; }
        if (index >= second.size()) { return 2003; }
        const unsigned char* borrowed = second.data();
        return static_cast<unsigned long long>(borrowed[index]) + second.get(index) + second.size();
    } catch (int code) {
        return 1000 + static_cast<unsigned long long>(code);
    } catch (...) {
        return 1001;
    }
}
'''
_HEPTA_PROTOCOL = r'''module cpp_owned_migrated;

pub struct OwnedBytes { data: Buffer<u8> }

pub fn OwnedBytes_new(size: usize, reject: bool) -> Result<OwnedBytes, u8> effects {alloc, block} {
    match try_buffer(size) {
        Result::Err(code) => { return Result::Err(code); },
        Result::Ok(bytes) => {
            if reject {
                drop(move bytes);
                return Result::Err(2);
            }
            return Result::Ok(OwnedBytes {data: move bytes});
        },
    }
}

pub fn OwnedBytes_move(owner: take OwnedBytes) -> OwnedBytes effects {} {
    return move owner;
}

pub fn OwnedBytes_drop(owner: take OwnedBytes) -> Unit effects {alloc, block} {
    drop(move owner);
}

pub fn OwnedBytes_size(owner: read OwnedBytes) -> usize effects {} {
    return len(owner.data);
}

pub fn OwnedBytes_data(owner: read OwnedBytes) -> read [u8] from owner effects {} {
    return read owner.data;
}

pub fn OwnedBytes_fill(owner: mut OwnedBytes, value: u8) -> Unit effects {panic, write} {
    for index in 0..len(owner.data) { owner.data[index] = value; }
}

pub fn OwnedBytes_get(owner: read OwnedBytes, index: usize) -> u8 effects {panic} {
    return owner.data[index];
}

pub fn OwnedBytes_set(owner: mut OwnedBytes, index: usize, value: u8) -> Unit effects {panic, write} {
    owner.data[index] = value;
}

pub fn run_owned(size: usize, value: u8, index: usize, reject_constructor: bool, early: bool) -> u64
effects {alloc, block, panic, write} {
    match OwnedBytes_new(size, reject_constructor) {
        Result::Err(code) => { return 1000 + code as u64; },
        Result::Ok(created) => {
            let mut first = move created;
            OwnedBytes_fill(mut first, value);
            if size != 0 { OwnedBytes_set(mut first, 0, value ^ 90); }
            let second = OwnedBytes_move(move first);
            if early {
                OwnedBytes_drop(move second);
                return 2002;
            }
            if index >= OwnedBytes_size(read second) {
                OwnedBytes_drop(move second);
                return 2003;
            }
            let answer = OwnedBytes_data(read second)[index] as u64
                + OwnedBytes_get(read second, index) as u64 + OwnedBytes_size(read second) as u64;
            OwnedBytes_drop(move second);
            return answer;
        },
    }
}
'''

if __name__ == '__main__':
    raise SystemExit(main())

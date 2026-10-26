"""Direct checked Hepta AST -> LLVM for the bounded owned-byte host profile.

The separate resource verifier checks the source-derived ownership graph.
Numerical and control-flow lowering uses the same checked AST, because that
graph deliberately abstracts scalar values. Neither Rust nor C generated code
is used to produce this module. This is not a backend refinement proof.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import tempfile

from .ast import Enum, EnumVariant, Type
from .borrowed_storage import has_borrowed_storage
from .checker import is_owned_type, substitute_type
from .llvm_ssa_backend import _clang_run
from .pipeline import compiler_hash
from .resource_ir import verify_resource_ir
from .artifact_publication import PublicationRejected, publish_verified
from .resource_lowering import lower_resource_ir
from .semantic_ir import lower_checked_program
from .elf_shared_abi import ELFSharedABIRejected, inspect_owned_shared_elf

PROFILE = "hepta.llvm-owned-bytes-host.v1"
TARGET = "x86_64-unknown-linux-gnu"
INTS = {**{"u" + str(n): n for n in (8, 16, 32, 64)},
        **{"i" + str(n): n for n in (8, 16, 32, 64)}, "usize": 64, "isize": 64}
SCALARS = set(INTS) | {"bool", "Unit"}
BUFFER = Type("Buffer", (Type("u8"),))
ALLOCATION_RESULT = Type("Result", (BUFFER, Type("u8")))
_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


class LLVMOwnedRejected(ValueError):
    pass


def reject(message, code="E_LLVM_OWNED_PROFILE"):
    raise LLVMOwnedRejected(code + ": " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _hash(value):
    return sha256(value).hexdigest()


def _type_budget(typ):
    pending, nodes = [(typ, 0)], 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if not isinstance(current, Type) or depth > 32 or nodes > 4096:
            reject("Concrete type exceeds the 32-level/4096-node limit", "E_LLVM_OWNED_LIMIT")
        pending.extend((child, depth + 1) for child in current.args)


@dataclass(frozen=True)
class OwnedLLVM:
    text: str
    sha256: str
    semantic_sha256: str
    resource_ir_sha256: str
    resource_verification_sha256: str
    compiler_sha256: str
    functions: tuple[str, ...]
    specializations: tuple[str, ...]
    profile: str = PROFILE

    def check_identity(self):
        if (self.profile != PROFILE or not isinstance(self.text, str)
                or not self.text.isascii() or len(self.text) > 8 * 1024 * 1024
                or _hash(self.text.encode()) != self.sha256):
            reject("LLVM text/profile identity differs", "E_LLVM_OWNED_IDENTITY")
        for value in (self.semantic_sha256, self.resource_ir_sha256,
                      self.resource_verification_sha256, self.compiler_sha256):
            if not isinstance(value, str) or re.fullmatch("[0-9a-f]{64}", value) is None:
                reject("Missing exact source/verification identity", "E_LLVM_OWNED_IDENTITY")


@dataclass
class _Slot:
    typ: Type
    pointer: str
    mode: str = "value"


class _Function:
    """Entry allocas, explicit blocks and fresh SSA temporaries within a body."""
    def __init__(self, emitter, declaration, arguments):
        self.e = emitter
        self.fn = declaration
        self.mapping = dict(zip(declaration.type_params, arguments))
        self.env = {}
        self.allocas = []
        self.lines = []
        self.counter = 0
        self.block_counter = 0
        self.current = "entry"
        self.terminated = False
        self.return_type = self.resolve(declaration.return_type)
        self.return_slot = self.e.uses_return_slot(self.return_type, declaration.return_mode)
        for index, parameter in enumerate(declaration.params):
            typ = self.resolve(parameter.type)
            value = "%arg" + str(index)
            if parameter.mode in {"read", "mut"} and typ.name != "slice":
                self.env[parameter.name] = _Slot(typ, value, parameter.mode)
            else:
                slot = self.slot(typ, parameter.mode)
                self.store(typ, value, slot.pointer)
                self.env[parameter.name] = slot

    def resolve(self, typ):
        return substitute_type(typ, self.mapping)

    def typ(self, expression):
        original = self.e.checked.expr_types.get(id(expression))
        if original is None:
            reject("Expression is not part of this exact checked AST", "E_LLVM_OWNED_TYPE")
        typ = self.resolve(original)
        self.e.typ(typ)
        return typ

    def reg(self):
        self.counter += 1
        return "%v" + str(self.counter)

    def emit(self, instruction):
        if self.terminated:
            reject("Instruction after a terminator", "E_LLVM_OWNED_CFG")
        self.lines.append("  " + instruction)

    def result(self, instruction):
        name = self.reg()
        self.emit(name + " = " + instruction)
        return name

    def label(self, prefix="block"):
        self.block_counter += 1
        return prefix + str(self.block_counter)

    def start(self, label):
        if not self.terminated:
            reject("Missing block terminator", "E_LLVM_OWNED_CFG")
        self.lines.append(label + ":")
        self.current, self.terminated = label, False

    def terminate(self, instruction):
        self.emit(instruction)
        self.terminated = True

    def slot(self, typ, mode="value"):
        pointer = self.reg()
        self.allocas.append("  " + pointer + " = alloca " + self.e.typ(typ))
        return _Slot(typ, pointer, mode)

    def load(self, typ, pointer):
        native = self.e.typ(typ)
        return self.result("load " + native + ", ptr " + pointer)

    def store(self, typ, value, pointer):
        self.emit("store " + self.e.typ(typ) + " " + value + ", ptr " + pointer)

    def store_return(self, value):
        native = self.e.typ(self.return_type)
        for indices, field_native in self.e.return_fields(self.return_type):
            suffix = ", ".join(map(str, indices))
            field = self.result(f"extractvalue {native} {value}, " + suffix)
            pointer = self.result(f"getelementptr {native}, ptr %out, i32 0, "
                                  + ", ".join("i32 " + str(index) for index in indices))
            self.emit(f"store {field_native} {field}, ptr {pointer}")

    def guard(self, condition):
        good, bad = self.label("checked"), self.label("abort")
        self.terminate(f"br i1 {condition}, label %{good}, label %{bad}")
        self.start(bad)
        self.emit("call void @abort()")
        self.terminate("unreachable")
        self.start(good)

    def extract(self, typ, value, indices):
        return self.result("extractvalue " + self.e.typ(typ) + " " + value + ", " + ", ".join(map(str, indices)))

    def insert(self, typ, value, field_type, field_value, indices):
        return self.result("insertvalue " + self.e.typ(typ) + " " + value + ", "
                           + self.e.typ(field_type) + " " + field_value + ", " + ", ".join(map(str, indices)))

    def field_pointer(self, typ, pointer, index):
        return self.result(f"getelementptr {self.e.typ(typ)}, ptr {pointer}, i32 0, i32 {index}")

    def nonmutating_index(self, expression):
        if expression.kind == "call" and expression.value in self.e.functions:
            fn = self.e.functions[expression.value]
            if (fn.effects | self.e.checked.effects.get(fn.name, set())) - {"panic"}:
                reject("Effectful nested index calls are outside this closed profile")
        for child in expression.children:
            self.nonmutating_index(child)

    def place(self, expression):
        kind = expression.kind
        if kind == "name" and expression.value in self.env:
            return self.env[expression.value].pointer
        if kind == "field":
            base = expression.children[0]
            typ = self.typ(base)
            fields = self.e.fields(typ)
            index = next((i for i, p in enumerate(fields) if p.name == expression.value), None)
            if index is None:
                reject("Unknown concrete struct field", "E_LLVM_OWNED_PLACE")
            return self.field_pointer(typ, self.place(base), index)
        if kind == "index":
            base, offset = expression.children
            self.nonmutating_index(offset)
            data, length = self.sequence(base)
            index = self.value(offset)
            if self.typ(offset) != Type("usize"):
                reject("Byte indices must have the checked usize type")
            self.guard(self.result(f"icmp ult i64 {index}, {length}"))
            return self.result(f"getelementptr i8, ptr {data}, i64 {index}")
        if kind == "call" and expression.value in self.e.functions:
            fn = self.e.functions[expression.value]
            if fn.return_mode != "value" and self.typ(expression).name != "slice":
                return self.call(expression)
        reject("Operation requires a named or immediately returned place", "E_LLVM_OWNED_PLACE")

    def sequence(self, expression):
        if expression.kind == "unary" and expression.value in {"read", "mut"}:
            expression = expression.children[0]
        typ = self.typ(expression)
        if typ not in {BUFFER, Type("slice", (Type("u8"),))}:
            reject("Only Buffer<u8> and borrowed [u8] sequences are supported")
        if expression.kind == "call":
            fn = self.e.functions.get(expression.value)
            if fn is None or fn.return_mode == "value":
                reject("A sequence call must return a checked immediate borrow")
            result = self.call(expression)
            value = result if typ.name == "slice" else self.load(typ, result)
        else:
            value = self.load(typ, self.place(expression))
        return self.extract(typ, value, (0,)), self.extract(typ, value, (1,))

    def borrow(self, expression, expected):
        child = expression.children[0] if expression.kind == "unary" and expression.value in {"read", "mut"} else expression
        if expected.name == "slice":
            data, length = self.sequence(child)
            value = self.result("insertvalue %hepta.bytes zeroinitializer, ptr " + data + ", 0")
            return self.result("insertvalue %hepta.bytes " + value + ", i64 " + length + ", 1")
        return self.place(child)

    def call(self, expression):
        fn = self.e.functions[expression.value]
        arguments = tuple(self.resolve(t) for t in expression.type_args)
        target = self.e.instance(fn, arguments)
        mapping = dict(zip(fn.type_params, arguments))
        values = []
        for child, parameter in zip(expression.children, fn.params):
            typ = substitute_type(parameter.type, mapping)
            value = self.borrow(child, typ) if parameter.mode in {"read", "mut"} else self.value(child)
            native = self.e.parameter_type(typ, parameter.mode)
            extension = self.e.extension(typ) if fn.export_c else ""
            values.append(native + extension + " " + value)
        returns = substitute_type(fn.return_type, mapping)
        if self.e.uses_return_slot(returns, fn.return_mode):
            output = self.slot(returns)
            values.insert(0, f"ptr sret({self.e.typ(returns)}) {output.pointer}")
            self.emit(f"call void @{target}(" + ", ".join(values) + ")")
            return self.load(returns, output.pointer)
        result_type = self.e.return_type(returns, fn.return_mode)
        extension = self.e.extension(returns).strip() + " " if fn.export_c and self.e.extension(returns) else ""
        instruction = f"call {extension}{result_type} @{target}(" + ", ".join(values) + ")"
        if result_type == "void":
            self.emit(instruction)
            return "0"
        return self.result(instruction)

    def checked_arithmetic(self, typ, operation, left, right):
        bits = INTS[typ.name]
        native = self.e.typ(typ)
        signed = typ.name.startswith("i")
        if operation in {"+", "-", "*"}:
            name = "llvm." + ("s" if signed else "u") + {"+": "add", "-": "sub", "*": "mul"}[operation] + ".with.overflow.i" + str(bits)
            self.e.intrinsics.add((name, bits))
            pair = self.result(f"call {{{native}, i1}} @{name}({native} {left}, {native} {right})")
            value = self.result(f"extractvalue {{{native}, i1}} {pair}, 0")
            overflow = self.result(f"extractvalue {{{native}, i1}} {pair}, 1")
            self.guard(self.result(f"xor i1 {overflow}, true"))
            return value
        if operation in {"/", "%"}:
            valid = self.result(f"icmp ne {native} {right}, 0")
            if signed:
                minimum = self.result(f"icmp eq {native} {left}, {-2**(bits-1)}")
                minus_one = self.result(f"icmp eq {native} {right}, -1")
                overflow = self.result(f"and i1 {minimum}, {minus_one}")
                valid = self.result(f"and i1 {valid}, " + self.result(f"xor i1 {overflow}, true"))
            self.guard(valid)
            instruction = ("s" if signed else "u") + ("div" if operation == "/" else "rem")
        elif operation in {"<<", ">>"}:
            self.guard(self.result(f"icmp ult {native} {right}, {bits}"))
            instruction = "shl" if operation == "<<" else "ashr" if signed else "lshr"
        else:
            instruction = {"&": "and", "|": "or", "^": "xor"}.get(operation)
            if instruction is None:
                reject("Unimplemented integer operation " + str(operation))
        return self.result(f"{instruction} {native} {left}, {right}")

    def value(self, expression):
        typ = self.typ(expression)
        kind, children = expression.kind, expression.children
        native = self.e.typ(typ)
        if kind == "int":
            if typ.name not in INTS:
                reject("Integer literal lacks a supported fixed-width type")
            return str(expression.value)
        if kind == "bool":
            return "true" if expression.value else "false"
        if kind == "name":
            if typ.name == "slice":
                reject("Borrowed slices cannot be copied as owned values")
            return "0" if typ.name == "Unit" else self.load(typ, self.place(expression))
        if kind in {"field", "index"}:
            if kind == "field" and children[0].kind not in {"name", "field", "call"}:
                base_type = self.typ(children[0])
                fields = self.e.fields(base_type)
                index = next(i for i, field in enumerate(fields) if field.name == expression.value)
                return self.extract(base_type, self.value(children[0]), (index,))
            return self.load(typ, self.place(expression))
        if kind == "unary":
            if expression.value in {"read", "mut"}:
                reject("Borrow syntax requires an argument/return/sequence position")
            child = children[0]
            if expression.value == "move":
                if is_owned_type(self.e.program, typ) and child.kind in {"name", "field"}:
                    pointer = self.place(child)
                    value = self.load(typ, pointer)
                    self.store(typ, "zeroinitializer", pointer)
                    return value
                return self.value(child)
            if expression.value == "-" and child.kind == "int":
                return str(-child.value)
            value = self.value(child)
            if expression.value == "+":
                return value
            if expression.value == "!":
                return self.result(f"xor {native} {value}, " + ("true" if typ.name == "bool" else "-1"))
            if expression.value == "-" and typ.name in INTS:
                return self.checked_arithmetic(typ, "-", "0", value)
            reject("Unimplemented unary operation")
        if kind == "binary":
            left = self.value(children[0])
            if expression.value in {"&&", "||"}:
                evaluated, skipped, end = self.label("logic"), self.label("skip"), self.label("join")
                first, second = (evaluated, skipped) if expression.value == "&&" else (skipped, evaluated)
                self.terminate(f"br i1 {left}, label %{first}, label %{second}")
                self.start(evaluated)
                right = self.value(children[1])
                right_block = self.current
                self.terminate("br label %" + end)
                self.start(skipped)
                self.terminate("br label %" + end)
                self.start(end)
                constant = "false" if expression.value == "&&" else "true"
                return self.result(f"phi i1 [ {right}, %{right_block} ], [ {constant}, %{skipped} ]")
            right = self.value(children[1])
            if expression.value in {"==", "!=", "<", "<=", ">", ">="}:
                operand = self.typ(children[0])
                prefix = "s" if operand.name.startswith("i") else "u"
                comparison = {"==": "eq", "!=": "ne", "<": prefix+"lt", "<=": prefix+"le",
                              ">": prefix+"gt", ">=": prefix+"ge"}[expression.value]
                return self.result(f"icmp {comparison} {self.e.typ(operand)} {left}, {right}")
            if typ.name in INTS:
                return self.checked_arithmetic(typ, expression.value, left, right)
            reject("Only supported integer/Boolean operations can be lowered")
        if kind == "cast":
            source = self.typ(children[0])
            if source.name not in INTS or typ.name not in INTS:
                reject("Only fixed-width integer casts are supported")
            value = self.value(children[0])
            before, after = INTS[source.name], INTS[typ.name]
            if before == after:
                return value
            operation = "trunc" if after < before else "sext" if source.name.startswith("i") else "zext"
            return self.result(f"{operation} {self.e.typ(source)} {value} to {native}")
        if kind == "struct":
            fields = self.e.fields(typ)
            values = [(name, child, self.value(child)) for name, child in zip(expression.value["fields"], children)]
            aggregate = "zeroinitializer"
            for name, child, value in values:
                index = next(i for i, field in enumerate(fields) if field.name == name)
                aggregate = self.insert(typ, aggregate, self.typ(child), value, (index,))
            return aggregate
        if kind == "variant":
            variants = self.e.variants(typ)
            index = next(i for i, (name, _) in enumerate(variants) if name == expression.value["variant"])
            values = [(self.typ(child), self.value(child)) for child in children]
            aggregate = self.insert(typ, "zeroinitializer", Type("u32"), str(index), (0,))
            for offset, (field, value) in enumerate(values):
                aggregate = self.insert(typ, aggregate, field, value, (index + 1, offset))
            return aggregate
        if kind == "call":
            name = expression.value
            if name in self.e.functions:
                fn = self.e.functions[name]
                result = self.call(expression)
                if fn.return_mode != "value":
                    if typ.name == "slice" or is_owned_type(self.e.program, typ):
                        reject("Returned owners/slices require immediate borrowed access")
                    return self.load(typ, result)
                return result
            if name in {"buffer", "try_buffer"}:
                size = self.value(children[0])
                output = self.slot(ALLOCATION_RESULT)
                self.emit(f"call void @__hepta_owned_try_buffer(ptr sret({self.e.typ(ALLOCATION_RESULT)}) "
                          + f"{output.pointer}, i64 {size})")
                result = self.load(ALLOCATION_RESULT, output.pointer)
                if name == "try_buffer":
                    return result
                tag = self.extract(ALLOCATION_RESULT, result, (0,))
                self.guard(self.result(f"icmp eq i32 {tag}, 0"))
                return self.extract(ALLOCATION_RESULT, result, (1, 0))
            if name in {"drop", "release"}:
                owner = self.typ(children[0])
                value = self.value(children[0])
                helper = self.e.drop(owner)
                self.emit(f"call void @{helper}({self.e.typ(owner)} {value})")
                return "0"
            if name == "len":
                return self.sequence(children[0])[1]
            if name == "assert":
                self.guard(self.value(children[0]))
                return "0"
            if name in {"wrapping_add", "wrapping_sub", "wrapping_mul", "min", "max"}:
                left, right = [self.value(child) for child in children]
                if name.startswith("wrapping_"):
                    operation = {"wrapping_add": "add", "wrapping_sub": "sub", "wrapping_mul": "mul"}[name]
                    return self.result(f"{operation} {native} {left}, {right}")
                comparison = ("s" if typ.name.startswith("i") else "u") + ("lt" if name == "min" else "gt")
                condition = self.result(f"icmp {comparison} {native} {left}, {right}")
                return self.result(f"select i1 {condition}, {native} {left}, {native} {right}")
            reject("Builtin " + str(name) + " has no implementation in this LLVM profile")
        reject("Expression " + str(kind) + " has no implementation in this LLVM profile")

    def block(self, statements):
        previous = dict(self.env)
        for statement in statements:
            if self.terminated:
                reject("Unreachable statements are not silently discarded", "E_LLVM_OWNED_CFG")
            kind, data = statement.kind, statement.data
            if kind == "let":
                value = self.value(data["expr"])
                typ = self.resolve(data["type"]) if data.get("type") else self.typ(data["expr"])
                slot = self.slot(typ)
                self.store(typ, value, slot.pointer)
                self.env[data["name"]] = slot
            elif kind == "assign":
                value = self.value(data["expr"])
                self.store(self.typ(data["target"]), value, self.place(data["target"]))
            elif kind == "expr":
                self.value(data["expr"])
            elif kind == "return":
                if self.fn.return_mode != "value":
                    value = self.borrow(data["expr"], self.return_type)
                    if self.return_slot:
                        self.store_return(value)
                        self.terminate("ret void")
                    else:
                        self.terminate("ret " + self.e.return_type(self.return_type, self.fn.return_mode) + " " + value)
                elif self.return_type.name == "Unit":
                    if data.get("expr") is not None:
                        self.value(data["expr"])
                    self.terminate("ret void")
                else:
                    value = self.value(data["expr"])
                    if self.return_slot:
                        self.store_return(value)
                        self.terminate("ret void")
                    else:
                        self.terminate("ret " + self.e.typ(self.return_type) + " " + value)
            elif kind == "if":
                condition = self.value(data["condition"])
                yes, no, end = self.label("then"), self.label("else"), self.label("join")
                self.terminate(f"br i1 {condition}, label %{yes}, label %{no}")
                self.start(yes)
                self.block(data["then"])
                yes_live = not self.terminated
                if yes_live:
                    self.terminate("br label %" + end)
                self.start(no)
                self.block(data.get("else", []))
                no_live = not self.terminated
                if no_live:
                    self.terminate("br label %" + end)
                if yes_live or no_live:
                    self.start(end)
            elif kind in {"while", "for"}:
                head, body, end = self.label("loop"), self.label("body"), self.label("exit")
                if kind == "for":
                    begin, stop = self.value(data["start"]), self.value(data["end"])
                    typ = self.typ(data["start"])
                    slot = self.slot(typ)
                    self.store(typ, begin, slot.pointer)
                    self.env[data["name"]] = slot
                self.terminate("br label %" + head)
                self.start(head)
                if kind == "while":
                    condition = self.value(data["condition"])
                else:
                    current = self.load(typ, slot.pointer)
                    comparison = "slt" if typ.name.startswith("i") else "ult"
                    condition = self.result(f"icmp {comparison} {self.e.typ(typ)} {current}, {stop}")
                self.terminate(f"br i1 {condition}, label %{body}, label %{end}")
                self.start(body)
                self.block(data["body"])
                if not self.terminated:
                    if kind == "for":
                        current = self.load(typ, slot.pointer)
                        advance = self.result(f"add {self.e.typ(typ)} {current}, 1")
                        self.store(typ, advance, slot.pointer)
                    self.terminate("br label %" + head)
                self.start(end)
                if kind == "for":
                    self.env.pop(data["name"], None)
            elif kind == "match":
                typ = self.typ(data["expr"])
                value = self.value(data["expr"])
                tag = self.extract(typ, value, (0,))
                variants = self.e.variants(typ)
                labels = [self.label("variant") for _ in variants]
                invalid, end = self.label("invalid"), self.label("join")
                self.terminate("switch i32 " + tag + ", label %" + invalid + " [ "
                               + " ".join(f"i32 {i}, label %{label}" for i, label in enumerate(labels)) + " ]")
                self.start(invalid)
                self.emit("call void @abort()")
                self.terminate("unreachable")
                live = False
                for arm in data["arms"]:
                    index = next(i for i, (name, _) in enumerate(variants) if name == arm.pattern.variant)
                    self.start(labels[index])
                    saved = dict(self.env)
                    for offset, (name, field) in enumerate(zip(arm.pattern.bindings, variants[index][1])):
                        if name != "_":
                            field_value = self.extract(typ, value, (index + 1, offset))
                            slot = self.slot(field)
                            self.store(field, field_value, slot.pointer)
                            self.env[name] = slot
                    self.block(arm.body)
                    self.env = saved
                    if not self.terminated:
                        self.terminate("br label %" + end)
                        live = True
                if live:
                    self.start(end)
            else:
                reject("Statement " + str(kind) + " is outside this LLVM profile")
        self.env = previous

    def render(self, name):
        self.block(self.fn.body or [])
        if not self.terminated:
            if self.return_type.name != "Unit" or self.fn.return_mode != "value":
                reject("A non-Unit function has a continuing exit", "E_LLVM_OWNED_CFG")
            self.terminate("ret void")
        result = "void" if self.return_slot else self.e.return_type(self.return_type, self.fn.return_mode)
        extension = self.e.extension(self.return_type).strip() + " " if self.fn.export_c and self.e.extension(self.return_type) else ""
        parameters = [f"ptr noalias sret({self.e.typ(self.return_type)}) %out"] if self.return_slot else []
        for index, parameter in enumerate(self.fn.params):
            typ = self.resolve(parameter.type)
            ext = self.e.extension(typ) if self.fn.export_c else ""
            parameters.append(self.e.parameter_type(typ, parameter.mode) + ext + " %arg" + str(index))
        linkage = "" if self.fn.export_c else "internal "
        return (f"define {linkage}{extension}{result} @{name}(" + ", ".join(parameters) + ") {\nentry:\n"
                + "\n".join(self.allocas + self.lines) + "\n}\n")


class _Emitter:
    def __init__(self, program, checked):
        self.program, self.checked = program, checked
        self.functions = {fn.name: fn for fn in program.functions}
        self.structs = {st.name: st for st in program.structs}
        self.enums = {enum.name: enum for enum in program.enums}
        self.enums["Result"] = Enum("Result", [EnumVariant("Ok", [Type("A")]),
                                              EnumVariant("Err", [Type("B")])], ("A", "B"))
        self.types, self.definitions, self.active_types = {}, [], set()
        self.instances, self.pending = {}, []
        self.drops, self.drop_definitions = {}, []
        self.intrinsics = set()
        if not checked.ok or has_borrowed_storage(program):
            reject("A checked program without stored lifetime records is required")
        for fn in program.functions:
            if (fn.extern_c or fn.body is None or fn.lifetime_params or fn.resources
                    or (fn.effects | checked.effects.get(fn.name, set())) - {"alloc", "block", "panic", "write"}):
                reject("Foreign/task/I/O/lifetime/resource-clause functions are outside the closed profile")
            if fn.export_c:
                boundary = [parameter.type for parameter in fn.params] + [fn.return_type]
                if (fn.type_params or fn.return_mode != "value" or any(p.mode != "value" for p in fn.params)
                        or any(t.name not in SCALARS or t.args or t.name == "bool" for t in boundary)
                        or any(p.type.name == "Unit" for p in fn.params)
                        or not _NAME.fullmatch(fn.name) or fn.name.startswith("__hepta_owned_")
                        or fn.name in {"calloc", "malloc", "free", "abort"}):
                    reject("Only ordinary scalar exported C signatures are admitted")
        for declaration in program.structs:
            if declaration.repr_c or declaration.lifetime_params:
                reject("Resource structs have internal layout only")

    @staticmethod
    def extension(typ):
        if typ.name in {"i8", "i16"}:
            return " signext"
        if typ.name in {"u8", "u16", "bool"}:
            return " zeroext"
        return ""

    def fields(self, typ):
        st = self.structs.get(typ.name)
        if st is None or len(st.type_params) != len(typ.args):
            reject("Expected a finite concrete struct layout", "E_LLVM_OWNED_TYPE")
        mapping = dict(zip(st.type_params, typ.args))
        return [replace(field, type=substitute_type(field.type, mapping)) for field in st.fields]

    def variants(self, typ):
        enum = self.enums.get(typ.name)
        if enum is None or len(enum.type_params) != len(typ.args):
            reject("Expected a finite concrete enum layout", "E_LLVM_OWNED_TYPE")
        mapping = dict(zip(enum.type_params, typ.args))
        return [(variant.name, [substitute_type(field, mapping) for field in variant.fields])
                for variant in enum.variants]

    def typ(self, typ):
        _type_budget(typ)
        if typ.lifetimes:
            reject("Stored lifetime values are outside the LLVM profile", "E_LLVM_OWNED_TYPE")
        if typ.name in INTS and not typ.args:
            return "i" + str(INTS[typ.name])
        if typ.name in {"bool", "Unit"} and not typ.args:
            return "i1" if typ.name == "bool" else "i8"
        if typ in {BUFFER, Type("slice", (Type("u8"),))}:
            return "%hepta.bytes"
        if typ in self.active_types:
            reject("Recursive by-value native layout", "E_LLVM_OWNED_TYPE")
        if typ in self.types:
            return self.types[typ]
        if len(self.types) >= 256 or len(str(typ)) > 4096 or len(self.active_types) >= 32:
            reject("Concrete LLVM type budget exceeded", "E_LLVM_OWNED_LIMIT")
        name = "%hepta.type" + str(len(self.types))
        self.types[typ] = name
        self.active_types.add(typ)
        if typ.name in self.structs:
            parts = [self.typ(field.type) for field in self.fields(typ)] or ["i8"]
        elif typ.name in self.enums:
            parts = ["i32"] + ["{ " + ", ".join(self.typ(field) for field in fields or [Type("u8")]) + " }"
                               for _, fields in self.variants(typ)]
        else:
            reject("Unsupported concrete native type " + str(typ), "E_LLVM_OWNED_TYPE")
        self.active_types.remove(typ)
        self.definitions.append(name + " = type { " + ", ".join(parts) + " }")
        return name

    def parameter_type(self, typ, mode):
        self.typ(typ)
        if mode in {"read", "mut"}:
            return "%hepta.bytes" if typ.name == "slice" else "ptr"
        if typ.name == "slice":
            reject("Unsized slice value parameters are unsupported")
        return self.typ(typ)

    def return_type(self, typ, mode):
        if mode != "value":
            return self.parameter_type(typ, mode)
        return "void" if typ.name == "Unit" else self.typ(typ)

    @staticmethod
    def uses_return_slot(typ, mode):
        # Resource aggregates have an internal ABI only. A fresh caller slot
        # lets SROA track enum discriminants and payload fields independently
        # across inlined returns, instead of merging opaque aggregate values.
        # For returned slices, noalias applies only to the result-slot storage;
        # the slice's data pointer continues to borrow the caller's owner.
        return typ.name not in SCALARS if mode == "value" else typ.name == "slice"

    def return_fields(self, typ):
        # Write return fields separately. An aggregate store can be sunk
        # behind a whole-aggregate phi before inlining, obscuring even a
        # constant Result discriminant from subsequent scalar optimization.
        fields = []
        def append(indices, native):
            if len(fields) >= 256:
                reject("Aggregate result exceeds the 256-leaf return-layout limit", "E_LLVM_OWNED_LIMIT")
            fields.append((indices, native))
        def visit(current, indices):
            if current.name in SCALARS:
                append(indices, self.typ(current))
            elif current in {BUFFER, Type("slice", (Type("u8"),))}:
                append(indices + (0,), "ptr")
                append(indices + (1,), "i64")
            elif current.name in self.structs:
                members = self.fields(current)
                for index, field in enumerate(members):
                    visit(field.type, indices + (index,))
                if not members:
                    append(indices + (0,), "i8")
            elif current.name in self.enums:
                append(indices + (0,), "i32")
                for index, (_, members) in enumerate(self.variants(current)):
                    for offset, field in enumerate(members):
                        visit(field, indices + (index + 1, offset))
                    if not members:
                        append(indices + (index + 1, 0), "i8")
            else:
                reject("Unsupported aggregate result layout", "E_LLVM_OWNED_TYPE")
        visit(typ, ())
        return fields

    def instance(self, fn, arguments=()):
        arguments = tuple(arguments)
        if len(arguments) != len(fn.type_params):
            reject("Generic argument count differs", "E_LLVM_OWNED_SPECIALIZATION")
        for argument in arguments:
            _type_budget(argument)
        if any(len(str(t)) > 4096 for t in arguments):
            reject("Concrete generic argument budget exceeded", "E_LLVM_OWNED_LIMIT")
        key = (fn.name, arguments)
        if key not in self.instances:
            if len(self.instances) >= 256:
                reject("Finite LLVM specialization limit exceeded", "E_LLVM_OWNED_LIMIT")
            self.instances[key] = fn.name if fn.export_c else "__hepta_owned_fn" + str(len(self.instances))
            self.pending.append((fn, arguments))
        return self.instances[key]

    def drop(self, typ):
        if typ in self.drops:
            return self.drops[typ]
        name = "__hepta_owned_drop" + str(len(self.drops))
        native = self.typ(typ)
        self.drops[typ] = name
        lines = [f"define internal void @{name}({native} %owner) {{", "entry:"]
        serial = 0
        def child(field, indices):
            nonlocal serial
            if is_owned_type(self.program, field):
                serial += 1
                value = "%child" + str(serial)
                helper = self.drop(field)
                lines.append(f"  {value} = extractvalue {native} %owner, " + ", ".join(map(str, indices)))
                lines.append(f"  call void @{helper}({self.typ(field)} {value})")
        if typ == BUFFER:
            lines.extend(("  %data = extractvalue %hepta.bytes %owner, 0",
                          "  %allocated = icmp ne ptr %data, null",
                          "  br i1 %allocated, label %release, label %empty",
                          "release:", "  call void @free(ptr %data)", "  ret void",
                          "empty:", "  ret void"))
        elif typ.name in self.structs:
            for index, field in enumerate(self.fields(typ)):
                child(field.type, (index,))
            lines.append("  ret void")
        elif typ.name in self.enums:
            variants = self.variants(typ)
            lines.append(f"  %tag = extractvalue {native} %owner, 0")
            lines.append("  switch i32 %tag, label %invalid [ " +
                         " ".join(f"i32 {i}, label %variant{i}" for i in range(len(variants))) + " ]")
            for index, (_, fields) in enumerate(variants):
                lines.append(f"variant{index}:")
                for offset, field in enumerate(fields):
                    child(field, (index + 1, offset))
                lines.append("  ret void")
            lines.extend(("invalid:", "  call void @abort()", "  unreachable"))
        else:
            reject("Drop requires a supported concrete owner")
        self.drop_definitions.append("\n".join(lines) + "\n}\n")
        return name

    def allocation_runtime(self):
        result = self.typ(ALLOCATION_RESULT)
        return f"""
define internal noalias ptr @__hepta_owned_allocate(i64 %size) noinline optnone {{
entry:
  %data = call ptr @malloc(i64 %size) nobuiltin
  ret ptr %data
}}
define internal void @__hepta_owned_try_buffer(ptr noalias sret({result}) %out, i64 %size) {{
entry:
  %tagptr = getelementptr {result}, ptr %out, i32 0, i32 0
  %dataptr = getelementptr {result}, ptr %out, i32 0, i32 1, i32 0, i32 0
  %lenptr = getelementptr {result}, ptr %out, i32 0, i32 1, i32 0, i32 1
  %errptr = getelementptr {result}, ptr %out, i32 0, i32 2, i32 0
  %oversized = icmp ugt i64 %size, 9223372036854775807
  br i1 %oversized, label %failure, label %check_zero
check_zero:
  %zero = icmp eq i64 %size, 0
  br i1 %zero, label %empty, label %allocate
empty:
  store i32 0, ptr %tagptr
  store ptr null, ptr %dataptr
  store i64 0, ptr %lenptr
  store i8 0, ptr %errptr
  ret void
allocate:
  %data = call ptr @__hepta_owned_allocate(i64 %size)
  %failed = icmp eq ptr %data, null
  br i1 %failed, label %failure, label %success
success:
  call void @llvm.memset.p0.i64(ptr %data, i8 0, i64 %size, i1 false)
  store i32 0, ptr %tagptr
  store ptr %data, ptr %dataptr
  store i64 %size, ptr %lenptr
  store i8 0, ptr %errptr
  ret void
failure:
  store i32 1, ptr %tagptr
  store ptr null, ptr %dataptr
  store i64 0, ptr %lenptr
  store i8 1, ptr %errptr
  ret void
}}
"""

    def render(self):
        for declaration in self.program.structs:
            if not declaration.type_params:
                self.typ(Type(declaration.name))
        for declaration in self.program.enums:
            if not declaration.type_params:
                self.typ(Type(declaration.name))
        for fn in self.program.functions:
            if not fn.type_params:
                self.instance(fn)
        bodies, index = [], 0
        while index < len(self.pending):
            fn, arguments = self.pending[index]
            index += 1
            bodies.append(_Function(self, fn, arguments).render(self.instances[(fn.name, arguments)]))
        runtime = self.allocation_runtime()
        # Allocation is observably fallible in this profile. Preserve the
        # runtime calls even when a small constant buffer would otherwise be
        # folded away together with its failure branch by library inference.
        # Numeric/loop optimization remains enabled at -O3.
        # Allocation failure is observable, so retain the opaque malloc call.
        # Standard free releases storage; it does not observe its initialized
        # payload. Keep that library contract available to dead-store analysis.
        # No custom allocator/foreign deallocator is admitted by this profile.
        declarations = ['declare noalias ptr @malloc(i64) "no-builtins"',
                        'declare void @free(ptr)', "declare void @abort() noreturn",
                        "declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)"]
        declarations += [f"declare {{i{bits}, i1}} @{name}(i{bits}, i{bits})" for name, bits in sorted(self.intrinsics)]
        return (f'; {PROFILE}: directly emitted from checked Hepta, no C/Rust codegen\n'
                f'target triple = "{TARGET}"\n%hepta.bytes = type {{ ptr, i64 }}\n'
                + "\n".join(self.definitions + declarations) + "\n" + runtime
                + "\n".join(self.drop_definitions + bodies))


def emit_owned_llvm(program, checked, *, project_sha256=None):
    """Emit only after typed semantic and independent resource gates agree."""
    semantic = lower_checked_program(program, checked, project_sha256=project_sha256)
    if (semantic["all_expressions_typed"] is not True or semantic["untyped_expressions"]
            or semantic["external_obligations"] or semantic["foreign_assumptions"]):
        reject("Exact typed safe source without external assumptions is required", "E_LLVM_OWNED_SOURCE")
    graph = lower_resource_ir(program, checked, project_sha256=project_sha256)
    verification = verify_resource_ir(json.loads(_wire(graph)))
    if verification.get("ok") is not True or verification.get("external_obligations"):
        reject("Independent resource CFG verification rejected", "E_LLVM_OWNED_RESOURCE")
    emitter = _Emitter(program, checked)
    text = emitter.render()
    result = OwnedLLVM(text, _hash(text.encode()), semantic["sha256"], _hash(_wire(graph)),
                       _hash(_wire(verification)), compiler_hash(),
                       tuple(sorted(fn.name for fn in program.functions if fn.export_c)),
                       tuple(name for name in emitter.instances.values()))
    result.check_identity()
    return result


def compile_owned_llvm(ir, *, program, checked, output, project_sha256=None, clang="clang", kind="shared"):
    """Replay exact typed/resource source before native LLVM compilation."""
    if not isinstance(ir, OwnedLLVM):
        reject("OwnedLLVM object required", "E_LLVM_OWNED_ORIGIN")
    ir.check_identity()
    expected = emit_owned_llvm(program, checked, project_sha256=project_sha256)
    if ir != expected:
        reject("LLVM differs from freshly verified checked source", "E_LLVM_OWNED_ORIGIN")
    if kind not in {"shared", "object"}:
        reject("Only a host shared library or host object is supported")
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        reject("This resource runtime requires Linux x86_64", "E_LLVM_OWNED_HOST")
    found = shutil.which(clang)
    if found is None:
        reject("Native Clang required", "E_LLVM_OWNED_TOOLCHAIN")
    compiler = Path(found).resolve()
    version = _clang_run([str(compiler), "--version"], timeout=10)
    target = _clang_run([str(compiler), "-dumpmachine"], timeout=10)
    if (version.returncode or target.returncode or not version.stdout.strip()
            or target.stdout.strip() not in {TARGET, "x86_64-pc-linux-gnu"}
            or re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", version.stdout) is None):
        reject("A qualified Clang 20+ x86_64 Linux compiler is required", "E_LLVM_OWNED_TOOLCHAIN")
    destination = Path(os.path.abspath(output))
    if destination.is_symlink() or destination.exists() or not destination.parent.is_dir():
        reject("A new output in an existing directory is required", "E_LLVM_OWNED_OUTPUT")
    compiler_digest = _hash(compiler.read_bytes())
    with tempfile.TemporaryDirectory(prefix=".hepta-llvm-owned-", dir=destination.parent) as directory:
        source, artifact = Path(directory) / "module.ll", Path(directory) / ("native.so" if kind == "shared" else "native.o")
        source.write_text(ir.text)
        flags = ["--target=" + TARGET, "-x", "ir", "-O3", "-fPIC", "-shared" if kind == "shared" else "-c"]
        command = [str(compiler), *flags, str(source), "-o", str(artifact)]
        built = _clang_run(command, timeout=60)
        data = artifact.read_bytes() if artifact.is_file() else b""
        if built.returncode or not data:
            reject("Clang rejected LLVM: " + built.stderr[:3000], "E_LLVM_OWNED_NATIVE")
        from .llvm_ssa_target import _qualified_header
        if kind == "object" and not _qualified_header(data, TARGET):
            reject("Native object target identity differs", "E_LLVM_OWNED_ARTIFACT")
        if kind == "shared" and (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
                                  or int.from_bytes(data[16:18], "little") != 3
                                  or int.from_bytes(data[18:20], "little") != 62):
            reject("Native shared-library target identity differs", "E_LLVM_OWNED_ARTIFACT")
        dynamic_abi = None
        if kind == "shared":
            # ELF magic and ET_DYN are necessary, not an ABI inventory.
            # Read the actual loader's dynamic symbol/string table and reject
            # extra exports, foreign imports and invalid executable extents.
            try:
                dynamic_abi = inspect_owned_shared_elf(data, ir.functions)
            except ELFSharedABIRejected as exc:
                raise LLVMOwnedRejected(
                    "E_LLVM_OWNED_ARTIFACT: dynamic export/import identity rejected: " + str(exc)) from exc
        if _hash(compiler.read_bytes()) != compiler_digest or compiler_hash() != ir.compiler_sha256:
            reject("Compiler identity changed during native build", "E_LLVM_OWNED_STALE")
        try:
            publication = publish_verified(artifact, destination, data)
        except PublicationRejected as exc:
            reject(str(exc), "E_LLVM_OWNED_PUBLICATION")
    return {"schema": "hepta.llvm-owned-native.v1", "ok": True, "status": "native_compiled_not_executed",
            "profile": PROFILE, "kind": kind, "target": TARGET, "output": str(destination),
            "artifact_sha256": publication["sha256"], "artifact_bytes": publication["bytes"],
            "dynamic_abi": dynamic_abi,
            "llvm_ir_sha256": ir.sha256, "semantic_sha256": ir.semantic_sha256,
            "resource_ir_sha256": ir.resource_ir_sha256,
            "resource_verification_sha256": ir.resource_verification_sha256,
            "compiler_sha256": ir.compiler_sha256,
            "toolchain": {"path": str(compiler), "sha256": compiler_digest,
                          "version": version.stdout.splitlines()[0], "default_target": target.stdout.strip()},
            "flags": flags, "claims": {"checked_ast_resource_origin_replayed": True,
                "rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False,
                "native_execution_qualified": False, "backend_refinement_proved": False,
                "whole_language_memory_safety_proved": False, "cross_target_execution_qualified": False}}

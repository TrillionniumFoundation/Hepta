"""Bounded syntax allowlist for the scalar SSA LLVM text compilation boundary.

A checked digest alone does not prove an LLVM payload came from verified SSA.
This confines exposed compiler APIs to the emitter's reviewed instruction set.
It does NOT establish SSA provenance, memory-model soundness, or equivalence.
"""
from __future__ import annotations

import re

HEADER = "; Hepta strict scalar SSA/PHI native-LLVM pilot, not whole-language qualified."
DECLARATIONS = (
    "declare void @abort() noreturn",
    "declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32)",
    "declare { i32, i1 } @llvm.ssub.with.overflow.i32(i32, i32)",
    "declare { i32, i1 } @llvm.smul.with.overflow.i32(i32, i32)",
)
NAME = r"[A-Za-z_][A-Za-z0-9_]*"
REG = rf"%r_{NAME}_[0-9]+"
TEMP = r"%t[0-9]+"
ATOM = rf"(?:{REG}|{TEMP}|-?[0-9]+)"
LABEL = r"(?:b[0-9]{4}|bad_[0-9]+|cont_[0-9]+)"
DEFINITION = re.compile(rf"define i32 @({NAME})\(((?:i32 {REG}(?:, i32 {REG})*)?)\) \{{\Z")
BLOCK = re.compile(rf"({LABEL}):\Z")
PHI = re.compile(rf"  {REG} = phi i32 \[ {REG}, %{LABEL} \](?:, \[ {REG}, %{LABEL} \])*\Z")
BRANCH = re.compile(rf"  br i1 (?:{ATOM}|true|false), label %({LABEL}), label %({LABEL})\Z")
GOTO = re.compile(rf"  br label %({LABEL})\Z")
INSTRUCTIONS = (
    re.compile(rf"  {REG} = add i32 0, {ATOM}\Z"),
    re.compile(rf"  {TEMP} = call \{{ i32, i1 \}} @llvm\.(?:sadd|ssub|smul)\.with\.overflow\.i32\(i32 {ATOM}, i32 {ATOM}\)\Z"),
    re.compile(rf"  {TEMP} = extractvalue \{{ i32, i1 \}} {TEMP}, [01]\Z"),
    re.compile(rf"  {TEMP} = icmp (?:eq|ne|slt|sle|sgt|sge) i32 {ATOM}, {ATOM}\Z"),
    re.compile(rf"  ret i32 {ATOM}\Z"),
)


class LLVMProfileRejected(ValueError):
    """LLVM input contains a construct outside the reviewed scalar codegen profile."""


def validate_scalar_llvm_profile(source: str, functions: tuple[str, ...]) -> None:
    """Reject extra external calls, globals, pointers, memory, asm and metadata.

    Only the exact declared abort/overflow functions and known i32 CFG syntax
    are admissible. A surviving payload is still NOT proof of SSA origin.
    """
    if (not isinstance(source, str) or len(source.encode("utf-8")) > 4 * 1024 * 1024
            or not source.isascii() or "\r" in source or "\x00" in source
            or not source.endswith("\n") or not isinstance(functions, tuple)
            or not 0 < len(functions) <= 32 or tuple(sorted(set(functions))) != functions
            or any(re.fullmatch(NAME, fn) is None or fn == "abort" for fn in functions)):
        raise LLVMProfileRejected("E_LLVM_PROFILE_ID: invalid source/function inventory")
    lines = source.splitlines()
    if (len(lines) < 9 or lines[0] != HEADER
            or tuple(lines[1:5]) != DECLARATIONS or lines[5] != ""):
        raise LLVMProfileRejected("E_LLVM_PROFILE_HEADER: unexpected LLVM declarations or preamble")

    in_function, saw_label, terminated, phi_allowed = False, False, False, False
    labels: set[str] = set()
    referenced: set[str] = set()
    found: list[str] = []

    for line in lines[6:]:
        if not in_function:
            if not line:
                continue
            define = DEFINITION.fullmatch(line)
            if define is None or len(found) >= len(functions):
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: unexpected top-level definition")
            found.append(define.group(1))
            in_function, saw_label, terminated, phi_allowed = True, False, False, False
            labels, referenced = set(), set()
            continue
        if line == "}":
            if not saw_label or not terminated or not referenced <= labels:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: incomplete function or branch targets")
            in_function = False
            continue
        block = BLOCK.fullmatch(line)
        if block:
            if saw_label and not terminated:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: unterminated preceding basic block")
            name = block.group(1)
            if name in labels or len(labels) >= 4096:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: duplicate or oversized block")
            labels.add(name)
            saw_label, terminated, phi_allowed = True, False, True
            continue
        if not saw_label or terminated:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: instruction outside live block")
        if PHI.fullmatch(line):
            if not phi_allowed:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: PHI after non-PHI")
            continue
        phi_allowed = False
        branch = BRANCH.fullmatch(line)
        if branch:
            referenced.update(branch.groups())
            terminated = True
            continue
        goto = GOTO.fullmatch(line)
        if goto:
            referenced.add(goto.group(1))
            terminated = True
            continue
        if line == "  unreachable":
            terminated = True
            continue
        if line == "  call void @abort()":
            continue
        if any(rule.fullmatch(line) for rule in INSTRUCTIONS):
            if line.startswith("  ret "):
                terminated = True
            continue
        raise LLVMProfileRejected("E_LLVM_PROFILE_INSTRUCTION: unsupported instruction, external call or memory operation")

    if in_function or tuple(sorted(found)) != functions:
        raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: missing function end or inventory mismatch")

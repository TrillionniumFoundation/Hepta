"""Fail-closed grammar for the narrow checked-scalar SSA/PHI LLVM backend.

This protects public native compilation entrypoints from arbitrary rehashed
LLVM text. It is NOT a proof of source-to-LLVM refinement, SSA origin or general
LLVM verification; those are separate compiler and verifier obligations.
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
DEF = re.compile(rf"define i32 @({NAME})\(((?:i32 {REG}(?:, i32 {REG})*)?)\) \{{\Z")
LAB = re.compile(rf"({LABEL}):\Z")
PHI = re.compile(rf"  {REG} = phi i32 \[ {REG}, %{LABEL} \](?:, \[ {REG}, %{LABEL} \])*\Z")
BRANCH = re.compile(rf"  br i1 (?:{ATOM}|true|false), label %({LABEL}), label %({LABEL})\Z")
GOTO = re.compile(rf"  br label %({LABEL})\Z")
PATTERNS = (
    re.compile(rf"  {REG} = add i32 0, {ATOM}\Z"),
    re.compile(rf"  {TEMP} = call \{{ i32, i1 \}} @llvm\.(?:sadd|ssub|smul)\.with\.overflow\.i32\(i32 {ATOM}, i32 {ATOM}\)\Z"),
    re.compile(rf"  {TEMP} = extractvalue \{{ i32, i1 \}} {TEMP}, [01]\Z"),
    re.compile(rf"  {TEMP} = icmp (?:eq|ne|slt|sle|sgt|sge) i32 {ATOM}, {ATOM}\Z"),
    re.compile(rf"  ret i32 {ATOM}\Z"),
)


class LLVMProfileRejected(ValueError):
    """The LLVM text is outside the reviewed scalar code generation profile."""


def validate_scalar_llvm_profile(text: str, functions: tuple[str, ...]) -> None:
    """Reject all LLVM constructs not in the SSA emitter's finite vocabulary.

    Arbitrary globals, load/store/alloca, inline asm, extra declarations,
    foreign calls and unreviewed metadata cannot be admitted merely by
    recomputing a SHA-256 digest. CFG/SSA equivalence is NOT proved here.
    """
    if (not isinstance(text, str) or len(text.encode("utf-8")) > 4 * 1024 * 1024
            or not text.isascii() or "\r" in text or "\x00" in text
            or not text.endswith("\n") or not isinstance(functions, tuple)
            or not 0 < len(functions) <= 32 or tuple(sorted(set(functions))) != functions
            or any(re.fullmatch(NAME, name) is None or name == "abort"
                   for name in functions)):
        raise LLVMProfileRejected("E_LLVM_PROFILE_ID: malformed source or function identity")

    lines = text.splitlines()
    if (len(lines) < 9 or lines[0] != HEADER
            or tuple(lines[1:5]) != DECLARATIONS or lines[5] != ""):
        raise LLVMProfileRejected("E_LLVM_PROFILE_HEADER: unexpected LLVM preamble")

    in_function = False
    labels: set[str] = set()
    referenced: set[str] = set()
    found: list[str] = []
    saw_label = saw_terminator = allow_phi = False
    blocks = 0

    def close_function() -> None:
        if not saw_label or not saw_terminator or not referenced <= labels:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: missing terminator or unresolved branch")

    for line in lines[6:]:
        if not in_function:
            if not line:
                continue
            match = DEF.fullmatch(line)
            if match is None:
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: unexpected top-level LLVM content")
            found.append(match.group(1))
            if len(found) > len(functions):
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: too many functions")
            in_function, saw_label, saw_terminator, allow_phi = True, False, False, False
            labels, referenced, blocks = set(), set(), 0
            continue
        if line == "}":
            close_function()
            in_function = False
            continue
        match = LAB.fullmatch(line)
        if match:
            if saw_label and not saw_terminator:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: previous block lacks terminator")
            label = match.group(1)
            if label in labels or blocks >= 4096:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: duplicate or excess blocks")
            labels.add(label)
            blocks += 1
            saw_label, saw_terminator, allow_phi = True, False, True
            continue
        if not saw_label:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: instruction outside basic block")
        if saw_terminator:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: instruction after terminator")
        if PHI.fullmatch(line):
            if not allow_phi:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: PHI after ordinary instruction")
            continue
        allow_phi = False
        jump = BRANCH.fullmatch(line)
        if jump:
            referenced.update(jump.groups())
            saw_terminator = True
            continue
        jump = GOTO.fullmatch(line)
        if jump:
            referenced.add(jump.group(1))
            saw_terminator = True
            continue
        if line == "  unreachable":
            saw_terminator = True
            continue
        if line == "  call void @abort()":
            continue
        if any(pattern.fullmatch(line) for pattern in PATTERNS):
            if line.startswith("  ret "):
                saw_terminator = True
            continue
        raise LLVMProfileRejected("E_LLVM_PROFILE_INSTRUCTION: unreviewed or external LLVM instruction")
    if in_function or tuple(sorted(found)) != functions:
        raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: missing function or mismatched inventory")

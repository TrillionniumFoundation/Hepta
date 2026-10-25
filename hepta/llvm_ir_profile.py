"""Validate the *textual codegen profile* of Hepta's restricted scalar LLVM backend.

This confines compilable LLVM syntax. It does NOT establish source equivalence,
type soundness, or prove the LLVM text came from the independently checked SSA.
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
LABEL = r"(?:b[0-9]{4,}|bad_[0-9]+|cont_[0-9]+)"
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
    """LLVM text is outside the reviewed scalar codegen vocabulary."""


def validate_scalar_llvm_profile(text: str, functions: tuple[str, ...]) -> None:
    """Fail closed on LLVM syntax not emitted by the restricted scalar generator.

    A matching SHA-256 is only an integrity check: it does not authorize calls,
    global state, stores, loads, inline asm, imports or source-level semantics.
    Every branch target must remain in the same function, and PHIs must lead
    their block. The independent SSA verifier remains mandatory at emission.
    """
    if (not isinstance(text, str) or len(text.encode("utf-8")) > 4 * 1024 * 1024
            or not text.isascii() or "\r" in text or "\x00" in text
            or not text.endswith("\n") or not isinstance(functions, tuple)
            or not 0 < len(functions) <= 32 or tuple(sorted(set(functions))) != functions
            or any(re.fullmatch(NAME, name) is None or name == "abort" for name in functions)):
        raise LLVMProfileRejected("E_LLVM_PROFILE_ID: malformed source/function identity")
    lines = text.splitlines()
    if (len(lines) < 9 or lines[0] != HEADER
            or tuple(lines[1:5]) != DECLARATIONS or lines[5] != ""):
        raise LLVMProfileRejected("E_LLVM_PROFILE_HEADER: unexpected preamble or declaration")
    in_function = False
    labels: set[str] = set()
    references: set[str] = set()
    found: list[str] = []
    saw_label = False
    saw_terminal = False
    allow_phi = False
    blocks = 0
    for line in lines[6:]:
        if not in_function:
            if not line:
                continue
            header = DEF.fullmatch(line)
            if header is None:
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: unexpected top-level LLVM text")
            found.append(header.group(1))
            if len(found) > len(functions):
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: too many functions")
            in_function, saw_label, saw_terminal, allow_phi = True, False, False, False
            labels, references = set(), set()
            blocks = 0
            continue
        if line == "}":
            if not saw_label or not saw_terminal or not references <= labels:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: missing terminator or unresolved branch")
            in_function = False
            continue
        match = LAB.fullmatch(line)
        if match is not None:
            if saw_label and not saw_terminal:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: missing block terminator")
            label = match.group(1)
            if label in labels or blocks >= 4096:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: duplicate or excessive basic blocks")
            labels.add(label)
            saw_label, saw_terminal, allow_phi = True, False, True
            blocks += 1
            continue
        if not saw_label:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: instruction outside a basic block")
        if saw_terminal:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: instruction after terminator")
        if PHI.fullmatch(line):
            if not allow_phi:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: PHI after non-PHI instruction")
            continue
        allow_phi = False
        branch = BRANCH.fullmatch(line)
        if branch:
            references.update(branch.groups())
            saw_terminal = True
            continue
        jump = GOTO.fullmatch(line)
        if jump:
            references.add(jump.group(1))
            saw_terminal = True
            continue
        if line == "  unreachable":
            saw_terminal = True
            continue
        if line == "  call void @abort()":
            continue
        if any(pattern.fullmatch(line) for pattern in PATTERNS):
            if line.startswith("  ret "):
                saw_terminal = True
            continue
        raise LLVMProfileRejected("E_LLVM_PROFILE_INSTRUCTION: unreviewed operation or external call")
    if in_function or tuple(sorted(found)) != functions:
        raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: missing function end or inventory mismatch")

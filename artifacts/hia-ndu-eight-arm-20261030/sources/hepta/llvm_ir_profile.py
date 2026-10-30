"""Constrain the textual vocabulary of Hepta's checked scalar LLVM backend.

This is an input boundary for the native compiler, not a proof of source
equivalence. Source-bound builds additionally regenerate LLVM from verified
SSA/CFG. A self-consistent digest alone never authorizes arbitrary LLVM.
"""
from __future__ import annotations

import re


HEADER = "; Hepta strict scalar SSA/PHI native-LLVM pilot, not whole-language qualified."
TYPE_MARKER = "; hepta-source-types=scalar32-i32-u32"
DECLARATIONS = (
    "declare void @abort() noreturn",
    "declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32)",
    "declare { i32, i1 } @llvm.ssub.with.overflow.i32(i32, i32)",
    "declare { i32, i1 } @llvm.smul.with.overflow.i32(i32, i32)",
    "declare { i32, i1 } @llvm.uadd.with.overflow.i32(i32, i32)",
    "declare { i32, i1 } @llvm.usub.with.overflow.i32(i32, i32)",
    "declare { i32, i1 } @llvm.umul.with.overflow.i32(i32, i32)",
)
NAME = r"[A-Za-z_][A-Za-z0-9_]*"
REG = rf"%r_{NAME}_[0-9]+"
TEMP = r"%t[0-9]+"
ATOM = rf"(?:{REG}|{TEMP}|-?[0-9]{{1,10}})"
LABEL = r"(?:b[0-9]{4,}|bad_[0-9]+|cont_[0-9]+)"
DEF = re.compile(rf"define i32 @({NAME})\(((?:i32 {REG}(?:, i32 {REG})*)?)\) \{{\Z")
LAB = re.compile(rf"({LABEL}):\Z")
PHI = re.compile(rf"  {REG} = phi i32 \[ {REG}, %{LABEL} \](?:, \[ {REG}, %{LABEL} \])*\Z")
BRANCH = re.compile(rf"  br i1 (?:{ATOM}|true|false), label %({LABEL}), label %({LABEL})\Z")
GOTO = re.compile(rf"  br label %({LABEL})\Z")


class LLVMProfileRejected(ValueError):
    """LLVM text is outside the reviewed scalar code-generation vocabulary."""


def validate_scalar_llvm_profile(text: str, functions: tuple[str, ...], *,
                                 profile: str) -> None:
    """Reject additional imports, memory operations, globals, asm and metadata.

    The profile check also confines branch/PHI labels to their own function
    and requires block terminators and leading PHIs. LLVM's verifier remains
    responsible for LLVM typing/dominance; the SSA verifier plus exact origin
    regeneration is responsible for binding this text to a supplied graph.
    """
    if (not isinstance(text, str) or not text.isascii() or len(text) > 4 * 1024 * 1024
            or "\r" in text or "\x00" in text or not text.endswith("\n")
            or not isinstance(functions, tuple) or not 0 < len(functions) <= 32
            or any(not isinstance(name, str) or re.fullmatch(NAME, name) is None
                   or name == "abort" for name in functions)
            or tuple(sorted(set(functions))) != functions
            or not isinstance(profile, str)
            or profile not in {"hepta.llvm-ssa-i32.v0", "hepta.llvm-ssa-scalar32.v1"}):
        raise LLVMProfileRejected("E_LLVM_PROFILE_ID: malformed source/function identity")
    unsigned = profile == "hepta.llvm-ssa-scalar32.v1"
    preamble = [HEADER] + ([TYPE_MARKER] if unsigned else []) + list(DECLARATIONS) + [""]
    lines = text.splitlines()
    if lines[:len(preamble)] != preamble:
        raise LLVMProfileRejected("E_LLVM_PROFILE_HEADER: unexpected preamble or declaration")
    sign = "[su]" if unsigned else "s"
    patterns = (
        re.compile(rf"  {REG} = add i32 0, {ATOM}\Z"),
        re.compile(rf"  {TEMP} = call \{{ i32, i1 \}} @llvm\.{sign}(?:add|sub|mul)\.with\.overflow\.i32\(i32 {ATOM}, i32 {ATOM}\)\Z"),
        re.compile(rf"  {TEMP} = extractvalue \{{ i32, i1 \}} {TEMP}, [01]\Z"),
        re.compile(rf"  {TEMP} = icmp (?:eq|ne|{sign}(?:lt|le|gt|ge)) i32 {ATOM}, {ATOM}\Z"),
        re.compile(rf"  ret i32 {ATOM}\Z"),
    )
    in_function = False
    labels: set[str] = set()
    references: set[str] = set()
    found: list[str] = []
    saw_label = saw_terminal = allow_phi = False
    blocks = 0
    for line in lines[len(preamble):]:
        if not in_function:
            if not line:
                continue
            header = DEF.fullmatch(line)
            if header is None:
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: unexpected top-level LLVM text")
            found.append(header.group(1))
            if len(found) > len(functions) or len(re.findall(REG, header.group(2))) > 16:
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: excessive functions or parameters")
            in_function, saw_label, saw_terminal, allow_phi = True, False, False, False
            labels, references, blocks = set(), set(), 0
            continue
        if line == "}":
            if not saw_label or not saw_terminal or not references <= labels:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: missing terminator or unresolved label")
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
        if not saw_label or saw_terminal:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: instruction outside an active basic block")
        if PHI.fullmatch(line):
            if not allow_phi:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: PHI after non-PHI instruction")
            references.update(re.findall(rf", %({LABEL}) \]", line))
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
        if any(pattern.fullmatch(line) for pattern in patterns):
            if line.startswith("  ret "):
                saw_terminal = True
            continue
        raise LLVMProfileRejected("E_LLVM_PROFILE_INSTRUCTION: unreviewed operation or external call")
    if in_function or tuple(sorted(found)) != functions:
        raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: missing function end or inventory mismatch")

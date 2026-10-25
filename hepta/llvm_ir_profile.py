"""Closed LLVM grammar for the reviewed 32-bit Hepta scalar SSA emitter.

A self-rehashed SSA_LLVM_IR is not trusted merely because the SHA-256 agrees.
This pass rejects LLVM operations outside the emitter's finite vocabulary.
It does not prove that a grammar-conforming program corresponds to its Hepta
source; callers must additionally re-derive from the exact verified SSA/CFG.
"""
from __future__ import annotations

import re

HEADER = "; Hepta strict scalar SSA/PHI native-LLVM pilot, not whole-language qualified."
UNSIGNED_MARKER = "; hepta-source-types=scalar32-i32-u32"
SIGNED_PROFILE = "hepta.llvm-ssa-i32.v0"
MIXED_PROFILE = "hepta.llvm-ssa-scalar32.v1"
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
REGISTER = rf"%r_{NAME}_[0-9]+"
TEMP = r"%t[0-9]+"
ATOM = rf"(?:{REGISTER}|{TEMP}|-?[0-9]+)"
CONDITION = rf"(?:{REGISTER}|{TEMP}|true|false)"
LABEL = r"(?:b[0-9]{4}|bad_[0-9]+|cont_[0-9]+)"
DEFINITION = re.compile(rf"define i32 @({NAME})\(((?:i32 {REGISTER}(?:, i32 {REGISTER})*)?)\) \{{\Z")
BASIC_LABEL = re.compile(rf"({LABEL}):\Z")
PHI = re.compile(rf"  {REGISTER} = phi i32 \[ {REGISTER}, %{LABEL} \](?:, \[ {REGISTER}, %{LABEL} \])*\Z")
PHI_EDGE = re.compile(rf"\[ {REGISTER}, %({LABEL}) \]")
BRANCH = re.compile(rf"  br i1 {CONDITION}, label %({LABEL}), label %({LABEL})\Z")
GOTO = re.compile(rf"  br label %({LABEL})\Z")
OPERATIONS = (
    re.compile(rf"  {REGISTER} = add i32 0, {ATOM}\Z"),
    re.compile(rf"  {TEMP} = call \{{ i32, i1 \}} @llvm\.(?:sadd|ssub|smul|uadd|usub|umul)\.with\.overflow\.i32\(i32 {ATOM}, i32 {ATOM}\)\Z"),
    re.compile(rf"  {TEMP} = extractvalue \{{ i32, i1 \}} {TEMP}, [01]\Z"),
    re.compile(rf"  {TEMP} = icmp (?:eq|ne|slt|sle|sgt|sge|ult|ule|ugt|uge) i32 {ATOM}, {ATOM}\Z"),
    re.compile(rf"  ret i32 {ATOM}\Z"),
)


class LLVMProfileRejected(ValueError):
    """LLVM text does not belong to the trusted, finite emitter vocabulary."""


def validate_scalar_llvm_profile(text: str, functions: tuple[str, ...], profile: str) -> None:
    """Check exact preamble, bounded scalar syntax and closed control-flow labels.

    This is an *instruction containment* gate, not value-semantic refinement.
    Hashes and syntax both remain attacker-controllable until origin rechecking.
    """
    if (profile not in {SIGNED_PROFILE, MIXED_PROFILE}
            or not isinstance(text, str) or len(text) > 4 * 1024 * 1024
            or not text.isascii() or "\r" in text or "\x00" in text
            or not text.endswith("\n") or not isinstance(functions, tuple)
            or not 0 < len(functions) <= 32
            or functions != tuple(sorted(set(functions)))
            or any(re.fullmatch(NAME, name) is None or name == "abort"
                   for name in functions)):
        raise LLVMProfileRejected("E_LLVM_PROFILE_ID: invalid source, function inventory or profile")
    lines = text.splitlines()
    if len(lines) > 131_072 or any(len(line) > 2048 for line in lines):
        raise LLVMProfileRejected("E_LLVM_PROFILE_LIMIT: too many or too-long LLVM lines")
    preamble = [HEADER]
    if profile == MIXED_PROFILE:
        preamble.append(UNSIGNED_MARKER)
    preamble.extend(DECLARATIONS)
    preamble.append("")
    if lines[:len(preamble)] != preamble:
        raise LLVMProfileRejected("E_LLVM_PROFILE_HEADER: unrecognized LLVM header/marker/import")

    in_function = False
    found: list[str] = []
    defined_labels: set[str] = set()
    referenced_labels: set[str] = set()
    started = terminated = False
    phi_allowed = False
    abort_pending = False
    block_count = instruction_count = 0

    for line in lines[len(preamble):]:
        if not in_function:
            if not line:
                continue
            match = DEFINITION.fullmatch(line)
            if match is None or len(found) >= len(functions):
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: unexpected top-level LLVM definition")
            if match.group(1) in found:
                raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: duplicate function")
            found.append(match.group(1))
            in_function = True
            started = terminated = abort_pending = False
            phi_allowed = False
            defined_labels, referenced_labels = set(), set()
            block_count = instruction_count = 0
            continue

        if line == "}":
            if not started or not terminated or abort_pending or not referenced_labels <= defined_labels:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: function lacks a complete CFG")
            in_function = False
            continue
        label = BASIC_LABEL.fullmatch(line)
        if label:
            if abort_pending or (started and not terminated) or label.group(1) in defined_labels:
                raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: repeated label or missing terminator")
            block_count += 1
            if block_count > 4096:
                raise LLVMProfileRejected("E_LLVM_PROFILE_LIMIT: too many basic blocks")
            defined_labels.add(label.group(1))
            started, terminated, phi_allowed = True, False, True
            continue
        if not started or terminated or not line or instruction_count >= 65536:
            raise LLVMProfileRejected("E_LLVM_PROFILE_CFG: instruction outside active basic block")
        instruction_count += 1
        if abort_pending:
            if line != "  unreachable":
                raise LLVMProfileRejected("E_LLVM_PROFILE_ABORT: abort must end with unreachable")
            abort_pending = False
            terminated = True
            phi_allowed = False
            continue
        if PHI.fullmatch(line):
            if not phi_allowed:
                raise LLVMProfileRejected("E_LLVM_PROFILE_PHI: phi after ordinary instruction")
            referenced_labels.update(PHI_EDGE.findall(line))
            continue
        phi_allowed = False
        # The signed-only profile cannot be retagged to contain unsigned
        # operations without changing its source-type declaration.
        if (profile == SIGNED_PROFILE and
                (re.search(r"@llvm\.u(?:add|sub|mul)\.with\.overflow", line)
                 or re.search(r"\bicmp u(?:lt|le|gt|ge)\b", line))):
            raise LLVMProfileRejected("E_LLVM_PROFILE_SIGNED: unsigned op in signed-only profile")
        branch = BRANCH.fullmatch(line)
        if branch:
            referenced_labels.update(branch.groups())
            terminated = True
            continue
        jump = GOTO.fullmatch(line)
        if jump:
            referenced_labels.add(jump.group(1))
            terminated = True
            continue
        if line == "  call void @abort()":
            abort_pending = True
            continue
        if any(op.fullmatch(line) for op in OPERATIONS):
            if line.startswith("  ret "):
                terminated = True
            continue
        raise LLVMProfileRejected("E_LLVM_PROFILE_INSTRUCTION: forbidden/unrecognized LLVM operation")

    if in_function or tuple(sorted(found)) != functions:
        raise LLVMProfileRejected("E_LLVM_PROFILE_DEFINE: unclosed/missing/mismatched function")

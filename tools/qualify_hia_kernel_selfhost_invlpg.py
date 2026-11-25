"""Isolated authoring and native bootstrap experiment for the kernel-tlb profile.

No historical generator, source, lock, or native owner is replaced. Python
authors a candidate Core v8 compiler and seeds B0 only; all following compiler
generations and subject objects are produced by the resulting HIA machine code.
The experiment is deliberately not a CPL0 authority proof or Linux acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from tools import generate_hia_selfhost as gen
from hepta.hia_agent_assembly import render_assembly
from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
from tools import hia_kernel_selfhost_msr as msr
from tools import hia_kernel_selfhost_idtr as idtr
from tools import hia_kernel_selfhost_iretq as iretq
from tools import hia_kernel_selfhost_tr as tr
from tools import hia_kernel_selfhost_kernel_frame as kernel_frame
from tools import hia_kernel_selfhost_kernel_irq as kernel_irq

PROFILE = "hepta.hia.program.kernel-tlb.v1"
LEGACY = "hepta.hia.program.v8"
HEADER = b"hia-asm.v1 hepta.hia.program.v8 selfhost\n"
# The experimental compiler has a separate 2 MiB scratch envelope.
# Source and output are still independently bounded at the historical 1 MiB.
# No default Core v8 generator, binary ABI, or source/output limit is changed.
CANDIDATE_WORKSPACE = 2 << 20
CANDIDATE_FUNCTIONS = 192
CANDIDATE_BLOCKS = 2048
CANDIDATE_INSTRUCTIONS = 10000
CANDIDATE_RELOCATIONS = 16000
CANDIDATE_EXPORTS = 128
RELOCATION_RECORD_BYTES = 16

def candidate_layout():
    # Pack each global table using its actual indexing dimensions. Every
    # downstream name/origin/export table is relocated, not just the first
    # overflowed table. Keep the original per-function SSA/block limits.
    intervals = [("state", 0, 2048)]
    layout = {}
    cursor = gen.FBASE

    def reserve(label, size, key=None):
        nonlocal cursor
        cursor = (cursor + 15) & ~15
        base = cursor
        cursor += size
        intervals.append((label, base, cursor))
        if key is not None:
            layout[key] = base
        return base

    if reserve("functions", CANDIDATE_FUNCTIONS * gen.FSTRIDE) != gen.FBASE:
        raise ValueError("function table origin changed")
    reserve("blocks", CANDIDATE_BLOCKS * gen.BSTRIDE, "BBASE")
    reserve("ssa", 2048 * 16, "VBASE")
    reserve("args", 1024, "ARGS")
    reserve("relocations", CANDIDATE_RELOCATIONS * RELOCATION_RECORD_BYTES, "FIXBASE")
    reserve("call_graph", CANDIDATE_FUNCTIONS ** 2, "CBASE")
    reserve("call_state", CANDIDATE_FUNCTIONS * 8, "CSTATE")
    if layout["CSTATE"] != layout["CBASE"] + CANDIDATE_FUNCTIONS ** 2:
        raise ValueError("call graph and marks are not contiguous")
    reserve("capabilities", 2048 * 24, "CAPBASE")
    reserve("kind", CANDIDATE_BLOCKS, "KBASE")
    reserve("cap_tmp", 16, "CAPTMP")
    reserve("queue", 256 * 8, "QBASE")
    reserve("origins", 2048, "ORIGINBASE")
    reserve("block_origins", CANDIDATE_BLOCKS * 16, "BLOCKORIGIN")
    names = {
        955152: reserve("value_names", 2048 * 24),
        1004304: reserve("block_names", 256 * 24),
        1010448: reserve("exports", CANDIDATE_EXPORTS * 48),
    }
    previous = 0
    for label, begin, stop in intervals:
        if begin < previous or stop <= begin or stop > CANDIDATE_WORKSPACE:
            raise ValueError(("candidate scratch overlap or overflow", label, begin, stop))
        previous = stop
    # Function count is stored in an existing private byte, not a u64.
    if not 128 < CANDIDATE_FUNCTIONS < 256:
        raise ValueError("function count exceeds private header representation")
    relocation_bound = (CANDIDATE_FUNCTIONS + CANDIDATE_INSTRUCTIONS +
                        2 * CANDIDATE_BLOCKS + CANDIDATE_EXPORTS + 2)
    if relocation_bound > CANDIDATE_RELOCATIONS:
        raise ValueError("candidate relocation capacity exceeded")
    return layout, names, intervals, relocation_bound

def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("authoring anchor not unique: " + old)
    return source.replace(old, new, 1)

def candidate_source():
    words = dict(gen.W)
    for word in (PROFILE, "privilege", "atomic", "x86.tlb.invlpg", "x86.cr0.write", "x86.cr3.write", "x86.cr4.write", "x86.cr0.read", "x86.cr2.read", "x86.cr3.read", "x86.cr4.read", "x86.irq.disable", "x86.irq.enable", "x86.io.in8", "x86.io.out8", "x86.io.in16", "x86.io.out16", "x86.io.in32", "x86.io.out32", "x86.fence.mfence", "x86.atomic.cmpxchg64", "x86.mmio.read32", "x86.mmio.write32", *msr.WORDS, *idtr.WORDS, iretq.WORD, *tr.WORDS, kernel_frame.WORD, kernel_irq.WORD):
        if word in words:
            raise ValueError("candidate keyword already present")
        words[word] = max(words.values()) + 1
    # The sixteen experimental opcodes occupy a contiguous token interval.
    # Keep the native compiler within its audited candidate capacity.
    if [words[name] - words["x86.tlb.invlpg"] for name in
            ("x86.tlb.invlpg", "x86.cr0.write", "x86.cr3.write", "x86.cr4.write", "x86.cr0.read", "x86.cr2.read", "x86.cr3.read", "x86.cr4.read", "x86.irq.disable", "x86.irq.enable", "x86.io.in8", "x86.io.out8", "x86.io.in16", "x86.io.out16", "x86.io.in32", "x86.io.out32")] != list(range(16)):
        raise ValueError("kernel token interval changed")
    source = gen.SOURCE
    layout, names, _, _ = candidate_layout()
    # Increase only scratch admission and the actual CLI workspace mapping:
    # input [0,1 MiB), output [1,2 MiB), workspace [2,4 MiB).
    source = replace_once(source, "if n < 1048576:",
                          f"if n < {CANDIDATE_WORKSPACE}:")
    from tools.hia_selfhost_cli import _bytes
    mmap_old = ("31 ff be 00 00 30 00 ba 03 00 00 00 41 ba 22 00 00 00"
                " 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff")
    source = replace_once(source, _bytes(mmap_old),
                          _bytes(mmap_old.replace("be 00 00 30 00", "be 00 00 40 00")))
    call_old = ("4c 89 e7 4c 89 ee 49 8d 94 24 00 00 10 00 b9 00 00 10 00"
                " 4d 8d 84 24 00 00 20 00 41 b9 00 00 10 00 e8")
    source = replace_once(source, _bytes(call_old),
                          _bytes(call_old.replace("41 b9 00 00 10 00", "41 b9 00 00 20 00")))
    # All function admission sites and both call-graph strides change
    # together; retain independent name-length and export-count limits.
    for old, new in (
        ("f != get(w, 64) or f >= 128", f"f != get(w, 64) or f >= {CANDIDATE_FUNCTIONS}"),
        ("if f >= 128:", f"if f >= {CANDIDATE_FUNCTIONS}:"),
        ("if x >= 128:", f"if x >= {CANDIDATE_FUNCTIONS}:"),
        ("CBASE + get(w, 72) * 128 + x", f"CBASE + get(w, 72) * {CANDIDATE_FUNCTIONS} + x"),
        ("while target < 128:", f"while target < {CANDIDATE_FUNCTIONS}:"),
        ("CBASE + f * 128 + target", f"CBASE + f * {CANDIDATE_FUNCTIONS} + target"),
        ("fill_range(w, CBASE, 17408, 0)",
         f"fill_range(w, CBASE, {CANDIDATE_FUNCTIONS ** 2 + CANDIDATE_FUNCTIONS * 8}, 0)"),
    ):
        source = replace_once(source, old, new)
    # Both global block bounds and the global discovery-table clear grow.
    # The per-function 256-block name/queue admission stays unchanged.
    source = replace_once(source, "fill_range(w, KBASE, 1536, 0)",
                          f"fill_range(w, KBASE, {CANDIDATE_BLOCKS}, 0)")
    source = replace_once(source, "get(w, 80) >= 1536",
                          f"get(w, 80) >= {CANDIDATE_BLOCKS}")
    source = replace_once(source, "bid >= 1536",
                          f"bid >= {CANDIDATE_BLOCKS}")
    # The three-phase compiler proves output <= 1 MiB before emission.
    # Keep a full 64-bit target; pack the bounded offset and kind in one word.
    # Retain kind 3/4 behavior and every existing relative patch operation.
    source = replace_once(source,
        """        put(w, FIXBASE + n * 24, get(w, 56))
        put(w, FIXBASE + n * 24 + 8, kind)
        put(w, FIXBASE + n * 24 + 16, target)""",
        """        if get(w, 56) > 4294967295 or kind > 4294967295:
            return fail(w, 44)
        put(w, FIXBASE + n * 16, get(w, 56) | (kind << 32))
        put(w, FIXBASE + n * 16 + 8, target)""")
    source = replace_once(source,
        """        at = get(w, FIXBASE + i * 24)
        kind = get(w, FIXBASE + i * 24 + 8)
        target = get(w, FIXBASE + i * 24 + 16)""",
        """        at = get(w, FIXBASE + i * 16)
        kind = at >> 32
        at = at & 4294967295
        target = get(w, FIXBASE + i * 16 + 8)""")
    # External ELF relocation emission has its own reader (kind 3).
    # Keep the emitted RELA record 24 bytes; compact only private scratch.
    source = replace_once(source,
        """            if get(w, FIXBASE + i * 24 + 8) == 3:
                emit8(o, w, get(w, FIXBASE + i * 24) - 64)
                emit8(o, w, ((get(w, FIXBASE + i * 24 + 16) + symbol_base) << 32) | 4)""",
        """            if (get(w, FIXBASE + i * 16) >> 32) == 3:
                emit8(o, w, (get(w, FIXBASE + i * 16) & 4294967295) - 64)
                emit8(o, w, ((get(w, FIXBASE + i * 16 + 8) + symbol_base) << 32) | 4)""")
    if any("FIXBASE" in line and "* 24" in line for line in source.splitlines()):
        raise ValueError("unconverted relocation-table access")
    for old, new in names.items():
        if str(old) not in source:
            raise ValueError(("missing scratch table anchor", old))
        source = source.replace(str(old), str(new))
    source = replace_once(source,
        "        expect(s, w, @hepta.hia.program.v8@)",
        """        if get(w, 8) == @hepta.hia.program.kernel-tlb.v1@:
            put(w, 200, 1)
            expect(s, w, @hepta.hia.program.kernel-tlb.v1@)
        else:
            expect(s, w, @hepta.hia.program.v8@)""")
    source = replace_once(source, "        read_exports(s, w)",
        """        if get(w, 200) == 1 and get(w, 232) != 1:
            return 4294967295
        read_exports(s, w)
        if get(w, 200) == 1 and get(w, 640) != 1:
            return 4294967295""")
    source = replace_once(source,
        """        if token != @alloc@:
            if token < @read@ or token > @trap@:
                return fail(w, 65)
            flag = 2 << (token - @read@)""",
        """        if token == @privilege@ or token == @atomic@:
            if get(w, 200) != 1:
                return fail(w, 65)
            flag = 16 << (token - @privilege@)
        else:
            if token != @alloc@:
                if token < @read@ or token > @trap@:
                    return fail(w, 65)
                flag = 2 << (token - @read@)""")
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.fence.mfence@:
        return 32
    if op == @x86.mmio.read32@:
        return 26
    if op == @x86.mmio.write32@:
        return 28
    if op == @x86.atomic.cmpxchg64@:
        return 62
    if op >= @x86.tlb.invlpg@ and op <= @x86.io.out32@:
        return 16""")
    source = replace_once(source,
        """    if op >= @buffer.new@ and op <= @chain.head_mut@:
        owned_instruction(o, w, op, n, a, at)""",
        """    if op == @x86.mmio.read32@ or op == @x86.mmio.write32@:
        if get(w, 200) != 1 or at != 1:
            return fail(w, 65)
        if op == @x86.mmio.read32@:
            if n != 1 or t != 3 or get(w, 288) != 1:
                return fail(w, 65)
            define(w, v, t)
        else:
            if n != 2 or bt != 3 or t != 0 or get(w, 288) != 0:
                return fail(w, 65)
        expect(s, w, 10)
        if get(w, 40) != 0:
            return 0
        # Raw MMIO address: live device ownership and UC mapping remain
        # caller obligations. Exactly one aligned dword access, in emitted
        # program order. No implicit posted-write flush or DMA ordering.
        load_var(o, w, 2, a, 0)
        emit_bytes(o, w, 3112727954572022, 7)
        if op == @x86.mmio.read32@:
            emit_bytes(o, w, 651, 2)
            store_var(o, w, v, 0)
        else:
            load_var(o, w, 0, b, 0)
            emit_bytes(o, w, 649, 2)
        return 0
    if op == @x86.fence.mfence@:
        if get(w, 200) != 1 or (n | t | get(w, 288)) != 0:
            return fail(w, 65)
        expect(s, w, 10)
        if get(w, 40) != 0:
            return 0
        emit_bytes(o, w, 15773199, 3)
        return 0
    if op == @x86.atomic.cmpxchg64@:
        if get(w, 200) != 1 or n != 3 or at != 1 or bt != 1 or t != 1 or get(w, 288) != 1:
            return fail(w, 65)
        c = get(w, ARGS + 16)
        if variable(w, c) != 1:
            return fail(w, 65)
        expect(s, w, 10)
        define(w, v, t)
        if get(w, 40) != 0:
            return 0
        # Experimental raw-address operation: caller must establish mapped
        # coherent WB memory and authority. Check alignment before any access.
        # RDX=address, RAX=expected, RCX=replacement, RAX returns observed old.
        load_var(o, w, 2, a, 0)
        emit_bytes(o, w, 3112727954834166, 7)
        load_var(o, w, 0, b, 0)
        load_var(o, w, 1, c, 0)
        emit_bytes(o, w, 45920241904, 5)
        store_var(o, w, v, 0)
        return 0
    if op >= @x86.io.in8@ and op <= @x86.io.out32@:
        if get(w, 200) != 1 or at != 10:
            return fail(w, 65)
        direction = (op - @x86.io.in8@) & 1
        width = (op - @x86.io.in8@) >> 1
        if direction == 0:
            if n != 1 or t != 1 or get(w, 288) != 1:
                return fail(w, 65)
            define(w, v, t)
        else:
            # Packed scalar type codes: u8=4, u16=10, u32=3.
            if n != 2 or bt != ((932 >> (4 * width)) & 15) or t != 0 or get(w, 288) != 0:
                return fail(w, 65)
        expect(s, w, 10)
        if get(w, 40) != 0:
            return 0
        load_var(o, w, 2, a, 0)
        if direction != 0:
            load_var(o, w, 0, b, 0)
        # IN/OUT are byte, word (66 prefix), or dword (EAX). EAX writes
        # zero the upper half of RAX; byte/word input explicitly extends.
        if width == 1:
            emit(o, w, 102)
        opcode = 236 + 2 * direction
        if width != 0:
            opcode = opcode + 1
        emit(o, w, opcode)
        if direction == 0:
            if width < 2:
                emit(o, w, 15)
                emit(o, w, 182 + width)
                emit(o, w, 192)
            store_var(o, w, v, 0)
        return 0
    if op >= @x86.irq.disable@ and op <= @x86.irq.enable@:
        if get(w, 200) != 1:
            fail(w, 65)
        if (n | t | get(w, 288)) != 0:
            fail(w, 65)
        expect(s, w, 10)
        if get(w, 40) != 0:
            return 0
        # CLI/STI, explicit privilege effect, not an authority proof.
        emit(o, w, 250 + op - @x86.irq.disable@)
        return 0
    if op >= @x86.cr0.read@ and op <= @x86.cr4.read@:
        if get(w, 200) != 1 or n != 0 or t != 1 or get(w, 288) != 1 or get(w, 256) != 0:
            return fail(w, 65)
        expect(s, w, 10)
        define(w, v, t)
        if get(w, 40) != 0:
            return 0
        # MOV RAX, CR0/CR2/CR3/CR4 (0F 20 /r). The checked token
        # interval indexes packed CR numbers 0x4320 (17184), low nibble first.
        emit(o, w, 15)
        emit(o, w, 32)
        emit(o, w, 192 + 8 * ((17184 >> (4 * (op - @x86.cr0.read@))) & 15))
        store_var(o, w, v, 0)
        return 0
    if op >= @x86.cr0.write@ and op <= @x86.cr4.write@:
        if get(w, 200) != 1 or n != 1 or at != 1 or t != 0 or get(w, 288) != 0:
            return fail(w, 65)
        expect(s, w, 10)
        if get(w, 40) != 0:
            return 0
        load_var(o, w, 0, a, 0)
        # MOV CR0/CR3/CR4, RAX. Valid state and CPL0 are caller obligations.
        # Packed CR numbers 0x430; no CR2 write is admitted.
        emit(o, w, 15)
        emit(o, w, 34)
        emit(o, w, 192 + 8 * ((1072 >> (4 * (op - @x86.cr0.write@))) & 15))
        return 0
    if op == @x86.tlb.invlpg@:
        if get(w, 200) != 1 or n != 1 or at != 1 or t != 0 or get(w, 288) != 0:
            return fail(w, 65)
        expect(s, w, 10)
        if get(w, 40) != 0:
            return 0
        load_var(o, w, 0, a, 0)
        # Typed one-operand x86 INVLPG, ModRM /7, base RAX.
        # This is the compiler's own instruction lowering, not source bytes.
        emit(o, w, 15)
        emit(o, w, 1)
        emit(o, w, 56)
        return 0
    if op >= @buffer.new@ and op <= @chain.head_mut@:
        owned_instruction(o, w, op, n, a, at)""")
    # 200..207 is a dedicated candidate profile word within the existing
    # per-phase 0..255 zeroed header; no existing state field is moved.
    # Keep the main instruction function below the fixed per-function SSA
    # name limit. The MMIO lowering is an actual Core helper, not a second
    # interpreter or a change to the emitted subject instruction sequence.
    mmio_start = "    if op == @x86.mmio.read32@ or op == @x86.mmio.write32@:"
    mmio_end = "    if op == @x86.fence.mfence@:"
    first = source.index(mmio_start)
    last = source.index(mmio_end, first)
    body = source[first:last].splitlines()[1:]
    if not body or any(line and not line.startswith("        ") for line in body):
        raise ValueError("MMIO lowering helper boundary changed")
    helper = ("\ndef mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
              "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:\n")
    helper += "".join(line[4:] + "\n" for line in body)
    source = (source[:first] + mmio_start + "\n"
              "        return mmio_instruction(s, o, w, op, n, at, t, v, bt, a, b)\n"
              + source[last:] + helper)
    source = msr.extend_source(source, replace_once)
    source = idtr.extend_source(source, replace_once)
    source = iretq.extend_source(source, replace_once)
    source = tr.extend_source(source, replace_once)
    source = kernel_frame.extend_source(source, replace_once)
    source = kernel_irq.extend_source(source, replace_once)
    with patch.multiple(gen, SOURCE=source, W=words,
                        MAX_INSTRUCTIONS=CANDIDATE_INSTRUCTIONS,
                        MAX_RELOCATIONS=CANDIDATE_RELOCATIONS, **layout):
        document, _ = gen.document()
    functions = document["functions"]
    blocks = [b for f in functions for b in f["blocks"]]
    ops = sum(len(b["ops"]) for b in blocks)
    # Selfhost's exact-name table counts distinct SSA definitions, not the
    # numerical suffix (authoring may preserve sparse names). Check each
    # function before attempting the independent B0/B1 replay.
    for function in functions:
        names = {v["name"] for v in function["params"]}
        for block in function["blocks"]:
            names.update(v["name"] for v in block["params"])
            for instruction in block["ops"]:
                names.update(v["name"] for v in instruction.get("out", ()))
        if len(names) > 2048 or len(function["blocks"]) > 256:
            raise ValueError(("per-function native limit", function["name"],
                              len(names), len(function["blocks"])))
    if len(functions) > CANDIDATE_FUNCTIONS or len(blocks) > CANDIDATE_BLOCKS or ops > CANDIDATE_INSTRUCTIONS:
        raise ValueError({"functions": len(functions), "blocks": len(blocks), "ops": ops})
    result = render_assembly(document).encode()
    if not result.startswith(HEADER) or len(result) > 1 << 20:
        raise ValueError("candidate source exceeds bootstrap envelope")
    return result, {"functions": len(functions), "blocks": len(blocks), "ops": ops}

def candidate_child(output):
    # A derived, recorded observer only for this isolated experiment; retain
    # the default child and its source/output guards byte-for-byte.
    from tools import qualify_hia_selfhost as qualification
    original = qualification.CHILD.read_text()
    old = 'assert type(workspace_size) is int and 0 <= workspace_size <= MAX_BYTES'
    new = f'assert type(workspace_size) is int and 0 <= workspace_size <= {CANDIDATE_WORKSPACE}'
    changed = replace_once(original, old, new)
    child = output / "candidate-workspace-observer.py"
    child.write_text(changed)
    return child

def candidate_seed(output, source):
    # This B0 is a different explicitly bounded development seed, not a
    # legacy Core borrowed-byte release. Scope the extent adjustment to B0;
    # the authored HIA entry still checks source/output <= 1 MiB.
    from tools import qualify_hia_selfhost as qualification
    from hepta import hia_native_byte_abi as abi
    with patch.object(qualification, "CAPACITY", CANDIDATE_WORKSPACE), \
            patch.object(abi, "MAX_EXTENT", CANDIDATE_WORKSPACE):
        return build_seed(output, source)

def candidate_invoke(output, label, image, source, **kwargs):
    from tools import qualify_hia_selfhost as qualification
    kwargs.setdefault("workspace_size", CANDIDATE_WORKSPACE)
    with patch.object(qualification, "CHILD", output / "candidate-workspace-observer.py"):
        return invoke(output, label, image, source, **kwargs)

def candidate_compile_stage(output, label, image, source, **kwargs):
    from tools import qualify_hia_selfhost as qualification
    with patch.object(qualification, "invoke", candidate_invoke):
        return compile_stage(output, label, image, source, **kwargs)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def program(profile=PROFILE, effect="privilege", op="  _ = x86.tlb.invlpg(v0)\n",
            typ="u64", module="selfhost_elf", exports="exports(f0)\n"):
    return (f"hia-asm.v1 {profile} {module}\n" + exports +
            f"fn f0(v0:{typ}) -> ({typ}) effects({effect}) entry(b0)\n"
            f"block b0(v0:{typ})\n" + op + "  ret(v0)\nend\n").encode()

def cr3_program(profile=PROFILE, effect="privilege",
                op="  v1:u64 = x86.cr3.read()\n", result="v1"):
    return program(profile=profile, effect=effect, op=op).replace(
        b"  ret(v0)\n", f"  ret({result})\n".encode())

def io_program(action, *, profile=PROFILE, effect="privilege", port="u16",
               value=None, op=None, module="selfhost_elf"):
    if action in ("in8", "in16", "in32"):
        args = f"v0:{port}"
        result = "u64"
        operation = f"  v1:u64 = x86.io.{action}(v0)\n"
        ret = "v1"
    elif action in ("out8", "out16", "out32"):
        if value is None:
            value = "u" + action[3:]
        args = f"v0:{port},v1:{value}"
        result = port
        operation = f"  _ = x86.io.{action}(v0,v1)\n"
        ret = "v0"
    else:
        raise ValueError(action)
    return (f"hia-asm.v1 {profile} {module}\nexports(f0)\n"
            f"fn f0({args}) -> ({result}) effects({effect}) entry(b0)\n"
            f"block b0({args})\n" + (operation if op is None else op) +
            f"  ret({ret})\nend\n").encode()


def compile_cli(compiler, source, output, label, expected=0):
    result = subprocess.run([str(compiler)], input=source, capture_output=True,
                            env={"PATH": ""}, cwd=output, timeout=30)
    (output / (label + ".input")).write_bytes(source)
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    (output / (label + ".json")).write_text(json.dumps({
        "compiler_sha256": digest(compiler.read_bytes()), "source_sha256": digest(source),
        "returncode": result.returncode, "output_sha256": digest(result.stdout),
        "expected_returncode": expected}, sort_keys=True) + "\n")
    if result.returncode != expected or result.stderr or (expected and result.stdout):
        raise AssertionError((label, result.returncode, expected))
    return result.stdout

def text_bytes(output, label, data):
    obj = output / (label + ".o")
    raw = output / (label + ".text")
    obj.write_bytes(data)
    subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", str(obj), str(raw)], check=True)
    return raw.read_bytes()

def capacity_subject(blocks, instructions):
    """Exact-sized, independently executable scalar CFG. Every block is live."""
    sizes = [min(256, blocks - i) for i in range(0, blocks, 256)]
    adds, extra = divmod(instructions - blocks, blocks)
    if adds < 1:
        raise ValueError("capacity fixture needs at least one add per block")
    rows = [f"hia-asm.v1 {PROFILE} selfhost_elf",
            "exports(" + ",".join(f"f{i}" for i in range(len(sizes))) + ")"]
    expected = []
    ordinal = 0
    for f, size in enumerate(sizes):
        rows.append(f"fn f{f}(v0:u64) -> (u64) effects() entry(b0)")
        v = 0
        count = 0
        for b in range(size):
            rows.append(f"block b{b}(v{v}:u64)")
            current = v
            v += 1
            one = v
            rows.append(f'  v{one}:u64 = const() {{"value":1}}')
            for _ in range(adds + int(ordinal < extra)):
                v += 1
                rows.append(f"  v{v}:u64 = int.add.wrap(v{current},v{one})")
                current = v
                count += 1
            ordinal += 1
            if b + 1 < size:
                v += 1
                rows.append(f"  jump b{b + 1}(v{current})")
            else:
                rows.append(f"  ret(v{current})")
        rows.append("end")
        if v >= 2048:
            raise ValueError("capacity fixture exceeded per-function SSA bound")
        expected.append(count)
    if ordinal != blocks or sum(expected) + blocks != instructions:
        raise AssertionError("fixture shape mismatch")
    return ("\n".join(rows) + "\n").encode(), expected


def dense_relocation_subject():
    """Fill exact source ceilings with real call and dual-edge relocations.

    One private helper adds one. Each exported function passes its bool along
    both edges. True visits every block; false skips alternate blocks. Neither
    path depends on compiler-produced counts or disassembly.
    """
    blocks = CANDIDATE_BLOCKS - 1
    calls = CANDIDATE_INSTRUCTIONS - 2
    sizes = [min(256, blocks-i) for i in range(0, blocks, 256)]
    base, extra = divmod(calls, blocks)
    rows = [f"hia-asm.v1 {PROFILE} selfhost_elf",
            "exports(" + ",".join(f"f{i+1}" for i in range(len(sizes))) + ")",
            "fn f0(v0:u64) -> (u64) effects() entry(b0)",
            "block b0(v0:u64)",
            '  v1:u64 = const() {"value":1}',
            "  v2:u64 = int.add.wrap(v0,v1)",
            "  ret(v2)", "end"]
    expected = []
    ordinal = 0
    edges = 0
    for f, size in enumerate(sizes, 1):
        rows.append(f"fn f{f}(v0:u64,v1:bool) -> (u64) effects() entry(b0)")
        v = 0
        counts = []
        for b in range(size):
            current, cond = v, v+1
            rows.append(f"block b{b}(v{current}:u64,v{cond}:bool)")
            v += 2
            count = base + int(ordinal < extra)
            counts.append(count)
            for _ in range(count):
                rows.append(f'  v{v}:u64 = call(v{current}) {{"function":"f0"}}')
                current = v
                v += 1
            ordinal += 1
            if b+2 < size:
                rows.append(f"  branch v{cond} b{b+1}(v{current},v{cond}) b{b+2}(v{current},v{cond})")
                edges += 2
            elif b+1 < size:
                rows.append(f"  jump b{b+1}(v{current},v{cond})")
                edges += 1
            else:
                rows.append(f"  ret(v{current})")
        rows.append("end")
        if v > 2048:
            raise ValueError("dense relocation fixture exceeded per-function SSA")
        skipped = sum(counts[::2]) + (counts[-1] if size % 2 == 0 else 0)
        expected.append([skipped, sum(counts)])
    if ordinal != blocks or sum(x[1] for x in expected) != calls:
        raise AssertionError("dense relocation fixture shape mismatch")
    if calls+edges <= 12300:
        raise AssertionError("dense witness does not exercise past the former table")
    subject = ("\n".join(rows)+"\n").encode()
    if len(subject) > 1 << 20:
        raise AssertionError("dense relocation fixture exceeded source envelope")
    return subject, expected, calls+edges

def qualify_dense_relocations(exe, output, flat):
    subject, expected, lower = dense_relocation_subject()
    receipt, raw = candidate_invoke(output, "relocation-dense-flat", flat, subject, workspace_fill=0x5a)
    count = receipt.get("workspace_header", {}).get("224", -1)
    if (receipt.get("status") != "returned" or receipt.get("abi_status") != 0
            or receipt.get("source_unchanged") is not True
            or receipt.get("forbidden_compiler_modules_loaded") != []
            or receipt.get("workspace_header", {}).get("40") != 0
            or type(count) is not int or not lower <= count <= CANDIDATE_RELOCATIONS
            or not 0 < receipt.get("core_u32", 0) <= len(raw)):
        raise AssertionError(("dense relocation receipt", receipt))
    obj = compile_cli(exe, subject, output, "relocation-dense-1")
    if obj != raw[:receipt["core_u32"]] or obj != compile_cli(exe, subject, output, "relocation-dense-2"):
        raise AssertionError("dense flat/CLI or repeated object bytes differ")
    text_bytes(output, "relocation-dense", obj)
    lib = output / "relocation-dense.so"
    subprocess.run(["ld", "-shared", "-o", str(lib), str(output / "relocation-dense.o")], check=True)
    runner = """import ctypes, json, sys
lib = ctypes.CDLL(sys.argv[1])
for i, deltas in enumerate(json.loads(sys.argv[2]), 1):
    fn = getattr(lib, "f" + str(i))
    fn.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    fn.restype = ctypes.c_uint64
    for cond in (0, 1):
        for x in (0, 123456789, (1 << 64)-1):
            assert fn(x, cond) == (x + deltas[cond]) % (1 << 64), (i, cond, x)
"""
    process = subprocess.run([sys.executable, "-I", "-c", runner, str(lib), json.dumps(expected)],
                             capture_output=True, timeout=30)
    (output / "relocation-dense-native.stdout").write_bytes(process.stdout)
    (output / "relocation-dense-native.stderr").write_bytes(process.stderr)
    if process.returncode or process.stdout or process.stderr:
        raise AssertionError(("dense native execution", process.returncode))
    return {"status":"PASS", "native_relocations":count, "required_relocations":lower,
            "native_calls":len(expected)*6, "object_sha256":digest(obj),
            "source_sha256":digest(subject), "flat_cli_object_identity":True}


def qualify_external_relocations(exe, output, flat):
    """Legacy owned-buffer ELF must still emit real calloc/free RELA records."""
    from tools.hia_selfhost_owned_elf_cases import allocation_case
    results = []
    for optional in (False, True):
        label = "relocation-owned-" + ("try" if optional else "new")
        subject = allocation_case(8, optional=optional)
        receipt, raw = candidate_invoke(output, label+"-flat", flat, subject)
        if (receipt.get("status") != "returned" or receipt.get("abi_status") != 0
                or receipt.get("source_unchanged") is not True
                or receipt.get("forbidden_compiler_modules_loaded") != []
                or receipt.get("workspace_header", {}).get("40") != 0
                or not 0 < receipt.get("core_u32", 0) <= len(raw)):
            raise AssertionError((label, receipt))
        obj = compile_cli(exe, subject, output, label+"-1")
        if obj != raw[:receipt["core_u32"]] or obj != compile_cli(exe, subject, output, label+"-2"):
            raise AssertionError(label+" flat/CLI object differs")
        text_bytes(output, label, obj)
        relocs = subprocess.run(["readelf","-Wr",str(output/(label+".o"))],
                                check=True,capture_output=True,text=True).stdout
        (output/(label+"-relocs.txt")).write_text(relocs)
        entries = [line for line in relocs.splitlines() if "R_X86_64_PLT32" in line]
        for symbol in ("calloc","free"):
            if not any(symbol in line.split() for line in entries):
                raise AssertionError((label, symbol, relocs))
        lib = output/(label+".so")
        subprocess.run(["cc","-shared","-Wl,-z,noexecstack","-o",str(lib),str(output/(label+".o"))],check=True)
        observed, payload = candidate_invoke(output,label+"-native",lib,b"",
                                   image_format="linked-selfhost",capacity=8,workspace_size=0)
        if (observed.get("status") != "returned" or observed.get("abi_status") != 0
                or observed.get("core_u32") != 8 or payload != b"\0"*8
                or observed.get("source_unchanged") is not True):
            raise AssertionError((label,"native result",observed,payload.hex()))
        results.append({"case":label,"object_sha256":digest(obj),
                        "plt32_relocations":len(entries),"native_calls":1})
    return {"status":"PASS","cases":results}

def qualify_capacity(exe, output, flat):
    _, _, intervals, bound = candidate_layout()
    subject, expected = capacity_subject(CANDIDATE_BLOCKS, CANDIDATE_INSTRUCTIONS)
    # Retain the native compiler's actual scratch error code and source offset
    # on failure. The stdio wrapper alone intentionally reports only exit 2.
    # This observer executes the same HIA compiler generation, not a Python
    # implementation of subject compilation.
    flat_receipt, flat_bytes = candidate_invoke(output, "capacity-exact-flat", flat, subject)
    if (flat_receipt.get("status") != "returned"
            or flat_receipt.get("abi_status") != 0
            or not 0 < flat_receipt.get("core_u32", 0) <= len(flat_bytes)
            or flat_receipt.get("source_unchanged") is not True
            or flat_receipt.get("forbidden_compiler_modules_loaded") != []
            or flat_receipt.get("workspace_header", {}).get("40") != 0):
        raise AssertionError(("capacity-exact-flat", flat_receipt))
    obj = compile_cli(exe, subject, output, "capacity-exact-1")
    if obj != flat_bytes[:flat_receipt["core_u32"]]:
        raise AssertionError("capacity flat and CLI objects differ")
    if obj != compile_cli(exe, subject, output, "capacity-exact-2"):
        raise AssertionError("capacity repeat bytes differ")
    # Independent native execution, not just acceptance. Each exported
    # function traverses all of its blocks; compare wraparound and ordinary
    # inputs against arithmetic derived without the compiler.
    text_bytes(output, "capacity-exact", obj)
    lib = output / "capacity-exact.so"
    subprocess.run(["ld", "-shared", "-o", str(lib),
                    str(output / "capacity-exact.o")], check=True)
    runner = """import ctypes, json, sys
lib = ctypes.CDLL(sys.argv[1])
expected = json.loads(sys.argv[2])
for i, delta in enumerate(expected):
    fn = getattr(lib, "f" + str(i))
    fn.argtypes = [ctypes.c_uint64]
    fn.restype = ctypes.c_uint64
    for x in (0, 123456789, (1 << 64) - 1):
        assert fn(x) == (x + delta) % (1 << 64), (i, x, delta)
"""
    result = subprocess.run([sys.executable, "-I", "-c", runner, str(lib),
                             json.dumps(expected)], capture_output=True, timeout=30)
    (output / "capacity-native.stdout").write_bytes(result.stdout)
    (output / "capacity-native.stderr").write_bytes(result.stderr)
    if result.returncode != 0 or result.stdout or result.stderr:
        raise AssertionError(("capacity native execution", result.returncode))
    refusal_codes = {}
    for label, b, n, allowed in (
        ("capacity-block-over", CANDIDATE_BLOCKS + 1, CANDIDATE_INSTRUCTIONS, (11, 18)),
        ("capacity-instruction-over", CANDIDATE_BLOCKS, CANDIDATE_INSTRUCTIONS + 1, (54,)),
    ):
        malformed, _ = capacity_subject(b, n)
        receipt, _ = candidate_invoke(output, label + "-flat", flat, malformed)
        code = receipt.get("workspace_header", {}).get("40")
        if (receipt.get("status") != "returned"
                or receipt.get("abi_status") != 0
                or receipt.get("core_u32") != 4294967295
                or receipt.get("source_unchanged") is not True
                or receipt.get("forbidden_compiler_modules_loaded") != []
                or code not in allowed):
            raise AssertionError((label, "wrong refusal reason", receipt))
        refusal_codes[label] = code
        compile_cli(exe, malformed, output, label, expected=2)
    return {"status": "PASS", "blocks": CANDIDATE_BLOCKS,
            "instructions": CANDIDATE_INSTRUCTIONS, "scratch_intervals": intervals,
            "relocation_upper_bound": bound, "relocation_capacity": CANDIDATE_RELOCATIONS,
            "relocation_record_bytes": RELOCATION_RECORD_BYTES,
            "dense_relocations": qualify_dense_relocations(exe, output, flat),
            "external_relocations": qualify_external_relocations(exe, output, flat),
            "source_sha256": digest(subject),
            "object_sha256": digest(obj), "native_calls": len(expected) * 3,
            "over_limit_refusals": 2, "native_refusal_codes": refusal_codes,
            "flat_cli_object_identity": True}


ATOMIC_OBSERVER = ROOT / "tests/fixtures/hia_kernel_atomic64_observer.c"
CAS_EFFECTS = ("privilege", "atomic", "read", "write", "trap")
CAS_OPCODE = bytes.fromhex("f0480fb10a")
CAS_GUARD = bytes.fromhex("f6c20774020f0b")

def function_subject(count, cycle=False):
    # f0 -> f(count-1) -> ... -> f1; all high ordinal functions are
    # traversed at runtime. A cycle through the high ordinal must refuse.
    rows = [f"hia-asm.v1 {PROFILE} selfhost_elf", "exports(f0)"]
    for i in range(count):
        rows.extend((f"fn f{i}(v0:u64) -> (u64) effects() entry(b0)",
                     "block b0(v0:u64)"))
        if i == 1 and not cycle:
            rows.extend(('  v1:u64 = const() {"value":1}',
                         '  v2:u64 = int.add.wrap(v0,v1)', "  ret(v2)"))
        else:
            target = count - 1 if i == 0 else (0 if i == 1 else i - 1)
            rows.extend((f'  v1:u64 = call(v0) {{"function":"f{target}"}}',
                         "  ret(v1)"))
        rows.append("end")
    return ("\n".join(rows) + "\n").encode()

def qualify_function_capacity(exe, output, flat):
    subject = function_subject(CANDIDATE_FUNCTIONS)
    obj = compile_cli(exe, subject, output, "capacity-functions-exact")
    if obj != compile_cli(exe, subject, output, "capacity-functions-repeat"):
        raise AssertionError("function-capacity object bytes differ")
    # Exercise nonzero scratch initialization and compare the exact object
    # emitted by the flat compiler and the expanded executable CLI.
    receipt, flat_bytes = candidate_invoke(output, "capacity-functions-poisoned-flat",
                                           flat, subject, workspace_fill=0x5a)
    if (receipt.get("status") != "returned" or receipt.get("abi_status") != 0
            or receipt.get("core_u32") != len(obj)
            or receipt.get("source_unchanged") is not True
            or receipt.get("forbidden_compiler_modules_loaded") != []
            or flat_bytes[:len(obj)] != obj):
        raise AssertionError(("function-capacity poisoned workspace", receipt))
    text_bytes(output, "capacity-functions-exact", obj)
    lib = output / "capacity-functions-exact.so"
    subprocess.run(["ld", "-shared", "-o", str(lib),
                    str(output / "capacity-functions-exact.o")], check=True)
    runner = """import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
fn = lib.f0
fn.argtypes = [ctypes.c_uint64]
fn.restype = ctypes.c_uint64
for x in (0, 123456789, (1 << 64)-1):
    if fn(x) != (x+1) % (1 << 64): raise SystemExit(1)
"""
    p = subprocess.run([sys.executable, "-I", "-c", runner, str(lib)],
                       capture_output=True, timeout=30)
    (output / "capacity-functions-native.stdout").write_bytes(p.stdout)
    (output / "capacity-functions-native.stderr").write_bytes(p.stderr)
    if p.returncode or p.stdout or p.stderr:
        raise AssertionError(("function-capacity native", p.returncode))
    refusals = {}
    for label, bad, allowed in (
        ("capacity-functions-over", function_subject(CANDIDATE_FUNCTIONS + 1), (2,)),
        ("capacity-functions-cycle", function_subject(CANDIDATE_FUNCTIONS, cycle=True), (56,)),
    ):
        receipt, _ = candidate_invoke(output, label + "-flat", flat, bad)
        code = receipt.get("workspace_header", {}).get("40")
        if (receipt.get("status") != "returned" or receipt.get("abi_status") != 0
                or receipt.get("core_u32") != 4294967295 or code not in allowed
                or receipt.get("source_unchanged") is not True
                or receipt.get("forbidden_compiler_modules_loaded") != []):
            raise AssertionError((label, receipt))
        compile_cli(exe, bad, output, label, expected=2)
        refusals[label] = code
    # Distinct source/output/workspace limits: the old 1 MiB scratch and the
    # new bound minus one must refuse without touching output; exact bound
    # has already been exercised by all native generations and subjects.
    for size in (1 << 20, CANDIDATE_WORKSPACE - 1):
        receipt, _ = candidate_invoke(output, f"capacity-workspace-short-{size}",
                                      flat, subject, workspace_size=size)
        if (receipt.get("status") != "returned" or receipt.get("abi_status") != 0
                or receipt.get("core_u32") != 4294967294
                or receipt.get("output_unchanged") is not True
                or receipt.get("source_unchanged") is not True):
            raise AssertionError(("short candidate workspace", size, receipt))
    return {"status": "PASS", "functions": CANDIDATE_FUNCTIONS,
            "native_calls": 3, "native_refusal_codes": refusals,
            "short_workspace_refusals": 2, "poisoned_workspace_object_identity": True,
            "object_sha256": digest(obj)}

ATOMIC_OBSERVER = ROOT / "tests/fixtures/hia_kernel_atomic64_observer.c"
def cas_program(*, profile=PROFILE, effects=CAS_EFFECTS, types=("u64","u64","u64"),
                op="  v3:u64 = x86.atomic.cmpxchg64(v0,v1,v2)\n", module="selfhost_elf"):
    args = ",".join(f"v{i}:{typ}" for i, typ in enumerate(types))
    return (f"hia-asm.v1 {profile} {module}\nexports(f0)\n"
            f"fn f0({args}) -> (u64) effects({','.join(effects)}) entry(b0)\n"
            f"block b0({args})\n" + op + "  ret(v3)\nend\n").encode()

def qualify_atomic(exe, output):
    """Host-only independent oracle; no privilege authority or full SMP claim."""
    fence_op = "  _ = x86.fence.mfence()\n"
    fence = program(effect="atomic", op=fence_op)
    fence_bad = {
        "no-effect": program(effect="", op=fence_op),
        "privilege-only": program(effect="privilege", op=fence_op),
        "legacy": program(profile=LEGACY, effect="", op=fence_op),
        "legacy-declaration": program(profile=LEGACY, effect="atomic", op=""),
        "operand": program(effect="atomic", op="  _ = x86.fence.mfence(v0)\n"),
        "result": program(effect="atomic", op="  v1:u64 = x86.fence.mfence()\n"),
        "attribute": program(effect="atomic", op=fence_op.rstrip()+' {"trust_me":true}\n'),
        "duplicate-effect": program(effect="atomic,atomic", op=fence_op),
        "wrong-module": program(effect="atomic", module="selfhost", op=fence_op),
    }
    callee = ('fn f1(v0:u64) -> (u64) effects(atomic) entry(b0)\n'
              'block b0(v0:u64)\n' + fence_op + '  ret(v0)\nend\n').encode()
    caller = program(effect="atomic", op='  v1:u64 = call(v0) {"function":"f1"}\n')
    caller = caller.replace(b"  ret(v0)\n", b"  ret(v1)\n") + callee
    compile_cli(exe, caller, output, "mfence-call-propagation")
    fence_bad["caller-missing-atomic"] = caller.replace(b"effects(atomic)", b"effects()", 1)
    cas_bad = {
        "legacy": cas_program(profile=LEGACY, effects=()),
        "wrong-module": cas_program(module="selfhost"),
        "zero-operand": cas_program(op="  v3:u64 = x86.atomic.cmpxchg64()\n"),
        "two-operands": cas_program(op="  v3:u64 = x86.atomic.cmpxchg64(v0,v1)\n"),
        "extra-operand": cas_program(op="  v3:u64 = x86.atomic.cmpxchg64(v0,v1,v2,v2)\n"),
        "wrong-result": cas_program(op="  v3:u32 = x86.atomic.cmpxchg64(v0,v1,v2)\n").replace(b"-> (u64)",b"-> (u32)"),
        "no-result": cas_program(op="  _ = x86.atomic.cmpxchg64(v0,v1,v2)\n").replace(b"ret(v3)",b"ret(v0)"),
        "attribute": cas_program(op='  v3:u64 = x86.atomic.cmpxchg64(v0,v1,v2) {"trust_me":true}\n'),
        "duplicate-atomic": cas_program(effects=(*CAS_EFFECTS,"atomic")),
    }
    for effect in CAS_EFFECTS:
        cas_bad["missing-"+effect] = cas_program(effects=tuple(e for e in CAS_EFFECTS if e != effect))
    for i in range(3):
        types = ["u64"] * 3
        types[i] = "u32"
        cas_bad["wrong-type-"+str(i)] = cas_program(types=types)
    out = {}
    for label, subject, mnemonic, opcode, bad in (
            ("mfence",fence,"mfence",bytes.fromhex("0faef0"),fence_bad),
            ("cas64",cas_program(),"lock cmpxchgq %rcx,(%rdx)",CAS_OPCODE,cas_bad)):
        elf = compile_cli(exe,subject,output,label+"-1")
        if elf != compile_cli(exe,subject,output,label+"-2") or not elf.startswith(b"\x7fELF"):
            raise AssertionError(label+" repeated ELF differs")
        machine = text_bytes(output,label,elf)
        oracle_s = output / (label+"-oracle.s")
        oracle_s.write_text(".text\n "+mnemonic+"\n")
        oracle_o = output / (label+"-oracle.o")
        subprocess.run(["as","--64","-o",str(oracle_o),str(oracle_s)],check=True)
        if text_bytes(output,label+"-oracle-copy",oracle_o.read_bytes()) != opcode or machine.count(opcode) != 1:
            raise AssertionError(label+" GNU as oracle mismatch")
        for key, malformed in bad.items():
            compile_cli(exe,malformed,output,label+"-"+key,expected=2)
        original = output / (label+".o")
        def mutate(name,needle,replacement):
            if machine.count(needle)!=1 or len(needle)!=len(replacement):
                raise AssertionError((label,name,"mutation shape"))
            changed=machine.replace(needle,replacement,1)
            raw=output/(label+"-"+name+".text")
            raw.write_bytes(changed)
            target=output/(label+"-"+name+".o")
            subprocess.run(["objcopy","--update-section",".text="+str(raw),str(original),str(target)],check=True)
            if text_bytes(output,label+"-"+name+"-readback",target.read_bytes())!=changed or original.read_bytes()!=elf:
                raise AssertionError((label,name,"mutation custody"))
            return target
        nop=mutate("nop",opcode,b"\x90"*len(opcode))
        if opcode in (output/(label+"-nop.text")).read_bytes():
            raise AssertionError(label+" NOP not detected")
        results={}
        def execute(name,obj,mode,fence_only=False):
            runner=output/(label+"-"+name+"-observer")
            flags=["-DHIA_TEST_FENCE"] if fence_only else []
            subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror","-pthread","-Wl,-z,noexecstack",*flags,str(ATOMIC_OBSERVER),str(obj),"-o",str(runner)],check=True)
            proc=subprocess.run([str(runner),mode],capture_output=True,env={"PATH":""},timeout=30)
            (output/(label+"-"+name+".stdout")).write_bytes(proc.stdout)
            (output/(label+"-"+name+".stderr")).write_bytes(proc.stderr)
            if proc.returncode or proc.stderr:
                raise AssertionError((label,name,proc.returncode,proc.stderr))
            results[name]=json.loads(proc.stdout)
            if results[name].get("mode")!=mode or results[name].get("status")!="PASS":
                raise AssertionError((label,name,"observer status"))
        if label=="mfence":
            execute("native",original,"fence",True)
        else:
            guard_s=output/"cas64-guard-oracle.s"
            guard_s.write_text(".text\n testb $7,%dl\n jz 1f\n ud2\n1:\n")
            guard_o=output/"cas64-guard-oracle.o"
            subprocess.run(["as","--64","-o",str(guard_o),str(guard_s)],check=True)
            if text_bytes(output,"cas64-guard-oracle-copy",guard_o.read_bytes())!=CAS_GUARD or machine.count(CAS_GUARD)!=1:
                raise AssertionError("CAS alignment guard mismatch")
            guard_nop=mutate("guard-nop",CAS_GUARD,b"\x90"*len(CAS_GUARD))
            mutate("unlocked",opcode,b"\x90"+opcode[1:])
            if CAS_OPCODE in (output/"cas64-unlocked.text").read_bytes():
                raise AssertionError("LOCK deletion not detected")
            execute("native",original,"cas")
            execute("nop",nop,"nop")
            execute("guard-nop",guard_nop,"guard-nop")
        out[label]={"elf_sha256":digest(elf),"text_sha256":digest(machine),
                    "source_sha256":digest(subject),"oracle_hex":opcode.hex(),
                    "refusals":sorted(bad),"host_observer":results,
                    "nop_elf_sha256":digest(nop.read_bytes()),
                    "observer_sha256":digest(ATOMIC_OBSERVER.read_bytes())}
    return out



MMIO_GUARD = bytes.fromhex("f6c20374020f0b")
MMIO_EFFECTS = {"read32": ("privilege","read","trap"),
                "write32": ("privilege","write","trap")}

def mmio_program(action, *, profile=PROFILE, effects=None, address="u64",
                 value="u32", op=None, module="selfhost_elf"):
    if action not in MMIO_EFFECTS:
        raise ValueError(action)
    if effects is None:
        effects = MMIO_EFFECTS[action]
    if action == "read32":
        args, ret_type, ret = f"v0:{address}", "u32", "v1"
        operation = "  v1:u32 = x86.mmio.read32(v0)\n"
    else:
        args, ret_type, ret = f"v0:{address},v1:{value}", address, "v0"
        operation = "  _ = x86.mmio.write32(v0,v1)\n"
    return (f"hia-asm.v1 {profile} {module}\nexports(f0)\n"
            f"fn f0({args}) -> ({ret_type}) effects({','.join(effects)}) entry(b0)\n"
            f"block b0({args})\n" + (operation if op is None else op) +
            f"  ret({ret})\nend\n").encode()

def qualify_mmio(exe, output):
    """Exact native lowering; actual device/guard controls run in CPL0 QEMU."""
    guard_s = output / "mmio-guard-oracle.s"
    guard_s.write_text(".text\n testb $3,%dl\n jz 1f\n ud2\n1:\n")
    guard_o = output / "mmio-guard-oracle.o"
    subprocess.run(["as","--64","-o",str(guard_o),str(guard_s)],check=True)
    if text_bytes(output,"mmio-guard-oracle-copy",guard_o.read_bytes()) != MMIO_GUARD:
        raise AssertionError("MMIO GNU as guard mismatch")
    out = {}
    for action, mnemonic, opcode in (
            ("read32","movl (%rdx),%eax",bytes.fromhex("8b02")),
            ("write32","movl %eax,(%rdx)",bytes.fromhex("8902"))):
        label = "mmio-"+action
        subject = mmio_program(action)
        obj = compile_cli(exe,subject,output,label+"-1")
        if obj != compile_cli(exe,subject,output,label+"-2") or not obj.startswith(b"\x7fELF"):
            raise AssertionError(label+" repeated ELF differs")
        machine = text_bytes(output,label,obj)
        asm = output/(label+"-oracle.s")
        asm.write_text(".text\n "+mnemonic+"\n")
        oracle_o = output/(label+"-oracle.o")
        subprocess.run(["as","--64","-o",str(oracle_o),str(asm)],check=True)
        if (text_bytes(output,label+"-oracle-copy",oracle_o.read_bytes()) != opcode
                or machine.count(opcode) != 1 or machine.count(MMIO_GUARD) != 1
                or machine.index(MMIO_GUARD) >= machine.index(opcode)):
            raise AssertionError(label+" independent encoding/order mismatch")
        bad = {
            "legacy": mmio_program(action,profile=LEGACY,effects=()),
            "legacy-effect": mmio_program(action,profile=LEGACY),
            "wrong-module": mmio_program(action,module="selfhost"),
            "wrong-address": mmio_program(action,address="u32"),
            "duplicate-effect": mmio_program(action,effects=(*MMIO_EFFECTS[action],"privilege")),
        }
        for effect in MMIO_EFFECTS[action]:
            bad["missing-"+effect] = mmio_program(action,effects=tuple(e for e in MMIO_EFFECTS[action] if e != effect))
        if action == "read32":
            bad.update({
                "zero-operand": mmio_program(action,op="  v1:u32 = x86.mmio.read32()\n"),
                "extra-operand": mmio_program(action,op="  v1:u32 = x86.mmio.read32(v0,v0)\n"),
                "wrong-result": mmio_program(action,op="  v1:u64 = x86.mmio.read32(v0)\n").replace(b"-> (u32)",b"-> (u64)"),
                "no-result": mmio_program(action,op="  _ = x86.mmio.read32(v0)\n").replace(b"-> (u32)",b"-> (u64)").replace(b"ret(v1)",b"ret(v0)"),
                "attribute": mmio_program(action,op='  v1:u32 = x86.mmio.read32(v0) {"trust_me":true}\n'),
            })
        else:
            bad.update({
                "zero-operand": mmio_program(action,op="  _ = x86.mmio.write32()\n"),
                "one-operand": mmio_program(action,op="  _ = x86.mmio.write32(v0)\n"),
                "extra-operand": mmio_program(action,op="  _ = x86.mmio.write32(v0,v1,v1)\n"),
                "wrong-value": mmio_program(action,value="u64"),
                "result": mmio_program(action,op="  v2:u32 = x86.mmio.write32(v0,v1)\n"),
                "attribute": mmio_program(action,op='  _ = x86.mmio.write32(v0,v1) {"trust_me":true}\n'),
            })
        for key, malformed in bad.items():
            compile_cli(exe,malformed,output,label+"-"+key,expected=2)
        out[label] = {"elf_sha256":digest(obj),"text_sha256":digest(machine),
                      "source_sha256":digest(subject),"oracle_hex":opcode.hex(),
                      "guard_hex":MMIO_GUARD.hex(),"refusals":sorted(bad)}
    return out


def run(output):
    output.mkdir(parents=True, exist_ok=False)
    source, shape = candidate_source()
    (output / "candidate.hepta").write_bytes(source)
    (output / "candidate-shape.json").write_text(json.dumps(shape, sort_keys=True) + "\n")
    child = candidate_child(output)
    seed, _ = candidate_seed(output, source)
    b1, _ = candidate_compile_stage(output, "B1", seed, source, image_format="seed-shared")
    b2, _ = candidate_compile_stage(output, "B2", b1, source)
    b3, _ = candidate_compile_stage(output, "B3", b2, source)
    if not b1.read_bytes() == b2.read_bytes() == b3.read_bytes():
        raise AssertionError("candidate native generations disagree")
    executable_source = HEADER.replace(b"selfhost\n", b"selfhost_exec\n") + source[len(HEADER):]
    exe, _ = candidate_compile_stage(output, "compiler", b3, executable_source, output_extension="")
    exe.chmod(0o755)
    for i in (1, 2):
        rebuilt = compile_cli(exe, executable_source, output, f"self-rebuild-{i}")
        if rebuilt != exe.read_bytes():
            raise AssertionError("empty-PATH self-rebuild differs")
        exe = output / f"compiler-rebuilt-{i}"
        exe.write_bytes(rebuilt)
        exe.chmod(0o755)

    capacity = qualify_capacity(exe, output, b3)
    capacity["function_capacity"] = qualify_function_capacity(exe, output, b3)
    capacity["workspace_bytes"] = CANDIDATE_WORKSPACE
    capacity["workspace_observer_sha256"] = digest(child.read_bytes())
    compile_cli(exe, b"x" * ((1 << 20) + 1), output, "source-one-byte-over", expected=3)
    capacity["source_over_limit_refused"] = True
    capacity["source_and_output_limit_bytes"] = 1 << 20
    first = compile_cli(exe, program(), output, "invlpg-1")
    second = compile_cli(exe, program(), output, "invlpg-2")
    if first != second or not first.startswith(b"\x7fELF"):
        raise AssertionError("native ELF repeat failed")
    machine = text_bytes(output, "invlpg", first)
    asm = output / "oracle.s"
    asm.write_text(".text\n invlpg (%rax)\n")
    subprocess.run(["as", "--64", "-o", str(output / "oracle.o"), str(asm)], check=True)
    oracle = text_bytes(output, "oracle-copy", (output / "oracle.o").read_bytes())
    if machine.count(oracle) != 1:
        raise AssertionError("GNU as INVLPG oracle not found exactly once")
    dishonest = machine.replace(oracle, b"\x90" * len(oracle), 1)
    if dishonest.count(oracle) != 0:
        raise AssertionError("dishonest NOP control not detected")
    (output / "dishonest.text").write_bytes(dishonest)

    refusals = {
        "missing-effect": program(effect=""),
        "legacy-profile": program(profile=LEGACY),
        "legacy-opcode": program(profile=LEGACY, effect=""),
        "legacy-declaration": program(profile=LEGACY, op=""),
        "wrong-type": program(typ="u32"),
        "zero-operand": program(op="  _ = x86.tlb.invlpg()\n"),
        "extra-operand": program(op="  _ = x86.tlb.invlpg(v0,v0)\n"),
        "result": program(op="  v1:u64 = x86.tlb.invlpg(v0)\n"),
        "attribute": program(op='  _ = x86.tlb.invlpg(v0) {"trust_me":true}\n'),
        "duplicate-effect": program(effect="privilege,privilege"),
        "flat-profile": program(module="selfhost"),
        "missing-exports": program(exports=""),
    }
    for label, bad in refusals.items():
        compile_cli(exe, bad, output, label, expected=2)
    cr3 = compile_cli(exe, cr3_program(), output, "cr3-1")
    if cr3 != compile_cli(exe, cr3_program(), output, "cr3-2") or not cr3.startswith(b"\x7fELF"):
        raise AssertionError("CR3 native ELF repeat failed")
    cr3_text = text_bytes(output, "cr3", cr3)
    cr3_asm = output / "cr3-oracle.s"
    cr3_asm.write_text(".text\n movq %cr3, %rax\n")
    subprocess.run(["as", "--64", "-o", str(output / "cr3-oracle.o"), str(cr3_asm)], check=True)
    cr3_oracle = text_bytes(output, "cr3-oracle-copy", (output / "cr3-oracle.o").read_bytes())
    if cr3_oracle != bytes.fromhex("0f20d8") or cr3_text.count(cr3_oracle) != 1:
        raise AssertionError("CR3 GNU as oracle mismatch")
    cr3_refusals = {
        "cr3-no-effect": cr3_program(effect=""),
        "cr3-legacy": cr3_program(profile=LEGACY, effect=""),
        "cr3-argument": cr3_program(op="  v1:u64 = x86.cr3.read(v0)\n"),
        "cr3-no-result": cr3_program(op="  _ = x86.cr3.read()\n", result="v0"),
        "cr3-wrong-result": cr3_program(op="  v1:u32 = x86.cr3.read()\n", result="v0"),
        "cr3-attribute": cr3_program(op='  v1:u64 = x86.cr3.read() {"trust_me":true}\n'),
        "cr3-redefine": cr3_program(op="  v0:u64 = x86.cr3.read()\n", result="v0"),
    }
    for label, bad in cr3_refusals.items():
        compile_cli(exe, bad, output, label, expected=2)
    write_source = program(op="  _ = x86.cr3.write(v0)\n")
    write = compile_cli(exe, write_source, output, "cr3-write-1")
    if write != compile_cli(exe, write_source, output, "cr3-write-2") or not write.startswith(b"\x7fELF"):
        raise AssertionError("CR3 write ELF repeat failed")
    write_text = text_bytes(output, "cr3-write", write)
    write_asm = output / "cr3-write-oracle.s"
    write_asm.write_text(".text\n movq %rax, %cr3\n")
    subprocess.run(["as", "--64", "-o", str(output / "cr3-write-oracle.o"), str(write_asm)], check=True)
    write_oracle = text_bytes(output, "cr3-write-oracle-copy", (output / "cr3-write-oracle.o").read_bytes())
    if write_oracle != bytes.fromhex("0f22d8") or write_text.count(write_oracle) != 1:
        raise AssertionError("CR3 write GNU as oracle mismatch")
    write_refusals = {
        "write-no-effect": program(effect="", op="  _ = x86.cr3.write(v0)\n"),
        "write-legacy": program(profile=LEGACY, effect="", op="  _ = x86.cr3.write(v0)\n"),
        "write-zero-operand": program(op="  _ = x86.cr3.write()\n"),
        "write-extra-operand": program(op="  _ = x86.cr3.write(v0,v0)\n"),
        "write-wrong-type": program(typ="u32", op="  _ = x86.cr3.write(v0)\n"),
        "write-result": program(op="  v1:u64 = x86.cr3.write(v0)\n"),
        "write-attribute": program(op='  _ = x86.cr3.write(v0) {"trust_me":true}\n'),
    }
    for label, bad in write_refusals.items():
        compile_cli(exe, bad, output, label, expected=2)
    # CR2 uses the same typed zero-operand contract as CR3 read.
    cr2_source = cr3_program().replace(b"x86.cr3.read", b"x86.cr2.read")
    cr2 = compile_cli(exe, cr2_source, output, "cr2-1")
    if cr2 != compile_cli(exe, cr2_source, output, "cr2-2") or not cr2.startswith(b"\x7fELF"):
        raise AssertionError("CR2 native ELF repeat failed")
    cr2_text = text_bytes(output, "cr2", cr2)
    cr2_asm = output / "cr2-oracle.s"
    cr2_asm.write_text(".text\n movq %cr2, %rax\n")
    subprocess.run(["as", "--64", "-o", str(output / "cr2-oracle.o"), str(cr2_asm)], check=True)
    cr2_oracle = text_bytes(output, "cr2-oracle-copy", (output / "cr2-oracle.o").read_bytes())
    if cr2_oracle != bytes.fromhex("0f20d0") or cr2_text.count(cr2_oracle) != 1:
        raise AssertionError("CR2 GNU as oracle mismatch")
    cr2_refusals = {label.replace("cr3-", "cr2-"): bad.replace(b"x86.cr3.read", b"x86.cr2.read")
                    for label, bad in cr3_refusals.items()}
    for label, bad in cr2_refusals.items():
        compile_cli(exe, bad, output, label, expected=2)
    extra_reads = {}
    for reg, expected_hex in (("cr0", "0f20c0"), ("cr4", "0f20e0")):
        opcode = ("x86." + reg + ".read").encode()
        subject = cr3_program().replace(b"x86.cr3.read", opcode)
        native = compile_cli(exe, subject, output, reg + "-1")
        if native != compile_cli(exe, subject, output, reg + "-2") or not native.startswith(b"\x7fELF"):
            raise AssertionError(reg + " native ELF repeat failed")
        native_text = text_bytes(output, reg, native)
        asm = output / (reg + "-oracle.s")
        asm.write_text(".text\n movq %" + reg + ", %rax\n")
        oracle_object = output / (reg + "-oracle.o")
        subprocess.run(["as", "--64", "-o", str(oracle_object), str(asm)], check=True)
        reg_oracle = text_bytes(output, reg + "-oracle-copy", oracle_object.read_bytes())
        if reg_oracle != bytes.fromhex(expected_hex) or native_text.count(reg_oracle) != 1:
            raise AssertionError(reg + " GNU as oracle mismatch")
        reg_refusals = {label.replace("cr3-", reg + "-"): bad.replace(b"x86.cr3.read", opcode)
                    for label, bad in cr3_refusals.items()}
        for label, bad in reg_refusals.items():
            compile_cli(exe, bad, output, label, expected=2)
        extra_reads[reg + "_read"] = {"elf_sha256": digest(native), "text_sha256": digest(native_text),
            "oracle_hex": reg_oracle.hex(), "refusals": list(reg_refusals), "source_sha256": digest(subject)}

    extra_writes = {}
    for reg, expected_hex in (("cr0", "0f22c0"), ("cr4", "0f22e0")):
        label = reg + "-write"
        opcode = ("x86." + reg + ".write").encode()
        subject = write_source.replace(b"x86.cr3.write", opcode)
        obj = compile_cli(exe, subject, output, label + "-1")
        if obj != compile_cli(exe, subject, output, label + "-2") or not obj.startswith(b"\x7fELF"):
            raise AssertionError(label + " native ELF repeat failed")
        obj_text = text_bytes(output, label, obj)
        asm = output / (label + "-oracle.s")
        asm.write_text(".text\n movq %rax, %" + reg + "\n")
        oracle_object = output / (label + "-oracle.o")
        subprocess.run(["as", "--64", "-o", str(oracle_object), str(asm)], check=True)
        reg_oracle = text_bytes(output, label + "-oracle-copy", oracle_object.read_bytes())
        if reg_oracle != bytes.fromhex(expected_hex) or obj_text.count(reg_oracle) != 1:
            raise AssertionError(label + " GNU as oracle mismatch")
        negatives = {reg + "-" + key: bad.replace(b"x86.cr3.write", opcode)
                     for key, bad in write_refusals.items()}
        for key, bad in negatives.items():
            compile_cli(exe, bad, output, key, expected=2)
        extra_writes[reg + "_write"] = {"elf_sha256": digest(obj), "text_sha256": digest(obj_text),
            "oracle_hex": reg_oracle.hex(), "refusals": list(negatives), "source_sha256": digest(subject)}
    compile_cli(exe, write_source.replace(b"x86.cr3.write", b"x86.cr2.write"),
                output, "cr2-write-unavailable", expected=2)

    irq = {}
    for action, mnemonic, hexcode in (("disable", "cli", "fa"), ("enable", "sti", "fb")):
        label = "irq-" + action
        instruction = "x86.irq." + action
        operation = "  _ = " + instruction + "()\n"
        subject = program(op=operation)
        obj = compile_cli(exe, subject, output, label + "-1")
        if obj != compile_cli(exe, subject, output, label + "-2") or not obj.startswith(b"\x7fELF"):
            raise AssertionError(label + " native ELF repeat failed")
        obj_text = text_bytes(output, label, obj)
        asm = output / (label + "-oracle.s")
        asm.write_text(".text\n " + mnemonic + "\n")
        oracle_object = output / (label + "-oracle.o")
        subprocess.run(["as", "--64", "-o", str(oracle_object), str(asm)], check=True)
        irq_oracle = text_bytes(output, label + "-oracle-copy", oracle_object.read_bytes())
        if irq_oracle != bytes.fromhex(hexcode) or obj_text.count(irq_oracle) != 1:
            raise AssertionError(label + " GNU as oracle mismatch")
        bad = {
            "no-effect": program(effect="", op=operation),
            "legacy": program(profile=LEGACY, effect="", op=operation),
            "operand": program(op="  _ = " + instruction + "(v0)\n"),
            "result": program(op="  v1:u64 = " + instruction + "()\n"),
            "attribute": program(op=operation.rstrip() + ' {"trust_me":true}\n'),
            "wrong-module": program(module="selfhost", op=operation),
        }
        for key, malformed in bad.items():
            compile_cli(exe, malformed, output, label + "-" + key, expected=2)
        irq[label] = {"elf_sha256": digest(obj), "text_sha256": digest(obj_text),
            "oracle_hex": irq_oracle.hex(), "refusals": list(bad), "source_sha256": digest(subject)}

    port_io = {}
    for action, mnemonic, hexcode in (
            ("in8", "inb %dx, %al\n movzbl %al, %eax", "ec0fb6c0"),
            ("out8", "outb %al, %dx", "ee"),
            ("in16", "inw %dx, %ax\n movzwl %ax, %eax", "66ed0fb7c0"),
            ("out16", "outw %ax, %dx", "66ef"),
            ("in32", "inl %dx, %eax", "ed"),
            ("out32", "outl %eax, %dx", "ef")):
        label = "io-" + action
        subject = io_program(action)
        obj = compile_cli(exe, subject, output, label + "-1")
        if obj != compile_cli(exe, subject, output, label + "-2") or not obj.startswith(b"\x7fELF"):
            raise AssertionError(label + " native ELF repeat failed")
        obj_text = text_bytes(output, label, obj)
        asm = output / (label + "-oracle.s")
        asm.write_text(".text\n " + mnemonic + "\n")
        oracle_object = output / (label + "-oracle.o")
        subprocess.run(["as", "--64", "-o", str(oracle_object), str(asm)], check=True)
        io_oracle = text_bytes(output, label + "-oracle-copy", oracle_object.read_bytes())
        if io_oracle != bytes.fromhex(hexcode) or obj_text.count(io_oracle) != 1:
            raise AssertionError(label + " GNU as oracle mismatch")
        bad = {
            "no-effect": io_program(action, effect=""),
            "legacy": io_program(action, profile=LEGACY, effect=""),
            "wrong-port-type": io_program(action, port="u64"),
            "wrong-module": io_program(action, module="selfhost"),
        }
        if action.startswith("in"):
            bad.update({
                "zero-operand": io_program(action, op=f"  v1:u64 = x86.io.{action}()\n"),
                "extra-operand": io_program(action, op=f"  v1:u64 = x86.io.{action}(v0,v0)\n"),
                "attribute": io_program(action, op='  v1:u64 = x86.io.WIDTH(v0) {"trust_me":true}\n'.replace('WIDTH', action)),
                "wrong-result-type": io_program(action, op=f"  v1:u8 = x86.io.{action}(v0)\n").replace(b"-> (u64)", b"-> (u8)"),
                "no-result": io_program(action, op=f"  _ = x86.io.{action}(v0)\n").replace(b"-> (u64)", b"-> (u16)").replace(b"ret(v1)", b"ret(v0)"),
            })
        else:
            bad.update({
                "zero-operand": io_program(action, op=f"  _ = x86.io.{action}()\n"),
                "one-operand": io_program(action, op=f"  _ = x86.io.{action}(v0)\n"),
                "extra-operand": io_program(action, op=f"  _ = x86.io.{action}(v0,v1,v1)\n"),
                "wrong-value-type": io_program(action, value="u64"),
                "result": io_program(action, op=f"  v2:u8 = x86.io.{action}(v0,v1)\n"),
                "attribute": io_program(action, op='  _ = x86.io.WIDTH(v0,v1) {"trust_me":true}\n'.replace('WIDTH', action)),
            })
        for key, malformed in bad.items():
            compile_cli(exe, malformed, output, label + "-" + key, expected=2)
        port_io[label] = {"elf_sha256": digest(obj), "text_sha256": digest(obj_text),
            "oracle_hex": io_oracle.hex(), "refusals": list(bad), "source_sha256": digest(subject)}

    atomic = qualify_atomic(exe, output)
    mmio = qualify_mmio(exe, output)
    msr_report = msr.qualify(exe, output, PROFILE, LEGACY, compile_cli, text_bytes, digest)
    idtr_report = idtr.qualify(exe, output, PROFILE, LEGACY, compile_cli, text_bytes, digest)
    iretq_report = iretq.qualify(exe, output, PROFILE, LEGACY, compile_cli, text_bytes, digest)
    tr_report = tr.qualify(exe, output, PROFILE, LEGACY, compile_cli, text_bytes, digest)
    kernel_frame_report = kernel_frame.qualify(exe, output, PROFILE, LEGACY, compile_cli, text_bytes, digest)
    kernel_irq_report = kernel_irq.qualify(exe, output, PROFILE, LEGACY, compile_cli, text_bytes, digest)
    legacy = compile_cli(exe, program(profile=LEGACY, effect="", op=""), output, "legacy-scalar")
    if not legacy.startswith(b"\x7fELF"):
        raise AssertionError("legacy scalar ELF failed")
    if oracle != bytes.fromhex("0f0138") or machine.count(oracle) != 1 or len(refusals) != 12:
        raise AssertionError("INVLPG report binding changed while qualifying other opcodes")
    report = {"status": "PASS", "source_sha256": digest(source),
        "compiler_sha256": digest(exe.read_bytes()), "elf_sha256": digest(first),
        "text_sha256": digest(machine), "oracle_hex": oracle.hex(),
        "subject_source_sha256": digest(program()),
        "native_generations": 3, "empty_path_rebuilds": 2, "refusals": list(refusals),
        "cr3_read": {"elf_sha256": digest(cr3), "text_sha256": digest(cr3_text),
                     "oracle_hex": cr3_oracle.hex(), "refusals": list(cr3_refusals),
                     "source_sha256": digest(cr3_program())},
        "cr3_write": {"elf_sha256": digest(write), "text_sha256": digest(write_text),
                      "oracle_hex": write_oracle.hex(), "refusals": list(write_refusals),
                      "source_sha256": digest(write_source)},
        "cr2_read": {"elf_sha256": digest(cr2), "text_sha256": digest(cr2_text),
                     "oracle_hex": cr2_oracle.hex(), "refusals": list(cr2_refusals),
                     "source_sha256": digest(cr2_source)},
        **extra_reads,
        **extra_writes,
        "irq": irq,
        "port_io": port_io,
        "atomic": atomic,
        "mmio": mmio,
        "msr": msr_report,
        "idtr": idtr_report,
        "iretq": iretq_report,
        "tr": tr_report,
        "kernel_frame": kernel_frame_report,
        "kernel_irq": kernel_irq_report,
        "kernel_irq_authority_proved": False,
        "kernel_frame_authority_proved": False,
        "tr_authority_proved": False,
        "iretq_authority_proved": False,
        "idtr_authority_proved": False,
        "msr_authority_proved": False,
        "mmio_authority_proved": False,
        "memory_order_proved": False,
        "capacity": capacity,
        "unsupported_cr2_write_refused": True,
        "shape": shape, "guest_execution": "NOT_RUN", "full_linux_acceptance": "HOLD",
        "locked_compiler_changed": False, "privilege_authority_proved": False}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.output.resolve())

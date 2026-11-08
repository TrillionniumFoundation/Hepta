"""Independent, closed x86-64 byte semantics used by Safe Core validation.

This module intentionally imports neither the encoder nor the lowering module.
It decodes the final linked bytes, models integer flags and SysV stack effects,
and rejects unreviewed encodings.  These Python semantics are in the proof's
trust base; they are not an independently machine-checked Intel ISA model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import struct


class SafeCoreMachineRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise SafeCoreMachineRejected("E_HIA_SAFE_CORE_MACHINE: " + message)


@dataclass(frozen=True)
class Instruction:
    op: str
    args: tuple
    size: int


def decode(data):
    """Decode complete bytes, including unreachable code, with exact boundaries."""
    require(type(data) is bytes and 0 < len(data) <= 65536, "machine text budget exceeded")
    result, pc = {}, 0
    while pc < len(data):
        begin, rex = pc, None

        def take(count):
            nonlocal pc
            require(pc + count <= len(data), "truncated machine instruction")
            value = data[pc:pc + count]
            pc += count
            return value

        opcode = take(1)[0]
        if 0x40 <= opcode <= 0x4f:
            rex = opcode
            require(not rex & 2, "indexed memory addressing is outside the profile")
            opcode = take(1)[0]
        wide = rex is not None and bool(rex & 8)
        high_b = 8 if rex is not None and rex & 1 else 0
        high_r = 8 if rex is not None and rex & 4 else 0

        def modrm():
            value = take(1)[0]
            mode, group, low = value >> 6, (value >> 3) & 7, value & 7
            reg, rm = group + high_r, low + high_b
            require(mode in (2, 3), "only register or explicit base/disp32 addressing is admitted")
            if mode == 2:
                if low == 4:
                    require(take(1) == b"\x24", "unknown SIB addressing")
                disp = struct.unpack("<i", take(4))[0]
                return mode, reg, rm, disp, group
            return mode, reg, rm, None, group

        if 0x50 <= opcode <= 0x5f:
            require(rex is None or rex == 0x41, "unreviewed stack instruction prefix")
            op, args = ("push" if opcode < 0x58 else "pop"), ((opcode & 7) + high_b,)
        elif 0xb8 <= opcode <= 0xbf:
            require(rex is None or rex in (0x41, 0x48, 0x49), "unreviewed immediate prefix")
            value = int.from_bytes(take(8 if wide else 4), "little")
            op, args = "imm", ((opcode & 7) + high_b, value)
        elif opcode in (0xc3, 0xc9, 0x90):
            require(rex is None, "unreviewed single-byte prefix")
            op, args = {0xc3: "ret", 0xc9: "leave", 0x90: "nop"}[opcode], ()
        elif opcode in (0xe8, 0xe9):
            require(rex is None, "unreviewed direct branch prefix")
            displacement = struct.unpack("<i", take(4))[0]
            op, args = ("call" if opcode == 0xe8 else "jmp"), (pc + displacement,)
        elif opcode == 0x0f:
            extension = take(1)[0]
            if 0x80 <= extension <= 0x8f:
                require(rex is None, "unreviewed conditional branch prefix")
                displacement = struct.unpack("<i", take(4))[0]
                op, args = "jcc", (extension & 15, pc + displacement)
            elif 0x90 <= extension <= 0x9f:
                mode, reg, rm, disp, group = modrm()
                require(not wide and mode == 3 and group == 0 and high_r == 0 and rex is not None,
                        "unreviewed SETcc byte register")
                op, args = "setcc", (extension & 15, rm)
            elif extension == 0x45:
                mode, reg, rm, disp, group = modrm()
                require(wide and mode == 3,
                        "only 64-bit register-register CMOVNE is admitted")
                # Register-only selection has no conditional memory access.
                # REX.R extends the destination; REX.B extends the source.
                op, args = "cmovne", (reg, rm)
            elif extension == 0xb6:
                mode, reg, rm, disp, group = modrm()
                require(wide and mode == 2, "unreviewed zero-extending byte load")
                op, args = "load8", (reg, rm, disp)
            elif extension == 0x0b:
                require(rex is None, "unreviewed UD2 prefix")
                op, args = "ud2", ()
            else:
                raise SafeCoreMachineRejected("unsupported 0F opcode")
        elif opcode in (0x89, 0x8b, 0x8d, 0x88):
            mode, reg, rm, disp, group = modrm()
            if opcode == 0x88:
                require(not wide and rex is not None and mode == 2, "unreviewed byte store")
                op, args = "store8", (rm, disp, reg)
            else:
                require(wide, "non-64-bit ordinary move is outside the profile")
                if opcode == 0x89 and mode == 3:
                    op, args = "mov", (rm, reg)
                elif opcode == 0x89:
                    op, args = "store", (rm, disp, reg)
                else:
                    require(mode == 2, "unreviewed move/LEA register form")
                    op, args = ("load" if opcode == 0x8b else "lea"), (reg, rm, disp)
        elif opcode in (0x01, 0x29, 0x21, 0x09, 0x31, 0x39, 0x85):
            mode, reg, rm, disp, group = modrm()
            require(wide and mode == 3, "unreviewed ALU memory or narrow operand")
            op = {0x01: "add", 0x29: "sub", 0x21: "and", 0x09: "or", 0x31: "xor",
                  0x39: "cmp", 0x85: "test"}[opcode]
            args = (rm, reg)
        elif opcode in (0x81, 0x83):
            mode, reg, rm, disp, group = modrm()
            require(wide and mode == 3 and high_r == 0 and group in (0, 1, 4, 5, 6, 7),
                    "unreviewed immediate ALU instruction")
            immediate = int.from_bytes(take(4 if opcode == 0x81 else 1), "little", signed=True)
            op, args = "immediate_alu", ({0: "add", 1: "or", 4: "and", 5: "sub", 6: "xor", 7: "cmp"}[group], rm, immediate)
        elif opcode == 0xc1:
            mode, reg, rm, disp, group = modrm()
            count = take(1)[0]
            require(wide and mode == 3 and high_r == 0 and group in (4, 5) and count < 64,
                    "unreviewed shift instruction")
            op, args = ("shl" if group == 4 else "shr"), (rm, count)
        elif opcode == 0xf7:
            mode, reg, rm, disp, group = modrm()
            require(wide and mode == 3 and high_r == 0 and group == 2,
                    "unreviewed unary instruction")
            op, args = "not", (rm,)
        else:
            raise SafeCoreMachineRejected(f"unsupported machine opcode at byte {begin}")
        result[begin] = Instruction(op, args, pc - begin)
        require(len(result) <= 8192, "decoded instruction budget exceeded")
    for pc, instruction in result.items():
        if instruction.op in ("jmp", "jcc"):
            require(instruction.args[-1] in result, "branch is not an exact instruction boundary")
        if instruction.op in ("jcc", "setcc"):
            require(instruction.args[0] in (2, 3, 4, 5, 6, 7),
                    "only reviewed unsigned/equality conditions are admitted")
    return result


@dataclass
class State:
    pc: int
    path: object
    registers: dict
    flags: dict
    stack: dict
    stack_words: dict
    memory: object
    visited: frozenset = field(default_factory=frozenset)

    def fork(self, pc, path):
        return State(pc, path, dict(self.registers), dict(self.flags), dict(self.stack),
                     dict(self.stack_words), self.memory, self.visited)


class Executor:
    """Symbolically execute exact decoded bytes under an explicit caller contract."""

    def __init__(self, theory, binding, words, loan):
        self.t, self.z, self.ctx = theory, theory.z, theory.ctx
        self.code = decode(binding["text"])
        self.calls, self.entry = binding["calls"], binding["entry"]
        require({pc for pc, op in self.code.items() if op.op == "call"} == set(self.calls),
                "call instruction inventory differs from checked relocations")
        for pc, target in self.calls.items():
            if target != "abort":
                require(target in self.code and self.code[pc].args == (target,),
                        "call target is not an admitted function boundary")
        self.loan = loan
        self.words = words
        self.initial = {i: self.z.BitVec("native_register_" + str(i), 64, ctx=self.ctx) for i in range(16)}
        self.sp = self.z.BitVec("initial_rsp", 64, ctx=self.ctx)
        self.codebase = self.z.BitVec("loaded_text_base", 64, ctx=self.ctx)
        self.return_address = self.z.BitVec("caller_return_address", 64, ctx=self.ctx)
        self.initial[4] = self.sp
        for reg, value in zip((7, 6, 2, 1, 8, 9), words):
            self.initial[reg] = value
        self.unknown_stack = {}
        self.outcomes, self.faults, self.abi_faults = [], [], []
        self.steps = 0
        self.minimum_stack_offset = 0

    def value(self, n):
        return self.z.BitVecVal(n & ((1 << 64) - 1), 64, ctx=self.ctx)

    def offset(self, address):
        delta = self.z.simplify(address - self.sp)
        if not self.z.is_bv_value(delta):
            return None
        return delta.as_signed_long()

    def stack_offset(self, state):
        offset = self.offset(state.registers[4])
        require(offset is not None and -16384 <= offset <= 8,
                "stack pointer is not a bounded displacement of the caller stack")
        self.minimum_stack_offset = min(self.minimum_stack_offset, offset)
        return offset

    def memory(self, state, address, size, value=None):
        write = value is not None
        offset = self.offset(address)
        if offset is not None:
            low = self.stack_offset(state)
            allowed = low <= offset and offset + size <= (0 if write else 8)
            if not allowed:
                self.faults.append(state.path)
                state.path = self.z.BoolVal(False, ctx=self.ctx)
            if write:
                # Preserve exact aligned word values without asking the SMT
                # simplifier to reconstruct concatenated byte-extract additions.
                # Every overlapping write invalidates the cache first; bytes
                # remain authoritative for partial or unaligned reads.
                for start in list(state.stack_words):
                    if offset < start + 8 and start < offset + size:
                        del state.stack_words[start]
                for index in range(size):
                    state.stack[offset + index] = self.z.Extract(8 * index + 7, 8 * index, value)
                if size == 8:
                    state.stack_words[offset] = value
                return None
            if size == 8 and offset in state.stack_words:
                return state.stack_words[offset]
            result = []
            for index in range(size):
                at = offset + index
                if at not in self.unknown_stack:
                    self.unknown_stack[at] = self.z.BitVec("initial_stack_byte_" + str(at), 8, ctx=self.ctx)
                result.append(state.stack.get(at, self.unknown_stack[at]))
            return self.z.Concat(*reversed(result)) if size > 1 else result[0]
        if self.loan is None or size != 1 or (write and self.loan[2] != "mutbuf"):
            self.faults.append(state.path)
            state.path = self.z.BoolVal(False, ctx=self.ctx)
            return self.z.BitVecVal(0, size * 8, ctx=self.ctx)
        pointer, length, typ = self.loan
        allowed = self.z.And(length != 0, self.z.UGE(address, pointer),
                             self.z.ULT(address, pointer + length))
        self.faults.append(self.z.And(state.path, self.z.Not(allowed)))
        state.path = self.z.simplify(self.z.And(state.path, allowed))
        if write:
            state.memory = self.z.Store(state.memory, address, self.z.Extract(7, 0, value))
            return None
        return self.z.Select(state.memory, address)

    def condition(self, state, code):
        zf, cf = state.flags["zf"], state.flags["cf"]
        return {2: lambda: cf, 3: lambda: self.z.Not(cf), 4: lambda: zf,
                5: lambda: self.z.Not(zf), 6: lambda: self.z.Or(cf, zf),
                7: lambda: self.z.And(self.z.Not(cf), self.z.Not(zf))}[code]()

    def alu(self, state, action, destination, right):
        left = state.registers[destination]
        if action in ("add", "sub", "cmp"):
            result = left + right if action == "add" else left - right
            cf = self.z.ULT(result, left) if action == "add" else self.z.ULT(left, right)
        else:
            result = left & right if action in ("and", "test") else left | right if action == "or" else left ^ right
            cf = self.z.BoolVal(False, ctx=self.ctx)
        state.flags = {"zf": result == 0, "cf": cf}
        if action not in ("cmp", "test"):
            state.registers[destination] = self.z.simplify(result)

    def run(self):
        z = self.z
        stack = {i: z.Extract(8 * i + 7, 8 * i, self.return_address) for i in range(8)}
        initial = State(self.entry, z.BoolVal(True, ctx=self.ctx), dict(self.initial),
                        {f: z.Bool("initial_" + f, ctx=self.ctx) for f in ("zf", "cf")},
                        stack, {0: self.return_address}, self.t.memory)
        pending = [initial]
        states = 0
        while pending:
            state = pending.pop()
            states += 1
            require(states <= 4096, "machine path budget exceeded")
            while not z.is_false(z.simplify(state.path)):
                self.t.check_time()
                self.steps += 1
                require(self.steps <= 65536, "machine execution budget exceeded")
                require(state.pc in self.code and state.pc not in state.visited,
                        "unknown instruction entry, machine cycle or recursion")
                state.visited = state.visited | {state.pc}
                instruction = self.code[state.pc]
                op, args, nextpc = instruction.op, instruction.args, state.pc + instruction.size
                regs = state.registers
                if op == "imm":
                    regs[args[0]] = self.value(args[1])
                elif op == "mov":
                    regs[args[0]] = regs[args[1]]
                elif op == "cmovne":
                    destination, source = args
                    # Both operands and ZF belong to the pre-instruction state;
                    # this also preserves self-aliases. CMOV never changes flags.
                    regs[destination] = z.simplify(z.If(z.Not(state.flags["zf"]),
                        regs[source], regs[destination]))
                elif op in ("load", "load8", "lea"):
                    dst, base, disp = args
                    address = z.simplify(regs[base] + self.value(disp))
                    regs[dst] = (address if op == "lea" else self.memory(state, address, 8) if op == "load"
                                 else z.ZeroExt(56, self.memory(state, address, 1)))
                elif op in ("store", "store8"):
                    base, disp, src = args
                    self.memory(state, z.simplify(regs[base] + self.value(disp)), 8 if op == "store" else 1, regs[src])
                elif op in ("add", "sub", "and", "or", "xor", "cmp", "test"):
                    self.alu(state, op, args[0], regs[args[1]])
                elif op == "immediate_alu":
                    self.alu(state, args[0], args[1], self.value(args[2]))
                elif op == "not":
                    regs[args[0]] = ~regs[args[0]]
                elif op in ("shl", "shr"):
                    register, count = args
                    if count:
                        old = regs[register]
                        regs[register] = z.simplify(old << count if op == "shl" else z.LShR(old, count))
                        state.flags = {"zf": regs[register] == 0,
                                       "cf": z.Extract(64 - count if op == "shl" else count - 1,
                                                       64 - count if op == "shl" else count - 1, old) == 1}
                elif op == "setcc":
                    condition, register = args
                    regs[register] = z.simplify((regs[register] & self.value(~255)) |
                                               z.If(self.condition(state, condition), self.value(1), self.value(0)))
                elif op == "push":
                    value = regs[args[0]]
                    regs[4] = z.simplify(regs[4] - self.value(8))
                    self.memory(state, regs[4], 8, value)
                elif op in ("pop", "leave"):
                    register = args[0] if op == "pop" else 5
                    if op == "leave":
                        regs[4] = regs[5]
                    value = self.memory(state, regs[4], 8)
                    regs[4] = z.simplify(regs[4] + self.value(8))
                    regs[register] = value
                elif op == "call":
                    self.abi_faults.append(z.And(state.path, (regs[4] & self.value(15)) != 0))
                    target = self.calls[state.pc]
                    # CALL writes its return address before entering either a
                    # local function or a nonreturning external one.  Modelling
                    # abort as terminal must not erase this stack memory access.
                    regs[4] = z.simplify(regs[4] - self.value(8))
                    self.memory(state, regs[4], 8, self.codebase + self.value(nextpc))
                    if target == "abort":
                        self.outcomes.append(dict(kind="abort", path=state.path, value=self.value(0), memory=state.memory))
                        break
                    state.pc = target
                    continue
                elif op == "ret":
                    address = z.simplify(self.memory(state, regs[4], 8))
                    regs[4] = z.simplify(regs[4] + self.value(8))
                    if z.eq(address, self.return_address):
                        restored = z.And(regs[4] == self.sp + self.value(8),
                                         *[regs[r] == self.initial[r] for r in (3, 5, 12, 13, 14, 15)])
                        self.abi_faults.append(z.And(state.path, z.Not(restored)))
                        self.outcomes.append(dict(kind="return", path=state.path, value=regs[0], memory=state.memory))
                        break
                    displacement = z.simplify(address - self.codebase)
                    if not z.is_bv_value(displacement) or displacement.as_long() not in self.code:
                        self.faults.append(state.path)
                        break
                    state.pc = displacement.as_long()
                    continue
                elif op == "jmp":
                    state.pc = args[0]
                    continue
                elif op == "jcc":
                    condition = self.condition(state, args[0])
                    pending.append(state.fork(args[1], z.simplify(z.And(state.path, condition))))
                    state.path = z.simplify(z.And(state.path, z.Not(condition)))
                elif op == "ud2":
                    self.faults.append(state.path)
                    break
                elif op != "nop":
                    raise SafeCoreMachineRejected("instruction has no reviewed semantics")
                state.pc = nextpc
        return self.outcomes

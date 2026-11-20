"""Independent, closed x86-64 byte semantics used by Safe Core validation.

This module intentionally imports neither the encoder nor the lowering module.
It decodes the final linked bytes, models integer flags and SysV stack effects,
and rejects unreviewed encodings. Its selected HIA register formulas and
remaining host semantics are trusted, not a machine-checked Intel ISA model.
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


def decode(data, *, allow_variable_shifts=False, allow_unsigned_multiply=False,
           allow_unsigned_divide=False, allow_signed=False):
    """Decode complete bytes, including unreachable code, with exact boundaries."""
    require(type(allow_variable_shifts) is bool, "variable-shift admission must be explicit boolean")
    require(type(allow_unsigned_multiply) is bool, "unsigned-multiply admission must be explicit boolean")
    require(type(allow_unsigned_divide) is bool, "unsigned-divide admission must be explicit boolean")
    require(type(allow_signed) is bool, "signed-integer admission must be explicit boolean")
    from .hia_safe_core_x64_decode_native import selected_safe_core_x64_decode

    selected = selected_safe_core_x64_decode()
    profile = dict(allow_variable_shifts=allow_variable_shifts,
                   allow_unsigned_multiply=allow_unsigned_multiply,
                   allow_unsigned_divide=allow_unsigned_divide, allow_signed=allow_signed)
    return (_reference_decode(data, **profile) if selected is None else selected.decode(data, **profile))


def _reference_decode(data, *, allow_variable_shifts=False, allow_unsigned_multiply=False,
                      allow_unsigned_divide=False, allow_signed=False):
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
        elif opcode == 0x99:
            require(allow_signed and rex == 0x48, "only explicitly admitted CQO is supported")
            op, args = "cqo", ()
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
            elif extension == 0xaf:
                mode, reg, rm, disp, group = modrm()
                require(wide and mode == 3,
                        "only 64-bit register-register IMUL is admitted")
                op, args = "imul", (reg, rm)
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
            require(wide and mode == 3 and high_r == 0 and group in ((4, 5, 7) if allow_signed else (4, 5)) and count < 64,
                    "unreviewed shift instruction")
            op, args = {4: "shl", 5: "shr", 7: "sar"}[group], (rm, count)
        elif opcode == 0xd3:
            require(allow_variable_shifts, "variable shifts are outside the selected machine profile")
            mode, reg, rm, disp, group = modrm()
            require(wide and mode == 3 and high_r == 0 and group in ((4, 5, 7) if allow_signed else (4, 5)),
                    "unreviewed 64-bit register shift by CL")
            op, args = {4: "shl_cl", 5: "shr_cl", 7: "sar_cl"}[group], (rm,)
        elif opcode == 0xf7:
            mode, reg, rm, disp, group = modrm()
            require(wide and mode == 3 and high_r == 0 and group in ((2, 3, 4, 5, 6, 7) if allow_signed else (2, 4, 6)),
                    "unreviewed unary instruction")
            require(group != 4 or allow_unsigned_multiply,
                    "unsigned MUL is outside the selected machine profile")
            require(group != 6 or allow_unsigned_divide,
                    "unsigned DIV is outside the selected machine profile")
            op, args = {2: "not", 3: "neg", 4: "mul", 5: "imul_full", 6: "div", 7: "idiv"}[group], (rm,)
        else:
            raise SafeCoreMachineRejected(f"unsupported machine opcode at byte {begin}")
        result[begin] = Instruction(op, args, pc - begin)
        require(len(result) <= 8192, "decoded instruction budget exceeded")
    for pc, instruction in result.items():
        if instruction.op in ("jmp", "jcc"):
            require(instruction.args[-1] in result, "branch is not an exact instruction boundary")
        if instruction.op in ("jcc", "setcc"):
            allowed = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15) if allow_signed else (2, 3, 4, 5, 6, 7)
            require(instruction.args[0] in allowed,
                    "condition lies outside the selected machine profile" if allow_signed else
                    "only reviewed unsigned/equality conditions are admitted")
    return result


def _reference_validate_calls(code, calls):
    require({pc for pc, op in code.items() if op.op == "call"} == set(calls),
            "call instruction inventory differs from checked relocations")
    for pc, target in calls.items():
        if target != "abort":
            require(target in code and code[pc].args == (target,),
                    "call target is not an admitted function boundary")


def _reference_memory_admitted(offset, low, size, writing, loan):
    if offset is not None:
        return low <= offset and offset + size <= (0 if writing else 8)
    return loan is not None and size == 1 and (not writing or loan == "mutbuf")


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


def _unsigned_division(z, high, low, divisor):
    """Exact DIV r64 result and condition for avoiding architectural #DE.

    For B=2**64, H*B+L has a quotient below B exactly when H<D, for D>0.
    A constant-zero high word also reduces the exact quotient/remainder to
    64-bit operations. Only the independently executed state can supply that
    zero; producer intent or source arithmetic never supplies an assumption.
    """
    high = z.simplify(high)
    admitted = z.And(divisor != 0, z.ULT(high, divisor))
    if z.is_bv_value(high) and high.as_long() == 0:
        quotient, remainder = z.UDiv(low, divisor), z.URem(low, divisor)
    else:
        dividend, extended = z.Concat(high, low), z.ZeroExt(64, divisor)
        quotient = z.Extract(63, 0, z.UDiv(dividend, extended))
        remainder = z.Extract(63, 0, z.URem(dividend, extended))
    return z.simplify(quotient), z.simplify(remainder), z.simplify(admitted)


def _signed_division(z, high, low, divisor):
    """Exact IDIV r64 semantics, including an arbitrary old RDX:RAX.

    CQO commonly creates the sign-extension of RAX. When that identity is
    present in the independently executed state, a 64-bit quotient is exact
    except at MIN/-1. Otherwise compute the complete signed 128-bit dividend
    and require the mathematical quotient to fit the architectural register.
    No Core intent or producer declaration supplies the sign-extension premise.
    """
    high, low = z.simplify(high), z.simplify(low)
    if z.eq(high, z.simplify(low >> 63)):
        quotient, remainder = low / divisor, z.SRem(low, divisor)
        admitted = z.And(divisor != 0, z.Not(z.And(low == -(1 << 63), divisor == -1)))
    else:
        dividend, extended = z.Concat(high, low), z.SignExt(64, divisor)
        full_quotient = dividend / extended
        quotient = z.Extract(63, 0, full_quotient)
        remainder = z.Extract(63, 0, z.SRem(dividend, extended))
        admitted = z.And(divisor != 0, full_quotient == z.SignExt(64, quotient))
    return z.simplify(quotient), z.simplify(remainder), z.simplify(admitted)


class Executor:
    """Symbolically execute exact decoded bytes under an explicit caller contract."""

    signed_profile = False

    def __init__(self, theory, binding, words, loan, *, allow_variable_shifts=False,
                 allow_unsigned_multiply=False, allow_unsigned_divide=False, allow_signed=False):
        self.t, self.z, self.ctx = theory, theory.z, theory.ctx
        from .hia_safe_core_x64_decode_native import selected_safe_core_x64_decode

        self.signed_profile = allow_signed
        self.native_model = selected_safe_core_x64_decode()
        profile = dict(allow_variable_shifts=allow_variable_shifts,
                       allow_unsigned_multiply=allow_unsigned_multiply,
                       allow_unsigned_divide=allow_unsigned_divide, allow_signed=allow_signed)
        self.calls, self.entry = binding["calls"], binding["entry"]
        if self.native_model is None:
            self.code = _reference_decode(binding["text"], **profile)
            _reference_validate_calls(self.code, self.calls)
        else:
            self.code = self.native_model.decode(binding["text"], self.calls, **profile)
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
        allowed = (self._reference_stack_admitted(offset) if self.native_model is None
                   else self.native_model.stack_admitted(offset))
        require(allowed,
                "stack pointer is not a bounded displacement of the caller stack")
        self.minimum_stack_offset = min(self.minimum_stack_offset, offset)
        return offset

    @staticmethod
    def _reference_stack_admitted(offset):
        return offset is not None and -16384 <= offset <= 8

    def memory_admitted(self, offset, low, size, writing):
        loan = None if self.loan is None else self.loan[2]
        if self.native_model is None:
            return _reference_memory_admitted(offset, low, size, writing, loan)
        return self.native_model.memory_admitted(offset, low, size, writing, loan)

    def memory(self, state, address, size, value=None):
        write = value is not None
        offset = self.offset(address)
        if offset is not None:
            low = self.stack_offset(state)
            allowed = self.memory_admitted(offset, low, size, write)
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
        if not self.memory_admitted(None, None, size, write):
            self.faults.append(state.path)
            state.path = self.z.BoolVal(False, ctx=self.ctx)
            return self.z.BitVecVal(0, size * 8, ctx=self.ctx)
        pointer, length, _ = self.loan
        allowed = self.borrow_range(address, pointer, length)
        self.faults.append(self.z.And(state.path, self.z.Not(allowed)))
        state.path = self.z.simplify(self.z.And(state.path, allowed))
        if write:
            state.memory = self.z.Store(state.memory, address, self.z.Extract(7, 0, value))
            return None
        return self.z.Select(state.memory, address)

    def borrow_range(self, address, pointer, length):
        if self.native_model is None:
            return self._reference_borrow_range(address, pointer, length)
        return self.native_model.borrow_predicate(self.z, self.ctx, address, pointer, length)

    def _reference_borrow_range(self, address, pointer, length):
        return self.z.And(length != 0, self.z.UGE(address, pointer),
                          self.z.ULT(address, pointer + length))

    def address(self, operation, base, displacement):
        if self.native_model is None:
            return self._reference_address(base, displacement)
        value, _, _, _ = self.native_model.symbolic(
            self.z, self.ctx, operation, left=base, right=self.value(displacement),
        )
        if value is None:
            raise RuntimeError("missing native Safe Core effective address")
        return value

    def _reference_address(self, base, displacement):
        return self.z.simplify(base + self.value(displacement))

    def stack_adjustment(self, operation, pointer):
        if self.native_model is None:
            return self._reference_stack_adjustment(operation, pointer)
        adjusted, _, _, fault = self.native_model.symbolic(self.z, self.ctx, operation, left=pointer)
        if adjusted is None or (fault is not None) != (operation == "call"):
            raise RuntimeError("invalid native Safe Core stack adjustment")
        return adjusted, fault

    def _reference_stack_adjustment(self, operation, pointer):
        adjusted = pointer - self.value(8) if operation in ("push", "call") else pointer + self.value(8)
        fault = (pointer & self.value(15)) != 0 if operation == "call" else None
        return self.z.simplify(adjusted), fault

    def return_site(self, operand, *, recover=False):
        if self.native_model is None:
            return self._reference_return_site(operand, recover=recover)
        if recover:
            operation, left, right = "return_offset", operand, self.codebase
        else:
            operation, left, right = "call_address", self.codebase, self.value(operand)
        value, _, _, _ = self.native_model.symbolic(self.z, self.ctx, operation, left=left, right=right)
        if value is None:
            raise RuntimeError("missing native Safe Core return site")
        return value

    def _reference_return_site(self, operand, *, recover):
        if recover:
            return self.z.simplify(operand - self.codebase)
        return self.codebase + self.value(operand)

    def caller_restored(self, registers):
        if self.native_model is None:
            return self._reference_caller_restored(registers)
        return self.native_model.caller_restored(self.z, self.ctx, registers, self.initial, self.sp)

    def _reference_caller_restored(self, registers):
        return self.z.And(registers[4] == self.sp + self.value(8),
                          *(registers[r] == self.initial[r] for r in (3, 5, 12, 13, 14, 15)))

    def condition(self, state, code):
        if self.native_model is None:
            return self._reference_condition(state, code)
        _, _, _, condition = self.native_model.symbolic(
            self.z, self.ctx, "jcc", code, zf=state.flags["zf"], cf=state.flags["cf"],
            right=state.flags.get("sf"), arbitrary=state.flags.get("of"),
        )
        if condition is None:
            raise RuntimeError("missing native Safe Core condition")
        return condition

    def _reference_condition(self, state, code):
        zf, cf = state.flags["zf"], state.flags["cf"]
        if 2 <= code <= 7:
            return {2: lambda: cf, 3: lambda: self.z.Not(cf), 4: lambda: zf,
                5: lambda: self.z.Not(zf), 6: lambda: self.z.Or(cf, zf),
                7: lambda: self.z.And(self.z.Not(cf), self.z.Not(zf))}[code]()
        sf, of = state.flags["sf"], state.flags["of"]
        return {0: lambda: of, 1: lambda: self.z.Not(of),
                8: lambda: sf, 9: lambda: self.z.Not(sf),
                12: lambda: sf != of, 13: lambda: sf == of,
                14: lambda: self.z.Or(zf, sf != of),
                15: lambda: self.z.And(self.z.Not(zf), sf == of)}[code]()

    def sign(self, value):
        return self.z.Extract(63, 63, value) == 1

    def undefined_flag(self, operation, flag):
        return self.z.Bool(operation + "_undefined_" + flag + "_step_" + str(self.steps), ctx=self.ctx)

    def alu(self, state, action, destination, right):
        if self.native_model is None:
            self._reference_alu(state, action, destination, right)
            return
        left = state.registers[destination]
        formula = self.native_model.symbolic(
            self.z, self.ctx, action, left=left, right=right,
        )
        self.apply_register_formula(state, destination, formula)
        if self.signed_profile:
            self.apply_signed_flags(state, action, left, right)

    @staticmethod
    def apply_register_formula(state, destination, formula):
        value, zf, cf, branch = formula
        if branch is not None or (zf is None) != (cf is None):
            raise RuntimeError("invalid native Safe Core register effects")
        if value is not None:
            state.registers[destination] = value
        if zf is not None:
            state.flags.update(zf=zf, cf=cf)

    def apply_signed_flags(self, state, operation, left, right=None, *, count=0):
        recipe = {"shl_cl": "variable_shl", "shr_cl": "variable_shr"}.get(operation, operation)
        sf, of = self.native_model.signed_flags(
            self.z, self.ctx, recipe, left, right, count=count,
            sf=state.flags["sf"], of=state.flags["of"], arbitrary=self.undefined_flag(operation, "of"),
        )
        if sf is not None:
            state.flags.update(sf=sf, of=of)

    def _reference_alu(self, state, action, destination, right):
        left = state.registers[destination]
        if action in ("add", "sub", "cmp"):
            result = left + right if action == "add" else left - right
            cf = self.z.ULT(result, left) if action == "add" else self.z.ULT(left, right)
            of = self.z.And(self.sign(left) == self.sign(right) if action == "add"
                            else self.sign(left) != self.sign(right), self.sign(result) != self.sign(left))
        else:
            result = left & right if action in ("and", "test") else left | right if action == "or" else left ^ right
            cf = self.z.BoolVal(False, ctx=self.ctx)
            of = self.z.BoolVal(False, ctx=self.ctx)
        state.flags = {"zf": result == 0, "cf": cf, "sf": self.sign(result), "of": of}
        if action not in ("cmp", "test"):
            state.registers[destination] = self.z.simplify(result)

    def register_formula(self, state, operation, args):
        if self.native_model is None:
            self._reference_register_formula(state, operation, args)
            return
        parameter, right, arbitrary = 0, None, None
        if operation == "setcc":
            parameter, destination = args
            right, arbitrary = state.flags.get("sf"), state.flags.get("of")
        else:
            destination = args[0]
        if operation in ("cmovne", "imul"):
            right = state.registers[args[1]]
        elif operation in ("shl", "shr", "sar"):
            parameter = args[1]
        if operation == "imul":
            arbitrary = self.z.Bool("imul_undefined_zf_step_" + str(self.steps), ctx=self.ctx)
        left = state.registers[destination]
        formula = self.native_model.symbolic(
            self.z, self.ctx, operation, parameter, left=left, right=right,
            zf=state.flags["zf"], cf=state.flags["cf"], arbitrary=arbitrary,
        )
        self.apply_register_formula(state, destination, formula)
        if self.signed_profile and operation in ("neg", "shl", "shr", "sar"):
            self.apply_signed_flags(state, operation, left, count=parameter)
        if self.signed_profile and operation == "imul":
            state.flags.update(of=state.flags["cf"], sf=self.undefined_flag(operation, "sf"))

    def _reference_register_formula(self, state, op, args):
        z, regs = self.z, state.registers
        if op == "cmovne":
            destination, source = args
            # Both operands and ZF belong to the pre-instruction state;
            # this also preserves self-aliases. CMOV never changes flags.
            regs[destination] = z.simplify(z.If(z.Not(state.flags["zf"]),
                regs[source], regs[destination]))
        elif op == "imul":
            destination, source = args
            # Two-operand IMUL keeps the low product. CF and OF report signed
            # truncation, not unsigned overflow. Read both operands
            # before writing, including self-aliases.
            full = z.SignExt(64, regs[destination]) * z.SignExt(64, regs[source])
            product = z.Extract(63, 0, full)
            regs[destination] = z.simplify(product)
            # ZF is architecturally undefined. A fresh arbitrary value
            # overapproximates every allowed result; preserving the old
            # ZF or deriving it from the product could prove false code.
            overflow = full != z.SignExt(64, product)
            state.flags = {"cf": overflow, "of": overflow,
                "zf": self.undefined_flag("imul", "zf"), "sf": self.undefined_flag("imul", "sf")}
        elif op == "not":
            regs[args[0]] = ~regs[args[0]]
        elif op == "neg":
            old = regs[args[0]]
            result = -old
            regs[args[0]] = z.simplify(result)
            state.flags = {"cf": old != 0, "zf": result == 0,
                           "sf": self.sign(result), "of": old == self.value(1 << 63)}
        elif op in ("shl", "shr", "sar"):
            register, count = args
            if count:
                old = regs[register]
                regs[register] = z.simplify(old << count if op == "shl"
                                           else old >> count if op == "sar" else z.LShR(old, count))
                cf = z.Extract(64 - count if op == "shl" else count - 1,
                               64 - count if op == "shl" else count - 1, old) == 1
                of = (self.sign(regs[register]) != cf if op == "shl" else self.sign(old)
                      if op == "shr" else z.BoolVal(False, ctx=self.ctx)) if count == 1 else self.undefined_flag(op, "of")
                state.flags = {"zf": regs[register] == 0,
                               "cf": cf, "sf": self.sign(regs[register]), "of": of}
        elif op == "setcc":
            condition, register = args
            regs[register] = z.simplify((regs[register] & self.value(~255)) |
                                       z.If(self._reference_condition(state, condition), self.value(1), self.value(0)))

    def extended_registers(self, state, op, args):
        if self.native_model is None:
            self._reference_extended_registers(state, op, args)
            return
        z, regs = self.z, state.registers
        operand = args[0]
        if op in ("shl_cl", "shr_cl", "sar_cl"):
            recipe = {"shl_cl": "variable_shl", "shr_cl": "variable_shr", "sar_cl": "sar_cl"}[op]
            old, count = regs[operand], regs[1]
            formula = self.native_model.symbolic(z, self.ctx, recipe, left=old, right=count,
                                                 zf=state.flags["zf"], cf=state.flags["cf"])
            self.apply_register_formula(state, operand, formula)
            if self.signed_profile:
                self.apply_signed_flags(state, op, old, count)
            return
        # Fresh unknowns overapproximate the architecturally undefined flags;
        # the HIA recipe supplies the two words, carry and DIV admission.
        recipe = {"mul": "multiply_words", "div": "divide_words", "imul_full": "imul_full", "idiv": "idiv"}[op]
        carry = self.undefined_flag(op, "cf")
        # The short formula is valid only when the actual pre-instruction
        # high word is the HIA-computed sign extension of the low word.
        narrow = op == "idiv" and z.eq(z.simplify(regs[2]), self.cqo(z.simplify(regs[0])))
        low, high, cf, admitted = self.native_model.word_pair(z, self.ctx, recipe, regs[0], regs[2],
                                                              regs[operand], carry, parameter=int(narrow))
        require(low is not None and high is not None and cf is not None and
                (admitted is not None) == (op in ("div", "idiv")), "incomplete native two-word machine formula")
        regs[0], regs[2] = low, high
        state.flags.update(cf=cf, zf=self.undefined_flag(op, "zf"))
        if self.signed_profile:
            state.flags.update(sf=self.undefined_flag(op, "sf"),
                               of=cf if admitted is None else self.undefined_flag(op, "of"))
        if admitted is not None:
            state.path = z.simplify(z.And(state.path, admitted))

    def _reference_extended_registers(self, state, op, args):
        z, regs = self.z, state.registers
        if op in ("mul", "imul_full"):
            # One-operand MUL/IMUL read old RAX and the explicit source,
            # then write their full product to RDX:RAX. Capture
            # both first so RAX/RDX source aliases are also exact.
            extension = z.SignExt if op == "imul_full" else z.ZeroExt
            full = extension(64, regs[0]) * extension(64, regs[args[0]])
            low, high = z.Extract(63, 0, full), z.Extract(127, 64, full)
            regs[0], regs[2] = z.simplify(low), z.simplify(high)
            overflow = full != z.SignExt(64, low) if op == "imul_full" else high != 0
            # ZF and SF are undefined, not derived from either half.
            state.flags = {"cf": overflow, "of": overflow,
                "zf": self.undefined_flag(op, "zf"), "sf": self.undefined_flag(op, "sf")}
        elif op in ("div", "idiv"):
            # Read the old dividend and source before either output
            # is updated, including DIV RAX and DIV RDX aliases.
            semantics = _signed_division if op == "idiv" else _unsigned_division
            quotient, remainder, admitted = semantics(
                z, regs[2], regs[0], regs[args[0]])
            # #DE is neither a conforming return nor the declared
            # nonreturning libc abort. Its path therefore has no
            # admitted terminal outcome, which the totality obligation
            # must refute if any valid caller state can reach it.
            state.path = z.simplify(z.And(state.path, admitted))
            regs[0], regs[2] = quotient, remainder
            # Every modeled arithmetic flag receives an independent
            # arbitrary value; no preceding comparison survives.
            state.flags = {flag: self.undefined_flag(op, flag) for flag in ("cf", "zf", "sf", "of")}
        elif op in ("shl_cl", "shr_cl", "sar_cl"):
            register = args[0]
            # Intel SDM SAL/SAR/SHL/SHR: 64-bit operands mask CL to
            # six bits. Capture CL before writing even when RCX is
            # also the destination. Effective count zero preserves
            # both destination and every modeled flag.
            old, count = regs[register], regs[1] & self.value(63)
            value = old << count if op == "shl_cl" else old >> count if op == "sar_cl" else z.LShR(old, count)
            shifted_out = z.LShR(old, self.value(64) - count if op == "shl_cl"
                                else count - self.value(1)) & self.value(1)
            regs[register] = z.simplify(z.If(count == 0, old, value))
            one_bit_of = (self.sign(value) != (shifted_out == 1) if op == "shl_cl"
                          else self.sign(old) if op == "shr_cl" else z.BoolVal(False, ctx=self.ctx))
            shifted_of = z.If(count == 1, one_bit_of, self.undefined_flag(op, "of"))
            state.flags.update(zf=z.If(count == 0, state.flags["zf"], value == 0),
                               cf=z.If(count == 0, state.flags["cf"], shifted_out == 1))
            if "sf" in state.flags:
                state.flags.update(sf=z.If(count == 0, state.flags["sf"], self.sign(value)),
                                   of=z.If(count == 0, state.flags["of"], shifted_of))

    def cqo(self, low):
        if self.native_model is None:
            return self.z.simplify(low >> 63)
        value, _, _, _ = self.native_model.symbolic(self.z, self.ctx, "cqo", left=low)
        if value is None:
            raise RuntimeError("missing native Safe Core CQO result")
        return value

    def _initial_state(self):
        z = self.z
        stack = {i: z.Extract(8 * i + 7, 8 * i, self.return_address) for i in range(8)}
        return State(self.entry, z.BoolVal(True, ctx=self.ctx), dict(self.initial),
                     {f: z.Bool("initial_" + f, ctx=self.ctx) for f in ("zf", "cf", "sf", "of")},
                     stack, {0: self.return_address}, self.t.memory)

    def _path_live(self, state):
        return not self.z.is_false(self.z.simplify(state.path))

    def run(self):
        initial = self._initial_state()
        if self.native_model is None:
            self._reference_schedule(initial)
        else:
            self._native_schedule(initial)
        return self.outcomes

    def _reference_schedule(self, initial):
        pending = [initial]
        states = 0
        while pending:
            state = pending.pop()
            states += 1
            require(states <= 4096, "machine path budget exceeded")
            while self._path_live(state):
                self.t.check_time()
                self.steps += 1
                require(self.steps <= 65536, "machine execution budget exceeded")
                require(state.pc in self.code and state.pc not in state.visited,
                        "unknown instruction entry, machine cycle or recursion")
                state.visited = state.visited | {state.pc}
                finished, fork = self._instruction_step(state)
                if fork is not None:
                    pending.append(fork)
                if finished:
                    break

    def _native_schedule(self, initial):
        from .hia_safe_core_x64_decode_native import MAX_INSTRUCTIONS, SCHEDULER_LIVE

        scheduler = self.native_model.scheduler()
        # The decoder supplied the complete immutable PC inventory; Python
        # only looks up its ordinal for the HIA-owned path visit bitmap.
        ordinals = {pc: index for index, pc in enumerate(self.code)}
        states = {1: initial}
        last_handle = 1
        action, handle, steps = scheduler.start(last_handle)
        while action:
            state = states[handle]
            if action == SCHEDULER_LIVE:
                if self._path_live(state):
                    self.t.check_time()
                    action, handle, steps = scheduler.observed(True, ordinals.get(state.pc, MAX_INSTRUCTIONS))
                else:
                    del states[handle]
                    action, handle, steps = scheduler.observed(False)
            else:
                self.steps = steps
                finished, fork = self._instruction_step(state)
                fork_handle = 0
                if fork is not None:
                    last_handle += 1
                    states[last_handle] = fork
                    fork_handle = last_handle
                if finished:
                    del states[handle]
                action, handle, steps = scheduler.advance(finished, fork_handle)

    def _instruction_step(self, state):
        z = self.z
        fork = None
        instruction = self.code[state.pc]
        op, args, nextpc = instruction.op, instruction.args, state.pc + instruction.size
        regs = state.registers
        if op == "imm":
            regs[args[0]] = self.value(args[1])
        elif op == "mov":
            regs[args[0]] = regs[args[1]]
        elif op == "cqo":
            # CQO sign-extends the old RAX and changes no flags.
            regs[2] = self.cqo(regs[0])
        elif op in ("cmovne", "imul", "not", "neg", "shl", "shr", "sar", "setcc"):
            self.register_formula(state, op, args)
        elif op in ("mul", "div", "imul_full", "idiv", "shl_cl", "shr_cl", "sar_cl"):
            self.extended_registers(state, op, args)
        elif op in ("load", "load8", "lea"):
            dst, base, disp = args
            address = self.address(op, regs[base], disp)
            regs[dst] = (address if op == "lea" else self.memory(state, address, 8) if op == "load"
                         else z.ZeroExt(56, self.memory(state, address, 1)))
        elif op in ("store", "store8"):
            base, disp, src = args
            self.memory(state, self.address(op, regs[base], disp), 8 if op == "store" else 1, regs[src])
        elif op in ("add", "sub", "and", "or", "xor", "cmp", "test"):
            self.alu(state, op, args[0], regs[args[1]])
        elif op == "immediate_alu":
            self.alu(state, args[0], args[1], self.value(args[2]))
        elif op == "push":
            value = regs[args[0]]
            regs[4], _ = self.stack_adjustment(op, regs[4])
            self.memory(state, regs[4], 8, value)
        elif op in ("pop", "leave"):
            register = args[0] if op == "pop" else 5
            if op == "leave":
                regs[4] = regs[5]
            value = self.memory(state, regs[4], 8)
            regs[4], _ = self.stack_adjustment(op, regs[4])
            regs[register] = value
        elif op == "call":
            adjusted, fault = self.stack_adjustment(op, regs[4])
            self.abi_faults.append(z.And(state.path, fault))
            target = self.calls[state.pc]
            # CALL writes its return address before entering either a
            # local function or a nonreturning external one.  Modelling
            # abort as terminal must not erase this stack memory access.
            regs[4] = adjusted
            self.memory(state, regs[4], 8, self.return_site(nextpc))
            if target == "abort":
                self.outcomes.append(dict(kind="abort", path=state.path, value=self.value(0), memory=state.memory))
                return True, None
            state.pc = target
            return False, None
        elif op == "ret":
            address = z.simplify(self.memory(state, regs[4], 8))
            regs[4], _ = self.stack_adjustment(op, regs[4])
            if z.eq(address, self.return_address):
                restored = self.caller_restored(regs)
                self.abi_faults.append(z.And(state.path, z.Not(restored)))
                self.outcomes.append(dict(kind="return", path=state.path, value=regs[0], memory=state.memory))
                return True, None
            displacement = self.return_site(address, recover=True)
            if not z.is_bv_value(displacement) or displacement.as_long() not in self.code:
                self.faults.append(state.path)
                return True, None
            state.pc = displacement.as_long()
            return False, None
        elif op == "jmp":
            state.pc = args[0]
            return False, None
        elif op == "jcc":
            condition = self.condition(state, args[0])
            fork = state.fork(args[1], z.simplify(z.And(state.path, condition)))
            state.path = z.simplify(z.And(state.path, z.Not(condition)))
        elif op == "ud2":
            self.faults.append(state.path)
            return True, None
        elif op != "nop":
            raise SafeCoreMachineRejected("instruction has no reviewed semantics")
        state.pc = nextpc
        return False, fork

# Bind this executing module, including its top-level constants, to retained source.
from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)

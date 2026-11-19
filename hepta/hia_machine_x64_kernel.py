"""Isolated x86-64 kernel instruction byte encodings, not HIA Core opcodes.

KernelCode is an explicit subclass so the source-bound ordinary Code AST,
its native selected implementation, and its unprivileged HIA caller semantics
remain byte-for-byte unchanged. Do not execute these CPL0 instructions in a
host user process or expose them in HIA Core without authority/effect checking.
"""
from __future__ import annotations

from .hia_machine_x64 import Code, MachineEncodingError, _s32


class KernelCode(Code):
    """Experimental privileged x86-64 encoder, not selfhost_elf integration."""

    def read_cr3(self, dst):
        """MOV r64, CR3. CPU execution requires CPL0."""
        reg = self._reg(dst)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x20" + bytes([0xd8 | (reg & 7)]))

    def write_cr3(self, src):
        """MOV CR3, r64; no address-space ownership effects modeled yet."""
        reg = self._reg(src)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x22" + bytes([0xd8 | (reg & 7)]))

    def invlpg(self, base, disp=0):
        """INVLPG m8 with explicit 64-bit base and checked signed disp32."""
        reg = self._reg(base)
        displacement = _s32(disp)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x01" + bytes([0xb8 | (reg & 7)]) +
                  (b"\x24" if reg & 7 == 4 else b"") + displacement)

    def lidt(self, base, disp=0):
        """LIDT m80: memory operand must refer to a valid 10-byte IDTR image.

        Only the instruction is encoded here. Validity, provenance, CPL0
        authority and interrupt-safe sequencing need HIA verifier semantics.
        """
        reg = self._reg(base)
        displacement = _s32(disp)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x01" + bytes([0x98 | (reg & 7)]) +
                  (b"\x24" if reg & 7 == 4 else b"") + displacement)

    def lgdt(self, base, disp=0):
        """LGDT m80: encode a memory operand for a ten-byte GDTR image.

        No CPL0 authority, GDT lifetime, interrupt exclusion, canonical
        base or CPU-mode transition is established by this byte encoder.
        """
        reg = self._reg(base)
        displacement = _s32(disp)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x01" + bytes([0x90 | (reg & 7)]) +
                  (b"\x24" if reg & 7 == 4 else b"") + displacement)

    def ltr(self, selector):
        """LTR r16 from the low 16 bits of a GPR; CPU validates selector/TSS."""
        reg = self._reg(selector)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x00" + bytes([0xd8 | (reg & 7)]))

    def iretq(self):
        """IRETQ (REX.W + CF). Stack-frame/canonicality checks are not modeled."""
        self.emit(b"\x48\xcf")

    def _locked_memory(self, opcode, base, disp, source):
        """Emit LOCK + REX.W + 0F opcode m64,r64 after complete admission.

        Caller must prove owned, coherent, properly aligned memory. This
        direct encoder does not establish a concurrency or MMIO proof.
        """
        src = self._reg(source)
        address = self._reg(base)
        displacement = _s32(disp)
        if opcode not in (0xb1, 0xc1):
            raise MachineEncodingError("unreviewed locked memory operation")
        rex = 0x48 | ((src >> 3) << 2) | (address >> 3)
        modrm = 0x80 | ((src & 7) << 3) | (address & 7)
        sib = b"\x24" if (address & 7) == 4 else b""
        self.emit(b"\xf0" + bytes((rex, 0x0f, opcode, modrm)) + sib + displacement)

    def lock_cmpxchg(self, base, disp, desired):
        """Atomic CMPXCHG m64,r64. RAX holds expected, and old on failure."""
        self._locked_memory(0xb1, base, disp, desired)

    def lock_xadd(self, base, disp, addend):
        """Atomic XADD m64,r64. The register receives the old memory word."""
        self._locked_memory(0xc1, base, disp, addend)

    def _mov_control(self, opcode, gpr, control_number):
        """Admit only reviewed control registers, then encode a whole MOV.

        This remains a byte encoder only: CPL0, CR0/CR4 reserved bits, PCID,
        paging modes and side effects must be proved by the future verifier.
        """
        reg = self._reg(gpr)
        if type(control_number) is not int or control_number not in (0, 2, 3, 4):
            raise MachineEncodingError("unreviewed x86 control register")
        if opcode not in (0x20, 0x22) or (opcode == 0x22 and control_number == 2):
            raise MachineEncodingError("unreviewed control register direction")
        modrm = 0xc0 | (control_number << 3) | (reg & 7)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  bytes((0x0f, opcode, modrm)))

    def read_cr0(self, dst):
        """MOV r64, CR0. Requires CPL0 and a qualified CPU state."""
        self._mov_control(0x20, dst, 0)

    def write_cr0(self, src):
        """MOV CR0, r64. No mode-transition authority is provided here."""
        self._mov_control(0x22, src, 0)

    def read_cr2(self, dst):
        """MOV r64, CR2. Read-only fault-address sampling stage."""
        self._mov_control(0x20, dst, 2)

    def read_cr4(self, dst):
        """MOV r64, CR4. Requires CPL0."""
        self._mov_control(0x20, dst, 4)

    def write_cr4(self, src):
        """MOV CR4, r64. Feature-dependency verification is NOT implemented."""
        self._mov_control(0x22, src, 4)

    def _port_transfer(self, direction, width, port):
        """Encode only x86 IN/OUT AL/AX/EAX, imm8 or implicit DX port.

        These instructions require IOPL or CPL0 and explicit device ownership.
        The compiler must not infer a port from an arbitrary GPR/address.
        """
        if type(direction) is not str or direction not in ("in", "out"):
            raise MachineEncodingError("unreviewed I/O direction")
        if type(width) is not int or width not in (8, 16, 32):
            raise MachineEncodingError("I/O width must be exactly 8, 16 or 32")
        is_dx = type(port) is str and port == "dx"
        is_imm = type(port) is int and 0 <= port <= 255
        if not (is_dx or is_imm):
            raise MachineEncodingError("I/O port must be DX or exact imm8")
        op = (0xec if is_dx else 0xe4) if direction == "in" else (
            0xee if is_dx else 0xe6)
        if width != 8:
            op += 1
        self.emit((b"\x66" if width == 16 else b"") +
                  bytes((op,)) + (bytes((port,)) if is_imm else b""))

    def in_port(self, width, port="dx"):
        """IN from a DX-selected or literal imm8 port into AL/AX/EAX."""
        self._port_transfer("in", width, port)

    def out_port(self, width, port="dx"):
        """OUT from AL/AX/EAX to a DX-selected or literal imm8 port."""
        self._port_transfer("out", width, port)

    def mfence(self):
        """x86 MFENCE; not a portable cross-platform memory-order contract."""
        self.emit(b"\x0f\xae\xf0")

    def lfence(self):
        """x86 LFENCE; not a complete speculative-execution security proof."""
        self.emit(b"\x0f\xae\xe8")

    def sfence(self):
        """x86 SFENCE, including earlier non-temporal streaming stores."""
        self.emit(b"\x0f\xae\xf8")

    # Isolated stage only: no Core v8 opcode, authority, native selfhost path,
    # or guest execution is created by exposing these byte encodings.
    def cli(self):
        """CLI: mask maskable interrupts; CPL <= IOPL is a CPU precondition."""
        self.emit(b"\xfa")

    def sti(self):
        """STI: enable interrupts with architectural one-instruction shadow."""
        self.emit(b"\xfb")

    def rdmsr(self):
        """RDMSR: ECX selects MSR, EDX:EAX receives data; CPL0 required."""
        self.emit(b"\x0f\x32")

    def wrmsr(self):
        """WRMSR: ECX selects MSR, EDX:EAX provides data; CPL0 required.

        A future verifier must constrain MSR index, reserved bits, feature
        availability, cross-CPU state and side effects before any execution.
        """
        self.emit(b"\x0f\x30")

    def swapgs(self):
        """SWAPGS exchanges GS base/KERNEL_GS_BASE; CPL0 long mode only.

        Valid entry/exit sequencing must be proven separately; never use this
        unchecked before the CPU has established a legitimate kernel GS base.
        """
        self.emit(b"\x0f\x01\xf8")

    def cpuid(self):
        """CPUID, with EAX/ECX input and EAX/EBX/ECX/EDX results."""
        self.emit(b"\x0f\xa2")

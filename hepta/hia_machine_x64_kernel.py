"""Isolated x86-64 kernel instruction byte encodings, not HIA Core opcodes.

KernelCode is an explicit subclass so the source-bound ordinary Code AST,
its native selected implementation, and its unprivileged HIA caller semantics
remain byte-for-byte unchanged. Do not execute these CPL0 instructions in a
host user process or expose them in HIA Core without authority/effect checking.
"""
from __future__ import annotations

from .hia_machine_x64 import Code, _s32


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

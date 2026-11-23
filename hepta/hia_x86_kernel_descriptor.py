"""Isolated x86-64 descriptor-table machine encodings for the kernel stage.

This subclasses the unpromoted PrivilegedCode byte encoder. It is NOT a
HIA Core language opcode, privilege effect, verifier, or selfhost_elf lowering.
The only intended execution is in independently instrumented QEMU guests.
"""
from __future__ import annotations

import struct

from .hia_machine_x64 import MachineEncodingError, PrivilegedCode, _s32


class KernelDescriptorCode(PrivilegedCode):
    """Explicit kernel-only encoder; ordinary HIA Code stays unchanged."""

    def lidt(self, base: str, disp: int = 0) -> None:
        """LIDT m16&64, x86-64 0F 01 /3: read 10 bytes via a GPR base."""
        reg = self._reg(base)
        _s32(disp)  # Strict type/range admission before appending any byte.
        if disp == 0 and (reg & 7) != 5:
            mod, displacement = 0, b""
        elif -128 <= disp <= 127:
            mod, displacement = 1, struct.pack("<b", disp)
        else:
            mod, displacement = 2, _s32(disp)
        modrm = (mod << 6) | 0x18 | (reg & 7)
        sib = b"\x24" if (reg & 7) == 4 else b""
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x01" + bytes([modrm]) + sib + displacement)

    def ltr(self, selector_register: str) -> None:
        """LTR r/m16 (register form): low 16 bits identify a TSS descriptor.

        CPU performs descriptor validation, potentially raising #GP/#NP. This
        encoder does NOT prove GDT identity, TSS bounds, busy-bit state or CPL0.
        """
        reg = self._reg(selector_register)
        self.emit((b"\x41" if reg >= 8 else b"") +
                  b"\x0f\x00" + bytes([0xd8 | (reg & 7)]))

"""Unpromoted single-CPU x86 PTE-revoke effect plan -> direct x86-64 bytes.

This is an isolated host-side *staging* adapter, not HIA Core verifier or
selfhost_elf lowering. Claims in QuiescentOwner are untrusted caller inputs.
The emitted machine code checks real CR3 and the live old PTE before the
single aligned 64-bit write, then performs a local INVLPG. Run only in an
isolated CPL0 QEMU fixture, never in a host process.
"""
from __future__ import annotations

from dataclasses import dataclass

from hepta.hia_machine_x64 import PrivilegedCode

_U64 = 1 << 64
_PHYS_MASK = ((1 << 52) - 1) & ~((1 << 12) - 1)


class KernelEffectRejected(ValueError):
    """The staged effect sequence is outside its exact single-owner profile."""


@dataclass(frozen=True)
class QuiescentOwner:
    cpl: int
    cpu_count: int
    max_physical_address_bits: int
    interrupts_masked: bool
    preemption_disabled: bool
    exclusive_page_table_owner: bool
    dma_quiescent: bool
    pcid_disabled: bool
    global_pages_disabled: bool
    la57_disabled: bool
    upper_table_links_checked: bool
    pte_slot_identity_mapped: bool


@dataclass(frozen=True)
class LeafRevoke:
    active_cr3: int
    pte_slot_phys: int
    virtual_page: int
    expected_old_pte: int
    replacement_pte: int


def _require(ok, why):
    if not ok:
        raise KernelEffectRejected("E_HIA_X86_EFFECT: " + why)


def _u64(value):
    return type(value) is int and 0 <= value < _U64


def _canonical48(value):
    sign = (value >> 47) & 1
    return (value >> 48) == (0xffff if sign else 0)


def admit_leaf_revoke(owner: QuiescentOwner, request: LeafRevoke) -> None:
    """Static, supplied-context fail-closed profile; NO CPU ownership proof."""
    _require(type(owner) is QuiescentOwner and type(request) is LeafRevoke,
             "exact plan and authority record types required")
    _require(type(owner.cpl) is int and owner.cpl == 0 and
             type(owner.cpu_count) is int and owner.cpu_count == 1,
             "only one isolated CPL0 CPU")
    _require(type(owner.max_physical_address_bits) is int and
             36 <= owner.max_physical_address_bits <= 52,
             "physical width outside restricted profile")
    flags = (owner.interrupts_masked, owner.preemption_disabled,
             owner.exclusive_page_table_owner, owner.dma_quiescent,
             owner.pcid_disabled, owner.global_pages_disabled,
             owner.la57_disabled, owner.upper_table_links_checked,
             owner.pte_slot_identity_mapped)
    _require(all(type(x) is bool and x for x in flags),
             "all quiescence and paging exclusion claims required")
    for name, value in vars(request).items():
        _require(_u64(value), "invalid u64 " + name)
    phys_limit = 1 << owner.max_physical_address_bits
    _require(0 < request.active_cr3 < phys_limit and
             request.active_cr3 % 4096 == 0,
             "aligned physical CR3 root required; no PCID/PWT/PCD")
    _require(4096 <= request.pte_slot_phys < phys_limit and
             request.pte_slot_phys % 8 == 0 and
             (request.pte_slot_phys + 7) < phys_limit,
             "aligned physical 8-byte PTE slot required")
    _require(request.pte_slot_phys + 7 < (1 << 47),
             "identity-mapped PTE slot must have a canonical low VA")
    _require(request.pte_slot_phys // 4096 != request.active_cr3 // 4096,
             "leaf PTE cannot alias the PML4 root page")
    va = request.virtual_page
    _require(_canonical48(va) and va % 4096 == 0,
             "canonical 48-bit page-aligned VA required")
    old = request.expected_old_pte
    _require(old & 1 and not old & (1 << 8),
             "present, non-global PTE required")
    frame = old & _PHYS_MASK
    _require(0 < frame < phys_limit,
             "valid nonzero physical frame required")
    _require(frame != request.active_cr3 and
             frame != (request.pte_slot_phys & ~4095),
             "reclaimed frame cannot alias the root or PTE table page")
    _require((old & _PHYS_MASK) ==
             (old & (((1 << owner.max_physical_address_bits) - 1) & _PHYS_MASK)),
             "no reserved physical address bits")
    _require(request.replacement_pte == (old & ~1),
             "only exact Present-bit clearing is admitted")
    # Hardware CR3 and live PTE are rechecked in the emitted code. All other
    # authority facts remain caller assertions, NOT authenticated resources.


def lower_leaf_revoke(owner: QuiescentOwner, request: LeafRevoke) -> bytes:
    """Emit one guarded PTE Present-clear and local INVLPG; reject before bytes."""
    admit_leaf_revoke(owner, request)
    code = PrivilegedCode()
    code.read_cr3("rcx")
    code.mov_imm("r8", request.active_cr3)
    code.cmp("rcx", "r8")
    code.jcc("ne", "reject")
    # Direct Code.load/store intentionally use disp32. A +4096 base offset
    # preserves the PTE physical slot while retaining independent GNU-as
    # exact-byte disassembly (which would otherwise compress displacement 0).
    code.mov_imm("rax", request.pte_slot_phys - 4096)
    code.load("r9", "rax", 4096)
    code.mov_imm("rdx", request.expected_old_pte)
    code.cmp("r9", "rdx")
    code.jcc("ne", "reject")
    code.mov_imm("rdx", request.replacement_pte)
    code.store("rax", 4096, "rdx")
    code.mov_imm("rax", request.virtual_page)
    code.invlpg("rax")
    code.ret()
    code.label("reject")
    code.ud2()
    encoded, relocations = code.finalize()
    _require(relocations == [], "unreviewed external relocation")
    return encoded

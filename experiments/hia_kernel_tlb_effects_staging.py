"""Conservative single-CPU x86 page-table effect sequencing, *staging only*.

This is a static admission experiment for a future HIA kernel effect verifier.
It neither parses HIA Core v8 nor emits/executes instructions. Caller-supplied
root ownership, PTE readback and CPU state are assumptions, NOT proved facts.
No SMP, PCID, global translations, MMIO, interrupt/NMI reentrancy, or physical
frame reclamation is authorized. Do not substitute this for native HIA code.
"""
from __future__ import annotations

from dataclasses import dataclass


class KernelEffectRejected(ValueError):
    """An operation has no valid ordering or authority in this narrow profile."""


@dataclass(frozen=True, slots=True)
class PageTableEffectSummary:
    writes: int
    invalidations: int
    irq_mask_pairs: int
    touched_pages: tuple[int, ...]
    touched_slots: tuple[int, ...]


def _u64(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise KernelEffectRejected(field + " requires an exact u64")
    return value


def _canonical_page(value: object) -> int:
    va = _u64(value, "virtual page")
    top = va >> 48
    sign = (va >> 47) & 1
    if top != (0xffff if sign else 0) or va & 0xfff:
        raise KernelEffectRejected("virtual page must be canonical 48-bit and 4KiB aligned")
    return va


def _physical_pte_slot(value: object) -> int:
    slot = _u64(value, "physical PTE slot")
    # Restrict this experiment to nonzero, 8-byte-aligned RAM-range
    # physical PTE addresses. No actual ownership or RAM provenance is proved.
    if slot == 0 or slot >= (1 << 52) or slot & 7:
        raise KernelEffectRejected("physical PTE slot must be aligned and within 52 bits")
    return slot


def admit_single_cpu_tlb_sequence(
    steps: object, *, active_cr3: object, owned_root: object,
    cpl: object, cpu_count: object, pcid_enabled: object = False,
    global_pages: object = False,
) -> PageTableEffectSummary:
    """Check explicit page-table write/INVLPG/interrupt sequencing.

    Each planned PTE write includes a caller-declared physical slot. A slot
    may not be relabeled as another virtual page (nor may a virtual page
    change its slot) within the plan, even after an INVLPG. No page-table
    walk or ownership authentication is performed.
    A planned PTE write's expected_old and observed_old must agree, but the
    latter is caller-supplied; no memory or runtime readback is performed.
    Rewriting one VA later in this same plan requires the previous candidate
    as the next expected_old. This excludes unmodeled hardware A/D changes;
    the check does not establish that the real memory has this value.
    The sequence must be interrupt-masked for each write and flush, must
    flush each written VA before unmasking, and must end unmasked. This is
    deliberately *not* sufficient for Linux SMP or async exception safety.
    """
    root = _u64(active_cr3, "active_cr3")
    owner = _u64(owned_root, "owned_root")
    if root == 0 or root & 0xfff or root >= 1 << 52 or root != owner:
        raise KernelEffectRejected("active root requires aligned exact owner")
    if type(cpl) is not int or cpl != 0:
        raise KernelEffectRejected("CPL0 required")
    if type(cpu_count) is not int or cpu_count != 1:
        raise KernelEffectRejected("multi-CPU effect ordering not established")
    if type(pcid_enabled) is not bool or type(global_pages) is not bool:
        raise KernelEffectRejected("PCID/global flags must be exact booleans")
    if pcid_enabled or global_pages:
        raise KernelEffectRejected("PCID/global translation invalidation is not modeled")
    if type(steps) not in (tuple, list) or not 1 <= len(steps) <= 128:
        raise KernelEffectRejected("bounded explicit operation sequence required")

    masked = False
    pending: set[int] = set()
    touched: set[int] = set()
    # Within one admitted plan, a later write to the same page must use the
    # earlier write's candidate as its complete old word. An intervening
    # INVLPG orders the TLB, but does not reset the PTE's dataflow.
    # Hardware A/D updates and external writers are outside this model.
    last_candidate: dict[int, int] = {}
    slot_to_va: dict[int, int] = {}
    va_to_slot: dict[int, int] = {}
    touched_slots: set[int] = set()
    writes = invalidations = pairs = 0
    for index, step in enumerate(steps):
        if type(step) is not dict or type(step.get("op")) is not str:
            raise KernelEffectRejected(f"step {index}: exact operation record required")
        op = step["op"]
        if op == "irq.disable":
            if set(step) != {"op"} or masked:
                raise KernelEffectRejected("nested IRQ mask or unexpected fields")
            masked = True
        elif op == "irq.enable":
            if set(step) != {"op"} or not masked or pending:
                raise KernelEffectRejected("cannot unmask with outstanding TLB invalidation")
            masked = False
            pairs += 1
        elif op == "pte.write":
            if set(step) != {"op", "va", "slot_pa", "expected_old", "observed_old", "candidate"}:
                raise KernelEffectRejected("PTE write requires exact fields")
            va = _canonical_page(step["va"])
            slot = _physical_pte_slot(step["slot_pa"])
            old = _u64(step["expected_old"], "expected_old")
            seen = _u64(step["observed_old"], "observed_old")
            candidate = _u64(step["candidate"], "candidate")
            if not masked or va in pending or seen != old or candidate == old:
                raise KernelEffectRejected("PTE write not exclusively admitted or stale")
            if (slot in slot_to_va and slot_to_va[slot] != va) or (
                    va in va_to_slot and va_to_slot[va] != slot):
                raise KernelEffectRejected("physical PTE slot / virtual page alias changed")
            if slot in last_candidate and old != last_candidate[slot]:
                raise KernelEffectRejected("PTE write reuses a stale prior plan state")
            last_candidate[slot] = candidate
            slot_to_va[slot] = va
            va_to_slot[va] = slot
            pending.add(va)
            touched.add(va)
            touched_slots.add(slot)
            writes += 1
        elif op == "tlb.invlpg":
            if set(step) != {"op", "va"}:
                raise KernelEffectRejected("INVLPG requires exact address")
            va = _canonical_page(step["va"])
            if not masked or va not in pending:
                raise KernelEffectRejected("missing or mismatched pending invalidation")
            pending.remove(va)
            invalidations += 1
        else:
            raise KernelEffectRejected("unknown or forbidden privileged operation: " + op)

    if masked or pending or writes == 0 or writes != invalidations or pairs == 0:
        raise KernelEffectRejected("unbalanced IRQ/TLB effects at return")
    return PageTableEffectSummary(writes, invalidations, pairs,
                                  tuple(sorted(touched)), tuple(sorted(touched_slots)))

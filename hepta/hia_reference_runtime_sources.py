"""Whole-file source relation between the typed-resource and original v9 interpreters."""
from hashlib import sha256

TYPED_RESOURCE_SHA256 = "b5dfeb949c9fc1ba2b6b54c7b1b74a3142ba9e7ecfa346ad502b68144d35b0e5"
WORD_RUNTIME_SHA256 = "db118314608168799a0d2c1210cec04ba38981a329e8da6cf4debcd07b267aa0"

# Ranges use zero-based complete source lines. Each replacement is the earlier
# text needed to recover the independent word-runtime image. Both ends are pinned.
_PREVIOUS_LINES = (
    (10, 13, b""),
    (18, 19, b""),
    (20, 22, b""),
    (45, 52, b""),
    (113, 114, b""),
    (122, 125, b""),
    (137, 139, (
        b'                "live_owners": len(self.owners), "live_bytes": self.live_bytes,\n'
    )),
    (142, 144, b""),
    (149, 150, (
        b'                           "live_chains": len(self.chains),\n'
    )),
    (154, 157, b""),
    (200, 205, b""),
    (208, 215, (
        b'        if size == 0:\n'
    )),
    (216, 217, (
        b'        if size > (1 << 63) - 1:\n'
    )),
    (221, 222, (
        b'        if size > self.max_heap_bytes - self.live_bytes:\n'
    )),
    (223, 224, (
        b'        self.allocation_attempts += 1\n'
        b'        failed = self.allocation_fail_at == self.allocation_attempts\n'
    )),
    (232, 243, b""),
    (263, 268, (
        b'        if op == "const":\n'
    )),
    (393, 400, (
        b'            if op in WORD_LOADS:\n'
    )),
    (405, 411, (
        b'            if index >= len(owner.data):\n'
        b'                raise HIAProgramTrap("bounds", "byte load outside the borrowed buffer")\n'
        b'            result = [owner.data[index]]\n'
    )),
    (415, 421, (
        b'            if index >= len(owner.data):\n'
        b'                raise HIAProgramTrap("bounds", "byte store outside the borrowed buffer")\n'
        b'            owner.data[index] = value\n'
    )),
    (428, 432, (
        b'                fill_bytes(owner.data, 0, len(owner.data), value)\n'
    )),
    (440, 447, (
        b'            if size > len(destination.data) or size > len(source.data):\n'
        b'                raise HIAProgramTrap("bounds", "bulk copy exceeds an owner extent")\n'
        b'            # Distinct live allocations are guaranteed by the verified roots.\n'
        b'            memoryview(destination.data)[:size] = memoryview(source.data)[:size]\n'
    )),
    (457, 471, (
        b'            if (destination > extent or source > extent\n'
        b'                    or size > extent - destination or size > extent - source):\n'
        b'                raise HIAProgramTrap("bounds", "in-place byte range exceeds owned extent")\n'
        b'            if size:\n'
        b'                # Match memmove overlap semantics without O(size) host scratch.\n'
        b'                try:\n'
        b'                    move_bytes(owner.data, destination, source, size)\n'
        b'                except MemoryError as exc:\n'
        b'                    raise HIAProgramBudgetExceeded(\n'
        b'                        "host_memory", "in-place copy exceeds host memory") from exc\n'
    )),
    (478, 489, (
        b'            if offset > extent or size > extent - offset:\n'
        b'                raise HIAProgramTrap("bounds", "fill range exceeds owned extent")\n'
        b'            if size:\n'
        b'                try:\n'
        b'                    fill_bytes(owner.data, offset, size, value)\n'
        b'                except MemoryError as exc:\n'
        b'                    raise HIAProgramBudgetExceeded(\n'
        b'                        "host_memory", "range fill exceeds host memory") from exc\n'
    )),
    (498, 508, (
        b'            if (dst_offset > dst_size or src_offset > src_size\n'
        b'                    or size > dst_size - dst_offset or size > src_size - src_offset):\n'
        b'                raise HIAProgramTrap("bounds", "cross-owner range copy exceeds byte extent")\n'
        b'            if size:\n'
        b'                memoryview(destination.data)[dst_offset:dst_offset + size] = (\n'
        b'                    memoryview(source.data)[src_offset:src_offset + size])\n'
    )),
    (514, 522, (
        b'            # Snapshot both source bytes before modifying either position.\n'
        b'            if left >= len(owner.data) or right >= len(owner.data):\n'
        b'                raise HIAProgramTrap("bounds", "swap byte offset outside owner extent")\n'
        b'            a, b = owner.data[left], owner.data[right]\n'
        b'            owner.data[left], owner.data[right] = b, a\n'
    )),
    (560, 561, (
        b'                    value, parent = values[index], bindings[origin]\n'
        b'                    _underlying(value)\n'
        b'                    _underlying(parent)\n'
        b'                    if (not isinstance(value, _View) or not isinstance(parent, _View)\n'
        b'                            or typ == "mutbuf" and (not value.mutable or not parent.mutable)):\n'
        b'                        raise HIAProgramRejected("returned view permission invariant", "E_HIA_RUNTIME_INVARIANT")\n'
        b'                    if value is parent:\n'
        b'                        # Forwarding must not expose one consumable runtime view\n'
        b"                        # as both the caller's parent and its returned child.\n"
        b'                        values[index] = _View(parent, typ == "mutbuf")\n'
        b'                        self.loans_started += 1\n'
        b'                    elif value.parent is not parent:\n'
        b'                        raise HIAProgramRejected("returned view origin invariant", "E_HIA_RUNTIME_INVARIANT")\n'
    )),
    (571, 597, b""),
    (616, 623, (
        b'            validate_execution_observation(status, resources, steps=self.steps,\n'
    )),
    (643, 935, b""),
    (990, 991, (
        b'        values = machine.invoke(fn, arguments)\n'
    )),
    (1001, 1002, (
        b'    if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:\n'
    )),
)


def word_runtime_source(raw):
    """Recover the v9 image from its admitted typed-resource successor."""
    if type(raw) is not bytes or sha256(raw).hexdigest() != TYPED_RESOURCE_SHA256:
        raise ValueError('the typed-resource interpreter source differs')
    lines = raw.splitlines(keepends=True)
    for start, stop, previous in reversed(_PREVIOUS_LINES):
        lines[start:stop] = [previous]
    restored = b''.join(lines)
    if sha256(restored).hexdigest() != WORD_RUNTIME_SHA256:
        raise ValueError('the resource interpreter does not reconstruct its complete v9 predecessor')
    return restored

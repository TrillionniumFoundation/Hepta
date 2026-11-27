"""Whole-file source relation between the typed-resource and original v9 interpreters."""
from hashlib import sha256

TYPED_RESOURCE_SHA256 = "b5dfeb949c9fc1ba2b6b54c7b1b74a3142ba9e7ecfa346ad502b68144d35b0e5"
PACKAGE_INTEGER_SHA256 = "8295665a1f138f09f2613fdec8f9b20bb40541db5bdf426ffe640b273c61c2e9"
INITIAL_PACKAGE_SCALAR_SHA256 = "5110923716b1e60960e71ffa2a3678184c29b7a1a78bbb21743e40c486ae92ce"
PACKAGE_ALLOCATION_SHA256 = "eda571fbc25f37f299468db718123a1b30a6e71c587ca712aa8a49a6d6b3906a"
PACKAGE_LEDGER_SHA256 = "b0397a6778ddadd8136c4a76efb687508a9f8e2d9c8779817e0419d520537b4a"
PACKAGE_BORROWED_SHA256 = "320b1ddf801d521ecbf530646444c9faa1abdb0a2bf9a9f9a9d45113a3767f22"
PACKAGE_LEDGER_BORROWED_SHA256 = "6acf327f879f9c181e4ac3ddd90ff29459a3cb921a774bdc4cefe52e27c4f0f1"
PACKAGE_BULK_SHA256 = "c522f9f95d2dab53189b634c0ac6834902add6e9bad5953898a8cbda096e2d11"
PACKAGE_GRAPH_SHA256 = "341f245bedfc14d459459ba4dbe9b4a0e0f36a3a409a1b549a1e1debb88a9aaa"
OPCODE_MEMBERSHIP_SHA256 = "62d6f1a120f89c4bc1699fe9b305eda63ee10a41111c50a200f4ddbbaf208f8d"
PACKAGE_SCALAR_SHA256 = OPCODE_MEMBERSHIP_SHA256
PACKAGE_LEDGER_RUNTIME_SHA256S = frozenset((PACKAGE_LEDGER_SHA256, PACKAGE_LEDGER_BORROWED_SHA256, PACKAGE_BULK_SHA256, PACKAGE_GRAPH_SHA256, OPCODE_MEMBERSHIP_SHA256))
PACKAGE_SCALAR_DISPATCH_SHA256S = frozenset((
    INITIAL_PACKAGE_SCALAR_SHA256, PACKAGE_ALLOCATION_SHA256, PACKAGE_LEDGER_SHA256,
    PACKAGE_BORROWED_SHA256, PACKAGE_LEDGER_BORROWED_SHA256, PACKAGE_BULK_SHA256, PACKAGE_GRAPH_SHA256,
    OPCODE_MEMBERSHIP_SHA256,
))
RESOURCE_RUNTIME_SHA256S = PACKAGE_SCALAR_DISPATCH_SHA256S | {TYPED_RESOURCE_SHA256, PACKAGE_INTEGER_SHA256}
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


_ALLOCATION_INVERSE = (
    (208, 212, (
        b'        if self.scalar_reference is not None:\n'
        b'            decision, attempts = self.scalar_reference.allocation(\n'
        b'                size, self.max_heap_bytes, self.live_bytes, self.allocation_attempts, self.allocation_fail_at)\n'
        b'        else:\n'
    )),
    (213, 217, b''),
    (260, 269, b''),
    (279, 280, (
        b"            if not hasattr(self, '_package_integer'):\n"
        b'                from .hia_default_native import default_integer_image\n'
        b'                self._package_integer = default_integer_image()\n'
        b'            package_scalar = self._package_integer\n'
    )),
)

_LEDGER_INVERSE = (
    (18, 20, (
        b'from .hia_execution_ledger_native import SELECTOR as LEDGER_SELECTOR, installed_execution_ledger\n'
        b'from .hia_opcodes import ExecutionObservationRejected, WORD_LOADS, WORD_STORES, validate_execution_observation\n'
    )),
    (634, 635, (
        b'            validator = validate_execution_observation\n'
        b'            selected = os.environ.get(LEDGER_SELECTOR)\n'
        b'            if selected is not None:\n'
        b'                if not selected:\n'
        b"                    raise ValueError('native execution ledger selector must not be empty')\n"
        b'                validator = installed_execution_ledger(selected).validate\n'
    )),
)

_BORROWED_INVERSE = (
    (269, 275, b''),
    (417, 419, b'            if self.scalar_reference is not None:\n'),
    (421, 422, b'                    result = [self.scalar_reference.byte_operation(operation, owner.data, offset=index)]\n'),
    (423, 424, b'                    self.scalar_reference.byte_operation(operation, owner.data, offset=index, value=args[2])\n'),
    (430, 433, (
        b'            if self.scalar_reference is not None:\n'
        b'                result = [self.scalar_reference.byte_operation("load", owner.data, offset=index)]\n'
    )),
    (441, 444, (
        b'            if self.scalar_reference is not None:\n'
        b'                self.scalar_reference.byte_operation("store", owner.data, offset=index, value=value)\n'
    )),
)

_BULK_INVERSE = (
    (17, 18, b''),
    (270, 271, b'    def borrowed_byte_operation(self):\n'),
    (273, 275, b''),
    (458, 461, (
        b'                if self.scalar_reference is not None:\n'
        b'                    self.scalar_reference.byte_operation("fill", owner.data, count=len(owner.data), value=value)\n'
    )),
    (471, 474, (
        b'            if self.scalar_reference is not None:\n'
        b'                self.scalar_reference.byte_operation("copy", destination.data, source=source.data, count=size)\n'
    )),
    (490, 494, (
        b'                if self.scalar_reference is not None:\n'
        b'                    self.scalar_reference.byte_operation("move", owner.data, offset=destination,\n'
        b'                                                        source_offset=source, count=size)\n'
    )),
    (512, 515, (
        b'                if self.scalar_reference is not None:\n'
        b'                    self.scalar_reference.byte_operation("fill", owner.data, offset=offset, count=size, value=value)\n'
    )),
    (532, 536, (
        b'            if self.scalar_reference is not None:\n'
        b'                self.scalar_reference.byte_operation("copy_range", destination.data, offset=dst_offset,\n'
        b'                                                    source=source.data, source_offset=src_offset, count=size)\n'
    )),
    (549, 552, (
        b'            if self.scalar_reference is not None:\n'
        b'                self.scalar_reference.byte_operation("swap", owner.data, offset=left, source_offset=right)\n'
    )),
)

_GRAPH_INVERSE = (
    (623, 624, b''),
    (625, 632, (
        b'        result = (None if native is None else\n'
        b'                  native.program(self.program.canonical_bytes, fn["name"], arguments,\n'
        b'                                 self.max_steps, self.max_call_depth, machine=self))\n'
    )),
    (684, 685, b'    def __init__(self, machine):\n'),
    (686, 687, b'        self.native = machine.scalar_reference\n'),
)

# The actual current interpreter keeps the old comprehension for every
# non-exact-string opcode. Restore the complete preceding source, then apply
# the already admitted graph/resource chain; no unknown source is normalized.
_OPCODE_MEMBERSHIP_INVERSE = (
    (296, 301, b'        elif op in {f"int.{a}.{m}" for a in ("add", "sub", "mul") for m in ("checked", "wrap")}:\n'),
)

_PACKAGE_PREDECESSORS = {
    OPCODE_MEMBERSHIP_SHA256: (PACKAGE_GRAPH_SHA256, _OPCODE_MEMBERSHIP_INVERSE),
    PACKAGE_GRAPH_SHA256: (PACKAGE_BULK_SHA256, _GRAPH_INVERSE),
    PACKAGE_BULK_SHA256: (PACKAGE_LEDGER_BORROWED_SHA256, _BULK_INVERSE),
    PACKAGE_ALLOCATION_SHA256: (INITIAL_PACKAGE_SCALAR_SHA256, _ALLOCATION_INVERSE),
    PACKAGE_LEDGER_SHA256: (PACKAGE_ALLOCATION_SHA256, _LEDGER_INVERSE),
    PACKAGE_BORROWED_SHA256: (PACKAGE_ALLOCATION_SHA256, _BORROWED_INVERSE),
    PACKAGE_LEDGER_BORROWED_SHA256: (PACKAGE_LEDGER_SHA256, _BORROWED_INVERSE),
}


def word_runtime_source(raw):
    """Recover the v9 image from its admitted typed-resource successor."""
    digest = sha256(raw).hexdigest() if type(raw) is bytes else None
    while digest in _PACKAGE_PREDECESSORS:
        previous, inverse = _PACKAGE_PREDECESSORS[digest]
        lines = raw.splitlines(keepends=True)
        for start, stop, replacement in reversed(inverse):
            lines[start:stop] = [replacement]
        raw = b''.join(lines)
        digest = sha256(raw).hexdigest()
        if digest != previous:
            raise ValueError('the package interpreter differs from its complete predecessor')
    additions = {
        PACKAGE_INTEGER_SHA256: ((274, 276), (265, 271), (17, 18)),
        INITIAL_PACKAGE_SCALAR_SHA256: ((273, 275), (264, 270)),
    }
    if digest in additions:
        lines = raw.splitlines(keepends=True)
        for start, stop in additions[digest]:
            del lines[start:stop]
        raw = b''.join(lines)
    if type(raw) is not bytes or sha256(raw).hexdigest() != TYPED_RESOURCE_SHA256:
        raise ValueError('the typed-resource interpreter source differs')
    lines = raw.splitlines(keepends=True)
    for start, stop, previous in reversed(_PREVIOUS_LINES):
        lines[start:stop] = [previous]
    restored = b''.join(lines)
    if sha256(restored).hexdigest() != WORD_RUNTIME_SHA256:
        raise ValueError('the resource interpreter does not reconstruct its complete v9 predecessor')
    return restored

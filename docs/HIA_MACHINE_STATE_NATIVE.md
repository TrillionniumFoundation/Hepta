# Explicit HIA Code state control

`HEPTA_HIA_MACHINE_STATE_MANIFEST` selects the HIA `HIACST01` continuation
together with an explicitly selected `HEPTA_HIA_MACHINE_ENCODING_MANIFEST`.
The state selector alone refuses before constructing ordinary `Code`. Both
selections, including no selection, are pinned across a whole backend emission
and included in its implementation identity. Existing subclasses retain their
original virtual methods.

The six HIA-owned ordinary operations are initialization, `emit`, `label`,
`offset`, `_reg`, and `finalize`. HIA chooses validation and refusal order,
scratch mapping and option admission, the 64 MiB code limit, the 512-character
label limit, register-name admission, fixup iteration, signed rel32 admission,
and relocation-copy order. Literal field names, options and errors are emitted
from the checked-in HIA source. The separate HIA instruction encoder produces
the rel32 bytes.

Public `data`, `labels`, `fixups`, and `relocations` remain the actual mutable
Python objects. There is no hidden native copy of their current state. The
continuation reobserves attributes, binds methods, performs actual iteration,
arithmetic and slicing, and copies relocation rows at the original points.
The bridge consumes each requested effect before invoking it; an exception or
terminal response closes the session and cannot silently replay an effect.
Object handles remain strongly referenced for the invocation. Primitive Python
allocation, arithmetic, object identity, container behavior and foreign effects
remain hosted boundaries, including interpreter resource behavior.

Other instruction operand checks, branch/fixup/relocation append decisions,
general Core lowering, ELF output, linking, installation and default activation
remain separate owners. This component does not claim a fully replaced Code
class, general backend, interpreter-free runtime, all-input equivalence or
complete native delivery. The original complete Code class remains an
independent oracle, with an exact 608 fixture; no supported old owner is removed.

The strict builder admits a completed cold report for the current entire source
contract before creating its output. Reusing an actual prior compiler image for
development is explicitly distinct and cannot produce matching-current-source
cold or full-qualification claims. Compiler line, operation, block, SSA,
function and source-byte limits are unchanged.

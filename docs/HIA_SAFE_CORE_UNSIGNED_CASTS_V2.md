# Explicit Safe Core v2: u16 and checked unsigned casts

The optional v2 profile extends independent final-image validation to `u16`
and checked casts between `u8`, `u16`, `u32`, `u64` and `usize`. Original v1
remains the default with its original type and cast boundary. The Agent service
continues to use v1; this grants no adoption or execution authority and changes
no public installation lock.

Set `profile_version=2` in `build_safe_core`, `validate_safe_core_image` or
`validate_safe_core_artifact`, or pass `--profile-version 2` to the retained
build/check CLI. Only exact integer versions 1 and 2 are accepted.

The canonical profile is
`hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v2`; the independent profile
is `hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v2`.
The compatible report schema remains v1; the explicit profile identifier
selects the larger semantic boundary.

## Cast semantics and trust

Raw ABI arguments are normalized to their source width. An unsigned value `x`
fits destination width `w` exactly when `x <= 2**w - 1`. A checked cast returns
that value or aborts; wrapping retains the low `w` bits. Equal-width and widening
casts cannot overflow. The independent Core model uses an unsigned bitvector
comparison and retains preceding caller-memory changes on an abort.

The byte decoder, ELF binding, ABI preservation, memory bounds, terminal paths
and five solver obligations retain their original meaning. The identified
Python models, Z3 implementation, Core verifier and caller/loader contract
remain trusted. No general compiler or hardware-ISA theorem is added.

## Reproduce

```sh
python -B -m unittest tests.test_hia_safe_core_unsigned_casts -v
python -B tools/qualify_hia_safe_core_unsigned_casts.py --output /tmp/new-cast-proof-evidence
```

The retained qualification has 25 unsigned cast type pairs and one program
that writes a caller byte before narrowing: 26 programs and 130 original solver
obligations. Fresh contexts replay the same 130 hashed query files; these are
not additional independent properties. Three representative artifacts are
also rechecked from pinned Core/object/final-image bytes.

Tests cover v1 compatibility, strict version selection, mathematical boundaries,
u16 arithmetic, dirty ABI words, bit operations, six comparisons, select, block
parameters and CLI propagation. A normal wrapping artifact fails the different
checked specification with a mathematical witness; the test executes no
overflowing native call or modified machine image.

Proof envelopes retain subject, property, profile, assumptions, checker identity
and unproved obligations. Signed scalars, loops, multiple functions, general
resource ownership, full compiler/ABI/FFI/ISA/loader correctness and original
unfamiliar-Agent whole-program claims remain open. Six-track acceptance is HOLD.

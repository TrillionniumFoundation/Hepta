# Independent seed bulk profiles

The original v1 seed and separately qualified unsigned division seed remain
byte-for-byte unchanged. The additional `seed_bulk_backend.hepta` adds only raw
resource opcode 10 (`buffer.move_within`) to v1. The separate
`seed_div_bulk_backend.hepta` composes that operation with the existing div
profile; it is not a replacement for either earlier root.

## Wire and machine behavior

The existing HIAERW02 input and six-word borrowed-buffer entry ABI are unchanged.
Output is exactly 1 MiB and workspace is at least 1 MiB, as for v1. A move site
requires kind 4 (mutable view), four inputs (view, destination offset, source
offset, count), and no outputs. Other raw validation limits are unchanged.

The generated x86-64 code validates both complete ranges with unsigned
subtractions before writing any destination byte. This avoids addition wraparound.
Zero length still checks both offsets and permits an offset equal to the view
extent. It uses forward REP MOVSB except for rightward overlapping ranges,
which use backward REP MOVSB. The direction flag is clear on every returning
path. Failure enters the existing UD2 trap and leaves the whole destination
unchanged by this operation; earlier program effects remain visible.

This is memmove semantics. Callers replacing an existing forward byte loop must
first prove the complete ranges valid and disjoint when the old loop exposes
partial writes or overlapping forward propagation. The cold driver preserves
its original byte loop for those cases.

## Independent construction and evidence

Both new sources were assembled, projected, compiled and packed by the retained
original native v1 roots, with an empty PATH and no child compiler or interpreter.
No target selfhost compiler or successor produced this root. The two profiles
were subsequently rebuilt by the new bulk seed and produced identical bytes.

The qualification record alongside this document fixes all source/image pins,
original immutable roots, complete evidence reports and replay scripts. It
covers 393 fresh complete-HIA-VM versus native-process cases, the original 75
raw refusals and five ABI controls, 106 additional move refusals per profile,
75 existing div-domain comparisons, and seven actual returned-direction-flag
probes. Normal, zero-length, overlap in both directions, full-u64 adversarial
ranges, prior-effect preservation, and 1 MiB moves are included.

All 15 original source components were independently reassembled and projected,
then compiled through the bulk seed. Their Core, reference wire and machine
bytes match the retained original roots. Repacked original assembly, projector,
filter and seed executables are byte-identical, and both the rebuilt original
seed and the bulk seed reproduce the original B0 image exactly.

The optional combined div+bulk profile shares the identical move emitter. The
strict v1+bulk profile remains the preferred root when a consumer needs no
unsigned division. The original independently qualified div executable remains
available for its existing consumers.

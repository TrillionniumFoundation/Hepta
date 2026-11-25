# Native runtime snapshot capture

This component captures the existing multiversion runtime and retirement state,
then invokes the qualified native snapshot renderer. The capture runs inside the
same HIA effect owner and holds the selection lock while it reads generation,
lease, number, proof and cleanup ownership. Callers cannot supply verified facts.

The current native effect image is 8,352,528 bytes, SHA256
`10e1965e7c1844352897a9b2e06418604c512a2db13b31ea7b93de9d613fab6e`.
The source compiler is the captured v95 image; the actual ELF object and shared
image are produced by HIA packer and linker roles. The existing five-import
mechanical boundary is unchanged. This is a qualified component, not a claim
that the final public runtime or final source installation has passed.

## Interface and ownership

The existing six-word effect entry accepts `HIAMVEX3`. Operation 10 returns the
complete public snapshot; operation 9 returns the complete cleanup snapshot after
the actual retry. Their `HIAMVER1` reply contains an independently allocated
result pointer at byte 144 and its full u64 byte length at 152. The receiving
owner frees that allocation exactly once. It survives release of the selection
lock and later runtime changes. Existing diagnostic descriptors at 96 and 104
retain their original transfer/close rules.

The effect continuation uses its existing exclusive 40 MiB output/work area
and 128 KiB persistent context. It does not put an 8 MiB ceiling on aggregate
snapshot JSON or public decimal values. A real 9,437,201-digit immutable epoch
produced a complete 9,440,393-byte snapshot; a later caller mutation did not
change the owner or the next snapshot.

The separate `multiversion_runtime_snapshot_number` role converts a canonical
little-endian unsigned magnitude into decimal without imposing a numeric word
limit. It returns u32 status and writes the full u64 result length at workspace
0. Short output is atomic; required workspace is reported at 8. Its temporary
storage is sized from the actual magnitude. It supplies active-lease counts to
the full capture, while generation, epoch and attempt counts remain actual
immutable decimal owner values.

## Captured fields and error observations

GenerationInfo comes from the actual retained generation. The capture verifies
its header, includes the real loaded-mapping report and uses the actual
proved-total receipt frame at the generation owner's declared offset. Proof
evidence preserves the native checker identity and reason; it does not pretend
to be the original QA Z3 implementation.

Each retirement query supplies its actual last-attested 512-byte header and
current authority flags. A fenced owner exposes the last attested diagnostic
state with flags zero, rather than interpreting the corrupted live header.
Directory acquisition, close, observation and removal retain actual errno,
original filesystem path bytes and the original first-error behavior. Actual
`dlerror` bytes are copied before subsequent loader calls can replace TLS
storage; a nonzero `dlclose` result is never treated as errno.

The full snapshot preserves the original distinction between numeric sorting
of pending tasks and insertion ordering of pending identity releases. The
original maximum live-artifact budget remains 64 and counts both live and
pending artifacts. Slot numbers are private finite positions, not public
generation numbers. Selection and cleanup histories each retain their original
last 128 entries. Repeated rollback while already on baseline is a true no-op.

## Interrupted accounting and allocation failure

A native cleanup can complete a filesystem effect before a later allocation
fails. Each task therefore retains a separately owned decimal attempt count
and the last charged private retirement ordinal. A later capture reconciles
unaccounted actual attempts before reporting them. It installs the new immutable
value before releasing the old reference. Global cleanup accounting and its
history advance only at their original completion boundary.

An old value-reference release failure is quarantined with its reference still
recorded at the generation owner; finalization consumes that retained reference.
It is not reported as a successful cleanup or a second increment. Complete
public dependency-exception mapping remains separate work.

## Actual qualification

The accompanying JSON binds every report, role, source and image by full SHA256.
It keeps the real image identity for each component revision. Earlier evidence
is not relabelled as having run against the final D5 image.

| Gate | Actual result |
| --- | --- |
| Binary magnitude to decimal, private bounds, short-output atomicity | 2,064 checks passed |
| Original complete lifecycle snapshots | 17 comparisons passed on D5 |
| Proved-total profiles and exact retained receipt bytes | 10 comparisons passed on D5 |
| Real filesystem failure, repair and retry | 42 comparisons passed |
| Fenced last-attested state and actual loader-error capture | 32 comparisons passed |
| Actual allocation failure after acquisition and cleanup effects | 16 groups passed |
| New counter operations and unchanged old private rejection domain | 106 checks, 787 actual identity calls passed on D5 |
| Pending insertion/numeric ordering and cleanup history eviction | 145 original comparisons, 552 actual original cleanup attempts passed on D5 |
| Aggregate snapshot above 9 MiB | Two full captures passed on D5 |
| Two concurrent snapshot readers with real publication/rollback | 4,462 snapshots and 16 writer operations passed on D5 |
| Selection-event history eviction | 66 original and 66 native publications, eight full snapshot comparisons passed on D5 |

The real filesystem gates cover permissions, replacement/absence, nonempty
directories and already-invalid owned descriptors. Descriptor-close uncertainty
does not trigger a second close. Loader gates include Unicode, invalid UTF-8,
empty diagnostics and the original Unicode-character truncation boundary.
Allocation gates exercise each actual call site and verify subsequent retries,
allocation ownership and descriptor cleanup.

Failed QA runs remain available. One interrupted output run produced no usable
qualification. Another fixture incorrectly expected baseline rollback to fill the
event ring; the original and native snapshots agreed. A fixed reader-count limit
also ended a concurrency fixture before its writer completed; the independently
rerun explicit-wait fixture passed. A real wrong proved-total frame offset was
corrected using the generation owner's actual layout and rechecked against all
retained receipt bytes.

## Remaining integration

The next step is to rebuild the public runtime-handle and background-provider
capsules with these roles and verify their result lifetime. Complete typed
public exception mapping and the shared historical-v2/types collision admission
gate remain open. No final installation, default activation, source cleanup or
whole-runtime success is asserted here.


## Owned public carrier composition

The unchanged qualified handle and background provider policies now compose the
48-role snapshot effects image through two newly generated native packers.
Both objects are produced by actual HIA packers, compared byte for byte with
the independent object construction, and linked by the actual native linker.
Each packer passed 17 malformed-frame, role-count, extent and short-output
atomic refusal checks.

| Actual product | Bytes | SHA-256 |
| --- | ---: | --- |
| Runtime and lease carrier | 8561424 | 426fb168686beb757bb477898ca0ba56b5d30067ee2f9a72668cf410d9901dbf |
| Background runtime provider | 8852240 | 2170b895ed9c146c87888c7c83057e22aa0f2bfd7a87fbf348f51f50e3f09192 |

The same carrier passed the original seven lifecycle groups (24 calls) and
two full snapshot lifetime groups (18 calls). Three complete snapshots match
the original runtime, including an old leased generation after publication
and a closed runtime with that lease retained. Two separately allocated JSON
results remain byte-identical after all runtime and lease capabilities are
released and the context is destroyed. Another actual snapshot reads an
immutable 9437201-digit epoch while the last user capability is dropped.
Its 9440432-byte result remains valid after the carrier's real finalizer runs
and the context is destroyed; the receiver then frees the result. This uses
a real in-flight capability pin, not a supplied lifetime assertion.

The provider passed the original eight groups (18 calls): actual normalize,
proof, build and load; selection-lock snapshot; strong reference cloning;
same-token conditional publication; stale-before-token precedence;
cancellation; retained reply ownership; and actual descriptor/finalizer cleanup.
The four provider status classes remain distinct. Unmapped dependency errors
remain explicitly open and are not relabeled as MemoryError or as an
uncommitted publication.

The first additional fixture incorrectly expected a GenerationInfo payload
from the runtime constructor. Its failed log remains pinned in the JSON
record. The constructor returns its owned runtime capability and an empty
extra payload; the corrected fixture checks this result through actual
snapshots and operations. No product bytes changed for that correction.

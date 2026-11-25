# Native multiversion decimal transactions

This fixed native companion owns the decimal identities used by the in-process multiversion coordinator. It does not prove a candidate, execute a constructor, choose an active generation, or complete the public runtime by itself.

The public generation and selection epoch are canonical decimal strings owned by the existing immutable value owner. A machine word is only a private strong-reference identity or a physical slot index. There is no u64 or u128 numerical limit, overflow substitution, or wraparound. Actual memory allocation remains fallible.

## Native construction

The runtime sources are `multiversion_runtime_numbers.hepta`, `multiversion_runtime_numbers_packer.hepta`, and readable mechanical `tools/hia_multiversion_runtime_numbers_bridge.S`. The companion embeds the already-qualified `multiversion_values.hepta` and `unsigned_decimal_values.hepta`. The three-role HIA packer creates a closed ET_REL requiring only malloc and free. The unchanged general `elf_shared_linker.hepta` creates the callable shared image. Production construction requires no assembler, C compiler, Python policy, or hosted integer arithmetic.

The mechanical adapter performs fixed six-word calls, raw syscalls, futex-word atomics, and copies of already-owned memory. Decimal arithmetic, reference ownership, state changes, and refusal decisions are HIA.

## Private callable interface

`u32 hia_mv_runtime_numbers(s, sN, o, oN, w, wN)` uses a 64-byte request, at least 2048 output bytes, and an exclusive initialized 8192-byte context. Each invocation has distinct output and request memory. The context contains its own mutex. Initialization is exclusive, as it is performed during creation of a new runtime. A forked process cannot reuse the context.

The request is `HIAMVNB1` followed by seven little-endian u64 words:

| Offset | Field |
|---:|---|
| 8 | Operation |
| 16 | Physical slot or selector |
| 24, 32, 40 | Actual reference node and two nonce words, only for operations 12 and 13 |
| 48, 56 | Zero |

| Operation | Effect |
|---:|---|
| 0 | Initialize baseline 0, epoch 0, and next generation 1 using actual independent reference nodes |
| 1 | Reserve physical slot 1..63 and advance next; the old next reference transfers to the slot |
| 2 | Stage the incremented epoch, retaining the current epoch |
| 3 | Commit the staged epoch and transfer the old epoch reference to the native caller |
| 4 | Abort a staged epoch and transfer that pending reference to the caller |
| 5 | Release a nonbaseline slot and transfer its reference to the caller |
| 6 | Observe the current private epoch reference and whether a pending reference exists |
| 7 | Copy a slot's complete decimal digits |
| 8 | Copy current epoch digits |
| 9 | Copy next-generation digits |
| 10 | Destroy only when every reference in the value registry belongs to this context |
| 11 | Retain an independent reference: selectors 0..63 are slots, 64 is epoch, 65 is next |
| 12 | Drop a caller-owned independent or transferred reference; live context-owned references are refused |
| 13 | Copy an actual reference's complete digits |

The outer runtime must hold its original selection lock across stage and commit or abort. This companion's mutex protects each actual reference transaction; it does not replace the wider publication linearization point.

A successful reserve allocates the incremented value before changing either the next reference or the slot. An allocation failure preserves both. The generation remains consumed after a successful reserve even if subsequent admission, proof, or build fails. Epoch staging does not change the selected epoch.

Commit, abort, and slot release transfer their displaced reference rather than hiding a release inside the marker operation. The native parent must retain that returned capability until it is dropped through operation 12. It cannot free a continuation that still owns this capability. This permits the parent's actual token marker and cleanup registration ordering to remain explicit.

## Reply and custody

A completed call returns zero and begins with `HIAMVNR1`.

| Offset | Field |
|---:|---|
| 8 | Status |
| 16, 24, 32 | Result reference node and nonces |
| 40 | Decimal byte count |
| 48 | Number of copied bytes |
| 56 | Pending reference identity for observation |
| 64, 72, 80 | **Transferred owned** reference from commit, abort, or slot release |
| 88 | That transferred reference's decimal byte count |
| 96..127 | Reserved zero |
| 2048 | Complete copied digits, when requested |

Status 0 is success. Status 1 is an invalid or absent reference, 4 is allocation failure, 5 is a lifecycle refusal, 6 is a system-call failure, 7 is short copy output, and 9 is an internal invariant failure. Original value-owner digit/underflow statuses remain reserved for that underlying boundary.

The ordinary result capability from reserve or observation is a private borrowed view of a context-owned reference. It is usable only while the enclosing runtime's lock and ownership keep that value alive. Operation 11 instead returns a new independently owned node. The reference at offsets 64..88 is always an ownership transfer.

Malformed private headers or inadequate buffers return `0xfffffffd`; they do not mutate the context. The per-call mechanical continuation is scratch, not an atomic public response region.

Destroy first traverses the actual native registry. Any independently retained or transferred reference prevents destruction before a context-owned reference is released. A failed release keeps the existing context for later cleanup instead of guessing that ownership ended.

## Qualification and limits

The adjacent JSON records the exact source, flat, image, and evidence hashes. Qualification includes real native calls for sequential generation consumption, epoch commit and abort, exact full-context preservation on allocation failure, independent-node retention, stale and foreign-process refusal, 16 simultaneous caller threads, and 1,048,577-digit carry chains. The large-value setup uses actual nodes created by the same native value owner; it is a qualification fixture, not a new runtime counter-seeding API.

Allocation injection is restricted to the actual malloc/free call sites inside this image. The complete native context is compared after failed reserve/stage/retain. Native packaging is separately checked at each closed role boundary with unchanged output on refused packaging.

These are component guarantees. The final effect dispatcher still has to combine the same owner with native admission, proof, construction, load/probes, publication measurement, lease calls, and registered retirement.

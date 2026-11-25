# Native BackgroundOptimizer accounting owner

This component performs the existing accounting path using the actual accepted Job, the actual public Future, the held native queue condition, the checked receipt freezer, and the unbounded decimal ledger. It is a private fixed-dependency entry for the background controller. It is not the complete public BackgroundOptimizer.

## Construction

The HIA policy and HIA object packer are built with the independently captured native source compiler. The HIA packer constructs the ET_REL object and the existing HIA shared linker produces the shared image. The readable assembly file describes only view checks, raw syscall forwarding, allocation/free, byte copying, and six-word fixed calls. Its development assembly is used to verify the packer's literal mechanical template; production packing and linking are HIA.

The compiled policy was produced twice with identical bytes. The qualified component image is 230,160 bytes, SHA256 \`614da156ffe0ae6d0ab46afb2955d8720c72a9832d1eeab8895cd451251cf695\`. The full source, dependency and evidence identities are in HIA_BACKGROUND_NATIVE_ACCOUNT_QUALIFICATION.json.

## Fixed entry and custody

\`hia_background_account(s, sN, o, oN, w, wN)\` uses six machine words. The views must be nonzero, nonoverlapping, and have nonoverflowing endpoints. Output is at least 524,288 bytes and the captured private context is at least 4,096 bytes. These fixed workspaces contain control records and transient chunks; they are not limits on scalar values, receipt payloads, or observed cost. Dynamic conversion storage uses the actual full 64-bit extent and allocator failure is preserved.

Input is exactly 128 bytes:

| Offset | Meaning |
|---|---|
| 0 | HIABACQ1 |
| 8 | 0: account; 1: retry retained cleanup only |
| 16 | Zero |
| 24, 32, 40 | Actual Job capability |
| 48, 56, 64 | Private mutable metadata value capability |
| 72, 80, 88 | Mutable result value capability |
| 96, 104, 112 | Actual public Future's cell capability |
| 120 | Zero |

Retry input has zero in every field after the operation. The caller holds the real Q02 condition before accounting and releases it afterward. The owner checks the queue's actual process identity, lock word, and owner thread id. It does not reacquire that condition. The context itself is exclusive while a call is in progress and while failed cleanup is retained.

The captured context contains trusted same-instance entry points and contexts, never public caller assertions:

| Offset | Captured dependency |
|---|---|
| 0 | HIABACC1 |
| 8, 16, 24 | Mutable value entry, context, extent |
| 32 | Observed report pure policy |
| 40 | Fixed value-freeze entry |
| 48, 56 | Immutable value-freeze context template pointer and extent |
| 64, 72, 80 | Ledger entry, context, extent |
| 88, 96, 104 | Jobs entry, context, extent |
| 112, 120, 128 | Public Future entry, global context, extent |
| 136, 144, 152 | Actual factory identity |
| 160 | Qualified native Future kernel entry |
| 168, 176, 184 | Unbounded decimal owner entry, context, extent |
| 192, 200, 208 | Public factory's actually borrowed cell entry, context, extent |
| 216 | Captured process id, initially zero |
| 224, 232, 240 | Queue entry, context, extent |
| 248 | Retained-cleanup state |
| 256..4095 | Private retained cleanup, never caller-owned data |

The owner retains the real Job and the real public Future, then checks that borrowing the Future cell resolves to the same actual 512-byte kernel as the Job. A different Future is refused before reporting. The enclosing controller holds the metadata and result references throughout the call.

## Original accounting order

The owner first asks the ledger for the Job's actual accounted marker. A set marker returns immediately without reading the clock, changing the result, or observing the Future again. Otherwise the same sequence is performed under the held condition:

1. Read CLOCK_MONOTONIC and create its exact decimal nanoseconds value.
2. Run the existing report policy's HIABRP02 account operation.
3. After the policy writes the three elapsed cost fields, observe the same Job's actual token.
4. Resume the same policy, which writes publication_committed.
5. Observe the actual public Future accounting state through public operation 9.
6. Resume the policy through cancellation override and creation of an independent receipt/costs object.
7. Run the fixed native lossless value transport, owned capture, checked sorted freezer, and immutable payload owner.
8. Transfer the observed cost through full-length scalar chunks into an actual unbounded decimal value.
9. Settle the native ledger; transfer the receipt only when the ledger confirms ownership transfer. Its original accounted marker remains the final publication.
10. Release every private reference and allocation.

The public Future state is not captured early or supplied as a boolean. Future callbacks do not run in this path. The shared result retains its original object identity, while the ledger holds detached sorted receipt bytes.

The integer decimal conversion policy is inherited from the captured freezer/value context. The ordinary captured policy is 4300, and its original ValueError is preserved before settlement. A separately configured 0 policy retains the qualified unlimited conversion behavior. This does not put a digit limit on the decimal ledger itself.

## Output and failed cleanup

The entry returns zero with a 128-byte HIABACR1 header. Malformed private frames or views return 0xfffffffd; mechanical view rejection leaves all views unchanged, while a well-formed view with a malformed frame may reset its private phase word at output +128.

| Offset | Meaning |
|---|---|
| 8 | Status |
| 16 | Actual already-accounted flag |
| 24 | Receipt/ledger settlement completed in this call |
| 48 | Original encoding error JSON length |
| 56 | Cleanup retained in the context |
| 64 | Private dependency or syscall detail |
| 72, 80, 88, 96 | Unicode error character count, start, end, codepoint |
| 128 | Exact original encoding error JSON for status 1 |

Statuses are 0 success, 1 original checked-freeze error, 5 allocation failure, 6 lifecycle/condition refusal, 7 dependency refusal, 8 OS error, and 9 invariant or retained cleanup. A failure does not imply that publication or ledger settlement did not occur; inspect the actual settled flag and the Job/token state.

If a dependency refuses to release a still-owned reference, the owner retains that reference in its context and blocks another account operation. Operation 1 retries only that cleanup. It does not run the report, observe a new clock, encode a receipt, or settle the ledger again. Nested freezer cleanup is retained with its complete private context. Successful cleanup of a post-settlement failure cannot create a second accounting entry.

## Qualification

The component has passed:

- Nine whole accounting cases using the actual native queue condition, external Job, public Future factory, observed report policy, mutable value owner, fixed freezer, immutable payload and decimal ledger. These include pending/cancelled/finished states, actual token commit, a never-started job, ranking/publication context, 100,001-digit cost under captured policy 0, captured-policy-4300 refusal, and condition ownership refusal.
- Ten control groups: four real allocator failures before the accounted marker, real mismatched Future identity, invalid result reference, late Unicode/nonfinite errors, eight competing threads with exactly one settlement, and private frame/view/context/process boundaries.
- Two retained-cleanup groups. One withholds a public Future guard release after actual ledger settlement; the other withholds an actual payload release inside the nested freezer. Retrying releases the original references without repeating effects.
- Twenty-nine native packer cases, including exact ET_REL bytes, the inherited 4 MiB policy bound, short output/work refusals and malformed packets.

Two earlier observer failures are retained in external evidence: an unlimited-conversion expectation was incorrectly applied to captured policy 4300, and a fault was initially armed at the ledger image even though its allocations belong to its decimal owner. The component bytes did not change for those observer corrections.

The public Future dependency used here is the actual b65ff1e4 candidate with its stable accounting ABI. This component result does not claim that all public Future methods, runtime exception mappings, the whole background controller, or the final release have completed qualification.

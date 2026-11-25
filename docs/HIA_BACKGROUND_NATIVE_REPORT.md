# Native background result reports and accounting preparation

## Qualified component

The closed `hia_background_optimizer_report` image is **1273350 bytes** /
`c43a55e3a8bd5408f9ae37e482dcdd5036f84ac83e4677d227e0250435488bda`.
It constructs the original `BackgroundOptimizer._report` result and performs
the mutable-result/receipt preparation in `_account_job`.

The report policy, integer arithmetic, object graph, dictionary order, JSON
capture and ownership are actual HIA code. A 424-byte fixed bridge calls only
the report policy and its embedded value owner. It imports no libc function
and never invokes a caller-selected function pointer. The HIA packer emits
both ET_REL and flat code.

This component does not settle the ledger, mark a Job accounted, predict a
Future terminal state, own the worker queue, or constitute the complete
BackgroundOptimizer/public runtime. Those operations remain with the actual
controller, Future, immutable-payload and ledger owners. In particular, the
prepared receipt must be frozen with the original **sorted** packer before
ledger transfer; ordinary insertion-order value export is not that operation.

## Source and native build

The policy source is
`examples/hia_bootstrap/background_optimizer_report.hepta`:
249737 bytes /
`511a3e0a9e2d3b875d7774efaf0eec28493c86d12431a794d14c58330a3f7528`.
It has 24 functions, 784 blocks, 4595 operations and at most 12 block
parameters. Its actual native flat is 282576 bytes /
`7e1f369d025e30177d53238e18add58c4dc0fac448aad6da651ac9579d0f382a`.

The packer source is
`examples/hia_bootstrap/background_optimizer_report_packer.hepta`:
43019 bytes /
`82bebd49315504b5606821108cd06c4ceb116a3c27f4ba92c2e0521610f56114`.
It has 14 functions, 66 blocks, 914 operations and at most 6 block parameters.
Its native flat is 42202 bytes /
`fc0282c2bce2377d4fcef0cd9e3560c56da00ba88f669f90033ec81e128ed7d3`.

Both sources were independently compiled twice with the qualified HIA source
builder, producing identical bytes. The original per-source
128-function/1536-block/8192-operation/16-block-parameter bounds and the native
per-function bounds remain unchanged. Dispatch is divided into bounded
functions; no compiler limit was enlarged.

The readable fixed template is
`tools/hia_background_optimizer_report_bridge.S`. Its assembled 424-byte
text has SHA-256
`f98866ab02466da63dada015caf03abb8b2cbcbb70c42f6395ad879e4d5009bf`.
The HIA packer embeds the same verified template and patches three fixed
relative displacements (policy call at 288; value address at 227; value call
at 375). The second role is the complete qualified value image, 990342 bytes /
`6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c`;
its source closure is recorded in `HIA_RESULT_VALUE_NATIVE.json`.

The `HIABPK01` pack request is 40 bytes followed by policy and value flat
images: magic at 0, count 2 at 8, lengths at 16/24, mode at 32 (0 ET_REL,
1 flat). Work capacity is at least 512. Existing 4 MiB per-role and 16 MiB
text bounds remain unchanged. Invalid or insufficient requests publish no
partial output.

## Entry and input ownership

The exported entry has six words:
`entry(s, sn, o, on, w, wn)`. Output requires at least 8192 bytes; work
requires at least 32768. The fixed entry rejects null/nonwrapping/overlapping
views before writes and resets the private continuation itself for each
complete call.

The work prefix contains `HIABRC01` at 0, the privately bound value entry
at 8, actual value-context address at 16, and its size at 24 (at least 256).
Bytes 32..127 are zero. The closed entry binds its own fixed value role and
restores the original word at 8 on return; a caller's address at that word
cannot redirect execution. The actual controller owns and captures the
value context. The rest of the work area is private and may be reused without
clearing.

The request is exactly 128 bytes:

| Offset | Field |
| --- | --- |
| 0 | `HIABRP01` |
| 8 | Operation: 0 base report, 1 accounting preparation |
| 16 | Actual committed observation, 0/1; zero for operation 0 |
| 24/32/40 | Metadata dict capability |
| 48/56/64 | Existing result capability for operation 1; zero for operation 0 |
| 72 | Actual Future state: 0 pending, 1 cancelled, 2 finished; zero for operation 0 |
| 80..127 | Reserved zero |

Capabilities belong to the same actual value context. The controller holds
the inputs for the call. The HIA policy separately retains metadata and the
accounting result, then releases every private reference on all terminal
paths. Failed calls publish no new capabilities. Result mutations already
performed before an allocation failure remain visible, matching the
operation's nontransactional update order; receipt construction and temporary
references are still reclaimed.

Metadata is a private captured dict, not caller-supplied evidence of time,
commitment or Future state. Base-report fields are `job`, `generation`,
`epoch`, `function`, `before_sha256`, `before_input_sha256`,
`original_baseline_sha256`, `submit_work_ns`, `status` and `reason`.
Accounting fields are `now_ns`, `submitted_ns`, `work_started_ns`
(integer or null), `enqueued_ns` and `submit_work_ns`.
Elapsed arithmetic and epoch increment use exact unbounded kind-2 integers;
there is no conversion to a u64 counter.

## Reply and private continuation

The completed `HIABRR01` reply has status at 8; result capability at
24/32/40; receipt capability at 48/56/64; and observed-cost integer capability
at 72/80/88. Other public words are zero. Operation 0 returns only the result.
Operation 1 returns all three. The result is an independently owned reference
to the same existing result object. The receipt is newly constructed, with
its own newly constructed costs dictionary. Every returned capability must
be dropped by its eventual owner.

Status codes are those of the qualified value primitive, including invalid
capability, TypeError, KeyError, MemoryError and lifecycle errors. Invalid
private envelope/work configuration returns `0xfffffffd`; ordinary operation
outcomes return 0 with their status in the reply.

For trusted integration, the separately compiled pure policy uses phase at
output 128 (initially zero), actual callback return at 136, actions 4 fixed
value call, 10 continue, and 0 terminal. Action 4 uses function at 0, two-bit
argument base selectors at 8, and six arguments at 16..56. Base selectors
are 0 absolute, 1 work, 2 input, 3 output. The closed exported image drives
this continuation entirely in native code.

## Preserved report and receipt behavior

The base report preserves the original field insertion order, schema, six
false claims, null ranking/publication and initial submit-work costs.
`decision_generation` is the exact selection epoch plus one.

Accounting updates the existing costs dictionary in original order:
wall duration before Future completion, worker duration (zero when no worker
has started), and submit plus worker duration. It then records the captured
publication commitment. An observed cancelled Future overwrites status and
reason with the original cancellation outcome; it does not infer whether a
future cancellation will occur.

Receipt fields are copied in the original order. The receipt carries execution
status, the captured Future state and the original status-scope text.
Its costs map is a separate shallow copy. Optional detail retains the original
value. Queue waiting is added only to receipt costs when the worker has not
started. Later replacement of a field in result costs cannot alter this
separate map. As in the original implementation, complete historical
immutability comes from the controller's subsequent sorted byte snapshot.

Ranking is recognized only when its exact kind is dict. Invocation requires
an exact dict admission object with an exact true boolean. Native request and
binary hashes are copied only from exact strings. The four externally
reported cost fields are retained, in their original fixed order, only for
exact integers; bool and binary64 are excluded. These reported costs do not
enter observed-work totals a second time. Publication presence is likewise
an exact dict observation.

The prepared observed-cost integer is a distinct owned reference. The
controller converts it to the ledger's immutable decimal owner, freezes the
receipt to the immutable payload owner, and settles once under the existing
Job/ledger lifecycle. This component never writes the ledger's counters,
64-entry ring, or `job.accounted`.

## Actual qualification

| Gate | Evidence |
| --- | --- |
| Independent HIA compilation | Policy and packer each compiled twice, byte-identical |
| Native packaging and views | 40 gates (the original 35 and five atomic refusals of the new private profile): actual HIA object/flat packing twice, atomic invalid/short handling, unchanged role bounds and native view guards |
| Original behavior | 82 groups through the actual closed image, including every six-status/three-Future/two-commit/two-worker combination, original insertion order, same result identity and independent costs |
| Wide integer domain | Original Python comparison with 100001-digit job/epoch/time values under the matching unlimited conversion setting |
| Private and concurrent use | 25 gates, poisoned reused storage, fixed callee with a supplied address of one, stale/cross-context capabilities, 8193 extra ordered cost fields, eight threads and 200 report/account pairs |
| Actual allocation failure | Three groups and six real kernel ENOMEM returns: base construction, unbounded arithmetic, and receipt insertion after result costs were updated |
| Ownership after failure | Original mapping and external capability count preserved; retry succeeds; all owned mappings reach actual munmap |

Kernel qualification alters only mmap/mremap size arguments in the fixed
embedded value bridge under a child-only RLIMIT_AS. Return values are actual
Linux ENOMEM. The report's continuation phase is observed for scope;
no product state, code or return value is patched. Temporary owned
capabilities are reclaimed even when receipt insertion fails after the
result has already been updated.

One initial concurrency fixture compared the shared global capability count
during another thread's legitimate work. Its failure remains recorded. The
corrected fixture keeps all single-call checks for serial use and compares
the aggregate count only before starting and after joining the concurrent
threads. Product bytes did not change.

## Private observations at the original accounting points

The old `HIABRP01` operations 0 and 1 and their admission domain remain
unchanged. A trusted account owner can use the separate `HIABRP02` request
with operation 1. In this profile both input words 16 and 72 must be zero:
they cannot carry prematurely captured commitment or Future-state facts.
All other input and context fields have the same layout and bounds.

The pure HIA policy returns action 11 twice. The action header is
`HIABROQ1`, with stage number at 8:

1. After the three ordered cost mutations have completed, stage 1 requests
   the actual Job token's commitment observation.
2. The same report policy writes `publication_committed` to the shared result.
   Only after this write has completed does stage 2 request the actual
   Future's consistent accounting-state observation.

The owning account continuation writes callback status 0 at output 136 and
the observation at 144, then resumes the same policy. Stage 1 accepts 0 or 1;
stage 2 accepts 0 pending, 1 cancelled or 2 finished. Both feedback words are
initially poisoned by the policy. Missing, failed or out-of-domain feedback
terminates with private status 11 and releases report-owned references.
Mutations performed before the failure remain visible in their original order.

This new profile is a private composition interface, not a new public
authority to assert observations. The closed report bridge rejects its magic
before modifying output, context, values or capabilities, including truncated
and oversized frames. It cannot accidentally drive action 11 with stale
pre-captured inputs. Only the fixed account owner connected to the actual
Job token and public Future owner may drive it in production.

The new profile ran the original 82 behavior groups through the actual HIA
policy and value owner. A further 37 groups include 22 original/native pairs
with actual Future kernels and actual threads: cancellation or completion
before either read, commitment after the token read, interrupted token/Future
handoff, and cancellation or completion after the state read. They assert
that all cost writes precede the token read and the committed-field write
precedes the Future read. The returned receipt records the observed state
even when a later transition has already occurred. Additional groups verify
malformed feedback cleanup, atomic private-frame refusals and a cost failure
that reaches neither observation.

The original 82 closed-entry groups, 25 private/concurrent groups and all six
real kernel ENOMEM returns were rerun on the new image. The pure observation
tests do not claim that the complete public account/controller is closed.
That owner must still freeze the receipt, transfer it into the ledger and
mark the actual Job accounted only after successful settlement.

The first timing observer assumed that no other legitimate value reference
could appear during a report call. A simultaneous Future completion correctly
retained its result and invalidated that observer assumption. The corrected
observer compares ownership after actual Future destruction and final value
cleanup; it changed no product bytes. The failed observer evidence is retained.

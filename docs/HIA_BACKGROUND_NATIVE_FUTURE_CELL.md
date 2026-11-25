# Native Background Future cell and external-Future Jobs

This component separates the public Future lifetime, the Job's captured input,
and the mutable result value. It does not complete the public BackgroundOptimizer
controller. Constructor, worker execution, accounting, shutdown and the final
typed public dispatcher remain integration gates.

## Actual construction

The Future cell policy and packer are compiled from HIA by the captured native
source compiler (SHA-256
`494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`).
A HIA object packer embeds the readable fixed mechanical adapter; the existing HIA
shared linker produces the loadable component. The two policy compilations are
byte-identical. GNU assembly is used only by development provenance checks of the
readable mechanical prefix, never by the native production object or shared link.

The final Future cell policy is 192197 bytes,
`49f0579e2d631c42195382c1926b842a21b9e64f61f2db7406013c6f83567973`;
the actual shared image is 205584 bytes,
`1929df3ca8e6e3dc6df02a55476efe88b021f10e55bcf8b7c9e902f785301b3a`.
The final Jobs policy is 163313 bytes,
`1c1b306f80471c02306122f333bd1ee3315dcaef15a2b7009d864e8acdf4ac58`;
its shared image is 172816 bytes,
`209cce0ce13288f6d52afa41e9bbb28c0ffa5b198ffc248f7f527d85c7d2964e`.
Complete inputs, reports and source pins are in the adjacent qualification JSON.

## Ownership

Every Future retain creates a distinct nonce node. The Future object owns its
actual 512-byte native Future kernel and an independent result-value context
token. A method has an in-flight strong pin through native waiting, callbacks and
cleanup. A last user drop cannot free storage still used by a method.

A completed Future owns a ResultBox with an owned mutable value capability.
Each result call returns another retain of that same value identity. Mutation
through one result remains visible through later results. A retained result can
outlive both the Future and the value context's initial anchor. Immutable payload
copies are used only for internal serialized data, never as the public result
object.

Retirement invokes the actual Future kernel and drops values outside the Future
registry mutex. On return it reads the current intrusive neighbours again before
unlinking. Pending finalizers and active methods block context destruction.
A failed cleanup remains quarantined and can be retried; it is not reported as a
successful release.

The external-Future Job owns an independent Future reference and its own captured
input. The Job may release its full input and private continuation storage while
the Future is still pending. Completion and retained results remain usable after
that release. The queue retains Jobs, not entire completed Future input buffers.

## Future cell ABI

The fixed native entry is `hia_mv_background_future_cell(s,sN,o,oN,w,wN)`.
Input is exactly 128 bytes, output is at least 16384 bytes, context is at least
256 bytes. The full native entry initializes its continuation; caller output may
contain arbitrary prior bytes. The context is opaque and cannot be recycled as a
new instance after destruction.

The request magic is `HIABFQ01`; operation is at 8, A capability at 24/32/40,
B capability or callback fields at 48/56/64, result kind or callback identity at
80, timeout nanoseconds at 104 and infinite flag at 112. All unused words are
zero.

| Operation | Action |
| --- | --- |
| 0 | Initialize captured kernel/value entries and the actual value context. |
| 1 | Create an independent Future. |
| 2 | Retain A, producing a distinct nonce capability. |
| 3 | Drop A. |
| 4 | Reserved and rejected. |
| 5 | Destroy an empty, non-retiring context. |
| 6 | Private borrow of the kernel view while A remains strongly held. |
| 7 | Cancel through the actual Future and publication token. |
| 8 | Settle an already accepted token cancellation. |
| 9 | Observe one actual kernel state. |
| 10 | Wait for a result; return an independent retain of its mutable value. |
| 11 | Complete with B: kind 1 result, 2 Exception, 3 BaseException. |
| 12 | Register the existing private native callback and owned closure drop. |
| 13 | Retry quarantined retired objects. |

Operation 0 uses words 24/32/40/48 for kernel entry, value entry, value context and
context size. Operation 12 uses 48/56/64 for callback, user data and non-throwing
closure release. This is the existing private two-argument native callback
contract. It does not by itself supply a complete public typed callable/exception
dispatcher; that dispatcher is an explicit remaining whole-BG obligation.

Reply `HIABFR01` has carrier status at 8, owned Future capability at 16/24/32,
kernel status at 40, state at 48, token at 56, private borrow/cancel result at 64,
result kind at 72, owned value capability at 80/88/96, callback counters at
104/112 and cleanup-failure flag at 120. Carrier and kernel statuses are separate.
In particular a kernel timeout is not a malformed private call.

Completion observes the actual kernel before retaining or allocating a ResultBox.
An already completed or cancelled Future ignores the supplied value and performs
no owner allocation, matching the original early return. The final tests include
an invalid discarded value and a denied next allocation on both states.

## Jobs extension

The existing `HIABJO01` operations 0 through 8 and their rejection domain are
preserved. `HIABJO02` adds two private operations without enlarging the original
2048-byte output or 256-byte context views.

Operation 9 initializes the ordinary kernel/payload entries at 24/32/40/48 and
the fixed Future cell entry/context/size at 56/64/72. Operation 10 creates a Job
from an actual Future capability at 24/32/40 and opaque input whose byte length
is at 72, with bytes starting at 128. All other public BG input limits remain
the responsibility of the original typed submit gate.

A Job's first 864 bytes preserve the existing metadata and eight owned-payload
slots. An external Job stores its independent Future capability at 96/104/112,
the borrowed actual kernel pointer at 120, and input at 864. An aligned private
16384-byte continuation follows the input. This storage is freed with the Job;
it is never retained merely because a user still holds a Future.

A real injected failure exposed a cleanup bug in the candidate: after retaining a
Future, a Job nonce allocation failure could be overwritten by a successful
retirement status. The final policy preserves the original error across cleanup.
Both failed construction and ordinary release are checked using actual malloc,
free and real cell calls.

## Final qualification

All of the following use the final policies, actual native Future, actual result
value v4 (`6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c`)
and actual native immutable-payload owner where applicable.

- Future smoke: 6 groups and 49 native cell calls, including alias mutation,
  result survival, wait pins, callback reentry and initial-anchor handoff.
- Future lifecycle: 5 groups and 1195 cell calls, including 80 simultaneous
  completion/cancellation races, 100 result aliases, eight overlapping
  retirements, exact framing/capability/fork guards, and callback status handling.
- Future allocation: 8 groups and 2039 cell calls, including actual failure
  sites, 1001 distinct retained references, allocation-free final release and
  both already-done early-return controls.
- Actual external Jobs: 5 groups and 41 direct cell calls, preserving legacy
  coexistence, foreign-cap rejection, all payload slots and callback last drops.
- External allocation: 8 groups, covering object, nonce and real Future-retain
  failures, plus exact malloc/free counts for an 8MiB input released before
  Future completion.
- The original Jobs suite remains 10 groups, 6177 Job calls and 2558 payload
  calls, with its seven allocation controls and 24 native-packer guards.
- The Future cell has 24 native-packer/layout/atomic-refusal guards.

The earlier observer failures and the real candidate failures remain external
qualification evidence. No failed run is relabelled as a pass. These are component
and combination results; the complete BackgroundOptimizer remains unqualified
until its actual controller and public entry are integrated and tested.

## Current callback identity and concurrent retry

The separate private HIABFQ02 profile accepts only operation 14 and the actual
currently pinned kernel pointer at word 24; all other payload words are zero.
It finds the registered owning object before using the pointer and creates a
new independent nonce reference. The original HIABFQ01 profile still rejects 14.
A typed callback therefore receives the same Future identity even when it
drops the last external reference during completion. Three identity groups
and 35 actual native calls pass, along with the original smoke/lifetime/OOM gates.

Retry operation 13 now claims a quarantined object under the cell mutex before
unlocking to finalize it. The previous image actually crashed with SIGSEGV
under concurrent retry. The fixed public composition passes 8 threads retrying
9 closures across 3 factories, with all tokens and mappings reclaimed.
The typed public core is qualified in HIA_BACKGROUND_NATIVE_PUBLIC_FUTURE_CORE;
full observer, inherited setter and BG dispatcher integration remain explicit.

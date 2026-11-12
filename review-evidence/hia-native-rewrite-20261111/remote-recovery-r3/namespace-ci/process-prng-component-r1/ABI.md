# Selected SQLite 3.46.1 PRNG: new native owner draft

## Exact scope and status

The new HIA author implements the complete selected random.c algorithm: reset, state initialization, all twenty ChaCha rounds, cached output ordering, wrapping counter, and serial test save/restore. It is newly authored and unexecuted: zero AST, generated image, B3, VM or native observations. It is not an installed Store or the completion of unixOpen.

The original upstream random.c is preserved byte for byte as Git ea8431ba9409dbabefc972fe22f6d1e78dd328c7, 4,419 bytes, SHA-256 d25ba0221b50349bb75ab568813e6f9f4882f883dbe093dd06859d40439bdb2a. Fetching os_unix.c at the same version-3.46.1 reference produced the exact previously frozen namespace original, including Git9e7ba05d... and SHA83e4f995... . The original source disclaims copyright. No reconstructed source is labelled an original.

The new owner has five explicit pending effects: SQLite initialization, static PRNG mutex acquisition, default VFS lookup, the complete 44-byte sqlite3OsRandomness result, and static mutex release. They are not replaced by Python decisions or a fabricated successful receipt. The current development oracle will provide labelled foreign effects; actual fixed native issuers still have to be joined. The HIA source owns the algorithm and all effect order.

## Input and result framing

The entry is R/W/W: immutable request, mutable result, persistent workspace. Workspace must be at least4,096 bytes. The result header is256 bytes. On an ordinary positive random request it needs another N bytes. N is represented by the exact32-bit two's-complement bit pattern of the original C int; this does not add an integer or byte quota. The maximum positive N remains2,147,483,647.

A begin request is256 bytes:

| Offset | Value |
| --- | --- |
|0|HIANPR01|
|8|command1|
|16,24|private process/context identity, not both zero|
|32|nonzero call serial; next completed call must increment exactly|
|40|API1=randomness,2=serial test save,3=serial test restore|
|48|original N bits,0..2^32-1|
|56|destination-present Boolean|
|64..255|zero|

Save/restore require N and destination-present to be zero. They copy the full original132-byte state without initialization or mutex effects, as the selected testing routines do. They are serial testing operations, not a new concurrent public Store API.

A completion reply is a256-byte control header, followed by the exact256-byte issued effect request and, only for entropy,44 complete returned bytes. It binds context, call, action, effect kind and nonzero actual peer/lease/entry identifiers. The issued-request copy is compared completely. These fields are correlation under an immutable private issuer; they do not authenticate arbitrary supplied bytes.

| Reply offset | Value |
| --- | --- |
|0,8|HIANPR01, command2|
|16,24,32|the same context and call|
|40,48|the exact issued action and effect|
|56|original32-bit scalar return bits|
|64|payload bytes:44 only for entropy, otherwise0|
|72,80,88|actual peer, allocation generation and completed entry serial|
|96..255|zero|
|256..511|complete issued256-byte event|
|512..555|complete entropy buffer, only for effect4|

The output event is HIANPE01 plus status0=done,1=pending,2=output GROW,3=private compute continuation, or BAD. Its header contains exact call/action/effect, phase, requested/completed byte counts, mutex-held flag, capacity requirement, refusal reason and original initializer/entropy scalar returns. Bytes120..251 contain the complete132-byte PRNG state, including padding. Random output occupies bytes256 onward and is not a returned result until DONE.

The whole input, result and workspace remain live through a pending call. On compute status3, the fixed owner resumes with the identical original begin request, changing only its command to3. Input or extent replacement is refused. Output GROW is resolved before initialization or mutex acquisition and therefore before original algorithm effects. No callback or native producer is repeated as a result of GROW.

## Persistent state and original behavior

Workspace offsets512..643 hold the original process PRNG state: sixteen little-endian32-bit words,64 output bytes, remaining-byte count and three zero padding bytes. Offsets768..899 hold the serial saved state. Offsets1024..1087 are the ChaCha working words. The transport header and frozen request copies do not overlap them.

Reset changes only the first32-bit state word to zero. In particular it does not erase the old output or n. On the next positive generation, VFS lookup occurs before writing constants. After the44 entropy bytes are installed, the old12th state word becomes word15, the counter becomes zero, and n becomes zero. The next block preincrements the counter before twenty rounds and feed-forward addition.

The original output order is retained. If the entire remaining request fits the cached n bytes, the owner copies the suffix beginning at n-N. If it does not, it copies the entire cached prefix starting at zero, generates one new64-byte block, and continues. It does not replace this with a forward byte queue.

Every ChaCha addition and counter increment is explicitly masked to32 bits. Rotations use the fixed16/12/8/7 counts. The eight quarter-round index tuples are distinct within each quarter and preserve original column/diagonal order. The complete state and all output bytes must be compared to the original C oracle, in addition to full VM/native workspace equality.

## Bounded execution without a new semantic size limit

After each generated64-byte block, the owner may return a private compute continuation while retaining the same mutex and source. The next invocation continues the same C call. This does not publish a partial result, release the mutex, reenter VFS entropy or add a new public API. It allows the original int-sized N domain without inventing a per-call byte cap.

Every future actual invocation remains subject to the original4,000,000 VM steps,32 MiB arena and depth64. New component process-tree tests keep90 CPU seconds,180 wall seconds and1 GiB address space; fresh B3 keeps10/20/256 MiB with1 MiB compiler output/workspace. A complete semantic test call cannot split or inherit the aggregate budget from another run. None of these limits has yet been executed for this source.

A malformed private reply poisons the context permanently. It retains an already-held mutex flag, since a byte-level error is not evidence that the real lock was released. The actual issuer must perform its owned abort cleanup or terminate the owning process. The current draft is not evidence that physical mutex cleanup has been implemented.

## Required first actual gate

The planned original oracle will compile the exact preserved random.c through a minimal mechanical wrapper. The wrapper records initializer, lock, VFS, entropy and unlock calls, and exports all132 current/saved state bytes. Its foreign effects are explicit and are not recorded as actual namespace syscalls.

The complete comparison must cover initializer refusal before reset; zero/negative N; NULL destination; exact cache boundaries; repeated same-process calls; reset and reinitialize; save/restore before/after generation; absent/default VFS; complete entropy source bytes; near counter wrap; the reverse cache suffix; large outputs across multiple private continuations; complete partial state at each callback; output GROW; changed source, stale action, duplicate reply and terminal poison.

The separate Unix VFS entropy owner still needs the original /dev/urandom robust-open/read/close path and time/PID fallback. The temp-directory selector and filename formatter/collision loop also remain separate. Substituting getrandom, treating a Graph ID as namespace authority, or calling this draft a complete Store is excluded.


## First executable development gate (new, not yet run)

The exact original C file is included without text edits in a small reference
translation unit. The stub supplies the selected Linux little-endian layout,
THREADSAFE=1, automatic initialization, ordinary mutable static storage and
serial save/restore routines. The PRNG static mutex constant5 was read directly
from sqlite/sqlite version-3.46.1 src/sqlite.h.in, Git
549b52a1536e1035792a0b9d94097d9989fa90d3. The C library binds its local functions
with -Bsymbolic-functions so an unrelated host SQLite cannot intercept peers.

Typed effect2 includes the original static-mutex allocation followed by enter,
in that exact order. The C trace records both calls independently; the native
owner issues one pending acquisition and does not acknowledge it until both
complete. Current callbacks are labelled controlled foreign dependencies.
There is no physical mutex or VFS authority claim.

The fixed semantic corpus contains34 fresh scenarios and122 complete original
API calls:103 randomness calls and19 serial save/restore calls. It covers
initialization failure before any mutex/reset, all relevant64-byte cache edges,
suffix consumption, continuous refill, repeated reset, negative int values and
null destination, ignored entropy return values,0..44-byte entropy prefix
writes preserving old bytes, absent default VFS, save/restore continuity,
counter wrap by an explicitly private legal-state injection, and4096-byte
multi-continuation output. It compares every original output byte, all132
current and saved bytes, and the complete dependency order/state snapshots.

The65 explicit private protocol refusals compare complete VM/native buffers.
Each case verifies persistent poison when at least8 writable bytes were
available to store the marker; shorter workspace cases explicitly do not claim
a stored poison marker. One separate positive control requests INT_MAX output
and observes GROW without allocating2GiB or introducing a smaller semantic
quota.

One complete process tree must fit90CPU seconds,180 wall seconds and1GiB
address space. The single fresh B3 compile keeps10CPU/20wall/256MiB and1MiB
workspace/output. The original-C fixture compiler separately keeps10CPU/
20wall/256MiB within the same whole budget. Every VM entry retains4,000,000
steps,32MiB arena and depth64; the profile stays128functions/1536blocks/
8192operations/256blocks per function/16parameters. No corpus splitting,
old counts or previous images satisfy this new gate.

The exact source and executable artifacts, full C callback/state records,
every VM/native input/output/workspace, canaries, source-after checks, compiler
requests/receipts and original failure are retained. Completed C records are
flushed before the corresponding HIA invocation, so a later HIA failure cannot
erase a reference result. The old unexecuted fixture that recorded C results
only after HIA completion is retained as a prior draft. This source delivery
has zero AST, C compile, HIA generation, B3, VM or native observations.

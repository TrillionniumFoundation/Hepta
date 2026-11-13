# SQLite database-header source request draft

This isolated development module makes the byte decisions in the complete
SQLite 3.46.0 and 3.53.2 lockBtree bodies. Their full 6,334-byte function bodies
are identical. It emits a decision: accept, open WAL and reread, change page
size and reread, or an SQLite format/page-count error. It does not acquire a
lock, open WAL, change pager geometry, read storage, or grant a transaction.

The immutable inputs are the 100-byte database header and a 128-byte context.
The private 256-byte output is the only writable span. Current page size is a
power of two from 512 through 65536. The context permits usable size from
page_size-255 through page_size, including 257 after a resize: the original
later nonempty check rejects values below 480. Empty/reset decisions preserve
current geometry and vacuum flags.

The fixed 12 methods plan 670 VM calls with per-method counts
[0,16,512,16,18,32,16,36,6,0,18,0]. The complete 256-value read-version domain and
256-value write-version domain are retained. WAL retries precede payload
fractions and page-size checks. Resize retries precede page-count and usable
size checks. Writable-schema clamping, change-counter fallback, reset,
unknown write versions, and unused header words remain explicit.

There are 36 protocol refusals with all three spans unchanged. The other
634 calls return complete 256-byte semantic decisions, including format
errors. Six of those calls then receive one declared host-side custody fault:
source, command, output canary, entry identity, boolean return, or reserved
output word. Complete pre/post-fault spans plus 64-byte canaries are retained;
each must be rejected by the bridge. These are part of the 670, not extra calls.

Source execution uses the existing 180-second owner with 3-second cleanup.
The nine original Core/assembly limits, including 16 logical parameters and
arguments, are unchanged. Each VM call retains 200,000 fuel, 1 MiB allocation,
and depth 256. No flattened-machine-word limit is introduced. The source worker
denies compiler/native image construction, subprocess, network, SQLite and
mapping effects, and preserves complete actual inputs/outputs after bound
ECHILD. A nonzero worker remains HOLD and retains its closed originals.

The root r1 author draft is retained separately. Its two unsupported FloorDiv
expressions were replaced before any execution by the exact bounded HIA
divide32 helper; the new author has 11 functions. Tests use independent Python
integer division on the positive domain to compute expected metadata.

Status: SOURCE DRAFT, UNFROZEN, UNEXECUTED.
No generator, Core VM, C compiler/oracle, native code, SQL, installation, or
default AgentStore activation is qualified by this draft. The future C oracle
must use the stated WAL/autovacuum-enabled profile and compare byte decisions
without pretending that fixture pager callbacks performed real I/O or locks.

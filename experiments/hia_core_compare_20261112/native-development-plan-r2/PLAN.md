# Exact numeric comparison: finite native request, unexecuted

This request is an isolated CPython 3.12.14 development operation for the
comparison owner preserved in commit
`6e530a596a4df0fd1ffa1e5c1f145215e40059c9`. Its generated 63,601-byte HIA source
is copied exactly; it is not regenerated here. The original source/Core-VM
result was 11/11 PASS. That result is not a native result.

## Execution and admission

The sole launcher is `control/launch.py`, called with the exact request SHA in
`LAUNCH.json`. It creates `/tmp/hia-core-compare-native-development-r2` only if
absent. There is no automatic retry, replacement key or overwrite. Root must
review and authorize the frozen request before execution.

One unchanged process owner covers all compilation, native cases and complete
trace readback in **180 seconds plus 3 seconds cleanup**. One unchanged
`compile_stage` invocation uses the pinned current v87/b7 same-run cold B3, with **20 seconds
wall, 10 seconds CPU, 1 MiB input/output/workspace** and the original child.
This B3 is a development input, not a fresh matching-source cold compiler for
the new owner. Its provenance and all seven original companion pins are in
`reference/COMPILER-ORIGIN.json`.

The new finite child has no independent wall extension: it remains inside the
same owner. Its CPU ceiling is 180 seconds, address-space limit 256 MiB, stack
8 MiB, file limit 16 MiB and descriptor limit 32. Those are limits for this new
finite control child; the original compiler child still uses CPU 10 seconds.
No original caller time limit is changed.

The minimal source fixture contains only the exact eight files necessary to
load the numeric companion and exercise the modified opcode-13 adapter. It is
explicitly not a full repository checkout, installed wheel, or cold source
closure. Source/image/ABI/bridge/selector/actual compiler hashes are bound by
the real manifest loader. The ordinary Core39 bundle is not compiled or run
in this finite operation. Full Core39 plus numeric companion must later be
compiled by the same *current* matching cold B3 before that claim is possible.

## Fixed finite population

Eight named unittest methods are frozen in `EXPECTED-IDS.json` and must all
load and execute once, with zero failures, errors, skips, expected failures,
unexpected successes and loader errors. The finite child cannot start a
compiler or subprocess and must not import the Core interpreter/authoring
modules.

The first four numeric populations retain all **172 original numeric pairs**
in their actual source/VM order. Three complete vector-building method bodies
are copied byte for byte. The fourth retains its complete 24 end-to-end pairs;
its separate scalar-VM-only checks are not relabelled as native execution.
Every actual native input/output/status for these pairs must equal the fixed
reference, in addition to matching the builtin operator oracle. The original
matrix has 291 entry returns and 119 requested windows. These are expected
counts from the prior VM run, not native observations.

The matrix's large cases deliberately have different scopes:

| Matrix case | Scope | Expected windows |
| --- | --- | ---: |
| 24: two values over 9 MiB, differing near their most significant word | Actual high-window comparison only | 2 |
| 25: negative large integer versus negative infinity | Summary classification | 0 |
| 26: large integer versus maximum finite binary64 | Summary magnitude classification | 0 |
| New independent case: two 8,388,612-byte limb representations differing only at the lowest limb | Complete two-sided traversal | 131,074 |

The new case uses 2,097,153 limbs per operand and requires exactly 65,537
windows on each side, in descending offset order, including every limb. Its
minimal integer magnitude is also greater than 8 MiB. There must be 131,075
real entry returns and an actual LT/true result. A summary shortcut cannot
satisfy this case. The whole comparison still has fixed **256-byte input,
128-byte output, 512-byte workspace, and at most 32 32-bit limbs per request**.

Additional cases exercise real native entries followed by one-use violations,
post-entry ledger failure, representation failure, malformed ACK refusal and
terminal workspace refusal. The outer adapter controls bind target before
left then right get, each once; six exact operator paths require real native
entry and poison observation of the retained operator call. Subclasses,
independently implemented `__ne__`, containment, replaced operators and foreign
lookup/get/target exceptions retain their old path. These are direct adapter
controls, not execution of the Core39 lowering images.

Static total for this exact fixture is **131,397 entries**, with 180 status-0
returns, 131,200 status-1 requests and 17 refusal returns, across 185 trace
cases. Actual counts must be independently recovered from raw trace bytes.
The additional eight finite methods do not replace the unchanged 18/116 or
installed/cold gates.

## Complete raw trace and custody

Each native entry is recorded as PRE and POST records, each 960 bytes:

1. A 32-byte header contains magic, absolute entry index, case ID or returned
   status, and reserved zero or measured native elapsed nanoseconds.
2. All three actual buffers follow: input 256, output 128, workspace 512.
3. A 32-byte SHA256 binds that header and those buffers.

PRE is written before the actual machine call; POST follows its real return.
The trace therefore includes full input/output/workspace **before and after**.
A crash may leave a partial prefix; it never yields a successful index or
qualification. Buffered writes are intentional. No guarantee is claimed for
unflushed suffix bytes after a crash; remaining raw prefixes are preserved.

Records are streamed into fixed chunks of at most 8 MiB, rather than one file
per call. The index binds every chunk's offset, length and SHA and the entire
sequence SHA. The independent reader rechecks every record hash, entry and
case order, actual input preservation, persistent workspace/output continuity,
all 172 VM packet/output comparisons, and the new case's complete request/ACK
sequence. It reads the complete operand files and compares ACK payloads to
their actual recorded byte ranges. Missing, truncated, duplicated, reordered
or incomplete raw records cannot produce PASS.

The exact fixture's expected complete trace is 252,282,240 bytes. The control
ceiling of 132,096 entries bounds trace storage at 253,624,320 bytes in at most
31 chunks. Full deduplicated operand files require 35,656,854 bytes for the frozen corpus (139 original values plus two new large values) and are reserved 40 MiB. Complete
compiler input/output/request/stdout/stderr/receipt/image, all admission
controls, source before/after and terminal receipts are preserved as ordinary
raw files. A **384 MiB** conservative output reservation and at most **512
regular files** include these records; the preflight requires **512 MiB free
and 4,096 available inodes**. This is a finite-development resource check, not
the formal full-qualification resource gate. No compression or large output
is produced while preparing this request.

The 10 MiB operand reader allowance and trace entry ceiling describe only this
frozen finite corpus. They are not product limits on arbitrary Python
integers. The product bridge still lazily materializes a hosted magnitude
byte representation, with hosted allocation/MemoryError behavior and no 8 MiB
value policy. This work does not close CPython objects, representation,
reference lifetime, foreign hooks or the remaining primitive families.

## Success and unresolved scope

`FINITE_NATIVE_DEVELOPMENT_PASS` requires the exact compiler result, all eight
methods and 173 numeric pairs, complete independent trace readback, stable
source/compiler/runtime/build artifacts, and the unchanged owner's natural
exit, ECHILD and no forced kill/error/overflow. A partial report, a child
timeout, or a mere archive hash is HOLD. The first failure is retained; this
request contains no performance retry or selective rerun.

CPython 3.14, installed packaging, actual Core39 ordinary callers, the original
full 116 and 18 groups, matching-source cold/full qualification, resource
registration, and default activation remain unexecuted by this request. The
default owner remains unselected.

## Revision r2

Revision r1 (`74efbb5a63a007a8a3f994d3c1dd93aee127d7ca`) is preserved unexecuted and is not the authorized execution candidate. This revision uses the current b7/run43220208164 B3, 670,467 bytes, SHA256 `9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892`. The seven original members, complete 1 MiB compiler output, provider ZIP identity and all source/receipt/stdout/prefix joins were independently read back. The original whole CI failure is unchanged. The compiler provenance and launcher operation identity change. The final revision also requires exactly185 ordered exact-integer case IDs before dictionary construction in the independent reader, and records full startup statvfs/disk values. Native algorithms, finite cases, trace ABI and original budgets are retained.

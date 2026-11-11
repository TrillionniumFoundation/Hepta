# Native HIA recovery checkpoint r14

This checkpoint preserves completed, source-bound development components and
their complete original evidence. Its parent is recovery commit
`ef6afe945384d7796c460f984ca858f864d81711`. Product main remains
`5831f52fada45e076f8f68f198a15c0585e6104f`; the audited compiler candidate remains
`0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`. No entry activation, deletion of an
unreplaced owner, relaxed compiler gate or whole-product qualification is
claimed by this checkpoint.

## Shared native language metadata

The new `agent_program_metadata.hiaasm` is a complete finite metadata owner for
the existing CLI capabilities, all eight primitive opcode catalogs and the
compatibility/schema registry. Every instruction, signature, effect, attribute,
guard, trap, resource transition, type group, terminator and limitation from
the exact original contract is retained. The fixed metadata is embodied in HIA
source constants. Lossless constant packing keeps that source within the
original compiler limits; runtime inputs cannot replace the packed constants.

Actual HIA selects the exact profile, expands those constants, computes the
selected catalog's SHA-256 and inserts the digest into sorted canonical JSON.
No catalog digest is copied from a precomputed oracle result. The registry uses
the same freshly computed v8 digest. The existing HIA hash's compression and
padding algebra is retained; source delivery and digest output offsets are
adapted to disjoint regions of the component's private workspace.

The final source is 169,517 bytes, SHA-256
`394b864a5e1f92f544fdc5de89a1f000bf778fbaf3de83ab584069d4a5f727da`.
The actual B3 image is 179,744 bytes, SHA-256
`9ae3ce79f3287a2f156db2e26dd87b8150f7011b66b6465f66277d1120c6a22f`.
The source has 33 functions, 234 blocks and 3,523 instructions, maximum 94
blocks per function and 14 block parameters. Fresh compilation passed the
unchanged 10 CPU seconds, 20 wall seconds, 256 MiB address space and 1 MiB
compiler input/output/workspace bounds.

Fifty-one complete public metadata cases passed: every profile, the default,
registry, capabilities, full error text and unknown-schema ordering. Sixty-six
private protocol cases also passed, including exact growth, changed command or
source, terminal replay, independent interleaved leases and untouched extra
workspace bytes. These groups made 63 and 128 actual fresh-process native
entries. Every complete input, command, before/after workspace and result is
preserved. Sources and commands were protected read-only during execution;
canaries, exact source/image pins and full native-computed digests matched.

All failed originals remain present. They include the initial authoring type
mismatch, a first actual compile rejected for the flat entry ABI, two harness
setup/path errors and an actual private-state probe exposing five consistency
counterexamples in the earlier image. The final source cross-checks stored
lease, request, operation, schema flag and selected version against the bound
command/source. The full semantic cases and all five counterexamples were
rerun on the final image. The earlier successful public metadata cases are not
relabelled as proof of its later private-state fix.

This component returns finite metadata, not arbitrary program inspection
answers. Summary/function/block inspection, complete program reports and the
admission-to-service join remain subsequent work. Capabilities retain the
unchanged product entry's hosted implementation and false native qualification
and activation fields. Passing this component does not make promotion claims
true. The private ABI, manifest and handoff are included in the root archive.

## Ordinary worker request admission

The complete request component includes the exact original worker envelope,
field/schema/digest/catalog/tool ordering, all eleven tool names and the alias
forwarding boundary. Its actual execution chain uses the native bytes decoder,
Graph request owner, both Graph wire owners and HIA SHA. It does not call the
retained worker request, JSON value producer, canonical digest or wire
semantics during the native execution area.

The sealed evidence contains 113 original-worker semantic cases, 262 private
protocol controls and three reachable canonical-body boundary cases at 8 MiB
minus one, exactly 8 MiB and plus one. The three submitted raw inputs remain
below the raw input cap; the late canonical-wire gate is actually reached.
Original 90 CPU seconds/1 GiB execution limits remain unchanged. The first
protocol test's incorrect expectation about an already closed state remains
in the archive; only that test assertion was corrected for its new run.

This is complete request admission, not complete eleven-tool service behavior.
The shared tool-schema validator, journal, transactions, immutable artifacts,
execution/proof services and adoption lifecycle remain separate work.

## Original CLI argument grammar and public text

The CLI parser and formatter cover the original fifteen actions, version/help,
required and optional arguments, defaults, choices, abbreviations, short
options, `--`, usage/error ordering and complete public text. The oracle is the
actual original `hia_main` parser, pinned to retained CPython 3.12.14 and Unicode
15.0.0 presentation behavior.

All 1,268 original cases passed full stdout, stderr and exit-code comparison,
with 2,536 parser and 3,724 formatter native entries. Twenty-six targeted public
cases and 32 private protocol controls add 92 parser and 112 formatter native
entries. The original formatting test assumptions and a first formatter
compile exceeding an existing per-function SSA limit are preserved. Fixed
table initialization was split into ordinary HIA helpers without widening the
limit. All final sources/images remained pinned before and after execution.

This closes argument requests and public parser text only. OS argv/environment
capture, file/process ownership, output JSON formatting, business services and
installed dispatch are still explicit integration gates. In particular, the
CLI's ordinary `output_json` does not acquire the worker's 8 MiB wire cap.

## Immutable namespace commit component

The new complete r2 archive retains r1/r2 authoring, both actual B3 images,
positive real-file paths, three original private-state counterexamples, their
permanent-refusal fixes and 22 further real-file boundary cases. Across its
groups, 1,052 actual commit-image entries were compared with complete VM return,
output and workspace bytes. The added boundary group contributes 900 paired
entries and 782 real filesystem system calls, plus the actual native log owner.

The evidence covers original snapshot rejection before writing, a new-epoch
append with the previous prefix retained, immutable-head collisions, pending
file truncation/changes, close handling, ACK association and replay. Injected
errno and lost-ACK controls are explicitly labelled; they are not claims of
physical power-loss testing or naturally occurring OS errors. Controlled
lock/pending/head predecessors and a Python mechanical syscall transport are
still present. Fixed native syscall transport, authentic descriptor leases,
ordinary namespace integration, migration and complete multiwriter behavior
remain open.

## Custody and independent readback

All archives are complete original bytes, including failed attempts. Indexes
bind original names, byte lengths, modes and SHA-256 values. The root metadata
archive has 651 members containing 650 original files and 11,386,551 original
bytes; all are independently read back against live source bytes. Its 476
lossless CAS objects were reassembled and hash-checked in full.

Independent peer readback compares every archive member and reassembles every
hash-named compressed CAS object. The worker's original custody reports 3,747
such objects; its complete member index contains 3,750 hash-named compressed
members. The first root reader retained a failed count assertion after checking
all those bytes. The revised reader uses the full index count of 3,750 and keeps
the peer-reported count alongside it. No original custody or semantic result is
rewritten to hide the accounting difference.

The worker's separately appended count clarification identifies the exact
three additional members: complete final Graph buffers from the large decoder
cases, saved in decoder CAS without a storage-tagged ledger reference. Their
sizes are 8,397,732, 8,397,733 and 8,397,734 bytes. The actual request-source CAS
already references identical bytes. All three were independently reassembled
and hashed; the clarification is included without replacing the original
archive or custody. Root readback covers all 3,750 compressed members and
8,053,602,813 logical bytes. CLI readback covers all 26,842 compressed members
and 750,459,170 logical bytes.

The r13 publication receipt and duplicate transport retirement are also
included. Exactly 36 already published transport fragments, 107,767,204 bytes,
were removed locally only after fresh complete original/fragment comparison
and Git blob SHA/mode/size readback. All original archives remain intact. This
is duplicate evidence cleanup, not deletion of unreplaced product code.

The transport manifest records lossless JSON compression and ordered 3 MiB
parts where required. Complete reassembly is checked before upload. The Git
tree publication must verify every prior and new blob's SHA, mode and size;
the subsequent publication receipt records the exact commit and branch readback.

## Whole-product state

The r13 exact static inventory of 2,798 tracked files remains the audit baseline:
1,130 Python files parse, 156 package modules, 302 hosted tools, 65 assembly
sources and 12 HIA JSON sources are inventoried. Static byte/mode identity is
not a dynamic all-path ownership proof.

The retained 0ef full qualification remains HOLD. The prior 4,157-test run's
187 errors, one failure and 18 skips are preserved; the missing NDU binary
artifacts and the unknown deleting actor remain distinct facts. This checkpoint
does not substitute component passes for matching-source cold/installed full
qualification, general object building, proof/evaluation, patch/impact,
complete CLI/worker service or durable-store integration. Unreplaced old owners
remain until their actual replacements and complete release gates pass.

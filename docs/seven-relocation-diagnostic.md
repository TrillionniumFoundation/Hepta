# Relocation candidate: bounded first-six diagnostic

This experiment executes the separate source-only parallel-fact relocation.
It is not full-DAG acceptance. Every outcome, including six successful
processes, leaves all twelve wider obligations unproved and authority
`DENY_ALL`. Both the execution command and successful replay exit with status 1.

## Exact scope

The schedule is Baseline, SyntaxData, CertPart01, CertPart02, relocated
CertPart03, and marked relocated CertPart04. All five parents must be freshly
checked in the same run. A failed parent stops the schedule; no seventh process
is allowed. Part05, Part06, Part07, ConnectionsTransportRejections and WrongArm
are authenticated as source but never scheduled by this diagnostic.

The candidate moves 491 unchanged auxiliary theorem declarations from Part04
to Part03. Part03 has 1,655 printed theorem subjects; Part04 has 807. This may
move a deadline failure into Part03. No stage headroom or performance benefit
is assumed from source counts or earlier marker timings.

All original eleven source files, all five complete byte inputs, the original
66 positive targets and ten negative proofs remain bound by the unchanged
full source validators. Replay reads actual retained candidate bytes and
reconstructs the old seven layout, which in turn reconstructs the original
eleven files. It does not substitute a newly generated candidate for retained
source evidence. No old receipt, module or source identity authorizes a new
candidate process.

## Identity, markers and failure evidence

The protocol is `seven-parallel-relocation-first-six-diagnostic-v1`. Run and
start records bind original, old-seven, relocation and diagnostic manifests,
source identity, pinned Lean binary, full support identity and fresh ancestor
module/receipt hashes. Identity and safe-file checks repeat before launches
and during replay, including immediately before the 540-second launch cutoff.

The unchanged low-level Part04 collector is reused. Its fixed marker labels
are not experiment identities: the new protocol, manifests and actual marked
source bind their meaning. Eleven markers surround the same logical
frontiers, at unmarked candidate byte offsets:

65, 102701, 104333, 112569, 112729, 113075, 143327, 143786,
384381, 384413, 426586.

Removing the exact inserted marker commands reconstructs the 426,586-byte
candidate Part04. The marked target is 426,971 bytes. A marker is only an
asynchronously observed reporting frontier, not proof completion or theorem
CPU time. Completion additionally requires the complete exact 807-subject
inventory and actual bounded module, and remains diagnostic-only.

Successful parent receipts require their complete inventories and actual
modules. Failed processes retain bounded raw streams and failed receipts when
safe. Any malformed outcome, changed identity or incomplete finalization is
kept distinct from verified completion. Maximum arbitrary parent output can
exhaust the aggregate evidence budget; in that case trusted replay/display
must refuse rather than claim a complete failure container. No required
bytes are silently discarded to make a complete-evidence claim.

RESULT parent rows contain a compact process projection: launch state,
rounded process elapsed seconds, return code, timeout/incomplete/truncation
flags, and actual retained stream byte count. Replay derives this from the
verified receipt and raw files. Known nonlaunch is false; uncertain launch is
null and cannot authorize a descendant. Missing fields remain explicit nulls;
malformed data is not converted into an apparently verified all-null row.
Return codes are signed 64-bit integers or null; bools are not integers.
Elapsed values are finite in [0, 600]. These are process timings, not theorem
timings. Receipt hashes commit undisplayed details; the job-log projection is
not a portable full replay container.

To fit the unchanged RESULT limit, its target process omits only the duplicate
`files` map. The collector's original map is checked before omission. Replay
independently derives the three actual file identities and verifies
`raw_files` plus `compact_receipt_reference`, retaining every original hash,
raw-byte and accounting check. Collector output and EVENTS are unchanged.

## Resource limits

- At most six launches; 60 seconds per process, 540-second new-launch cutoff,
  600-second outer execution command, 2-second cleanup, 15-minute CI job.
- Source limit 2 MiB each and 8 MiB aggregate. Retained original/candidate/
  marked sources total 6,020,325 bytes across 23 files.
- Module limit 32 MiB each and 128 MiB aggregate.
- Target raw cap 507,392 bytes. EVENTS limit 8,416 bytes; RESULT limit
  7,968 bytes; combined metadata limit 16,384 bytes.
- Identity limit 114,688 bytes. Durable diagnostic evidence plus displayed
  EVENTS and RESULT must remain within 1,048,576 bytes.

Source-derived sizing with all three distinct permitted axioms per subject
places the conservative natural complete-inventory aggregate at 1,024,173
bytes and a deliberately mixed conservative RESULT envelope at 7,940 bytes.
Branch-consistent success/failure projection fixtures reach 7,285 bytes;
neither synthetic fixture is a complete replay container. The historical support
map gives an identity estimate of 107,553 bytes. These are serialization
feasibility estimates, not bounds on arbitrary warning/error output or
substitutes for actual identity and finalization checks. Any schema change
requires refreshed sizing; no cap may increase.

## Activation and interpretation

The kernel workflow atomically switches both execution and replay to
`tools.diagnose_core_seven_relocation`; it does not invoke the old diagnostic
or provide a manual dispatch fallback. Python-only controls retain all old
tests and add separately bounded candidate controls. Publication must verify
the actual remote parent and frozen tree, then inspect the automatically
created exact-head run rather than dispatch a duplicate.

Run with the pinned Lean checker and a fresh output directory, then replay
the same directory with `--print-diagnostics`. Replay never launches Lean.
Only complete replay may display its checked projection. Full narrow proof
acceptance still requires a separately reviewed eleven-stage acceptance run
with all original targets and negatives; this experiment cannot grant it.

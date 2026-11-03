# Explicit loader APIs: compatibility proposal and executable counterexamples

Status: isolated design, stacked on #619 (`43ea9c8f316d38cf3aa14b883d550a7ad0c5f3c6`).
No `hepta/` changes, CLI flag, global defaults, replacement loader, production
rollout, or claim that the proposed APIs already exist. Small contract models live
in `experiments/loader_api`; existing loaders remain the behavioral oracles.

## Decision and falsifiable migration plan

Replace duplication only after a staged mechanical extraction, not by adopting
the research fork as production. Preserve one implementation each for package
inventory/lock handling, graph resolution, lexer loop and parser construction.

1. Extract internal `LoaderOps` calls in the production algorithms, without
   changing public signatures or output schemas. A legacy operations object must
   retain current read/text decoding, directory ordering, parse diagnostics,
   symlink rules, identity construction, and override behavior. Run differential
   tests against the pinned old implementation on unchanged and mutated inputs.
   A changed report, diagnostic, filesystem effect or acceptance is a failed gate.
2. Add a separate explicit `LoadSession(policy, checkpoint)` entry point. Policy
   selection is required, never a hidden global default. Its operations implement
   read(role), stream_digest(role), inventory, find-manifest admission, edge/depth
   admission, tokenize-admitted and parse-admitted. Pass it explicitly through
   package loading, snapshot, lock verification, graph loading, Prepared reads and
   every revalidation. No optional argument may silently fall back to unmetered
   operations inside a bounded session. A protocol/type check alone proves none
   of this; instrument every primitive with a forbidden fallback in tests.
3. Make parsed-token ownership explicit: lexer returns an opaque internal batch
   bound to session, source bytes, path and parse purpose. Parser consumes only
   matching batches, with token admission on append and no duplicate lexing.
   User-supplied token lists must never skip charges. Preserve production tree
   depth checks as well as optional stricter policy. This mechanism is proposed,
   not implemented by the small ledger model in this PR.
4. Bind project handles and Prepared handles to their originating session. Reads,
   reloads and unchanged checks share the same ledger/deadline until request end.
   Cache hits still charge graph edges. Fresh execute means a new session;
   reload never does. Internal load already calls unchanged: budget this work.
5. Only delete forked files after every legacy test passes and finite admitted
   workloads match identity/report/errors; retain counterexamples as regression
   tests. Adopt bounded mode per caller after explicit review. Do not re-pin an
   upstream hash merely to quiet a test. Native qualification remains separate.

A future implementation should use `hepta/loading.py` for the internal operations
and session, while `modules.py` and `packages.py` retain domain algorithms. Do not
add another copied parser/module/package implementation in the name of extraction.

## Error taxonomy and terminality

Proposed admission diagnostic: code `E_LOAD_BUDGET`, phase (admit/discover/load/
revalidate), dimension, limit, admitted, attempted. The model exercises this
serializable structure and immutable first-failure preservation. `attempted` is
cumulative requested admission, not a measurement of retained heap or OS bytes.
Do not parse current error strings to infer fields. Structured context must be
created where failure is detected, including role, depth and read invocation.

Keep the internal budget exception outside `HeptaError` and `ValueError`. Current
unchanged catches `HeptaError` and can turn it into false; JSON/manifest catches
can mislabel ValueError. Convert only at the user-facing boundary, after any
revalidation/cleanup, into a structured failure response. A false unchanged
result means stale/unreadable state; it must not mean quota exhaustion. Owner,
reentrancy, invalid override policy and deadline errors need separate categories,
not bogus byte-limit fields. Timeout stays the original native request timeout.

For actual OS reads, record bytes returned including an overflow sentinel and
separate proposed admission counters from observed consumption. The ledger model
is not a replacement for #615's reader: its rejected admission does not increment
an admitted count. A per-file rejection, cumulative-byte rejection and nonregular
file refusal must remain distinguishable in a future reader API. Keep the first
budget diagnostic on all later attempts; do not replace it with 'terminal'.

Current context closes on arbitrary exceptions, not just budget failure. Proposed
sessions also become unusable after failed operations. The small overlay function
only makes **budget** failures terminal via its ledger; callers must discard it
on encoding, policy or filesystem errors. These helpers are models, not a usable
session with owner-thread/reentrancy guarantees or tamper-proof counters.

## Source overrides and lock semantics

Observed compatibility, now executable tests:

- Legacy accepts None and empty mapping; #619 refuses any non-None override.
- Used overlay text enters source hashes and graph identity. Unused overlay text
  does not enter graph identity, even if its syntax is invalid.
- Legacy `unchanged()` reads disk, so a differing overlay makes it false;
  `except_paths` may omit those sources. Do not redefine this method quietly.
- With `locked=True`, the existing lock validates the disk package inventory,
  before overlay substitution. A valid disk lock plus different overlay can load;
  a stale disk lock is still `E_LOCK_STALE`, even with an overlay. Therefore
  `locked=True` is not evidence that the overlaid program is described by the lock.

Preserve those semantics in the legacy path. For a separate bounded editor
profile, accept None/empty mappings equivalently, freeze overrides once at request
admission, and charge ALL keys and UTF-8 bytes including unused inputs. An ordinary
dict of ordinary strings is the proposed first profile; mapping/str subclasses,
resolved alias duplicates and invalid encodings are refused explicitly. These
restrictions differ from legacy and must not leak into its adapter. Per-source
role caps apply again when consuming overlays. Snapshot mutation cannot change a
reload; a new editor revision requires a new request/session.

The prototype encodes at most 1024 characters before each byte admission; joining
chunks still allocates and the caller's input strings already exist. UTF-8 byte
count is not character count or heap. Resolved paths do not freeze symlinks:
retain original lexical-to-resolved bindings and check them on every reload.
Root/extension/C-import sidecar checks still apply after overlay selection.
No overrides for sidecars, manifests, locks or original headers in this profile.

Do NOT authorize native build/publication with this editor profile. A later native
overlay feature needs an explicit effective-source manifest plus disk-lock
provenance, frozen revision identity, and overlay-aware revalidation distinct from
legacy unchanged. Until then the native context continues refusing overlays.
Do not use `except_paths` as a blanket native-output publication bypass.

## Workload evidence and quota selection

`python -m experiments.loader_api.measure` runs six fixed, actual repository
examples through #619's loader: initial load (including implicit revalidation),
explicit unchanged, then reload. `workloads.json` records all cumulative counts,
source hashes, chosen experimental limits, stage and failures without silently
excluding a rejection. It is loader-only evidence, not native builds or large
customer projects. Samples: scalar, results, borrowed-storage modules, owned
modules, shared-budget syntax, and package app with algebra dependency.

Observed final cumulative values for this checkout:

- Scalar: 1,850 bytes / 5 reads / 2 parses / 144 tokens.
- Results: 4,165 / 5 / 2 / 526.
- Borrowed storage: 11,815 / 10 / 4 / 1,382.
- Owned: 10,390 / 10 / 4 / 1,002.
- Shared budget: 12,170 / 5 / 2 / 1,080.
- Package app: 10,640 / 40 / 4 / 476; 10 package loads, 10 metadata parses
  and 10 inventory entries. Rechecks dominate the package operation count.

All six preserved identity and reported unchanged. Absolute ancestor discovery
counts depend on checkout depth; the recorder captures them rather than claiming
path-independent reproducibility. Manifest and lock hashes are not fully captured
by `source_bytes`; source hashes here identify loaded graph input, not an
authenticated package closure. The recorded baseline identifies the intended
published experiment source; it is not a claim that a dirty local checkout has
that Git HEAD. Verify changed inputs before comparing later runs.

These small samples are insufficient to select production limits or percentiles.
Collect bounded, consented representative editor and native-build traces, include
failed/outlier projects, repeated rechecks, large valid locks, dependency diamonds,
unrelated inventory and C header workloads. Record counts and separately measured
peak RSS/time; neither substitutes for the other. Review a versioned caller
profile with explicit headroom and rejection UX. Never automatically raise a
quota after rejection, infer universal limits from these maxima, or restart a
session to fit a project. Where finite limits cannot admit required work, report
that tradeoff instead of advertising a hard sandbox.

## Test and release gates

Run `python -m unittest experiments.loader_api.test_contract -v` for model and
existing-loader counterexamples. The isolated loader-api-design workflow requires 55 unique controls (14 new
plus #619's 41 context controls), exact head and no skips. The workload test
reproduces the recording, excluding only checkout-depth-dependent path checks.
Run the earlier
164-test exact-head native matrix for integration changes. This design does not
modify that earlier workflow or claim its native coverage applies to new code.

Additional required implementation gates: extracted legacy differential corpus;
role retention under misleading suffix/aliases; nonregular-file/late-growth reads;
UTF-16/32 escaped JSON depth; metadata errors not swallowed; source/manifest/lock
mutation during recheck; fresh deadline not minted; owned token batch replay and
foreign-session refusal; editor lexical path mutation and frozen revision tests;
explicit prohibition of native publication with overlays. Existing #619 tests
cover a subset, not all proposed API behavior.

No hard CPU/heap bound, in-process security, atomic filesystem snapshot, binary
authenticity, foreign safety, production default change, merge or deployment.

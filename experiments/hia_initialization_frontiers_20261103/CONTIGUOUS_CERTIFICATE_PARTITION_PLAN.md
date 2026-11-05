# Contiguous certificate partitions under the original launch budget

Design only. This proposal does not change any generator, validator, workflow,
proof, or production behavior. It needs independent design review, subsequent
implementation review, and actual exact-head kernel validation. All twelve global
obligations stay unproved and all authorization flags remain DENY_ALL.

## Evidence and scope

The noncomputable diagnostic at f1191d1325441e8009706562ac0b2e9afa8f7f3d
(run 41681244860, job 126075153784) still timed out at 60.325806 seconds.
It observed marker013 after theorem ordinal768, but did not reach marker014
or the final inventory. That is a reporting frontier, not completion of768
proofs, a controlled timing comparison, or identification of the slow theorem.
Its independently checked evidence and all previous failures remain preserved.

This proposal starts from O, the unchanged complete structured source builder
at local01a0b6fd (tree1b433f7a), not its marker or noncomputable derivatives.
It changes module boundaries only. Ordinary def declarations, every type,
definition body, theorem target and proof text remain byte-for-byte unchanged.
No pooling, evaluator change, new theorem assumption, stronger fuel, native
decision, or noncomputable modifier is combined with this experiment.

## Frozen eleven-module dependency graph

Use the existing eleven-launch ceiling, not eleven launches plus hidden probes.
Current bootstrap verifies downloaded bytes without invoking lean --version.

1. Baseline, unchanged; imports its existing locked standard support.
2. SyntaxData, unchanged; imports Baseline.
3. CertPart01 imports SyntaxData.
4. CertPart02 imports CertPart01.
5. CertPart03 imports CertPart02.
6. CertPart04 imports CertPart03.
7. CertPart05 imports CertPart04.
8. CertPart06 imports CertPart05.
9. Connections imports CertPart06.
10. TransportRejections imports CertPart02.
11. WrongArm imports CertPart03.

Implement this as a separately versioned, exactly enumerated eleven-module
protocol with independently derived names, ordered parents and inventories.
Do not merely relax the old validator's ten-stage count. Unsupported layouts
or failures refuse; there is no automatic fallback to the old layout, marker
diagnostic, noncomputable candidate, or a reduced target set.

Every direct and transitive import inventory includes implicit Init. The last
three consumers retain their original declarations and proof bodies, changing
only imports. No certificate partition contains the original extraction suffix,
Hint declarations, Connections, or any rejection consumer. Consequently WrongArm
can see complete parallel transport and earlier inert data, but cannot import
the original extractor. Its wrong-arm evaluator is separately defined in that isolated import graph
under the same HiaCoreSyntaxSlice.extract name, and checked there; it is not
inferred from acceptance of the original evaluator.

## Deterministic partition and exact source accounting

Remove only the known import, namespace framing and final axiom-print framing
from each of the five independently validated original Transport modules.
Keep each declaration as an exact byte interval, including its complete proof.
Concatenate their declaration streams in the existing order: linear, parallel,
wrong_phi, literal_two, wrong_condition. Cut immediately after theorem ordinals
703,1406,2109,2811,3513,4215. Keep all intervening data declarations in order.
Reopen the exact fully qualified namespace when a partition begins mid-input;
never rename a declaration or rely on an ambiguous open namespace.

Each partition prints exactly its owned theorem inventory, once per theorem.
This moves print locations, not their subjects; simply retaining the old print
blocks would leave early partitions without complete checked inventories.

| Module | Theorems | Definitions | Source bytes |
| --- | ---: | ---: | ---: |
| CertPart01 |703|1419|378135|
| CertPart02 |703|1417|394675|
| CertPart03 |703|1416|391198|
| CertPart04 |702|1416|389828|
| CertPart05 |702|1413|388958|
| CertPart06 |702|604|310773|

Baseline30632 and SyntaxData27925 bytes are unchanged. Consumer sizes are
Connections21498, TransportRejections51025, WrongArm15735. Total2400382 bytes,
only117 more than the original2400265. These are preparation measurements,
not estimates of elaboration time or olean size. Every module remains under
2MiB and aggregate under8MiB. Any retained duplicate diagnostic source must
also count toward the same aggregate; this plan requires none.

Exact first/last declaration anchors (all under HiaCoreSyntaxSlice):

- 01: linear_g0 through linear_s146; first theorem linear_s1.
- 02: linear_p146 through parallel_pl113_0.
- 03: parallel_r113 through WrongPhi.mutated_kd87_0;
  first theorem parallel_o113.
- 04: WrongPhi.mutated_kp87_0 through LiteralTwo.mutated_p51.
- 05: LiteralTwo.linear_r63 through WrongCondition.mutated_kd29_3;
  first theorem LiteralTwo.mutated_s63.
- 06: WrongCondition.mutated_kp29_3 through
  WrongCondition.mutated_transport.

## Complete byte binding and non-circular verification

The existing original source verifier remains the first oracle for all five
complete independently supplied canonical byte streams. It parses emitted data
expressions independently of the emitter and reconstructs whole Raw values and
bytes, not selected slices. No successful Python check is a Lean proof.

The new proposal layer must independently parse the restricted declaration
framing, derive deterministic cuts and namespace ownership, and reverse the
new framing. Per-input reconstruction must equal each original declaration
stream byte-for-byte. Compare original full Raw/byte identities and target sets,
not only digests supplied by the proposer. Source hashes bind actual execution;
they do not establish a theorem, source provenance, or semantic refinement.

The original per-input843 target sets must be recovered as disjoint unions:

- linear:703 in01 plus140 in02; full root aliases/six root facts in02.
- parallel:563 in02 plus280 in03; full root in03.
- wrong_phi:423 in03 plus420 in04; full root in04.
- literal_two:282 in04 plus561 in05; full root in05.
- wrong_condition:141 in05 plus702 in06; full root in06.

All 4,215 transport theorem declarations (plus 7,685 data definitions), the
original 66 positive targets and ten exact
negation certificates remain mandatory. A partition success proves only its
precise declared targets under its checked same-run ancestors. It is not a
complete-input certificate until the root owner and all its required ancestors
are admitted. No projection, prefix receipt, or arbitrary union of unrelated
successful modules can replace complete root acceptance. Final full connection
acceptance still requires all eleven stages, exact inventories and negatives.

Imports refer only to earlier successful modules in this same run, with pinned
binary/support identities and parent source/olean/receipt hashes checked before
and after every launch. Imported oleans are trusted successful kernel outputs,
not independently rechecked theorem bodies; this existing trust boundary stays
explicit. No original extractor is used to justify its own syntax relation.

## Frozen limits and failure behavior

Keep60 seconds per process,540-second new-launch cutoff,600-second external
command and15-minute job. Eleven stages fit the invocation ceiling, not a claim
that eleven worst-case60-second processes fit the wall clock: the launch cutoff
must refuse remaining stages when exhausted. No retries or additional probes.
Keep32MiB per olean/128MiB aggregate and all existing source/output/identity
limits. Failed, unknown, incomplete, truncated, stale or nonzero modules cannot
produce an admitted parent. Stop successors on any failure. DENY_ALL remains
unconditional even if the narrow syntax connection eventually checks.

A long individual root proof, larger imported environment, repeated module load
or asynchronous proof work can still hit the same limit. Theorem counts merely
choose deterministic cuts; they are not cost weights or proof-completion times.
Do not increase budgets or relax inventories to force this layout to pass.

## Required adversarial controls before any execution

- Omit, duplicate, swap, edit, rename or move a declaration across its prescribed
  cut, including changes with fully recomputed outer manifests and hashes.
- Change a namespace, split a multiline proof, move a data definition after its
  use, introduce self/forward imports, duplicate module names, or shadow Init.
- Keep the correct theorem count but replace a theorem, omit its print, duplicate
  a print, alter its axiom list, or compare only proposer-supplied inventories.
- Alter a complete byte segment/root alias, bind a mutant to the original bytes,
  or claim complete input after only its first partition succeeded.
- Import Connections/original extraction into WrongArm, or let a partition
  depend on a later consumer; any such cycle or trust shortcut must refuse.
- Change a parent olean/source/receipt, borrow an earlier-run olean, or replace
  binary/support after preparation. Preserve all existing filesystem negatives.
- Fail each of eleven stages in turn and verify no successor/acceptance; reject
  a twelfth launch and any launch beyond540 seconds. No mock kernel success may
  be reported as a real proof.
- Independently reconstruct all source bytes, exact cuts, all target unions and
  complete five inputs; test budgets at the boundary and over it.

Only after independent review of implementation should a separately authorized
exact-head CI run test this layout. The existing diagnostic remains historical
evidence; this document neither resumes full validation nor publishes code.

## Alternatives deliberately not combined

Splitting each of five original Transport modules in half yields15 total modules
and exceeds the ceiling. A shared pool has132 strict leaf keys and13 object-key
packets, requiring290 new pool facts. Keeping all original names gives442 wrapper
proofs and401 unchanged proofs per input; estimated full source2609712 bytes.
That approach changes proof bodies and requires additional exact fuel/depth,
Raw/byte/delimiter and symbolic-tail binding. It is a separate future candidate,
not part of this mechanical layout or an already established optimization.

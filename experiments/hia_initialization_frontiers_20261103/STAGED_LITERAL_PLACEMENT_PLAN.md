# Proposed per-input literal placement

Design only. Independent review is required before implementation. This proposal
changes no Lean proposition, proof tactic, process limit, or acceptance rule.
All twelve global obligations remain unproved, all production/admission flags
remain false, and DENY_ALL remains in force.

## Observed fourth attempt

The fourth actual pinned CI attempt at head `a6f28ab`, run `41651943901`, job
`125972101751`, successfully completed Baseline in 2.115 seconds. SyntaxData
reached its existing process timeout after 60.079 seconds, with empty captured
stdout and stderr. The remaining eight stages did not start. No complete syntax
connection receipt was produced.

These observations identify the failed stage, not the expensive declaration or
root cause. With no command-level progress from SyntaxData, there is no evidence
that its five literal inputs, rather than its common transport model or another
part of elaboration, caused the timeout. In particular, the common transport
model alone might still time out after the proposed redistribution.

## Smallest proposed change

Keep all ten stage names, their order, exact ordered direct imports (including
implicit Init), theorem inventories, and proof text. Move each input's existing
wrapped Raw/Bytes declaration block out of SyntaxData and into its own existing
transport module, immediately before that module's existing wrapped certificate
block. Move the wrapper and declarations verbatim; do not merge wrappers, change
namespaces, rewrite terms, abbreviate literals, or introduce aliases.

SyntaxData then consists of its existing Baseline import, the exact original
transport-model prefix, and the same three generic transport axiom prints. It
contains no concrete Raw/Bytes or Hint declarations.

The following source sizes are UTF-8 byte counts calculated from the current
source builder, with only this in-memory relocation. No proof source has been
changed and no Lean process was launched for this calculation.

| Module under HiaSyntaxResearch | Current bytes | Proposed bytes |
| --- | ---: | ---: |
| Baseline | 30,632 | 30,632 |
| SyntaxData | 497,132 | 15,107 |
| LinearTransport | 1,088 | 97,312 |
| ParallelTransport | 1,144 | 97,372 |
| WrongPhiTransport | 1,177 | 97,419 |
| LiteralTwoTransport | 1,193 | 97,439 |
| WrongConditionTransport | 1,225 | 98,310 |
| Connections | 21,683 | 21,683 |
| TransportRejections | 51,030 | 51,030 |
| WrongArm | 15,742 | 15,742 |
| **Total** | **622,046** | **622,046** |

The five relocated blocks contain respectively 96,224, 96,228, 96,242, 96,246,
and 97,085 bytes, totaling 482,025 bytes. Thus SyntaxData loses exactly the
bytes the five transport sources gain. All other source bytes remain identical.
The maximum proposed source is 98,310 bytes, below the existing 2 MiB per-source
cap; the unchanged aggregate remains below the existing 8 MiB cap.

## Constant ownership and dependency invariants

Module names and constant namespaces are distinct. The relocation changes the
module owning these declarations but preserves each fully qualified constant:

- LinearTransport owns `HiaCoreSyntaxSlice.linearRaw` and
  `HiaCoreSyntaxSlice.linearBytes`.
- ParallelTransport owns `HiaCoreSyntaxSlice.parallelRaw` and
  `HiaCoreSyntaxSlice.parallelBytes`.
- WrongPhiTransport owns `HiaCoreSyntaxSlice.WrongPhi.linearRaw` and
  `HiaCoreSyntaxSlice.WrongPhi.linearBytes`.
- LiteralTwoTransport owns `HiaCoreSyntaxSlice.LiteralTwo.linearRaw` and
  `HiaCoreSyntaxSlice.LiteralTwo.linearBytes`.
- WrongConditionTransport owns `HiaCoreSyntaxSlice.WrongCondition.linearRaw` and
  `HiaCoreSyntaxSlice.WrongCondition.linearBytes`.

Each transport module still imports SyntaxData, which still imports Baseline.
Its own declarations precede its five bounded component proofs and assembled
checkedEncode equality. No transport certificate references another concrete
input, so the sibling transports remain independent.

Connections already imports all five transport modules in the existing order.
It therefore retains all five complete literal inputs and their checked
transport certificates. Its exact original extraction suffix, locator
instructions, two extraction equalities, real structural relation, four syntax
negations, and 66-name positive inventory remain unchanged.

TransportRejections still imports LinearTransport. That import supplies its
original real Raw/Bytes and cached exact checkedEncode equality. The separately
declared changed-byte list, equality rewrite, and all five exact transport
negations remain unchanged.

WrongArm still imports only ParallelTransport. It receives the exact parallel
Raw/Bytes and checked transport without importing Connections or the original
extraction suffix. Its single mutated extraction suffix, parallel Hint, and
unchanged wrong-arm negation remain isolated. Neither extraction implementation
enters the other's dependency graph.

Hint declarations remain in their existing extraction stages. No additional
import, process, standard-library dependency, or native/plugin discovery is
introduced. The printed inventories remain 56, 3, six for each of five transport
stages, 70 for Connections (original 66 plus four rejections), five transport
rejections, and one wrong-arm rejection.

## Manifest and structural validation required for implementation

Freeze the revised source/DAG manifest before execution. Source hashes change
only for SyntaxData and the five transport modules; the other four generated
source hashes must remain identical. Actual olean hashes must always be obtained
from successful same-run pinned invocations, never predicted or reused.

Record each input's definition-owning module explicitly. Tests must check that:

1. Every original wrapped input declaration block occurs byte-for-byte exactly
   once, in its designated transport module, before its certificate block.
2. SyntaxData contains no concrete input declarations, and no transport module
   contains a sibling input's declaration block.
3. All five canonical-byte, Raw-literal, byte-literal, Hint-literal, and definition
   hashes remain identical. Preserve fresh Core verification of all mutants.
4. The full-model partition hashes and unique wrong-arm mutation remain
   identical. Each Hint, every qualified proposition and substitution mapping,
   all ten negative declaration hashes, and the original 66 positive theorem
   names remain identical.
5. Exact imports, stage count/order, source totals, and graph separation are
   unchanged. Connections reaches all five checked transports; WrongArm reaches
   only its parallel transport, common model, and baseline, never Connections.
6. Existing forged-module, timeout, source/import mutation, axiom-inventory,
   partial-result, and resource-limit tests continue to pass. Add a placement
   mutation test that moves a literal to the wrong sibling or restores all five
   literals to SyntaxData and requires rejection against the frozen layout.

Only module ownership and placement change. No selected-tree substitution,
unchecked Python proposition, name-resolution drift, weaker rejected target,
or omitted transport component is permitted.

## Unchanged limits and unresolved outcome

Retain ten planned launches within the existing eleven-launch cap, 60 seconds
per process, no new process after 540 seconds, the 600-second external command
wall time, and the 15-minute job limit. Preserve the 32 KiB input, 4096-node,
depth32 transport bounds; 2 MiB per-source and 8 MiB aggregate source caps;
32 MiB per-olean and 128 MiB aggregate module caps; diagnostic limits; fresh-root
module isolation; and complete-DAG acceptance rule. No extra diagnostic Lean
invocations or retries are proposed.

This relocation lowers the largest per-module concrete-definition burden and
reduces imported sibling data. The old transport stages imported those literals
rather than elaborating their declarations again. It does not
prove a performance improvement: a single input plus its certificates may
still exceed the existing limit, and the common model alone may still fail.
Independent design review comes first, then authorized implementation and
independent implementation review. A new actual pinned exact-head run is needed
before any narrow syntax connection can be claimed. A timeout remains failure,
not permission to raise limits or treat partial checks as complete evidence.

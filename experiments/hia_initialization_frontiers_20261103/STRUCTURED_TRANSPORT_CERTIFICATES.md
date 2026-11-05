# Proposed structured transport certificates

Design only. No implementation, new kernel result, admission, or performance
claim. Exact-head staged CI accepted Baseline and SyntaxData, but the real
LinearTransport serialization and parsing certificates failed. Bounds, length,
and byte-range declarations printed axiom-free results inside the failed module;
that module was not admitted. The diagnostic failure obscures the original
kernel error; this plan does not assume that the remaining problem is only time.
All existing DENY_ALL and unproved runtime/exporter/body obligations remain.

## Fixed contract and budgets

Keep the existing Raw, serializer, parser, checkedEncode, determinacy theorem,
and checkedEncode_of_parts unchanged. The final statements remain:

- serializeRaw transportFuel transportDepth linearRaw = some linearBytes
- parseRaw transportFuel transportDepth linearBytes = some (linearRaw, [])
- checkedEncode linearRaw = some linearBytes

The byte list still contains every one of the independently reread 14,466
canonical bytes. No subtree, attribute, or unselected block is omitted.
Fuel remains 4096, depth 32, node bound 4096, and byte bound 32768. Retain 60
seconds per process, no new launches after 540 seconds, 600 seconds externally,
at most 11 invocations, 2 MiB per generated source, and 8 MiB total sources.
No native evaluation, new axioms, changed kernel limits, or longer timeouts.

Replace two large decision proofs with short equality proofs composed from
already checked local facts. Do this inside the existing per-input transport
stage; do not add a process for each chunk.

## Representation and independent input binding

Use small named Raw subtrees and named byte segments to share expressions.
This changes generated term representation, not the Raw datatype or List Nat
value and not either evaluator.

Generate byte segments from the independently reread canonical byte stream,
not by running the Raw serializer. The generator may propose split offsets,
but must check that intervals form an ordered, gap-free, nonoverlapping partition
of [0, byte_count), and that concatenating their literal Nat bytes is exactly
the independently reread input. Retain the full byte-stream hash and length.
Every byte literal remains range checked. Independently flatten the emitted
alias/segment terms and compare the complete resulting Raw and byte list with
the previous independently verified full input. Self-consistency between two
outputs of the same new generator is insufficient. No raw-fragment Raw
constructor is introduced.

Prefer defining linearBytes as the concatenation of these independently sourced
literal lists, with named tails. A flat list literal and a nested append of the
same literal pieces denote the same List Nat; the latter permits sharing.
This representation choice must receive review because it changes generation,
although it does not weaken the full-byte theorem or the existing I/O boundary.
Do not define linearBytes from serializer output. Do not substitute a hash for
kernel equality. If a separate flat literal is retained, its equality with the
segmented representation also needs a compositional proof, not another giant
whole-list decision.

Use maximal complete JSON subtrees of at most 256 encoded bytes as initial
leaves. The threshold is a proof-generation cut, not a larger admission budget.
An inspection of the actual linear fixture gives 127 such leaves and 30 enclosing
containers; maximum leaf size is 253 bytes, maximum string length is 20.
At a 128-byte cut there are 261 leaves and 69 containers. These are planning
measurements, not proof-size or kernel-runtime results.

Outside complete leaf subtrees, punctuation and quoted-key pieces are separate
small literal segments. Name the byte suffix after each segment without copying
its entire contents: tail_j = segment_j ++ tail_(j+1), with the final tail = [].
A parser proof must treat the remaining tail symbolically, rather than unfold
and normalize the entire rest of the document.

## Small generic serialization interfaces

Add generic lemmas proved only from the existing defining equations. In the
following interfaces f and d are the exact recursive call arguments; they are
not an extra fuel allowance. Write quoteKey k b for the expression
34 :: (k ++ (34 :: 58 :: b)), without adding a new serializer semantics.

1. Array constructor:
   serializeItems f d xs = some b implies
   serializeRaw (f+1) (d+1) (.arr xs) = some (91 :: (b ++ [93])).
2. Object constructor:
   orderedFields fs = true and serializeFields f d fs = some b imply
   serializeRaw (f+1) (d+1) (.obj fs) = some (123 :: (b ++ [125])).
3. Empty item/field lists reduce directly.
4. Singleton item:
   serializeRaw f d x = some b implies
   serializeItems (f+1) d [x] = some b.
5. Nonfinal item:
   serializeRaw f d x = some b and serializeItems f d (y::ys) = some t
   imply serializeItems (f+1) d (x::y::ys) = some (b ++ (44::t)).
6. Singleton field:
   stringBytes k = true and serializeRaw f d x = some b imply
   serializeFields (f+1) d [(k,x)] = some (quoteKey k b).
7. Nonfinal field: the same key/value hypotheses plus
   serializeFields f d ((k2,x2)::fs) = some t imply the corresponding
   result quoteKey k b ++ (44::t) for the larger field list.

Leaf serialization equations use their actual numeric fuel and depth and small
independent literal byte segment. Local kernel decisions may be used only on
these small closed goals. Parent equations apply the generic lemmas and cached
child facts. Ordered-field and key-domain checks remain explicit obligations.
Byte expressions are joined using List.append associativity and small local
literal equalities, not a full 14,466-element decidable equality.

## Small generic parsing interfaces

The parser is not replaced by parsing chunks in isolation. Certificates record
exact consumption, including the delimiter and the remaining suffix.

1. Nonempty array constructor:
   input.head? != some 93 and parseItems f d input = some (xs, tail) imply
   parseRaw (f+1) (d+1) (91::input) = some (.arr xs, tail).
   The head condition excludes the separate empty-array branch.
2. Nonempty object constructor:
   parseFields f d (34::input) = some (fs, tail) and
   orderedFields fs = true imply
   parseRaw (f+1) (d+1) (123::34::input) = some (.obj fs, tail).
   The explicit quote excludes the empty-object branch.
3. Final array item:
   parseRaw f d input = some (x, 93::tail) implies
   parseItems (f+1) d input = some ([x], tail).
4. Nonfinal array item:
   parseRaw f d input = some (x, 44::middle) and
   parseItems f d middle = some (xs, tail) imply
   parseItems (f+1) d input = some (x::xs, tail).
5. Final object field:
   parseStringTail keyInput [] = some (k, 58::valueInput) and
   parseRaw f d valueInput = some (x, 125::tail) imply
   parseFields (f+1) d (34::keyInput) = some ([(k,x)], tail).
6. Nonfinal object field: the corresponding value result ends in 44::middle,
   followed by parseFields f d middle = some (fs, tail); conclude the
   field-list result ((k,x)::fs, tail).
7. Empty containers are small direct leaf equations.

The first interface must not omit its head condition. A generic parser-extension
lemma accepting arbitrary numeric suffixes would be false: bytes [49] followed
by [50] encode 12, not a parse of 1 leaving 2.

For a complete string, array, or object leaf, generate a small proof of

    forall tail, parseRaw F D (leafBytes ++ tail) = some (leafRaw, tail).

For numeric leaves use the actual structural delimiter c in {44,93,125}:

    forall tail, parseRaw F D (leafBytes ++ (c::tail)) =
      some (leafRaw, c::tail).

This form makes the number termination check explicit while keeping the rest
of the input opaque. An end-of-input numeric rule, if ever needed, is separate.
Leaf proofs can unfold only their fixed short prefix; they cannot use decide on
an arbitrary free tail. Direct reduction or small defining-equation rewrites
must actually prove the quantified statement. No universal suffix hypothesis
may be supplied by Python.

## Fuel, coverage, and generation order

Compute the exact F,D at every certificate site by following the existing
mutual definitions from root (4096,32). Containers subtract one before their
list parser/serializer; each list step subtracts one before the child and the
remaining list. Siblings do not all inherit the first child's fuel. There is no
fuel reset at a chunk boundary. Generate the recursive call ledger as proposed
data and let every generic lemma application check its numeric arguments.

Emit local leaf facts first, then list/field suffix facts and enclosing container
facts, ending in the two unchanged root equations. Sharing is allowed only when
Raw value, literal bytes, fuel, depth, and delimiter condition all match.
Each parser parent must join the exact suffix returned by its child to the exact
input of the next parser; a mismatched suffix is not a new assumption.
The root returned suffix is explicitly [], not an ignored variable.

Use the unchanged checkedEncode_of_parts with bounds, length, and range facts
that must pass together with the full transport module. The resulting root transport certificate remains the
one consumed by the syntax connection and its negative controls.

## Resource and acceptance gates

### Measured certificate-count envelope

Read-only counting against the five current staged input payloads (HEAD f62897a),
using a 256-byte complete-subtree cut, gives the same counts for each: 127 leaf
subtrees, 30 enclosing containers, 156 child/list steps, and 94 enclosing object
keys. Thus a direct two-direction construction requires 626 primary equations
per document: 2 * (127 + 30 + 156). This is about 3,130 primary equations across
all five inputs, before key checks, ordering facts, and byte-expression glue.

The measured existing Raw rendering of the 127 leaves totals 44,139 bytes for
the real, parallel, wrong-phi and literal-two cases; 44,543 for wrong-condition.
Their independent leaf-byte literal renderings total 46,959 and 47,386 bytes
respectively. These figures do not include enclosing keys/punctuation or aliases.
The current entire source DAG is 622,046 bytes (approximately 608 KiB); these measurements are
source-generation observations only.

A conservative design envelope per input is:

- 626 primary equations, at most 94 separately named key packets (each combines
  its string-domain fact and symbolic parseStringTail prefix fact), 30 ordering
  checks, and 156 local byte-expression bridges: target at most 906 facts;
- target at most 1 KiB of generated declaration/proof/axiom-print text per fact,
  using short deterministic aliases rather than repeating subtrees or suffixes;
- reserve 160 KiB for literal leaves, remaining punctuation/keys, tree/list/tail
  aliases and imports.

That envelope is about 1.04 MiB per transport source, below 2 MiB, and about
5.2 MiB across the five transport sources. Reserving another 0.5 MiB for shared
lemmas, baseline, connection and rejection modules keeps the design estimate
below 8 MiB. This is a feasibility estimate, not an implemented rendering or a
runtime prediction. The 1 KiB/fact and 160 KiB data allowances must be checked
against the complete proposed renderer output before any implementation is
presented as fitting. Extra bridge facts, verbose proof terms, or duplicated
suffix literals could invalidate the estimate. Do not raise the existing caps.

Before invoking Lean, build the complete proposed sources and enforce both
source-byte caps, the existing process count, and the original deadline rules.
Roughly hundreds of small facts per input may fit, but the actual generated
byte count must be measured. Count shared data only as emitted; do not assume
future deduplication when claiming feasibility. Every named generic and concrete
lemma needs a deterministic axiom inventory; no unprinted auxiliary claim from
the generator is accepted as evidence.

Prepare all five input certificates and the complete ten-stage source inventory
before running CI. The real linear transport remains the first concrete stage
and blocks all successors if it fails. Do not skip later modules after a first
success, or claim full acceptance from that success: all five documents and all
rejection controls still must pass. Do not increase limits when a leaf or
composition fails. Existing staged identity checks, full-DAG acceptance and
trusted .olean loader boundaries remain unchanged.

## Required counterexamples

Preserve all current controls, and add or explicitly map these local failures:

- Flip a byte inside a leaf while holding Raw fixed: its leaf certificate fails.
- Change a comma, colon, quote, or closing delimiter between leaves: composition
  fails even if all standalone leaf payloads are individually valid.
- Omit, duplicate, or reorder a segment: the byte partition check or root
  consumption/equality proof fails. Include trailing extra bytes.
- Split numeric digits across a purported boundary, including 1 followed by 2,
  and test leading zero 01. Arbitrary-tail numeric acceptance is forbidden.
- Duplicate or reorder object keys across two leaf boundaries: orderedFields
  must still reject at the enclosing object.
- Give one child a mismatched lemma parameter or reconnect it to the wrong
  suffix: the proposed composition must not typecheck. Separately use genuinely
  insufficient fuel/depth to obtain a false computation claim. Do not assert
  that any different fuel value is semantically invalid: multiple sufficiently
  large values can evaluate successfully.
- Retain byte>255, unsupported-string, changed exact byte, stale descriptor,
  well-typed syntax mutation, and wrong-arm implementation controls.

A proof error, timeout, missing module, or resource exhaustion remains unknown or
failed execution. Only a successful kernel proof of the exact required negation
counts as a rejection certificate under the current runner policy.

## Remaining risks

Generic one-step interfaces are design sketches until Lean checks them. Mutual
recursion equations may require careful rewrite lemmas. Poorly controlled simp
or unfolding could accidentally normalize opaque tails and reproduce the
original cost. Parser-prefix facts need real boundary proofs, especially for
numbers. Source growth, thousands of elaboration steps, and proof-kernel equality
cost may still exceed current budgets. The hidden original kernel exception may
also have a different cause. Nothing in this plan predicts a successful run.

## Isolated implementation checkpoint (not kernel evidence)

The candidate renderer now emits all five input modules, not a single-input
pilot. Its independently parsed alias grammar reconstructs the complete old Raw
and byte lists, checks each gap-free segment and suffix, and checks exact root,
leaf and list-step proposition schemas against the fuel/depth/delimiter ledger.
The existing literal-only builder is retained for historical structural controls;
the actual qualification entry point selects the structured protocol explicitly
and does not fall back after any failure.

Measured complete generated source is 2,399,016 UTF-8 bytes. The five transport
modules are 438,468 / 461,322 / 448,624 / 450,314 / 454,525 bytes, with 843 named
facts each. The planning-only 160 KiB data reserve was exceeded: actual data
declarations range from 169,104 to 175,808 bytes. This does not increase any
hard limit; complete source sizes above remain below the existing caps.
SyntaxData is 26,676 bytes and checks the original three transport
lemmas plus 21 new composition helpers and eight short, fixed rejection
certificates. The original 66 positive targets and ten original negations remain
required; the eight new local controls do not replace them. All named helpers
and local facts are included in exact per-stage axiom inventories.

These are generation and mock-orchestration results, not accepted Lean proofs.
Full-source budgets, the ten-stage DAG, 60/540/600-second execution boundaries,
same-run module isolation and DENY_ALL are unchanged. A fully mocked execution
with the real source-identity map produced a 287,458-byte result receipt before
the eight small controls were added; it established log-size feasibility only,
not a real kernel result. Actual complete proof and negative-control acceptance
still require the exact-head pinned Lean lane after independent review.

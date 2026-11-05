# Explicit noncomputable data: single-factor diagnostic proposal

Design only, based on clean worktree head `2f35dda`. Independent review and
separate implementation authorization are required. No evaluator, generator,
validator, workflow, proof, or acceptance behavior is changed by this document.
No Lean execution accompanies it.

## Evidence and hypothesis

The actual `c09f98d3` declaration diagnostic reached markers through original
LinearTransport theorem ordinal 640 at about 56.2 seconds, then hit the unchanged
60-second process timeout. This is progress evidence, not proof completion or
evidence that code generation is the dominant expense.

Hypothesis: omit unnecessary executable compilation of research-only data
constants while preserving their transparent kernel definitions and all proofs.
Use explicit `noncomputable def`, not a section, opaque declaration, axiom,
compiler option, native decider, evaluator change, or definition pooling.
Kernel checking and reduction still cost time; the experiment may show no
useful improvement or may fail before completion.

## Pinned Lean 4.19 implementation evidence

All links below pin `v4.19.0`; line numbers are from the actual repository files,
not a web renderer that removes blank lines.

- [PreDefinition/Main.lean, addPreDefinitions, lines 266–278](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/PreDefinition/Main.lean#L266-L278):
  a singleton nonrecursive declaration explicitly marked noncomputable takes
  `addNonRec`; otherwise it takes `addAndCompileNonRec`. Both still enforce that
  a nonrecursive declaration has no termination annotation.
- [PreDefinition/Basic.lean, addNonRecAux, lines 124–172](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/PreDefinition/Basic.lean#L124-L172):
  both routes construct `Declaration.defnDecl` from the same name, parameters,
  type and value, with regular reducibility hints and safe status unless an
  unsafe modifier was supplied. Both call `addDecl`. Explicit noncomputability
  adds an environment tag; compilation is conditional, and `addNonRec` supplies
  `compile := false`. Attributes/equation-generation handling is not bypassed.
- [Basic.lean, shouldGenCodeFor and compileDecl, lines 102–106](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/PreDefinition/Basic.lean#L102-L106):
  explicit noncomputability excludes executable compilation. In contrast,
  noncomputable-section context controls compiler error logging. A section is
  therefore not the requested guaranteed omission mechanism.
- [DeclModifiers.lean, lines 152–155](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/DeclModifiers.lean#L152-L155):
  the explicit modifier flag comes from presence of the modifier syntax.
- [NoncomputableAttr.lean, lines 11–22](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Compiler/NoncomputableAttr.lean#L11-L22):
  `addNoncomputable` tags a declaration in an environment extension;
  `isNoncomputable` queries that explicit tag. Its documented role is
  introspection, not the code generator's dependency criterion. This changes
  environment metadata as well as executable-code availability. Do not claim
  that the complete environments or resulting olean bytes are identical.
- [AddDecl.lean, lines 12–22 and 47–95](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/AddDecl.lean#L12-L95):
  ordinary declaration admission still invokes kernel checking under the
  unchanged options. Asynchronous admission and error-recovery behavior remain;
  a marker is not evidence that all prior kernel tasks succeeded. Require the
  existing terminal receipt, successful exit and complete axiom inventory.
- [Main.lean, lines 289–307](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/PreDefinition/Main.lean#L289-L307):
  safe recursive declarations still undergo termination handling. The modifier
  is not a termination exemption; this proposal rejects recursive inputs rather
  than depending on that machinery.
- [MutualDef.lean, lines 49–69](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/MutualDef.lean#L49-L69):
  mixed computability in mutual definitions and noncomputable partial definitions
  are rejected. Theorems already omit executable compilation and must not receive
  the noncomputable modifier.
- [IR/Checker.lean, getDecl, lines 50–54](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Compiler/IR/Checker.lean#L50-L54):
  an executable dependency without generated code can cause compilation failure.
  Mark the entire generated data family, including aliases referring to earlier
  aliases. Do not rely on automatic tag propagation or opportunistic inlining.
- [Tactic/ElabTerm.lean, lines 447–480](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/Tactic/ElabTerm.lean#L447-L480):
  `decide +kernel` constructs a proof via `mkDecideProof` and submits it through
  `mkAuxLemma` for kernel checking. It is distinct from the native-decider path.
  Existing `rfl`, `simp` and `decide +kernel` proofs continue to use transparent
  definitions, not executable alias code. No `native_decide` is introduced.

This is a source-byte preservation argument for a restricted generated data
fragment plus an audit of the pinned implementation path, not a formal
refinement theorem for the whole Lean elaborator. Actual acceptance still
requires kernel checking of the unchanged complete 843-theorem inventory and
full-byte equalities. Add neither new assumptions nor 1,537 bridge theorems to
replace that obligation or evade the budgets.

## Exact candidate and isolation

Keep the original prepared DAG and formal validator unchanged. First perform
all existing independent validation of original preparation and the existing
marker diagnostic. Let O be the verified original LinearTransport source and M
its verified marker-instrumented source. Derive candidate N only after these
checks, by inserting the exact 14 ASCII bytes `noncomputable ` immediately before
every eligible top-level `def` in M.

The reviewed actual LinearTransport family contains 1,537 declarations:

- 1,223 with type `List Nat`;
- 158 with type `Raw`;
- 94 with type `List (List Nat × Raw)`;
- 62 with type `List Raw`.

There are no String-typed fields in this allowlist. Exactly 1,537 insertions add
21,518 bytes. Every original name, type, RHS, byte literal, declaration order,
namespace, import, theorem and proof remains unchanged. Preserve all 843 original
LinearTransport theorems, all original axiom-print commands and marker text.
Baseline and SyntaxData remain byte-identical to the frozen original sources.

Use only the existing three-stage diagnostic launcher: Baseline, SyntaxData,
then candidate LinearTransport. Do not start the remaining seven stages even
if the candidate succeeds. No extra probe invocation, retries, full-DAG resume,
native execution, install or publication is authorized by this design.

Preserve the current capture accounting exactly: durable metadata 16,384 bytes
(internal 12,288 plus final 4,096, with one display counted), raw capture 507,392
bytes, and the existing total at most 1 MiB. The 32 KiB manifest cap below is a
separate frozen-preparation limit, not a live log allowance. A combined manifest
may be one prepared manifest; the existing manifest-reference check does not
replace or enlarge its 32 KiB cap.

All existing source, receipt, PTY, pinned-checker, support-identity, fresh-root,
module-hash and same-run import gates stay intact. Retain 60 seconds/process,
540-second launch cutoff, 600-second external limit, three diagnostic invocations
within the existing eleven-invocation ceiling, 2 MiB/source, 8 MiB/source aggregate,
32 MiB/olean and 128 MiB/olean aggregate. Count every retained O, M and N source
under existing accounting; the extra 21,518 bytes are not exempt. No accepted
artifact may depend on the diagnostic candidate olean.

## Two-layer reversible binding

Add a separate candidate diagnostic manifest, not a relaxation of the original
source parser or formal validator. Preserve the old marker manifest and original
source bindings. The new layer records O/M/N hashes and sizes, the exact fixed
insertion token, reviewed declaration count/type counts, and a strictly increasing
array of the 1,537 insertion offsets in M. Derive names and types independently
from validated O, rather than repeating long names in the manifest.

Independently verify all of the following before launch:

1. Parse the restricted original data grammar and derive the complete eligible
   declaration list from O. Require the reviewed counts. Each declaration has no
   parameters and an allowed closed data-expression RHS referring only to
   previously validated aliases. Reject forward/self references, functions,
   recursive or mutual declarations, extra attributes, unsafe/partial/opaque
   forms, options, theorem edits and unsupported syntax.
2. Map those original declaration boundaries through the verified marker
   insertion map to M. Require exact equality with the entire offset array,
   not a subset, superset or merely a matching count.
3. For offset m[i], require the exact insertion token at N offset m[i] + 14*i.
   Strip only those exact recorded intervals and require byte equality with M.
   Then run the old independent marker stripping check M → O. Revalidate all
   original full-tree, full-byte, fuel/depth, target and proof-source bindings.
4. Keep each marker's `original_offset` relative to O unchanged. Recompute its
   candidate `instrumented_offset` from the actual transformed stream, counting
   modifier insertions strictly before that marker in M. Preserve the original
   M positions in the old layer. Verify exact marker bytes at both coordinates;
   do not infer elapsed progress from stale positions.
5. Recompute all candidate source/module/receipt hashes. The runner must receive
   exactly N, not a regenerated or normalized equivalent. Preserve original
   declarations' theorem ordinals and existing nonaccepting terminal checks.

Both manifest layers together must remain at most 32 KiB in their actual encoded
form. A compact integer-offset array is expected to fit substantially better
than repeating names, but exact size validation is mandatory before launch.
For M below 2 MiB, 1,537 decimal offsets require at most approximately 12.3 KiB
including separators; existing marker metadata and all additional fields must
fit the remaining space. If not, reject preparation rather than raise the cap,
truncate evidence, or silently change the manifest contract.

Independent read-only in-memory preparation accounting for this exact candidate (diagnostic arithmetic, not Lean evidence):
O = 438,468 bytes; M = 439,164; N = 460,682. The original full DAG is
2,400,265 bytes; retaining that DAG plus M and N totals 3,300,111 bytes, below
8 MiB. The compact offset array occupies 9,820 bytes; the original marker
manifest is 11,392 bytes and the reference-style candidate manifest 10,657.
An inline combined encoding was measured at 22,087 bytes, below 32 KiB.
Independent preparation must reproduce and check these facts rather than trust
these reported counts. The same independent calculation reconstructed N → M → O byte-for-byte
in memory; no source implementation or Lean run resulted from that check.

## Required adversarial preparation tests

Invalid preparation must fail before the first Lean process starts. Runtime
scheduling or retry violations must fail before the forbidden invocation:

- missing one modifier, duplicate modifier, extra modifier, offset permutation,
  duplicate offset, off-by-one byte offset, wrong token or whitespace;
- marking only literal leaves but not aliases; marking a theorem, import,
  evaluator definition, parameterized function or marker;
- changed name/type/RHS, recursive/self/forward dependency, unsafe/partial/opaque
  declaration, inserted option or alternate codegen/native mechanism;
- unchanged counts with a substituted declaration or relocated modifier;
- stale original/marker/candidate hash, altered original input, wrong source sent
  to the launcher, or original full-tree/full-byte validation bypass;
- stale marker offsets, changed marker IDs/text/order, altered theorem ordinals,
  changed axiom inventory, source-cap or combined-manifest-cap overflow;
- scheduling stage four, retrying a timeout, accepting a diagnostic result as a
  formal bridge receipt, or importing its olean into later accepted work.

Positive preparation tests reconstruct N → M → O byte-for-byte, confirm the exact
21,518-byte increase and 1,537-entry family, and show that stripping the candidate
layer leaves the previously verified marker transformation unchanged.

## Interpretation and future consumers

The current diagnostic runner intentionally does **not** run theorem_inventory
on its third process. An exit-zero candidate is therefore only
`diagnostic_completed`; neither this proposal nor that status asserts that the
843-entry inventory was independently checked. Before reporting that all 843
candidate facts were kernel accepted, separately verify the exact candidate
source/receipt identities, exit zero, complete untruncated output, absence of
errors/sorry/custom axioms, and the strict unique 843-name inventory with the
existing permitted-axiom policy. Only the exact fixed marker message lines may
be separated from that output; no error or theorem entry may be discarded.
This may be an independent post-run evidence check, not a new success path in
the diagnostic runner or a relaxation of the original acceptance validator.
Without that check, report only the diagnostic outcome. In either case every
formal bridge/production/performance flag remains false and DENY_ALL remains.

Report the same nonaccepting diagnostic outcomes: completed, timed out, failed,
or interrupted/missing receipt. Even successful completion establishes only this
candidate module's bounded diagnostic result; formal bridge flags remain false,
all twelve wider obligations remain unproved and policy remains DENY_ALL.
A faster marker or later theorem does not establish proof completion or a causal
speed claim. Compare matched markers descriptively; code generation, elaboration,
kernel work and scheduling may overlap.

Later ordinary executable definitions that retain references to these aliases
may lack compiled dependencies. Their explicit noncomputable treatment, if
needed, requires a separate reviewed scope change; it is not authorized here.
The generic evaluators and theorem statements do not need executable versions of
these concrete values for kernel checking. This experiment does not activate the
later seven stages or promise their acceptance. If unchanged limits still fail,
retain the failure and return for a separate design decision.

## Isolated implementation checkpoint

The candidate is selected by the explicit `--noncomputable-data` diagnostic flag.
Without it, the existing marker-only protocol remains distinct and rejects the
candidate. The new source layer validates the old preparation/marker protocol
without modifying either formal validator, reconstructs the complete eligible
family, and strips the candidate back to M and O. Both new and nested stage
metadata use canonical encoded equality, rejecting floating-point aliases for
integer byte counts. M is retained at a fixed non-package path and never launched.

The implemented combined manifest is 23,337 bytes, rather than the earlier
22,087-byte arithmetic prototype; its additional explicit schema/bindings remain
inside the same 32 KiB cap. N remains 460,682 bytes, adds exactly 21,518 bytes,
and retaining O-DAG plus M and N remains 3,300,111 bytes. No logical source,
843-item theorem inventory, first/second stage, process budget, or capture budget
is changed. These are preparation checks, not evidence of Lean success or gain.

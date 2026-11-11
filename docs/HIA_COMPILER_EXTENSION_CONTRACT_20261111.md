# Exact-domain contract for the original select compiler upgrade

The new qualifier implements a separately versioned maintenance relation:
preserve the emitted output of two registered old source files and correctly
handle a registered finite set of new select programs and runtime inputs.
Its schema is `hepta.hia.compiler-extension.finite-domain.v1`.
A successful run is labeled `PASS_REGISTERED_FINITE_UPGRADE_DOMAIN`.
This is a finite native qualification, with separately identified local SMT
lemmas. It does not add an Agent acceptance claim or discharge the original
task's whole-compiler obligations.

## Frozen subjects and domain

The qualifier accepts only the original C0, frozen C1 and original patch
identities already required by
`tools/qualify_hia_original_select_fragments.py`.
It applies the compiler-source member of that exact patch and requires an
exact reconstruction of C1. The current compiler is never substituted.

The domain is registered before compiler execution and retained in
`domain.json`. It contains exact source and input byte identities.

| Domain | Required observations |
| --- | --- |
| Historical bytesum source | C0 and C1 must emit identical nonempty images; both images must return the independent hash recurrence and exact output byte for eight declared inputs. |
| Original C0 source | C0 and C1 must emit identical images; both resulting compiler images must compile the exact historical bytesum source into its expected image. |
| Two old refusal controls | Both compiler seeds must reject the registered unknown opcode and insufficient workspace cases with their declared codes and unchanged output buffers. |
| Five new select source files | C0 must return INVALID for each; the exact frozen C1 must compile them successfully. |
| New runtime-input set | The five complete generated programs must match 64 registered observations for u8, u32, u64, usize and bool. |
| Copied output fragments | The existing supplied-ELF checker and replay must discharge the same 25 local obligations under the existing normalized-slot preconditions; the original 200 projection observations remain separately counted. |

The copied-fragment qualification and replay run through their existing entry
points and retain their own raw artifacts and exact manifest. Their formal
scope does not grow merely because the maintenance runner consumes them.
No projection is represented as a complete generated-program proof.

Each complete generated-program observation must also satisfy its actual
byte ABI: integer status zero, a zero-extended low-u32 return, exactly eight
expected output bytes, the declared empty workspace, and unchanged input.
The image, input and output digests are checked against the actual bytes.
Fresh replay separately compares the original child stdout, the augmented
invocation receipt, the retained input/output files and the witness row.
Python equality between booleans and integers cannot satisfy a typed status
field or erase a change to the original JSON observation.

An independent 24-byte x86 negative control writes the expected output and
returns the correct low word with a nonzero upper status word. The former
whole-output predicate accepted this real execution. The current producer and
replay both reject it. This control is explicitly hand-written machine code;
it is not attributed to either historical compiler. Historical successful
observations must be inspected individually before concluding that this gate
defect invalidated any of their recorded results.

## Checker and compiler bindings

Each side records its actual compiler source and seed image identity, seed
build receipt, and the current checker implementation and native selection
identity. The shared checker dependency closure binds source bytes and actual
selected immutable native mappings. Full current source inventories are
retained and compared across the nested qualification and at completion.

Both original compilers are checked by the current identified implementation.
The original historical checker's implementation identity is unavailable and
is explicitly not inferred from the old source revision. A changed digest is
an identity change, not evidence that a semantic upgrade is correct.

A source, domain, selected owner or checker drift aborts the run. Empty,
missing, duplicated or substituted domains cannot obtain the positive finite
qualification status. Timeouts and failed subcommands retain their original
stdout, stderr, commands and return codes. No accepted report is produced
until all registered cases and fresh local-proof replay complete.

## Reproduction

Use the same Linux x86-64, GNU ld/objdump, libc and pinned solver requirements
as the original copied-fragment qualifier. The exact historical bytesum fixture
is shipped under `tests/fixtures/hia_original_select_v1/bytesum.hiaasm`.

The original public raw archive is recoverable from commit
`6502316907b10fba822b3518d0ba2cc7417afa61`,
at `review-evidence/hia-agent-original-select-delta-20261108-5e6c/raw-evidence.zip`.
Its Git blob is `a66a472bfe6a6f3043b8175e4bd173c9913fc433`;
its SHA256 is
`0b18f5665657601141ada5fe67990ee192d91665eb5463f806b495d6240a2d3a`.
The archive is 4,233,093 bytes with 526 members. The new reader checks these
pins before looking for the three exact input byte strings. It never extracts
archive-controlled filesystem paths.

```sh
python -B -m unittest tests.test_hia_original_select_extension \
  tests.test_hia_original_select_fragments -v
python -B tools/qualify_hia_original_select_extension.py \
  --historical-archive /absolute/path/to/original-raw-evidence.zip \
  --output NEW_OUTPUT_DIRECTORY
```

Alternatively supply `--original`, `--candidate` and `--patch`
with the three existing pinned files. A pre-existing output directory is
refused. The original qualifier's budgets are unchanged; the encompassing
runner has its own fixed 600-second budget. Its outer process owns one Linux
session inherited by every nested child. Timeout cleanup sends TERM then KILL
under a separate bounded two-second grace budget and retains the actual
termination record; it does not extend the qualification budget. A final
positive report is published only after the process owner completes cleanly.

## Remaining boundary

The report always retains `original_agent_four_claim_gate: HOLD`,
no Agent proof receipt, no evaluation and no adoption authority. The finite
source set does not establish the complete old grammar boundary or preserve
every previously valid program. The new source set does not establish every
valid select context. Workspace, resource, capacity, parser, termination and
whole-machine obligations outside the declared observations remain open.

The seed's general Core-to-machine refinement is still an assumption. Native
observations are not formal hardware proofs, and the local select lemma still
requires its slot preconditions to be established by the surrounding compiler.
The original learner transcript and full provider costs remain unavailable.

This document describes the executable contract and its boundaries. A source
change or passing unit test is not a completed qualification. Only the retained
report, raw observations and artifact manifest from the final source candidate
can establish that candidate's finite result.

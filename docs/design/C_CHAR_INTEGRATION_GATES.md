# Gates before integrating the experimental plain-char boundary

Status: design and characterization only. No production integration is implemented
or authorized by this document. Baseline is #612 tree
`bfcb0b27a166813ca0bfee8b5f2ba73fe2baa2ce`; exact published source
`a5ffcf9a8d6a8ccab97d9e67b9756c3f53cc6624` passed 49 tests on each native Linux
x86_64/AArch64 runner, including actual Rust 1.90. These finite tests do not
qualify every compiler entry point or an arbitrary native library.

## Recommendation

Do not make imported plain-char lowering automatic. First implement an explicitly
selected, native-bin-only profile for `check`, `build`, and `run`, using one live
project preparation object from graph loading through final artifact creation.
Keep `emit`, source-only APIs, other artifact kinds, and every currently unsupported
header shape outside that profile. The first useful end-to-end acceptance example
is an imported libc `strlen` or `puts` called through existing safe/unsafe language
rules. No native helper source injection or arbitrary linker arguments are needed
for those examples. Do not widen the verified Linux GCC x86_64/AArch64 scope.

Proposed flag spelling (not implemented): `--c-import-profile plain-char-v1`.
The admission predicate is command in {check, build, run} AND backend=c AND
crate_type=bin. Reject every invalid combination before native probing.
`check` and `build` must never execute the user program (only the controlled
existing importer probe); `run` preserves its timeout, captured output and exit
semantics. A native `check` must explicitly use `--crate-type bin` in this first profile;
its current default is rlib. Reject incompatible combinations instead of changing
existing defaults. Keep the flag off by default. This is not permission to accept
an arbitrary header or to claim foreign memory/effect safety.

## Existing integration seams and concrete hazards

1. `hepta/pipeline.py:analyze` stores generated C as an ordinary string and performs
   an object-only native check. `hepta/cli.py` subsequently invokes `compile_c`
   again for build/run. A private header owned by an already-closed preparation
   session cannot qualify that second compilation. Returning an ordinary C string
   is not enough to transport the native contract.
2. `analyze_project` supports `locked` and in-memory `source_overrides`; the
   prototype's `Prepared` does not. Re-loading with defaults silently changes the
   caller's validation request. An implicit project accepted by Prepared is
   correctly rejected by `load_project(..., locked=True)`.
3. `LoadedProject.c_imports` records module/sidecar identities but does not expose
   an authenticated declaration-level native lowering map. The prototype binds
   one header and checks the complete set of externs. A generalized implementation
   cannot identify eligible declarations by link-symbol spelling alone.
4. `compile_c` accepts arbitrary `link_args`, multiple artifact modes and debug
   source retention. These are not covered by the prototype. GCC driver link args
   can also affect compilation; treating them as inert library names would allow
   unrecorded semantic/preprocessor changes.
5. The CLI's output protection currently derives from `result.project.sources`.
   A profile additionally reads native headers outside the package and private
   compiler inputs. Their resolved identities must be protected too; never allow
   successful output publication to overwrite an input used for qualification.
6. The experiment exposes Python exceptions and uses generic read/capture helpers.
   Production needs bounded reads, subprocess stdout/stderr budgets, timeouts and
   normal diagnostics. Same-process Python mutation resistance is not a security
   sandbox; do not advertise it as one.
7. Saved C referring to a temporary header is not a distributable source artifact.
   Debug-source retention and `emit` require a separate retained-input/bundle
   design; do not label such C independently rebuildable or qualified.
8. Current importer grammar already rejects quoted local includes. Fresh native
   probing of libc prototype snippets does not establish transitive private-header
   support. Neither probe hashes nor post-build dependency observations prove an
   unchanged or atomic sysroot snapshot.

## Characterized counterexamples

`python -m unittest experiments.c_char_boundary.test_integration_gaps -v`
executes six independent tests. These assert existing boundaries, not fixes:

- A live prototype compiles and runs; the same emitted C fails after session close
  because original.h is gone.
- `locked=True` rejects a manifest-less project while default Prepared accepts it.
- `source_overrides` is not accepted by Prepared, so candidate edits cannot be
  silently qualified against on-disk source instead.
- obj/staticlib/cdylib are not accepted compile modes.
- A mixed plain-char and non-char header is refused, not partially routed.
- A quoted local include is rejected by the existing importer before preparation.

These passed locally on GCC14.2 x86_64. They do not require Rust. Additional
integration controls below remain planned, not executed implementations.

## Stage 1: preserve one request and one live qualification lifetime

Before any CLI switch is enabled, introduce an internal native build-plan API,
with an explicit lifetime and no public JSON-to-context constructor. Its inputs
are one freshly loaded project, an immutable normalized profile and the native
compiler identity. The plan owns its temporary header and final compilation.
A build or run performs final native compilation inside that lifetime; an early
object check never substitutes for the final result. Do not attach an opaque
Python object to a serializable report or let a report authorize recompilation.

Required conditions:

- Load with the caller's exact package-lock policy once; preserve source graph,
  alias bindings and source bytes. Reject source overrides for this first profile
  before work rather than silently discarding them. Patch/IDE integration remains
  out of scope. Re-check graph identities around the complete native operation.
- Re-probe the actual original header using the exact admitted compiler and fixed
  profile flags. Preserve existing header grammar and one-header restrictions.
  Use the same-TU prototype/typedef/character assertions during final compilation.
- Build declaration provenance from original module path, sidecar identity,
  declaration span/name and resolved function identity. Require every adapted
  extern to have exactly one fresh matching origin. Reject manual extern mixing,
  duplicate/ambiguous native origins and explicit exports in the first profile.
  Language module aliases must not lose origin; link-symbol spelling alone is
  insufficient. Never infer permission from self-consistent metadata hashes.
- Only native Linux GCC x86_64/AArch64, bin, fixed optimization/char-mode options.
  Reject target, no-std, arbitrary link args, debug retained source, unroll,
  source emission, other artifact kinds, frontend-only mode and unsupported
  compiler search environments when this profile is selected. Do not silently
  fall back to the old path after a profile rejection.
- Use bounded source/header/probe/compiler-identity processing and existing
  structured diagnostic conventions. Bound the whole prepare-plus-compile
  operation, not only each subprocess; cap captured output and aggregate work.
  Clean private inputs on all outcomes. Every new request, including a second
  request in the same process, must create a fresh plan rather than reuse a
  previously successful context.
- Preserve existing output atomic replacement on success and existing artifact
  on failure. Protect all source, metadata, original-header, compiler-input and
  private-input resolved paths against output overwrite; bind the final receipt
  to the actual output hash and final compile command. No receipt on failed final
  compile may describe an earlier successful object check as a completed build.
- Keep foreign effects and pointer/lifetime/bounds/termination obligations explicit.
  Report `frontend`, `native declaration compatibility`, `final artifact` as
  separate outcomes; do not assert Rust borrow checking or whole-FFI safety.

Exit tests: real subprocess CLI check/build/run on imported strlen/puts, with
actual observed output; no source-only fallback; absent/deleted/changed inputs;
lock failure preservation; rejected overrides; alias provenance; duplicate/manual
extern and export refusal; target/flags/crate/debug/emit refusal; unchanged old
APIs and ordinary byte APIs; invalid combinations fail before probing; check/build never run user code;
same-process second requests cannot reuse stale context; whole-operation timeout
and output budgets; final-compile failure retains previous output; output
aliases to protected inputs refused; cleanup on success/failure/timeout. Run all
#612 controls and original importer controls with actual Rust on both architectures.
Independent review must examine the final CLI-to-build-plan path, not only adapter
C text. Until these pass, stage 1 remains disabled/unshipped.

## Stage 2: qualify a narrow user-facing opt-in

After stage-1 code and tests pass independent review, publish an opt-in draft
candidate with explicit capability diagnostics and the documented command matrix.
Keep default lowering unchanged. Verify native check results cannot be reused as
build authorization after a source/compiler/profile change. Keep ordinary process
execution limits and failure behavior. Collect a concrete user-project use case
before proposing more artifacts or header shapes; successful libc examples alone
are not general C import completeness.

## Separate later work, not stage-1 prerequisites to weaken

Mixed headers/multiple imports need declaration-level routing with collision and
conflicting-origin tests. obj/staticlib/shared libraries need actual external
callers, symbol/visibility and linker tests. `emit` and debug retained source need
an explicit immutable source-input packaging model. Private/transitive headers
need a separately defined include-search and dependency model. Native library
configuration/selection needs bounded link-input policy and clear assumed ABI
contracts, never an assertion that caller-side checks authenticated a binary.
Each extension requires new counterexamples, native matrix evidence and review.
None is implied by the current plain-char scalar/single-pointer validation.

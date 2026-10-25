# Project boundary repairs on the newer record-view line

This draft candidate starts at the frozen #14 source
`b336a2dfa816a106867d7a9038be409f6e045db6`, not at #35. It integrates only
three previously reviewed project repairs: canonical per-translation-unit
value types (#31), unsupported function-type calling conventions (#32), and
ordered preprocessing-semantic optimization/PIC options (#35).

## Preserved newer interfaces

- Signed/unsigned-char options remain forwarded, mixed captured data models
  still reject, and user `-D`/`-U` macro values cannot attest the native ABI.
  The independent ABI-model probe is retained unchanged.
- The virtual `field_type` hook remains intact, with explicit translation-unit
  identity passed through both ordinary and record-view field resolution.
  Record-view signature pre-resolution also uses its actual unit. Function
  expression lowering continues to use the current function's unit.
- Forward record declarations, comment handling, record-view contracts,
  allocation/extent obligations and the original record-view algorithms remain.
- Typedefs are resolved from the captured TU, including system type context,
  without interpreting familiar spellings as canonical evidence. Actual
  pointer-sized signedness/width is required for size_t/ptrdiff_t special names.
- Already accepted optimization/PIC options retain their original order through
  dependency discovery, preprocessing, macro capture, AST and verification.
  This is not support for arbitrary compiler flags.

The new full-function-type check conservatively rejects unsupported convention
attributes. It does not generate adapters or establish general foreign safety.

## Local evidence and historical failures

Three donor regression modules are retained byte-for-byte. On the frozen base,
15 methods produced 21 assertion failures and one error for the not-yet-existing
explicit-unit API. Those results include valid matching-signature native C
comparisons; no mismatched-ABI call was executed.

An intermediate integration run exposed an accidental explicit `unit` reference
inside IntegerLiteral lowering, where no local unit exists. Its 28 NameErrors
are retained separately. That edit was corrected to the existing current-unit
expression behavior before the successful final checks.

Final focused checks: 42 project tests, 25 original record-view tests, and three
additional integration tests passed. Independent review ran the 25 record-view
tests and three integration tests plus seven additional real compiler/API cases:
separate TU aliases, missing context, inherited conventions, real char options
and spoofed macro controls. Production changes and regression scope were reviewed.

The first complete run executed 833 tests with one error: the newer C++
constructor qualification required Boost development headers absent on this dot
host. Its original failure log is retained. Official Debian
libboost1.83-dev 1.83.0-4.2 (SHA-256
`1f11fc6fb2ffe9378a0f0ebc8f2fd9223fb958b4a40bb9381c67a8857d947ca3`)
was verified and its headers extracted into an isolated workspace toolchain.
Only task-local CPLUS_INCLUDE_PATH changed; no system package installation or
source change was used to address this dependency. The existing pinned Rust
1.90, Clang 19.1.7 and GCC 14.2 remain in use.

The affected eight constructor tests passed, then the unchanged-source complete
final suite passed all **833 tests**, with zero failures/errors/skips in
185.259 seconds. The first complete run and dependency remedy are retained
separately. These are current-candidate local results; not a rerun of the 24
release gates. The final-suite receipt is reported in this draft's publication record;
prior #14's 815 tests/24 gates or #35's 729 tests do not qualify this new source.
This integration does not import the other scalar/C++/transport repair stack from
#35, nor claim all language/project blockers closed. No remote CI was queried,
no branch merged, no AI model invoked, and no system security setting changed.

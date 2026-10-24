# Main-file declaration inventory and AST-visible macro rejection

Based on PR #17, frozen commit
`c2423e71e8ed5c30687f02f5ce523e2a73d87fec`. This narrowly reconciles one concrete
failure motivating PR #15 without importing its stdint-only source policy.

## Reproduced failure and intentionally narrower scope

On the baseline, a plain function followed by a macro-expanded global and
another plain function was accepted: the global disappeared because its Clang
range had spelling/expansion objects instead of direct numeric offsets. A macro
global first in the file, followed by a stdint include and a plain function,
also disappeared. Other first-node cases instead rejected with
`E_C_NO_FUNCTIONS` because the scanner lost file identity; those are not reported
as successful omissions.

Clang's JSON dumper elides repeated physical filenames across the entire output
stream, not just top-level declarations. Spelling locations, expansion locations
and nested statement ranges participate in that state. `includedFrom.file` and
`presumedFile` do not replace physical-file identity. This behavior was checked
against real Clang 19.1.7 output and its
[official JSONNodeDumper implementation](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.7/clang/lib/AST/JSONNodeDumper.cpp#L275-L335).

The repair restores physical filenames in JSON serialization order before
classifying declarations. Declaration origin uses the expansion location when
present. Main-file declarations with AST-visible macro locations reject with
`E_C_MACRO`; missing, invalid or cross-file main declaration ranges reject with
`E_C_SOURCE_LOCATION` instead of silently continuing. Source-less implicit
compiler declarations remain ignored. Header declarations remain external to
this scalar pilot, and their canonical typedef information remains available.

This preserves ordinary included-header typedefs, typedefs built from internal
header macros, standard-header internal macros, and unused macro definitions.
It does not add general macro translation support, expand the language, or ban
all preprocessor bytes. The separate project migration capture is unchanged.

## Explicitly unresolved operator-token counterexample

AST-only inspection cannot reject every macro-dependent function body:

```c
#define PLUS +
int f(int x, int y) { return x PLUS y; }
```

Clang's complete function JSON has no spelling/expansion wrapper for the plus
operator, although `-Xclang -dump-tokens` exposes its spelling origin. This input
**still accepts** after this repair. It is retained as an unresolved
unsupported-source enforcement gap, not a successful rejection or a new claim
of macro support. No incorrect arithmetic result is claimed for this example.
A trustworthy token-origin gate, including presumed filenames, `#line` and
path attribution, is separate work; an ad hoc token-dump string parser is not
introduced here.

Accordingly this change does not close all of PR #15's preprocessing-policy
objectives. It does not prove dependency CAS, header/configuration stability,
all inactive-branch accounting, or comprehensive macro-body rejection. The
stdint-only restriction would reject valid included-header cases retained by
#17 and is not mechanically combined with this patch.

## Regression evidence

Twelve new tests run against the exact baseline produced eleven failed
assertions and no test errors, including wrong diagnostic rejection cases as
well as accepted omissions. The same twelve tests pass after repair. They cover
first and trailing macro globals, a header-defined macro expanded in the main
file, whole-function macros, AST-visible nested-body macros, token pasting,
digraph/spliced directives, physical versus presumed filename attribution,
header/system-macro positives, and an injected missing-range response from the
actual Clang AST. The injected case demonstrates fail-closed response handling;
it is not described as a naturally emitted Clang construct.

The operator-token input and real token/AST evidence are kept separately from
the passing rejection tests. No wrong-ABI calls or provider/model runs are
needed for these checks. Source-bound prior release receipts are not inherited.

## Final local validation

- Current focused scalar migration suite: 34 passed.
- Current full unit/integration suite: 673 passed, zero skips, 113.532 seconds.
- Python 3.12.14, Clang 19.1.7, GCC 14.2 and pinned Rust 1.90.0 on x86_64 Linux;
  the full run used a 420-second timeout and single-job/thread environment.
- Independent source and claims review found no blocking issue, reran all twelve
  new tests and checked nine real Clang fixtures including the still-accepted
  operator counterexample. `git diff --check` passed.

No remote CI, merge or deployment was performed. These results cover the
current tests, not all release gates or general preprocessor correctness.

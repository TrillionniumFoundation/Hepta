# A real changed-body `stb_divide` maintenance qualification

`tools/qualify_hia_stb_divide_update.py` recaptures and remigrates two complete,
unmodified upstream headers through the existing C-project migrator, Hepta
source lowering, Core verifier, and direct LLVM backend. This is a finite
source-maintenance qualification. It does not promote either version's
undefined C behavior into an equivalence result.

## Source change and configuration

The baseline is `stb_divide.h` v0.93 at upstream commit
[`dcb1116f1351bc8edad059d9ca432e8f322ba922`](https://github.com/nothings/stb/blob/dcb1116f1351bc8edad059d9ca432e8f322ba922/stb_divide.h).
Its 14,279 original bytes have SHA-256
`160e8c23d1c21aa2845062e357af06ca1c833ffa514d4ca7504fe11af77a6866`.
The successor is the existing v0.94 fixture at
[`003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5`](https://github.com/nothings/stb/blob/003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5/stb_divide.h).
Its 14,507 original bytes have SHA-256
`46358dedcc0f49324a602f796b13f24e00fa0e512046354ee69511997401af6c`.
Both complete embedded MIT and Unlicense texts remain intact. The baseline
has a separate fixture; the existing successor fixture and historical
qualification results remain unchanged.

The actual upstream overflow fix is
[`c38ec91d229cbe56167f8af865c05b3d92db705f`](https://github.com/nothings/stb/commit/c38ec91d229cbe56167f8af865c05b3d92db705f).
The qualification selects exactly
`-std=c11 -O2 -DC_INTEGER_DIVISION_TRUNCATES`. Under this configuration,
the six active functions and six matching declarations are all inventoried
and migrated. Semantic projections of the actual captured Clang ASTs must
show exactly two changed active bodies: `stb_div_floor` and `stb_mod_eucl`.
The two Core hashes and two native artifact hashes must also differ.
Other macro configurations and the disabled upstream self-test program
remain in the complete headers but are outside this qualification.

The migrator's generated function bodies are never edited. The tool adds
six exported scalar forwarding functions to call those generated bodies.
It lowers this source to Core and builds the shared library directly from
LLVM. The original C implementation is compiled only into the comparison
harness and original-C probe; it is not linked into the Hepta target.
The existing migration bundle also emits its usual Rust source, but this
qualification neither compiles nor executes that Rust source. It creates
no second migrator or language lowering path.

## Fixed inputs and separate denominators

The common-domain corpus has 119 unique `(a,b)` pairs: a seven-by-seven
small-integer grid excluding a zero divisor, 13 explicit boundary pairs,
and 64 seeded pairs. Its arithmetic domain predicates are fixed before
execution. They exclude division by zero, `INT_MIN / -1`, the old floor
implementation's overflowing intermediate subtraction/addition, and the
old Euclidean remainder's `-INT_MIN` operation. These predicates are a
conservative source-level domain restriction, not an all-input refinement
proof for the migrator or backends.

The original comparison code is built by actual GCC with
`-fsanitize=undefined -fno-sanitize-recover=undefined`. Each common pair is
evaluated by all six original C functions, all six Hepta native functions,
and all six Core VM functions. A separate mathematical division/remainder
oracle determines expected results. Native TSV rows, input bytes, raw
process streams, and VM JSONL rows are retained and checked individually.

| Category | Fixed observations |
| --- | ---: |
| Common input pairs per version | 119 |
| Common original-C + Hepta-native function observations, both versions | 2,856 |
| Common Core VM function observations, both versions | 1,428 |
| Old original-C UBSan failure processes | 4 |
| Old Hepta native overflow-trap processes | 4 |
| Successor original-C probe return processes | 4 |
| Successor-only original-C + Hepta-native function observations | 48 |
| Successor-only Core VM function observations | 24 |
| Additional old/new Core VM witness observations | 8 |
| Invalid-input Hepta-only native trap processes, both versions | 24 |
| Invalid-input Hepta-only VM traps, both versions | 24 |
| Failed actual native negative-control processes | 2 |

Counts in different rows are different observation types and must not be
added to infer a number of independent programs, input pairs, or proofs.

Four explicit witnesses expose the original source bug:

| Function | Arguments | Required old result | Required successor result |
| --- | --- | --- | --- |
| `stb_div_floor` | `INT_MAX, -2` | Original UBSan overflow; Hepta overflow trap | Independent arithmetic result |
| `stb_div_floor` | `INT_MIN + 1, 2` | Original UBSan overflow; Hepta overflow trap | Independent arithmetic result |
| `stb_mod_eucl` | `-7, INT_MIN` | Original UBSan invalid negation; Hepta overflow trap | Independent arithmetic result |
| `stb_mod_eucl` | `-1, INT_MIN` | Original UBSan invalid negation; Hepta overflow trap | Independent arithmetic result |

These witnesses are never counted as cross-version equivalent behavior.
Their successor-only matrix runs all six functions on all four pairs.
For invalid division inputs, only the checked Hepta target is invoked:
original C is not called on zero divisors or `INT_MIN / -1`.

The actual stale old Hepta library must fail when substituted into the
successor-only matrix. An additional legal Core program that returns zero
from every exported function must fail the actual native comparison.
Resource legality alone therefore cannot satisfy this qualification's
functional criterion. SIGABRT observations remain failure/trap categories;
they are not allocator-failure recovery. The previous C++ bridge's foreign
SIGABRT observations are not changed by this scalar-C qualification.

## Running and retaining a qualification

Use a fresh output directory outside the repository and an exact, clean
implementation commit. The CLI has no implicit development mode:

```sh
python tools/qualify_hia_stb_divide_update.py \
  --output /absolute/new-output-directory \
  --clang /absolute/clang-20 \
  --gcc /absolute/gcc \
  --source-sha <exact-clean-40-character-implementation-commit>
```

The callable `qualify(..., source_sha=None)` is reserved for focused
development tests and reports `development_only: true` and
`qualified_implementation_commit: false`. A wrong or dirty explicit
commit fails before compiler launches. Current source identities, fixture
identities, compiler executable identities, Python identity, and observed
configured frontend loader inputs are checked before and after execution.
The captured C projects are also rechecked. This is an observed input
binding, not complete OS, dynamic-loader or environment attestation.

The collector retains generated source, captured project data, full AST
output, Core, LLVM, native libraries, original-C harness/probe executables,
raw child streams, input/output rows, native build receipts, and SHA-256
identities for every retained file. It rejects an existing output directory
instead of overwriting an earlier attempt. Failed and timed-out attempts
keep their terminal report, attempted process records, retained capture
prefixes when available, and elapsed collection time. The bounded child
timeout is 60 seconds per explicit collector launch; the existing capture
and backend calls retain their own limits.

`collected_work_wall_ns` includes attempted capture, migration, lowering,
native building, all positive and negative executions, postflight checks,
and the readback check. It excludes final report serialization and does not
represent historical development time, human effort, or agent token cost.
The report gives those unmeasured quantities no numerical substitutes.

`validate_qualification(output)` is a read-only consistency replay. It
rehashes every retained file, refuses symlinks and changed inventories,
checks the pinned original headers, rebuilds the AST body projection,
verifies the retained Core, and checks process/command bindings and all
finite output rows. It executes no retained binary or generated source.
It also works after the evidence directory is relocated: recorded absolute
command paths are checked against the original recorded execution root,
while retained bytes are read from the new root. It depends on the current
repository's verifier and fixed fixtures; it is not a cryptographic proof
that a supplied self-authored receipt records a real execution.
A failed collection readback marks the terminal qualification as failed.

## Scope

This adds a concrete changed-body source-maintenance case with automatic
recapture, remigration, checked arithmetic and differential observations.
It qualifies a finite corpus for a scalar integer component on Linux
x86-64 with a fixed macro configuration. VM resource reports must stay at
zero for this scalar component; native allocator counters are not measured.
The result provides no all-input backend theorem, arbitrary C/C++ rewrite
claim, foreign exception/noexcept recovery guarantee, measured performance
advantage, new holdout claim, or model/agent productivity result.

# HIA Core + Agent product scope

Owner decision, 2026-11-10: retain HIA Core, strengthen Agent interfaces, and
freeze the high-level Hepta language. This supersedes the previous requirement
to port the entire high-level language before closing the HIA product.

## Active product

HIA is the sole evolving language core. Explicit typed assembly and structured
Core JSON describe the same checked instructions, effects and resource flow.
Core type/borrow/ownership checks remain mandatory. Necessary abstractions and
standard libraries are not removed merely to resemble CPU assembly.

The delivery scope remains native assembly/JSON admission, validation,
code generation/linking, HIA modules/packages/builds, runtime/library, Agent
diagnostics and snapshot-bound editing/persistence, installation/release and
bounded artifact/cache lifecycle. Each must be qualified on actual callers.

## Frozen reference, not production prerequisites

No new high-level Hepta grammar, AST, high-level semantic checker, source
backend or corresponding native-port expansion is required. Retain the current
implementations, tests and historical evidence for compatibility and independent
comparison. Do not remove or relabel their existing failures. Running historical
qualifications may finish; their result does not qualify the new product.

An active HIA dependency on a frozen component remains an OPEN separation task;
calling it reference-only does not remove that dependency. Existing high-level
module resolution cannot substitute for a HIA module/build implementation.

## Agent entry, first separation step

Installing this development candidate exposes `hia` in addition to the retained
`hepta` compatibility entry. Examples:

```sh
hia capabilities
hia catalog --schema hepta.hia.program.v8
hia check-assembly program.hiaasm
hia import-assembly program.hiaasm -o program.hia
hia verify program.hia
hia edit-query program.hia --function calculate --block entry --value y --fields op -o query.json
hia edit-apply program.hia --query query.json --response response.json -o revised.hia
hia build revised.hia -o revised.o
```

The Agent entry admits no high-level source/migration route, LLVM backend, Rust
shadow option or reference-interpreter command. Its build defaults to the
existing direct x86-64 Linux ELF object generator; it neither invokes a linker
for that object nor silently selects a foreign backend. Existing whole-Core
verification, stale-query refusal and no-replace publication stay in force.
The retained `hepta` entry keeps its explicitly selected compatibility routes.
HIA operations no longer eagerly load the high-level backend/pipeline/protocol.

**This entry is still a Python host bridge, not a HIA-native replacement.** It
does not establish whole native delivery, installation independence, complete
Agent persistence or production activation. `capabilities` explicitly reports
these limits. The already qualified bounded native compiler/linker filters
remain separately scoped; this bridge does not inherit their qualification.

## Closure, not scope accounting

Original/modified-source bootstrap, exact-source relevant regression, clean
machine installation, real Agent project execution and recovery must pass.
All shipped production authorities must use the native HIA route without a
Python/Rust/LLVM legacy fallback before retirement of the old production stack.
High-level code may remain outside that delivered package as frozen reference;
its presence in the research repository is not a native runtime dependency.

Token cost, retry rate, elapsed time, execution quality and disk footprint must
be measured on equivalent tasks. This scope decision makes no superiority or
completion claim. The historical whole-tree audit remains historical; removing
high-level obligations from the active product must not turn open HIA work green.

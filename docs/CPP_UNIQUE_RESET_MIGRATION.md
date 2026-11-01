# Direct `std::unique_ptr` release/reset migration

## Delivered scope

`hepta.cpp_unique_reset.lower_unique_reset_project` captures a real C++20
translation unit and translates its algorithm directly into Hepta source and
verified standalone Core. It adds the following resource operations to the
previously qualified unique-array work:

| Actual C++ operation | Generated ownership behavior |
| --- | --- |
| `destination.reset(source.release())` | Drop the old destination, consume the source, introduce a fresh destination binding. |
| `owner.reset(owner.release())` | Preserve the same owner; the C++ release has already nulled the pointer seen by reset. |
| `owner.reset()` / `owner.reset(nullptr)` | Consume the current resource immediately; later ordinary destruction is empty. |
| Literal `int` throw / allocator refusal | Emit the captured handler result after reverse-order cleanup of all acquired live owners. |

The accepted source uses `std::unique_ptr<unsigned char[]>` directly. It does
not need the fixed `OwnedBytes` and composite wrapper classes used by the
older project adapter. Scalar expressions, guard conditions, byte stores,
return expressions and exception handler results come from the actual AST.
The compiler-owned reference program selects library operation declarations;
its algorithm is never substituted for the project algorithm.

The existing unique-owner, cross-translation-unit, memberwise move-assignment,
GSL final-action and nested-scope migration results are inherited work. This
profile does not relabel those results as new implementation.

## Trust and accepted-program boundaries

The default-deleter `std::unique_ptr` contract remains trusted. Complete
standard-library declarations are inventoried and bound to header bytes and
expanded preprocessor text, including a comparison against the default
toolchain headers. Their implementation bodies are **not** translated or
formally proved by this adapter. Project-defined library specializations,
extra active declarations, altered header macros, custom deleters and raw
pointer escape are outside this profile.

The supported source has one complete scalar-returning function, immutable
scalar bindings, a checked outer `try` with integer and catch-all handlers,
and local exclusive byte-array owners. Each allocation has an explicit
source guard bounding its length to at most 65,536 bytes. The supplied example
chooses 4,096. Each subscript needs a dominating syntactic unsigned
`index < current_length` fact, or the continuation after a returning
`index >= current_length` branch. Byte-array allocation explicitly uses
`size == 0 ? nullptr : new unsigned char[size]{}`.

These restrictions make zero-length behavior explicit and avoid conflating
large-array constructor limits with an observed allocator refusal. They do
not change the source API's input range: oversized inputs execute the actual
source guard and return its actual result. The native vectors include
`UINT64_MAX` lengths and indices.

A release result is accepted only as the direct argument of one reset.
The compiler never creates a raw Hepta pointer for it. Reusing a consumed
source is rejected, even though some empty-source operations are legal in
general C++. A continuing branch may not change an outer ownership binding;
ownership changes on terminating return/throw branches are checked separately.
Nested owner construction, loops, concurrent access and arbitrary C++
templates require separate profiles.

The generated program passes the existing Hepta checker and standalone Core
resource checker without adding assumptions. This is not a new proof that
all C++ programs are equivalent to their translations. The source-profile
translation rules, Clang frontend, accepted standard-library semantics,
allocator mapping and native code generator remain explicit parts of the
trusted or separately validated boundary.

## Native qualification

Run from the repository root with Clang20+ and native GCC/G++ available:

```sh
python tools/qualify_cpp_unique_reset.py --workdir /tmp/reset-native-evidence
python tools/qualify_cpp_unique_reset.py --source-refusals-only --workdir /tmp/reset-source-refusals
python -m unittest tests.test_cpp_unique_reset -v
```

Each command requires a new output directory. Raw native command arguments,
exit statuses, exact stdout/stderr bytes and hashes are retained, including
failed observations. A final source/compiler identity check prevents a run
spanning compiler modifications from being declared qualified.

The original target contains separately compiled C++ component and allocator
objects, a C++ scalar ABI adapter, and a **separately compiled C caller**. The
translated target links only the standalone HIA object and the C caller.
Its undefined symbols are restricted to the selected allocation, release,
initialization and abort runtime functions. No original C++ object is linked
into that target.

The C caller records allocation identity, allocation size, refusal, release
identity, release order and final live count. An independent Python oracle
models those events from inputs without consulting the generated Hepta/Core.
It covers successful transfer, self transfer, zero owners, destruction before
transfer, explicit clearing, scalar bounds, capacity guards, integer exceptions
and actual failures at both allocation attempts.

The initial implementation run on x86-64 Linux, Clang 20.1.8 and the captured
libstdc++ 13 headers produced the following observations. These are finite
qualification results; a subsequent integrated release must rerun against
its own exact compiler identity.

| Variant | Inputs per implementation | Allocations | Releases | Actual allocation refusals | Live at completion | Observation digest |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Original component | 1,245 | 1,066 | 1,066 | 642 | 0 | `a277038c3b7457f2` |
| Authored project API/algorithm maintenance | 1,245 | 1,066 | 1,066 | 642 | 0 | `73aa6f85c0ebc822` |

The maintenance variant renames the C++ entry function and changes its actual
arithmetic multiplier from three to five. Both versions are captured and
translated independently, and their observed results differ as required.
This is a project maintenance control, **not** an upstream standard-library
version upgrade or evidence of generalized automatic API migration.

Two kinds of generated-target negative control are mandatory:

1. Deleting an actual Core `owner.drop` is refused before an object is published.
2. Reversing the exception cleanup order still passes the resource checker but
   is rejected by the independent native lifecycle oracle. Both resources are
   freed and the live count is zero; the event sequence remains observably wrong.

Fresh-Clang source negative controls additionally cover pointer escape,
`reset(get())` self-adoption, repeated release of a consumed source, unguarded
subscripts, a missing capacity guard, a continuing ownership-state divergence,
and a project macro that alters the expanded standard-library contract.

## Cost accounting and limits

Each migration report separately records build-configuration capture,
complete AST/library-contract capture, source generation, source/Core
verification, source/toolchain revalidation and total automatic migration
wall time. The native report separately records reference build, HIA
source/Core/native build, native execution and complete qualification wall
time. Process and child peak RSS are recorded. These values include actual
work; they are not runtime throughput benchmarks.

In the initial two-variant native run, complete qualification took 44.65 s.
Automatic migration took 19.46 s and 22.19 s, respectively; AST/library
capture accounted for most of that time. These numbers characterize this
small component and this host, rather than a generalized migration-cost
advantage. Full library declaration inventories are stored losslessly in
gzip files with compressed and uncompressed hashes.

`human_engineering_seconds` is null. Agent development elapsed time is tracked
separately in the task evidence and must not be presented as engineer hours.
Earlier engineering costs and costs of designing the admitted profile are
not retroactively set to zero.

The qualification establishes a scalar C ABI observation on the tested host.
It does not preserve C++ class layout, mangled names or exception ABI across
the boundary. It also does not claim custom allocator semantics, asynchronous
cancellation, abort-time destructors, recovery after process termination,
concurrent ownership, a universal resource proof, performance superiority over
Rust, or an actual upstream library upgrade.

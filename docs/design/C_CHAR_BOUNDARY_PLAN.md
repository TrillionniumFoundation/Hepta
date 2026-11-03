# Plain-char import boundary: pre-implementation safety and test plan

Status: proposal for independent review, not implemented or qualified.
Base: f2b76f5741c83822be2e12cf5a50b50a8d27b96a (#564).
Scope: the previously reproduced strlen import-to-C compilation failure.
No production change, suppression flag, asm label, or new language type.

## 1. Smallest proposed acceptance profile

Only project-loaded, native-imported extern functions may acquire the special
boundary treatment. Hand-authored extern declarations and low-level parse /
check / emit_c calls do not acquire it by symbol name or user metadata claims.
The original, freshly parsed header must use the existing importer's subset.
For the first prototype, additionally reject headers containing records,
arrays, macros/constants, function pointers, varargs, or nested pointers.
Simple scalar typedefs may resolve to plain char but must be independently
checked against the native typedef. Existing include guards remain allowed.

A qualified function has at least one plain-char scalar or one-level pointer
to plain char. The pointer may point to const char or mutable char. All other
parameters/results must be already-supported primitive scalars, or void as a
result; no mixed record/pointer-to-other-type bridge in this initial profile.
No char**, volatile char, atomic types, function pointers, or qualifier erasure.
This narrowed adapter profile must reject explicitly rather than quietly
redirect unsupported APIs. Existing unrelated imports retain their old path.

CHAR_BIT must be 8. Require native compatibility of int8_t with signed char
and uint8_t with unsigned char, plus matching size/alignment of the participating
character types. Do not infer character-type aliasing permissions from an
arbitrary same-width extended integer type. Probe the compiler's actual plain-char signedness and map
to i8 or u8 accordingly. A 64-bit native profile still applies. Linux ELF
x86-64 and AArch64 are the first experimental qualification targets. No macOS,
Windows, cross-target or custom compiler ABI claim follows from those runs.

## 2. Validation context: data, not a new authority

Proposed internal immutable LoweringContext, created only by a dedicated
project-native preparation path. It carries:
- exact assembled program/source identities and imported-binding identities;
- normalized original C declarators parsed anew from the original header;
- each mapped Hepta declaration, not just a function name;
- original header bytes/hash and a private immutable copy used for compilation;
- compiler path/hash/version/triple, selected strict flags and native char facts;
- a fixed adapter-profile version and explicit caller-supplied effect assumptions;
- the generated adapter/source identity and receipt identifying final validation.

No serialized context or sidecar is accepted as proof of validation. Existing
sidecar hashes are identity/self-consistency checks, not authentication. A
coordinated rewrite of a manifest cannot be ruled out by hashing alone.
The preparation path must reparse and re-probe real native declarations, and
compare the newly derived Hepta declarations with the actual imported AST.
A Python caller controlling the compiler process itself is not an adversary
this context can sandbox; the boundary is between untrusted project/manifest
data and supported compiler lowering, not a cryptographic capability API.

The current v1 source/sidecar meaning is unchanged. Old bundles do not become
newly qualified merely by adding metadata. The opt-in prototype prepares fresh
facts from the original header; incompatible or unavailable inputs reject.
The ordinary project-loader source/host/target checks remain prerequisites.
Caller-declared foreign effects remain assumptions, never upgraded to proof.

## 3. Revalidation and transitive headers

Prepare a private copy of the exact original header bytes before probing.
The first profile allows only the importer's existing standard include set
(stdint.h, stddef.h, limits.h), not new arbitrary transitive user includes.
Use the same selected compiler and semantic flags for the probe and final
translation unit. Initial strict flag choices are the backend's default
profile plus an explicit signed-char/unsigned-char test profile; the exact
choice is part of identity. No unrecorded -D, -include, target, packing, or
language-mode flags may be appended after validation.

A probe-source hash containing an include directive does not identify the
system header closure. Therefore the final native compilation must independently
assert the original function prototype, every participating typedef, char
width/signedness and mapped-type representation in the same translation unit
that defines the adapters. It must not reuse an earlier probe success as a
substitute for these checks. Retain compiler dependency output and available
dependency hashes as evidence, distinguishing these observations from an
atomic snapshot of a mutable system toolchain.

Reject a changed source/header/compiler/selected-flags identity detected between
preparation and result publication. This is not a guarantee against malicious
concurrent mutation of compiler binaries or system headers between observations.
If that stronger threat model is required, use an immutable toolchain/sysroot
and a closed dependency snapshot before claiming it. Do not hide this limit.

The first prototype compiles within the preparation operation and returns an
artifact/receipt. It does not promise a portable source-only C file whose
native assumptions survive later compilation with arbitrary headers/flags.
Standalone emit_c and compile_c keep their existing semantics; a context cannot
silently carry mutable file paths into an otherwise source-only API.

## 4. Typed adapter shape

Include the exact prepared original header in the generated translation unit.
Do not redeclare the original API using flattened i8/u8 types. Validate the
real function's type against its parsed native prototype with GCC's native
type-compatibility machinery. Use a distinct translation-unit-local adapter
name, collision-checked against generated names and the original header
ordinary identifier namespace (all functions and typedefs), plus relevant
preprocessor macro names, without creating a new
externally visible ABI or changing the original link symbol.

Calls from Hepta use the adapter. The adapter's signature uses the mapped
Hepta representation; its body calls the original native declaration through
explicit boundary conversions. These conversions are limited to:
- plain-char scalars with freshly verified matching width and signedness;
- one-level char pointers, preserving pointee constness and pointer direction.
Return values/pointers use the corresponding explicit conversion back.
Retain constness through typedef resolution and pointer returns; a claimed
raw_mut result for an actual const-char pointer must be refused, not cast away.
No function-pointer cast, opaque asm binding, warning suppression, memcpy of
unrelated records, or generic recursive pointer cast is permitted.

A pointer conversion does not establish length, lifetime, non-nullness,
termination, read/write permission or ownership. These remain explicit foreign
caller obligations. Tests must use live aligned arrays and bounded valid
pointers, not undefined behavior as a success/failure oracle. Standard library
contracts (for example nul termination for strlen) are not inferred merely
from a matching char-pointer signature.

Prototype/header generation for public consumers must not silently produce a
flattened conflicting declaration. The first profile is internal compilation
only; exporting a replacement public native header needs a separate design.
Explicit export "C" declarations remain unchanged and cannot use this imported
extern-only adapter path.

## 5. Falsifiable acceptance tests

The case inventory is C_CHAR_BOUNDARY_CASES.json. Every acceptance/rejection
must be tied to a named assertion and preserve a complete test identity list.
Required native tests use GCC O0/O3, UBSan, and a separate LTO link with
-Werror=lto-type-mismatch. Include a strict-aliasing-enabled native adapter
control so success does not depend on the existing backend
-fno-strict-aliasing flag. Compiler incompatibility warnings remain errors.
Use actual Rust as a behavioral reference only after binding the same original
header/native implementation and safe caller inputs. Build custom native
implementations with the same recorded semantic flags as the probe/final
caller. A caller-side assertion cannot authenticate the prototype, char
signedness mode or semantics of an arbitrary precompiled foreign binary; those
remain explicit external ABI/implementation assumptions. Rust success alone is
not proof of C source-type compatibility.

Critical positive controls:
1. Existing real strlen import reproducer transitions from E_C_COMPILE to a
   successful actual call, with the original header and provenance checks.
2. A custom original-header C implementation exercises char scalar arguments
   and returns, const/mutable pointer arguments, pointer returns, legal null
   passthrough and high-bit byte values for the selected signedness profile.
3. puts uses a valid terminated array and exact captured output. Runtime
   standard headers remain present; no header-removal trick is accepted.
4. Independent native profiles re-probe all char facts and run both defaults
   and recorded -fsigned-char/-funsigned-char variants. Do not transplant facts.
5. nm/readelf confirms calls still reference original symbols and adapters are
   TU-local. Real multi-TU/LTO native callers preserve ordinary C boundaries.

Include a probe-success-to-final-compilation drift test: preserve the original
top-level header and successful probe receipt, then alter a controlled included
typedef/header-guard fixture so the actual native declaration changes. Final
assertions must reject rather than trust the earlier probe. Use only temporary
fixture dependencies with all search flags fixed/recorded from the start; do
not edit installed system headers or silently expand the production flag profile.
This tests final revalidation, not an atomic-system-snapshot claim.

Negative controls must reject before reporting a qualified artifact: changed
binding/source/header identities; wrong host/target; incompatible actual native
prototype or typedef; fabricated char mapping/signedness; missing original
header; unsupported declarators; stale context reused after flags change;
unexpected post-preparation compiler flag additions; and explicit exports
incorrectly routed through adapters. In-package and external original headers
must follow the same explicit fresh-preparation rules for this new profile.

Compatibility controls retain ordinary signed-char/unsigned-char APIs without
remapping them to plain char, existing v1 loader rejection behavior, source-only
low-level behavior, qualifiers, explicit export names and unrelated C imports.
A narrowed profile may continue to reject valid but unsupported C APIs; it may
not silently admit or claim broader compatibility for them.

## 6. Stopping conditions

Before any production implementation: independent review of this trust model,
case inventory and adapter conversion limits. If the reviewer cannot justify
the one-level pointer conversion under the qualified C profile, narrow further
to scalars or stop; native execution success cannot replace that reasoning.
Then build an isolated experimental implementation, not a default backend
change. If an incompatible declaration is accepted, a boundary cannot be
bound to actual compilation, or a regression requires disabling a type check,
stop and report the counterexample. A green limited prototype does not by
itself authorize enabling this path for all imports or platforms.

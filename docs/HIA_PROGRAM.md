# HIA Core programs and Agent interfaces

HIA is a typed, resource-aware assembly/IR. The executable admission authority is
`hepta.hia_program.verify_core` / `verify_program`; it does not require the removed
high-level source language. A caller's hash, producer or proof claim does not
replace verification of the actual immutable program bytes.

This is the Core-only product. No high-level parser, source checker, source
lowering or migration compatibility route is provided. Existing separately held
historical evidence does not qualify this source tree.

## Program structure

A primitive JSON document declares a versioned `hepta.hia.program.v1` through
`hepta.hia.program.v8` schema, module and functions. Each function declares named
parameters, result types, effects, an entry block and its complete block set.
Each block declares `id`, typed `params`, ordered `ops` and a `term`. Operations
name their arguments, typed output values and explicit attributes. Entry block
parameters repeat the exact function signature. Branch arguments must match the
target block's parameter types and order. Use the local opcode catalog and actual
verifier for the complete version-specific vocabulary and diagnostics.

Names identify values and blocks; they are not machine addresses. Duplicate or
unbound definitions, malformed edges and incorrect calls/results are rejected.
Do not infer a newer schema merely because an older payload happens to contain
newer fields. Explicit schema/profile admission remains required.

## Core type and effect safety

The Core verifier checks scalar widths, opcode operand/result types, function
signatures, control-flow argument agreement, versioned capabilities and declared
effects. Arithmetic wrapping and checked operations are distinct instructions;
checked failures and traps are observable, not an optimizer's permission to
invent a value. Calls and returns preserve complete ordered result tuples.

Buffers and resource operations retain their actual ownership and borrowing
rules. An owner cannot be silently copied, leaked, used after a move/drop or
conflicted with an active loan. Access permissions, initialized ranges, dynamic
bounds, mutation rights, loan endings and branch/loop resource agreement remain
mandatory. A static verifier result is not a promise that an allocator or an
external resource will succeed at runtime.

Primitive v8 returned loans use an explicit function `return_loans` contract.
Returned origins must be the declared original formal resources; a borrowed
result cannot be used to extend an unowned local allocation's lifetime. Distinct
read/mutable contracts and outstanding loans remain checked across calls and
control-flow joins. The authoritative rules are the current Core verifier and
its unchanged resource/control-flow regression tests, not a producer's metadata.

Structural composite inputs, where admitted by the hosted Core normalizer, must
be normalized and reverified. They are not accepted automatically by a narrower
native byte/JSON/compiler profile. Unsupported representation or capacity is a
refusal; it must not silently select a different ABI or a deleted frontend.

## Execution and compiler boundaries

The hosted independent Core interpreter provides reference observations. The
selfhosted HIA compiler supports an explicit bounded assembly profile; the native
Core JSON frontend emits assembly for that compiler. Native application builds
bind exact source, compiler and image identities. A trusted native image is not
a sandbox. OS descriptor, memory mapping, allocator, kernel and hardware
conditions remain external requirements.

The native `hia-native` stdio application currently implements `capabilities`,
`verify` and `compile`. Build-time `flat`, `elf` and `exec` profile selection is
explicit. Native runtime needs neither Python nor an external compiler for those
commands. Its input/node/depth/output and process limits remain enforced. It is
not the complete hosted Agent service or a general module/build system.

The hosted `hia` entry exposes Core tools including capabilities, verification,
object building and bounded editing. Use `hia --help` and command help from the
actual installed version. No `hepta` high-level entry or source migration command
is part of this distribution.

## Agent editing and identities

Discovery uses `hia_describe` and `hia_read`. Copy the actual returned profile,
catalog and artifact references; one digest's spelling does not authorize it to
stand in for a different identity. Each request's declared schema, source bytes,
revision and administrator pins are independently checked by its actual owner.

Editing is snapshot-bound. Queries identify an actual verified source window,
function, block, value and editable fields. Apply operations must match that
query and current source; stale snapshots or invalid edits publish no replacement
program. Accepted edits undergo complete Core verification, not only a local
syntax check. Output publication retains descriptor identity and no-symlink
protections. An unknown operation outcome is not permission to replay a mutation
under a new identity.

The explicitly selected native scalar identity kernel checks canonical u64
strings and lowercase SHA-256 grammar. It does not compute hashes, authorize a
request, validate a complete JSON schema or persist an edit. Selected missing or
tampered images/sources fail closed; no numeric/regex fallback is allowed under
that selector.

## Installation and remaining work

The hosted wheel carries its actual Agent discovery documents and HIA identity
source under `hepta/_data`. Installed code does not borrow a checkout, cwd or HOME
resource. Real source distributions, wheels, isolated installs and native-selected
workers require separate exact-source verification. Host Python/setuptools,
JSON objects, SQLite, journaling and OS transport are still dependencies.

Full native Agent editing/persistence, module graph/build orchestration,
runtime/library coverage, durable publication/recovery, artifact lifecycle,
native-only installation and clean-machine real-project acceptance remain open.
A native primitive, removed dependency or passing bootstrap does not close those
whole-product obligations. No production/default activation follows from this
reference document.

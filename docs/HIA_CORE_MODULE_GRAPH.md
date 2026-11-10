# HIA Core module graph — explicit development candidate

This is a new Core workspace path, not the frozen/removed high-level Hepta
module/package resolver. `core_module_graph.hiaasm` owns identifier spelling,
duplicate modules/local definitions, alias collisions, export identity and
privacy, imported/local call resolution, entry selection and stable
dependency-first order. Every declared module and import is checked, including
unused ones. Cyclic imports, self-imports and re-exported aliases are refused;
an export names a local definition only. Function names may repeat in different
modules. HIA resolves exact original ASCII bytes, not host-assigned name hashes.

## Closed inline workspace

The document has exactly `schema`, `entry` and `modules`; schema is
`hepta.hia.core-workspace.v1`, entry is a module name, and modules is an ordered
list of objects with exactly:

- `core`: primitive Core with exactly `schema`, `module`, `functions`.
- `imports`: list of `{alias, module, symbol}` objects.
- `exports`: ordered list of local function names visible to importers.

All modules use the same existing primitive Core feature version. Module exports
are not external ABI declarations: imported internal functions may carry borrowed
resources. Only entry-module exports become public scalar exports of the linked
Core. Whole-Core admission checks every linked definition, including unused
ones, all function signatures, effects, SSA/CFG/resource flow, recursion and v8
returned-loan interfaces. Native name resolution never waives this check.

The host captures one bounded detached JSON snapshot, serializes structural
facts, copies definitions and substitutes HIA-returned function indexes. There
is no Python name resolver/topological algorithm or old-policy fallback. The
host still owns JSON framing, Core materialization/verification, metadata and
filesystem/process/build custody. These are explicit unfinished native boundaries.

Linked definitions currently use generated `fN` symbols, described by the
`function_names` receipt. Original entry export spelling is not yet preserved
as an external C ABI name; external ABI-name compatibility remains OPEN.

```sh
python -B -m tools.build_hia_core_module_graph --compiler /qualified/B3.image.bin \
  --cold-report /qualified/cold.json --output /new/module-graph
python -B -m tools.compile_hia_core_workspace --source workspace.json \
  --graph-manifest /new/module-graph/manifest.json \
  --frontend-manifest /qualified/core-json-frontend/manifest.json \
  --compiler /qualified/B3.image.bin --output /new/object --output-profile elf
```

The build tool admits the original eleven cold checks and all three exact
compiler generation hashes. The native Core JSON frontend requires v8 and
explicit ELF mode for public exports; older Core documents can be linked and
checked, but are not silently upgraded or relabeled native-compiled. The
workspace compiler emits a native object, not a complete package/install. It
never strips exports to make an incompatible flat/exec request pass. Existing
Core/compiler limits remain unchanged; unsupported nominal types remain OPEN.

## Fact/result ABI

Input, at most 8 MiB, starts with ten little-endian u64 words: `HIAMOD01`,
module/function/import/call/export counts, string-byte count, entry offset/length
and zero. Modules and definitions have 32-byte rows, imports 56-byte rows,
calls and exports 24-byte rows. Row fields are:

- Module: name offset/length, first function, function count.
- Definition: owning module, name offset/length, zero.
- Import: owning module, alias offset/length, target module offset/length,
  target function offset/length.
- Call: caller definition index, callee name offset/length.
- Export: owning module, name offset/length.

The string blob follows all rows. Name offsets are relative to that blob.
HIA validates exact length, all ranges/partitions/owners, nonwrapping profile
counts, names and reserved fields before policy traversal. Names match the
existing Core ASCII identifier grammar, including its reserved `__hia_` prefix.
Bounds are 1024 modules, 1024 total definitions, 4096 imports, 16384 calls and
1024 exports, within the original 8 MiB input envelope.

Output is `64 + 8*(modules+imports+calls+exports)` bytes. Its eight u64 header
words are `HIAMOR01`, module/function/import/call/export counts, entry module
index and zero. Arrays then contain ordered module indexes, resolved definition
indexes for imports and calls, and public export definition indexes. Non-entry
module exports have all-ones sentinels. Private scratch adds eight bytes per
function and module; HIA initializes it even when dirty. No output byte changes
before all admission, visibility and cycle checks succeed. The local immutable
native image is trusted executable code, not an untrusted machine-code sandbox.

`0xffffffff` refuses malformed facts/names, `0xfffffffe` short buffers;
`0xfffffffd/fc/fb` duplicate modules/functions/aliases;
`0xfffffffa/f9/f8` missing imported module/function/entry;
`0xfffffff7/f6/f5` missing/duplicate/private exports;
`0xfffffff2/f1` unresolved calls/import cycles. Workspace invocation never
silently substitutes another implementation on refusal.

Dependency ordering keeps native incoming-degree counters and decrements them
after choosing each dependency. Stable declaration order breaks ties. This
avoids repeated whole-graph scans for every tentative node: ordering takes
O(M*M + M*I), with unchanged scratch capacity. Regression witnesses exercise
the full 1024-module reverse chain with both 1023 and 4096 imports, under the
original ten-second child CPU limit, comparing every result byte. No timeout
or admitted graph bound is increased to accommodate the algorithm.

## Qualification boundary

Independent Core VM execution compares every byte of a hand-authored two-module
packet/result before native compilation. Native tests cover real projects with
high-level imports forbidden, shuffled DAGs, all policy refusals, malformed fact
canaries, short buffers, private concurrent calls, resource leak rejection and
unchanged returned-loan obligations. Actual original/modified projects proceed
through the native JSON frontend, compiler, HIA ELF linker and kernel execution
without a foreign payload resolver, compiler, assembler or linker after build.
These finite observations do not establish all-input refinement, source-only
whole-toolchain bootstrap, other platforms or clean-machine native-only release.

Nominal type linking, filesystem modules/package locks, incremental build,
native Core admission, native-only workspace entry and installation/lifecycle
are still required and OPEN. No default, service or legacy removal is implied.

# Explicit u32 entry-layout gate — authored, not executed

This package supplies one executable, finite gate with the original 20 check predicates and order. No product, compiler, VM, gate or CI run has been performed while authoring it. Only the necessary original artifact input extraction has run.

## Exact source lineage and applicability

The selected source is the frozen 3,180-file tree `4c62be4ed66ff107fa6f88c6131313a354868bd9`: the actual R19 `d15d7a476fc3f711b2729236e84b7a9573da7a3d` tree's 3,175 files, unchanged, plus the five explicitly authored u32 source paths. It is not the later R20 3,177-file candidate. The actual hosted u32 5,052-check qualification used this same 3,180-file tree. The complete actual source manifest is copied as metadata; no second source tree is made.

The original `tools.hia_selfhost_names.qualify_entry_layout` tests declaration ordering, fixed-point reproduction, canonical reproduction, actual executable reproduction and two existing owned-resource cases. These operations depend on the compiler byte ABI and the same supported Core source grammar, not on the ordinary immediate encoding being selected. The u32 source retains that grammar/ABI. The unchanged mutation algorithm applied to the actual canonical source is also bound to the actual M3 source. Applying this unchanged finite gate to explicit u32 B3/M3 is therefore meaningful, but its result is a separately named u32 entry-layout result.

The function has exactly three reversible changes: rename it, add a keyword-only source path, and read that path instead of importing ordinary `SOURCE`. The rest of its complete bytes and AST are preserved. `_construct_reordered_blocks` and all original callees remain the frozen definitions. No original `SOURCE` is rebound. The original unittest method is recorded verbatim as provenance; its ordinary full-qualification fixture is not executed or claimed here.

## Original complete inventory

The four combinations are `original`/`modified` × `last`/`middle`. Here the historical label `original` means the unmutated **u32** compiler, not the ordinary encoding. For each combination the original check keys are:

1. `flat-fixed-point`
2. `canonical-reproduction`
3. `executable-fixed-point`
4. `resource-queued-owner-and-local-loan`
5. `resource-queued-chain-move-drop`

`EXPECTED-IDS.json` contains all complete names, ordered compile/invoke/link/ELF labels and the original test ID. Success requires exactly 20 boolean checks, all true, four references, eight reference results, and the unchanged original false whole/refinement flags. The call journal requires exactly 24 `compile_stage` calls, 32 loader invocations (24 compiles plus eight resource runs), eight GNU-ld calls, four executable reproduction calls and the one original mutation call. All eight VM resource references must finish before the first native compilation.

| Boundary | Retained limit |
|---|---|
| Entire gate, including all references and observations | One owner, 180 seconds plus 3 seconds cleanup |
| Each reference VM | Original default 1,000,000 steps; no keyword override |
| Each compiler/resource child | Original 20-second subprocess timeout; 10 CPU seconds |
| Each GNU-ld child | Original 20-second timeout |
| Each executable reproduction owner | Original 15 seconds plus 3 seconds cleanup |
| Source/output/workspace spans | Original maximum 1 MiB each; resource cases retain their smaller original extents |
| Loader other limits | Original 256 MiB address space, 8 MiB stack, 16 MiB file size, 32 FDs; original code unchanged |

The original loader's linked-image admission remains unchanged; successful compiler-produced images are still bounded by the original 1 MiB compile output admission. No limit is raised or rewritten.

## Actual B3/M3 input custody

Inputs come from original run `43579403463`, artifact `14108215158`, exact original ZIP 1,270,286,664 bytes, SHA-256 `f318593523cc6294e9507aae9ef351d64231a2ead829d325e2e563a96176fb02`. The earlier full readback validated all 4,945 ZIP members and the full 3,180-file source tree.

This extraction decoded only raw span 1 using a single 128 MiB cache. It retained 18 necessary files / 4,359,489 bytes: B3/M3 images, input sources, complete 1 MiB outputs, requests, receipts, stdout/stderr and before/after frame metadata. Each member is checked against the actual stored-member local header/data descriptor, CRC, SHA-256, Git identity and original NODE file mode. The full actual output prefix is compared byte for byte to each image. Original files and all eleven custody ZIPs remain untouched.

| Input | Bytes | SHA-256 |
|---|---:|---|
| B3 | 658,860 | `56cddd318fbdd7cd269c103fa70c8061d43a3bf9130e877961a5b8af2078c764` |
| M3 | 658,860 | `9e3b554aee6b819b2764e5018605a00790b2863014c75f4b6c4a2fe217073718` |

The prior complete six-frame custody proof remains authoritative for the original generation frames not re-extracted here. These existing images are development inputs. They do not become matching-current-source cold inputs merely because their bytes and source provenance are checked.

## Physical observations and failures

The existing private full-frame loader is copied byte for byte; removing its three previously reviewed observer insertions recovers the whole original loader. The original `invoke`, `compile_stage`, VM, tool, ELF and owner function bodies are unmodified. The only temporary product binding is the explicit private `CHILD` capture path, restored after the attempt. The two existing runtime-bridge definitions are copied exactly; this gate reaches only four original CLI launch sites. They add the pinned libpython directory to fresh child/supervisor environment dictionaries while preserving original argv, five original environment keys, request, result, 15+3 budget and owner body.

All 32 loader calls retain real source/output/workspace before and after bytes and metadata, full original requests, stdout, stderr, receipts, images and image-prefix checks. The eight VM calls retain immutable input bytes and complete actual returns, without adding a VM call or changing fuel. The four actual ELF execs retain original stdin/stdout/stderr and owner records. Their internal workspaces are **not** observed; six-buffer claims apply only to the 32 loader calls.

The journal records starts before delegation and actual return/exception stops. Partial timeout stdout/stderr and any real pre-call frames remain. A trap, kill, absent receipt, missing after-frame, incomplete cleanup or changed input cannot be turned into a synthetic normal-return witness. There is no automatic retry or temporary-directory deletion. A final full raw inventory is created after the owner has cleaned up. Its own manifest is explicitly outside its self-inventory. A custody failure prevents a successful launcher exit without rewriting the original gate observation.

The original complete source bytes/modes and inode tuples are checked before/after in both parent and child. Runtime/control/input/tool identities are read again. No hardlink, shared source write, complete ZIP rebuild or source-copy operation is part of execution. A 384 MiB free-space preflight reserves a conservative 256 MiB raw allowance plus 128 MiB margin; this is a storage check, not a changed product budget.

## Execution boundary

`REVIEWED-COMMAND-INTENT.json` gives the exact argv, complete clean environment and plan SHA. The runtime is the previously observed CPython 3.14.4 executable and pinned library. Execution must wait for Root's separate approval and exclusive product slot. There is only one planned output directory, and an existing directory is refused.

This gate does not run ordinary-encoding qualification, source-only new current-cold replay, all original Native tests, R8 integration, roundtrip aggregate qualification, installation or default-provider promotion. The frozen R19-derived source lineage remains explicit. Neither the earlier 5,052-check result nor a future 20-check result is a proof of the whole language or stack.

# Private R8 retained controls — authoring R2

This package is prepared for review. It has executed **zero oracle restorations, zero HIA generators, zero compiles, zero Native calls, zero VMs and zero CI runs**. Static parsing, complete byte inverses and metadata reads are the only new observations. Root must authorize the independent oracle restore and the product sequence separately.

The executable controls are in `/tmp/hia-u32-r8-controls-r2-dda7`. R1 remains intact in `/tmp/hia-u32-r8-controls-r1-dda7`. The storage successor has full before/after records in `/tmp/hia-u32-r8-controls-storage-r2-dda7`. No frozen production file is modified.

## Actual predecessor and source lineage

The actual R8 size/pack predecessor produced the 549,866-byte image with SHA-256 `c9f328a1c748243292d0eebfbf27c49da0ef83155ca7dbb0dc621d5e488a081a` and the 1,044,480-byte ELF with SHA-256 `54d596ee04320d3c8cc02c73fef5ad2fb0c06b9516363279cf1a5aed5e3d159f`. Root verified its full frames, limits, guards and cleanup; its ELF remains mode 0644 and has never been executed. Its result is size/pack only.

The next controls use the complete frozen **3,180-file** tree `4c62be4ed66ff107fa6f88c6131313a354868bd9` at `/workspace/scratch/dda74a4fae35/v121-selfhost-small-constant-r1/candidate/source`. This is the actual R19 3,175-file lineage plus the five explicit u32 files. It is not R20's 3,177-file tree. The exact R8 HIA source and its original generator are separately pinned inputs. The generator's dependency ROOT is explicitly projected to the same frozen 3,180-file tree, solely for the retained diagnostic's function labels; every original generator function body remains byte-identical.

The original ordinary compiler is used only for the original two observer build calls. The original extended profile compiler is used only for the original four last-byte fault build/pack calls. `qualify_hia_selfhost.SOURCE` is never rebound. No ordinary-encoding, matching-current-cold, public-profile or whole-Native result follows from this private package.

## Exact original oracle restoration

The complete old R4 oracle domain used by the 162-case body contains **496 files / 704,110,777 bytes**. Of these, 136 `native/OBSERVATION.json` files were retired from the expanded tree; they contain **578,353,224 bytes**. The other 360 inputs remain at their explicitly declared original paths.

The missing files are present in the frozen original archive:

- File: `/workspace/scratch/dda74a4fae35/v98-compact-R1-R5-custody-r1/attempt-r1/COMPLETE-PRESENT-RAW.tar.gz`
- Compressed bytes: 27,221,867.
- SHA-256: `1d133292058042e3002d1fa9a91f34ba791a2da6cf250361517225b0adbe6cb8`.
- Git blob: `f5f2d7b9bcb2aa3fe97c4980aa5d15bc022eeb6a`.
- Complete original manifest: Git blob `dddd66283c27c846e7c75de35fb82f347ca38317`.

`ORACLE-RESTORE-PLAN.json` lists every required identity and all 136 selected original members. `restore_oracles.py` streams the original gzip/tar, validates all 2,396 CAS objects and 2,397 archive nodes, checks the full gzip CRC, and writes only the selected original observations to the **fixed independent root** `/workspace/scratch/dda74a4fae35/u32-r8-original-oracles-20261114-r1`. It does not write to the retired locations, create hardlinks, or copy a product source tree or a second archive. It retains failed and partial writes. There is no automatic retry.

The two groups with retired observations use explicit, frozen path-map entries. The 26 observations in `compact-semantic-r1` remain at their declared original locations. The selection never tests file existence to choose a fallback. Removing the literal path/import projections recovers the entire old control script byte for byte. The old wrong-expectation fixture and all old failures remain in the original oracle and in the unchanged assertions.

The original archive's two historical missing items are still missing. This restoration neither reconstructs the unwritten first R1 third-VM buffers nor invents the overwritten first generated HIA file.

## Original phases and limits

Every group has one original 180-second qualification owner and a 3-second cleanup window. The separate restoration has its own 180+3 owner but runs no product. The product driver stops at the first failed/incomplete group, preserves its result and all partials, and marks later groups not started. No failed group is automatically repeated.

| Phase | Original scope preserved | Actual calls at the maximum successful path |
| --- | --- | --- |
| Public R5 refusal | Real original controller/startup/component admission rejects the R8 source with `E_HIA_LINUX_FILE_ROUNDTRIP_COMPONENT` | 0 Native, 0 VM; no provider call |
| Native replay | All 162 old inputs, old return values, complete S/O/W, canaries, IO and forbidden-module assertions | 162 Native entries |
| Same-input edge | Original diagnostic, exact input/preimages, full state and step accounting | 1 extra Native entry and 1 VM |
| Original semantic six | Exact original order; five new VMs plus the exact newly observed R8 edge result | 6 logical cases, 5 additional VMs |
| Kernel 130 | All original ordered file inputs, stdout, stderr, return codes and original oracle comparisons | 130 direct ELF execs |
| Observer build | Original pure-HIA postreturn observer, actual unchanged payload comparisons | 2 original compile/pack calls |
| Pipeline seven | Original seven providers/scenarios, shared fuel and actual complete F/O/W equality | 7 VMs, 6 postreturn-observed kernel execs |
| Last-byte two | Original C1/C2 last-byte injection, equal lengths, five residents, return 72/phase 7/no stdout and complete F/O/W | 2 VMs, 2 kernel execs, 4 original compile/pack calls |

Each native or compile child retains 20 seconds, 10 CPU seconds, 256 MiB address space, 8 MiB stack, and the original file/descriptor limits. Compile spans remain 1 MiB. Each semantic VM keeps 10,000,000 steps, 1 MiB heap and depth 128. Each pipeline/fault VM keeps the original shared 10,000,000 steps, 16 MiB heap and depth 256. The file span remains 8 MiB+1; output and workspace remain 1 MiB each. These values are not pooled or enlarged across groups.

The six-case report reuses only the **new, same-R8** edge observation after checking its actual image, HIA source, input, preimages, full buffers and terminal record. It does not reuse the historical R5 VM result. Historical R5's six logical outcomes remain 5 PASS and one cross-target fuel failure.

## Public and private reference boundary

The public `roundtrip.v2` source table is unchanged. Its semantic pin is still R5. A concrete new guard calls the original public `execute_linux_file_roundtrip` path with the real controller and startup object and requires the original component refusal before any provider or VM execution.

The private reference has the explicit name `hepta.test-only.u32-r8-roundtrip-reference.v1`. Its `_checked_components` and `execute_linux_file_roundtrip` functions are copied in their entirety, byte for byte. Only the independent private semantic source pin is R8. The controller verification, exact tuple/bytes shape, ordered assembly, startup checks, limits, argument copy, extents, loans, exception order, and call to the **original** `_execute` remain intact.

The original `_execute` does not re-read the public component pin. Its returned report still carries the old public PROFILE text because that function is unchanged. That field is an inherited representation tag, **not public R5 admission or qualification for R8**. Both the wrapper and final result explicitly identify the private reference scope.

## Full observations and failure custody

The original standalone Native observer is unchanged. Its three actual shared spans, D3×64 canaries, requests, complete hex reports, stdout/stderr and child results are retained. The added readback records all six logical before/after buffers, including untouched tails, without rerunning the call.

The six standalone VMs keep the original `_Owner.data` writes in the original `finally` blocks. Their exact input/preimages and all actual after buffers are indexed separately, including budget/trap results. The pipeline/fault reference observes immutable input arguments and the actual returned or raised VM report after the unchanged execution path. Observation failure never replaces an already raised original exception; it is independently recorded and blocks qualification. No second VM is run for custody.

The six observer/fault compile calls use the already verified entry20 frame observer. Removing its three observation insertions recovers the entire original loader byte for byte. The original request, 20-second `invoke`, 10-CPU child, stdout, receipt and complete 1 MiB output are bound to the actual six frames. No ordinary SOURCE substitution occurs.

Kernel F/O/W records are the original actual postreturn BSS observations. No native pre-call memory capture or invented canary between adjacent production buffers is claimed. All stderr, including SyntaxWarnings, remains unfiltered.

Full 3,180-file byte/mode and seven-stat snapshots, fixed controls, current images, runtime and every consumed oracle are checked before and after each group. The owner includes that group's checks and observation IO within the original 180+3 limits.

## Storage and execution readiness

The fixed workspace oracle requires 578,670,592 allocated file bytes at 4 KiB blocks, plus 8 MiB metadata allowance and 128 MiB remaining space: **721,276,928 free bytes before restoration**. The restoration separately requires **3,355,443,200 free bytes in shm**, preserving the 3 GiB product entry floor plus 128 MiB reserved for the other planned source/materials. Both are checked on their actual filesystems. There is no dynamic relocation.

The product output is fixed at `/dev/shm/hia-u32-r8-controls-r1-dda7`. Its fresh entry check remains **3 GiB**. The exact original request extents and old observation lengths already imply 1,043,271,132 bytes for the successful 162-case Native body alone. The complete new successful-path evidence is conservatively planned at **2 GiB**, including the other groups, full frames, source snapshots and binding reports. This is a planning estimate, not a new output cap, a truncation rule or permission to drop failure evidence. An output/storage failure remains a failure with its partials preserved.

`COMMAND-INTENT.json` contains the product argv. The restoration uses the same fixed actual 3.14.4 executable and library environment, with `restore_oracles.py --plan-sha256` and the exact oracle authorization pin. Neither command has been launched. Root must inspect the concrete package and allocate its next execution window before either command is used.

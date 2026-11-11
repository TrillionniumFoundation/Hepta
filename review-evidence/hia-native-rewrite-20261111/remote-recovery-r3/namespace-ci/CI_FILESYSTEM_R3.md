# Independent namespace FS r3 CI handoff

This is a NEW, not-yet-executed GitHub CI revision. It does not resolve the original ROG prepare request, inherit any ROG tests, or qualify the ordinary AgentStore.

## Publish these three adjacent files

| Filename | Git blob | Bytes | SHA256 |
|---|---|---:|---|
| namespace-filesystem-r3-ci.py | 7b922d4e210960eab3a55be61b0b4869557ea602 | 16543 | 21496a61c07c8bd6a8d118a0f79f1070044f7bb5d0b54a3f846b57aa7ba42028 |
| namespace-filesystem-r3-validate.py | 105d4a8bd7a05ee37052dada24ddde8dc487710d | 11790 | 02460a84978d0d218506b0a6b21def854ca070de63624486e284012c4a65f3c0 |
| namespace-filesystem-r3-input.json | 4a9ac654e496f2bbe2e4067cbec5129ee81b45dc | 73403 | 2a5010afba63239e641af4ddad21cb8799baba857131e443f1aa48901808275d |

The launcher pins common module Git blob b3637486fbd73dccc91051de05873daff78ed630 via HIA_CI_COMMON. The common module must be inside the current GITHUB_WORKSPACE checkout, as must the validator and input bundle. HIA_CI_OUTPUT is a new, unique directory. Run Python 3.12.14 with:

    python -B path/to/namespace-filesystem-r3-ci.py

The default input/validator paths are adjacent to the launcher. Explicit --input-bundle and --validator options are supported and remain hash-pinned.

## Dependencies and gates

- Linux x86-64, CPython exactly 3.12.14, Unicode exactly 15.0.0.
- z3-solver exactly 4.15.4.0, as required by the exact reference source. The verified official wheel z3_solver-4.15.4.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl has SHA256 7e103a6f203f505b8b8b8e5c931cc407c95b61556512d4921c1ddc0b3f41b08e and size 29,268,352 B. Do not borrow another Python minor version's site-packages.
- Standard library unittest, ctypes, mmap/native executable mapping and ordinary Git. No pytest, Rust/NDU prerequisite, or rpds package is required by these component tests.
- Common prepare() restores and fully verifies exact a3c source (3350 blobs) and exact 0ef reference (2798 blobs), and restores the original B3: 669556 B, SHA256 35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b.
- Common preparation uses one allowed CPU, 1 GiB parent address space, and core limit0. The compiler child still uses the reference's original 10 CPU seconds, 20 wall seconds, 256 MiB address space, 1 MiB output and 1 MiB workspace. No cold qualification or 180-second cold gate is run or replaced here.
- Current CI SQLite version/sourceid is recorded as environment identity only. It is not substituted for, or attributed to, ROG's SQLite3.46.1 or any earlier whole-SQL result.

## Executed workflow once launched

1. Restore the nine already-published namespace archives from exact a3c. Verify every outer SHA/Git blob/size, all646 regular member bytes, mode and readback, totaling67455469 raw bytes. These old artifacts are custody inputs only.
2. Materialize exact VALUES and ObjectBuilder sources plus the complete ten-table/31-operation ABI. Materialize the new FS-r3 source, documentation and corrected14-group test source from the pinned input bundle.
3. Generate HIA with the frozen0ef authoring provider. Preserve generated source, full source/provider pins and profile. Existing128 functions/1536 total blocks/256 blocks per function/8192 ops/16 block params remain enforced.
4. Run all14 new VM groups with complete raw invocation ledger. A VM failure prevents a B3 compile; failure logs and counts remain original.
5. Compile the new source with the real retained B3 under the original child limits and retain all request/input/output/receipt/stdout/stderr artifacts.
6. Load the actual produced image and replay all14 groups. Each invocation compares return, every output byte, every persistent workspace byte, unchanged source and all native guard bytes. Synthetic workspace mutations and syscall ACKs are explicitly labelled as private test controls. Actual native-entry counts are observed, never pre-filled.
7. Require nonempty loaded IDs, exact executed counts and zero errors/failures/skips/expected failures/unexpected successes. Verify source/provider/context/image pins after use.
8. Common finish() verifies the source/reference before/after and creates a complete byte/mode-verified raw artifact. A failing step remains FAIL.

The new current kernel is Git blob26d7c3b8fe64730b585260e84754331221eb383c, unchanged from the source-only checkpoint. The original unexecuted test blob04d5c2bf10e5b6f0afb697265d1b071fd3d05c5b was corrected to d941bd82b2de44450515c9952a79e1198c773132: the synthetic near-u64 call-counter control now gives its independent source lease a representable nonzero u64. The old fixture would have raised struct.error before entering HIA. All14 groups and kernel assertions remain. This was a static correction, not an observed execution failure.

## Remaining scope

This test executes the complete HIA filesystem-continuation owner, including22 primitive selections, FD0/UID0, dynamic slots beyond16, close/EINTR, growth, replay, raw result extents, permanent refusal and u64 boundaries. Its syscall replies are explicit private fixtures. It does not execute the future fixed syscall carrier, establish root permission policy, fence a real legacy writer, migrate SQLite, or activate an ordinary native AgentStore. Those remain the next implementation stages.

The former FS r2 full archive and complete rows-r2 archive are currently inaccessible in the recovered inputs, not assumed lost. Their old observation counts are not replayable proof for this new revision. No source or old evidence is deleted.

# Local stored-slice native qualification

`d3d0927.json` retains the complete new Linux x86-64 LLVM/C/Rust execution
from this isolated worktree. Its source, compiler and qualifier identities
were independently replayed after implementation commit
`d3d09275b2c9824741685a80f363bbf14bcd6b4c`; no earlier-environment report was
substituted. The raw JSON bytes are unchanged:

- SHA-256: `871ae9e4e230d4d89dfffbb50de300dd0c89aa8fd9bf447c92749d711a133f49`
- Bytes: 463866
- Compiler tree: `b7065a17b5a4c28c1bedec719721780b8b77e3291b8f876b741560716130a28c`
- Status: `passed` under `hepta.llvm-local-views-qualification.v1`

Each of the three backends executed all 140 calls and observed 110
allocations, 110 releases, 30 actual allocator refusals and zero remaining
live allocations after every call. LLVM/C/Rust each aborted a stored-view
out-of-bounds child. The separately compiled LLVM owner-release omission
was caught at case 20: two allocations, zero releases, two live allocations,
exit 86. Fourteen invalid/unsupported source candidates published no native
object, and three changed LLVM/source identities failed before Clang.

The implementation and existing affected suites completed 95 tests with
zero skips in 17.758 seconds, including 25 deliberate report mutations.
The modules were `test_llvm_local_views`, `test_llvm_owned_backend`,
`test_c_backend`, `test_resource_views`, `test_borrowed_storage`,
`test_owned_drop_plan`, and `test_owned_drop_llvm`. The explicit unittest
loader added this checkout's `tests` directory to `sys.path`; it did not
modify a shared package or substitute tests from another checkout.

The source-facing pipeline's native Rust reference, exact source/resource
replay, verified ordinary-owner Drop plans, target-layout probes and safe
artifact publication remain enabled. This is the local v4 single-u8-slice
profile. Labelled v5 records, stored-view parameters/returns, mixed generic
lifetimes and arbitrary interprocedural regions remain unsupported here.

Reproduction on this exact source/compiler tree:

```sh
RUSTC=/tmp/hepta-ai-rust-1.90.0/bin/rustc \
python3 -m tools.qualify_llvm_local_views --clang /usr/lib/llvm-20/bin/clang \
    --cc gcc --output /tmp/new-local-views.json
```

`validate_report` can check this retained report without compiling or
executing native programs, as long as its recorded compiler/source paths
and hashes still match. A final integrated release must produce a fresh
receipt on its own source tree. The native binaries were temporary; their
complete identities and execution observations remain in the report.
No performance protocol or benchmark workload was run for this change.

# Source-bound local stored views in LLVM and C

The existing Resource IR v4 local single-slice record profile now reaches
the independent LLVM and C backends. This implementation uses the existing
Hepta parser, checker, resource lowerer and resource verifier. It introduces
no alternate source syntax or second loan checker.

## Closed native scope

Records contain exactly one `read 'a [u8]` or `mut 'a [u8]` field and one
declared lifetime. Their values have inferred local regions. Shared records
copy; exclusive records move and require explicit `drop(move view)`. The
existing resource verifier checks owner conflicts, permission, branch joins,
loop backedges, and each `bind_view`, `copy_view`, `move_view`, `end_view` and
`use_view`. Shared loans end at the represented lexical scope.

```hepta
struct Bytes<'a> { data: read 'a [u8] }
struct Edit<'a> { data: mut 'a [u8] }

if true {
    let initial = Edit { data: mut owner };
    let mut edit = move initial;
    edit.data[0] = 7;
    drop(move edit);
    let first = Bytes { data: read owner };
    let copied = first;
    assert(copied.data[0] == first.data[0]);
}
drop(move owner);
```

LLVM stores a pointer/length descriptor in the record. Shared copying copies
the descriptor. Exclusive moves clear the moved-from slot using existing
owned-move lowering. Ending a view is a no-release helper: the view does not
own the allocation. Ordinary owner destruction still consumes the existing
verified Resource IR Drop plan and checks field layout and child ownership.
The new path cannot disable that check for a program which also uses views.

C uses the same descriptor shape with `const uint8_t *` for shared access
and `uint8_t *` for exclusive access. Resource verification is mandatory even
when a program uses only shared local views. LLVM does not use Rust or C
machine code; C emits its implementation independently. The native layout
admission helper checks source/graph agreement and exact v4 descriptors.

Explicitly unsupported are stored-view parameters/returns, named function
regions, nesting, reference reborrowing into calls, mixed lifetime/type
parameters, arbitrary pointees, and multiple fields. The newer Resource IR
v5 labelled-view profile is not silently admitted; its additional Copy
fields, including unused declarations, remain outside this native increment.
Immediate borrowed parameters/returns and ordinary `Owned` generics retain
their existing separate support. A generic owner can coexist with a local
view without implying a general generic-lifetime implementation.

## Source and publication gates

Use the existing source-facing compiler:

```sh
RUSTC=/path/to/rustc python3 -m hepta.llvm_owned_pipeline \
    examples/llvm_local_views/main.hepta --kind object \
    --clang /path/to/clang-20 --output /new/path/local-views.o
```

It still requires fresh native Rust metadata validation and exact resource
verification. The native API regenerates LLVM and all semantic/resource
identities before Clang is invoked. Existing target-layout probes, object/ELF
guards, staged artifact checks, no-replace publication, and post-publication
source/compiler/inode checks are unchanged. Rehashing altered LLVM does not
bind it to the original source. Renaming a view can preserve every emitted
LLVM instruction and still invalidates the old source/resource identity.

The generic frontend `borrowed_storage` capability remains conservative.
Its general C/independent-resource flags are not changed to imply that all
stored lifetime forms are supported. The precise native scope is the v4
`stored_views` verification descriptor and this dedicated qualification.
The executable target is Linux x86-64 with ordinary scalar C exports only.
Internal owner/view records have no new public foreign ABI.

## Untimed qualification and retained evidence

```sh
RUSTC=/path/to/pinned/rustc python3 -m tools.qualify_llvm_local_views \
    --clang /path/to/clang-20 --cc gcc --output /new/path/local-views.json
```

The output must be new. `qualify(output, rustc=..., clang=..., cc=...)`
returns and saves the full report. `validate_report(report)` replays current
source and validates retained observations without recompiling or rerunning
native programs, making it suitable for the release evidence collector.

The fixed domain has **140 calls per backend**. The same source is compiled
into an independent LLVM object, a C object with UBSan, and an instrumented
Rust reference library. Each native caller records exact result, allocation
attempts, allocations, frees, actual refusals and live allocations after
every call. The 420 observations must match a separate Python oracle.

The source combines generic `Box<Buffer<u8>>`, an `Owned` forwarding function,
fallible construction, post-allocation constructor rejection, exclusive-view
move and early return, shared copies, disjoint fields, loop-local views, and
a second allocation while the first owner is live. The fixed oracle requires
**110 allocations, 110 releases, 30 refusals and zero live allocations per
backend**. Every fault attempt is followed by a normal call, so recovery is
observed. Views must add neither allocations nor releases.

Each backend separately executes an out-of-bounds access through a copied
stored view and must abort. The existing abort-on-panic policy does not
promise cleanup on abort. A genuinely compiled wrong LLVM module, with
owner `free` removed outside the production source gate, must fail the
observer on the first allocating call: two allocations, no frees, two live
allocations, exit 86. This negative control is not accepted Hepta code.

Seven alias/owner-move candidates are independently rejected by Resource IR
and by actual Rust metadata validation; three affine/read-only violations
fail the frontend. Four unsupported lifetime shapes fail the resource or
native-layout boundary after the Rust reference accepts them. No such
candidate publishes a native object. Three rehashed/native identity
mutations must fail before Clang is called.

The validator requires the exact source graph, compiler inputs, generated
LLVM/C/Rust identities, target-layout probe and fixed oracle. Native library,
link output and each executed binary are bound by recorded path/hash/size.
Complete raw stdout, all 140 rows on each backend, actual bounds aborts,
negative-source inventories and the native leak control are mandatory.
Deleting a backend/case, broadening a claim, changing source/graph or binary
identity, or fabricating a leak control invalidates the report. Successful
claims are set only after execution completes, and failed reports retain
the already collected command and bounded output evidence.

This is consistency validation of retained local evidence, not authentication
of arbitrary third-party reports. Temporary binaries are deleted after their
hashes and observations are retained. Finite tests do not prove complete
language soundness, source/native refinement or general lifetime support.
No performance protocol or benchmark source is modified or executed.

On the isolated `bdb8690` descendant implementation, 95 targeted tests
completed with zero skips, covering the new 11 tests plus the existing
LLVM owned, C backend, Resource IR v4/v5, borrowed-storage and native Drop
plan suites. The new validator mutation test rejects 25 changes to scope,
denominators, source/graph/native identities, raw outputs and negative
controls without rerunning native tools. The qualification is retained as a
complete source-bound JSON report; an integrated release must generate its
own receipt against the final integrated compiler and source paths.

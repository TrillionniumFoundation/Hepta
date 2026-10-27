# Resource composition candidate — acceptance boundary

This increment starts from published `bdb8690`, the evidence-bearing HIA
seven-stage candidate, itself a descendant of the source-language candidate
`a04ae789`. It preserves both formats' explicit admission rules. It does not
reinterpret a historical pass as a qualification of a modified compiler.

## The user's seven stages

| Stage | Executable increment and acceptance evidence | Remaining acceptance boundary |
| --- | --- | --- |
| 1. Unified semantics and candidate | Shared source checker/canonical semantics; independently authored HIA has its explicit Core verifier; both run on the same frozen tree. `release_check.py` includes every new resource/migration gate, and `qualify_hia_unified.py` retains the HIA gates. | The source/HIA profiles are distinct and documented. No unsupported construct may silently use another backend. Final acceptance requires the actual complete unchanged-source reports. |
| 2. Safe resource core | Existing owned ADTs, partial moves, Result and resource CFG; local views now execute through LLVM/C; task-tree cancellation wakes worker-owned reactors with four-dimensional shared I/O admission and failure rollback. | General escaping regions, trait/lifetime combinations, full process allocator/stack/FFI accounting, arbitrary scheduling and complete soundness/refinement proofs. |
| 3. Practical C migration | Existing real compilation databases, complete active declaration inventories, two upstream scalar modules, complete Ring-Buffer state, plus finite multi-configuration modules. | Arbitrary upstream modules/configurations, undocumented ownership, macro/inline/layout forms outside admitted profiles, cross-module resource inference and measured total human migration cost. |
| 4. Broad C++ library access | Existing object/borrow/constructor/template bridges and two actual nlohmann/json versions. | Bridges retain foreign implementation/assumptions; three foreign noexcept destructor failures remain aborts. More library families and upgrade histories are required. |
| 5. Expanded safe C++ migration | New native-AST translation of two-to-four-resource composition: actual constructor/method/control-flow lowering, selected integer errors, member moves, reverse cleanup and destruction. Three different programs execute in original C++, generated Rust, generated C and independent LLVM. | The exclusive-byte leaf protocol and composite grammar remain bounded. Custom destructors/allocators, inheritance/virtual dispatch, arbitrary templates, retained pointers and general exception behavior remain rejected. |
| 6. Independent native backend | v4 local byte-slice views reach LLVM and C; fresh actual multi-resource migration output reaches independent LLVM without original C++ or generated Rust/C machine-code input. | General effects/tasks/I/O and lifetime coverage, whole-backend refinement, target-specific execution and the unchanged performance gates. Correctness does not qualify performance. |
| 7. Agent/platform benefit | Actual host ABI matrix, finite native workload observations, QEMU and independently frozen local-model experiments with all failures/costs retained. CI now resolves the actual Rust binary and loads Ubuntu's distribution namespace profile. | Representative agent benefit has not been demonstrated. Stable current performance, total maintenance cost, long-running services, physical boards/DMA and GPU qualification remain open. |

## New production entry points

```sh
python -m hepta migrate-cpp-composed \
  examples/cpp/composed_migration/triple.cpp \
  --output /new/path/triple.hepta --clang /path/to/clang++

python -m hepta build-llvm-owned \
  examples/llvm_local_views/main.hepta \
  --output /new/path/local-views.o --kind object --clang /path/to/clang
```

Translation reports distinguish generated checked source from native execution.
The qualification tools actually compile and run the resulting implementation.
Existing output is never replaced by migration. Source/compiler changes around
publication must reject or withdraw only the newly published inode, preserving
any independent replacement.

The admitted task runtime uses `group_io_configure`, `group_io_snapshot` and
`io_attach`. See [the protocol](TASK_TREE_IO_COMPOSITION.md),
[native local-view scope](LLVM_LOCAL_VIEWS.md),
[composed C++ scope](CPP_COMPOSED_MIGRATION.md), and
[CI prerequisites](CI_NATIVE_PREREQUISITES.md).

## New mandatory release gates

`llvm_local_stored_views`, `task_io_composition`, `cpp_composed_migration` and
`cpp_composed_to_llvm` are mandatory alongside the previous 46 gates. Each
producer's exact success status is checked, followed by its strict replay and
evidence validator. A process exit alone, rehashed fabricated claim, missing
case, unsupported source or stale report cannot count as a pass. Task/I/O must
complete the fixed three repetitions. The release collector runs no actual
model study; its zero model count describes that run, not the project's
historical local-model experiments.

The full regression watchdog is 900 seconds: the published 2,023-test HIA
baseline already required 548.93 seconds before these additional mandatory
native regressions. The watchdog is separate from every benchmark threshold;
a timeout, missing terminal test count or any skipped test still fails.

The new finite oracles include real allocator refusals and recovery, byte
results, allocation/free identity and order, illegal-source rejection and
compiled incorrect implementations. These are tests of particular programs
and implementations. They do not authenticate arbitrary third-party reports,
prove arbitrary source equivalence or establish an unrestricted safety theorem.

## Qualification discipline

Commit and freeze implementation before a complete qualification. Record the
exact Git head, source hashes, actual toolchain and before/after artifacts.
Retain every failure and interrupted attempt. The LLVM performance protocols,
native workloads, two Rust baselines, sample order, sample counts and quality
thresholds remain unchanged. No favorable historical run replaces a failed
current one. New scheduling observations may diagnose uncertainty but cannot
discard a sample or change its result.

`whole_project_blockers_closed` remains false until all requested conditions
have their own evidence. Hardware access and research results cannot be
substituted by accepting a smaller denominator.

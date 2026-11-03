# Loader read admission before graph construction

Status: characterization and isolated reader experiment only. No production
loader, public API, CLI admission policy, or native profile is changed.
Baseline: #613 at `6992d6befa1b14bd7caf6f2a407b0f549891dcd4`
(tree `77ac90a4dcdae42e033ee7fab983b4e6d7061a83`).

## Reproduced gap

`python -m unittest experiments.loader_budget.test_characterization -v`
contains six passing observations of existing behavior, not six fixed defects:

1. Entry source is fully materialized before tokenization/parsing, then reread.
2. Package inventory reads an unused `.hepta` file even when it is not imported.
3. Manifest comment padding is fully read before TOML parsing.
4. Valid lock-file padding is fully read before JSON parsing. Stale lock checks
   still work; introducing a budget must not replace or bypass lock enforcement.
5. C import sidecars and in-package original headers are fully materialized.
6. `LoadedProject.unchanged()` reads an entire changed file before rejecting it.

The experimental `build_plan._protected_inputs()` graph/header size checks occur
*after* loading, so they do not bound these reads. `Prepared._assert_current()`
then reads identities and reloads the project independently. A single entry-file
stat check or a fresh budget for each reload is insufficient.

## Proposed contract

An opt-in read context must be created before package discovery and remain owned
by the entire request. Pass the same context explicitly through `load_package`,
recursive dependency loads, `verify_lock`, `package_snapshot`, `load_project`,
`LoadedProject.unchanged`, and all preparation/revalidation reloads. Never use a
global monkeypatch or mutable module singleton. Preserve default APIs until an
explicit production policy and compatibility tests are reviewed.

Charge every actual read, including repeated reads of the same path. Distinguish
per-file limits by role (source, manifest, lock, sidecar, original header) and a
single aggregate byte/read-operation budget. Inventory-only hashes should stream
through the same context instead of materializing files. In-memory source
overrides need explicit admission too; the first native profile already refuses
them. Budget exhaustion must fail closed, not downgrade locked mode or retry
without the context. Normalize failures into structured diagnostics at the API
boundary; preserve unchanged()'s boolean contract where applicable.

A size check is an optimization, not the boundary. Open the file, inspect the
opened descriptor, reject nonregular objects, then use reads limited by remaining
capacity plus at most one overflow sentinel. Files can grow after stat; reject
without reading their remainder. Opening must not wait for a FIFO writer. Bind
identity checks to bytes actually read, and retain existing path-binding and
package-race revalidation. A descriptor read does not freeze the path or make a
multi-file snapshot atomic; replacement/in-place mutation still needs validation.

Byte quotas alone do not bound graph work. Before integration also provide:

- Incremental inventory traversal with entry count and depth quotas *before*
  materializing or sorting directory listings. Keep directory-symlink rejection.
- Package count, dependency depth, module count, import depth and retained-graph
  limits, enforced before recursion/allocation. Many empty files consume work.
- Cooperative deadline checkpoints around discovery, traversal, reads, parsing,
  graph assembly and repeated qualification. The caller's one deadline cannot be
  reset by helper construction or reload.
- Separate bounded native dependency hashing and native artifact checks. Loader
  limits do not automatically cover probe-driver bytes, private snapshots,
  compiler identity, system headers or post-compile observed dependencies.
- Explicit parser/AST recursion and expansion behavior. A bounded input can still
  consume disproportionate CPU/memory. Filesystem operations can stall even with
  nonblocking regular-file opens; this is not a hard real-time or sandbox claim.

## Isolated candidate primitive

`experiments/loader_budget/prototype.py` provides a POSIX regular-file reader
with per-file bytes, cumulative actual bytes, read-operation count and bounded
chunk size. The values are experimental, not selected production quotas.
An optional checkpoint callback supports a shared cooperative deadline. Failure
makes the reader terminal. Overlapping/reentrant operations are rejected rather
than sharing a stale allowance. Streaming digest and materialized read consume the
same counters. Oversize fstat results fail before any byte read; post-stat growth
reads at most one byte beyond the remaining allowance before terminal rejection.
Successful materialization uses bounded chunks and a final join, so peak Python
memory includes both chunks and the resulting bytes, not just one quota's worth.

The primitive deliberately does not load a project, admit directory entries,
validate symlink policy, enforce deadlines on blocking syscalls, parse input,
freeze a sysroot, or authenticate foreign binaries. Do not present its tests as
an end-to-end fix. It is not imported by production or the native build plan.

Run its controls with:

```
python -m unittest experiments.loader_budget.test_prototype -v
```

Controls cover exact/empty boundaries, pre-read oversize refusal, repeated-read
charging, empty-file invocation limits, streaming digest, growth after fstat,
aggregate overflow sentinel, path replacement after open, FIFO refusal, deadline
failure cleanup, failed-open terminal state, invalid limits and reentrant rejection.

## Integration exit criteria

Before wiring the candidate into production or claiming bounded loading, cover
all six characterized read paths with instrumented read-size and allocation
assertions, including locked packages, dependencies, unused inventory files,
source overrides, C metadata, headers, and every revalidation. Add too-many-empty
files, deep directories/dependencies/imports, symlink swaps, post-stat growth,
read errors, deadline exhaustion and low remaining budget on reload. Demonstrate
that ordinary valid projects retain graph identities and stale locks still fail.
Run production module/package suites, the complete native experiment suites and
the existing x86_64/AArch64 qualification workflow against the exact published
commit. Current prototype controls alone do not satisfy these exit criteria.

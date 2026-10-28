# Complete stateful C module migration through checked record views

This opt-in migration profile translates a complete pointer-bearing C module
into a safe Hepta algorithm plus an explicit unsafe C ABI bridge. It extends
`migrate-c-project`; it does not add raw pointer operations or stored references
to the generated Hepta core, and it does not infer ownership of foreign memory.

## Qualified upstream and configuration

The frozen module is [AndersKaloer/Ring-Buffer](https://github.com/AndersKaloer/Ring-Buffer)
at commit `8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba`. The complete,
unchanged `ringbuffer.c` and `ringbuffer.h`, MIT license and upstream README are
in `tests/fixtures/c_migration/ring_buffer/`. `UPSTREAM.json` binds the exact Git
blobs, SHA-256 digests and sizes. A mismatch fails qualification.

The qualified compilation database uses C11, `-DNDEBUG` and `-funsigned-char`.
Both the original GCC build and the Clang migration capture use these exact
semantic flags. `NDEBUG` is an explicit build configuration: the upstream
assertion is disabled by its own header macro in that configuration. Debug
assertion expansions and other configurations are not silently stripped or
qualified. Plain-char signedness is retained in preprocessing and measured in
the compiler data model; it is not discarded as an optimization flag.
The native ABI probe uses semantic compiler options separately from caller
`-D`/`-U` macros: spelling `__CHAR_UNSIGNED__` in a user macro cannot change
the actual native char type. Include-path operands cannot masquerade as compiler
options. Bundles whose listed translation units have different data models,
including different plain-char signedness, are rejected after recording the
complete active declaration inventory.

This is a stateful library with nine functions: initialization/reset, single and
array queue/dequeue, peek, and three state queries. There are **22 active
project declarations**, comprising nine function definitions, nine prototypes,
one record definition, one forward declaration, and two typedefs. All of them
remain in the output inventory. Every active unsupported declaration rejects
the whole bundle even when unused. System/compiler declarations are listed
separately and are not counted as translated project code. Inactive branches
outside the captured macro configuration remain outside this denominator.

## Translation mechanism

A `hepta.c-record-views.v1` contract has exact `records` and `functions` maps.
For example, the record held by this library declares one pointer field whose
extent is the unsigned `buffer_mask` field plus one:

```json
{
  "schema": "hepta.c-record-views.v1",
  "records": {
    "ring_buffer_t": {
      "buffers": {
        "buffer": {"length_field": "buffer_mask", "add": 1}
      }
    }
  },
  "functions": {
    "ring_buffer_queue": {
      "records": {"buffer": {"access": "mut"}},
      "slices": {}
    }
  }
}
```

That fragment illustrates the schema; a complete module contract must describe
every captured function. The frozen fixture contains the complete contract.
Both migration CLIs use the [bounded contract intake](C_MIGRATION.md#contract-intake-before-compiler-work):
duplicate keys, including conflicting read/mutable access declarations, reject
before compilation. The API freezes a detached checked graph and records its
canonical identity. These are authored obligations, not inferred contracts.
The supported record has one primitive buffer pointer and primitive scalar
state. Its extent expression is an unsigned field plus zero or one. A function
may take one such record by pointer and additional primitive slice/scalar
parameters. The profile rejects by-value pointer-bearing record ABI crossings,
so the omitted pointer field can never silently change the ABI of a C value.

The translator emits a scalar-only Hepta record. A C record pointer parameter
becomes a borrowed state record plus an explicit borrowed slice. Accesses to
scalar fields and buffer elements lower from the captured Clang AST. Internal
calls pass those borrows; local C pointer cursors become checked `usize`
offsets into the same borrowed slice. Cursor advancement admits the one-past
position but never permits dereferencing it. Signed relative indexing widens
the cursor and C integer index to `i128` before addition, checks the absolute
index against the declared slice, then narrows to `usize`. Thus `p[-1]` remains
valid after a cursor advances, including from the one-past position. Negative
absolute indices, huge unsigned indices and `i64::MIN` cannot wrap into a valid
position. General `p += n` and decrement statements remain rejected.
Short-circuit `&&`/`||` preserve C
sequencing when a right-hand call changes the record. Other unsequenced
side-effectful arithmetic expressions still reject migration.

C declarations of an uninitialized scalar can be accepted only when a first
unconditional assignment in the same scope initializes the corresponding Hepta
binding before use. A read before that assignment or conditional first
initialization is rejected. No invented zero value is substituted for a C
uninitialized read. Function-like macros and inline bodies are lowered from
the captured expanded AST, with dependencies/preprocessed bytes still bound
to the build snapshot; this is not general source-level macro rewriting.

A constructor's contract additionally maps the record buffer pointer to an
unchanged mutable slice parameter. Its body must write every record field
exactly once in straight-line code without reading previous record contents.
The translator checks those assignments before omitting the pointer store from
the safe core; the ABI edge performs the original pointer store. The newly
computed extent must fit the input slice. Subsequent pointer-field writes and
extent-field writes are rejected. General allocator, reallocation, pointer
escape, callback, packed/bitfield, volatile and concurrent protocols remain
outside this profile.

The implementation is structural and parameterized by captured record and
function declarations. A separate conformance test changes record/field/function
names and the state-update algorithm; it is not a source-hash recipe containing
a handwritten implementation of the selected upstream library.

## C ABI and safety boundary

The bridge declares the original `repr(C)` record layout, including its raw
pointer field, and retains the original exported C function names and
signatures. It copies scalar state into the safe Hepta record, calls the
translated function, and writes changed scalar state back. It leaves the
record's buffer pointer unchanged outside complete initialization.

Before constructing borrowed slices it checks non-null pointers for nonempty
storage, alignment, representable slice size, address-range overflow, and
numeric overlap whenever either participating record/buffer/output range is
mutable. A read-only/read-only alias remains allowed. Empty slices accept a
null data pointer. An initializer does not read uninitialized old record bytes.

Those checks **do not establish pointer provenance, actual allocation extent,
initialized storage, foreign lifetime, or exclusion of concurrent accesses**.
The caller must provide a live valid record and fully initialized backing
storage for the declared extent, and keep them stable during the call. The
declared view bounds all permitted pointer arithmetic; an allocation may be
larger, but storage outside that view is not imported into the safe core. The
whole-buffer initialization and disjointness contract narrows some source C
input domains. In particular, the original C library may only read initialized
queue entries, whereas constructing a Rust slice for the translated call
requires all of that slice's element storage to be initialized. C's internal
unsigned arithmetic is preserved as wrapping operations; Hepta adds checked
memory and cursor operations.

No bridge-wide memory-safety proof or whole-source semantic-equivalence claim
is made. A bad original algorithm or invalid scalar invariant can still reach
a checked abort; normal-path resource safety does not promise destructor
execution after `panic=abort` or process termination.

## Executable acceptance and costs

Run:

```sh
python tools/qualify_c_ring_buffer.py --output artifacts/c-ring-buffer.json
```

The qualification builds the complete original module with independent GCC,
builds the migrated module with the pinned Rust reference backend, and checks:

- 16,384 state transitions across capacities 1, 2, 4, 8, 16, 32, 64 and 256;
  65,544 paired native API comparisons, comprising 65,544 original-C entries
  and 65,544 translated entries (131,088 total native entries), including 543 null/zero-length buffer pairs
  for the frozen default seed. All nine functions are executed.
- Return values, every scalar state field, every backing-buffer byte, output
  sentinels, unchanged input storage and backing-pointer identity, against both
  the original C and an independent bounded-deque oracle.
- Independent C/Rust probes of record size, alignment and every field offset.
- Nine native subprocess rejection controls for null/misaligned record,
  record/buffer and input/output overlap, extent overflow, malformed index,
  null nonempty storage and zero-capacity initialization. The original C is
  not executed on these inputs outside the qualified contract.
- A genuinely mutated generated implementation, built as a native library and
  rejected by the same stateful oracle.
- An authored Hepta client which owns the backing `Buffer<u8>` inside a
  resource-bearing record. Normal completion, an early drop, two actual
  allocator refusals and subsequent successful recovery all end with zero
  live allocations. This demonstrates a safe owner of the upstream library's
  **caller-owned** storage; it does not claim that upstream allocator code was
  migrated. Persistent allocation/reallocation protocols remain open work.

The native benchmark reports all seven alternating-order samples for three
workloads: single-byte queue/dequeue, 64-byte array queue/dequeue and three state
queries. Both routes use the same dynamic-library function-pointer dispatcher.
It measures core translation, state copying and boundary checks together;
allocation/startup are outside the timed loops. Actual regressions are retained.
One shared host, GCC `-O2` versus Hepta's Rust `-O3` reference path, and no LTO or
affinity control do not establish universal parity or superiority.

`migration_disposition` separates the function and declaration denominators:
nine converted function bodies, zero untranslated C bodies behind bridges,
zero rejected/unaccounted bodies, and 22 active declarations with their exact
dispositions. Nine generated original-C ABI wrappers call those nine converted
bodies; they do not add nine more functions to the conversion denominator.
One translation unit, one active header and one listed compilation command are
covered. The license, upstream README, caller contract and compilation database
each have explicit input dispositions. This complete pinned module is not a
measurement of a production application's or the whole C ecosystem's migration
rate; inactive branches and unlisted configurations remain outside scope.

The report contains generated core/bridge line counts, elapsed migration and
qualification time, original compiler identity, complete source snapshots
before/after, input hashes and native builds. Automatic stage costs distinguish
wall time, coordinator CPU time, and completed child-process user/system CPU
time. Contract authoring, human review and maintenance hours remain unmeasured
(`null`), as do model tokens; actual model runs remain zero. The recorded tool
duration is not the total migration labor or a maintenance-cost estimate.

The output report must be a new path. Its inode is reserved before compiler
work; existing success, failure or partial reports are never overwritten. Each
report gets a new `<report-name>.generated/` directory rather than sharing a
fixed generated-source destination. The exact authored `contracts.json`, its
raw digest, generated core/bridge, migration receipt, compilation database,
upstream license and notice are retained. Intermediate checkpoints retain later
failures and interrupts. They are flushed writes, not a crash-atomic archive.
A changed output pathname is rejected, and source changes during the run reject
qualification. Use a fresh output name for every attempt, including retries.

The report keeps its existing `hepta.c-stateful-upstream-qualification.v1`
schema and adds `evidence` with schema `hepta.c-ring-retained-evidence.v2`.
The actual workspace now remains inside `<report-name>.generated/workspace/`:
original and translated libraries, the wrong candidate, layout libraries,
benchmark binary, all authored/generated inputs and build receipts are retained.
Artifact paths in this evidence object are relative to the report's parent;
the complete ordinary-file inventory binds both bytes and SHA-256.

`state-transitions.jsonl` records the actual initialization and every attempted
transition: capacity, step, operation/input, both return values and outputs,
scalar state, all backing bytes, pointer identities and actual query results.
It also keeps the failing wrong-candidate observation, including partial query
results and the exception; a failed observation is never counted as a passing
transition. The positive summary counts are derived from these retained rows.
`native-observations.jsonl` keeps owned-client and layout results. These
observations are separate from unit-test methods and migration-function counts.

`processes.jsonl` binds actual native compiler/version, boundary and benchmark
argv/cwd/returncode to retained stdout/stderr. Boundary and benchmark summaries
reference those process indices. The backend observer executes each command
once and restores its module reference in `finally`; frontend capture continues
through its existing bounded runner and receipts. Backend temporary source and
output paths stay unchanged in the observed argv. Their exact bytes are copied
and bound to explicit retained paths before normal staging cleanup, without
pretending the compiler used a different path. Byte-mode subprocess streams are
preserved byte for byte; backend text-mode streams are identified as decoded
text retained in UTF-8 before diagnostic filtering.

The defaults remain 2,048 steps per capacity and 100,000 benchmark iterations.
`--steps` and `--benchmark-iterations` allow explicitly smaller development
replays; a small run cannot claim the default run's observation denominator.
Benchmark invocation counts cover the timed dispatch loops and explicitly
exclude harness initialization. Failed and interrupted attempts retain process
checkpoints and all completed observations instead of deleting their workspace.

## Independent audit findings retained

The first complete upstream run did not exercise every newly accepted C
construct. An independent source audit found two additional counterexamples:

1. Converting a negative relative cursor index to `usize` before adding the
   cursor caused a checked abort for valid `++p; p[-1]` access. The widened,
   checked absolute-index calculation above fixes this; five original-C/native
   positive cases and four invalid-position abort cases cover the correction.
2. Two translation units with opposite plain-char signedness were accepted,
   while record fields used the first unit's model. The second unit read byte
   `255` as `255` instead of C's `-1`. The bounded bundle now explicitly rejects
   differing models while retaining all four declarations in that counterexample.

Related regressions prevent user macros or include-path operands from spoofing
the independent native ABI probe. Earlier successful finite differentials are
retained as pre-audit evidence, not substituted for the corrected-source run.

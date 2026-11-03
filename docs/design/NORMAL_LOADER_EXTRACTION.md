# Normal-source legacy loader extraction

Status: reviewable normal-source implementation atop #622. This changes the
production implementation, not legacy defaults or public API. It is not bounded
loading, a sandbox, native ABI qualification, merging or deployment.

## Implemented boundary

`hepta/_loader_ops.py` provides private eager legacy read, inventory, JSON, TOML,
tokenize and parse operations plus one small identity dispatch helper.
`hepta/packages.py` and `hepta/modules.py` retain their public names, signatures,
annotations and original dataclasses. Algorithms occur once in ordinary private
functions in those same modules. Public entry points construct stateless legacy
operations and delegate. There is no production source rewriting, compile/exec,
module replacement, hidden session context or graph ownership field.

LoadedProject remains the original eleven-field `hepta.modules.LoadedProject`.
Package remains `hepta.packages.Package`. Positional package recursion/cache
arguments, dataclass constructor/match fields, report aliasing and public
unchanged semantics are retained. Compiler identity necessarily changes because
compiler_hash includes the changed/new production source files. Existing
compiler-bound artifacts cannot be relabelled as qualified for this implementation.

## Deliberate monkeypatch strategy

Simply calling private helpers breaks existing module-level interception;
simply calling public wrappers loses the explicit owner on every internal call.
The small `_dispatch` helper resolves this tension for legacy namespace hooks:

1. Each package public wrapper has a retained canonical function identity.
2. At each original call site, evaluate the same public symbol in the same
   namespace. If it is the canonical wrapper, call its private implementation
   with the current operations instance. Otherwise call the replacement with
   exactly the legacy positional/keyword arguments, never an added ops keyword.
3. Use identity (`is`), never equality or inspect.unwrap. Mock(wraps=original),
   decorated forwarders and replacements remain real interception points.
4. Module-imported aliases and live package globals stay distinct. A package
   replacement before modules import is recognized as a replacement, because
   identity constants come from packages, not a possibly patched imported alias.
5. The final result.unchanged lookup occurs once. Dispatch to private revalidation
   only for an exact bound MethodType whose receiver is the result and whose
   function is the original method. Otherwise invoke the returned callable.
   This preserves custom descriptors, false-returning and raising hooks, methods
   bound to another object, and callables spoofing a `__func__` attribute.

Parser/tokenizer/JSON/TOML callables are passed from their original namespace at
the call site, not imported and cached in the ops module. This preserves both
module-attribute patches and whole namespace rebinding. The original JSON callable
is captured before lock read, TOML callable before decode, and outer snapshot
callable before nested load can change it. Path reads/rglob still invoke the
original path object's methods. The parser retains duplicate legacy lexing.

This is compatibility for namespace callable replacement and the documented
public surface, not arbitrary reflective modification of function bytecode,
default internals, tracing/profiling stack frames, private implementation symbols
or import/reload machinery. New wrappers necessarily change source locations and
tracebacks. No whole-program theorem for external monkeypatches is claimed.

## Ownership limits, not a bounded-loader interface

An uninterrupted original-helper path shares one explicit operations instance
through recursive packages, snapshots, lock verification/publication rechecks,
graph reads and final private revalidation. A replacement hook is an external
compatibility boundary. If it calls a captured public wrapper, that wrapper
creates fresh legacy operations. Public graph.unchanged also creates fresh
legacy operations; a returned graph retains no session.

These are tested boundaries, not omissions to hide with global context. Custom
operations are private test seams; no public custom-ops API is offered. A future
bounded caller needs a separately reviewed owner handle across its entire
lifetime and cannot use public legacy unchanged as its budget authority.

Path resolution/discovery, graph edges/depth, parser depth, metadata allocation,
serialization, digest work and native processing retain their original code.
Read roles are labels only. No quotas, timeout/cancellation limit, hard heap
ceiling, complete role provenance or filesystem snapshot is implemented here.

## Behavior retained

- Full program/AST/report/source bytes and canonical graph identity, including
  symlink bindings/import edges and metadata/header reads.
- Error code/message/phase/span, ordinary exception types/messages, existing
  catches and read/decode order. RuntimeError is not swallowed as stale state.
- Original override alias/last-wins/unused-entry behavior and disk revalidation.
  A valid disk lock still does not authenticate candidate overlaid text.
- report shares its original mutable containers. unchanged compares stored
  package snapshots but does not reread Hepta.lock after initial load.
- Lock bytes and final snapshot check, original destination retention and stage
  cleanup under fsync/replace failures. No broader write or publication changes.
- CLI/protocol/workspace/native consumers continue using the same public graph
  and API; this PR does not rewrite callers or weaken their qualification checks.

## Frozen oracle and reviewed pin transition

The exact pre-extraction modules.py/packages.py bytes from #622 are retained under
`experiments/legacy_loader_ops/baseline/`, with their original SHA-256 pins. They
are immutable test data, not another maintained/shipped production loader.
The #621 recipe now reads those historical inputs rather than requiring current
production to remain byte-identical forever. Its original source drift refusal
still applies. A second test-only import harness changes only relative import
locations to execute the raw historical algorithm in isolated namespaces; it
never replaces hepta modules. Production imports no experiment.

All 80 repository examples are compared against that raw historical algorithm:
68 matching successful graph loads and 12 matching missing-input diagnostics.
This is not 80 compilation successes. The existing 26-control #621 oracle also
continues comparing the current loader with its independent historical recipe.

The consumer inventory is regenerated after review: 180 production Python files,
26 candidate files and 203 references, now including explicit hook-dispatch
sites. Previous #622 counts describe its earlier snapshot. Request-context
upstream pins are refreshed for modules/packages and additionally pin the new
ops file after differential review; its isolated bounded prototype remains
unchanged and is not enabled by this extraction.

## Validation and limits

- 23 new raw-baseline/hook controls: full example corpus, exact signatures and
  object fields, historical pickle compatibility, module/package namespace distinction, pre-import patching,
  dynamic hook replacement, forwarding mocks, namespace decoder replacements,
  decoder/call evaluation order, custom revalidation descriptors, owner sharing
  and explicit owner loss across public forwarding, lock failure cleanup, and
  absence of direct read/parser fallback or production runtime rewriting.
- 98 previous loader/consumer controls plus 6 legacy characterization controls
  remain in the strict focused gate: 127 unique tests, zero skips or expected
  failures required. Independent review contributed four durable adversarial
  probes before final verification.
- A separate hosted gate adds 132 existing module/package, CLI label, protocol
  v1/v2/v3, workspace, workspace-query, semantic-inspection and crossfile/crash
  regression controls. Total 259 unique tests per job, zero skips required on
  exact PR HEAD, Ubuntu 24.04 with Python 3.11 and 3.12 and Rust 1.90/GCC.
- Local focused tests pass. Native-dependent local consumer attempts are blocked
  by absent rustc; 83 attempted tests in the initial six-suite run had 11 failures
  and 18 errors, not a passing native result. Hosted results must be checked for
  the final commit before claiming that finite regression gate passed.

The hosted tests are selected consumer regressions, not all 180 modules, every
supported platform or complete native ABI qualification. No macOS/Windows or
other Python version pass is implied. No broad semantic compatibility proof,
untrusted custom callback safety, bounded production, merge or deployment.

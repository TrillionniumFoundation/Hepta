# Remaining private authority and package-copy audit

Audited against draft #629 at b627dfeb353bb44a0ed8483b8dfb8e520f0265fa.
Runtime measurements use CPython 3.12.14. This is evidence for a future boundary,
not implementation of an authority-copy quota or a memory qualification.

## Actual paths and shapes

After normal graph assembly, experiments/owned_loader/owner.py makes a shallow
copy.copy(LoadedProject), then separately deepcopies four fields: source_bytes,
bindings, package_state and package. Each deepcopy has its own memo. These calls
are outside the assembly-copy and transform counters.

- source_bytes is exact dict[str, bytes]. Immutable byte values retain identity
  across deepcopy, but the mapping itself is copied.
- bindings is exact dict[str, str].
- package_state is None or nested exact string-keyed dictionaries and strings.
  Unlocked state is generated. A locked JSON snapshot must equal the generated
  expected schema. No source-producible cycles or shared containers were found
  in these plain maps.
- package is None or Package dataclasses with dependency dictionaries, strings,
  immutable manifest bytes and concrete pathlib paths. Package dependency aliases
  can share objects. Source dependency cycles reject before graph return.
- The shallow LoadedProject copy retains other public AST/report references, then
  only the four private revalidation fields are replaced. That shallow operation
  would remain excluded even if the first three maps were later admitted.

## Falsifiable plain-map metric

A future unfolded occurrence count can count each dictionary, key and value,
with exact str/bytes/None values each one visit. For actual canonical shapes:

- source_bytes: 1 + 2N for N entries.
- bindings: 1 + 2M for M entries.
- None package state: 1.
- package snapshot: 9 + 12P + 2E + 2F, for P package records, E dependency aliases
  summed over records and F distinct snapshot file entries.

An empty standalone function has map counts 3 + 3 + 1 = 7. A simple one-package
snapshot has 25 visits. The repository package example had map counts
5 + 7 + 43 = 55. These logical counts are not allocator bytes, peak memory or
portable exact deepcopy operation counts.

Three durable read-only tests in experiments.loader_transform/test_authority_audit.py
check standalone maps, generated and locked snapshot formulas, and a package DAG.
They also prove the current assembly-copy/transform counters remain 150/14 for
these one-function fixtures: the tests do not imply authority work is newly metered.

## Package aliases and Path counterexamples

The four-package fixture uses root aliases a and c for left, root b for right,
and both left and right reference leaf. Both public and copied authority graphs
preserve shared left and shared leaf identities. There are four distinct Packages
but seven Package occurrences under expanded traversal. Mutable aliases are
memoized by standard deepcopy, so expanded traversal conservatively differs from
actual copy dispatches.

Treating paths as single terminal values gave 132 logical Package visits for this
durable fixture (child source_root="." and lib.hepta); adding path component
strings gave 220; observed CPython deepcopy calls were 132. The temporary fixture was directly under /tmp. Adding absolute-path
components changes the component and actual-call counts; only the terminal
count and plain-map formulas are path-length independent. For
examples/packages/app at the measured local source location, those figures were
37, 85 and 87, not portable CI expectations. The mismatch
is evidence against presenting any ad hoc measure as complete copy accounting.

On inspected Python 3.12, PurePath holds lazy slots including raw paths, parsed
drive/root/tail and string/normalization/hash caches. PurePath.__reduce__ returns
its concrete class and parts. The parts property may construct a tuple, and copy
reconstructs through the Path constructor. Paths become distinct equal objects;
manifest bytes retain identity. Equal root and source_root values need not be the
same original object.

Therefore atomic Path admission would omit component traversal, lazy-property
work and constructor work. A complete proposed Path policy must deliberately
handle exact runtime classes, reducer/helper hooks, lazy state, reconstruction
and version differences. Merely calling unknown reducers during preflight or
walking all slots would not establish a safe boundary. Python 3.11 internals
were not available for this audit and are not assumed identical to 3.12.

## Why transform admission is staged first

Transform has a smaller exact boundary at each recursive body entry, before its
existing reconstruction branch. It preserves original evaluation order and does
not need Package/Path support. Actual invocation measurements are 14/depth 2 for
one empty function, 28/depth 2 for two modules, 333/depth 84 for forty operands,
and 293/depth 14 for examples/packages/app. These are invocation counts, not
allocation counts; Type branches also construct tuples and often Spans.

All 80 example parser graphs had no cycles or repeated mutable/dataclass/Type
identities in the measured traversal. Shared immutable tuple occurrences were
common. Synthetic alias tests still require per-occurrence transformation rather
than introducing memoization. Graph/transform input assumptions are not a sandbox
for arbitrary injected objects or private runtime mutation.

A later three-map authority profile is viable and simpler than Package copying.
It must explicitly support exact bytes, admit traversal before copy, preserve
separate memos and legacy callable/argument/finalizer behavior, and test quota,
cancellation, alias/cycle and terminal semantics. Package copying and shallow
LoadedProject copying must remain explicit exclusions until separately designed
and evidenced. This audit does not change defaults or establish a hard memory/CPU/time bound.

# Real musl comparison source migration

The C migration frontend now translates the complete generic `memcmp.c` and
`bcmp.c` component from musl 1.2.5 without editing the upstream function bodies.
The component demonstrates source translation of byte cursors, a short-circuit
loop, ordered comma increments, a lazy conditional return and a captured call
between translation units. The native target contains generated Hepta/Rust code;
the original C object files and libraries are used only as comparison oracles.

## Exact scope and provenance

| Item | Qualified scope |
| --- | --- |
| Upstream | musl 1.2.5 official release, tag commit `0784374d561435f7c787a555aeab8ede699ed298` |
| Official archive | `https://musl.libc.org/releases/musl-1.2.5.tar.gz` |
| Archive SHA-256 | `a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4` |
| Original source | 2 complete files, 2 functions, 319 bytes, 16 lines; unchanged |
| License | Full upstream MIT copyright and attribution retained |
| Configurations | Two separate C11 component builds: `-O0` and `-O2`, each with `-fPIC -fno-builtin -Iplatform` |
| Host | Executed x86-64 Linux only |
| Actual tools | Clang 20.1.8, GCC 13.3.0 and Rust 1.90.0 |
| Generated route | Captured Clang AST → Hepta parser/checker → Rust native reference backend |

The fixture's two platform headers are explicitly authored adapters for this
component's declarations and host `size_t`. They are shared by both original C
builds and the migration capture. The complete captured project inputs are
therefore four files totaling 840 bytes: 319 bytes of original algorithm source
and 521 bytes of adapter headers. The adapters are excluded from the upstream
source count. Four pointer annotations are supplied by `contracts.json`.

This is not a full musl build, a libc replacement, a migration of its optimized
architecture-specific implementations, or a new platform qualification. No
unselected source file is included in the claimed migration denominator. The
source manifest, complete licenses and original bytes are in
`tests/fixtures/c_migration/musl_compare/`.

## Frontend changes

The existing record-view translator can now express a cursor-only profile with
an empty record map and explicit slice contracts. It uses the same typed slice,
borrow, bounds and ABI bridge mechanisms as the existing Ring Buffer migration;
no dummy record or new raw-pointer language feature is introduced. A local C
cursor becomes a scalar offset into its original borrowed slice. Advancing a
cursor checks that it remains at or before the end, and dereferencing it checks
that an actual element exists.

Three generic control-flow extensions make the upstream source admissible:

* A C `for` loop may omit its initializer. Its condition and increment remain
  mandatory, and an unsupported condition or body still rejects the bundle.
* A statement-position comma operator executes its supported operands in their
  original left-to-right sequence. This includes the three increments in the
  upstream `for` loop. Comma expressions inside values remain unsupported.
* A scalar conditional directly in return position lowers to an `if` with one
  return in each branch. Only the selected branch evaluates, so the empty-range
  return does not read either cursor. Clang's operand conversions are retained.
  Mutating conditions still reject. The later scalar extension documented in
  `C_STB_DIVIDE.md` also accepts pure scalar conditional values in initializers
  and arithmetic through lazy helpers; pointer/record captures remain outside
  that value profile. The original musl qualification did not rely on it.

`-fno-builtin` is retained in captured frontend and model-probe arguments. It
prevents the component's public function names from being silently replaced by
host builtin semantics. Unsupported driver options are still refused.

## Acceptance denominators and observed results

The first full component qualification completed successfully. Each of the two
configuration bundles inventories all five active project declarations: two
converted definitions and three resolved prototypes. It also records 20 system
or compiler declarations. No active project declaration is silently skipped.
Each bundle contains 43 generated Hepta lines and a 37-line caller-unsafe C ABI
bridge. Migration plus the actual native build took approximately 1.3–1.4 seconds
per configuration on this host; this is an observed build time, not a general
migration-cost or program-performance promise. Manual review time and model-token
cost have not been measured.

For each configuration, the same corpus is executed through generated Hepta,
the original source compiled by GCC, and the original source compiled by Clang.
The original object files are compiled with the captured options and linked
separately with local symbol binding, so `bcmp` calls this component's own
`memcmp` implementation.

| Input category | Cases per configuration |
| --- | ---: |
| Every ordered pair of single-byte values | 65,536 |
| Every first-difference position for 13 selected lengths, both signs | 994 |
| Equal byte strings of lengths 0 through 128 | 129 |
| Seeded inputs of up to 512 bytes | 512 |
| Same-address and overlapping read-only input storage | 387 |
| **Total** | **67,558** |

Each input invokes both functions on each of the three native routes. This gives
405,348 observed native function calls per configuration and **810,696 across
135,116 input/configuration cases**. Every returned integer matched both original
compilers and an independent byte-difference expectation; every input region
remained unchanged. The qualifier retains each input, offsets, alias relation,
expected result and observed route results in `cases.jsonl`.

Additional gates executed successfully:

* An actual GCC C caller links against and executes each generated shared library.
  Both public ABI symbols are present. The target build receives generated Rust
  only, with no original C object or library as a link input.
* Twelve subprocess controls cover each function under each configuration:
  zero-length null input returns zero under the generated bridge's explicit
  empty-view policy; nonempty null and unrepresentable length abort before a
  foreign slice is formed. The invalid inputs are not passed to original C, and
  the empty-null behavior is not presented as a general C standard guarantee.
* An actually compiled, resource-legal wrong implementation returning zero for
  a difference is rejected by the same oracle at input pair `(0, 1)`. Resource
  acceptance and functional preservation remain separate obligations.
* Seven calls through an authored Hepta `Buffer` owner cover normal return,
  explicit early drop, zero length, two real allocator refusals, and successful
  recovery after refusal. Successful nonempty calls allocate and free exactly
  once, refused calls allocate nothing, and every call leaves zero live
  allocations. The upstream component itself only borrows; these are caller
  resource observations, not a claim to have translated upstream allocation.
* Three authored whole-bundle refusal controls cover a missing pointer contract,
  an extra unsupported global and an extra pointer-returning function. Each
  emits its expected diagnostic and publishes no partial translated bundle.

Focused tests also compare native C and translated sequencing, unsigned common
type conversion, nested lazy returns, rejection of unsupported loop/expression
forms, and compatibility with the existing complete Ring Buffer component.
Their first run had seven passes and one author-fixture failure: Clang's
`-Wempty-body` diagnosed a same-line empty loop. Changing that authored test body
to `{}` preserved the sequencing obligation, and its focused rerun passed.
The original musl source required no such alteration. Both attempts are retained.

## Contracts and remaining boundaries

The safe Hepta core receives initialized read-only byte slices. The foreign ABI
edge accepts C pointers and length, so their lifetime, allocation provenance,
actual extent, initialized bytes and absence of concurrent mutation remain
caller obligations. Numeric range and bounds checks cannot establish all of
those facts. Aliases between the two read-only inputs are accepted and exercised.

No equivalence theorem, universal memory-safety proof for foreign callers,
performance parity with Rust or optimized libc, standalone HIA LLVM slice
lowering, C++ migration expansion, or new cross-platform runtime qualification
is claimed by this component gate. The existing C++/library-reuse and platform
gates retain their own scopes. Full combined HIA qualification must run on the
integrated revision separately.

## Reproduction and retained evidence

With actual Clang and Rust configured, run:

```sh
python tools/qualify_c_musl_compare.py \
  --clang /path/to/clang \
  --rustc /path/to/rustc \
  --output-directory /path/to/new/musl-comparison-evidence
python -m unittest tests.test_c_cursor_control -v
```

The output directory must be new. `qualification.json` records the implementation
file hashes, source manifest, build invocations, complete migration reports,
counts and checks. The `O0` and `O2` subdirectories retain compilation databases,
source inputs, generated Hepta/Rust, both original compilers' objects/libraries,
generated binaries, actual C callers and per-case logs. Resource and wrong-code
artifacts are retained under `O2`; refusal reports are under `rejections`.

The local run is retained in
`hia-migration-next-validation/musl-qualification-attempt1/`. It is independent
of the older frozen `817713b` HIA evidence and the guard/capture tests described
in `C_MIGRATION_GUARDS_20261028.md`.

# Explicit native NDU build profiles

The scalar ranking executor is native HIA. Its JSON parsing, integer and ID
validation, feasibility partition, Pareto selection, digest construction and
bounded streaming state machine are implemented in
`examples/hia_bootstrap/ndu_scalar.hepta`. A mechanical syscall adapter performs
only process I/O. The resulting ELF runs with an empty PATH and has no dynamic
loader, interpreter or Rust evaluator dependency.

The recursive and finite utility profiles remain separate, explicitly pinned
reference profiles. They retain their distinct protocols and source receipts.
NDU advice does not prove HIA program safety or authorize publication; each
consumer still revalidates the candidate under its declared proof profile.

| Contract | Candidate ranking | Recursive utility |
| --- | --- | --- |
| Python consumer | `hepta.hia_ndu_optimizer` | `hepta.hia_ndu.NduBridge` |
| Builder | `tools/build_hia_ndu_scalar.py` | `tools/build_hia_recursive_ndu_bridge.py` |
| Compatibility source pin | `d3c2d760eca5065fc966820379c35c6e8d56e855` | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` |
| Active implementation | `examples/hia_bootstrap/ndu_scalar.hepta` | Original checkout `tools/hia-ndu-bridge` |
| Request schema | `hepta.hia.ndu-request.v1` | `hepta.hia.ndu.request.v1` |
| Build receipt schema | `hepta.hia.ndu-scalar-build.v1` | `hepta.hia.ndu.build.v1` |
| Receipt filename | `build-receipt.json` | `identity.json` |
| Explicit test binary environment | `HEPTA_NDU_BRIDGE` | `HEPTA_RECURSIVE_NDU_BRIDGE` |
| Receipt environment | `HEPTA_NDU_BUILD` is the build directory | `HEPTA_RECURSIVE_NDU_IDENTITY` is the identity file |
| Original Rust oracle custody tests | `HEPTA_NDU_UPSTREAM` (reference rebuild only) | Explicit builder/collector `--ndu-source` / `--recursive-upstream` |

The added finite continuation graph uses the recursive dotted wire schema but
has its own source pin `4b6391e116949af0c7e59776baead67271856bdb`, Rust
`1.95.0`, and the environment pair `HEPTA_FINITE_NDU_BRIDGE` /
`HEPTA_FINITE_NDU_IDENTITY`. `NduBridge.for_finite_profile()` checks this exact
source/tool profile before constructing the native transport. Neither a matching
wire schema nor a ranking/recursive environment variable satisfies that gate.

## Build independently

Build scalar ranking with a compiler and cold receipt belonging to the exact
current source inventory. The standard cold replay produces the compiler at
`REPORT.cold/qualification.evidence/B3.image.bin`:

```sh
python -m tools.replay_hia_selfhost_cold --output /absolute/cold.json
python -m tools.build_hia_ndu_scalar \
  --compiler /absolute/cold.cold/qualification.evidence/B3.image.bin \
  --cold-report /absolute/cold.json \
  --output /absolute/new-ranking-build
/absolute/new-ranking-build/hia-ndu-scalar < /absolute/request.json
```

Default and editable release assembly publish `hia-ndu-scalar` as a native
script. The compatibility Python API selects only the package-owned HIA image
and its source-bound receipt when no explicit bridge is supplied. Development
receipts and the former Rust build schema are refused by production admission.
An explicit `--development` build remains available for implementation work and
does not create a matching-source production receipt.

`tests.test_hia_ndu_scalar_native` checks the original public contracts and 64
unique frozen Rust request/stdout pairs, including all digest bytes, plus
framing, budgets and real caller admission. The upstream commit and entrypoint
strings in the compatibility response remain unchanged; the separate executable
identity reports `implementation: HIA`.

### Retired scalar Rust oracle

The old `rust/hia-ndu-bridge` production directory is removed. Its exact four
files remain inside the existing immutable review archive, together with the
original execution captures. `tools/hia_ndu_reference.py` verifies the archive
and each file against fixed SHA-256 identities. An explicit reference rebuild
can materialize those bytes in a temporary adapter directory:

```sh
python -m tools.build_hia_ndu_bridge --reference-scalar \
  --upstream /path/to/ranking-source \
  --output /path/to/new-reference-build \
  --cargo /path/to/rust-1.90.0/bin/cargo
```

That binary is an independent compatibility oracle and is never admitted by the
scalar production chooser. Original source-provenance tests still require its
actual build workspace and the pinned upstream Git checkout. Frozen historical
campaigns retain their original source identities; replay does not relabel them
as execution of current HIA source.

Keep reference checkouts and output directories separate. The recursive profile
uses Rust 1.90.0 and the finite graph profile uses Rust 1.95.0. HIA proof tests
use the separately pinned optional solver `z3-solver==4.15.4.0`; scalar native
execution itself has no solver dependency.

The recursive builder is the separately named original bridge builder. Its
checkout must contain the committed `tools/hia-ndu-bridge` workspace and lockfile
at the recursive source pin. It records source/bridge inventories, actual native
identity, compiler hashes and observed build costs. It rejects a dirty checkout,
checks each declared source input against its pinned Git blob before and after
compilation, and requires an already committed lockfile. It never generates a
new lockfile while claiming the old source identity.

```sh
python tools/build_hia_recursive_ndu_bridge.py \
  --ndu-source /path/to/recursive-source \
  --expected-source 2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b \
  --cargo /path/to/rust-1.90.0/bin/cargo \
  --rustc /path/to/rust-1.90.0/bin/rustc \
  --output /path/to/new-recursive-build
```

For the finite profile, reuse that builder with a distinct checkout and toolchain:

```sh
python tools/build_hia_recursive_ndu_bridge.py \
  --ndu-source /path/to/finite-source \
  --expected-source 4b6391e116949af0c7e59776baead67271856bdb \
  --cargo /path/to/rust-1.95.0/bin/cargo \
  --rustc /path/to/rust-1.95.0/bin/rustc \
  --output /path/to/new-finite-build \
  --target-dir /path/to/new-finite-cargo-target
```

With `--target-dir`, the builder copies the actual executable into
`OUTPUT/native/hepta-hia-ndu-bridge` and binds both compiled and retained hashes.
The durable output contains each actual command's argv, exit status, elapsed
time, and original stdout/stderr bytes. A failed attempt writes a failure
receipt without creating a successful identity. Reusing an existing output
directory is rejected so earlier evidence cannot be overwritten. The Cargo
target directory is reproducible intermediate storage, separate from those
retained inputs, streams, identity and executable bytes.

All receipts bind builder bytes and native source inputs. A receipt is a trusted
local build record, not remote attestation. The integrated qualification
collector separately binds the exact committed Hepta tree; neither builder
receipt alone claims that every integrated source file was tested.

## One-shot ranking executable custody

The ranking consumer retains the exact executable bytes checked against its
build receipt. It copies those bytes into a Linux `memfd`, requires write,
grow, shrink and seal seals, and checks both the seals and byte readback before
executing `/proc/self/fd/<descriptor>`. It never executes the admitted source
pathname. Replacing and then restoring that pathname between admission and
execution cannot substitute a different program. The original source pathname
is still rechecked after execution; a lasting change rejects the result.

Both build-receipt and executable reads open with `O_NONBLOCK` and `O_NOFOLLOW`
before checking the inode with `fstat`. A FIFO with no writer is refused without
waiting for a writer. Reads are byte-bounded and compare inode metadata before
and after reading. This does not establish a deadline for kernel/filesystem I/O.

The existing bounded subprocess pump limits each captured output stream to
1 MiB during execution, retains the leader with `waitid(WNOWAIT)`, and kills
its process group before reaping that leader on success, rejection or timeout.
The sealed descriptor remains owned until that cleanup finishes. Missing
sealing or process-ownership support, failed cleanup, mismatched request/source
identity and invalid advisory claims all refuse the result.

This is executable custody for a trusted local bridge. It does not sandbox
arbitrary hostile code, attest the dynamic loader or shared libraries, prevent
an arbitrary trusted-parent memory modification, or prove NDU safety or global
optimality. `tests.test_hia_ndu_optimizer_transport` uses real subprocess
fixtures to reproduce pathname ABA and FIFO blocking, check sealed execution,
and exercise overflow, timeout and response refusals. Those fixtures do not
qualify an upstream NDU implementation; the separate native bridge tests do.

## Configure all three profiles in one process

```sh
export HEPTA_NDU_BRIDGE=/path/to/hia-ranking-build/hia-ndu-scalar
export HEPTA_NDU_BUILD=/path/to/hia-ranking-build
export HEPTA_HIA_NDU_SCALAR="$HEPTA_NDU_BRIDGE"
export HEPTA_HIA_NDU_BUILD="$HEPTA_NDU_BUILD"
export HEPTA_RECURSIVE_NDU_BRIDGE=/path/to/recursive-build/target/release/hepta-hia-ndu-bridge
export HEPTA_RECURSIVE_NDU_IDENTITY=/path/to/recursive-build/identity.json
export HEPTA_FINITE_NDU_BRIDGE=/path/to/finite-build/native/hepta-hia-ndu-bridge
export HEPTA_FINITE_NDU_IDENTITY=/path/to/finite-build/identity.json

python -m unittest -v \
  tests.test_hia_ndu_bridge \
  tests.test_hia_ndu_scalar_native \
  tests.test_hia_ndu \
  tests.test_hia_ndu_bridge_isolation \
  tests.test_hia_ndu_graph \
  tests.test_hia_recursive_ndu_builder
```

`NduBridge.from_environment()` requires both recursive variables. It does not
fall back to `HEPTA_NDU_BRIDGE`, `HEPTA_NDU_BUILD` or the old
`HEPTA_NDU_IDENTITY` name. Explicit `NduBridge(binary, identity)` callers remain
supported, with the same recursive schema and native identity checks.
`NduBridge.from_finite_environment()` requires the complete finite pair and
additionally enforces its source/Rust profile. It has no legacy fallback.

The isolation tests execute all three real native binaries in one interpreter,
reject swapped build receipts, and submit each request shape to the other
native protocol to check refusal. Missing native prerequisites remain explicit
skips and fail the complete qualification gates; they are not a substitute for
those execution checks.

## Recursive loop and retained evidence

The active recursive loop entrypoint now captures the separately named builder
in its source inventory and can bind an explicit recursive executable:

```sh
python tools/qualify_hia_ndu_loop.py \
  --identity "$HEPTA_RECURSIVE_NDU_IDENTITY" \
  --bridge "$HEPTA_RECURSIVE_NDU_BRIDGE" \
  --clang /path/to/clang-20 \
  --output /path/to/new-loop-evidence
```

Omitting `--bridge` uses the binary named by the explicitly supplied recursive
identity file. It never consults the ranking environment. Existing historical
experiment records, source snapshots, build commands and measurements remain
unchanged. Their earlier filenames and solver identities describe those runs;
they do not qualify the integrated tree. New integration runs write new source-
bound evidence and keep performance or productivity conclusions separate from
protocol and regression success.

Qualification of the optional recursive/finite integration still requires those
actual reference binaries and their own source gates. Scalar HIA qualification
uses its matching cold build; a pass for that component does not close the
other profiles' prerequisites.

The finite graph collector binds the recursive builder that actually produced
its executable. Its bounded graph enumerates continuation paths, receives
native advisory values and replans after observed work. The strong lightweight
control solves the same additive finite-horizon model by dynamic programming;
neither enumeration nor native recursion is evidence of a learned policy or a
general performance advantage. Its same-information study is separate from
the frozen 48-episode economic deployment study and the historical 30-episode
recursive CI mechanism study. Native correctness tests do not relabel any of
those measurements or remove their negative results.

# Three explicit native NDU build profiles

The integrated tree retains two advisory wire protocols and three independently
pinned build profiles. They have separate source identities, environment
variables and receipts. Each executes the
original Rust NDU crate APIs. Neither protocol proves HIA program safety or
authorizes native publication; the HIA consumer must independently revalidate
the candidate under its declared proof profile.

| Contract | Candidate ranking | Recursive utility |
| --- | --- | --- |
| Python consumer | `hepta.hia_ndu_optimizer` | `hepta.hia_ndu.NduBridge` |
| Builder | `tools/build_hia_ndu_bridge.py` | `tools/build_hia_recursive_ndu_bridge.py` |
| Original source pin | `d3c2d760eca5065fc966820379c35c6e8d56e855` | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` |
| Adapter source | Hepta `rust/hia-ndu-bridge` | Original checkout `tools/hia-ndu-bridge` |
| Request schema | `hepta.hia.ndu-request.v1` | `hepta.hia.ndu.request.v1` |
| Build receipt schema | `hepta.hia.ndu-build.v1` | `hepta.hia.ndu.build.v1` |
| Receipt filename | `build-receipt.json` | `identity.json` |
| Binary environment | `HEPTA_NDU_BRIDGE` | `HEPTA_RECURSIVE_NDU_BRIDGE` |
| Receipt environment | `HEPTA_NDU_BUILD` is the build directory | `HEPTA_RECURSIVE_NDU_IDENTITY` is the identity file |
| Source environment for custody tests | `HEPTA_NDU_UPSTREAM` | Explicit builder/collector `--ndu-source` / `--recursive-upstream` |

The added finite continuation graph uses the recursive dotted wire schema but
has its own source pin `4b6391e116949af0c7e59776baead67271856bdb`, Rust
`1.95.0`, and the environment pair `HEPTA_FINITE_NDU_BRIDGE` /
`HEPTA_FINITE_NDU_IDENTITY`. `NduBridge.for_finite_profile()` checks this exact
source/tool profile before constructing the native transport. Neither a matching
wire schema nor a ranking/recursive environment variable satisfies that gate.

## Build independently

Keep all three original source checkouts and output directories separate. Use
Rust 1.90.0 for the existing ranking and recursive profiles, Rust 1.95.0 for the
new finite graph profile, and the integrated solver dependency
`z3-solver==4.15.4.0` for HIA proof tests. The Rust bridge protocols themselves
do not use the Python SMT solver.

The ranking builder reads its source pin from
`rust/hia-ndu-bridge/upstream.json`. It extracts that Git object into a new
isolated production workspace, verifies the copied inputs and adapter, and
requires the committed isolated lockfile. Its file bytes and existing protocol
are retained from the bounded-pipeline implementation.

```sh
python tools/build_hia_ndu_bridge.py \
  --upstream /path/to/ranking-source \
  --output /path/to/new-ranking-build \
  --cargo /path/to/rust-1.90.0/bin/cargo
```

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

## Configure all three profiles in one process

```sh
export HEPTA_NDU_BRIDGE=/path/to/ranking-binary
export HEPTA_NDU_BUILD=/path/to/ranking-build
export HEPTA_NDU_UPSTREAM=/path/to/ranking-source
export HEPTA_RECURSIVE_NDU_BRIDGE=/path/to/recursive-build/target/release/hepta-hia-ndu-bridge
export HEPTA_RECURSIVE_NDU_IDENTITY=/path/to/recursive-build/identity.json
export HEPTA_FINITE_NDU_BRIDGE=/path/to/finite-build/native/hepta-hia-ndu-bridge
export HEPTA_FINITE_NDU_IDENTITY=/path/to/finite-build/identity.json

python -m unittest -v \
  tests.test_hia_ndu_bridge \
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

The full qualification workflow and the existing verified-optimization workflow
prepare all three profiles before their current test gates. The full workflow keeps
its existing complete `release_check` discovery; the standalone integrated
collector is not invoked again in that same job.

The finite graph collector binds the recursive builder that actually produced
its executable. Its bounded graph enumerates continuation paths, receives
native advisory values and replans after observed work. The strong lightweight
control solves the same additive finite-horizon model by dynamic programming;
neither enumeration nor native recursion is evidence of a learned policy or a
general performance advantage. Its same-information study is separate from
the frozen 48-episode economic deployment study and the historical 30-episode
recursive CI mechanism study. Native correctness tests do not relabel any of
those measurements or remove their negative results.

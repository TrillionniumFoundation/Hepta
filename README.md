# HIA Core

HIA is typed abstract assembly and structured Core for AI agents. It checks
explicit control flow, types, effects, capabilities, ownership and borrowed
resources before machine-code generation. Assembly uses the `hia-asm.v1`
header; structured Core retains its versioned primitive or composite schema.
Source files use `.hepta`, with `.core.hepta` for paired JSON projections.
The `hia` command and `hepta.hia.*` wire schemas retain their names.

The Linux x86-64 source release is built by HIA programs. HIA owns parsing,
verification, lowering, object and executable construction, source inventories,
release packaging, Store and Worker policies, and build admission. The retained
assembly adapters supply bounded operating-system and machine-call mechanisms.
Their exact bytes are source-bound with the HIA programs that use them.

[CURRENT.md](docs/CURRENT.md) identifies the selected source and the actual
acceptance evidence. A source manifest or an earlier successful build does not
qualify a changed checkout. Component results and complete release acceptance
have separate scopes.

## Use an installed release

The standalone release contains `hia` and the companion programs its pinned
dispatch table names. The public CLI supports capabilities, Core verification,
assembly admission, compilation, assembly rendering and opcode discovery.

```sh
hia capabilities
hia check-assembly examples/hia_bootstrap/bytesum.hepta
hia verify examples/hia_program/counter.hepta
```

For a captured release package, check its supplied digests and install it into a
new private directory. `SOURCE_COMMIT` is supplementary provenance; the package,
source manifest and actual executable hashes remain authoritative.

```sh
sha256sum --check SHA256SUMS
chmod 500 hia-release
mkdir -m 700 hia-install
digest=$(sha256sum store.hiapack | cut -d ' ' -f 1)
env -i PATH= ./hia-release install "$PWD/hia-install" "$digest" < store.hiapack
env -i PATH= ./hia-release verify "$PWD/hia-install" "$digest" < store.hiapack
env -i PATH= "$PWD/hia-install/$digest/hia" --version
```

The digest selects the immutable installation. Selecting a running Worker,
changing an active release and installing runtime job routing are separate
state transitions with their own current-generation and byte-identity checks.
Package verification alone does not establish that a live endpoint uses it.

## Build and qualify from source

The native workflow has three explicit public stages. Each output directory must
be new. Each named input is an absolute path to the captured, matching artifact;
directory names do not confer authority.

| Stage | Native entry and required inputs |
| --- | --- |
| Construct the cold toolchain | `hia-cold-build --source ABS_SOURCE --bootstrap ABS_BOOTSTRAP --output NEW_ABS_BUILD` |
| Run complete cold qualification | `hia-cold --source ABS_SOURCE --output NEW_ABS_COLD --toolchain ABS_TOOLCHAIN --bundle ABS_DESCRIPTOR` |
| Admit the actual result and construct the source builder | `hia-source-bootstrap --source ABS_SOURCE --cold ABS_COLD --bootstrap ABS_BOOTSTRAP --output NEW_ABS_BUILD` |

The first stage executes the source-bound production recipe with the admitted
independent seed roots. The second runs the complete 60-phase catalog, including
independent references, B0/B1/B2/B3, the changed-source generations and all
required original/modified qualification families. Its computation deadline is
180 seconds, followed by at most three seconds to confirm process cleanup.
The third captures the actual B3 and cold report, performs strict report/source
admission before executing B3, and constructs and rebuilds the ordinary source
builder. It rechecks the captured inputs before issuing its final receipt.

The installed `hia-source-build` then compiles, packages and checks HIA source
kits and native release members. The complete release gates additionally require
the ordinary source build, package installation, Worker installation and an
installed whole-source rebuild. These stages retain their own evidence; a
successful fixed point does not imply they completed.

The cold construction output contains `cold-bundle.hiadat`, `hia-cold`,
`hia-cold-build`, `hia-source-bootstrap` and the source-bound toolchain roots.
The post-cold output supplies the ordinary native entry and its capabilities:

```sh
hia-release-build --output NEW_ABS_RELEASE --compiler ABS_B3 --cold-report ABS_FINAL_COLD_JSON --source ABS_SOURCE
```

The ordinary entry also accepts the explicit `--timeout-seconds SECONDS`
option. Its compiler and report must match the captured complete cold run.

- [Self-host compiler and complete cold contract](docs/HIA_SELF_HOSTING_CORE.md)
- [Cold toolchain build entry](docs/HIA_COLD_BUILD_ENTRY.md)
- [Post-cold source bootstrap](docs/HIA_COLD_SOURCE_BOOTSTRAP_ENTRY.md)
- [Ordinary native source builder and release member formats](docs/HIA_NATIVE_SOURCE_BUILD.md)
- [Machine-readable compiler support](docs/HIA_SELFHOST_CORE_SUPPORT.json)

## Agent and proof contracts

Agent operations bind immutable Core, artifacts, context, objective, workload,
target, installed implementation and generation. Discovery supplies the actual
tool catalog and validation profiles. Verification, emission, evaluation,
adoption, use and rollback retain distinct decisions. A serialized receipt is
evidence about its exact subject; it grants no execution authority by itself.

- [Reading scoped proof results](docs/HIA_AGENT_PROOF_RESULTS.md)
- [Independent Safe Core machine validation](docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md)
- [Explicit machine plans](docs/HIA_AGENT_MACHINE_PLANS.md)
- [Borrowed-buffer invocation and lifecycle](docs/HIA_AGENT_BUFFER_LIFECYCLE.md)
- [Planning, budgets and complete cost evidence](docs/HIA_AGENT_MACRO_POLICY.md)
- [Borrowed-byte ABI and finite bootstrap components](docs/HIA_DIRECT_BYTE_BOOTSTRAP.md)

The self-host compiler has a bounded language profile. Independent machine
validation has a narrower, separately selected model. Finite native tests,
source closure and byte fixed points do not prove the entire language, hardware
ISA or physical execution environment sound. Unsupported input, unknown proof,
expired budget and unconfirmed process termination remain explicit failures.

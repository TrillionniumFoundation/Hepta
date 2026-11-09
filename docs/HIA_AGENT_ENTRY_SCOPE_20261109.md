# HIA Agent entry and proof-scope handoff

Snapshot: 2026-11-09. Reviewed metadata main:
`0487859a143b74a2a9b33cadf465d25c5f826cc2`, merging
[PR #827](https://github.com/TrillionniumFoundation/Hepta/pull/827).
Start with [INSTALL.md](../INSTALL.md); the root README is intentionally empty.
This checkpoint neither promotes a release nor qualifies a new runtime.

## Select the installation

| Selection | Entry and exact source | Contract |
| --- | --- | --- |
| Default/current | `python3 -B tools/hia_release.py`; [hia-current.json](../releases/hia-current.json); Hepta `2598f4309791d3a023cd5df585ad26810b20c744`; bounded `selfhost-core-linux-x86_64-v9` | Read the printed lock digest, materialize this source and check both repositories. |
| Named v16 | `python3 -B tools/hia_release_v16_6ecd802.py` with the explicit [v16 lock](../releases/hia-v16-6ecd802.json) and digest; Hepta `6ecd8023615a6e0b2dc269379fb059c656b38b6f`; bounded `selfhost-core-linux-x86_64-v16` | Separate source qualification; does not replace current or activate online. |
| Development | `codex/hia-sixgap-source-5e6c-20261108`, observed at `dfde9df60e80d820e25527bc75624a063a92a36d`; [#826](https://github.com/TrillionniumFoundation/Hepta/pull/826) open at `0946d17dffc43d4ff03649e3bd73daf9612069a9` | Branches move. Record actual commit/tree, dirty state and installation identities. An open PR is not a selected release. |
| Online MCP | Retained formal readback reconciled the historical `2598f430` worker; see [release reconciliation](HIA_RELEASE_ENTRY.md#recorded-post-merge-observation--2026-11-09). A fresh attempt below failed before manifest publication. | Current identity is unestablished by this attempt. A new Agent must read an authenticated current manifest; no fresh loaded-binary or live-adoption attestation exists here. |

Both published locks select runtime
`4cd85c99c5f5a480832c48fbde8561bb365f67a9`, tree
`6b78d53b53d51a6c070bb37e8e9f6a15ad26d0e8`.
The current Hepta tree is `4c073a29839eff1e75fbcc6dd28db4108c04160c`;
the named tree is `4c51962e030e9ea39c6498224c99eb40fbdd2f35`.
Current lock SHA256:
`9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3`.
Named lock SHA256:
`b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0`.
See [the release guide](HIA_RELEASE_ENTRY.md) for exact installation commands.

A selfhost profile number is not a Core schema number. Read the selected
source's `docs/HIA_SELFHOST_CORE_SUPPORT.json`, opcode catalog and language
definitions. Do not infer syntax or coverage from the name "v16".

## CLI versus MCP

| Interface | Behavior | Retain |
| --- | --- | --- |
| `python -m hepta hia build` | CLI default is `llvm`. Explicit `--backend native` selects HIA direct generation. Shared output has a separate linker; `--linker ld` selects GNU ld. | Core/input, target/backend, object/final hashes and linker/build receipt. |
| `python -m hepta hia emit` | Emits LLVM text; does not select direct object generation. | Exact text and its separately scoped validation. |
| MCP `hia_emit` | Discovered Agent service uses direct HIA generation, with canonical lowering or an explicit checked Agent plan. | Endpoint manifest, catalog/worker/backend, context, candidate, plan, object, final artifact and build receipt. |
| MCP `hia_verify` | Each claim names an exact subject/profile. Plan preservation and independent supplied-final-ELF refinement have different assumptions. | Complete result, assumptions, checker/source/solver, queries and unproved obligations. |

For MCP, start with `hia_describe(section="manifest")`, read the issued manifest
with `hia_read`, then request language/backend/examples/plans before authoring.
Compare worker/backend/catalog identities with the chosen lock. A tool name
alone is insufficient. Verification does not grant execution/adoption authority.

Direct target: `x86_64-unknown-linux-gnu`; ELF64/AMD64, little-endian LP64,
System V AMD64. Scalar ABI:
`hepta.hia.program.direct-linux-x86_64.v1`.
Borrowed-byte exports use a separate explicit ABI profile.


A fresh read-only `hia_describe(section="manifest", max_bytes=32000)`
returned `unknown / HIA_OBSERVATION_UNAVAILABLE`, with
`stage=initial_publication cause=publication_invalid`.
The exact original request SHA256 was
`ffceea963380ffceca3c71dc86cc2532605c26bd8a389fef07703e8e18b30180`;
host `x230`, job `1a1bf5c6f26-5e21-4b8`.
Recovery of that same job reported terminal `failed`, exit code 127 and a
missing configured Python executable in
`hepta-hia-release-321daf28-6d5c/venv/bin/python`.
Both stdout and stderr were empty and at EOF. No automatic retry, source
change, context/candidate, verification, emission, evaluation or adoption
occurred. This is a current launch failure; it does not invalidate or refresh
the earlier successful historical identity capture.

## Minimum program

Complete [INSTALL.md](../INSTALL.md), then run from its materialized Hepta
source using the selected Python environment. Both published sources contain
`examples/hia_safe_core/scalar_add.hia.json`, Git blob
`7af8a569d79da97dfe35c0016384c55dab7fe33c`: primitive Core v1,
`calculate(u32,u32)->u32`, wrapping addition.

```sh
HIA_PYTHON=/absolute/new/hia-python/bin/python
HIA_EXAMPLE=examples/hia_safe_core/scalar_add.hia.json
HIA_EXAMPLE_OUT="$(mktemp -d)"
"$HIA_PYTHON" -B -m hepta hia catalog --schema hepta.hia.program.v1
"$HIA_PYTHON" -B -m hepta hia verify "$HIA_EXAMPLE"
"$HIA_PYTHON" -B -m hepta hia run "$HIA_EXAMPLE" \
  --function calculate --arguments '[35,7]'
"$HIA_PYTHON" -B -m hepta hia build "$HIA_EXAMPLE" \
  --backend native --target x86_64-unknown-linux-gnu \
  --kind object -o "$HIA_EXAMPLE_OUT/calculate.o"
"$HIA_PYTHON" -B -m hepta hia build "$HIA_EXAMPLE" \
  --backend native --target x86_64-unknown-linux-gnu \
  --kind shared --linker ld -o "$HIA_EXAMPLE_OUT/calculate.so"
```

The interpreter result should contain 42. Generation/linkage alone does not
establish a native call, independent proof or adoption. The default v9 checker
does not accept `--profile-version`, and GNU ld can emit only `.gnu.hash` while
the supplied-ELF checker requires both hash sections. Link the retained object
explicitly into a separately identified image:

```sh
ld -m elf_x86_64 -shared -z defs -z noexecstack -z relro -z now \
  --build-id=none --hash-style=both "$HIA_EXAMPLE_OUT/calculate.o" \
  -lc -o "$HIA_EXAMPLE_OUT/calculate-proof.so"
"$HIA_PYTHON" -B tools/check_hia_safe_core.py \
  --source "$HIA_EXAMPLE" --object "$HIA_EXAMPLE_OUT/calculate.o" \
  --image "$HIA_EXAMPLE_OUT/calculate-proof.so" \
  --output "$HIA_EXAMPLE_OUT/proof"
```

The proof binds `calculate-proof.so`; it does not cover a different final image.
For the automatically retained lock/proof/native-call sequence, use the
`qualify_hia_entry_proof.py` command in [INSTALL.md](../INSTALL.md). Both public
release CI rows execute this additional gate. The interrupted local checkpoint
and recovery-source scope are recorded in the
[recovery ledger](../review-evidence/hia-entry-proof-728f6e-20261109/RECOVERY.md).

Supplied-artifact profile:
`hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1`.
Agent projection:
`hia.agent.safe-core.scalar-supplied-elf.x86_64.v1`, one unsigned scalar
acyclic function without borrowed/foreign entry. The identified Python models,
ELF/x86 decoder, solver and explicit caller/stack/loader assumptions remain
trusted; complete hardware ISA refinement and execution authority are not
proved. Read the selected source's `docs/HIA_AGENT_PROOF_RESULTS.md` and
`docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md`.

Commands were checked against pinned repository definitions through reads;
they were not executed in this checkpoint after its environment became
unavailable.

## Execution, proof and adoption intersection

| Workload | Existing bounded evidence | Boundary |
| --- | --- | --- |
| Compiler buffer lifecycle | Fixed compiler Core; admitted buffer workload; identical-Core equivalence; same-implementation encoding rederivation; observed local nonproduction consumer generations | Its qualifier explicitly receives unsupported for independent full compiler lowering refinement. It does not inherit the scalar proof. |
| Agent scalar supplied ELF | Exact Core/object/final ELF; all-input model return/abort refinement, modeled memory bounds, SysV state and termination | One primitive unsigned acyclic function; no Agent borrowed/foreign entries. Model/solver soundness, real caller/loading/hardware and native resource exhaustion remain assumptions/open. |
| Adoption | Retained build/evaluation/proof references, frozen claims, ABI compatibility and conditional generation/epoch checks | A detached proof is not adoption authority. Runtime rechecks the actual candidate and receipts. |

Keep Core/input, explicit plan or canonical lowering, object, final image, ABI,
proof subject and adoption generation bound to the same artifact. Later
reemission does not replace original proof inputs. The raw borrowed-buffer
validator is not proof of the complete compiler buffer workload.

## P0-P5 status

| Priority | Snapshot | Next evidence |
| --- | --- | --- |
| P0 | #827 discovery repair merged; checked entry catalog and four-selection/CLI/MCP handoff added. Online exit-127 remains. Partial. | Exact-head current/v16 public installation plus a fresh Agent completing discovery and minimum program. |
| P1 | Scalar retained-byte proof and compiler-buffer lifecycle have distinct scopes. Local adoption identity projection was unfinished and is excluded here. | Tested same-artifact Core/plan/object/final/ABI/proof/adoption binding. |
| P2 | Nine valid-Core reference-only witness observations below. No bootstrap/native result. | Actual bootstrap combination matrix for signed, multiple results, returned resources, naming, module and calls. |
| P3 | Scoped scalar model proofs and local adoption tests do not establish general compiler soundness. Proposed richer qualifier did not complete. | Nontrivial closed family with exact proof inputs and adopted consumer, then model-to-production/ownership/loading obligations. |
| P4 | HOLD. Controlled generated narrowed-kernel full-path measurements are not a demonstrated production hotspot win. | Actual hotspot, strong matched baseline, repeated tails and full amortization costs. |
| P5 | HOLD. Existing four-arm bounded macro controls use passive feedback without optional paid READ. | Information acquisition that can change later actions under matched Agent/budget, with failures, fallback and full costs. |

The reference witness work kept the real assembly entry
`f0(readbuf,mutbuf,mutbuf)->u32`. Reference execution removed only the three
unused external entry parameters. General Core admission and expected reference
values were checked; the final column is the intended bootstrap expectation,
**not an observed bootstrap result**.

| Witness | Reference value | Intended bootstrap outcome |
| --- | --- | --- |
| unsigned-call-cfg | 17 | ACCEPT |
| owned-argument-scalar-return | 8 | ACCEPT |
| signed-helper-preserved-entry | 0 | REJECT |
| scalar-pair-helper-preserved-entry | 17 | REJECT |
| returned-owner-helper-preserved-entry | 8 | REJECT |
| returned-loan-helper-preserved-entry | 8 | REJECT |
| named-helper-preserved-entry | 17 | REJECT |
| named-module-preserved-entry | 17 | REJECT |
| named-pair-helper-preserved-entry | 17 | REJECT |

The signed row isolates the signed helper from mandatory entry ABI. The pair
row swaps 5/12 then adds. Resource rows return one resource and then close/drop
it. Helper-only rename preserves f0/module; the module row tests one name, not
module graphs/linking. The combined final row has no unique-cause claim.
These are session observations without a published complete raw archive or
successful native/bootstrap report.

The proposed scalar proof/adoption fixture was rejected for duplicate SSA names
at admission before native proof work. Its correction and second attempt did
not execute before the outage. Neither unfinished Python implementation is
included in this PR. Their native/proof/adoption qualification and local
documentation-command execution are **NOT_RUN** after interruption. The entry
adapter below has separate hosted-CI checks.

This PR changes five paths: this document, INSTALL.md, the new entry adapter,
its focused test module and the public-release workflow. The workflow retains
all seven original steps and adds one entry-catalog/minimal-CLI step. Empty
README, release locks/helpers, proof gates and online selection remain unchanged.
Hosted exact-head public-installation and CodeQL checks remain required; older
results do not qualify this head. Overall acceptance stays HOLD.

## Executable entry adapter follow-up

This PR adds `tools/hia_entry_catalog.py` and five focused
identity-boundary test methods. The standard-library adapter verifies both
original lock/helper sets, reports exact selections, syntax, target and the
scalar proof service profile, and compares a caller-supplied retained online
manifest without asserting freshness. Development inspection is explicit and
reports dirty state without inferring release qualification. It changes no
source lock, selected release helper or online runtime configuration.

The existing two-row public-installation workflow gains an additional step:
run the adapter tests, retain its catalog, execute the selected source's CLI
verification/VM, explicitly build with `--backend native --linker ld`, and
call the retained shared image for addition, zero and wraparound cases. Every
pre-existing installation, discovery, exact-source, native qualification and
installation-manifest equality gate remains. These are finite checks, not a
general machine proof or a fresh-Agent study.

The local executor remained unavailable while this follow-up was prepared.
Local checks are NOT_RUN. Only this new head's hosted CI can establish its
executed result; the initial documentation-only head's success does not
qualify these changes. The online exit-127 failure above remains unresolved.

### First executable-head workflow failure

Head `81b6d808` produced public-release run `42584887985`, which failed before
creating any jobs. Static inspection found that the new-step insertion had
omitted the original native-qualification step name and left duplicate
`shell`/`run` keys in one step. No adapter test, CLI/native example or
installation check ran in that failed workflow. The follow-up restores the
original step boundary and every original step; it needs its own exact-head
workflow run. This failure remains failed and is not relabelled by later CI.

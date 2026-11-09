# HIA Agent entry and proof-scope handoff

Snapshot: 2026-11-09. Reviewed metadata main:
`e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66`, merging
[PR #828](https://github.com/TrillionniumFoundation/Hepta/pull/828) after
[PR #827](https://github.com/TrillionniumFoundation/Hepta/pull/827)'s discovery repair.
Start with [INSTALL.md](../INSTALL.md); the root README is intentionally empty.
This checkpoint neither promotes a release nor qualifies a new runtime.

## Select the installation

| Selection | Entry and exact source | Contract |
| --- | --- | --- |
| Default/current | `python3 -B tools/hia_release.py`; [hia-current.json](../releases/hia-current.json); Hepta `2598f4309791d3a023cd5df585ad26810b20c744`; bounded `selfhost-core-linux-x86_64-v9` | Read the printed lock digest, materialize this source and check both repositories. |
| Named v16 | `python3 -B tools/hia_release_v16_6ecd802.py` with the explicit [v16 lock](../releases/hia-v16-6ecd802.json) and digest; Hepta `6ecd8023615a6e0b2dc269379fb059c656b38b6f`; bounded `selfhost-core-linux-x86_64-v16` | Separate source qualification; does not replace current or activate online. |
| Development | `codex/hia-sixgap-source-5e6c-20261108`, observed at `2e2afc1ad725db85cb8cf7eba69f657cae7c4464`; [#826](https://github.com/TrillionniumFoundation/Hepta/pull/826) merged on 2026-11-09 at 08:38:28 UTC, adding the outer-CPU accounting repair | Branches move. Record actual commit/tree, dirty state and installation identities. This source merge is separate from metadata main and does not select a release. |
| Online MCP | Retained formal readbacks match the public `2598f430` installation; a separate launch attempt below failed before manifest publication. | These observations do not establish continuous uptime, the current loaded binary or live adoption. A new Agent must obtain its own authenticated current manifest. |

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

### Retained online observations

During preparation of #828, a fresh read-only
`hia_describe(section="manifest", max_bytes=32000)`
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
occurred. This was an observed launch failure; it does not invalidate or refresh
the earlier successful historical identity capture.

The separately retained [formal readback in the #826 source merge](https://github.com/TrillionniumFoundation/Hepta/tree/2e2afc1ad725db85cb8cf7eba69f657cae7c4464/review-evidence/hia-online-fresh-20261109)
contains completed describe/read requests and the unchanged checker's
`PASS_CURRENT_INSTALLATION_READBACK` result for all three public-v9 installation
digests. Its manifest SHA256 is
`d05cf5c78bed8da1cb9486f307097e4a2303780dd76da1c7ee44bafbee08969c`.
The capture contains no timestamp establishing its order relative to the
exit-127 attempt. A matching retained response does not demonstrate repair of
that missing Python path, a newly executing worker, uptime or later state.
The same archive leaves admission freeze, complete owner inventory and
user-domain controller observation open; it records no configuration change,
restart, release promotion or adoption.

The current follow-up completed another authenticated describe/read pair,
retained in [live-observation.json](../review-evidence/hia-sixpriorities-20261109-3977/live-observation.json):
describe request `r-fb5a9ead950ceec08e2b2f8d0b92e8d6604ccc4c14352fe7149baf56eadf1edb`
and read request `r-833311467fb922a79ef147978764e6619421d09deff964aca537ab085f6cbf8f`.
The [checked entry comparison](../review-evidence/hia-sixpriorities-20261109-3977/live-entry-catalog.json)
matches all three current-v9 installation digests. This is successful
authenticated observation and retained-byte retrieval in this follow-up.
The returned immutable manifest is the same `d05cf5c7...` artifact; these
responses establish neither repair of the earlier Python path nor a newly
executing worker, loaded-binary attestation, deployment or adoption.

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
establish a native call, independent proof or adoption. A separate all-input
model check consumes exact supplied source/object/image bytes. The selected
default v9 checker's CLI has no `--profile-version` option. Its supplied-ELF
validator requires both SysV and GNU dynamic hash sections, while GNU ld 2.44
can build the shared image above with only `.gnu.hash`. For this proof path,
link the existing exact object explicitly into a separately named image:

```sh
ld -m elf_x86_64 -shared -z defs -z noexecstack -z relro -z now \
  --build-id=none --hash-style=both "$HIA_EXAMPLE_OUT/calculate.o" \
  -lc -o "$HIA_EXAMPLE_OUT/calculate-proof.so"
"$HIA_PYTHON" -B tools/check_hia_safe_core.py \
  --source "$HIA_EXAMPLE" --object "$HIA_EXAMPLE_OUT/calculate.o" \
  --image "$HIA_EXAMPLE_OUT/calculate-proof.so" \
  --output "$HIA_EXAMPLE_OUT/proof"
```

The separate proof receipt binds `calculate-proof.so`, not the earlier
`calculate.so`; preserve both final-image digests and the linker invocation.
The follow-up fresh-entry trial retained the original unsupported-option
failure, the GNU-hash-only ELF rejection and the successful same-object
both-hash validation. This explicit linking step does not alter either pinned
source or installation lock, waive a rejected image or grant adoption authority.

Supplied-artifact profile:
`hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1`.
Agent projection:
`hia.agent.safe-core.scalar-supplied-elf.x86_64.v1`, one unsigned scalar
acyclic function without borrowed/foreign entry. The identified Python models,
ELF/x86 decoder, solver and explicit caller/stack/loader assumptions remain
trusted; complete hardware ISA refinement and execution authority are not
proved. Read the selected source's `docs/HIA_AGENT_PROOF_RESULTS.md` and
`docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md`.

The original preparation checked these commands through repository reads and
did not execute them locally after its environment became unavailable. The
later exact-main hosted runs below independently executed the workflow's
minimal CLI/native program for both selected releases; this is distinct from
local documentation-command execution or a fresh-Agent study.

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
| P0 | Public discovery, checked catalog and minimum CLI/native publication PASS on exact metadata main `e2a4b4b0`; both current/v16 jobs pass. Current-follow-up authenticated manifest retrieval matches v9; online provenance has the separate limits above. | Independent fresh Agent completing discovery and minimum program; resolution of the observed launch failure and loaded-runtime provenance. |
| P1 | Prepared development source now retains explicit Core/plan/object/final/ABI/proof/generation projection; canonical and planned native adoption tests pass. Scalar and compiler-buffer proof scopes remain separate. | Publication and full compiler-buffer independent refinement; no production activation. |
| P2 | Prepared source actual B0→B3 matrix 9/9 expectations PASS; two native successes and seven valid-Core refusals; exact f0 ABI retained. | Implement rejected signed, multiresult, returned-resource and general naming/module combinations. |
| P3 | Three prepared unsigned branch/arithmetic instances (u8/u32/u64) complete all-input model proofs and 24 actual adopted-consumer observations, including rollback and lease checks. | Kernel-checked model/ISA/loader/ownership theorem chain and general compiler soundness. |
| P4 | HOLD. Controlled generated narrowed-kernel full-path measurements are not a demonstrated production hotspot win. | Actual hotspot, strong matched baseline, repeated tails and full amortization costs. |
| P5 | Separate paid-READ mechanism pilot 30/30 cells retained; real schema observation changes later actions and is charged. Trained/native NDU NOT_RUN. | Independent real tasks, matched trained NDU versus strongest controls, full costs and incremental utility. |

The following table preserves the original reference-only checkpoint. It is
superseded for finite native execution by the new matrix summarized above.
The original reference witness work kept the real assembly entry
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

The merged #828 changed five paths: this document, INSTALL.md, the new entry adapter,
its focused test module and the public-release workflow. The workflow retains
all seven original steps and adds one entry-catalog/minimal-CLI step. Empty
README, release locks/helpers, proof gates and online selection remain unchanged.
Its own final-head and actual-main hosted checks completed as recorded below;
older results are not substituted for either. Overall acceptance stays HOLD.

## Executable entry adapter follow-up

The merged #828 added `tools/hia_entry_catalog.py` and five focused
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

The local executor remained unavailable while #828 was prepared; its local
checks were NOT_RUN. Its own final-head and actual-main hosted CI establish
the executed results below. The initial documentation-only head's success is
not used to qualify the executable changes. No repair of the separately
observed online exit-127 path is established by these installation runs.

### First executable-head workflow failure

Head `81b6d808` produced public-release run `42584887985`, which failed before
creating any jobs. Static inspection found that the new-step insertion had
omitted the original native-qualification step name and left duplicate
`shell`/`run` keys in one step. No adapter test, CLI/native example or
installation check ran in that failed workflow. The follow-up restores the
original step boundary and every original step. The corrected final head and
merge have their own successful runs below. This failure remains failed and
is not relabelled by later CI.

## Exact-head and actual-main publication results

The final #828 head is `3a77d0bf7b89fc14df2510964dcfa681c0dd9cfc`.
Its merge into metadata main is
`e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66`, tree
`e800d0f3858a916628269d4b29aad0f5d5c2e111`.
Each run below completed successfully on attempt 1 at its stated exact commit.

| Subject | Public installation | CodeQL |
| --- | --- | --- |
| Final #828 head `3a77d0bf` | [42585423626](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42585423626), both selections PASS | [42585425614](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42585425614), all four jobs PASS |
| Actual metadata main `e2a4b4b0` | [42585805111](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42585805111), both selections PASS | [42585805848](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42585805848), all four jobs PASS |

Actual-main public jobs `129055224235` (current) and `129055224044` (v16)
completed every step, including the five entry-catalog test methods, selected
CLI verification and VM return, direct shared-image build with GNU ld, and
actual native calls for addition, zero and unsigned wraparound. The workflow
also retained its exact-source materialization, original native qualifier,
locked-input checks and complete installation-manifest equality gates.

These observations close the public entry/catalog/CLI-smoke publication gate.
They do not establish an independent Agent trial, current live-runtime
provenance, whole-language selfhosting, general machine correctness or P1-P5
acceptance. The source branch's later #826 merge and its CI remain a separate
subject; neither published lock changes here.

## Independent entry and executable follow-through

The new [independent Agent report](../review-evidence/hia-sixpriorities-20261109-3977/fresh-agent-REPORT.md)
retains commands, exact pinned sources, both failures, successful separate-image
proof and actual native calls. Its jsonschema 4.26.0 versus requested 4.25.1
deviation remains explicit; this is one finite Agent observation, not an exact
dependency-install reproduction or a population claim.

Prepared source changes add a reviewable same-artifact adoption projection,
actual selfhost feature matrix and a separate paid-observation runner. The
[follow-through record](../review-evidence/hia-sixpriorities-20261109-3977/README.md)
indexes results and remaining obligations. Those changes are local development
commits pending publication; existing release locks and online configuration
retain their identities. Earlier unfinished/refused observations below and above
remain historical results, not passing runs.

# Complete Worker service initialization — semantic join contract r1

Status: new source design, no generation, VM, B3, native entry or ordinary
Worker qualification. This document fixes the original operation order and
ownership boundaries before the new HIA initializer is connected. It does not
declare a high-level namespace implementation or turn a foreign test fixture
into one.

Reference: 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5,
hepta/hia_agent_service.py Git 2f56a5b4b02c54b9e56e53882db5cbd5687e4b4e,
100742 bytes, SHA256
684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330.
The complete __init__, _profiles and _examples bodies are the contract.
The immutable source inventory, actual returned values and first exception
must all remain independently observable.

## The ordinary Worker contains three distinct installation observations

main() calls installation_manifest before administrator-pin comparison and
stdin admission. HIAAgentService.__init__ then calls it again after catalog().
After service.call and service.close both return, main() calls it once more.
The initializer must not reuse the first manifest as the second, nor use a
digest or source cache instead of the third actual observation. A concurrent
installed-source change can therefore affect the retained state, side effects
and original final stale-implementation refusal.

The initializer's source-bound configuration contains the actual state-root
argument, the ordered administrator artifact-root strings, the actual numeric
digit setting and private invocation/call identity. It receives no caller
program, foreign pointer or replacement namespace registry. All result views
must come from the exact pending HIA or filesystem service in the same private
fixed invocation. Raw Graph IDs and matching header integers do not themselves
grant namespace or filesystem authority.

## Constructor order, including partially completed state

| Stage | Complete operation | State publication point |
|---|---|---|
| C0 | catalog(), full original tool catalog and its actual digest | catalog and catalog_sha256 together |
| C1 | Build name-to-tool lookup in catalog order | tools |
| C2 | Fresh installation_manifest() | identities |
| C3 | Complete AgentStore(state_root) | store only after its constructor succeeds |
| C4 | Path(root).absolute().resolve(strict=True) for every root, in input order | artifact_roots only after the complete tuple succeeds |
| C5 | is_dir() in order, short-circuit on first false | E_HIA_PROFILE / configured artifact roots must be directories |
| C6 | Complete _profiles sequence below | profiles, resources and manifest at the original points |

Do not probe the first root's directory type before resolving later roots:
the tuple comprehension finishes all resolves before any is_dir() call.
For an empty root list there are no resolve or is_dir entries.
Opening the namespace precedes all artifact-root path operations.
An initialization exception occurs before main sets service_entered, so it
must not be rewritten into the post-entry E_HIA_REQUEST_UNKNOWN response.

A private state export, if offered, distinguishes absent attributes from empty
mappings and completed prefixes. Lifetime cleanup may release native buffers
or a failed constructor's untransferred session, but may not synthesize commits,
rollback successful namespace statements, or move an existing exception earlier.

## The seven profile publications

The original bodies order is exactly:

1. compiler
2. target
3. backend
4. artifact
5. validation
6. lowering
7. plan

This is seven profiles. The eight language Core versions are a different
catalog and must not be used as this count.

All seven complete body values are constructed before profiles and
profile_artifacts become empty mappings. In particular, artifact-root count
and the actual digest([str(root) for root in resolved_roots]) are evaluated
while constructing the artifact body, before the first Store.profile call.
The digest includes its full ordinary wire call and native SHA-256; a host
must not provide a precomputed profile body or hash as an unbound integer.

For each name, in that order:

- Build exactly identifier "hia-" + name + "-v1".
- Call complete Store.profile(identifier, body), not a relational shorthand.
- Its full original order is Store.json(value, "profile"), construct the
  two-field profile reference, ordinary wire(ref).decode(), then
  INSERT OR IGNORE INTO profiles VALUES (?,?,?).
- Await actual namespace success before publishing the returned profile and
  artifact reference under that name.
- Preserve all already published earlier entries if a later call refuses.

The body values retain every current field, including explicit negative and
unsupported capability statements. Native development progress does not
authorize changing self_hosted, refinement claims, external assembler/linker
statements, proof domains, source/profile digests, or resource limits.

Static schema/description values may be held in a source-bound immutable
resource compiled from the exact original definitions. Dynamic identities,
catalog digest, resolved root count/hash and returned namespace references
must be inserted by HIA. The runtime carrier only maps issued views and
executes fixed operations; it does not interpret a dictionary-building plan.

## Nineteen discovery resources and final manifest

The six initial JSON calls are evaluated in this exact order before assigning
the newly completed resources dictionary:

| Key | Original value |
|---|---|
| schema_registry | complete schema_registry() result |
| workload_schema | WORKLOAD_SCHEMA |
| objective_schema | OBJECTIVE_SCHEMA |
| cost_policy_schema | COST_POLICY_SCHEMA |
| plan_schema | PLAN_SCHEMA |
| proof_contract | complete proof_contract_description() result |

Each calls Store.json(value, "discovery"), including its own full ordinary
wire and complete put behavior. There is no transaction invented around the
six calls. If a later expression fails, earlier effects remain, while the
resources attribute has not yet been assigned.

Then these ten installed files are read and published sequentially. Each is an
actual read at this stage, followed by complete Store.put(bytes, "discovery"),
then the one resource-field assignment:

| Key | Installed resource |
|---|---|
| assembly_grammar | docs/HIA_AGENT_ASSEMBLY.md |
| core_language | docs/HIA_PROGRAM.md |
| machine_plan_guide | docs/HIA_AGENT_MACHINE_PLANS.md |
| proof_contract_guide | docs/HIA_AGENT_PROOF_RESULTS.md |
| machine_validation_guide | docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md |
| buffer_lifecycle_guide | docs/HIA_AGENT_BUFFER_LIFECYCLE.md |
| macro_policy_guide | docs/HIA_AGENT_MACRO_POLICY.md |
| byte_bootstrap_guide | docs/HIA_DIRECT_BYTE_BOOTSTRAP.md |
| self_hosting_core_guide | docs/HIA_SELF_HOSTING_CORE.md |
| self_hosting_core_support | docs/HIA_SELFHOST_CORE_SUPPORT.json |

A source-bound executable does not justify replacing these actual installed
file reads with stale bytes from a prior request. The outer installation
observations remain separate, and the ordinary put still enforces its 64 MiB
artifact limit at the original point.

The final three resource calls, in order, are:

1. Store.json(macro_policy_guidance(identities), "discovery") -> macro_policy.
2. Store.json(complete _examples(), "discovery") -> examples.
3. Store.json(the complete original diagnostics document, "discovery") ->
   diagnostics.

The complete resource count is 6 + 10 + 3 = 19. The final manifest is a
separate Store.json call, after all nineteen fields exist, with exactly the
original profiles, profile_manifests, resources, installation, catalog digest,
cold-start list and disclosure fields. Only its actual returned reference
sets manifest.

## _examples retains every original public validation

The factory creates the complete original program.v6 discovery_identity
document with the shared u8 value parameter, identity function and ret
terminator. It then performs:

1. Complete verify_program(document).
2. Complete render_assembly(the admitted program), including the renderer's
   own verification and round-trip admission requirements.
3. A fresh explicit assemble_program(the returned assembly bytes).
4. Compare that actual assembled Core digest with the first actual program
   digest. A difference raises the original RuntimeError text:
   discovery example does not round-trip.
5. Return the full original examples object: actual admitted Core, actual
   assembly, wrong_reference text, workload, objective and cost policy.

The optional existing shared services must preserve all those calls. A bounded
selfhost compiler parser is not evidence for the general public assembler.
A fixed factory-specific HIA implementation can be reviewed as that precise
factory, but must not be advertised as a full general assembly API.

The example objective contains binary64 0.0. The same general-DataJSON/Graph
value domain used by ordinary wire is required; integer-only codecs must not
silently replace it. Actual program input/Core identities remain distinct where
the underlying admission service exposes them.

## Required complete service joins

The following are semantic services, not plans for Python to interpret.
Numeric dispatch values will be frozen only after reading the actual reusable
Graph-merge and peer interfaces; this document does not guess those ABIs.

| Service | Inputs owned by HIA | Required actual completion |
|---|---|---|
| Tool catalog | original installed catalog authority | complete catalog Graph and actual digest |
| Installation | source inventory authority | complete fresh installed-source identity value |
| Namespace open | state-root argument and private caller identity | actual ordinary high-level Store session or full exception |
| Root path | original administrator root, absolute/strict-resolve operation | issued absolute resolved path; later actual is_dir observation |
| Ordinary wire and SHA | actual Graph root/span and actual digit setting | full original wire admission, exact bytes and native SHA result |
| Profile/json/put | full value/bytes, exact kind/metadata and namespace authority | original complete high-level behavior and issued reference |
| Installed resource read | fixed installed resource name and resource authority | complete current file bytes or original filesystem exception |
| Metadata/schema | exact native source-bound metadata owner | complete original value in a general Graph domain |
| Macro discovery | actual service identities | complete original guidance value |
| Program/assembly | complete original factory input and each actual preceding result | complete admission/render/fresh-assemble values and diagnostics |
| Generic Graph composition | immutable template and issued dynamic Graph roots | complete HIA-constructed value; no runtime host dictionary filling |

Store.profile/get/json/put are owned by the namespace workstream. The Worker
may not substitute an SQL-only ACK, a Graph node or a fabricated receipt for
them. A wrapper must wait for the actual completion before committing its
state transition. Ordinary store methods retain all their own wire calls,
metadata decodes, content-key hashes and effect order even if a caller later
discards the returned value.

## Continuation custody and failure rules

There is one pending peer at a time. Requests bind initializer invocation,
call, event sequence, exact operation, full input roots/views and their issued
leases. Successful ACKs bind the actual native return/event and the exact
readonly view extent. Error ACKs forward the complete issued exception view;
the outer Worker determines whether it can form a correlated terminal report.

GROW repeats only local HIA construction or a documented same-input peer
continuation. It never repeats a completed Store.open, profile/json/put,
filesystem read, program admission, assembly call or wire/hash witness.
No cumulative command/output quota is added. Private ABI refusal, short
workspace or sequence overflow permanently retires the whole invocation;
matching header integers alone never authorize a substituted arena.

At completion the HIA owner publishes the actual initialized service state
and namespace authority for call dispatch. A report is not created in advance.
The fixed Worker must still execute full call semantics, close the service,
observe installation again, and only then run the actual report wire/stdout
path under the original failure and correlation rules.

## First independent verification panel

After actual source generation and original bounded B3 compilation, tests must
compare complete initialized values, every ordered peer input/result, partial
state at each failure point and all effects against the exact reference.
Required cases include empty/multiple roots, later resolve failure before an
earlier non-directory observation, each of seven profile failures, each of
nineteen resource failures, examples admission/render/assemble/hash mismatch,
final manifest failure, source changes between the three installation reads,
late malformed ACK, GROW without repeated effects and cleanup with a held error.

Foreign fixtures can establish the initializer's own decisions and order.
They cannot establish actual namespace, full assembly, installed source
scanning or an ordinary Worker run. Those separate complete peers must then
be joined under the fixed native carrier and tested with no Python dispatch.

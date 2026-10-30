# Focused context for existing HIA maintenance

`hepta.hia_agent_context` and `tools/hia_agent_context.py` add a usable information
tool for editing an existing primitive HIA v6/v7/v8 module. They keep the existing
`hepta.hia.patch.v1/v2` format and whole-module patch checker. They do not introduce
another language, verifier, persisted admission cache, or inferred repair.

## What the view contains

Every request first verifies the complete input module. It then returns complete,
unchanged definitions of up to 32 selected functions, the complete module snapshot
hash, the exact program envelope, direct incoming/outgoing call sites, and the
interfaces at that boundary. Interfaces include parameter names, effects, result
types and Core v8 returned-loan origins. The function inventory lets an agent ask
for other bodies when necessary.

The opcode slice includes instructions actually used by the selected functions
and any explicitly requested extra opcodes. It retains the full catalog's type,
effect, terminator, resource and semantic-contract rules. The slice has a distinct
schema and its own hash. Its `complete_catalog_sha256` is an identity for requesting
the complete catalog; it does not claim that missing instructions were provided.

This is selective information delivery. Omitted bodies may matter to a maintenance
task. A complete direct call boundary is not a complete behavioral impact analysis.
The returned context is not a standalone executable program. Hashes do not grant
admission, and no external context receipt can substitute for a full check.

```sh
python tools/hia_agent_context.py existing.hia --function helper
python tools/hia_agent_context.py existing.hia --function helper --function caller
python tools/hia_agent_context.py existing.hia --function helper --extra-opcode int.mul.wrap
python tools/hia_agent_context.py existing.hia --function helper --measure
python -m hepta hia patch existing.hia --request edit.json -o revised.hia
```

The patch's `expected_sha256` must equal the context's `snapshot_sha256`. A change
to any omitted body changes this hash too. `apply_program_patch` checks the complete
original snapshot and the complete candidate; the existing interface-preservation
policy includes returned-loan contracts. Failed or stale patches do not publish a
replacement. There is no claim that a well-typed maintenance patch is behaviorally
equivalent to its original.

## Actual payload measurement

`measure_payloads` serializes and counts the exact UTF-8 bytes of three disclosed
envelopes:

| Representation | Included information |
| --- | --- |
| Complete JSON | Complete canonical Core and complete version-specific catalog |
| Complete assembly | Checked assembly rendering and complete version-specific catalog |
| Focused JSON | Actual context envelope, boundary metadata, navigation and opcode slice |

The report also gives source-only Core/assembly byte counts and hashes of the
measured envelopes. It preserves negative savings if a focused envelope is larger.
Byte counts exclude a trailing display newline. They are not tokenizer estimates,
billing measurements, model timing, or evidence of full-task savings. Extra body or
opcode requests can erase initial savings. For example, the `wrapped_stride` task's
initial slice contains the erroneous checked multiply; discovering a different
instruction can require a catalog request.

## Fresh maintenance protocol and environment collection

`benchmarks/hia_agent_maintenance/PROTOCOL.json` specifies a prospective comparison
between complete JSON and focused JSON on two newly authored maintenance tasks:

| Task | Existing defect | Fixed contract |
| --- | --- | --- |
| `wrapped_stride` | A checked multiply traps on legitimate large inputs | Modular arithmetic for every `u32` input, with interfaces and other bodies preserved |
| `returned_view_byte` | A helper loses a stored byte's high bit | Preserve actual allocation, store/read/release and the declared returned-loan origin |

Each task contains a target, one editable helper and 24 disclosed synthetic
background functions. This inventory is fixed, but is not a representative sample
of application maintenance. Each author control executes four public and thirty
hidden cases against an independently written mathematical oracle. The resource
task observes original VM operations and requires an actual matching owner,
position and value through allocate/store/load/release, plus zero remaining local
owners and loans. Merely including resource opcodes in unused code cannot pass.

The preflight mode collects fresh author controls, actual payload bytes and
provider environment inventory:

```sh
python tools/qualify_hia_agent_maintenance.py --preflight-only --output /tmp/hia-maintenance-attempt
python tools/qualify_hia_agent_maintenance.py --preflight-only --codex /exact/path/to/codex --output /tmp/hia-maintenance-other-attempt
```

In preflight mode, `--registration-commit FULL_SHA` optionally checks all relevant
source bytes against an exact ancestor commit. The output directory must be new.
No historical model artifact is read and no model executable is invoked. Missing `codex` produces a
real `blocked` receipt with `provider_executable_missing`; a present executable
does not establish inference connectivity or authentication. Credentials are not
inspected.

## Registered actual model entry

The same collector has an implemented `--run` mode for the four registered cells:
two tasks by two initial-context arms. Publish the complete protocol, tasks, tools
and tests first, then supply the exact commit:

```sh
python tools/qualify_hia_agent_maintenance.py --run --registration-commit FULL_SHA --codex /exact/path/to/codex --output /tmp/hia-maintenance-live-attempt
```

The runner verifies that registration is an ancestor and that every bound source
file matches it. Before each provider request it rechecks the actual source bytes
and provider binary identity. It executes the original `CodexEvents/run_owned`
transport with explicit frozen byte limits, so the new study does not secretly
read the older study's protocol. Each response comes from a fresh ephemeral CLI
process in a new empty working directory. Direct CLI tools, unknown JSONL events,
malformed RPC, missing usage and uncertain process cleanup cannot qualify a cell.
The process sandbox and tool-event checks are an information boundary, not a claim
of hermetic isolation against a malicious provider or host.

Both arms can request a complete catalog, further function bodies or additional
opcode rules, and can check up to three original-snapshot patches. A final patch
is checked again, or final may name an accepted patch digest. All function
interfaces and noneditable bodies must remain unchanged. Whole-module admission
and actual public execution happen before terminal hidden execution. The hidden
results never enter another model request; there is no hidden-case retry or
host answer repair.

The evidence retains original request conversations, byte hashes, raw process
streams, exact model responses, all five usage fields, failed checks, resource
witnesses, tool feedback and terminal hidden observations. Known usage from a
failed attempt remains charged. Unknown usage makes aggregate token units null,
with known partial units retained. Cached input is not added twice; descriptive
units sum input, output and reasoning fields and are not billing estimates.
Per-cell wall time includes all context construction, checks, provider work,
cleanup and its own final evidence write. Common preparation is charged once to
each standalone arm; final aggregate write and unobserved human work remain
unknown. All four cells and complete usage are required for comparison eligibility.

The author controls and the scripted transport unit test are explicitly not model
observations; scripted control rows are ineligible for the comparison. There is no
historical-answer or author-patch fallback in the generation path. The repository's
older negative efficiency studies are not replaced. If `codex` is missing,
`--run` records `blocked`, makes zero provider requests, and exits with status 2.
Provider binary identity does not independently attest weights, routing, cache,
authentication or the provider's truthfulness.

Before the first formal run, an actual read-only probe found
`/opt/codex/bin/codex` outside PATH and confirmed the runner's argv through
`codex exec --help`. The protocol pins its observed 0.166.0-alpha.1 binary hash and
byte length. `--run` refuses a different binary; preflight explicitly distinguishes
PATH absence from the availability of an explicitly supplied path. The observed
read-only PATH-alias warning was on stderr, which is preserved. It is not silently
admitted as a stdout JSONL warning. These probes made no model requests and did
not inspect credentials or establish inference availability.

Exit zero from `--preflight-only` means its controls and evidence collection
completed. It does not mean a model was available or completed a task. The result
keeps `model_requests=0`, token/time fields null and model-efficiency claims false.
The live runner records provider request attempts separately from the transport's
observed generation events; a failed authentication attempt is not a completed
model answer. Both arms retain the same public tools and full-module verifier.

## Validation and remaining boundaries

Run the new deterministic controls with:

```sh
python -m unittest tests.test_hia_agent_context tests.test_hia_agent_maintenance -v
```

These tests cover complete checking of omitted bodies, stale snapshots, detached
views, exact byte counting, direct returned-loan dependencies, catalog-slice
identity, resource-witness rejection of scalar shortcuts, strict live RPC and
terminal hidden handling, unknown usage, explicitly ineligible scripted controls,
and absent/present executable preflight without invocation. The original default
transport and explicit-config path both have actual owned-process controls. CI preflight generates fresh
fixture/byte/control receipts on each host. No model-productivity, Rust-productivity
or native-backend result follows from these tests.

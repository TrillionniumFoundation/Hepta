# Pinned native helpers in the ordinary worker

The ordinary one-request worker can select existing HIA native kernels through
one administrator-supplied bundle. The worker remains Python, and the ordinary
eleven-tool service, SQLite transport, business methods and recovery owners
remain present. This integration does not replace the ordinary fifteen CLI
actions or convert the separate five-command native stdio protocol into them.

Pass both arguments to `python -m hepta.hia_agent_worker`:

```text
--native-helpers-manifest /absolute/operator-owned/helpers.json
--expected-native-helpers-sha256 <SHA256 of the exact helpers.json bytes>
```

The same flags apply to `--installation-manifest` and request execution. A
selected installation and terminal worker report include the optional
`native_helpers_sha256` identity. An unselected installation retains its three
existing identities. Native selection is not enabled by default.

## Bundle format and executable custody

```json
{
  "schema": "hepta.hia.native-helpers.v1",
  "target": "linux-x86_64-lp64",
  "abi": "hia-byte-six-argument-v1",
  "helpers": [
    {
      "selector": "HEPTA_HIA_AGENT_JOURNAL_MANIFEST",
      "manifest_path": "journal/manifest.json",
      "manifest_sha256": "<SHA256 of the exact child manifest bytes>"
    }
  ]
}
```

The example digest is a placeholder. Actual admission requires lowercase
64-character hexadecimal digests. Paths may be absolute or relative to the
containing pinned manifest; parent traversal and control characters refuse.
The exact allowlist is `HELPERS` in `hepta/hia_native_helpers.py`. Its twenty-nine
current single-image contracts include the original nineteen helper adapters
and the current **agent-journal-native.v2**, **execution-budget-native.v1**,
**candidate-budget-native.v1**, **retirement-state-native.v1** and
**slot-ledger-native.v1**, **native-mapping-native.v1** and
**publication-measurement-native.v1**, **scalar-profile-native.v1** and
**generation-retention-native.v1** and **bounded-memory-native.v1** owners.
A source test imports each
actual factory and checks its `.hepta` source against the packaged resources.
Unknown selectors, duplicate entries, extra fields and old journal schemas
refuse. Multi-image owners require their own explicit custody integration.
Retirement also maps its fixed 45-byte open syscall primitive from the installed
Python source closure; that primitive transports the selected HIA policy's
effect and is not another selectable policy image.

`HEPTA_HIA_NATIVE_MAPPING_MANIFEST` selects the HIA mapping parser and admission
decisions used by `verify_loaded_symbols`. The actual descriptor, seals, ctypes
entry addresses, bounded kernel maps snapshot and final descriptor readback
remain hosted. This helper uses the existing anonymous executable loader,
which does not invoke the mapping admission it supplies. The default path
retains the original Python mapping policy; a selected helper never falls back.

`HEPTA_HIA_PUBLICATION_MEASUREMENT_MANIFEST` selects the complete finite
measurement admission used before preparation and under the publication commit
lock. HIA computes paired medians and deviations, ordered refusal reasons and
exact cost projections, including intermediate products above 64 bits. The
input is the original frozen measurement envelope plus an exact integer
preparation time, transported without narrowing. Envelope capture, actual
monotonic observations, cancellation and locks, Core proofs, compilation,
loading and resource ownership remain hosted. The selected measurement owner
can only refuse publication and never substitutes for those requirements.
The ordinary default remains the original policy; an explicitly selected
helper has no fallback. The installed resource and pinned worker scope use the
same source-bound image contract, with the existing process/thread owner and
terminal identity checks.

`HEPTA_HIA_BOUNDED_MEMORY_MANIFEST` selects the HIA owner of ordinary VM
byte fills and overlapping moves. The exact-bytearray extent, exact integer
kind/sign/width/low bits and buffer address are observed by the Python bridge;
HIA performs the complete original admission order and in-place operation.
There is no additional input-size ceiling. The bridge holds the GIL and a
buffer export for the complete call. The original reference bodies are retained
as independent controls and are forbidden in the selected caller gate.

`HEPTA_HIA_SCALAR_PROFILE_MANIFEST` selects the scalar admission policy after
fresh Core verification and before the original fresh per-export Z3 proofs.
HIA owns the qualified version, export/signature/effect/operation limits,
whole-CFG acyclicity and ABI ordering. It transports no proof authority and
cannot bypass those independent proofs, compilation or publication effects.

`HEPTA_HIA_GENERATION_RETENTION_MANIFEST` selects the retained per-generation
reference count, retired state, one-close lease cells and retirement-task
handoff. HIA changes the count and cell together, with a growable exact
magnitude and no new fixed-width reference ceiling. The existing runtime
keeps its locks, current generation and epoch, cancellation and resource
effects. Preparation failures before registration retain their original
cleanup owner. Uncertain native transitions keep strong quarantined custody;
a verified no-write capacity refusal permits ordinary allocation recovery.
See the [generation retention contract](hia-generation-retention-native.md).

Selection and construction of a new runtime obey the pinned loader's original
process/thread admission and source readback. An existing runtime retains its
admitted image and original concurrent lease lifecycle, protected by its
creator-process check and locks. Changing an ambient selector does not rebind
that retained owner. This lifetime does not authorize another request to load
an unlisted image or bypass the worker's terminal identity check.

The bundle binds every child manifest; each child binds its schema, packaged
source, image and compiler digest. Only owned, bounded, ordinary files with
one link and without group/other write permission are admitted. The loader
rejects final-component symlinks and records file identity and bytes. Core
patch additionally requires its exact adjacent admission manifest in the
same bundle before any selected adapter is imported or mapped.

`HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST` selects the descriptor snapshot ABI used
by ordinary `buffer_size` and `buffer_bytes` calls, including descriptor
admission and materialization. The raw JSON snapshot program has its own
standalone interface and is not interchangeable with that descriptor ABI.
The Core patch image has two explicitly registered factory views:
`NativeCorePatch` for ordinary CLI patch calls and `NativeAgentCandidatePatch`
for ordinary Agent candidate calls. Both use the same captured image bytes;
their source and schema must match before either executable mapping is made.
Each view retains its exact manifest/source/schema/factory key. An unlisted
subclass cannot acquire the selected image through a general loader fallback.

This pins executable code chosen by the operator. It does not authenticate a
cold qualification receipt or prove the selected program correct. Production
builders separately require the matching complete-source cold admission.

## Scope and ordinary service routing

Only one worker request may hold the selection scope in a process. Its original
PID and thread own the context. Nested requests, concurrent requests, inherited
fork contexts and foreign-thread loader/identity calls refuse. Any nonempty
ambient `HEPTA_HIA_*_MANIFEST`, including an unknown name, refuses entry, whether
or not a bundle was supplied.

The scope installs the exact admitted selectors so ordinary service callers
actually enter their native adapters. Their shared loader returns the pinned
mapping before consulting its general cache. Unlisted images cannot load within
the scope, including an initially unselected scope. Terminal installation
identity checks reread the entire bundle, manifests, sources and images. A
post-effect drift produces `E_HIA_REQUEST_UNKNOWN` with `observe_original`;
it cannot attest success or instruct an automatic new mutation. Scope exit
restores the complete selector namespace, including initially empty values.

The journal's HIA source binds the exact tool catalog bytes. Adding the optional
bundle identity therefore regenerates the current journal's catalog constants;
an older journal image is correctly refused with the new catalog.

## Verification

`tests/test_hia_worker_native_helpers.py` exercises real HIA identity, request
and current journal and execution-budget images through the original worker and service. Controls
include hosted-reference refusal, SQLite mutation counts, restart/replay,
conflicts, post-effect image drift, cache precedence and process/thread custody.
The combined control poisons both hosted journal and budget owners, performs
an actual native evaluation, checks the original SQLite budget and request
rows, then restarts the original worker and observes the same response without
executing the child again. The installed bundle control additionally uses
packaged journal/budget sources with all authoring imports forbidden; its small
budget accounting outcome is an explicitly labeled host fixture, separate
from the real native evaluation control.
The installed-resource regression retains its real wheel installation and
native helper calls with authoring modules unavailable.

`NativeWorkerCallerViewTests` exercises the original buffer callers and both
patch views in one real bundle. It checks descriptor boundaries and refusals,
all four Agent patch forms with the hosted payload owners disabled, a stale
patch that publishes no candidate, and durable replay without a second native
patch execution. It also refuses unlisted factories and a missing or misplaced
adjacent admission manifest. The explicit development-image mode is mutually
exclusive with a requested matching-source cold report.

`tests/test_hia_candidate_budget_native.py` selects candidate counts, execution
budgets, the v2 journal and retirement in one pinned bundle. It disables all four
hosted policies, builds candidates through the original service, executes an
actual native evaluation, and checks original SQLite counts across service and
worker replay. A second control runs the original multiversion rollback test:
the old native generation stays callable through its existing lease and retires
when that lease exits. Those controls exercise the existing service and loader;
they do not establish that either has been rewritten in HIA.

The required CI and complete qualification runner select
`HEPTA_HIA_WORKER_HELPERS_COLD_REPORT`, `HEPTA_HIA_WORKER_REQUEST_COLD_REPORT`
`HEPTA_HIA_AGENT_JOURNAL_COLD_REPORT` and `HEPTA_HIA_EXECUTION_BUDGET_COLD_REPORT`
from the same current-source replay.
The candidate composition step uses `HEPTA_HIA_CANDIDATE_BUDGET_COLD_REPORT`
to build all four selected state-owner images from that same replay.
The slot-ledger composition step uses `HEPTA_HIA_SLOT_LEDGER_COLD_REPORT`
and the same current-source cold report for the journal, execution budget,
candidate budget, retirement and worker helper controls. The
[slot-ledger contract](HIA_SLOT_LEDGER_NATIVE.md) preserves the original SQLite
connection and the adoption/rollback request transaction. Its lease decisions
do not replace the separate in-process multiversion runtime or the process owner.
The helper CI step requires a complete nonempty run and no failures, errors,
skips, expected failures or unexpected successes. Explicit development images
and local B0/B1/B2 builds remain development observations; they cannot override
a requested cold report or establish whole-product native completion.

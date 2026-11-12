# Pinned native helpers in the HIA MCP worker

The existing Runtime still owns MCP negotiation, authorization, durable process identity, cancellation, observation and terminal-report admission. The one-request Python worker can now select explicitly installed native HIA helper images through an operator-pinned bundle. This does not describe a completely native worker or journal.

## Fixed public interface

Configure both Runtime fields together:

```json
{
  "native_helpers_manifest": "/absolute/operator-owned/helpers.json",
  "native_helpers_sha256": "<SHA256 of the exact helpers.json bytes>"
}
```

The manifest must be readable under the configured worker host's existing path policy and must be outside its mutable state directory. These fields are administrator configuration; HIA tool arguments cannot provide or override them. When both are absent, they are omitted from profile serialization, preserving the existing request/profile identity representation.

A version-one bundle has exactly these fields:

```json
{
  "schema": "hepta.hia.native-helpers.v1",
  "target": "linux-x86_64-lp64",
  "abi": "hia-byte-six-argument-v1",
  "helpers": [
    {
      "selector": "HEPTA_HIA_AGENT_IDENTITY_MANIFEST",
      "manifest_path": "identity/manifest.json",
      "manifest_sha256": "<SHA256 of that exact child manifest>"
    }
  ]
}
```

An absolute child path or a path relative to the bundle directory is accepted. Traversal and control characters are refused. The child's existing contract fixes its HIA source digest, image digest, compiler digest, image path and schema. Version one supports only the nineteen enumerated single-image adapters using the existing six-argument byte ABI, including the retained `HEPTA_HIA_WORKER_REQUEST_MANIFEST` owner. The composite type owner, the three multi-image composite owners, and the additional nominal, record, enum and task dependency sets are outside this bundle version. External executable publishers, namespace, journal, retirement and budget composition are also outside it.

A native Core patch selection additionally requires the exact adjacent `admission-manifest.json` as an independently pinned Core-admission member. An incomplete dependency set is refused before importing selected adapters or creating executable mappings.

## Custody and identity

The worker checks the bundle's exact bytes, every child manifest, the current HIA source and the complete image bytes. Files must be bounded ordinary files owned by the executing user or root, without writable group/other modes, final symlinks or multiple hard links. The existing loader verifies the Linux x86-64 LP64 platform and maps the admitted bytes read/execute after writing them.

The worker retains strong references to those exact mappings for the request. Its loader hook precedes the general loader cache, so an old cached mapping cannot override a new pinned bundle. A path outside the selected set cannot load another native owner. Input snapshots and selected environment values are checked again before terminal success is attested.

The extra `native_helpers_sha256` appears only when a bundle is configured:

- in the worker's installation manifest;
- in the Runtime-bound worker report;
- in the service's retained contexts, native artifact metadata and proof installation scope.

The proof checker's separate `native_selection_sha256` identifies its actual twenty-six Core-owner selections and immutable mappings. Both composite owner families and the task helper cache are included in that checker closure. This is a different digest from the whole helper bundle. The two inventories intersect in eleven selectors: eight bundle helpers are outside the Core checker inventory, and fifteen checker owners are outside this single-image bundle version. Recording a checker's selected images does not make that entire dependency set admissible as a worker bundle.

A digest identifies bytes and a selected implementation. It does not establish the soundness of those implementations or grant execution authority.

## Worker and consumer entry points

Runtime supplies the fixed flags:

```text
--native-helpers-manifest /absolute/operator-owned/helpers.json
--expected-native-helpers-sha256 <exact digest>
```

The same pair is supported by `--installation-manifest`, allowing candidate preparation to measure the actual selected installation before any service action. Ambient helper selector variables are refused at this worker boundary, including the previously direct worker-request selector. To use the existing native request owner, include its five-field child manifest as a `HEPTA_HIA_WORKER_REQUEST_MANIFEST` member in the explicit bundle. The native HIA image still owns request syntax, canonical digest bytes and admission. The worker's journal, response serialization and process owner retain their prior responsibilities.

A separately authorized local consumer uses the same scope for the full lifetime of its service and leases:

```python
from hepta.hia_native_helpers import native_helpers_scope
from hepta.hia_agent_service import HIAAgentService

with native_helpers_scope(bundle_path, expected_bundle_sha256):
    service = HIAAgentService(state_root, artifact_roots=artifact_roots)
    try:
        # acquire_slot / invoke_lease / release_slot keep their existing rules.
        ...
    finally:
        service.close()
```

Changing a helper bundle changes the installation identity. Old proof receipts do not become evidence for the new implementation. Original durable operation identities remain the recovery reference.

## Outcomes and qualification limits

| Observation | Treatment |
| --- | --- |
| Missing pair, wrong bundle/manifest/source/image pin or unsupported selector | Refuse admission before entering the service |
| Native inputs change after the service has been entered | Retain an unknown outcome and observe the original operation |
| A backing image file changes after mapping | The current mapping stays exact; terminal identity recheck refuses to attest successful unchanged execution |
| The same mutation key is replayed after a worker process restart | Observe the existing durable request; a changed body conflicts |
| No bundle is configured | Original three-field installation and report representation |
| Selected helper executes correctly | Evidence for that helper and path, not for a wholly native stack |

`tests/test_hia_worker_native_helpers.py` builds a real HIA scalar-identity image and exercises the actual worker, restart/replay, post-effect drift and refusal controls. `tests/test_hia_agent_identity_native.py` retains the original no-host-fallback and fresh-process forbidden-import assertions.

The retained worker-request integration fixture now supplies a pinned bundle
instead of setting an ambient selector. Its request, replay/conflict, correlation,
malformed-input, missing-manifest, unknown-outcome and installed-resource assertions
are unchanged. Its separate adversarial request tests are unchanged. This is an
explicit interface setup migration, not a claim that the original fixture runs
unmodified. New controls exercise the request mapping ahead of the ordinary
loader cache, refuse ambient selection with and without a bundle, and lose the
post-effect image attestation while preserving the original durable result.

For bounded development runs, the helper fixture can use
`HEPTA_HIA_WORKER_HELPERS_DEVELOPMENT_MANIFEST` for an already built identity
image. The request fixture retains its separately named development/cold options
and rejects simultaneous development and cold selection. Every such development
input still passes its installed source/image loader. The default helper fixture
retains its original B0/B1/B2 build. A development manifest does not qualify the
current compiler, current whole-source cold gate or complete worker.

## v68 integration status

The later pending v69 registration adds the full Core execution and complete
structural-budget images. The bundle inventory now has 21 single-image helper
kinds; the checker binds 28 native owner selections and the static/heap Python
continuation dependencies. Installed static controls select both static policy
and execution images from one exact bundle, forbid authoring imports and all
retained structural entry points, and compare complete reports to independently
obtained originals. The heap and final serialization continuations remain
explicit foreign dependencies. This registry extension grants no default
migration or matching-source cold qualification.

The integration starts from the retained v67 owner tree and the real candidate
merge at `8dae9d0b74f8520d1522548e0a04c0c077b3f074`, whose common ancestor is
`5831f52fada45e076f8f68f198a15c0585e6104f`. All retained owners and native resources
remain present. The explicit source inventory keeps the original 550 paths and
adds the candidate's 19 additional paths; the original 50 native source assets
include all 34 candidate assets. The subsequent v67 custody correction is merged
as its own ancestry before a final combined source freeze.

The original candidate omitted the native request owner from its bundle registry
and omitted twelve source dependencies and eleven verifier selectors from its
checker inventory. The latter omission was reproduced with an actual immutable
nominal-function HIA mapping and an actual Agent Core-admission receipt: changing
that selection left the old identity unchanged and the old receipt accepted.
Both observations are retained separately from corrected observations. The
corrected checker binds actual mapped bytes, including warm cached mappings;
manifest text alone is insufficient.

This source profile remains `v68-pinned-worker-integration-pending`. The original
joint CI evidence belongs only to its exact Hepta `8dae9d0b...` / Runtime
`9a430211...` pair. It is not qualification of the merged source, the added request
binding or the expanded checker closure. Fresh complete-source cold, retained
regression and actual Runtime/worker joint qualification remain required after
the final combined source freeze. No existing timeout or quota is relaxed.

The candidate-bindings workflow records source SHA/tree, raw output, exact counts and shared-catalog regeneration. It does not replace the original full cold replay, language coverage, native integration, real MCP lifecycle or production deployment gates. The original cold budget stays 180 seconds. No speedup, net optimization benefit, all-input equivalence, universal compiler correctness or whole-stack rewrite follows from this integration.

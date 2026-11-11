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

An absolute child path or a path relative to the bundle directory is accepted. Traversal and control characters are refused. The child's existing contract fixes its HIA source digest, image digest, compiler digest, image path and schema. Version one supports only the eighteen enumerated single-image adapters using the existing six-argument byte ABI. It does not implicitly support the four multi-image composite checker owners or external executable adapters.

A native Core patch selection additionally requires the exact adjacent `admission-manifest.json` as an independently pinned Core-admission member. An incomplete dependency set is refused before importing selected adapters or creating executable mappings.

## Custody and identity

The worker checks the bundle's exact bytes, every child manifest, the current HIA source and the complete image bytes. Files must be bounded ordinary files owned by the executing user or root, without writable group/other modes, final symlinks or multiple hard links. The existing loader verifies the Linux x86-64 LP64 platform and maps the admitted bytes read/execute after writing them.

The worker retains strong references to those exact mappings for the request. Its loader hook precedes the general loader cache, so an old cached mapping cannot override a new pinned bundle. A path outside the selected set cannot load another native owner. Input snapshots and selected environment values are checked again before terminal success is attested.

The extra `native_helpers_sha256` appears only when a bundle is configured:

- in the worker's installation manifest;
- in the Runtime-bound worker report;
- in the service's retained contexts, native artifact metadata and proof installation scope.

The proof checker's separate `native_selection_sha256` identifies its actual fifteen Core-owner selections and immutable mappings. It is a different digest from the whole helper bundle. The two inventories intersect in eleven selectors: seven bundle helpers are outside the Core checker inventory, and four composite checker owners are outside this single-image bundle version.

A digest identifies bytes and a selected implementation. It does not establish the soundness of those implementations or grant execution authority.

## Worker and consumer entry points

Runtime supplies the fixed flags:

```text
--native-helpers-manifest /absolute/operator-owned/helpers.json
--expected-native-helpers-sha256 <exact digest>
```

The same pair is supported by `--installation-manifest`, allowing candidate preparation to measure the actual selected installation before any service action. Ambient helper selector variables are refused at this worker boundary.

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

The candidate-bindings workflow records source SHA/tree, raw output, exact counts and shared-catalog regeneration. It does not replace the original full cold replay, language coverage, native integration, real MCP lifecycle or production deployment gates. The original cold budget stays 180 seconds. No speedup, net optimization benefit, all-input equivalence, universal compiler correctness or whole-stack rewrite follows from this integration.

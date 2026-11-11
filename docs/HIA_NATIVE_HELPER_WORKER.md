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
The exact allowlist is `HELPERS` in `hepta/hia_native_helpers.py`. Its twenty
current single-image contracts include the original nineteen helper adapters
and the current **agent-journal-native.v2** owner. A source test imports each
actual factory and checks its `.hepta` source against the packaged resources.
Unknown selectors, duplicate entries, extra fields and old journal schemas
refuse. Multi-image owners require their own explicit custody integration.

The bundle binds every child manifest; each child binds its schema, packaged
source, image and compiler digest. Only owned, bounded, ordinary files with
one link and without group/other write permission are admitted. The loader
rejects final-component symlinks and records file identity and bytes. Core
patch additionally requires its exact adjacent admission manifest in the
same bundle before any selected adapter is imported or mapped.

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
and current journal images through the original worker and service. Controls
include hosted-reference refusal, SQLite mutation counts, restart/replay,
conflicts, post-effect image drift, cache precedence and process/thread custody.
The installed-resource regression retains its real wheel installation and
native helper calls with authoring modules unavailable.

The required CI and complete qualification runner select
`HEPTA_HIA_WORKER_HELPERS_COLD_REPORT`, `HEPTA_HIA_WORKER_REQUEST_COLD_REPORT`
and `HEPTA_HIA_AGENT_JOURNAL_COLD_REPORT` from the same current-source replay.
The helper CI step requires a complete nonempty run and no failures, errors,
skips, expected failures or unexpected successes. Explicit development images
and local B0/B1/B2 builds remain development observations; they cannot override
a requested cold report or establish whole-product native completion.

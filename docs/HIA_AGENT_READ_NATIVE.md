# Native ordinary artifact reads

The HIA `agent_read.hepta` image owns page and cursor decisions for the ordinary
`hia_read` tool and its resource-read caller when the operator selects its
pinned helper. The ordinary CLI, worker, request envelope, issued-artifact
store and SQLite engine remain hosted. An unselected source checkout or wheel
continues to use the retained reference method. This component is not
whole-product native acceptance or production activation.

## Ownership and unchanged public inputs

The existing tool catalog admits `max_bytes` from 512 through 65,536, with
65,536 as the default. Its JSON integer validation accepts finite integral
binary64 values and rejects booleans; the bridge retains the original
`int(max_bytes)` conversion after admission. Artifact references retain their
exact three issued fields: `id`, `sha256` and `uri`.

The adapter captures the full argument mapping and full reference mapping
before calling the original `AgentStore.get`. Missing or extra reference
fields still reach the original shape checks. The original store remains
responsible for namespace authority, immutable file custody, digest checking
and metadata decoding. These checks run before cursor lookup and admission,
as in the reference method. The existing 64 MiB artifact bound is preserved.

The selected HIA image receives immutable request metadata and the entire
captured artifact, with a separate private output/workspace buffer. It owns:

- Exact cursor row identity comparison against the issued artifact.
- Signed SQLite INTEGER offset slicing, including negative retained offsets.
- UTF-8 classification of the complete artifact, including bytes beyond the
  requested page. Any invalid byte selects base64 for the page.
- Original UTF-8 page trimming, base64 conversion and the original repeated
  halving of a page whose two JSON representations exceed 230,000 bytes.
- Canonical cursor JSON, SHA-256, the `page-` cursor identifier and the exact
  row values for the next offset.
- The returned reference, encoding, page content and optional next cursor.

The bridge decodes the native result and issues the existing parameterized
cursor SELECT and INSERT OR IGNORE statements on the same captured connection.
It does not open or commit a transaction and does not replace existing request
locking. A selected-image or custody failure propagates; it does not call
`_reference_hia_read`. The existing request owners retain their replay and
unknown-outcome responsibilities.

The compatibility claim concerns catalog-admitted calls and issued store
state. Direct private calls outside the catalog range and manually corrupted
non-INTEGER cursor rows are not a claim of identical Python exception behavior.

## Installation and explicit selection

The schema is `hepta.hia.agent-read-native.v1`, the factory is
`NativeAgentRead`, and the selector is `HEPTA_HIA_AGENT_READ_MANIFEST`.
The builder `tools/build_hia_agent_read.py` requires an exact compiler image
and a complete matching-source cold report. It verifies all declared build
inputs before and after compilation and records the real compile receipt.
The generated image is admitted by the existing six-argument byte ABI.

For the ordinary installed worker, include the read child manifest in the
administrator's native-helper bundle and pass both existing options to
`python -m hepta.hia_agent_worker`:

```text
--native-helpers-manifest /absolute/operator-owned/helpers.json
--expected-native-helpers-sha256 <SHA256 of the exact bundle bytes>
```

The bundle scope is entered before installation identity and service creation.
It pins the child manifest, packaged `.hepta` source, image and compiler
digest. Ordinary tool arguments contain no executable path or per-call
selection. Ambient selectors cannot override the pinned worker bundle.
The [helper contract](HIA_NATIVE_HELPER_WORKER.md) defines scope ownership,
terminal identity checks and failure behavior.

Adding this optional native owner does not make a wheel without a bundle
native by default. It does not introduce automatic discovery of adjacent
executables or deny otherwise valid unselected calls.

## Qualification scope

`tests/test_hia_agent_read_native.py` covers generated source and the actual
native byte interface against the retained page algorithm and independent VM
observations. `tests/test_hia_agent_read_native_integration.py` exercises
ordinary tool/resource callers, real SQLite cursor state and restart, error
ordering, frozen arguments during file reads and the installed worker with
the hosted page owner forbidden.

Matching-source runs use `HEPTA_HIA_AGENT_READ_COLD_REPORT`.
An explicit `HEPTA_HIA_AGENT_READ_DEVELOPMENT_COMPILER` is mutually exclusive
with that selector and remains a development observation.
`HEPTA_HIA_AGENT_READ_EVIDENCE` selects the evidence output directory.

Source generation or structural acceptance alone does not establish native
equivalence. Actual native, installed-caller and complete retained outcomes
belong to the exact source and inputs recorded in their receipts. The
[current status index](CURRENT.md) reports those observations and remaining
whole-product boundaries.

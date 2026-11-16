# HIA discovery JSON component

The explicit discovery image owns the successful capabilities and opcode-catalog
JSON algorithms for the immutable metadata compiled from this source revision.
It selects one of all eight primitive schemas (or default v8), filters fields,
sorts object keys and type arrays, emits the original pretty JSON, constructs
the original canonical form, and computes SHA-256 inside HIA. It stores one
structured metadata table, not nine finished answers or catalog digests.

The ordinary `hia capabilities` and `hia catalog` commands can explicitly select
this source-bound component with `HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST`. Both the
retained parser and the selected HIA CLI control/format bundle support this
selection. The original fifteen-action parser, Unicode and color rules, errors
and stdout encoding retain their behavior. An absent selector keeps the current
Python dictionary APIs and dynamic providers. A present empty, missing, stale or
invalid selection fails closed without consulting those providers.

The selected profile uses immutable metadata compiled from the checked-in
source. Python provider replacement and mutable metadata are outside that
explicit profile. The public `agent_capabilities()` and `opcode_catalog()` APIs
still return their original dictionaries; only the CLI's internal output path
carries completed native UTF-8 bytes. HIA constructs all successful JSON and
catalog hashes. The bridge decodes the completed bytes and preserves the
original text stream's content and final newline.

## Build and select

After a real matching-current-source cold qualification has completed, build:

```sh
python tools/build_hia_cli_discovery_json.py --compiler /absolute/cold/B3.image.bin --cold-report /absolute/cold.json --output /absolute/new-discovery-build
```

The builder admits the original outer and nested cold reports, all three actual
equal compiler images, every current cold source and all owner inputs before
creating output. The actual B3 compiles the complete canonical HIA under the
original 20-second and 1 MiB bounds. The native request, receipt, full output,
compiled image and all publication bytes are read back. A separately named
`build_development` Python API records development provenance; the production
qualifier rejects that scope and has no development command-line option.

An explicitly selected local artifact is trusted executable code, not a sandbox
for untrusted images. Select the source-bound image through the installed API:

```python
from hepta.hia_cli_discovery_json_native import installed_cli_discovery_json
owner = installed_cli_discovery_json('/absolute/new-discovery-build/manifest.json')
capabilities_utf8 = owner.capabilities_json()
catalog_v8_utf8 = owner.catalog_json(b'hepta.hia.program.v8')
```

For the ordinary command, use the same explicit manifest:

```sh
HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST=/absolute/new-discovery-build/manifest.json hia capabilities
HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST=/absolute/new-discovery-build/manifest.json hia catalog --schema hepta.hia.program.v8
```

A separately selected `HEPTA_HIA_CLI_MANIFEST` composes the existing HIA parser
and formatter with this JSON owner. No manifest is selected automatically. This
component is not registered in the worker helper bundle. Its loader consults
the existing pinned-image scope before file access, so an unbound selection in
an active worker scope is rejected before executable mapping.


Every selection rereads the package-owned source, manifest and image. A held
owner keeps its actual immutable image. Missing or changed package resources
never fall back to a checkout or to Python JSON policy. The canonical asset is
one `NATIVE_SOURCE_FILES` resource with a real same-stem runtime bridge; the
existing eleven packaging roles remain distinct. A wheel includes the source
under `hepta/_data/examples/hia_bootstrap/cli_discovery_json.hepta`.

## Buffer contract

The ordinary Core entry is `f0(readbuf, mutbuf, mutbuf) -> u32` with distinct
physical owners. The request contains four little-endian u64 words followed by
the schema bytes: magic `HCLJSON1`, operation (1 capabilities, 2 catalog), mode
(0 absent, 1 explicit), and payload length. An explicit catalog schema is one
of `hepta.hia.program.v1` through v8. Absent catalog schema selects v8.

Workspace is at least 131072 bytes. The public wrapper and original child keep
the existing 1 MiB allocation ceiling. Successful output is the exact pretty
UTF-8 JSON followed by one newline. HIA constructs it in private workspace and
copies only after checking the final output capacity. Output is unchanged on
short output; early request/schema/workspace refusals change no buffer. Status
codes are ffffffff (frame), fffffffe (output), fffffffd (schema), fffffffc
(workspace), and fffffffb (static table bound). These are component statuses,
not an invented substitute for the original CLI diagnostics or exit values.

## Qualification and remaining scope

```sh
python tools/qualify_hia_cli_discovery_json.py --cold-report /absolute/cold.json --evidence /absolute/new-discovery-evidence
```

The strict qualifier builds a fresh matching-cold fixture, then runs four
independently supervised groups: all original 61 isolated native observations;
all original six independent VM full-buffer comparisons; the public byte API
with old Python semantic bodies and JSON construction poisoned; and a real
wheel build/install with no checkout resources, no site packages, empty PATH,
fresh drift refusals and held-image observations. All ordered test IDs and all
failure/skip/expected-failure/unexpected-success sets are checked. Each group
retains 180+3 seconds, native children 20 seconds, VM 10 million steps, 8 MiB
heap and call depth 128. Failed groups remain recorded; later groups are still
attempted. The JSON algorithm has not been granted more fuel.

The additional ordinary-entry qualifier independently builds the CLI companion
images from the same current cold compiler and runs all ten original successful
outputs through both CLI routes, with Python capabilities/catalog bodies and
JSON construction forbidden. It also compares parser errors/help and observes
empty or missing manifest refusals, under a separate 180+3-second owned process.

```sh
python tools/qualify_hia_cli_discovery_callers.py --cold-report /absolute/cold.json --evidence /absolute/new-discovery-callers
```

The unmodified full retained test runner may provide
`HEPTA_HIA_CLI_DISCOVERY_JSON_COLD_REPORT` plus
`HEPTA_HIA_CLI_DISCOVERY_JSON_EVIDENCE`. This explicit cold report is mutually
exclusive with an existing `HEPTA_HIA_CLI_DISCOVERY_JSON_COLD_FIXTURE` and the
development manifest. Empty selections are rejected. After that runner has
completed its same-run cold step, each test class prepares its own exclusive
matching-cold fixture below the evidence root. The ordinary-entry class also
builds and checks both CLI companions from that same compiler. This setup
interface adds no test filtering and does not replace the separately bounded
four-group qualification above.

## Imported source and qualification limits

The HIA source and original 61-case fixture are retained byte for byte from
`26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d` (R20). Git blob IDs and SHA256 values
for all eleven original files are recorded in
`tests/fixtures/hia_cli_discovery_r20_import.json`. The HIA source SHA256 is
`8e14590337e501c2315befe8dea1df9f6e7b02dbda28ca82d54b2f20959ed543`; it contains
39 functions, 256 blocks and 5476 operations, with maximum SSA index 540.

Integration preserves the current `0daf86d` CLI control and format assets and
all existing tests. The imported test's branch-specific R20 CLI snapshot guard
is adapted to the exact integration baseline and permits only five recorded
opt-in hook edits. Its pinned inverse is
`tests/fixtures/hia_cli_discovery_0daf_baseline.json`. The original 61 frames,
six VM labels, complete buffer comparisons and execution limits are unchanged.
The R20 fixed-word authoring helper and complete compiler-output admission are
local to the new component; existing SHA, compiler and runtime owners keep
their baseline implementation. Package resources use the baseline's eleven
roles. The current nominal receipt validator supplies the identical complete
compiler/source/image binding checks without importing unrelated R20 features.

R20's native CI run `43560753071` failed in the earlier Store namespace caller
step; discovery JSON and all later native steps were skipped. That run is not
positive qualification for this component. A final complete source tree must
pass its own matching-cold qualification. Source-only controls and explicitly
labelled development executions do not supply cold authority. Build,
generation, qualification and mechanical Python image loading remain hosted.
Whole CLI, physical process entry and whole native delivery remain incomplete.

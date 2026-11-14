# HIA discovery JSON component

The explicit discovery image owns the successful capabilities and opcode-catalog
JSON algorithms for the immutable metadata compiled from this source revision.
It selects one of all eight primitive schemas (or default v8), filters fields,
sorts object keys and type arrays, emits the original pretty JSON, constructs
the original canonical form, and computes SHA-256 inside HIA. It stores one
structured metadata table, not nine finished answers or catalog digests.

This component does not switch the ordinary `hia` command. Its fifteen-action
parser, Unicode and color rules, errors, stream encoding and dynamic Python
providers retain their original source bytes. The new API returns UTF-8 JSON
bytes; it is not the old dictionary-returning Python API. Replacing a provider,
mutating its metadata or observing an intermediate dictionary is outside this
new immutable-source component, and remains the responsibility of the unchanged
ordinary entry. No text carrier is substituted for an observable dictionary.

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

Every selection rereads the package-owned source, manifest and image. A held
owner keeps its actual immutable image. Missing or changed package resources
never fall back to a checkout or to Python JSON policy. The canonical asset is
one `NATIVE_SOURCE_FILES` resource with a real same-stem runtime bridge; the
existing twelve packaging roles remain distinct. A wheel includes the source
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

R5's independent development record is 61/61 native and 6/6 VM, with all prior
fuel failures retained. This new production wiring requires its own execution.
A matching-cold positive is pending a final complete source tree and its real
cold report. Source-only negative controls or a development image do not supply
that authority. Build/generate/qualification and mechanical Python image
loading remain hosted. Whole CLI, argv/environment/fd2 physical entry and whole
native delivery are not declared complete by this component.

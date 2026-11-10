# Native Core workspace JSON linker

`core_workspace_json.hiaasm` consumes `hepta.hia.core-workspace.v1` JSON and
emits linked primitive Core JSON. Syntax/Unicode/duplicate-key checking, exact
workspace/module/import framing, fact encoding, the existing mandatory HIA
module graph policy, capture-avoiding public ABI names, call substitution and
serialization execute in HIA, without a foreign JSON object graph.

The generator relocates the existing graph into private arena regions. Every
relocated helper receives **one mutable buffer**; it never supplies overlapping
loans as distinct arguments or waives a Core resource check. Region sizes are
checked before writes. Immutable graph bases can be hoisted to scalar locals.
The existing graph image remains an independent control, not a fallback.

Existing bounds remain: 8 MiB input, 1024 modules, 1024 functions, 4096 imports,
16384 calls, 1024 exports; JSON retains 1048576 nodes and depth 128. Primitive
Core versions v1–v8 are retained; mixed versions and nominal linking remain
outside this workspace profile. Linked JSON has an explicit 8 MiB output bound
and exhaustion refuses, never accepts truncation. Each invocation has private
decoder/graph/name storage. The host independently verifies the emitted Core,
including types, ownership and returned-loan origins, before compilation.

Build only from a completed matching cold qualification:

```sh
python -B -m tools.build_hia_core_workspace_json --compiler /path/B3.bin \
  --cold-report /path/cold.json --output /path/workspace-image
python -B -m tools.compile_hia_core_workspace --source workspace.json \
  --workspace-json-manifest /path/workspace-image/manifest.json \
  --frontend-manifest /path/frontend/manifest.json --compiler /path/B3.bin \
  --output /path/workspace-build
```

Workspace JSON and older graph-only manifests are mutually exclusive. A failed
selected image never falls back to host workspace materialization. The older
graph-only build is still explicitly selectable and host-dependent. No service
or product default is activated by this component.

Controls include whole-source VM interpretation **before seed compilation**,
complete independent native fact/result bytes, all primitive versions, escaped
names, public `fN` capture/128-byte names, actual original/modified ELF ABI calls,
invalid framing/duplicate keys, privacy/name/cycle/unresolved-call rejection,
and valid/invalid cross-module read/mutable returned loans. The entire 1024
module/4096 import case keeps the existing 10 CPU seconds and 256 MiB limits;
small successes cannot replace that witness. Development failures are retained
separately and are not qualification passes.

OPEN: native general Core verification; nominal/package/filesystem modules;
incremental/build locks; host-free build/install; remaining Agent/persistence;
whole exact-source regression; applicable platform/clean-machine real projects;
no-fallback defaults and old-production removal. This component is not whole
workspace/build/install or whole HIA closure.


## Explicit standalone inline-workspace linker

`tools.build_hia_core_workspace_json_cli` builds `hia-workspace-json` from a
completed, exactly source-matched cold compiler. The HIA packer embeds the
same complete JSON/graph/materialization image in a syscall-only Linux x86-64
ELF. With an empty PATH, the copied executable consumes inline workspace JSON
on stdin and emits linked primitive Core JSON on stdout, without loading a
foreign parser, interpreter, filesystem payload or second executable.
Original 8-MiB / 1M-node / depth-128 transport and all module/import/function/
call/export bounds are retained. EINTR is retried; nonblocking partial output
ends with nonzero status. Syntax and graph refusals publish no JSON, but this
is not an atomic filesystem publication protocol.

**Output is not a general Core type/resource verification receipt.** This
linker preserves all body operations; a malformed scalar or unsafe borrowed
result must still be rejected by the general Core consumer. The native JSON
compiler remains its existing explicitly bounded compiler profile, not a
substitute for the general verifier or nominal elaboration. Independent
workspace-to-native-compiler-to-ELF tests execute original/modified/reordered
projects and public `work` ABI calls; the shared library link is still a host
build/test bridge. Build, install custody, defaults and whole product closure
remain OPEN. No old production implementation is retired here.

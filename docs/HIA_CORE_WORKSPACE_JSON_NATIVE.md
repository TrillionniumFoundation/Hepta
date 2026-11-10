# Native Core workspace JSON fact transport

This explicit candidate accepts `hepta.hia.core-workspace.v1` JSON and emits the
exact `HIAMOD01` binary fact packet consumed by the separate HIA module graph.
JSON decoding, strict root/module/Core/import framing, primitive feature-version
agreement and fact traversal/copying execute in HIA. The standalone executable
uses only Linux x86-64 syscalls; it has no JSON interpreter subprocess or payload
decoder/encoder dependency. Its build driver, development oracle and test VM are
still hosted Python, not a native-only bootstrap/install claim.

## Build and invocation

From a clean matching checkout, first complete the unchanged original/modified
cold replay. The builder refuses an incomplete receipt or a completed receipt
from a different source manifest **before creating output**:

```sh
python -B -m tools.build_hia_core_workspace_json \
  --compiler /absolute/current-cold/B3.image.bin \
  --cold-report /absolute/current-cold.json --output /absolute/new-output
/absolute/new-output/hia-workspace-json < workspace.json > facts.bin
```

The native packer emits the actual executable and embeds the native application.
The caller must check the exit code before publishing its output. Exit statuses
are 0 success, 2 malformed/framing refusal, 3 byte/arena capacity, 4 I/O failure,
64 unexpected arguments. EINTR is retried. A real partial write followed by
EAGAIN produces a prefix and exit 4; stdout is **not transactional publication**.

## Boundaries, not semantic admission

Limits are 8 MiB JSON/facts, 1,048,576 decoded nodes, depth 128; 1,024 modules,
1,024 functions, 4,096 imports, 16,384 calls and 1,024 exports. Core schemas v1–v8
must agree. Nominal types are refused, not silently erased. Existing compiler
ABI, function/block limits and qualification deadlines are unchanged.

The private arena is 64 MiB + 4,096 bytes, scratch 16 MiB + 8,192 bytes. Either
may change on refusal; neither is a published verified Core program. Original
decoded UTF-8 name bytes and declared order are preserved without host interning,
sorting, deduplication or resolver fallback. Duplicate JSON keys (including escaped
spellings), invalid Unicode and malformed inventories are refused.

Framing success deliberately does **not** validate identifier spelling, symbol
existence, exports/privacy, alias collisions, entry existence or cycles. The
separate HIA module graph is mandatory for those policies, then whole-Core
verification remains mandatory for types, effects, SSA and resource/borrow safety.
Non-call instructions and extra function metadata are not verified by this
transport. Filesystem/build custody, Core materialization, full runtime/library,
Agent persistence and native-only installation remain open.

`NativeCoreWorkspaceJson.normalize(bytes)` is an explicit hosted adapter around a
locally trusted image manifest. It does not select or replace the default
`link_workspace` path. A trusted-code manifest is not a proof of all-input
equivalence, release promotion or full workspace/compiler closure.

## Required controls

`tests.test_hia_core_workspace_json_native` interprets independent manually laid
out packet bytes and packer/refusal canaries before any new seed, then compiles
fresh B0/B1/B2 and both HIA applications. It checks every fact byte against an
independent host oracle, all five complete count boundaries and one-past refusals,
native JSON-to-native graph composition with foreign decoder/encoder disabled,
private concurrent calls and buffer guards. Copied ELF/empty PATH/syscall tracing,
malformed-output refusal, actual injected EINTR and real nonblocking partial
output controls are required. Source/contract CI, fresh exact-source cold,
original/modified real projects and complete exact-source regression remain
separate gates; a development test pass is not their substitute.

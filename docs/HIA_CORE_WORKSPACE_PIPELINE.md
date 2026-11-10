# Native workspace compilation pipeline

The explicit `hia-workspace-compile` filter composes the **current** HIA workspace
JSON materializer, HIA primitive Core JSON frontend and mandatory native HIA
semantic compiler inside one copied Linux x86-64 executable. It does not carry a
second, older fact-encoder/materializer implementation. It preserves the current
workspace JSON path and its original public names, privacy, cycle and capture
avoidance policy. Default selections remain unchanged; there is no host fallback.

The workspace materializer can represent multiple primitive feature schemas, but
this complete compiler pipeline accepts **primitive v8 only**, matching the
existing frontend/compiler. Older versions and nominal types are refused, never
silently upgraded or erased. Unsupported Core programs remain unsupported.
Representation is not semantic admission: all private functions are checked,
including unused ones. Invalid SSA and owner drop under a live loan are refused
by the native compiler before stdout. Only ELF relocatable objects are returned;
an executable project still requires linking.

## Build and use

Build from a clean checkout with a completed matching-source original/modified
cold replay. A completed older-source receipt is not sufficient. Refusal precedes
output creation:

```sh
python -B -m tools.build_hia_core_workspace_pipeline \
  --compiler /absolute/current-cold/B3.image.bin \
  --cold-report /absolute/current-cold.json --output /absolute/new-native
/absolute/new-native/hia-workspace-compile < workspace.json > workspace.o
```

The existing hosted file-custody tool can explicitly select the complete filter:

```sh
python -B -m tools.compile_hia_core_workspace --source workspace.json \
  --pipeline-manifest /absolute/new-native/build.json --output /absolute/new-object
```

Do not provide separate graph/workspace/frontend/compiler selections with this
manifest. The hosted tool checks current source and executable identities, runs
exact immutable executable bytes through a sealed code descriptor, and performs
only wire/file/artifact custody. It does not decode the workspace payload, render
Core, run the host Core checker or fall back to an older bridge. The standalone
filter requires no Python, second executable, payload filesystem opens or PATH.
The build/authoring and file-custody tools themselves **still require Python**.

## Profiles and failure semantics

Existing Core checker/compiler/qualification-child limits and cold deadlines are
unchanged. Input is at most 8 MiB; the linked JSON view is at most 8 MiB, rendered
assembly and ELF output at most 1 MiB. Decoder key scratch uses separate 16-MiB
output views. The shared private arena is at least the current workspace arena
and private graph tables, and is explicitly cleared to the next image's fresh
initialization ABI before reuse. No scratch aliases cross image calls.

The existing compiler's 128-function, 256-block-per-function and 1,536-total-block
limits still apply even when workspace representation succeeds. The trusted HIA
application packer has an explicitly separate `3 * 1 MiB + 4096` byte bundle
profile for three <=1-MiB images plus their syscall ELF envelope. This does not
expand a compiler source/output/scratch buffer or an existing qualification-child
profile. The old application generators and generated images are unchanged.

Standalone statuses: 0 success, 2 policy/representation/semantic refusal, 3 byte
or arena capacity, 4 I/O failure, 64 unexpected arguments. Read/write EINTR is
retried. A real nonblocking partial write followed by EAGAIN returns 4 with an
exact output prefix; stdout is not transactional publication. Check the exit
status before publishing. The hosted route checks successful output before
creating its new output directory; existing output paths are not overwritten.

## Required evidence and remaining closure

Independent VM bytes and refusal canaries precede a fresh native seed. Native
controls cover full three-image packer boundaries, original/modified actual
projects with independent Core VM oracles, public/private symbol policy, native
SSA/loan/invalid-unused-function refusals, copied empty PATH/one exec/no opens or
children, real EINTR/descriptor/memory failures, and 128/129-function partial-write
boundaries. Source/contract CI, fresh exact-source cold, real source-bound builder
and public-route acceptance, installation/lifecycles and complete current-source
regression are separate gates. No development control substitutes for those gates.

General/nominal Core, runtime/library coverage, durable Agent editing and
persistence, native-only authoring/build/installation and whole delivery remain
OPEN. This route does not qualify an unrelated consolidated main commit, promote
a release, alter a live service or retire older evidence.

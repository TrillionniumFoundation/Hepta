# Native HIA JSON Core representation frontend

This is a real HIA program, not a Python JSON-to-assembly translator at runtime.
`examples/hia_bootstrap/core_json_frontend.hepta` contains 40 functions. The
native frontend decodes JSON into the HIA arena, checks closed representation
shapes and identifier spellings, emits assembly, and reuses the existing native
HIA compiler for semantic/resource verification and code generation.

## Explicit build and use

```sh
python -B -m tools.build_hia_core_json_frontend \
  --compiler /path/to/qualified/B3.image.bin \
  --cold-report /path/to/completed-cold-report.json \
  --output /new/private/frontend-directory
python -B -m tools.compile_hia_core_json \
  --source /path/to/program.core.json \
  --manifest /new/private/frontend-directory/manifest.json \
  --compiler /path/to/qualified/B3.image.bin \
  --output /new/private/program-directory
```

The build requires all existing completed cold gates and the matching compiler
digest. The driver binds the application manifest to that compiler. Python still
loads trusted manifest/receipt metadata, maps pinned code, allocates private
buffers, and drives filesystem/child operations. It does not parse submitted Core
JSON or invoke a Python Core verifier, renderer or code generator on this path.
Default production inputs and services are unchanged.

The representation entry uses the existing three-buffer ABI: immutable JSON
input, mutable output/key scratch, mutable arena workspace. A successful u32
return is assembly byte length. Representation success is **not semantic
acceptance**: the emitted assembly must pass the actual native HIA compiler.
For example, undefined SSA references can be represented but compilation refuses
with unchanged output. No semantic bypass or proof is conferred by JSON admission.

## Profile and preserved boundaries

- Primitive `hepta.hia.program.v8`, closed root/function/block/instruction/edge/
  terminator/parameter objects, including optional `return_loans`.
- Declaration and array order, parameter identities, exact ASCII identifiers and
  ordinary module names are preserved. JSON key order and escaped field spelling
  do not affect output. Attributes are emitted by the HIA subtree serializer,
  with canonical Unicode ordering and escaping; sibling objects cannot leak
  into fragments. The HIA semantic compiler decides op/type/effect/loan validity.
- Explicit nonempty exports of at most128 identifier spellings are rendered as
  `exports(name,...)` only with operator-selected `--output-profile elf`. Exact
  semantic name, signature, duplicate, private-body and reserved-symbol admission
  remains the native HIA compiler's responsibility. Empty/malformed/oversized
  lists refuse during representation. Composite types and other Core schemas
  still refuse; this is not full language grammar.
- The legacy `selfhost_elf` assembly label additionally requires explicit
  `--output-profile elf`, as do explicit exports with an ordinary module label.
  Flat output is the default. The `selfhost_exec` module additionally requires
  explicit `--output-profile exec`; it cannot contain exports. That profile
  produces a syscall-only executable with the compiler's checked three-buffer
  entry ABI, not arbitrary scalar entry signatures. Mismatched selections
  refuse. Neither a module label nor submitted JSON silently
  selects a different output ABI. ELF linking and libc-backed owners still need
  the existing external tools/runtime; this frontend does not rewrite them.
- Wire at most 8 MiB, at most 1,048,576 nodes, root depth at most 128. Output is
  capped at the existing compiler's 1 MiB source capacity. Native JSON budget,
  Unicode and duplicate decoded-key refusals remain. Generated compiler source,
  output, workspace, SSA, block and relocation limits and cold deadline are
  unchanged. No throughput or all-input refinement claim follows from tests.

## Actual observations

Independent VM representation observations and original/modified compiler JSON
inputs are prepared before building any seed. A fresh B0/B1/B2 then builds the
frontend. It reproduces the complete compiler's assembly byte for byte from
1,030,061 bytes of JSON, followed by real native compilation. Original and
genuinely modified compiler sources each reproduce through three generations.
The tested native frontend runs with host JSON payload parsing/encoding disabled.
Byte-program execution, returned-loan and general-name cases, explicit owned ELF
selection/linking, field reordering, subtree isolation, closed-shape/type confusion,
injection/refusal, exact/over output capacity, source-drift and private concurrent
calls have direct tests. Exact committed qualification is recorded separately;
development observations are not clean-source or remote CI qualification.

Full frontend/module graphs, composites/general signatures, foreign objects,
production CLI/runtime/stdlib, Agent/store/build/install, optimizer/proof tooling
and other native targets remain open. Whole-stack rewrite is **not complete**.


The integrated export continuation also executes an independent HIA Core VM
representation before B0, then compiles JSON through the actual native frontend
and HIA semantic compiler, inspects the exact ELF public-symbol set, links and
calls both exports. Default-flat ABI refusal, invalid public names/duplicates/
loader hooks and an invalid unexported private body remain negative controls.
Host JSON payload parsing/encoding is disabled during native representation;
manifest/receipt metadata and linking remain explicit host responsibilities.

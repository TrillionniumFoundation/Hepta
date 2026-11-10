# Standalone native primitive Core checker

The explicit `tools.build_hia_core_admission_cli` builder emits a standalone
Linux x86-64 ELF executable named `hia-verify-core`. Feed one raw primitive
Core v1–v8 JSON document on stdin. The embedded HIA verifier performs complete
declaration, instruction, call, type, resource/loan and CFG admission; no host
JSON decoder, language runtime, interpreter, dynamic loader, libc or external
image/manifest is used at execution.

The syscall-only adapter reads stdin and exits after the HIA decision. Actual
ELF header emission, call relocation and image copying run in HIA. The copied
executable works with an empty PATH and without the source or build directory.

| Exit | Meaning |
| --- | --- |
| 0 | Admitted |
| 2 | Malformed input or semantic/declaration refusal |
| 3 | Input byte/node/depth budget exceeded |
| 4 | Descriptor I/O failure |
| 64 | Unexpected command-line arguments |

Stdout and stderr are empty, including refusals. Excess function and block
inventories retain their existing Core FORMAT/CFG refusal classification (2),
not decoder-budget classification (3). This command does not execute submitted
Core or dynamically load code from its JSON input.

## Full profile and remaining work

The unchanged maximum is 8 MiB input, 262,144 JSON nodes, depth 64, 1,024
functions and 4,096 blocks per function. There is no compiler-profile reduction
in function count, parameters or return arity. A private anonymous mapping
reserves 64 MiB verifier state and 32 MiB JSON arena, sufficient for the full
existing Core byte/node bounds. This is scratch sizing, not a data quota.

Independent ordinary-Core VM packer witnesses precede native compilation.
Every native packed executable byte is compared against the interpreted HIA
packer. Kernel tests exercise valid and refused resource programs, copied
empty-PATH execution, full function/block/arity profiles, exact byte/node/depth
limits and actual descriptor failures. The strict builder requires current
source/cold/compiler identity before creating output.

The filesystem build driver, source authoring and test harness remain hosted.
This command accepts primitive JSON only; composite normalization, assembly
parsing, other CLI commands, structured diagnostic presentation, Agent editing
and persistence still require separate native replacements and acceptance.
There is no default switch or legacy removal here, no whole-product native-only
delivery claim, and no claim of an all-input formal refinement proof.

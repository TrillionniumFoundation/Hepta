# Standalone native primitive Core checker, normalizer and inspector

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

## Normalize admitted primitive Core

```sh
python -B -m tools.build_hia_core_admission_cli --normalize \
  --compiler /qualified/B3.image.bin --cold-report /qualified/cold.json \
  --output /private/new-normalizer
/private/new-normalizer/hia-normalize-core < primitive-core.json
```

The normalizer first runs the same complete HIA admission. Only on success
does a second embedded HIA image emit sorted, two-space-indented UTF-8 JSON
and a final newline, matching the hosted `hia normalize` stdout for primitive
v1–v8 input. It does not accept composite Core or write files by path. The
normalizer retains the same source limits and exit categories. Its 80 MiB
output/scratch mapping allows for formatting expansion; refusals write no
stdout. A descriptor error during output can leave a prefix on stdout and
exits 4. Stdout is not atomic publication.

## Inspect admitted primitive Core

```sh
python -B -m tools.build_hia_core_admission_cli --inspect \
  --compiler "$compiler" --cold-report "$cold_report" --output /private/new-inspector
/private/new-inspector/hia-inspect-core < primitive-core.json
```

The inspector runs the same complete semantic admission before producing the
primitive `hia inspect` view: function interfaces, blocks, operation indices,
the public scalar entrypoints, and v8 returned-loan declarations. HIA computes
SHA-256 over the canonical input, not the whitespace or field ordering supplied
on stdin. It emits sorted, two-space-indented JSON and uses the original input
limit and exit categories. This version does not normalize composite input or
change the default hosted CLI.

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

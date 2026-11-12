# Explicit HIA machine instruction bytes

The selected implementation emits x86-64 instruction bytes in HIA. It is a
bounded component of the direct backend. Public operand admission, mutable
Code state, Core lowering, ELF writing and publication retain hosted owners.

## Selection

An ordinary hepta.hia_machine_x64.Code construction selects the trusted local
image named by HEPTA_HIA_MACHINE_ENCODING_MANIFEST. An absent or empty selector
keeps the reference implementation. A nonempty invalid selection fails without
falling back. Existing Code subclasses retain their virtual instruction methods.

The adapter binds the package-owned machine_encoding.hepta on every selection,
including cache hits. Installed execution has no checkout fallback. Image pages
become read/execute and every invocation has private buffers. The direct backend
captures one selection, including no selection, for the entire emit operation.
Its implementation identity includes the adapter, HIA source and actual image;
environment changes during a foreign hook cannot switch that captured owner.

## Ownership

| Responsibility | Owner |
| --- | --- |
| REX, opcode, ModRM, SIB, instruction fields, NOP alignment and rel32 bytes used by public instruction methods | HIA |
| Numeric ABI admission before output/workspace writes | HIA |
| Public register/condition names, argument types and runtime exception objects | Host adapter |
| Foreign scratch-map reads, option truth observations and virtual method binding | Host adapter |
| Mutable bytearray capacity, labels, fixups and relocation containers | Retained Code state |
| Core lowering, stack layout, ELF object writer, linkage and publication | Existing backend |
| Custom subclasses and direct calls to retained private helpers | Existing extension domain |
| Manifest access, immutable mapping and operating-system effects | Foreign runtime |

The ALU packet carries separate opcode-width and immediate-width observations.
Foreign option objects can change truth values between the original three
observations. Those observations, the intervening signed-byte refusal and binding
emit before the last truth observation remain ordered. On the branch where a
signed byte cannot exist, the runtime's original failure primitive supplies its
exact exception. Every admitted instruction byte is produced by HIA.

## Private ABI and unchanged limits

HIAX6402 is eight little-endian u64 words: magic, command, two register indices,
value, auxiliary, mode and offset/width observation. There are 37 commands.
Input is exactly 64 bytes, output at least 80 bytes and workspace at least
8 bytes. Success returns zero and writes a count followed by at most 63 bytes;
the remaining output is unchanged. ABI refusal is 0xfffffffd before any output
or workspace write. The Code image limit remains exactly 64 MiB.

The HIA source has 14 functions, 118 blocks, 563 operations, at most 21 blocks
in a function and 201 SSA slots in a function. Its 828 lines and 30,894 bytes
fit the original compiler limits. No caller or cold deadline was increased.

## Build and qualify

Use a completed cold report for the current complete source contract:

    python -B tools/build_hia_machine_encoding.py \
      --compiler /absolute/current-cold/B3.image.bin \
      --cold-report /absolute/current-cold.json \
      --output /absolute/new-encoding-bundle

    python -B tools/qualify_hia_machine_encoding_native_callers.py \
      --cold-report /absolute/current-cold.json \
      --evidence /absolute/new-encoding-caller-evidence

The builder checks all eleven cold conditions, all three generation hashes
and the current complete source manifest before creating output. The separate
--development-manifest mode is development only. The caller gate requires all
loaded unique tests to execute and rejects failures, errors, skips, expected
failures and unexpected successes.

## Actual development observations

The reused compiler is SHA-256
0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.
It originated in an older desktop cold run whose complete outcome remains HOLD.
Current HIA source:
9d7de302acb40d62ec03ba886eb9bd1b2ded495eaf585cc1af2070d3f301f712.
Development image:
e482bf718f0ec87a0e0ab71a29ca28ae1fcfc2db8ad5c54576600f6ebd70d657.

| Control | Observed result |
| --- | --- |
| Independent Core interpretation | 159 complete Code comparisons, 194 entry packets, all 37 commands matched |
| Native image before product integration | 159 comparisons and original 51 tests passed |
| First foreign ALU candidate | Five mismatches retained |
| Ordered second foreign candidate | Four matched; one exception-text mismatch retained |
| Runtime exception correction | All five matched |
| Raw ABI guards | 34 controls passed |
| Nonzero alignment | All 256 offset/boundary combinations matched |
| Stateful scratch-register reads | Six controls matched |
| Actual 64 MiB partial-write boundary | Five full byte/container/error comparisons matched; both byte streams retained |
| Product selection | All 9 component tests and all 51 unchanged callers passed in 22.037 seconds |
| Actual installed wheel | Isolated Python without site, empty PATH/PYTHONPATH, authoring imports forbidden, old instruction encoding forbidden; source drift/missing-resource controls passed |

The product run used ordinary Code construction and existing imported aliases;
it did not replace caller methods, assertions, IDs or imported Code aliases.
Retained instruction encoder entries and all five unittest anomaly categories
were zero. Complete records are under experiments/hia_machine_encoding_next_20261111.
The product-callers-r1-preservation archive contains 840 regular members and
33,126,114 decoded bytes, all independently replayed with modes.

Two initial control publications differed from local execution only by one
additional terminal blank line. Both canonical versions and exact executed
bytes are retained; no selected rerun replaced an earlier result.

These observations do not qualify the final combined-source cold run, a complete
backend, default activation or removal of supported hosted owners.

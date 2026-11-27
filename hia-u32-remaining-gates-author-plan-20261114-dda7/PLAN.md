# Remaining u32 gates — authoring only

No product module was imported or executed for this plan. No generator, compiler, VM, cold replay, installation, or CI was run. The only execution was the static metadata/AST inventory writer. It read 38 fixed source files and checked each against the already verified hosted source manifest.

## Baseline and source lineage

Hosted run **43579403463**, job **132400693130**, head `de4afa1f7f4cb1fc2d5284965f7f2a7c55632d2a` completed the explicit `hepta.hia.selfhost-encoding.u32-immediate.v1` finite qualification: all original **5052 checks / 38 phases**, fresh references, real seed and mutation chains, and original **180+3** owner. This is the fixed canonical Core-v8 subset. The two extra observer references precede B0 by the retained serial producer and complete receipts; they have no independent completion timestamps.

The actual 3180-file source tree is `4c62be4ed66ff107fa6f88c6131313a354868bd9`. Complete manifest comparison establishes **actual R19 3175 files** (`d15d7a476fc3f711b2729236e84b7a9573da7a3d`) unchanged, plus exactly five u32 author/test/document/asset files. It is not the later 3177-file R20 product tree. The original static `SOURCE_FILES` still has 1400 entries and contains none of these five additions. Its dynamic `hepta/**/*.py` union does not add them either. The full private 3180-file manifest supplied their separate identity for the completed qualification.

Actual new B3 and M3 are both 658860 bytes:

| Input | Actual SHA256 |
| --- | --- |
| B3 | `56cddd318fbdd7cd269c103fa70c8061d43a3bf9130e877961a5b8af2078c764` |
| M3 | `9e3b554aee6b819b2764e5018605a00790b2863014c75f4b6c4a2fe217073718` |

The exact original ZIP member locations, source identities and pins are in `INPUT-INVENTORY.json`. Those images can be rebound as inputs to an additional finite gate. They cannot become inherited seeds of a new cold replay.

## Four remaining gates

| Gate | Existing entry and exact inventory | Missing work |
| --- | --- | --- |
| Ordinary regression | `tools/replay_hia_selfhost_cold.py`; original `SelfhostSourceTests` 34 IDs and `SelfhostNativeTests` 19 IDs in `EXPECTED-GATES.json` | The u32 report explicitly records `ordinary_encoding_gate=NOT_RUN`. Unchanged ordinary bytes do not establish a new execution. |
| u32 entry layout | `tools.hia_selfhost_names.qualify_entry_layout`; original method `tests.test_hia_selfhost.SelfhostNativeTests.test_entry_last_and_middle_whole_compilers_self_reproduce_and_preserve_owned_flow` | Not called by the 5052-check qualifier. The helper still reads ordinary `SOURCE`; it needs a narrow explicit-source projection and separately reviewed runner. |
| Matching-current new cold | Ordinary producer plus `build_hia_json_preflight.admit_cold_build` and stricter `hia_linux_stdio_cold.admit_cold` are concrete retained contracts | New schema `hepta.hia.selfhost-u32-immediate-cold.v1` is only reserved. No new producer, reader, permanent Native selector or positive/negative group exists. |
| Frozen R8 and aggregate | Exact R8 source; original standalone 162 Native inputs and six semantic VM cases; permanent roundtrip 130+7+2+1 IDs | No new-encoding R8 image, R8 semantic/fuel result, actual packed aggregate, new source/profile binding or matching cold/portable caller result exists. |

## 1. Entry layout: smallest finite successor

`ENTRY-LAYOUT-PROJECTION-SPEC.json` contains the complete original function and only three proposed replacements: explicit `source_path` parameter, removal of the imported ordinary `SOURCE` alias, and reading that explicit path. Inverse projection restores the entire original bytes and AST. Every original check predicate, reference, mutation, call and ordering remains. No global default is rebound. The proposed function is a JSON authoring specification, not an imported/executed implementation.

There are four `(original, modified) × (last, middle)` combinations. Each has same-source R1/R2 self-compilation, canonical reproduction, executable self-reproduction and two resource cases: **20 exact checks**, all listed in insertion order. The fixed call structure gives **24 compile_stage calls**, four executable calls and eight resource link/invocation pairs. All four source preparations and eight resource references precede the first native compilation.

Crucial budget detail: these resource references call the public VM without an override, whose actual default is **1,000,000 steps**, not the separate 10M budget. Preserve it. Native compile remains **20s / 10 CPU seconds / 1MiB output and workspace**; executable helper retains its **15s** owner; the separate group retains the original plan's **180+3**.

Future explicit invocation, after a reviewed runner binds actual B3/M3, exact source, runtime and outputs:

```python
qualify_entry_layout_explicit(
    new_directory,
    [('original', captured_actual_u32_B3), ('modified', captured_actual_u32_M3)],
    source_path=captured_exact_u32_source,
)
```

Keep all original method assertions: references before compile, four references, exactly 20 true checks, and `whole_stack_rewrite_complete=False`. Record the old method ID as provenance and a separate identity for the new explicit-source invocation; do not claim the unchanged unittest method ran with a substituted source. Rebind actual extracted NODE modes, full requests/receipts/stdout, images and all observed frames before/after. No extraction or execution is performed here.

## 2. Ordinary encoding remains ordinary

Existing commands, pending a reviewed owner and Root's slot:

```sh
python -B tools/replay_hia_selfhost_cold.py --output NEW_ORDINARY_COLD_REPORT
python -B tools/run_hia_unittest_gate.py tests.test_hia_selfhost.SelfhostSourceTests
python -B tools/run_hia_unittest_gate.py tests.test_hia_selfhost.SelfhostNativeTests
```

The cold command exports the current ordinary source contract and runs its own fresh references/B0/B1/B2/B3/mutation/full qualification in `-I -S -B`. Preserve all **11 original outer cold check keys**, **180+3**, and original nested limits. The two classes retain all **34 / 19 original IDs and bodies**. `SelfhostNativeTests.setUpClass` itself calls the ordinary full qualifier; selecting only its entry method still constructs an ordinary compiler and cannot verify new u32 entry layout.

That class deletes its temporary directory in `tearDownClass`. A complete-originals runner must explicitly retain actual observations before cleanup or state the missing raw-custody boundary. The persistent cold report is a separate run, not a substitute for method execution. Original word-I/O and exports partial-write expectations stay unchanged. Do not replace all reference fuels with a new common limit.

The current product workflow has ordinary cold at original Native step 6, but no standalone `SelfhostNativeTests` or new u32 entry invocation. Success of a named full-qualification step therefore does not fill these omissions. Any future wrapper and retention plumbing must be reviewed before execution; there is no new executable ordinary harness in this package.

## 3. New current-cold needs real production authoring

The ordinary reader requires exact old schema/profile/status, exact 11 check keys, exact success integer, three equal digests matching the compiler and a fresh complete source map. The stricter stdio reader also reads actual nested report/B1/B2/B3 bytes and rechecks original 180+3/cleanup and sources. Keep both ordinary readers closed to new-policy records.

The new producer must export the complete original closure plus every explicit u32 policy/asset/author/reader/qualifier dependency and bind a complete final source manifest. No inherited B0, successor, Python cache or ancestor checkout identity. In the source-only export repeat 17 fresh references, two serial observer references, actual new-source B0/B1/B2/B3, mutation, all 5052 keys/38 phases and original cleanup. Existing B3 may be a comparison oracle, never an input seed. Preserve original per-reference fuels, including their exceptions; retain 180+3 and every 20s/1MiB child limit.

A new strict reader must bind source-only provenance, exact current source/policy/runtime, actual predecessor chain, requests, stdout-to-receipt equality, full outputs-to-images, budgets and cleanup. Required new negative controls include ordinary/relabelled schema, stale or omitted source, changed owner/reader/asset, wrong predecessor, changed/missing image, receipt/stdout mismatch, false/missing checks and incomplete cleanup. They are pending new tests; this plan does not invent already existing IDs.

Prepare the final integrated source tree before this expensive replay. Adding a reader or R8 profile after a provisional cold run changes current-source identity. Finite entry/R8 development checks should precede final cold; then replay once against the actually reviewed final closure. No resulting report may set whole-language or default-promotion flags.

## 4. R8 has both size and semantic obligations

Frozen target: `v117-dense-token-r8-r1/source/examples/hia_bootstrap/file_render_checker_v4.hepta`, **395910 bytes**, SHA256 `83953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de`, Git `093489201db8aa0eade2e2a91eddf95463ada4ea`. Ordinary-encoded image: **562746 bytes**, SHA256 `2138fd3f57a76e3ac5ad00fee9d2b1a3e36c0af24395b7c491a772d788a3ab21`. Its retained +10696 growth exceeds the old aggregate allowance by **6600**. It has no semantic/VM pass.

First author one exact u32-B3-to-R8 compile/size/relocation/pack observation. Read the whole actual new image and relocations; retain every raw buffer and original 20s/1MiB limit. The static 2576 eligible constants × 5 bytes = 12880-byte opportunity is not an actual image or ELF. Only the actual HIA-packed aggregate can satisfy **1048576 bytes**.

Retain all **162** original Native inputs: 30 capacity/shape, 26 semantic, 106 retained semantic. Exact grouped IDs and original report pin are in `EXPECTED-GATES.json`. Keep original return, complete F/O/W, canary, no-I/O and forbidden-module predicates. If a deliberate R8 private state change differs from the old full workspace, the old gate fails; do not silently mask it. Any separately versioned state contract needs review and must retain the failure.

Six separate semantic VM cases: `formal-origin-256`, `formal-origin-256-wrong-source`, `edge-256-reversed-origin`, `edge-256-readonly-aliases`, `unreachable-call-result-arity`, `root-v8-cross-target-loans`. Historical R5 is five new calls plus one exact retained same-image VM, **5 PASS / 1 original-10M FAIL**. No R5 VM result transfers to R8. Require complete actual new R8 Native/VM F/O/W under each original **10M** budget, including failure state. Freeze R8-specific dirty-cache/high-SSA/overflow controls before execution; code compression does not establish them or reduce target IR fuel.

Current roundtrip v2 pins semantic source SHA `2fbedf12008851e7f428fbc60fed144c0d0ebd99d7cc93e004058a8d5e375aa9` (R5), so `_checked_components()` rejects R8. Its optional five-asset closure also has exact identities. Current `build_toolchain()` admits ordinary cold B3, builds old profile P1/P2/P3, and proves ordinary B3 reproduction; `build_program()` then compiles all payloads with that profile compiler. A full u32 report or changed image hash is not accepted wiring.

Minimal later integration may preserve the original qualified profile lineage for controller/representation/packer and explicitly compile only R8 semantic payload with new current-cold u32 B3. That needs a separately versioned component/profile and a builder binding both real authorities and all exact payloads. An alternative u32-emitting profile compiler would be a larger independent qualification. Neither is implemented; no additional compiler becomes a resident payload in the ELF.

After source/version/cold work, preserve permanent groups **130 kernel + 7 pipeline + 2 tail faults + 1 real portable install = 140**. All complete IDs are frozen here; the six actual postreturn F/O/W observations belong to the seven pipeline cases and are not six extra tests. Existing command:

```sh
python -B tools/qualify_hia_linux_file_roundtrip.py --cold-report REPORT --evidence NEW_DIRECTORY
```

It currently tests v2/R5/ordinary-cold only. A versioned R8 successor must retain old inputs/IDs/provenance/assertions, **180+3 per prepare/group**, **20s compiler/kernel**, **1MiB** bounds and **10M** pipeline fuel. Both last-byte faults must retain failure and no successful stdout publication. Explicit optional packaging must leave original default 210 resources unchanged. The old pipeline's seven passes do not close standalone checker6.

## Proposed order and authorization boundary

1. Review and run the narrow explicit entry-layout gate, once authorized.
2. Review one u32-to-frozen-R8 size/pack gate; stop on real size/admission failure.
3. If feasible, run the fixed R8 standalone semantic/VM inventories and reviewed cache controls.
4. Freeze final ordinary + new-policy + R8 selected source closure and production cold readers/negative controls. Exact final count/tree are pending, never guessed from R19/R20.
5. Run original ordinary/current-cold, new-policy current-cold, then explicit aggregate/portable 140 on those exact bytes. All failures remain; no automatic retries.

This is not authorization to execute any step. Inspect's next exclusive product slot is preserved. All eleven relay ZIPs remain intact. The complete original 1270286664 ZIP bytes were verified through ten spans, but are not all republished in Git. Small-originals custody recipe: `a7b6e223dd4a821de03118c0cf873f6fcbc519a5`.

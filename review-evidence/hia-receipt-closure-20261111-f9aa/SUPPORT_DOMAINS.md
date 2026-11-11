# Hepta 7c20 support domains and remaining boundaries

## Scope and identity

This read-only review inspected actual files at commit `7c20b6cfc792f0147b5418968f94734b8890fcca`, tree `d76c851edfb51fd649aca26a799ed4874af54489`. This evidence note does not change that candidate or widen an execution, ABI or proof profile. Core admission, direct emission, selfhost compilation and standalone applications remain distinct interfaces.

## Current interfaces

| Interface | Actual admitted domain | Important limit |
| --- | --- | --- |
| Hosted Core verify_program | Primitive v1–v8; composite v1–v4 is normalized to its declared primitive version and then checked | 8 MiB, 262,144 nodes, depth 64, 1,024 functions, 4,096 blocks/function; admission is not compilation or execution |
| Direct x86-64 emitter | Reverified immutable Core; explicitly reviewed schemas, types and opcodes; internal scalar and resource tuples | Linux x86-64; 64 KiB function frame, 16 MiB text, 64 MiB artifact, 1–128 public entrypoints; external ABI is narrower than internal Core |
| Selfhost compiler | Bounded assembly profile; current primitive scalar types and declared resource subsets | 128 functions, 256 blocks/function, 1,536 total blocks, 8,192 instructions, 16 parameters/arguments, 0–3 internal results, 2,048 SSA names/function; source/output/workspace each 1 MiB |
| Standalone hia-verify-core | Complete primitive v1–v8 declaration, instruction, call, type, resource/loan and CFG admission | Retains the full Core profile rather than the compiler's 16-argument/3-result profile; does not compile or execute input |
| Standalone hia-native | capabilities, verify, compile, render-assembly, assemble; native JSON frontend plus actual selfhost semantic/resource compiler | JSON compilation accepts primitive v8 and inherits the bounded compiler domain; build-time flat/ELF/exec selection is explicit |

`hia-native verify` and `hia-verify-core` are not interchangeable capabilities. A complete primitive checker can admit a program that the bounded compiler must refuse. Representation success in the JSON frontend is not semantic admission.

Sources: [Core](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/hepta/hia_program.py), [direct emitter](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/hepta/hia_program_native.py), [current support contract](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/docs/HIA_SELFHOST_CORE_SUPPORT.json), [complete checker CLI](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/docs/HIA_CORE_ADMISSION_CLI.md), [stdio application](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/docs/HIA_AGENT_STDIO_NATIVE.md), [JSON frontend](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/docs/HIA_CORE_JSON_FRONTEND_NATIVE.md).

## Semantics, resources and ABI

| Area | Core/direct behavior | Selfhost and standalone compiler behavior |
| --- | --- | --- |
| Multiple results | Core checks complete ordered tuples without the compiler's fixed three-result ceiling. Direct internal calls allocate and transfer the actual result words. Ordinary public C exports accept zero or one scalar/unit result. | Internal zero-to-three results may mix scalars, owned buffer/chain values and parameter-bound borrowed values. More than three results is refused. Scalar public exports allow zero or one result; legacy compiler f0 remains u32. |
| Recursion | General Core is not restricted to the selfhost acyclic graph. The reference VM has explicit step/heap/call-depth budgets; call-depth default and maximum are 256. Direct emission uses ordinary calls and does not provide VM quotas. | Only a direct self call immediately returning its exact result tuple in order is admitted; staged arguments reuse the same frame. Non-tail self calls, mutual recursion and non-tail cycles in unused functions are refused. Loops and self-tail calls do not gain a termination proof. |
| Ownership and loans | Owners cannot be copied, leaked, or transferred with outstanding descendants. V8 returned loans require an explicit original-formal origin, sufficient permission, and external/direct-child provenance. Normal returns consume or transfer all local capabilities. | Current v23+ support includes parameter-bound returned loans. Owned buffer/chain operations and internal owner transfer require selfhost_elf or explicit scalar-export ELF. Flat output has no allocator imports. |
| Allocator and traps | Direct imports use the reviewed libc set, including calloc/malloc/free and byte routines. Freshness, zero initialization, lifetime, linking/loading and hardware remain external contracts. Traps abort and do not promise cleanup. | Owned objects import only calloc/free. Maximum allocation size is 9223372036854775807. Mandatory allocation failure uses UD2; fallible failure returns a live empty owner and false; zero-length allocation is a logical live owner and successful try allocation. Workspace is not heap. |
| Foreign ABI | Scalar SysV AMD64 wrappers expose non-unit scalar (integer/bool) parameters and at most one scalar/unit result. The separately selected borrowed-byte profile admits 1–8 loan ranges with per-range extent at most 1 MiB and one u32 result; its u64 result packs ABI status in high32 and Core result in low32. Numeric checks cannot prove arbitrary-pointer liveness. | Legacy f0(readbuf,mutbuf,mutbuf)->u32 expands to six machine arguments. B0 returns packed status/u32; successors return zero-extended u32. Explicit scalar exports allow 0–16 non-unit scalar parameters and 0–1 scalar/unit result. Public resource descriptors, multiple-result C ABI and arbitrary imports/relocations remain unsupported. |
| Executable profile | An admitted native image is not a security sandbox. | selfhost_exec is syscall-only and uses borrowed buffers/scalars; owned/chain runtime programs retain the separate libc-linked object profile. Partial stdout writes are not atomic file publication. |

Sources: [Core](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/hepta/hia_program.py), [reference VM](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/hepta/hia_program_runtime.py), [direct emitter](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/hepta/hia_program_native.py), [borrowed-byte ABI](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/hepta/hia_native_byte_abi.py), [current support contract](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/docs/HIA_SELFHOST_CORE_SUPPORT.json), [contract implementation](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/tools/hia_selfhost_contract.py). The standalone checker verifies resource programs without executing them. Its lack of libc at runtime does not remove libc obligations from separately generated owned-resource objects.

## Current contract versus historical prose

The current machine-readable contract and its generating implementation state that internal parameter-bound borrowed results are supported and `block_entry_must_be_first_in_source` is false. Early sections of [HIA_SELF_HOSTING_CORE.md](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/docs/HIA_SELF_HOSTING_CORE.md) still contain older statements that returned loans are excluded and the entry must be first in source; later v23/v28 sections record the extensions. Those historical sentences must not override the current contract. This note records the discrepancy without editing the frozen candidate.

The support JSON's `general_core_checker: not_implemented` row describes the bounded selfhost compiler profile. It must not be used to deny the separately implemented complete primitive admission kernel or standalone hia-verify-core application.

## Exact-source observations

The original [Core push run 43015496423, attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015496423/attempts/1) checked out 7c20 and completed: 312 source tests; cold 11/11; language 1,242/1,242 plus 10 assertions; 14 native groups totalling 581 tests. The native groups included 11 complete Core admission tests and 7 standalone admission CLI tests. These finite observations do not prove equivalence for all admitted inputs.

The same-tree [PR run 43015503275](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015503275) failed its cold deadline on original attempt 1 and on one explicitly bounded diagnostic attempt 2. Each returned 6/11 outer checks; language/native stages were skipped. The original 180-second qualification and 3-second cleanup budgets were unchanged. The failures remain separate observations and are not replaced by successful runs. No further retry or compiler performance repair is claimed.

The original compiler-extension qualification and fresh replay on 7c20 retained separate old-domain and new-domain observations. Repaired full-return validation rejects the actual ABI-status negative control accepted by the former low32/output condition. This closes that receipt-admission defect within the registered finite upgrade domain; it is not a whole-compiler theorem.

## Remaining contract work

1. Keep discovery/catalog terminology precise across complete admission, direct compilation, bounded selfhost compilation and individual standalone commands. A valid Core program outside a compiler profile must produce its declared refusal, never a silent schema, ABI or semantic substitution.
2. Reconcile the current support table with historical prose while preserving version-specific evidence.
3. Before claiming complete Core native compilation, separately close compiler-domain gaps including larger signatures/tuples/program inventories and general recursion. If the product promises the current bounded profile, expose its limits.
4. Treat composite normalization, complete compilation, installation, durable Agent authority and Runtime cutover as separately evidenced owners. A primitive checker cannot prove correct lowering of structured input; a self-compilation fixed point cannot retire unrelated hosted owners.

Allocator, loader, kernel, hardware and caller-buffer assumptions remain explicit. The current support contract declares compiler_correctness_formally_proved=false, whole_HIA_language_self_hosted=false, native_execution_is_security_sandboxed=false and support_declaration_is_execution_evidence=false.

## Static inventory provenance

The [checked-in inventory](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/docs/HIA_NATIVE_REWRITE_INVENTORY.json) labels itself STATIC_INVENTORY_NOT_NATIVE_DELIVERY_ACCEPTANCE and records git_head 31d81594997cfb6cce5ab62ea5aaba3bb7757af1 and tree dc7b7f1f5fc07c8502a27ba4907fe768ee1f0207. It explicitly does not establish dynamic caller closure or a semantic audit of every line. It helped locate owners; the conclusions above were checked against actual 7c20 source and current contracts. The inventory is not an exact-7c20 execution proof.

## Documentation follow-up

[Hepta #892](https://github.com/TrillionniumFoundation/Hepta/pull/892), head c0fec2a233c64e492f633eb86235438b699d99f1, corrects the current selfhost summary and adds the official cross-interface support matrix. Independent review found no material blocker; its public direct-ABI parameter wording now explicitly excludes unit. This documentation-only follow-up does not change or requalify the frozen 7c20 candidate described above.

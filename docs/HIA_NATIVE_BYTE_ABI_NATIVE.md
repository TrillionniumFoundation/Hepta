# Native borrowed-byte ABI owner

This explicit component transfers `normalize_exports` and `emit_wrapper`, including the original `load` closure and the three closed helpers `_reject`, `_normalize`, and `_prologue`, to HIA. It keeps the unselected original implementation as an independent reference. It does not activate the selector or establish whole-backend equivalence.

## Decision and effect boundary

HIA emits the complete control table and owns branch order, iteration, short-circuit comparisons, wrapper construction, error selection, scope ownership, and retirement. The fixed bridge performs one issued Python object or `Code` operation at a time. Every effect is preclaimed by the HIA nonce/sequence state and the actual issued object. An interrupted observation or acknowledgement retains unknown custody and cannot authorize a callback retry. The bridge never imports either authoring policy or the retained business bodies.

The original empty-tuple return precedes `program.as_dict`; exact tuple/string/integer checks and all error ordering are retained. Wrapper guards keep the original extent/null/address/alias priorities, zero-length and readonly overlap behavior, SysV register/stack expansion, narrow scalar normalization, and packed ABI/u32 result distinction. Arbitrary foreign objects retain their actual Python operations; there is no primitive type-based policy fallback. Python interpreter introspection and replacement of the import machinery are not established equivalent domains. Physical object operations and the CPython exception-delivery bridge remain foreign dependencies.

## Selection and identity

Set `HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST` explicitly. A new admission freshly reads the manifest, the packaged `native_byte_abi.hiaasm` source and executable, and reads them back after binding. A held `native_byte_abi_scope` captures both an actual owner and explicit absence. Later environment changes cannot replace either choice. Independent threads and reentrant calls use ContextVar scope. The captured checker identity records the actual manifest/source/image; it does not accept caller-supplied hashes as proof. The backend captures Byte ABI alongside the existing owners for its complete emission. Its implementation identity includes both Byte bridge modules and the actual selected image. A caller-held owner or explicit absence takes precedence over later environment configuration.

## Build and packaging

`python -B tools/generate_hia_native_byte_abi.py --check` checks the generated asset. `tools/build_hia_native_byte_abi.py --cold-report REPORT --compiler IMAGE --output NEW` only builds after a complete current-source cold report is admitted. Missing, partial, stale or changed cold evidence refuses before creating output. The compiler receipt is validated both as the returned typed object and as the actual on-disk JSON. Original compiler limits and its 20-second child deadline stay unchanged. Output publication is exclusive and read back.

The separate `--development` entry requires an explicitly supplied compiler, records every consumed component dependency, and grants no cold authority. Native tests similarly require `HEPTA_HIA_NATIVE_BYTE_ABI_COLD_REPORT` or `HEPTA_HIA_NATIVE_BYTE_ABI_DEVELOPMENT_COMPILER`; the two inputs conflict. Evidence uses `HEPTA_HIA_NATIVE_BYTE_ABI_EVIDENCE`. Production installed selection requires the packaged HIA resource and source-bound manifest and must work without `tools` or test modules.

## Qualification boundary

The initial retained-compiler development image compiled under the original limits and passed the original 16 Byte ABI methods on CPython 3.12.14 with both retained business bodies poisoned. The R1 wrapper lifetime probe then exposed four destructor-order differences: lexical assignment order retired captured cells before the original fast locals. R2 binds the original unexecuted code object's fast-local/cell/free-variable layout into the HIA table. Twelve positive object-event comparisons passed on CPython 3.12.14. A later complete development group ran 23 methods (six source, fifteen native, one independent full-frame VM, one real installed wheel), with no skips. The original 29 caller methods (16 Byte ABI, 12 Agent buffer, one lease snapshot) also passed with both retained Byte ABI bodies poisoned. The original R2 test-fixture error when attempting to normally close an unobserved pending effect is preserved separately; the final test requires refusal and retained unknown custody. At that earlier freeze CPython 3.14 and current-source cold results were still pending. Later R4 controls passed on actual CPython 3.12.14 (25 methods) and 3.14.4 (25 component methods plus the unchanged 29 callers); current-source cold remains pending. None of these observations transfers earlier Core/Plan qualification, activates the default, authorizes deletion, or claims all HIA production ownership is complete.

## Original callers and integration

`tools/qualify_hia_native_byte_abi.py` admits either a matching current cold report or an explicitly labelled development manifest. It pins the three unchanged original test modules and their exact 29 ordered IDs, refuses skips and unexpected discovery, poisons the two old business bodies, and requires positive observations for all five HIA modes. The helper counter is in the test process; child-process semantic tests inherit the selector but are not relabelled as individually instrumented native entry counts. The backend merge consists only of Byte ABI module source identities, one selected identity contribution, and a whole-emission capture scope alongside the existing owners. The private development tree does not overwrite root's ongoing `_Emitter` migration.


## Temporary CALL references, R4

The frozen R3 component and original caller controls passed on actual CPython
3.12 and 3.14. A subsequent four-case observation found two additional 3.14
normal-return differences: a temporary Python method receiver was retired before
its temporary argument. The original call retired the argument first. Both
exception/held-traceback cases matched. Those original failures remain evidence;
they are not replaced by the earlier 23/29 results.

The Byte-only fixed CALL port now moves the HIA-claimed, uniquely owned temporary
operands onto the actual CPython call stack. It retains no additional reference
through the foreign call. The HIA ACK still consumes those exact slots and a lost
ACK cannot authorize a second call. Authoring verifies every CALL argument is a
unique, noncell temporary and is included in its complete consume list. Named
locals and shared closure cells are never moved by this port. The shared Plan
adapter and the generated HIA bytes are unchanged. New component observations
must be recorded separately from R3; whole/default/cold flags remain false.

## Whole-emission integration controls

The separate `NativeByteABIIntegrationTests` class exercises real object emission and encoding-proof consumption. It checks an environment change inside `render`, captured absence, the original target-error order, a fresh alternative image identity, and unknown native-entry scope unwinding. The alternative image is deliberately an identity fault control; it is not qualified compiler output. The builder includes the actual backend and this integration fixture in its consumed-source closure. These controls do not change the default selector or establish current-source cold or whole-project qualification.

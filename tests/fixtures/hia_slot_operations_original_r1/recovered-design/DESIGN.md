# NativeSlotLedgerStore SQL delivery: static design R1

## Status and exact source

This is a source review and proposed next implementation boundary, not a product patch or qualification. No product module, original oracle, SQL statement, native image, VM, test body, generator or metadata tool was executed. All whole-closure and input-equivalence flags remain false. The previous Slot transition R2 candidate is frozen and unchanged.

The primary source is Git commit `10b5347e287cd617ebc7bfdde0a5f7f439b421de`. The complete `hepta/hia_slot_ledger_native.py` is 23,319 bytes, SHA-256 `9595b61a527521ed4b8577cb8b2f681655715b09bd6fd053f98e893de9b27922`. The 15-method `NativeSlotLedgerStore` class is 11,402 bytes, SHA-256 `16172cd330522af44375633aa8e1c043957f00b917a493579c61320157275e3f`. Its complete body and seven supporting original functions are materialized in `originals/`. `SOURCE-FREEZE.json` pins 17 full original files; `call-order.json` lists the original expressions and 15 SQL literal sites; `public-caller-map.json` lists the actual service callers.

A separate read-only Git comparison found that the slot file, `hia_agent_store.py` and `hia_native_delivery.py` at later local commit `de1aad29e83728292eff3486db25f1234d4d1638` have exactly the same bytes as these three sources at 10b. This is a three-file source comparison, not entire-tree equivalence or a qualification result.

## Main conclusion

Transition R2 retains the exact native workspace and actual native input/output until all original receipt checks finish. It does not associate the SQLite connection or the Store which supplied it. `NativeSlotLedgerStore` performs SQL before its next transition and after its last transition. A transition receipt therefore cannot ACK the entire SQL operation.

The minimum credible design needs three distinct lifetimes:

1. A fresh occurrence for each actual SQL call: preparation, final argument guard, actual call attempt, original returned or raised outcome.
2. An operation responsibility spanning the SQL prefix, later native calls and final SQL suffix of one Store operation.
3. An independently reserved observation in an actual outer activation which still requires its own ACK after the Store operation returns.

A retired child record cannot supply the third lifetime. Public and journal ambient activations with `capture_resources=False` do not automatically supply it. An implementation providing only the first two lifetimes must leave late outer-ACK retention explicitly open. `RESOURCE-API-PROPOSAL.md` specifies the proposed separation and original object-lifetime constraints; no shared implementation is changed here.

## Complete original effect order

This table is derived from original source, not an executed trace. SQL labels resolve to exact statements and parameter expressions in `call-order.json`. Provider calls, truth tests, field accesses and dynamic lookups remain part of the input domain.

| Original method | SQL and native order | Obligation |
|---|---|---|
| `snapshot` | Capture `self.store.db`; SELECT slot, `fetchone`; absent row goes to native 2. Present row: SELECT version, `fetchone`; SELECT active-lease COUNT, `fetchone()[0]`; decode artifact; native 2. | One or three SQL calls precede the decision receipt. Cursor and row decoding retain their own ordinary exception behavior. |
| `conditional` | Native 1 for expected generation and epoch; dynamic snapshot reader; native 3. | Nested snapshot occurrences stay distinct. Stale receipt retains original rejection and pending snapshot. |
| `admit_evaluation` | Three native 17 decisions; native 18; original special unhashable-outcome diagnostic or `_raise`. | No direct SQL; an error name does not establish native loss. |
| `admit_net_benefit` | Original objective property access; native 19. | No direct SQL. |
| `adopt`, absent slot | Native 12; sql1 INSERT slot; sql2 INSERT baseline version; native 7; sql4 SELECT generation cursor; native 8 for every original cursor row; native 9; sql5 INSERT candidate version; sql6 UPDATE slot; return. | Five SQL calls. Two INSERTs precede native 7; two final DML calls follow native 9. No arbitrary intermediate receipt discharges these SQL facts. |
| `adopt`, present slot | Native 12; sql3 SELECT current slot; native 4 ABI check; supplied `native`; native 5 digest check; native 7; sql4 SELECT generations; native 8 per row; native 9; final INSERT and UPDATE. | Four SQL calls. Preserve the unbounded cursor stream, numeric validation and provider order. |
| `rollback` | Native 6; sql1 SELECT retained artifact; native 10; decode and supplied `native`; sql2 SELECT current slot; native 11; native 7 then 9; sql3 UPDATE; return. | Three SQL calls; final update has no subsequent slot transition. |
| `acquire` | Capture DB; dynamic snapshot reader; native 6; supplied `native`; UUID, fields and wire; native 15; decode lease; sql1 INSERT lease; return. | INSERT follows final slot transition; nested snapshot may itself perform multiple SQL calls. |
| `lease` | Original `lease.keys()`; select original Store DB or supplied connection; sql1 SELECT and `fetchone`; native 16; decode accepted row and claimed artifact; native 13 or 14; decode lease value. | Preserve optional-connection domain and original diagnostic order. |
| `release` | Capture DB; dynamic `self.lease(..., release=True, connection=db)`; sql1 UPDATE; return. | The nested lease has its own occurrence. UPDATE follows its final native transition. |

Other complete helpers are `__init__`, `_execute`, `_call`, `_begin`, `validate_u64` and `_lease_value`. They are frozen with the entire class. SQL-bearing service paths include `inspect_slot`, `_slot_snapshot`, `_conditional_slot`, `_hia_adopt`, `_hia_rollback`, `acquire_slot`, `_lease`, `invoke_lease` and `release_slot`. Their exact definition pins are in `public-caller-map.json`.

## Transactions and direct calls

`acquire_slot` and `release_slot` enter the original `self.store.transaction()`. Normal request dispatch places adoption and rollback under its original transaction and journal protocol. Direct calls to Store-driver methods do not add their own transaction; `inspect_slot` does not add one either. Do not add BEGIN/COMMIT/ROLLBACK to direct calls or turn an accepted ordinary partial-effect rejection into automatic rollback.

Original AgentStore connects with `isolation_level=None` and `check_same_thread=False`. These are source facts, not durability observations. Future direct-call tests need a separate read-only observation of a real database; transaction controls must separately retain original rollback/commit results. A fake log or Python `execute` return cannot establish committed state.

Selected Store transaction provides a body `ResourceScope` and explicit body-result delivery; the reference transaction does not. An active native journal likewise does not imply pending-resource capture. Existing original slot-integration tests explicitly require native journal failures before and after ACK to preserve ordinary exception identity, rollback and intent/replay behavior. Broad new resource poisoning must not silently alter those contracts.

## Concrete future edit surface

The minimum product surface is `hia_slot_ledger_native.py` and a reviewed shared occurrence-series primitive. `_execute` needs fresh occurrence handling and a final literal-call guard. `snapshot`, `adopt`, `rollback`, `acquire`, `lease` and `release` need operation lifetime. `conditional` retains dynamic nested snapshot behavior. `_call` and `admit_evaluation` retain dynamic transition semantics and receive genuine native loss through the separately frozen transition repair.

The HIA source, 19 operations, wire/status/action/length/echo/checksum/state checks, numeric domains, generation stream and exact SQL literals do not change in this mechanical phase. This is not a migration of Python SQL orchestration into HIA. Original complete method bodies remain independent oracle sources, never a selected fallback.

If late outer-ACK retention is promised, exact service/journal/transaction activation sites are an additional explicit edit surface. Their complete old gates must run. This design does not authorize changes to these files, any old test body, frozen fixture, provenance acceptance or budget.

## Next gates and remaining boundaries

`CONTROL-PLAN.json` specifies future original-only cases, actual loss controls and complete existing gates. It contains planned controls, not executed inputs or expected observations.

First freeze an independent original-only finite oracle using this complete class and fake providers. It must cover order, dynamic overrides, exception identity/release and original partial effects before running a candidate. Fake state cannot prove SQL durability, a native handoff, installed-worker behavior or current-cold qualification. Original AttributeError fields, GC results and exception/release traces must not be normalized.

Actual native controls then call the saved real entry before losing/corrupting its receipt. They cannot assign `record.loss`, publish invented loss or manufacture resource-failure flags. Required examples include the real two-INSERT prefix, valid refusal counterexample, multiple distinct SQL occurrences, late-parent ACK, exact resource separation and swallowed/replaced child loss.

Complete inventories remain: Slot Source10 + Native5; integration13 including original nested10; ordinary9-module112; separate8-module128; TX61 (journal21 + execution-budget25 + slot15, original1800 seconds); existing11-component152 if shared behavior changes. These overlap and cannot be summed as unique tests. Existing Store130 and installed/journal/transaction gates remain applicable to changed caller paths. No skip, prerequisite failure, absent cold evidence, unknown process termination or partial prefix counts as qualification.

Explicitly open: no implementation/execution qualification; opaque provider internal actions; outer ACK without an independent opted-in holder; dead or changed-generation temporary Store; arbitrary raw connection close; source-only versus installed proof; exact direct-call partial effects. No retry, refund, rollback or new atomicity is introduced. Read one-SQL weak-R3, frozen Slot transition R2 and this multi-SQL proposal remain separate scopes.

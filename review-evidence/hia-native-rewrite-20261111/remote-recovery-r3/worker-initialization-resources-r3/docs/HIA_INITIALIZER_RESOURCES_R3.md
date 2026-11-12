# P12 resources revision 3 — completed owner event admission

## Exact previous failure

FOLLOW38 head 86c3e60966085f9aefde1170fbbb737c20a52422, run 43181547044, resource job 131058484994 compiled all thirteen images successfully. All three runtime groups failed at their first resource-begin-1 entry, with BAD and first reason 717. Completed case counts were zero; actual entry counts were 647, 747 and 647. The metadata image had not been entered. The complete original log, original panel JSON projections and archive identities accompany this revision. They remain failures.

The separate initializer semantic job 131058485019 completed all original eight cases and 10,592 actual entries. Its measured group aggregate CPU was 47.03958799999999 seconds under the unchanged 90 CPU / 180 wall / 1 GiB gate. Its eleven fresh images and its remaining twelve foreign initializer peer IDs are a separate scope. It does not retroactively change the earlier local 95.352369 aggregate CPU observation.

The source contract explains a concrete gap: registry and pure owners share a private session workspace, sequence, command counter and issued value registry. The current 256-byte event at offset 512 can be the last registry event HIAWGE01 or the last completed pure event HIAWPE01. Revision 2 accepted only the first. An observer must not substitute a cached registry event: a subsequent pure completion has already advanced the shared sequence and command counter. This report has not independently decoded the pre-entry frame from the original artifact; the new tests preserve that actual frame and workspace on every captured BEGIN.

## Native repair

The original rs_previous_registry body remains byte-for-byte unchanged after one new dispatch to rs_previous_pure. The resource result owner, the eleven predecessors, the metadata source, complete resource pool construction, ordering, payload comparison and reply code are unchanged. There is no host-side event normalization.

The new branch accepts only a completed HIAWPE01 action 4, not initial ISSUE, NEED or pending child events. It validates all 32 fields against the frozen pure producer contract:

| Words | Requirement |
| --- | --- |
| 0–3 | Exact magic, action 4, invocation and call |
| 4–5 | Actual nonzero sequence and command, each below u64 maximum so RESERVE can advance |
| 6–7 | Supported pure peer/kind/mode relation; completed pending is nonzero and strictly earlier than the actual P12 pending |
| 8 | Exact registry capacity expression 8192 + 16 × issued; checked arithmetic |
| 9–11 | Exact maps/values kind relation, nonzero completed child sequence, child allocation at least 4096 |
| 12–16 | All zero because a completed event exposes no pending child request |
| 17–19 | Mode 6 maps result borrows owner 1 at offset zero; other results use owner 3 with bounded nonzero child offset; Graph extent equals actual current Graph |
| 20–23 | Exact current Graph lease and extent, reply offset 1280 and extent 256 |
| 24–25 | Same-session issued value-handle range; modes 2/3 maps have two distinct handles, other modes one |
| 26–29 | No error, checked issued count, exact origin and current Graph node count |
| 30–31 | Exact peer/kind/mode relation and zero final reserved field |

Legal relations are values peer 9/kind 2/modes 1–6; maps peer 2/kind 1/mode 1; lookup peer 19/kind 1/mode 6; and maps peer 10/kind 1/modes 2–5. The new branch retains the entire original 256-byte event across resource GROW, and derives the next registry command from its actual command and sequence. All borrowed views are immutable and privately issued by the fixed trusted predecessor; correlation fields do not authenticate arbitrary externally supplied bytes.

The current Graph is already structurally validated by the resource BEGIN path. A child-relative graph offset identifies the original completed view, but this event alone is not external proof that some different buffer holds that view. This revision does not add such a claim or turn a Graph handle into file/namespace authority.

## Tests and budgets

The same three runtime groups and original test cases remain:

- resource-semantic: the original two complete initializer cases, all six resource operations each.
- resource-capacity: the original staged GROW case, all six resources and actual metadata growth.
- resource-protocol: the original complete initializer fixture and all 51 original faults, plus one actual registry-branch positive control and 35 new bad-pure controls, for 88 cases.

The first BEGIN snapshot now additionally retains the exact shared owner workspace. To exercise the original registry branch without changing the ordinary test route, the protocol group forks that captured private workspace and current Graph, executes the original actual registry BORROW on its already issued handle, and feeds that actual event to an independent resource workspace. It does not invent an event or replace the real initializer's pure predecessor. The original four registry-event faults use this actual registry snapshot. The other 47 original faults retain their original inputs and meaning.

The new 34 field controls cover action, context, sequence/command overflow, pending order, peer/kind/mode, registry capacity, child sequence/capacity, every reserved field, Graph owner/offset/lease/extent, reply extent, handles, issued count, error, origin and node count. A thirty-fifth mutates the retained event during GROW and must be rejected. Every full-workspace BAD is followed by an unchanged valid input to prove persistent refusal. The original short-workspace control still requires the caller to retire the lease.

No native test has run for this new revision yet. Fresh compilation is required for all thirteen images. The compiler remains the exact historical 668608-byte B3 with SHA256 0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8. Each compile retains 10 CPU seconds / 20 wall seconds / 256 MiB. Each runtime group retains 90 CPU seconds / 180 wall seconds / 1 GiB and separately requires measured aggregate process-tree CPU below 90 seconds. The same HIA function/block/instruction/block-parameter/SSA limits remain.

The new CI driver and test/helper filenames use r3. Its fresh project keeps the preexisting internal compile-r2 and resources-source-r2 output names to avoid unrelated producer/harness path changes; all output bytes, source SHA values, actual compile receipts and bundle identities are newly recorded and never reused as old qualification.

## Scope

This is a development component with Python mechanical forwarding and an independent original constructor/Store oracle. The actual P12 owner, actual metadata catalog, registry RESERVE/import and Graph merge must all execute. Physical Store put/SQL results and eleven other initializer peer IDs remain foreign. No ordinary Worker, physical namespace, public selector, installation or complete fixed Worker executor is claimed. The separate complete eight-case semantic budget gate is retained and is not replaced by these resource groups.

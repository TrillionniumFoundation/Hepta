# Native immutable values and typed scalar preparation

This private profile adds actual tuple and frozen record objects to the same native value arena. A node owns its actual class capability and field edges. No string spelling supplies type authority. Q01 operations 0 through 24, Q02 operations 25 through 31 and Q03 operations 32 through 39 retain their request domains.

The complete image exports `hia_result_value` with the existing six-word entry ABI, a stable 256-byte context and at least 8192 bytes of output. The new native packer uses `HIABVP04`, count 11 at offset 8, eleven role lengths at 16 through 96, mode at 104 and role bytes beginning at 112. Mode 1 returns a flat image and mode 0 an ELF object. Roles are owner, core, import, export, capture, format, number, dictionary iterator, classes, C3 MRO and records. Each role retains its 4 MiB bound and the image its 16 MiB bound.

## Q04 operations

The standard 128-byte request layout uses `HIABVQ04`, capability triples A at 24/32/40, B at 48/56/64 and C at 72/80/88, tail length at 96 and argument at 104. All unused fields and offset 16/112/120 are zero. Only operation 45 has a tail, exactly 5136 bytes containing the actual admitted generation ABI.

| Operation | Behavior |
| --- | --- |
| 40 | Capture an exact native list as an immutable tuple, or retain the same exact tuple. Child references are shallow and independently retained. |
| 41 | Construct an actual ScalarABI record from A=function, B=parameters, C=result. Constructor annotations do not validate the supplied values. |
| 42 | Capture the twelve GenerationInfo fields from an exact native tuple/list. The actual record retains its own immutable field vector. |
| 43 | Return an independently owned record field, with its field index at 104. |
| 45 | Validate exact function and arguments against the actual admitted ABI, then capture the scalar call frame while the value mutex is held. |
| 46 | Return the canonical tuple, ScalarABI or GenerationInfo class, catalog ID 28, 29 or 30 at 104. |
| 47 | Read the actual independent capability-node count without allocating or consuming any reference. The initial context anchor is not counted. |

Operation 44 is reserved pending the complete GenerationInfo.as_dict conversion. Tuple hash/equality protocols and public dataclass constructors require separate enclosing API completion. This checkpoint is not a complete public runtime qualification.

Tuple nodes have native kind 11 and frozen records kind 12. Their child vectors are inaccessible to mutation operations. Tuple indexing, length, enumeration and JSON array export use the existing native value operations. Empty tuples have one arena-owned canonical object. Existing frozen record fields may themselves reference mutable values, matching the shallow nature of frozen Python dataclasses.

## Scalar preparation under the two real locks

Operation 45 takes function A and arguments B. It checks exact str and membership first, exact list/tuple next, then arity and exact scalar types/ranges. New statuses 20, 21 and 22 distinguish those three original rejection groups. Invalid capability or dependency results remain private value failures. It emits no function pointer.

A successful `HIABVR01` reply has the selected ABI function index at 56, payload length 152 at 64 and required output size 8344 at 72. Payload at 8192 is `HIAMVCAL`, argument count, result type and sixteen native scalar words. The enclosing runtime must invoke this operation inside its existing lease mutex and retain that mutex through the actual scalar call. Standalone preparation does not establish that integration.

Operation 47 returns the count at reply offset 48. An enclosing owner must prevent concurrent admission before using it for destruction. Q02 anchor consumption does not prove all references have gone; final cleanup still uses its attested consumed/known/pending protocol and operation 31.

[HIA_NATIVE_VALUE_RECORDS_QUALIFICATION.json](HIA_NATIVE_VALUE_RECORDS_QUALIFICATION.json) records the actual native construction and primitive comparison checkpoint. Final original campaigns and enclosing call integration remain explicit pending gates.

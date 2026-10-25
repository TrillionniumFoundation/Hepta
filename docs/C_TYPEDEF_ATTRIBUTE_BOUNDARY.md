# C project typedef attribute boundary

Both ordinary project migration and explicit `hepta.c-record-views.v1`
contracts reject reachable typedef declaration attributes with `E_C_ATTRIBUTE`.
A contract does not authorize erasing ABI metadata. Attributes are checked on
all captured redeclarations and spelled alias chains before canonical type
resolution, including typed buffer pointer aliases/pointees. Context is local
to each captured translation unit. Unused system aliases remain context;
ordinary type nodes and nonsemantic documentation comments remain supported.

Canonical typedef context, rather than familiar names such as `uint32_t`,
determines scalar types. `size_t`/`ptrdiff_t` keep pointer-sized representations
only when their captured underlying width and sign match the captured model.
The existing same-model bundle requirement is unchanged.

The compiler-free regression tests use modeled Clang JSON. They do not establish
native layout agreement, foreign pointer validity, source equivalence or general
C support. Existing source-bound native alignment fixtures need rerunning on the
final candidate. Newly covered record-view pointer cases additionally require
real compiler AST capture and separate layout-oracle validation. Attributed
rejected outputs must never be linked or called with a mismatched ABI.

This narrow repair does not incorporate separate calling-convention or scalar
migration provenance fixes, and does not close the whole-project blockers.

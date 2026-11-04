# Source-local generic parameter restrictions

## Existing rule and imported exception

`SPEC.md` and `ADTS_GENERICS.md` already prohibit a type parameter from
shadowing a declared or reserved type name. For source nominal declarations,
that rule belongs to the parameter's own module. A type in an unrelated module
does not reserve the parameter spelling.

On #663 at `190ed6a7596acef83ea5fdc58f2c356d48438bf1`, this source rejects
when checked directly or used as the entry file:

```hepta
struct Secret { value: i32 }
pub fn answer<Secret>(value: Secret) -> Secret effects {} {
    return value;
}
```

The same declarations were accepted when imported, because `Secret` the
nominal was mangled but the generic binder was not. Adding another nominal
named `Secret` to the entry made the library reject again. Function, record,
enum, and self-named generic declaration cases reproduced this inconsistency.
The original accepted scalar/record/enum controls compiled and returned 42
under actual GCC O0/O3 with UBSan. This establishes a source-language and
portability discrepancy, not demonstrated misexecution or a security boundary.

## Small loader correction, existing checker authority

For otherwise well-formed ordinary generic declarations, the loader maps a
source-local colliding binder to that nominal's existing flattened identity.
The existing bound-Type traversal updates occurrences, `type_params` and
function `type_bounds` keys together. The checker now sees the collision and
rejects with `E_GENERIC_PARAMETER`, exactly as it already did for entry source.
Root spellings remain unchanged. No checker or backend invariant is relaxed.

This deliberately uses the normal checker result rather than a new loader
exception. Analysis retains its project, interface hash, checked result and
check-phase diagnostic, and module visibility errors retain their existing
precedence. No source-local collision reaches code generation through a newly
permitted route.

The existing duplicate/reserved parameter, invalid-bound and generic C-boundary
guards remain unchanged. Those inputs already reject, and this change does not
promise identical diagnostic sets for every malformed declaration. Unrelated
module alpha-renaming from #663 is unchanged. Function names, value bindings,
fields, import aliases, nominal constructors, public symbols and lifetimes are
not globally renamed.

## Compatibility correction

Previously accepted imported declarations that violate the documented rule
now reject. Rename the generic binder, for example from `Secret` to `T`, and
its bound type uses. Positional type arguments at callers and C symbols need
not change. Generic names participate in inspection/interface hashes and patch
contracts, so renaming is not identity-neutral for those consumers.

Newly rejected diagnostics can display the internal nominal/binder spelling,
with original source spans. Further capability/lifetime diagnostics may differ
from the formerly imported result because the collision now has the same
nominal identity relationship as entry source. The first applicable generic
restriction remains a rejection, not a new capability.

One #663 method intentionally recorded the imported exception. Its original
failure on the candidate was retained before reconciling that same method to
require refusal, check-result presence and check-phase `E_GENERIC_PARAMETER`.
Its root refusal and foreign-only acceptance controls remain, and a renamed
self-generic record still executes. No inherited method was removed, renamed,
skipped or weakened to accept alternative outcomes.

## Verification scope

The dedicated regression runner includes every method from the #663
427-method inventory and 23 new source-local methods: **450 unique methods**.
`python tools/test_module_same_source_generic_scope.py` requires real GCC,
pinned Rust, exact unique planned/executed identities and zero
skips/xfails/xpasses on actual Linux x86-64 and AArch64 hosts. Missing local
Rust is not a passing native gate. Frontend capability/lifetime controls are
not resource-lifecycle execution qualification.

Other shadowing rules, reserved nominal declaration behavior, arbitrary
recursive/worker execution, loader budgets, ABI contracts and Part03 remain
outside this correction. Finite results do not prove whole-language soundness,
complete module isolation, foreign correctness or production readiness. Draft
publication does not authorize a merge or deployment.

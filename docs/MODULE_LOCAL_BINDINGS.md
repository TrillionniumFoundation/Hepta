# Local bindings across source modules

File identity owns a source module's namespace. A private entry helper or an
unrelated module's C function must not reserve its spelling as a local variable
in every other file. The flattened checker historically rejected such programs
with `E_NAME_COLLISION`, even when renaming only the unrelated function made
the same library execute correctly.

The module loader now gives only these cross-unit colliding bindings internal
names before resolving references. It rewrites ordinary parameters, `let` and
`for` binders, match payload binders, their name expressions and explicit
borrowed-return origins together. Call targets, qualified aliases, function
declaration names, types, fields and lifetime names are not rewritten by this
pass. Checker and backend rules remain in force.

Internal names use the reserved module prefix followed by a decimal counter and
the original binding name. A source declaration identifier cannot start with
that counter. Selection also avoids the full flattened function inventory
after the C backend's `h_` local prefix, so a legal explicit C symbol cannot
capture a newly generated local. The choice is deterministic for the same
source graph.

## Deliberate boundaries

- Same-module function spellings are excluded. This does not change the
  bootstrap's existing same-module binding behavior or add general shadowing.
- Extern declarations are untouched. Their parameters were not subject to body
  binding checks and their existing interface/header/assumption labels remain.
- Exported C parameters retain their source spelling throughout the function,
  including nested binders with that spelling. A source C keyword or reserved
  parameter identifier must still reject, rather than become valid through
  internal renaming. Cross-unit collisions involving these parameters remain
  rejected in this bounded repair.
- Match `_` remains a wildcard. Equal source binding names stay equal, so
  duplicate and overlapping-scope binders still reject. A renamed reference
  before declaration or after scope exit does not gain access to a function.
- Newly accepted ordinary parameters and locals can have internal spellings in
  flattened interface/inspection data and generated debug names; source spans
  still identify the original files and positions. Existing successful
  noncolliding programs retain their names and generated source.

This pass is separate from function/type import-visibility checks and does not
relax or replace them. It does not qualify every language feature, general
object layout, recursive programs, native worker lifecycles or foreign code.
Finite native tests and exact-source CI are regression evidence, not a proof
of whole-language soundness or complete module isolation.

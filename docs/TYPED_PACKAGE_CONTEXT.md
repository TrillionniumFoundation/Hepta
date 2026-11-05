# Context consistency on versioned typed packages

This bounded composition applies #720's verified context correction to exact
#719 `b67d1a00acec941ecc7f4218020a2eae8f6cd2b4`, tree
`1e66d7348eaaa4d5df2c28b6c112d6fb167e3642`. P01/P11/P12 remain PARTIAL.

## Separate source and actual typed behavior

Fresh reads show #690, #698, #709 and #719 retain unguarded module blob
`e6b2696e4c6ff1294e6c46ccdf994cc1513d4c19`. #720 fixes it on #698, not on
those other source trees. This composition uses the same three-line correction
and produces exactly #720's guarded module blob
`e0985f626bd1357d863a6a179c5763bce2ffee4c`.

The new fixtures copy the actual typed packet adapter, packet implementation
and four source libraries byte for byte. Two nested typed candidates select
low/high library versions. The application also has a deliberately different
local packet fixture, reachable through an unused local import of the selected
typed library. Only this application-local fixture is altered, not a supplier.

On the original source, the first context retained for a physical module wins.
An unused local-first import can therefore change the selected dependency's
typed result even with a freshly generated lock. The guard refuses conflicting
reuse in both orders at the second import's exact source span. It does not
backtrack to a different package version in response to a module error.

Positive cases retain Unicode success, exact Result/Unit/Bounds values,
ScalarCapacity payloads, complete scratch/scalar backing, repeated same-root
dependencies, distinct unselected candidates, explicit refresh and byte-exact
manifest/lock rollback. Nested candidates' source files remain covered by the
root source inventory even when their package is unselected.

## Preserve all parent obligations

Of #719's 308 files, **303 remain byte-identical**. The five changes are:

- The exact three-line `hepta/modules.py` guard.
- One module-hash slot in the store provenance manifest.
- Module and store-manifest identity slots in the typed provenance manifest.
- The two adapted-manifest identities in the versioned provenance manifest.
- An explicit extension to the versioned verifier. It preserves every original
  inventory, source check and inverse-transformation obligation and adds strict
  validation of this context composition.

All five originals remain byte-identical under `tools/typed_context_origins/`.
Their Git and SHA-256 identities are hard-pinned in the verifier. Removing one
exact guard must recover the original module bytes. Each current manifest must
equal a deep copy of its archived original with only the named slots changed.
The original store and typed verifiers remain unchanged and mandatory.

The outer source manifest binds every #719 input, four exact #720 qualification
files and the new reviewed sources. All ten parent workflows, every original
test/runner/inventory, all four libraries, compiler backends and historical
qualification documents are preserved. The archived verifier is historical
evidence; the current verifier is explicitly extended, not described as unchanged.

## Scoped reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 python -B tools/qualify_typed_package_context.py
```

The command runs **99 exact methods**: the 83-method scoped #720 selection,
all 12 original #719 migration methods and four new typed/context methods.
Planned = started = finished = passed is mandatory, with no skips, expected
failures or unexpected successes and unchanged source hashes.

The new methods cover both selected versions, both import orders, three entry
forms, locked/unlocked loading, C/Rust frontend rejection, complete typed values
and backing storage, upgrade/refusal/rollback and overlays. Original #719
methods retain intentionally wrong ordering/error-payload programs and their
expected native assertion aborts.

Three additional oracles execute: the unchanged acyclic package integration
oracle (326 states, 748 comparisons), the exact #720 context oracle (48 context
refusals, 16 positive frontends, eight native runs) and the independently authored
typed-context oracle (33 context refusals, ten native runs). The typed oracle
constructs its expected lock snapshots independently and uses hand-written
Unicode, typed-payload and complete-backing assertions, not the new test helpers.

This is C native evidence. Rust frontend emission does not establish native
Rust execution. The original #719 484-method/13-oracle aggregate is **not run**
by this command. The original #720 scope's cycle-specific and native Rust
omissions remain unexecuted; no reduced scope replaces the full parent gates.

## Failure history and remaining limits

#719's two Python 3.13 aggregates and standalone bytes oracle previously failed
when GCC's cc1 was killed. Original source, documents and recorded qualification
limits remain unchanged. This scoped work does not rerun that bytes oracle or
claim its blocker is fixed.

An initial unpublished attempt at this new 99-method scope was interrupted by
execution-environment replacement. Its ephemeral source/log/session could not
be recovered, so that aggregate outcome remains **unknown**. The present
candidate was reconstructed from exact remote #719/#720 bytes in a fresh
workspace. Only new completed verification of this source counts toward its
qualification; earlier reported oracle summaries are not substitutes for new
retained logs.

No workflow, matrix or manual dispatch is added or weakened. Required inherited
hosted results remain separate exact-head evidence. Native Rust, ARM, Python
3.11 and the complete #719 aggregate remain unexecuted locally. No recursive
program execution, literal validation, function-signature audit, C-import
publication or output-alias work is included. No universal solver, registry,
semantic compatibility, performance, formal soundness or production claim.
Lock review remains `compatibility: not_assessed`. Draft only; no merge,
release, deployment or activation.

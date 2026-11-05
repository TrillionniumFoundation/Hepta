# Fieldless source enums in the independent C backend

This is a finite P11 language-coverage increment on main
`125d11c5454835a7df1dc51915fc49901fbede5b`, not closure of P11 or P01.
It does not incorporate other research drafts. In particular, C header enum
imports are separate: these are source-level nominal values, not integer aliases
and not a public C enum representation.

A later bounded extension specializes concrete Copy-generic source enums; see
[C_GENERIC_ENUMS.md](C_GENERIC_ENUMS.md). The original scope and qualification
results recorded below describe this earlier increment, not a new full gate.

## Supported contract

- Non-generic source enums with one or more fieldless variants.
- Construction, Copy values, parameters and returns, assignments, nested
  non-ABI records and fixed arrays, and borrowed read/mut enum or slice parameters.
- Exhaustive statement matches, arbitrary arm order, nested matches, local arm
  scopes, continuing arms, early returns, and matches inside existing loops.
- The scrutinee is evaluated and copied exactly once before dispatch. Mutating
  its original place in an arm cannot change the selected branch. Only the
  selected arm executes; its completion does not leave an enclosing loop.
- Source module resolution and nominal typing remain in the unchanged frontend.
  Existing effects, mutability, exhaustiveness and conservative C borrow checks
  still apply.

Internally each enum receives its own generated struct type with a `size_t` tag.
Names come from a separate compiler prefix, so source names like `array_1` cannot
collide with generated array types. Tags are declaration indices, while match
cases use the corresponding variant identity rather than arm order. Every
case has a block and explicit break; the default aborts. Foreign construction
of tags and representation-dependent operations are not a supported interface.
This layout is compiler-private and has no size, tag or binary-stability promise.

The stacked [Copy-payload increment](C_PAYLOAD_ENUMS.md) extends this original
fieldless contract to supported non-generic tuple payloads. Unit payloads,
generic enums/functions/records, builtin Result and unions remain unsupported. An unsupported enum declaration rejects even
when unused. Enum exposure through C exports, extern declarations or repr(C)
records remains rejected. This does not add equality, ordering, integer casts,
pattern guards, catch-all arms or match expressions. No ownership/resource-payload
ADT, runtime allocation, scheduler or unsafe foreign-lifetime feature is added.
Existing C host/data-model restrictions remain; no no_std or cross-target claim.

## Reproduction

From the repository root with native GCC and Python 3.11 or newer:

```
python -m hepta run examples/fieldless_enums.hepta --backend c
python tools/validate_c_fieldless_enums.py
```

The frozen inventory contains 198 unique methods: 15 new enum methods, eight
unchanged C-backend methods, 149 parser/checker methods and 25 ADT syntax/refusal
methods, plus the existing cross-feature unsupported-language integration method
updated to use a Unit-payload enum. The runner requires exact planned/started/finished/passed identities,
zero skips/expected failures, and unchanged input hashes. This is a focused gate,
not the full project's native, formal, performance or release suite.

Nine new consumer methods each compile and execute C at O0 and O3 with
nonrecovering UBSan. A tenth runs the checked-in example through the actual CLI.
They cover 129 separately constructed variants with Python-generated expected
outputs, single-variant types, nominal name collisions, nested storage/copies,
read/mut parameters/slices, module aliases, dispatch ordering, exactly-once
side effects, branch scopes, return paths and loops. Five refusal methods retain
frontend, ABI, unsupported ADT and borrow boundaries. Both frontend emitters run
for every native consumer. Emitting Rust alone is not native Rust validation.

To require actual pinned Rust comparison at both optimization levels as well:

```
HEPTA_ENUM_REQUIRE_RUST=1 RUSTC=/path/to/rust-1.90.0/bin/rustc \
  python tools/validate_c_fieldless_enums.py
```

The dedicated read-only workflow runs that strict mode on the exact PR head,
Python 3.11/3.13 and Linux x86-64/ARM64. It retains identity and full test logs.
Missing tools or failed setup are not successful qualification. Hosted results
must be checked against that exact commit; publication/queueing is not a pass.

## Local evidence and retained development results

- Python 3.12.14 and 3.13.5, actual GCC 14.2.0: 198/198 methods each, no skips.
- Native Rust and ARM were not available locally and were not executed.
- The same final new suite with unchanged main production yields 3 failing
  methods, eight errors from unsupported enum lowering and four passing methods.
  One failure is the existing whole-enum refusal occurring before the new
  enum-specific overlapping-borrow refusal. These are method counts, not subcases.
- Initial implementation had an unhandled builtin Result constructor lookup;
  the final implementation checks type admissibility first and the refusal
  regression passes. An independent reviewer found an enum/array helper-name
  collision; the separate generated enum prefix repairs it and the regression
  executes natively. The initial runs are not counted as successful final gates.

Finite execution and UBSan evidence do not prove whole-language soundness,
full backend equivalence, arbitrary unsafe/foreign inputs, performance superiority,
platform ABI qualification or production readiness. P11 remains PARTIAL.

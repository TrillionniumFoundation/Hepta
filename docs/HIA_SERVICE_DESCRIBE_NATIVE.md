# HIA service discovery control

## Status and source boundary

This component gives an explicitly selected HIA image the continuation policy
of `HIAAgentService._hia_describe`. It does not replace Python module loading,
catalog implementation, Store/profile publication, opaque object protocols or
the eager resource dictionary with native implementations. The ordinary service
still has a retained handler when this component is not selected.

The reference is the complete original method in
`hepta/hia_agent_service.py` at commit
`3424f6d116a087373b161b9970cad07c65a9e4c4`, tree
`9fa3bc3d2699a18f0a78bd646a4d7b7af9fed84a`. Its 1,992 exact source bytes are
retained in
the `tests/fixtures/hia_service_describe_original_3424/` directory as
`describe.3424.py.txt`,
SHA-256 `bfed8acb543c9234c553c3e01ff37bfa24233c1a8b57adae3215a2839fc6c481`.
The adjacent source-identity and freeze records distinguish this original from
the candidate. Candidate output does not supply the original expectations.

The authored HIA source is `examples/hia_bootstrap/service_describe.hepta`.
Its initial generated source is 30,993 bytes, SHA-256
`9aa7d5d20fe250913ecbfa3e8dfd10e9226d61adb5d5cda236b67859fa6f5125`.
Source generation and static inspection establish no execution qualification.
Complete finite comparisons, actual Native calls, installed use and retained
caller runs must have their own exact-tree evidence. This document makes no
whole-stack replacement, production activation or old-stack deletion claim.

## Ownership and foreign expressions

The image issues every operation and selects the next continuation after an
acknowledged observation. The adapter dispatches only that claimed operation.
It never invokes `_NATIVE_SERVICE_DESCRIBE_REFERENCE` on the selected route.

| Port | Foreign observation | HIA continuation |
| --- | --- | --- |
| `import_catalog` | Original relative import of `opcode_catalog` | Check cursor membership |
| `has_cursor` | Truth of the original cursor membership expression | Reject cursor or check backend membership |
| `reject_cursor` | Original `reject` provider and original arguments | Continue to backend membership if the provider returns |
| `has_backend_profile` | Truth of backend membership | Compare the backend only when present |
| `backend_differs` | Truth of the original backend inequality expression | Reject the profile or continue |
| `reject_profile` | Original `reject` provider and original arguments | Continue to language selection if the provider returns |
| `language_schema` | Original `args.get` call and default | Query the imported catalog |
| `language` | Imported catalog call | Publish/query the profile pair |
| `profile_pair` | Original `self.store.profile` call and two-value unpack | Read the requested section |
| `section` | Original `args['section']` lookup | Construct and select resources |
| `resources` | Complete eager resource dictionary, then its key lookup | Construct the result |
| `result` | Original result dictionary expression | Release original local custody |
| `release_locals` | Normal local-reference release | Return the result |

Only the three predicate ports return observation values 0 or 1. Successful
observations from every other port are exactly 0. Every claimed foreign
exception requires a matching HIA exception acknowledgement before ordinary
propagation. An unconfirmed native handoff or foreign acknowledgement fences
the invocation; it does not trigger a retained-handler fallback or retry.

The first effect is the original import, before any membership checks. Its
literal import bytecode uses a fixed private proxy to the original function's
bound builtins and global namespace. This preserves late import-hook lookup,
relative-import arguments and the original namespace seen by that hook. It
does not claim equivalence of Python frame identity or arbitrary frame
introspection.

Backend membership and inequality remain separate HIA decisions. The absence
of `backend_profile` prevents all comparison-side lookups. Both rejection
providers may raise or return; an ordinary return follows the original
fallthrough instead of inventing an early return.

The `resources` expression remains eager. It constructs all six values in the
original order: manifest, language, backend, examples, diagnostics and plans.
Only after that construction does it index the dictionary by `section`.
An error or observable lookup in an unselected section therefore still occurs
at its original expression boundary. Moving the dictionary to a lazy switch
would change this behavior and is not this component's contract.

## Invocation protocol and custody

The ABI has an 80-byte request, 96-byte result and 128-byte private state. Its
magic values are `HSDREQ01`, `HSDRSP01` and `HSDSTA01`. The protocol is version
1 and uses a nonzero 128-bit invocation nonce.

The request carries the event, current sequence, current port, observation,
version, nonce and two reserved zero words. Initial state must be entirely
zero. A newly issued operation must be claimed before its foreign effect.
Claiming preserves the sequence and port; an acknowledged success or exception
advances the sequence. Sequence overflow, stale state, a wrong nonce, invalid
reserved fields, malformed observations and illegal phase transitions cannot
produce an ordinary accepted continuation.

The adapter checks the entire request remains unchanged, both output and state
guard regions, the return length, all output/state fields, the state checksum,
nonce, version, expected sequence and expected phase. Normal termination is
accepted only after `release_locals`. Exception termination carries the
explicit failure marker and no further port. The state checksum detects
accidental/tampered transport state; it is not a cryptographic authorization
mechanism.

Every invocation has an existing `DeliveryRecord`, reserved before native
entry. A claimed effect receives one fresh foreign activation with explicit
resource capture. The adapter validates the full native acknowledgement and
the exact pending activation before confirming it. Only then does it retire
healthy pending resource observations and, where appropriate, mark terminal
completion. Actual child handoffs and completed resource scopes establish
resource custody. A service getter, equal path or matching exception class
does not establish that custody.

Ordinary provider exceptions, including `KeyboardInterrupt`, `SystemExit` and
`MemoryError`, retain the original propagation path after a valid exception
acknowledgement. Actual delivery loss remains sticky through existing native
ancestry. There is no new replay policy, timeout, cancellation rule or
production deadline.

## Local lifetime

The original method has nine local slots: service, arguments, imported catalog,
language schema, language, profile, language reference, section and resources.
The adapter preallocates a builtin dictionary for these slots before invoking
providers. Fixed private probes observe the actual runtime's frame and
dictionary release directions; slot ordering follows that observation rather
than a Python version label.

The HIA owner requests normal local release only after constructing the return
dictionary. On the exceptional path it does not clear the original locals
early or collect garbage. Their real traceback determines their lifetime.
This mechanism still needs complete same-runtime observation and teardown
checks; the implementation alone is not proof of all object-lifetime behavior.

## Selection and build

`HEPTA_HIA_SERVICE_DESCRIBE_MANIFEST` explicitly selects the component. An unset
selector preserves the original handler. An empty or invalid selected value
is rejected; it does not silently choose the original handler.

The manifest schema is `hepta.hia.service-describe.v1`. It binds the canonical
HIA source digest, sibling image basename, image digest and compiler digest.
Admission verifies exact manifest fields, ordinary bounded file reads, the
source and image hashes, pinned worker-image identity where present, and a
second unchanged read of all three artifacts.

`tools/build_hia_service_describe.py` requires exactly one of an explicit
development build or a matching current-source cold report. It freezes its
component inputs, checks the compiler's complete output packet and resulting
image, and rereads the compiler, inputs and cold source snapshot before writing
its build result. A development image remains a development component. A
matching cold component remains one component rather than a default release.

The original observer, source fixtures and selected-handler tests live in
`tests/hia_service_describe_oracle.py`,
`tests/fixtures/hia_service_describe_original_3424` and
`tests/test_hia_service_describe_native.py`. Future qualification must retain
complete original and actual observations, failures, source identities, owned
process termination and the original caller scopes. Overlapping or partial
caller runs cannot replace their complete scopes or full regression.

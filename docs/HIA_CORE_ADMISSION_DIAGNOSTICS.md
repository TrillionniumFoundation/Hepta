# Native Core diagnostic frames

The explicitly selected primitive Core image retains the original admission
order and limits. It publishes complete value, body-policy and declaration error messages
in native memory. The host adapter checks the frame and transports its bytes;
it does not choose runtime text, templates, insertion values or error order.
The Python reference and unselected behavior remain available.

## Exact decision scope

The original value lookup exits retain frame version 1, families 1 and 2:
`E_HIA_SSA` for an undefined/nonlocal value and `E_HIA_RESOURCE` for an
already-consumed resource. Every declared and referenced identifier, including
an undefined reference, has passed the original 1..128 ASCII-byte name grammar.
The largest messages in these two families remain 412 and 153 bytes.

Frame version 2, family 16, carries the remaining body-policy messages selected
at the original refusal edge: opcode/version and local instruction contracts,
callee lookup and signatures, scalar literal/cast checks, owner and loan guards,
return capability checks, branch/edge type and liveness checks, predecessor
agreement and missing effects. The generated catalogue contains 39 message
programs. Multiple original failure edges may use the same program.

All insertion values are chosen by HIA from the admitted decoded arena or
the live policy state. In particular, an unsupported opcode is the original
complete decoded UTF-8 string. A call output mismatch carries the complete
Python-style list of the callee's admitted primitive return types. Missing
effects retain the original sorted list spelling. There is no truncation,
new arity cap or smaller input budget.

Frame version 2, family 17, carries 66 original declaration message programs:
program/schema/function inventories, exact field sets, parameters and returns,
versioned loan interfaces, effects, block/instruction shapes, SSA definitions,
all identifier positions, CFG connectivity and explicit scalar exports.
Each original refusal edge records its native message program and inputs.
The original policy AST is recovered exactly by removing the instrumentation
and restoring two same-order short-circuit conditions. Nontext terminators
retain the original "missing terminator" refusal before any opcode lexeme read.

Invalid names keep the original fixed message; the invalid value is not
inserted, coerced or truncated. The four duplicate-name programs insert only
names that already passed the original 1..128 ASCII-byte grammar. Their largest
message is 169 bytes. Complete invalid-name input values may still be long or
non-ASCII; no smaller name-input or document budget is introduced.

Strict JSON/snapshot and composite/legacy refusals remain outside this
diagnostic extension. Unreachable internal graph/capability corruption is not
promoted into an arbitrary public-arena API. Full code/type/message equivalence
for every `verify_program` input is not claimed.

## Private ABI v4

The manifest schema is `hepta.hia.core-admission-native.v4`. The entry remains
`f0(readbuf, mutbuf, mutbuf) -> u32`. The original state prefix is followed
by the existing dedicated 576-byte tail. The decoded JSON arena remains a
separate third buffer.

The tail starts with eight little-endian u64 words:

| Word | Version 1 | Version 2 |
| --- | --- | --- |
| 0 | bytes `HIACD001` | same |
| 1 | 1 | 2 |
| 2 | actual returned status | same |
| 3 | 0, 1 or 2 | 16 (body) or 17 (declaration) |
| 4 | complete message byte length | same |
| 5 | value-message capacity 512 | state-prefix size minus 16384 |
| 6 | zero | payload offset 16384 in the state buffer |
| 7 | zero | zero |

Version 1 family zero publishes no message. Families 1 and 2 use the 512-byte
tail payload exactly as before. Version 2 uses a complete UTF-8 payload in the
old state prefix; its 576-byte tail does not grow.

At a body or declaration failure, HIA records the selected message program and its decoded
node/bitmask inputs at the original refusal point. The complete policy stack
then returns to `f0`. Only after the status and these inputs have been captured
does the formatter overwrite any old state prefix. It never looks up another
symbol, capability, current block or function in the retired state. The
decoded arena remains unchanged and supplies all referenced strings/lists.

The shared constant table occupies at most bytes 0..16383. The current 105
programs (39 body and 66 declaration) use 8256 bytes; source preparation binds
and independently records the actual generated table. The message starts at
16384 and must finish before the tail. Formatting succeeds completely before
version, family, size, capacity and offset are published; the original returned
status is written last. A scratch/ABI refusal has no valid receipt.

The adapter accepts only the fixed offset and exact physical capacity,
checks status/family/version, rejects an empty or overlapping range and
strictly decodes the published UTF-8 bytes. Its logical receipt consists of
the native 64-byte header and those complete native payload bytes.

## Capacity and admission limits

For input size B, N=min(262144,ceil(B/2)+1) and S is the least power of two at
least 4N. The original state prefix size P is
128 + 24S + 4096*40 + 120N; the existing tail adds 576. The f0 allocation guard
runs before the original declaration writes. The maximum P is 56,787,072 bytes;
the original standalone CLI reservations of 64 MiB state and 32 MiB arena
remain sufficient.

The two variable-length message cases are mutually exclusive. The unsupported
opcode template uses direct string insertion, not repr or quoting, so its
UTF-8 payload is at most B + 19 bytes. The return-list case contains only
admitted primitive type names, whose longest spelling is seven ASCII bytes.
Its payload is at most 29 + 11N bytes. Other body programs are fixed catalogue text plus bounded opcode names,
effects or one version digit. The 66 declaration programs use fixed text and
at most one already-admitted 128-byte duplicate name, at most 169 bytes in all.

Before N reaches its ceiling, P is at least 163968 + 216N and B is at most
2N; the table and either payload fit. At the ceiling, P - 16384 is
56,770,688, exceeding both 8,388,608 + 19 and 2,883,613. The tail is outside
that region. These are layout bounds, not a native runtime performance claim.

Original input ceilings remain 8 MiB, 262144 JSON value nodes, depth 64,
1024 functions and 4096 blocks per function. The generated kernel must still
fit the original compiler's 128 functions, 1536 blocks, 8192 instructions and
all original argument, SSA, relocation, source and image limits.

## Host and qualification boundaries

Strict immutable snapshots, JSON/type admission, canonical transport,
composite elaboration, the nominal-v2 namespace guard and public
VerifiedProgram custody retain their original owners and order. The ordinary
Agent still applies its existing response-envelope limits, including its
4096-character error-message presentation; this component does not change
that policy.

The original 29 test IDs and inputs are retained. In one existing method,
the three invalid-reference-name assertions are strengthened from the former
family-zero/no-message limitation to complete independent-reference type,
code, message and native bytes for family 17. The previous test file and its
narrow diff are retained outside the source tree; all other original test
statements remain unchanged. Ten added controls exercise all 66 declaration
messages, maximum names and wire length, source function/block and first-error
order, publication bounds, corrupt frames and a real selected Agent request.
The existing body/value, VM, Core-profile and ordinary-caller controls remain. Static generation/discovery, actual component
execution and future matching-source cold/full qualification remain distinct.
The default is unchanged. No host owner or historical failed run is retired
by this candidate.

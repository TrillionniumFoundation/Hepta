# Shared HIA program service development

The ordinary CLI and the eleven-tool worker require the same complete program
semantics. This directory owns shared language metadata and, in subsequent
components, program verification reports and inspection projections. It does
not replace the agent contract's tool-input schema validator. Object building,
lowering inspection, direct patch contracts and patch-impact analysis remain
distinct unfinished owners until connected and verified.

## Fixed language metadata

The first component embodies the complete eight-version primitive opcode
catalog, compatibility/schema registry and existing public CLI capabilities as
ordinary HIA source constants. These are finite language-contract data. They
contain every original instruction, operand/result rule, attribute, effect,
trap, resource transition, guard, terminator, type group and scope statement.
They are not answers to arbitrary program inspection requests.

The source constants omit catalog digests. HIA selects the exact version,
expands its own losslessly packed constant pool, computes full SHA-256 using
the retained HIA algorithm, and inserts the actual digest into sorted canonical
JSON. The registry receives that same freshly computed v8 catalog digest. No
Python import, JSON encoder, metadata builder or hash call executes in the
native component. Authoring and independent oracle code are development tools.
The emitted `.hiaasm` is sufficient to compile the owner with the existing B3
compiler and its unchanged source limits.

Capabilities currently describe the unchanged public product entry. Its hosted
implementation and false native qualification/activation fields must be changed
only as part of actual complete product promotion. A passing metadata owner does
not make those claims true.

### Private request and result

The R/R/W entry takes exact immutable schema bytes, a 96-byte command and a
private zero-initialized workspace. The command is twelve little-endian words:
`[HIAPMC01, 1, lease, request, operation, explicitSchema, schemaBytes, 0,0,0,0,0]`.
Lease and request are nonzero. Operations are 1 capabilities, 2 opcode catalog,
3 schema registry. Only catalog accepts a schema; flag zero and empty source
select the original `None` default, and flag one is an exact UTF-8 string.
Unknown schema strings produce the original `OpcodeRejected` message and code
`E_HIA_OPCODE`. Arbitrary foreign Python object arguments are not this boundary.

The workspace initially has at least 3072 bytes. It may return GROW (`fffffffe`)
with the exact constant-derived needed size. Resume must preserve the complete
96-byte command, source bytes and private state. Success or semantic rejection
closes the lease. Invalid packets or mismatched resume permanently refuse it.
Every resumed operation also cross-checks stored correlation, operation, schema
flag and selected version against the original command and exact source.
The event at offset 2304 contains sixteen words: magic `HIAPME01`, action,
lease, request, operation, result offset, result byte length, detail, then eight
zero words. Actions are 0 result, 1 grow, 2 semantic error and 3 private refusal.
Detail is needed capacity for GROW and error category 1 for `OpcodeRejected`.
These internal tokens are not public admission or program verification receipts.

The fixed constant pool is packed only to keep the ordinary HIA source under the
unchanged compiler operation limit. The source contains the entire pool and its
expansion algorithm. Runtime inputs cannot provide or replace compressed data.
Every back-reference and final length is checked before native memory access.

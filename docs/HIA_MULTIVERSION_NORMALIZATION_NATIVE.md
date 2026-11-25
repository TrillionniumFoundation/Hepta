# Native normalization before scalar preparation

The ordinary `hia-nominal-constructor` product owns complete Core and composite
normalization. A preparation or proof facade captures this executable once,
verifies its installed identity, seals that capture, and executes it in a fresh
process. Its private assembly entry contains process-local globals and is not
an in-process concurrent normalization API.

## Invocation and result

Set the single argument, including argument zero, to `hia-admit-agent-json`.
Standard input is the actual JSON bytes, bounded by the original 8 MiB limit.
The process rechecks JSON, elaborates composite v1 through v4 when selected by
the actual schema, and independently verifies the complete primitive result.
There is no Python semantic fallback.

An exit-zero result has a 64-byte little-endian header: `HIAVCF01`, action zero,
error zero, profile, original canonical byte count, primitive canonical byte
count, and two zero words. Exactly those two byte strings follow. Profile zero
means primitive input; profiles one through four identify the actual composite
version. The caller verifies the header, both lengths, and exact end of input.

For refusal diagnostics, the same sealed executable can be invoked with its
single argument `hia-verify-core-json`; its diagnostic is the original Core
error, without interpreting a partially lowered program as verified. A facade
must account for both invocations under its existing absolute deadline.

## Three identities and the multiversion boundary

The actual request byte digest is distinct from the canonical original-input
digest and the canonical primitive-Core digest. Primitive original-input and
Core bytes coincide. A composite's two canonical representations can differ,
and both must remain attached to the preparation. Caller-supplied verification
flags or hashes are not an admission authority.

The original multiversion scalar profile rejects a verified structured source.
A successfully normalized composite must therefore still reach that original
structured-source rejection; it must not acquire multiversion authority simply
because its primitive result contains a scalar public function. The general
proof facade has its own original selection and profile rules.

## Actual qualification

The accompanying qualification records 74 original tests with all assertions
unchanged, followed by 337 fresh original-verifier/native-process input pairs.
They include composite resources, partial records, returned loans, original
multiversion profile inputs, repository Core examples, pretty input identities,
and malformed JSON boundaries. The 138 successful pairs compare the complete
header and both canonical byte strings; 73 are composite inputs. All 199
refusals compare the fresh original diagnostic text. Each invocation executes
an actually sealed copy of the installed native product. The 27 captured HIA
and transport inputs are byte-identical to the product's frozen source commit.

This proves the tested normalization and rejection interface. It does not mark
the complete multiversion coordinator, general proof service, or whole-native
installation as closed.

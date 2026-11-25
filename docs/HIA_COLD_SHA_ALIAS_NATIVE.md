# Native SHA companion qualification

The current companion preserves the complete 1,184-byte streaming state ABI
and the original six-word entry ABI. It routes only proven disjoint buffer
ranges to a pure HIA fast implementation. Every alias, zero-length, endpoint
overflow and uncertain foreign-pointer case follows the unchanged original
HIA fallback. The mechanical prefix performs range classification and jumps;
it contains no SHA computation.

## Repeated-word rotation

The fast implementation reduces rotation instructions without changing their
entire u64 result. For a value x below 2^32, multiplying by 2^32+1 places x in
both halves of a u64 without overflow. Shifting that repeated word right by n,
for 0<n<32, exactly equals the previous expression
(x >> n) | (x << (32-n)).

The message schedule uses this identity only for words written and masked by
the same compression invocation. Initial chaining words remain arbitrary u64
values: the first round retains the original rotations. Each round masks the
new a and e before the next round, so the remaining 63 rounds satisfy the
identity's premise. The first four rounds are emitted before the remaining
60-round loop to keep that premise explicit. Message, state and padding
writes retain their original order. The complete output and all state bytes,
including noncanonical full-u64 states, remain observable by the original
qualification harness.

## Native construction and unchanged fallback

The nonalias source uses the already qualified independent endian seed.
No new opcode or seed profile is introduced. Native source projection,
reference-wire construction and the independent seed build the fast flat;
the native HIA constructor joins it with the exact qualified fallback.

The public companion is 112,221 bytes: the unchanged 89-byte mechanical
prefix, the unchanged 64,588-byte fallback, and the 47,544-byte fast flat.
The constructor receives HIASHA01, two little-endian u64 lengths, then both
flats. It retains its previous bounds and atomic refusal behavior. Production
construction executes no assembler or linker.

## Preserved qualification

All original 27,043 semantic cases pass, including arbitrary full-u64 state,
streaming partitions, padding, large messages, concurrent states, buffer reuse
and foreign aliases. Another 2,000 offset-alias cases compare complete owner
buffers and canaries. The original 5,894 mechanical routing cases and all 51
native constructor controls also pass.

The actual archive consumer passes both original nineteen-case live and AZ02
suites, including real source, journal and output mutations. Six interleaved
executions of the same real original-chain archive compare all 28,828,792
output bytes and the complete native receipt. Every output is identical.
Median wall time decreases from 3.769824213 to 3.167296017 seconds. Each
private harness run also records its actual child user and system CPU time.

The adjacent JSON pins the source, flats, independent constructor and each
complete report. Its construction report retains the annotation that existed
before semantic qualification; the separately pinned completed reports supply
the subsequent evidence. This component result does not establish the full
60-phase, 180-second cold replay. Consumer reconstruction and the actual
complete replay remain separate release gates.

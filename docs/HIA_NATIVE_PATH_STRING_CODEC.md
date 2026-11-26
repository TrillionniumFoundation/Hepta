# Native path window codec

This pure HIA component transports path strings without using JSON export of a
whole public value. Mode 0 quotes raw WTF-8 bytes as a JSON string body, preserving
lone surrogate code units for the actual path resolver. Mode 1 decodes actual
filesystem UTF-8 bytes with surrogateescape, producing WTF-8 for the native exact
string owner. It performs no method call, path resolution, type admission or
filesystem access.

The six-word entry requires input at least 128 bytes, output at least 128 bytes
and work at least 32 bytes. `HIAPCDQ1` has mode at 8, tail length at 16, process
limit at 24 and final-window flag at 32. Words 40..127 are zero, and tail length
must equal the actual input length minus 128. Mode 0 requires limit equal to the
tail length and final flag zero. Mode 1 requires a Boolean final flag; nonfinal
windows include at least three lookahead bytes and process limit does not reach
those last three bytes. No input-derived total path quota is introduced.

The `HIAPCDR1` reply reports consumed bytes at 8, output bytes at 16 and total
required output extent at 24. The remainder of the header is zero. Payload
starts at 128. Return 0 means success. Return 1 means short output: only the
header is written, with the complete requirement and no partial payload.
Malformed private input returns `0xfffffffd` without an output write.

The implementation first computes the exact result extent, then emits it. It
accepts only well-formed Unicode scalar UTF-8 sequences. Every malformed byte
from 0x80 through 0xff becomes its corresponding U+DCxx code unit. A sequence
crossing a window's processing limit may consume at most its three supplied
lookahead bytes. Final truncated sequences use the same surrogateescape rule.

Actual native qualification on CPython 3.14.4 passed the original eight groups
with 326032 calls: all 256 filesystem bytes; all 65536 two-byte combinations;
JSON roundtrips for all 1114112 code points including lone surrogates; filesystem
decoding for all 1112064 Unicode scalars; 10240 randomized malformed/window
comparisons; byte-split quoting; exact and short output; and malformed private
frames. The unmodified qualifier executed the compiled HIA image. Both native
compilations produced the same 28197-byte image with SHA256
`845ee4a64d8bf3458f143ff94f13b7d7a27573507497f720e6a8d58a7da1a575`.

The same source-bound construction also rebuilt the previously qualified native
path resolver, compiled its new HIA packer twice, constructed the object with
the actual native packer, and passed all 24 packer cases. The fixed syscall
bridge then passed 21 real filesystem comparisons, including a 96-link chain,
a lexical path longer than 4096 bytes, loops, surrogateescape, adjacent lone
surrogates, embedded NUL, and descriptor retirement. The input to the resolver
uses this codec's actual WTF-8 output so adjacent lone surrogates retain their
original identity. Construction and terminal job evidence are recorded in
HIA_NATIVE_PATH_INTEGRATION_QUALIFICATION.json. Shared-library linking is an
external qualification step; production construction uses the HIA packer.

These results qualify the codec and resolver packaging components. Public
constructor composition, the complete native runtime, production activation,
and repository cleanup require their enclosing gates.

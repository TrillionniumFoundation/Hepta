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

Development author qualification passed eight groups with 326032 calls: all
256 individual filesystem bytes; all 65536 two-byte combinations; JSON
roundtrips for all 1114112 code points including lone surrogates; filesystem
decoding for all 1112064 Unicode scalars; 10240 randomized malformed/window
comparisons; control-character and byte-split quoting; exact versus short output;
and malformed private frames. These are exact-author checks under CPython
3.12.14, not execution of a compiled HIA image. The same qualifier has an actual
image mode. Native compilation, native-image qualification and final DAG
integration remain required and are recorded as pending.

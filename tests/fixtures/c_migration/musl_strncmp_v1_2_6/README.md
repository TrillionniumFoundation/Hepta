# musl 1.2.6 generic `strncmp` maintenance input

This is the complete unmodified `src/string/strncmp.c` from the official musl
1.2.6 release archive, with the complete release COPYRIGHT and README.
`UPSTREAM.json` records the archive digest, file identities and the mirror tag
commit. The mirror commit-pinned files were separately compared with archive
members. The official cgit endpoint returned HTTP 503; the tag commit is
therefore identified explicitly as mirror-derived. The release archive was
retrieved over HTTPS; its PGP signature was not verified.

The 220-byte function body is byte-identical to the pinned 1.2.5 fixture. The
COPYRIGHT file has changed. This is a subsequent-release maintenance case for an
unchanged function, not evidence for automatically adapting a changed function.

`platform/string.h` and `contracts.json` are authored, byte-identical adapters
from the 1.2.5 fixture. Both read slices must have at least `n` live initialized
bytes; an early NUL does not relax that admitted contract. The same C11,
unsigned-char, Linux x86-64 LP64 build profile is used. No arbitrary foreign
pointer or complete musl libc ABI is qualified.

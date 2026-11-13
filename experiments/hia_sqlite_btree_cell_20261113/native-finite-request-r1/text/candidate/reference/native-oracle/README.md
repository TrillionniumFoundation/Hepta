# Selected-cell C reference adapter — uncompiled draft

The two C translation units retain the complete four original SQLite cell-parser functions, both original varint functions and their constants, all three complete original structures, the complete recorded primitive definitions, and the exact four original local-payload-limit assignments. ORACLE-DRAFT.json records every embedded original range, byte count and SHA-256. The complete official source files and both actual LICENSE.md files remain in the frozen B-tree reference tree.

No compiler, C entrypoint, HIA generator, VM, native image, SQL operation or database has been executed in preparing this adapter. This directory is an input draft for a separate, explicitly frozen native request.

## Interface and projection

`uint32_t oracle_cell(const unsigned char *page, uint64_t page_bytes, uint64_t usable, uint64_t kind, uint64_t cell_offset, uint64_t *out6)`

The output has exactly six native uint64_t words (48 bytes), in this order:

| Word | Original CellInfo observation | Matching HIA descriptor |
| --- | --- | --- |
| 0 | All 64 original nKey bits, copied with memcpy | key_bits, word 11 |
| 1 | Whether pPayload is NULL | page_type == 5 |
| 2 | Page-relative pPayload offset; zero only when the NULL bit is set | payload_offset, word 7 |
| 3 | nPayload | payload_size, word 8 |
| 4 | nLocal | local_payload_size, word 9 |
| 5 | nSize | cell_size, word 6 |

The NULL flag is independent of the offset. An index or table-leaf zero-length payload still has a non-NULL payload pointer.

Return 0 means an original cell function returned and the pointer projection stayed within the supplied page. Return 1 is a basic harness-context refusal before calling an original parser. Return 2 reports an unexpected out-of-page non-NULL pointer; the other original scalar fields remain in out6 and offset is UINT64_MAX. Record the complete C output, source before/after, canaries and return value before projecting or asserting the result.

## Exact finite applicability

Only the 253 accepted rows from the frozen R3 Source12/339 matrix may call this adapter, after the separate pure-byte layout reader has admitted a complete valid selected cell. Applicability is selected from that frozen matrix, never from the new native implementation's observed status. All 86 HIA refusal rows remain NOT_CALLED for each C version.

The ordinary harness initializes the original structures' required fields from the independently checked page kind, usable size and selected-cell offset, following the recorded decodeFlags mapping. Unused original fields remain zero. The four local-payload-limit assignments are exact upstream text. The wrapper does not add a replacement cell or varint decoding algorithm.

The upstream functions have no input-length parameter. The adapter's basic context guards do not make these C routines a general malformed-input oracle. Preserve the independent complete-cell admission check and the entire page buffer with canaries.

## Build and scaffolding

Keep assertions enabled and retain -fno-strict-aliasing and -fno-fast-math. Compile-time assertions establish eight-bit bytes and the exact original integer widths. Fundamental sqlite_int64/sqlite_uint64 aliases and opaque pointer declarations are standalone harness scaffolding. The complete MemPage, BtShared and CellInfo definitions are retained, including the original conditional fields.

The two non-public varint helper names are remapped by version-specific preprocessor aliases so both reference libraries can be loaded independently. The original excerpt bytes remain unchanged. testcase is explicitly disabled coverage scaffolding. The mutex assertion accepts only the fixture's NULL mutex; this is not a database-lock implementation. SQLITE_NOINLINE retains the GNU noinline attribute.

The original C functions do not validate page headers, select cell pointers, validate child or overflow page numbers, follow overflow chains or perform pager I/O. HIA descriptor words outside the projection above must be checked by the frozen independent format model, and must not be claimed as outputs of these original C parsers. No whole-page/tree, SQL, transaction, recovery, locking or matching-cold qualification follows from a successful finite comparison.

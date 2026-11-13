# SQLite B-tree selected-cell C reference contract

This reference retains two independent upstream versions. The extracted functions are unchanged source excerpts; no C compilation, C call, HIA generation, VM call, native call, or SQL execution has occurred in preparing these files.

## Complete originals and extraction

Each version directory contains the complete btree.c, util.c, btreeInt.h, btree.h, sqliteInt.h, sqlite.h.in, and the actual repository LICENSE.md at its fixed commit. UPSTREAM.json binds exact bytes, SHA-256, Git blobs, and source offsets for every excerpt. The two LICENSE.md files differ and both are retained in full. The .source.txt fragments are reference excerpts, not a standalone compilable SQLite build or an oracle adapter.

cell-functions.inc contains the original overflow adjustment, no-payload parser, table leaf parser, and index parser. varint-functions.inc contains the original two SLOT constants, sqlite3GetVarint and sqlite3GetVarint32. The latter is retained to document the 32-bit macro contract; it must not silently replace either inline payload reader outside the declared domain.

## Minimal oracle inputs

A future ordinary-data adapter may call the corresponding original function only after independently admitting a complete valid cell and its required original MemPage/BtShared fields. No original parser has an input length parameter; passing arbitrary invalid or truncated cells to it is outside this reference contract.

The planned development domain is one selected cell in a page of 512..65536 bytes, with a valid usable size (page size minus reserved bytes, at least 480), legal page type 2, 5, 10, or 13, and a complete local cell including any four-byte overflow pointer and minimum cell padding. Payload values are at most 2147483647 and their encodings occupy 1..5 bytes. Rowids retain the complete u64 bit pattern in 1..9 bytes.

MemPage fields used by the four original functions are pBt, leaf, intKeyLeaf, childPtrSize, minLocal and maxLocal. BtShared supplies usableSize and the mutex used by assertions. The complete upstream structure definitions are retained; a later adapter must state any reduced harness structure explicitly and must not describe it as the complete original engine.

The original decodeFlags dispatch is: type 5 -> btreeParseCellPtrNoPayload; type 13 -> btreeParseCellPtr; types 2 and 10 -> btreeParseCellPtrIndex. Type 2 has childPtrSize 4, type 10 and 13 have childPtrSize 0, and type 5 has childPtrSize 4. Table leaf local maximum is U-35. Index local maximum is floor((U-12)*64/255)-23. All four page types retain the original minimum floor((U-12)*32/255)-23; table interior has no payload and does not use that allocation.

When payload P exceeds maxLocal, original surplus is minLocal+(P-minLocal)%(U-4); nLocal is surplus if surplus<=maxLocal, otherwise minLocal. The original cell size is payload-header length+nLocal+4 for overflow. A nonoverflow table/index payload cell has minimum nSize 4, including unused padding. A no-payload table-interior cell has nSize=4+rowid varint width and no payload pointer.

## Full CellInfo projection

Retain all five original fields: nKey, pPayload, nPayload, nLocal, nSize. Table nKey is an i64 representation of all rowid bits; project it by a defined u64 conversion or memcpy of those bits. Index nKey is the payload count. pPayload must retain a separate NULL indicator plus a page-relative offset when non-NULL; NULL for a table-interior cell must not be conflated with an ordinary header or offset zero. nPayload is u32 and nLocal/nSize are u16 in the original structure.

The table parser uses a pointer type-pun to preserve rowid bits, so any future harness build must retain -fno-strict-aliasing and establish CHAR_BIT=8 and exact u8/u16/u32/u64/i64 widths. Trace/testcase and mutex scaffolding must be explicitly described. That scaffolding is not part of the cell-layout algorithm or a database lock implementation.

## Deliberate boundaries

The original inline payload readers consume seven bits of the ninth byte and perform width-specific unsigned arithmetic; sqlite3GetVarint uses all eight bits of its ninth byte, and sqlite3GetVarint32 may saturate a wider result. The planned HIA payload restriction to 1..5 bytes prevents a false assertion of full noncanonical equivalence. No statement here expands that restricted HIA API into the whole SQLite cell domain.

These four functions do not select a cell pointer, read or validate left-child/overflow page numbers, check all page headers, verify freeblocks or other cells, follow overflow chains, validate the whole B-tree, or perform pager/database I/O. Any new HIA checks of those selected-page fields are separate API admission behavior. A passing valid-cell numeric comparison would not establish whole-page or SQL-engine qualification. Invalid HIA inputs must be checked without calling these unbounded C routines.

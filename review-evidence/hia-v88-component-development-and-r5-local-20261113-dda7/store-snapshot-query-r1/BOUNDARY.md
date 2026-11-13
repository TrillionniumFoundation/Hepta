# Fixed requests query over an explicit SQLite snapshot

This development image implements one complete byte operation: given an immutable SQLite main-database snapshot and a UTF-8 key of at most 64 bytes, find the six-column `requests` record whose TEXT primary key equals the supplied bytes. The policy runs in HIA: database header, sqlite_schema lookup, table B-tree traversal, signed rowid ordering, overflow payloads, record serial lengths, key comparison, duplicate-match refusal, and bounded result publication. The returned payload is the original SQLite record. The development harness only boxes that returned record into Python values to compare it with the independent SQLite query.

It does not parse arbitrary SQL. It does not acquire locks, serialize a live connection, commit pages, replay a WAL, modify a database, or replace the existing AgentStore connection. Snapshot acquisition, transaction and lock ownership, SQLite writes and the surrounding worker remain separate external responsibilities. No production/default selector, shared source, original test or budget is changed. This is not a whole-native or cold-qualified Store.

## Input and output

The six-argument byte ABI is the existing compiler ABI: immutable input pointer/size, distinct mutable output pointer/capacity, distinct mutable workspace pointer/extent. All three allocations must be independent caller-owned extents for the duration of the call.

Input is eight little-endian u64 words: `HIASQRY1`, version 1, database byte count, key byte count, and four zeros. Key bytes follow the 64-byte header; the complete snapshot follows the key. Workspace is 16,814,080 bytes. Database size is bounded at 64 MiB, record size at 8,390,656 bytes, and key size at 64 bytes.

Success output has eight u64 words: `HIASQRS1`, version 1, found flag, requests root page, rowid bits, record byte count, visited page count, zero. The record follows at byte 64. A missing key has found/rowid/record-size all zero. Return is exactly 64 plus record size. Refusal returns one of 0xfffffff0 through 0xfffffff6 and leaves every output byte unchanged. Workspace is scratch and may change on refusal. Input and outer canaries are checked unchanged in every actual native call.

The profile is SQLite rowid-table format 4, UTF-8, power-of-two page sizes 512 through 65536, usable page size at least 480, no auto-vacuum, and the original AgentStore requests declaration modulo whitespace. It accepts the original WAL-format header when the bytes came from an actual connection snapshot. It checks ranges, row ordering, visited-page reuse, record bounds and overflow termination of the traversed tables. It is not a general `PRAGMA integrity_check`, does not validate every other table/index/freelist, and is not an equivalence claim for corrupted or arbitrarily altered SQLite schemas.

The format reference used for authoring is the official SQLite file format, https://www.sqlite.org/fileformat.html . The external snapshot API reference is https://www.sqlite.org/c3ref/serialize.html .

## Same-transaction snapshot and observable boundaries

The actual SQLite 3.53.1 / CPython 3.12.14 observations cover:

- the same connection's uncommitted insert, update and delete;
- rollback and restored committed contents;
- a reader transaction retaining the previous snapshot while another connection commits to WAL;
- the reader obtaining the later committed value only after ending its old transaction;
- a direct main-file read missing an uncommitted record visible through the transaction's connection snapshot.

The current snapshot acquisition port is **not observationally interchangeable with Connection.execute**. `serialize(name='main')` actually produced two `PRAGMA "main".page_count` authorizer/trace events. The original SELECT produced its own table-read authorization and statement trace events. Two additional synthetic controls confirmed both directions of the mismatch: denying PRAGMA can reject serialization while permitting the original SELECT, and denying table reads rejects SELECT while serialization still returns snapshot bytes. No row was evaluated or returned under that denied-query control. The image is therefore exposed only as this explicit immutable-byte operation; it is not installed behind a live query or used to circumvent the existing SQLite authorization surface.

A production pager replacement must own the same transaction capability as request journal, artifact namespace and slot publication, and must supply the current committed plus uncommitted pages under that capability. Reading only a path or treating a package/hash as transaction authority is insufficient. Writes, locks, durable commit and cross-table atomicity must be migrated together under an explicit new backend contract before removing SQLite.

## Evidence and limits

The single development compilation used the exact 673,413-byte B3 image with SHA256 `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`, under the original 20-second, 1-MiB compiler output/workspace limits. The new source is 94,147 bytes with SHA256 `9dec178e3d65dcbc8684348f4f42cbc5c6d835f0b8fdff81717a695bc4bfda1f`; it contains 20 functions and 1,633 operations. The 125,710-byte compiled image has SHA256 `4cd2ab37e9bdee4f443249871af6298679237fb519b2fff43954316faba8a6a0`.

The original primary run is retained as FAIL: 65 original six-column query comparisons and one main-file negative observation passed, then a fixture incorrectly asserted that serialization had no observer events. The next continuation is also retained as FAIL: 13 bounded-refusal observations passed, then a fixture incorrectly assumed a multi-row overflow table still had a leaf root. Subsequent controls only executed the unfinished cases; they did not rerun or relabel those 66 or 13 completed observations. The final overflow refusal and two explicit authorization-mismatch controls passed. An additional 8-MiB response compared completely equal, a one-byte-short output was rejected without writes, and a record beyond the declared profile was rejected.

Six already captured native frames were replayed through the independent Core VM with the original 10,000,000 fuel / 64-MiB memory / 128-call-depth limits. All return values and all three complete buffers matched byte for byte. The VM replay made zero new native calls. The small initial five-case smoke is recorded separately. In total 89 actual native entries were observed across these separate runs; this is an execution count, not a unique-test qualification denominator.

All fixed source/image inputs were unchanged in each scope. No original Agent48, namespace35, ledger48, full Source or cold suite was run or inherited. No performance improvement is claimed; this first query kernel scans its table and is not a replacement for SQLite's indexed query performance.

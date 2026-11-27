# Linux process: source, portable observations and complete raw custody

This node preserves the exact authored source delta, registration contract, all local observations, and their original failures and transport records. It does not claim positive matching-current-source cold qualification, native CPython 3.14 qualification, or whole-system completion.

## Observed scopes

- First source revision: 87 methods passed on CPython 3.12.
- First portable revision: one complete real sdist/wheel/install/reference-VM method passed.
- Successor source revision: 17 source methods passed after the explicit Root preflight dependency and strict readback additions.
- Successor portable readback: existing complete portable originals were reread; zero new packaging or product commands.
- Current-cold positive and actual 3.14 native groups: not executed by this scope.

The immutable source packet is 49341a9888619f8d7bca0f585d230b2eb0491f2d and its registration specification is 088bdbe10f9afd6ed0d7f32078a388deb904e54f. The final independent source tree is 3a1c42c02bee93486b1cb440b2f44a8b32dccf65.

## Complete original evidence

The archive contains 1,339 logical files (101,776,815 bytes), represented by 853 exact content objects plus its manifest. All original bytes, symlink targets where present, file modes and directory modes are recorded. The 29,008,707-byte gzip is transported as 56 no-newline UTF-8 base64 blobs. These are wrapper Git blobs; the computed raw binary Git identity does not assert that a binary Git object was uploaded.

Every wrapper was POST-acknowledged and fetched in full. An independent actual restoration from the fetched copies verified all wrapper and decoded identities, the entire gzip CRC/ISIZE, all 854 tar members, and every logical file's bytes, SHA-256, Git identity and mode.

Place the mounted files in one directory and run:

```console
python -B restore.py TRANSPORT.json . NEW_EMPTY_TARGET
```

The twelve authored/dependency files and complete local original observations are embedded. The unchanged full source baseline is external: fixed Root tree d91c9154cbed9cc1473aad4e152049dc21c6ab9d (3,064 files). The source packet and final manifest describe the exact 3,074-file successor; this evidence archive does not embed the entire unchanged baseline.

The earlier process-development failures and raw observations remain a separate immutable scope under recipe a66c166016fb9a7012bd45d257080c92ec9f5f27. They are not reclassified as current-cold or new native qualification.

## Transport history

The source-publication preflight GET failure was retained; an actual subsequent fixed-object 404 preceded the single successful POST. During raw transport, chunks 48 and 49 were already fully acknowledged and fetched when a local read-only validation exceeded a one-second execution yield. The first scheduler incorrectly rejected that running session. Its exact session was resumed to exit zero; no POST was repeated. The original error, recovery terminal, both scheduler versions and all per-item receipts are preserved.

TRANSFER-RECEIPTS.zlib.json contains exact UTF-8 transfer records, encoded as zlib plus base64 with independent decoded identities. It can be decoded without importing any product code. Final metadata publication receipts are provided separately by the handoff.

No product, source, workflow, branch or audit reference was changed by this custody operation.

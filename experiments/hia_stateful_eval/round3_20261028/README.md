# Historical prepared-runtime protocol

`PROTOCOL.json` is the byte-for-byte protocol from donor archive
`0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997`, at this same path.

- Git blob: `27586976663d8bff0a722fbe13eb388580bc1d46`
- SHA-256: `50217b19d8b638792b7af6c3c53365d01cc3b238480a83a2f5fca0cd00849062`

The unified regression inventory explicitly includes this protocol directory.
The integration retained the corresponding optimizer and NDU protocols but
omitted this one, so the inventory failed before loading any tests on a clean
CI checkout. Restoring the declared input repairs that omission without making
the inventory optional or changing the test suite, verifier, or acceptance
criteria.

This file preserves an older experiment specification. It is not a new
registration, execution, or result for the unified source. Historical source
and working-tree identities remain in
[`docs/HIA_INTEGRATION_SOURCES.json`](../../../docs/HIA_INTEGRATION_SOURCES.json).
No historical result is imported by this restoration.

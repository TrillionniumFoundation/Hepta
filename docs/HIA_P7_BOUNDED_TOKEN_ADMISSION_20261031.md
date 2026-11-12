# HIA P7 — typed and bounded queue token intake

**Research-only, authority DENY_ALL, all P0–P7 production gates remain OPEN.**
Parent: #478 exact HEAD `7a39d62e9dd3988682b6b96ddb0b40ec21a020d7`.

P7 queue APIs should never call the hash/equality function of an attacker
supplied object while holding the owner lock, nor hash unbounded untrusted
text before checking the token budget. The parent accepts arbitrary objects
in cancel/status/execute/audit via `_queues.get(token)`; its continuation
has an exact builtin-str type guard but no length/ASCII bound.

Before the fix, an arbitrary `__hash__` or `__eq__` can execute at lookup.
The originally attached test-only commit intentionally tests this unfixed
boundary. A green candidate requires a single narrow exact builtin string,
ASCII-only, 1..64 length admission rule for all five public paths. The native
producer-generated token remains a 32-character hexadecimal string, and
short historical internal test tokens continue to work.

This does **not** confer authentication, cryptographic queue authorization,
durable journaling, cross-process exactly-once effect safety, hardware
portability, compiler soundness or positive NDU economy. Legitimate native
queue execution and exact-source P0/P1/P5 tests must remain green.

## Exact commit history and qualification boundary

- Parent #478: `7a39d62e9dd3988682b6b96ddb0b40ec21a020d7`.
- Test-only/unfixed negative commit: `6b8a0d1bc6c0d24a24cb291f78a924b9616c4b81`. Retain its actual CI result as a negative if it fails; do not call a queued run red.
- Fixed candidate: enforce exact built-in `str`, length 1–64, printable ASCII before all five public queue operations and both underlying direct helpers. Legitimate generated 32-character queue IDs continue to work.
- The strict native source-bound CI includes the new adversarial suite plus actual Linux Clang20/Z3 owner and independent ELF replay; all stages remain research-only DENY_ALL.

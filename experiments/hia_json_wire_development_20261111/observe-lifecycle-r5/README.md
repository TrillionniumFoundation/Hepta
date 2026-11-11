# One-shot native wire observation transport

This is a new development observation on the exact published r5 source and image from the canonical e09 package. It is separate from the frozen r7 performance candidate and does not recover or qualify the unknown earlier local session 96283.

The unmodified session repeated a foreign SUMMARY callback in three of five actual controls: repeated observe before reply consumption, observe after terminal bad-sequence status 199, and observe after the foreign callback raised. The original probe, outputs, and package readback were published before the implementation changed. A new regression method also failed those same three subcases on the old adapter.

The adapter now allows one observation only after an actual native request. It consumes that permission before reading the observation or entering foreign code. A new native step invalidates any preceding permission; terminal steps and terminal sessions cannot enable callbacks. This is transport lifecycle bookkeeping. HIA still chooses all traversal, admission, numeric, escaping, ordering, and output decisions. HIA source, native image, manifest, protocol packets, and normal callback order are unchanged.

The identical five-case probe has no callback replay after the fix. The new regression method and two existing actual-image methods (protocol/extent/canaries and buffer lifetime/exceptions/reentry) passed: 3 tests, zero failures, errors, skips, expected failures, or unexpected successes, in 0.032 seconds on Python 3.12.14. The small driver explicitly admits the existing r5 manifest and runs only those methods. It does not call their normal compiler-building setUpClass and does not claim a full module, installed wheel, current-source cold build, full 89 caller run, or performance-budget pass.

Source SHA256: a8fca6a58ecaa7e6f4faa0fa6a509ba8fe1748640799b8827a2e0f48ba16c8a9.
Image SHA256: 46e03185fc7f25771514f41dee552c2fb7106ffbe36ed81d415259cf5ba0f907.
Original adapter SHA256: 1404d8b7bb7dd0c138e4ad64f9901f8cb6ecc613dd8652872589d387f57bdcf8.
Fixed adapter SHA256: d5e278483a8f19f5a1152502a0a1e46a30511daabbc2fd63a230619001a9ae49.

The full 1666-member materialized source inventory was checked; only the adapter and dedicated native test module changed. Original r5 artifacts remain in ordinary-r2-r5/raw-development-r2-r5.tar.xz. The public misuse diagnostic now identifies terminal sessions or absent unconsumed observations. Arbitrary mutation of private continuation state and concurrent use of the same session are not proved safe by these controls.

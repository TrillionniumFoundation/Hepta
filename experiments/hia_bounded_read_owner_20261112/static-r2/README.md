# Bounded-read terminal-result permission — static revision 2

This checkpoint contains an unexecuted candidate change to the private bounded-file read continuation. It is based on exact acffa9262f31d073f8f0a6f0201eae201039f619 / tree 22a095436c94efc87b1a89aca912c8caab2eed80. It changes no production file, public dispatch, contract or workflow.

## Concrete change

The original static r1 bridge allowed repeated `finish()` calls to decode the retained output. A kind-3 terminal result includes a foreign diagnostic constructor and exception-context operation, so source inspection shows that repeated calls, including after `close()`, could repeat those effects. The ordinary proposed `read()` wrapper calls `finish()` once. This is a private protocol finding, not an executed public API failure.

Revision 2 adds one terminal-result permission. A real native return of status zero grants it only after entry accounting returns normally. `finish()` checks and consumes it before decoding the envelope or calling any foreign operation. `close()` and every exceptional session path clear it. Invalid packets, nonzero terminal native status, premature finish and post-entry accounting exceptions cannot grant a result permission. The original finish body is preserved inside that guard; its original foreign exception is re-raised with bare `raise` after sealing.

The HIA generator remains exactly 9003 bytes / SHA256 e21045b16a5d50ad9d63a2bf2e0cfda595b16edc22bfcbe5df5547bb1bc3a201. The r2 bridge is 12139 bytes / SHA256 73bb61c65daf6efb45c3d246aa3385d0d250b15043aad1baa8801ac220d45708. No native image currently exists for this bounded-read candidate.

## Required observations

The validation plan lists ten concrete lifecycle controls. They must call an actual compiled entry, preserve the old r1 bridge, and record native status/output plus foreign constructor/read attempts. A mocked success envelope cannot establish the intended old-versus-new result. All original eight program-tools test IDs, full caller census, 8 MiB default, explicit limit behavior, and original 3/5-second product assertions remain required.

## Remaining boundaries

Neither source file has been parsed, generated, assembled, imported, compiled or executed in this revision. The source-authoring worker will be a separate draft and is not yet approved for dispatch. There is no source or native PASS inherited from ELF, installer, CLI, page or any earlier component.

Path/OS access, CPython buffered file IO, opaque object operations, context-manager protocol and exception identity remain explicit foreign runtime primitives. The original dynamically replaceable `_reject` helper is not yet faithfully represented by r1/r2's direct diagnostic construction; a replacement that returns also needs HIA continuation handling. Temporary release/finalizer schedules and full public-domain parity are still open. This checkpoint must not be used to claim a Python-free runtime, a complete read-owner replacement or permission to delete the old owner.

The r1 source and review history remain unchanged at 7d5a4c4a8551807b6722116af0a5364741151080, under `experiments/hia_bounded_read_owner_20261112/static-r1/`.

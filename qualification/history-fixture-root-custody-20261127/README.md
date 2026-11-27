# Historical fixture root and terminal capture

The original exact 4ed7bf2 historical readers could admit an installed source
from an independent reader directory even when that directory lacked its two
history fixtures or contained changed copies. The helpers read the valid
fixtures beside their imported author modules instead. The original physical
reproduction retains five false acceptances across two failing test methods.

Both fixed-fixture helpers now accept an explicit reader root and capture
callback, pass them to nested history readers, and bind their complete original
fixture bytes again at terminal readback. Their fixed fixture hashes, full-file
successor/predecessor identities and inverse transforms remain unchanged.
The Delivery consumers pass their actual root and capture context, so the outer
terminal read includes the history files actually consumed.

Eleven real controls pass without skips. They retain the original failure,
exercise complete actual builder and installed-caller predecessors, missing and
changed physical fixtures, capture-time mutation, a mutation after the nested
reader returns, independent root selection, unknown source bytes, and a fresh
data-only import guard. The run used macOS Python 3.9.6; it does not claim a Linux
product run, full caller suite, new cold qualification or whole-stack closure.

The archive contains every original and repaired materialized source/fixture,
complete stdout/stderr, operator terminal records and readback. Every member was
independently reread and checked against members.json. The initial failed copy
from an older 6f source without the later authoring-history fixture is retained;
the second copy is explicitly checked against the unchanged exact Git pins.

Run the repaired controls from a complete checkout with:
    python -B -m unittest tests.test_hia_history_fixture_custody

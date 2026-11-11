# Step exception closure draft

This source-only delta follows the five passing private lifecycle controls retained by canonical c4a21f0. It has not executed. The old five-case success record is preserved with its original scope.

An independent review identified a second private interruption window: a BaseException after native entry returns but before step updates finished/pending can retain an old SQL observation permission. This candidate closes both fields inside step and uses a bare rethrow in the same function. The existing observe guard and its original effect ordering remain unchanged.

The extended control keeps the first five cases and adds actual native entry invocation returning 199 for malformed ACK, followed by the same ForeignStop under an existing handled OSError. It requires both subsequent observe and step to refuse, zero SQL INSERT attempts, and unchanged exception object, held traceback identity, original traceback tail and ambient context. This is an authored control, not yet a reproduced finding or fix validation.

Use the actual previous adapter ff49d9779e532f91a4d8e4f1341b0b729dd1392416d3520fe18990854902db50 for the original comparison, then this candidate. The HIA page image and HIA source do not change. Wait for the coordinated wire performance window and retain exact source/image pins and all original results. No public request failure, persistent-disk durability or whole-native delivery is claimed.

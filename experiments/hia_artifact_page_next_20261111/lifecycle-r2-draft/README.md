# Private continuation lifecycle draft

This checkpoint is source only. No controller, HIA image, product or full qualification test has executed for this delta. The previous development records remain bound to adapter d54b0999af3829d865e362d593ad6d0dfc06670e316005bd0a863a573324cab5, page image f2aaee2be275fb3f8831ae994e4c03f0ec6a12c53892fe8840eb4a4fa8270d3d and their recorded historical wire source/image.

The candidate adds a finished check and consumes a private observation permission before each foreign operation. A foreign BaseException closes the continuation and is re-raised unchanged. The exact original adapter remains in the prior checkpoint and in the immutable Git parent history. No HIA source or page image changes are proposed here.

The authored five-case probe uses an actual page image and a source-matching wire image, plus isolated in-memory SQLite. It counts attempted INSERT calls as well as rows, because INSERT OR IGNORE can hide a repeated operation. Planned controls are ordinary single execution, malformed ACK followed by stale observe, duplicate observe before ACK, successful terminal observe rejection, and the same original foreign BaseException with retained traceback/context. These controls must first run against the original adapter and then against the candidate; neither result exists yet.

Run the archived probe with explicit --source-root, --draft-root (the prepared development page workspace), --adapter (original or candidate), --wire-manifest, a fresh --output, and --expect observe/fixed. Wait for the wire owner's exclusive performance window and its new matching image. A static defect candidate is not counted as a reproduced defect. No disk durability or whole-native delivery claim is made.

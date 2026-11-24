# Native cold journal back references (AZ03)

AZ03 only removes repeated physical journal bytes within the current phase. Every plan node is still executed, every raw chunk is still encoded and decoded, and every raw result remains reconstructible. It is not an execution-result cache.

## Wire and bounded state

A reference is exactly 40 bytes: `HIAQAZ03`, raw byte count (u64), payload length 8 (u64), mode 3 (u64), and the physical offset of a prior original AZ01/AZ02 record (u64), all words little endian. Raw sizes remain 1..65504. References cannot name another reference, a later record, a non-boundary, another phase, or an original record smaller than 64 bytes. The referenced original must have the same raw size.

The fixed table has 8192 entries of 64 bytes, in the already allocated 4 MiB private workspace. Its FNV word fingerprint chooses a slot only; it is not an integrity witness. Each original entry retains its complete-record SHA-256, size, and physical offset. The writer computes the current encoded chunk's SHA-256 before considering a hit, reads the actual prior bytes, compares every encoded byte, and independently decodes those actual bytes against the complete current raw chunk. A mismatch fails closed. Collisions with a different SHA-256 produce an original record. Only a successfully written original updates the table; a reference never updates it.

## Custody and archive validation

The writer retains the existing running physical SHA-256, fsync, full journal readback hash, and trusted success receipt. The archive retains every existing journal/file custody check and every original full hash pass. After the initial journal receipt/hash check, it copies the whole journal into an anonymous memfd in 64 KiB transfers, applies and verifies all four seals (15), and independently hashes the complete immutable capture against the trusted driver receipt. Logical parsing and reference reads use this sealed capture; original-file inventory, archiving, and postchecks still use the original file. This prevents a live file from changing between boundary validation and reference resolution.

## Qualification status

The writer passes the original 18 controls. The new writer and sealed-capture archive execute the unchanged 3394-node base plan and 21424-node original-chain plan, retain all nodes, reproduce every published file byte for byte, and archive every file byte for byte. The component performance run reuses prior independent reference inputs, so it is explicitly not a whole cold qualification. The new-format adversarial gates also pass: eight actual writer collision/custody cases, 48 actual archive-format cases (seven positive and 41 refusal), and four real sealed-capture/ABA cases. Seven archive refusals explicitly preserve the complete logical journal if their corresponding boundary rule is omitted, isolating the rule being tested. The actual complete 60-phase admission remains a separate integration gate. The 180-second qualification limit, 3-second cleanup limit, target compiler bounds, scheduler capacities, and complete evidence requirements are unchanged.

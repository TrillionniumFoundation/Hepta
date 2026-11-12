# Read the sealed 970 HOLD small artifact

This candidate reads artifact `13913382201` once: 22,390,611 bytes, SHA256 `58424f2690a09f10e2f06557985648aa89d0dab1c37be89833b0f2653344976d`. It never requests the original 599 MB artifact again and never executes project code or product tests.

Original run `43150215535` remains a failure. Its `FINAL.json` SHA is `afc25dc9c884a935441b75c276760e6e6455085ddc2c34186fed237fc65d1345`; both its custody and framing statuses are HOLD. Its earlier worker error is still unknown. This new reader restores the actual records needed to diagnose it.

The fixed historical request is 371 targets: 17 custody records and all 354 selected CI records. The outer ZIP is checked against its external seal, full flat inventory, CRCs and FINAL captured map. The inner selected ZIP, when present and correctly bound, is read member by member against its original directory, selection and custody receipts. Missing originals and partial raw fallback remain explicit. The reader does not rerun old semantic header checks or reinterpret old statuses.

The new evidence budget is 32 MiB of raw bytes and 48 MiB of stdout, using 24 KiB frames. Five current reader records have priority, then the 17 historical custody records, then the 354 original targets. A fixed-budget omission remains HOLD, appears in the exact missing/omitted accounting, and stays preserved in the public artifact. The original 16 MiB framing failure is not overwritten.

The complete 22 MB small ZIP must also be independently copied and verified for successful recovery. An incomplete `.partial` can be retained as separate failure evidence under the original strict single-link rules; it never satisfies the complete archive seal. All public output remains below 480 MiB. END follows original-copy and source rechecks plus durable RESULT readback.

The original guardian stays at 900 seconds with 3 seconds of cleanup. Product limits and denominators, including cold 180 seconds, two workers, 38 phases, the original 3/5-second assertions and full retained 5400 seconds, are unchanged and are not proven by this reader.

These Python sources are unparsed and unexecuted at this checkpoint. Parent review and a separately frozen workflow precede the parent's unique trigger creation.

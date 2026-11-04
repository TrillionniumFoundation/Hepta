# Current Windows compiler identity readback

The owner fix in #645 is already included in frozen #643 commit `c12ae2c3788c3b74acf8e283676b4145743b1883`. The original six-host identity and integer workflows completed successfully at this exact source. `READBACK.json` records all twelve complete logs, native Windows stat observations and named test inventories.

Each current host passed all nine new cross-API controls and all 164 original integer/parser/checker cases. Existing Windows identity tests retain five declared POSIX skips; these are recorded separately. Linux also ran all ten existing identity tests and five source-envelope tests. The two earlier failed Windows logs are retained in full. That older source also precedes separate fixture repairs, so its entire failure count is not attributed to one change.

No duplicate product implementation or new host run was created for this readback. There is no complete post-run source snapshot or same-job old/new probe, and no scientific or whole-project acceptance is asserted. Formal source accounting remains 5889/6116, the 49 extra recoveries remain separate, and no original Library item is deleted.

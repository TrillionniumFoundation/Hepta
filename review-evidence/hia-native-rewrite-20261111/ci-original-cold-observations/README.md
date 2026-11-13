# Original GitHub cold timeout observations

These raw reports and job logs retain the original failed observations for
34963 PR Core and ec484 push Core. The transfer manifest binds the exact
size and SHA-256 of each original report, summary and log. The ec484 source
comparison is a separate local readback, not an altered GitHub report.

Both runs retain the original 180-second qualification limit and 3-second
owned-cleanup budget. Cleanup completed with ECHILD after qualification
timeout. A later successful run, including the same-source ec484 PR run,
does not change either timeout into a pass. These observations do not
qualify the current integrated source.

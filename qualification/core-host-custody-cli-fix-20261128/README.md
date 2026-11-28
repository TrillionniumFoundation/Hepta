# Preserve the original native CLI phase contract

The first real B3-native run executed all 22 methods and exposed valid-input refusals.
The raw decoder passed VM execution but had been placed at the executable's first
function without the existing native CLI state machine. Consequently the initial
argv packet was incorrectly treated as a custody packet. This is a production
entry defect, not a reason to change test input or relax acceptance.

The correction retains the original complete stage f0 argv/input/EOF implementation.
Only its three original payload dispatch calls now target custody. All phase checks,
workspace limits and terminal return rules are preserved; the complete raw custody
decoder and identity data are unchanged. Source controls compare the exact original
entry after reversing those three call targets. VM controls exercise command
admission, all six data views, EOF completion and invalid commands/states.

All six source/VM controls pass. The failed native receipt reports natural exit 1,
complete cleanup and kernel ECHILD. Full first-run originals remain at their exact
ROG path and are not overwritten. The included readback is diagnostic evidence;
the complete native archive and a separate new native run follow.

The same archive preserves the ordinary two-parent Query/Page merge inputs and
review: all source registrations were unioned; reversing the single Page initializer
change restores the entire pre-merge Service file byte-for-byte.

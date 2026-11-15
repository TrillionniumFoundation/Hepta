"""Complete stable-read and authorized capture continuation protocol.

Foreign ports observe one original expression or one interpreter protocol step.
Every branch, root/component/cleanup loop, handler and terminal is HIA-owned.
"""
SELECTOR = 'HEPTA_HIA_STORE_FILE_CAPTURE_MANIFEST'
SCHEMA = 'hepta.hia.store-file-capture.v2'
SOURCE_NAME = 'examples/hia_bootstrap/store_file_capture.hepta'
REQUEST_MAGIC = 0x3243515041434948
RESULT_MAGIC = 0x3252435041434948
STATE_MAGIC = 0x3253435041434948
REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES = 80, 96, 128
INITIALIZE, CLAIM, SUCCEEDED, RAISED, FINALIZE, RESUME = range(6)
ISSUED, CLAIMED, READY_RETURN, RETURNED, PROPAGATE, READY_PROPAGATE, LEAVE_EXCEPTION, REFUSED = range(1, 9)
STABLE_READ, CAPTURE_PATH = 1, 2
STATE_VERSION = 2
# Word 9 is HIA acquisition/issuance state, never proof of actual close.
FD_NONE, FD_OWNED, FD_CLOSE_CLAIMED = range(3)
PORTS = (
    "stable_flags",
    "stable_open",
    "stable_fdopen",
    "stable_cm_prepare",
    "stable_cm_next",
    "stable_lookup_enter",
    "stable_lookup_exit",
    "stable_enter",
    "stable_before",
    "stable_not_regular",
    "stable_too_large",
    "stable_reject_file",
    "stable_read",
    "stable_after",
    "stable_identity",
    "stable_size_differs",
    "stable_identity_differs",
    "stable_reject_changed",
    "stable_result",
    "stable_exit_normal",
    "stable_exit_error",
    "stable_exit_truth",
    "stable_suppressed_result",
    "stable_cancel_return",
    "stable_cm_unwind",
    "stable_enter_unwind",
    "stable_match_oserror",
    "stable_bind_exception",
    "stable_wrap_oserror",
    "stable_clear_exception",
    "stable_release_locals",
    "capture_not_string",
    "capture_not_absolute",
    "capture_reject_absolute",
    "capture_parts",
    "capture_parent_component",
    "capture_dot_component",
    "capture_nul",
    "capture_reject_traversal",
    "capture_lexical",
    "capture_chosen_none",
    "capture_roots_iter",
    "capture_roots_next",
    "capture_relative",
    "capture_match_valueerror",
    "capture_relative_truth",
    "capture_choose",
    "capture_roots_release",
    "capture_search_unwind",
    "capture_no_chosen",
    "capture_reject_authority",
    "capture_unpack",
    "capture_descriptors",
    "capture_open_root",
    "capture_append_root",
    "capture_components_iter",
    "capture_components_next",
    "capture_open_component",
    "capture_append_component",
    "capture_read",
    "capture_body_unwind",
    "capture_match_oserror",
    "capture_bind_exception",
    "capture_wrap_oserror",
    "capture_clear_exception",
    "capture_cleanup_iter",
    "capture_cleanup_next",
    "capture_close",
    "capture_cleanup_unwind",
    "capture_cancel_return",
    "capture_release_locals",
    "stable_close_normal",
    "stable_close_error",
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
LAST_STABLE_PORT = PORT['stable_release_locals']  # original contiguous stable boundary
STABLE_CLOSE_PORTS = (PORT['stable_close_normal'], PORT['stable_close_error'])
STABLE_PORTS = tuple(range(1, LAST_STABLE_PORT + 1)) + STABLE_CLOSE_PORTS
CAPTURE_PORTS = tuple(range(LAST_STABLE_PORT + 1, PORT['capture_release_locals'] + 1))

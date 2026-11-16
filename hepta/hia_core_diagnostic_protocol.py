"""Private whole-Core scratch trailer; public admission status codes are unchanged.

The image owns the diagnostic table, message composition and UTF-8 bytes.  The
host reserves capacity and validates the returned trailer before transporting
those bytes into the existing exception.  There is no host message selection.
"""

TABLE_CAPACITY = 8192
MESSAGE_SLACK = 4096
TRAILER_BYTES = 64
DIAGNOSTIC_MAGIC = 0x3147414944484941


def diagnostic_capacity(source_bytes):
    # Every copied name/string occurs in the source. A type-list repr adds at
    # most one separator space per admitted node; its types contain no escapes.
    # This tighter bound preserves the existing standalone 64 MiB state region.
    nodes = min(262144, (source_bytes + 1) // 2 + 1)
    return source_bytes + nodes + MESSAGE_SLACK


def diagnostic_scratch_bytes(source_bytes):
    return TABLE_CAPACITY + diagnostic_capacity(source_bytes) + TRAILER_BYTES

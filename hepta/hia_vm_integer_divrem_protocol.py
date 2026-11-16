"""Word representation and complete ACK checks for the explicit div/rem image.

No quotient/remainder or trap prediction is implemented by this transport.
A selected caller classifies post-handoff protocol refusal using real delivery
custody. This module itself grants no image or source admission authority.
"""
import struct

REQUEST_BYTES = 64
REPLY_BYTES = 96
REQUEST_MAGIC = 3544427779418310984
REPLY_MAGIC = 3544423437206374728
COMPLETION = 3550329983607392580
UINT64_MAX = (1 << 64) - 1
_TYPES = {
    "i8": (8, 1), "u8": (8, 0),
    "i16": (16, 1), "u16": (16, 0),
    "i32": (32, 1), "u32": (32, 0),
    "i64": (64, 1), "u64": (64, 0),
    "isize": (64, 1), "usize": (64, 0),
}
_OPERATIONS = {"int.div.checked": 1, "int.rem.checked": 2}


def _request_words(raw):
    if type(raw) is not bytes or len(raw) != REQUEST_BYTES:
        raise ValueError("div/rem request extent differs")
    words = struct.unpack("<8Q", raw)
    magic, nonce, operation, width, signed, a, b, reserved = words
    if (magic != REQUEST_MAGIC or nonce == 0 or operation not in (1, 2)
            or width not in (8, 16, 32, 64) or signed not in (0, 1)
            or reserved != 0):
        raise ValueError("div/rem request identity differs")
    mask = (1 << width) - 1
    if a > mask or b > mask:
        raise ValueError("div/rem request is not a canonical width-bit encoding")
    return words


def request(operation, typ, a, b, nonce):
    """Encode already admitted exact scalars, without arithmetic decisions."""
    if (type(operation) is not str or operation not in _OPERATIONS
            or type(typ) is not str or typ not in _TYPES
            or type(a) is not int or type(b) is not int
            or type(nonce) is not int or not 1 <= nonce <= UINT64_MAX):
        raise ValueError("div/rem request requires exact typed transport facts")
    width, signed = _TYPES[typ]
    # to_bytes performs only the declared representation conversion. No
    # masking of an oversized input is allowed to fabricate an admitted value.
    lhs = int.from_bytes(a.to_bytes(width // 8, "little", signed=bool(signed)), "little")
    rhs = int.from_bytes(b.to_bytes(width // 8, "little", signed=bool(signed)), "little")
    return struct.pack("<8Q", REQUEST_MAGIC, nonce, _OPERATIONS[operation],
                       width, signed, lhs, rhs, 0)


def reply(request_raw, output_raw, written):
    """Validate this invocation's complete receipt, then decode its value."""
    _, nonce, operation, width, signed, lhs, rhs, _ = _request_words(request_raw)
    if (type(written) is not int or written != REPLY_BYTES
            or type(output_raw) is not bytes or len(output_raw) != REPLY_BYTES):
        raise ValueError("div/rem complete receipt is missing")
    words = struct.unpack("<12Q", output_raw)
    magic, version, got_nonce, got_op, got_width, got_signed = words[:6]
    status, value, got_lhs, got_rhs, checksum, completion = words[6:]
    if ((magic, version, got_nonce, got_op, got_width, got_signed,
         got_lhs, got_rhs, completion) !=
        (REPLY_MAGIC, 1, nonce, operation, width, signed, lhs, rhs, COMPLETION)):
        raise ValueError("div/rem receipt belongs to a different invocation")
    folded = 0
    for index, word in enumerate(words):
        if index != 10:
            folded ^= word
    if checksum != folded or status not in (0, 1, 2):
        raise ValueError("div/rem receipt status or checksum differs")
    if value > (1 << width) - 1 or status != 0 and value != 0:
        raise ValueError("div/rem receipt result representation differs")
    decoded = (int.from_bytes(value.to_bytes(width // 8, "little"), "little",
                              signed=bool(signed)) if status == 0 else None)
    return {"status": status, "value": decoded, "nonce": nonce,
            "operation": operation, "width": width, "signed": signed}

SCHEMA = "hepta.hia.vm-integer-divrem-native.v1"
IMAGE_NAME = "vm-integer-divrem.image.bin"
SOURCE_NAME = "examples/hia_bootstrap/vm_integer_divrem.hepta"
COMPONENT_INPUTS = (
    SOURCE_NAME,
    "hepta/hia_vm_integer_divrem_protocol.py",
    "hepta/hia_vm_integer_divrem_native.py",
    "hepta/hia_vm_integer_divrem_runtime.py",
    "hepta/hia_program_runtime.py",
    "hepta/hia_program.py",
    "hepta/hia_opcodes.py",
    "hepta/hia_schema.py",
    "hepta/hia_bounded_memory.py",
    "hepta/hia_native_delivery.py",
    "hepta/hia_json_preflight_native.py",
    "hepta/hia_native_admission_io.py",
    "hepta/hia_native_helpers.py",
)

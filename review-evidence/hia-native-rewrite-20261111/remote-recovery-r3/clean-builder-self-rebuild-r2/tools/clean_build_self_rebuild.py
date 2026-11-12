"""Author the explicit v2 kit owner that compiles its own complete builder.

The seven original recipes, original compiler fixed-point check, original
decoder and complete cold/source-contract checks remain present.  The v2 kit
adds a distinct ordered owner-source region; it is covered by the actual kit
digest but is not claimed to be part of the older cold qualification.

This module is development authoring.  The resulting HIA owns all runtime
inventory checks, compilation requests, framing, hashing, and package bytes.
"""
import ast

OWN_NAMES = (
    "tools/build_authoring.py",
    "tools/clean_build_driver.py",
    "tools/clean_build_gate.py",
    "tools/clean_build_gate_common.py",
    "tools/clean_build_package.py",
    "tools/generate_hia_clean_build_driver.py",
    "tools/generate_hia_clean_build_gate.py",
    "tools/generate_hia_clean_build_packer.py",
    "tools/clean_build_self_rebuild.py",
    "tools/hia_agent_edit_source_views.py",
    "tools/clean_build_executor.S",
    "examples/hia_bootstrap/clean_build_driver.hiaasm",
    "examples/hia_bootstrap/clean_build_packer.hiaasm",
)
DECODER_NAME = "examples/hia_bootstrap/agent_data_json.hiaasm"
CONSTANTS = {"OWN_START": 3632, "OWN_ROWS": 6144,
             "BUILD_MAGIC": int.from_bytes(b"HIABPK01", "little")}

OWN_BODY = r'''
def own_sources(s:readbuf, w:mutbuf) -> u64:
    cursor = get(w, OWN_START)
    index = 0
    while index < 13:
        if cursor > length(s) or length(s) - cursor < 32:
            bad(w, 130)
            return 0
        name = uint(s, cursor)
        size = uint(s, cursor + 8)
        if uint(s, cursor + 16) != 0 or uint(s, cursor + 24) != 0:
            bad(w, 131)
            return 0
        cursor = cursor + 32
        if name > length(s) - cursor:
            bad(w, 132)
            return 0
        if own_name(s, cursor, name, index) != 1:
            bad(w, 133)
            return 0
        start = cursor + name
        if size == 0 or size > IMAGE_CAP or size > length(s) - start:
            bad(w, 134)
            return 0
        row = OWN_ROWS + index * 64
        put(w, row, start)
        put(w, row + 8, size)
        hash_range(s, start, size, w, row + 16)
        cursor = start + size
        index = index + 1
    if cursor != length(s) or get(w, 624) == 0 or get(w, 632) == 0:
        bad(w, 135)
        return 0
    return 1

def builder_frame(w:mutbuf) -> u32:
    driver = get(w, B_ROWS + 9 * 96 + 24)
    decoder = get(w, B_ROWS + 10 * 96 + 24)
    size = 32 + driver + decoder
    if size > IMAGE_CAP:
        return refused(w, 11)
    cursor = get(w, B_CURSOR)
    if size > NONE - cursor - 15:
        return bad(w, 136)
    needed = (cursor + size + 15) & 18446744073709551600
    if needed > length(w):
        return grow(w, needed)
    put(w, cursor, BUILD_MAGIC)
    put(w, cursor + 8, driver)
    put(w, cursor + 16, decoder)
    put(w, cursor + 24, 0)
    copy_work(w, get(w, B_ROWS + 9 * 96 + 16), cursor + 32, driver)
    copy_work(w, get(w, B_ROWS + 10 * 96 + 16), cursor + 32 + driver, decoder)
    put(w, B_FRAME, cursor)
    put(w, B_FRAME_BYTES, size)
    put(w, B_CURSOR, needed)
    hash_work(w, cursor, size, B_ROWS + 12 * 96 + 64)
    return build_call(w, 6, cursor, size, 2, get(w, B_ROWS + 11 * 96 + 16), get(w, B_ROWS + 11 * 96 + 24), 15)
'''


def name_matchers():
    names = (*OWN_NAMES, DECODER_NAME)
    body = "\ndef own_name(s:readbuf, at:u64, size:u64, id:u64) -> u64:\n"
    for index in range(len(names)):
        body += f"    if id == {index}:\n        return own_name_{index}(s, at, size)\n"
    body += "    return 0\n"
    for index, name in enumerate(names):
        raw = name.encode("ascii")
        body += f"\ndef own_name_{index}(s:readbuf, at:u64, size:u64) -> u64:\n    if size != {len(raw)}:\n        return 0\n"
        for at in range(0, len(raw), 8):
            part = raw[at:at + 8]
            if len(part) == 8:
                body += f"    if uint(s, at + {at}) != {int.from_bytes(part, 'little')}:\n        return 0\n"
            else:
                for offset, value in enumerate(part):
                    body += f"    if byte(s, at + {at + offset}) != {value}:\n        return 0\n"
        body += "    return 1\n"
    return body


def transformed_parts():
    import clean_build_driver as driver
    import clean_build_gate as gate
    import clean_build_package as package
    sources = {"driver": driver.BODY, "gate": gate.BODY,
               "package": package.BODY}
    originals = dict(sources)
    changes = []

    def edit(owner, old, new):
        assert sources[owner].count(old) == 1, (owner, old)
        sources[owner] = sources[owner].replace(old, new, 1)
        changes.append({"owner": owner, "old": old, "new": new})

    # Explicit v2 framing, with an independently counted owner-source region.
    # The original base count continues to bind the complete old cold map.
    edit("gate", "if uint(s, 64) != KMAGIC or uint(s, 72) != 1:",
         "if uint(s, 64) != KMAGIC or uint(s, 72) != 2:")
    edit("gate", "if uint(s, 80) > 2 or uint(s, 112) != 0 or uint(s, 120) != 0:",
         "if uint(s, 80) > 2 or uint(s, 112) != 13 or uint(s, 120) != 0:")
    edit("gate", "        cursor = start + size\n        index = index + 1\n    if cursor != length(s) or get(w, 80) == 0 or get(w, 88) == 0 or get(w, 88) > 8388608:",
         "        if own_name(s, cursor, name, 13) == 1:\n            put(w, 624, start)\n            put(w, 632, size)\n        cursor = start + size\n        index = index + 1\n    put(w, OWN_START, cursor)\n    if get(w, 80) == 0 or get(w, 88) == 0 or get(w, 88) > 8388608:")

    # Only after both complete old JSON gates accept is the new region checked.
    old = "return build_begin(w)"
    assert sources["driver"].count(old) == 2
    sources["driver"] = sources["driver"].replace(old, "return build_begin(s, w)")
    changes.append({"owner": "driver", "old": old, "new": "return build_begin(s, w)", "count": 2})
    edit("driver", "def build_begin(w:mutbuf) -> u32:\n    put(w, B_CURSOR, get(w, 336))",
         "def build_begin(s:readbuf, w:mutbuf) -> u32:\n    if own_sources(s, w) != 1:\n        return BAD\n    put(w, B_CURSOR, get(w, 336))")
    edit("driver", "while i < 9 * 96:", "while i < 13 * 96:")
    edit("driver", "    if index > 6:\n        return bad(w, 102)\n    source = get(w, 512 + index * 16)\n    size = get(w, 520 + index * 16)",
         "    if index > 11 or index == 7 or index == 8:\n        return bad(w, 102)\n    source = get(w, 512 + index * 16)\n    size = get(w, 520 + index * 16)\n    if index == 9:\n        source = get(w, OWN_ROWS + 11 * 64)\n        size = get(w, OWN_ROWS + 11 * 64 + 8)\n    if index == 10:\n        source = get(w, 624)\n        size = get(w, 632)\n    if index == 11:\n        source = get(w, OWN_ROWS + 12 * 64)\n        size = get(w, OWN_ROWS + 12 * 64 + 8)")
    edit("driver", "    if found != 1:\n        return bad(w, 103)",
         "    if index == 9:\n        copy_work(w, OWN_ROWS + 11 * 64 + 16, row + 64, 32)\n        found = found + 1\n    if index == 11:\n        copy_work(w, OWN_ROWS + 12 * 64 + 16, row + 64, 32)\n        found = found + 1\n    if found != 1:\n        return bad(w, 103)")
    edit("driver", "    if phase == 16:\n        return package(s, w)\n    return bad(w, 104)",
         "    if phase == 16:\n        return package(s, w)\n    if phase == 17:\n        return builder_frame(w)\n    return bad(w, 104)")
    edit("driver", "    if index < 6:\n        return request_compile(w)\n    put(w, 16, 11)\n    return agent_frame(w)",
         "    if index < 6:\n        return request_compile(w)\n    if index == 6:\n        put(w, 16, 11)\n        return agent_frame(w)\n    if index < 11:\n        return request_compile(w)\n    put(w, 16, 17)\n    return builder_frame(w)")
    edit("driver", "    return build_call(w, 7, 0, 0, 0, 0, 0, 15)",
         "    put(w, B_INDEX, 9)\n    return request_compile(w)")
    edit("driver", "def self_reply(r:readbuf, w:mutbuf) -> u32:\n    if length(r) < 64:\n        return bad(w, 116)\n    size = reply_size(r, w, 4, length(r) - 64)",
         "def self_reply(r:readbuf, w:mutbuf) -> u32:\n    if length(r) < 64:\n        return bad(w, 116)\n    size = reply_size(r, w, 3, IMAGE_CAP)")
    edit("driver", "    put(w, B_SELF, cursor)\n    put(w, B_SELF_BYTES, size)",
         "    row = B_ROWS + 12 * 96\n    put(w, row, get(w, B_FRAME))\n    put(w, row + 8, get(w, B_FRAME_BYTES))\n    put(w, row + 16, cursor)\n    put(w, row + 24, size)\n    copy_work(w, B_TEMP, row + 32, 32)\n    put(w, B_SELF, cursor)\n    put(w, B_SELF_BYTES, size)")
    edit("package", "while index < 9:", "while index < 13:")

    # Prove the production changes are exactly the listed edits.
    inverse = dict(sources)
    for change in reversed(changes):
        count = change.get("count", 1)
        assert inverse[change["owner"]].count(change["new"]) == count
        inverse[change["owner"]] = inverse[change["owner"]].replace(change["new"], change["old"], count)
    assert inverse == originals
    return sources, changes


def source():
    import generate_hia_clean_build_driver as old
    import clean_build_gate_common as common
    import clean_build_driver as driver
    import clean_build_package as package
    from build_authoring import expanded
    parts, changes = transformed_parts()
    h = common.hashing()
    tree = ast.parse(h)
    fn = next(n for n in tree.body if n.name == "hash_range")
    pad = next(n for n in tree.body if n.name == "hpadded")
    wh = ast.get_source_segment(h, fn).replace(
        "hash_range(s:readbuf, start:u64, size:u64, w:mutbuf, target:u64)",
        "hash_work(w:mutbuf, start:u64, size:u64, target:u64)").replace("hpadded(s,", "wpadded(w,")
    wp = ast.get_source_segment(h, pad).replace("hpadded(s:readbuf,", "wpadded(w:mutbuf,").replace("byte(s,", "byte(w,")
    shared = common.BODY.replace("return event(w, 1, source, size, 0, 0)", "return decoder_event(w, source, size)")
    original_texts = tuple(package.TEXTS)
    replacement = list(original_texts)
    replacement[0] = replacement[0].replace(b"native-clean-build.v1", b"native-clean-build.v2").replace(
        b"SOURCE_BOUND_NATIVE_BUILD", b"SELF_REBUILT_NATIVE_BUILD")
    replacement[10] = replacement[10].replace(b'],"runtime_python_required":false,',
        b'],"runtime_python_required":false,"builder_recompiled_from_kit_source":true,"builder_copy_used":false,')
    try:
        package.TEXTS = replacement
        emitted_texts = package.texts()
    finally:
        package.TEXTS = list(original_texts)
    body = (parts["driver"] + parts["gate"] + shared + common.literals() + common.literals(True) +
            "\n" + h + "\n" + wh + "\n" + wp + "\n" + parts["package"] + emitted_texts +
            OWN_BODY + name_matchers())
    return expanded(body, {**common.CONSTANTS, **driver.CONSTANTS, **CONSTANTS}), changes

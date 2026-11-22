"""Author the immutable Emit product publication transaction."""


PUBLICATION = r'''
def emit_publish(o:mutbuf, w:mutbuf, kind:u64, product:u64, metadata:u64) -> u64:
    if kind < 12 or kind > 14 or get(w, product + 16) == 0 or get(w, metadata + 16) < 2:
        return BAD
    put(w, EMIT_PUB_KIND, kind)
    put(w, EMIT_PUB_INSERTED, 0)
    move_fragment(w, product, EMIT_PUB_BYTES)
    move_fragment(w, metadata, EMIT_PUB_METADATA)
    return inspection_hash(o, w, EMIT_PUB_HASHED_BYTES, EMIT_PUB_BYTES)

def emit_publication_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64, resume:u64) -> u64:
    if resume == EMIT_PUB_HASHED_BYTES:
        copy_span(s, w, at, EMIT_PUB_CONTENT_HASH, 64)
        if emit_authorized_digest(w, EMIT_PUBLIC_AUTHORITY) == False:
            return BAD
        return inspection_hash(o, w, EMIT_PUB_HASHED_METADATA, EMIT_PUB_METADATA)
    if resume == EMIT_PUB_HASHED_METADATA:
        copy_span(s, w, at, EMIT_PUB_METADATA_HASH, 64)
        return emit_publication_plan(o, w, False)
    if resume != EMIT_PUB_WRITTEN:
        return BAD
    copy_span(s, w, at, EMIT_PUB_PUBLISHED_HASH, 64)
    if emit_authorized_digest(w, EMIT_PUB_PUBLISHED_HASH) == False:
        return BAD
    put(o, 144, 32)
    return action(o, w, EMIT_PUB_ENTROPY, RANDOM, 0, 0, 0, 0)

def emit_authorized_digest(w:mutbuf, other:u64) -> bool:
    i = 0
    while i < 64:
        if byte(w, EMIT_PUB_CONTENT_HASH + i) != byte(w, other + i):
            return False
        i = i + 1
    return True

def emit_publication_plan(o:mutbuf, w:mutbuf, insert:bool) -> u64:
    put(o, HEADER, choose(insert, EMIT_ISSUE_DOCUMENT, EMIT_LOOKUP_DOCUMENT))
    put(o, HEADER + 8, get(w, EMIT_PUB_KIND))
    copy_private(w, o, EMIT_PUB_CONTENT_HASH, HEADER + 16, 64)
    use_span(w, o, EMIT_PUB_METADATA, 0)
    if insert:
        fragment(o, 1, INLINE_FRAGMENT, 416, 32)
        return action(o, w, EMIT_PUB_ISSUED, RUN, DOCUMENT_PLAN_ROLE, 0, 2, 80)
    return action(o, w, EMIT_PUB_QUERY, RUN, DOCUMENT_PLAN_ROLE, 0, 1, 80)

def emit_publication_store(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    purpose = get(w, STORE_PURPOSE)
    if state == PEER_ADMITTED and purpose == EMIT_PUB_OPEN:
        return emit_query_key(o, w)
    if state == PEER_CLOSED and purpose == EMIT_PUB_CLOSE:
        copy_private(w, o, EMIT_PUB_CONTENT_HASH, 416, 64)
        store(o, 480, 0)
        return artifact_command(o, w, EMIT_PUB_REOPENED, STORE_GET, STORE_GET_END, 0)
    if state != STORE_SETTLED:
        return BAD
    if purpose == EMIT_PUB_INSERT:
        if input_word(s, 72) != 8 or input_word(s, 80) > 1:
            return BAD
        put(w, EMIT_PUB_INSERTED, 1)
        return emit_query_key(o, w)
    if purpose != EMIT_PUB_LOOKUP:
        return BAD
    put(o, HEADER, EMIT_OBSERVE_DOCUMENT)
    put(o, HEADER + 8, get(w, EMIT_PUB_KIND))
    copy_private(w, o, EMIT_PUB_CONTENT_HASH, HEADER + 16, 64)
    copy_private(w, o, EMIT_PUB_KEY_HASH, HEADER + 80, 64)
    copy_private(w, o, EMIT_PUB_METADATA_HASH, HEADER + 144, 64)
    put(o, HEADER + 208, get(w, EMIT_PUB_METADATA + 16))
    whole_slot(w, o, STORE_RESULT, 0)
    return action(o, w, EMIT_PUB_OBSERVED, RUN, EMIT_PUBLICATION_ROLE, 0, 1, 216)

def emit_query_key(o:mutbuf, w:mutbuf) -> u64:
    return store_transaction(o, w, EMIT_PUB_LOOKUP, 1, 1, get(w, EMIT_PUB_KEY), 8, 120)

def emit_publication_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == EMIT_PUB_QUERY:
        if plan_ok(s) == False or size != 128:
            return BAD
        sample_span(s, w, EMIT_PUB_KEY)
        return read_span(o, w, EMIT_PUB_QUERY_KEY, fd, 64, 64)
    if state == EMIT_PUB_QUERY_KEY:
        if length(s) != 128 or input_word(s, 56) != 64:
            return BAD
        copy_span(s, w, 64, EMIT_PUB_KEY_HASH, 64)
        return open_store(o, w, EMIT_PUB_OPEN)
    if state == EMIT_PUB_OBSERVED:
        return emit_publication_observed(s, o, w, size)
    if state == EMIT_PUB_WRITTEN:
        if size < 88 or size > 105:
            return BAD
        put(w, INSPECTION_HASH_RESUME, EMIT_PUB_WRITTEN)
        return read_span(o, w, INSPECTION_HASH_FRAME, fd, 0, size)
    if state == EMIT_PUB_ENTROPY:
        if size != 32 or length(s) != 96:
            return BAD
        copy_span(s, o, 64, 416, 32)
        return emit_publication_plan(o, w, True)
    if state == EMIT_PUB_ISSUED:
        if plan_ok(s) == False or size <= 208 or input_word(s, 72) != EMIT_DOCUMENT_ISSUED:
            return BAD
        width = input_word(s, 80)
        if width != size - 208 or input_word(s, 88) != 176:
            return BAD
        return store_transaction(o, w, EMIT_PUB_INSERT, 20, 1, fd, 32, width)
    if state == EMIT_PUB_REOPENED:
        if size != get(w, EMIT_PUB_BYTES + 16):
            return BAD
        sample_span(s, w, EMIT_PUB_READBACK)
        put(w, EMIT_PUB_OFFSET, 0)
        return emit_publication_compare(o, w)
    if state == EMIT_PUB_COMPARE:
        if plan_ok(s) == False or size != 24 or input_word(s, 72) != EMIT_COMPARE_RESULT or input_word(s, 80) != 1:
            return BAD
        if get(w, EMIT_PUB_OFFSET) < get(w, EMIT_PUB_BYTES + 16):
            return emit_publication_compare(o, w)
        return emit_publication_complete(o, w)
    return BAD

def emit_publication_observed(s:readbuf, o:mutbuf, w:mutbuf, size:u64) -> u64:
    if plan_ok(s) == False:
        return BAD
    if size == 24 and input_word(s, 72) == EMIT_DOCUMENT_MISSING and input_word(s, 80) == 0:
        if get(w, EMIT_PUB_INSERTED) != 0:
            return BAD
        put(o, 416, 45)
        use_span(w, o, EMIT_PUB_BYTES, 0)
        return artifact_command(o, w, EMIT_PUB_WRITTEN, STORE_PUT, STORE_PUT_END, 1)
    if size != 208 or input_word(s, 72) != EMIT_DOCUMENT_FOUND or input_word(s, 80) != 176:
        return BAD
    kind = get(w, EMIT_PUB_KIND)
    hold(w, EMIT_PUB_RECEIPT, input_word(s, 32), 8, 200)
    hold(w, EMIT_ARTIFACT_REFS + 24 * (kind - 12), input_word(s, 32), 32, 176)
    return close_store(o, w, EMIT_PUB_CLOSE)

def emit_publication_compare(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, EMIT_PUB_OFFSET)
    remaining = get(w, EMIT_PUB_BYTES + 16) - at
    extent = choose(remaining > 1048576, 1048576, remaining)
    put(o, HEADER, EMIT_COMPARE_REQUEST)
    put(o, HEADER + 8, extent)
    put(o, HEADER + 16, extent)
    fragment(o, 0, get(w, EMIT_PUB_BYTES), get(w, EMIT_PUB_BYTES + 8) + at, extent)
    fragment(o, 1, get(w, EMIT_PUB_READBACK), at, extent)
    put(w, EMIT_PUB_OFFSET, at + extent)
    return action(o, w, EMIT_PUB_COMPARE, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)

def emit_publication_complete(o:mutbuf, w:mutbuf) -> u64:
    kind = get(w, EMIT_PUB_KIND)
    move_fragment(w, EMIT_PUB_READBACK, EMIT_ARTIFACT_BYTES + 24 * (kind - 12))
    if kind == 14:
        return emit_confirm_custody(o, w)
    return inspection_feedback(o, w, kind + 3, 0, EMIT_PUB_RECEIPT)
'''


def publication_constants(constants):
    states = (
        'EMIT_PUB_QUERY', 'EMIT_PUB_QUERY_KEY', 'EMIT_PUB_OBSERVED', 'EMIT_PUB_WRITTEN',
        'EMIT_PUB_ENTROPY', 'EMIT_PUB_ISSUED', 'EMIT_PUB_REOPENED', 'EMIT_PUB_COMPARE',
        'EMIT_PUB_HASHED_BYTES', 'EMIT_PUB_HASHED_METADATA',
    )
    purposes = ('EMIT_PUB_OPEN', 'EMIT_PUB_CLOSE', 'EMIT_PUB_LOOKUP', 'EMIT_PUB_INSERT')
    spans = ('EMIT_PUB_BYTES', 'EMIT_PUB_METADATA', 'EMIT_PUB_KEY', 'EMIT_PUB_RECEIPT', 'EMIT_PUB_READBACK')
    words = {
        'EMIT_ISSUE_DOCUMENT': b'HIADAI01', 'EMIT_LOOKUP_DOCUMENT': b'HIADAL01',
        'EMIT_OBSERVE_DOCUMENT': b'HIAEPO01', 'EMIT_DOCUMENT_MISSING': b'HIAEPB01',
        'EMIT_DOCUMENT_FOUND': b'HIADOC01', 'EMIT_DOCUMENT_ISSUED': b'HIADAR01',
        'EMIT_COMPARE_REQUEST': b'HIAABC01', 'EMIT_COMPARE_RESULT': b'HIAABR01',
        'STORE_PUT': b'store-pu', 'STORE_PUT_END': b't',
        'STORE_GET': b'store-ge', 'STORE_GET_END': b't',
    }
    return {
        **{name: constants['EMIT_OBJECT_TIME'] + 1 + i for i, name in enumerate(states)},
        **{name: constants['EMIT_CLOSE_WALL_ROW'] + 1 + i for i, name in enumerate(purposes)},
        **{name: 4928 + i * 24 for i, name in enumerate(spans)},
        **{name: int.from_bytes(value, 'little') for name, value in words.items()},
        'EMIT_ARTIFACT_REFS': 5048, 'EMIT_ARTIFACT_BYTES': 5120,
        'EMIT_PUB_OFFSET': 5192, 'EMIT_PUB_KIND': 5200, 'EMIT_PUB_INSERTED': 5208,
        'EMIT_PUB_CONTENT_HASH': 5216, 'EMIT_PUB_METADATA_HASH': 5280, 'EMIT_PUB_KEY_HASH': 5344,
        'EMIT_PUB_PUBLISHED_HASH': 5408, 'EMIT_PUBLIC_AUTHORITY': 5472,
        'EMIT_NATIVE_ARTIFACT_ROLE': 32, 'EMIT_PUBLICATION_ROLE': 42, 'RANDOM': 10,
    }

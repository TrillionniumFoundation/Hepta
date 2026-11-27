"""Current-journal exact-byte back references; never execution-result caching.

Every hit compares the actual prior physical bytes and independently decodes
those bytes against the current fully observed raw chunk before publication.
The archive separately records validated physical chunk boundaries in its own
fixed table. FNV is only a bounded-table selector, never an integrity witness.
"""
CACHE_START=0x330000
CACHE_ENTRIES=8192
CACHE_STRIDE=64
CACHE_BYTES=CACHE_ENTRIES*CACHE_STRIDE
READ_BUFFER=0x3b0000
REF_MAGIC=int.from_bytes(b'HIAQAZ03','little')
HELPERS=r'''
def chunk_fingerprint(w:mutbuf, start:u64, size:u64) -> u64:
    value = 14695981039346656037
    at = 0
    while size - at >= 64:
        value = (value ^ word_load(w, start + at)) * 1099511628211
        value = (value ^ word_load(w, start + at + 8)) * 1099511628211
        value = (value ^ word_load(w, start + at + 16)) * 1099511628211
        value = (value ^ word_load(w, start + at + 24)) * 1099511628211
        value = (value ^ word_load(w, start + at + 32)) * 1099511628211
        value = (value ^ word_load(w, start + at + 40)) * 1099511628211
        value = (value ^ word_load(w, start + at + 48)) * 1099511628211
        value = (value ^ word_load(w, start + at + 56)) * 1099511628211
        at = at + 64
    while size - at >= 8:
        value = (value ^ word_load(w, start + at)) * 1099511628211
        at = at + 8
    while at < size:
        value = (value ^ byte(w, start + at)) * 1099511628211
        at = at + 1
    return value

def chunk_cache_slot(fingerprint:u64) -> u64:
    return 3342336 + (fingerprint & 8191) * 64

def chunk_cache_store(w:mutbuf, fingerprint:u64, offset:u64, amount:u64) -> u64:
    slot = chunk_cache_slot(fingerprint)
    put(w, slot, fingerprint)
    put(w, slot + 8, offset + 1)
    put(w, slot + 16, amount)
    return 0
'''

"""External QA readback of both lossless chunk profiles and the complete node journal."""
import struct


def journal_records(raw):
    if raw[:8] in (b'HIAQAZ01', b'HIAQAZ02'):
        from tools.qualify_hia_cold_qualification_codec_lz import decode
        logical = bytearray(); cursor = 0
        while cursor < len(raw):
            assert len(raw) - cursor >= 32
            magic, size, payload, mode = struct.unpack_from('<8s3Q', raw, cursor)
            assert magic in (b'HIAQAZ01',b'HIAQAZ02') and 0 < size <= 65504
            end = cursor + 32 + payload
            assert end <= len(raw)
            decoded = decode(raw[cursor:end])
            assert len(decoded) == size
            logical += decoded; cursor = end
        assert cursor == len(raw)
        raw = bytes(logical)
    at=0;rows=[]
    while at<len(raw):
        h=struct.unpack_from('<8Q',raw,at)
        assert h[0]==int.from_bytes(b'HIAQJL01','little') and h[1]==len(rows),h
        begin=at+64+h[4]*8+h[5];end=begin+h[6]
        assert end<=len(raw)
        rows.append({'index':h[1],'op':h[2],'id':h[3],'args':list(struct.unpack_from('<'+'Q'*h[4],raw,at+64)),'payload':raw[at+64+h[4]*8:begin],'result':raw[begin:end],'failure':h[7]})
        at=end
    assert at==len(raw)
    return rows

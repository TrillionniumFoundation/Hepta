"""Independent DATA-only reader for current47 retaining original44 and handoff8.

This reads complete raw logs/receipts and both original reports. It never
imports a product, producer or its helper. This is not the 17-reference /
38-phase cold binary/archive reader, which remains separately mandatory.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import stat
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
SOURCE_INPUTS = (
    "tools/hia_cold_native_transport.h", "tools/hia_cold_native_transport.c",
    "tools/hia_cold_native_transport_driver.c", "tools/hia_cold_native_transport_python.c",
    "tools/hia_cold_native_transport_handoff_controls.c",
    "tools/hia_cold_native_transport_bridge.py", "tools/generate_hia_cold_native_transport.py",
    "tools/build_hia_cold_native_transport.py", "tools/hia_cold_native_transport_evidence.py",
    "tools/qualify_hia_cold_native_transport.py", "tools/read_hia_cold_native_transport.py",
    "examples/hia_bootstrap/cold_native_transport.hepta",
    "tools/hia_selfhost_native_observer.py", "tools/hia_selfhost_linked_observer.py",
    "tools/qualify_hia_selfhost.py", "tools/replay_hia_selfhost_cold.py", "tools/hia_selfhost_child.py",
    "tools/build_hia_json_preflight.py", "tools/build_hia_source_build.py",
    "tools/generate_hia_selfhost.py", "tools/generate_hia_native_observer.py",
    "tools/generate_hia_linked_observer.py", "tools/hia_native_observer_template.S",
    "tools/hia_linked_observer_bridge.S",
    "tests/test_hia_selfhost_native_observer.py", "tests/test_hia_selfhost_linked_observer.py",
    "tests/test_hia_linked_observer_build_custody.py",
    "tests/test_hia_cold_native_transport.py",
    "tests/fixtures/cold_native_transport_original_gates_v3.json",
    "tests/fixtures/cold_native_transport_controls_v3.json",
    "tools/run_hia_unittest_gate.py",
)
GATE_SHA = "8720447c115e1737dc395271ebb91bb4c8bd5a83bc89558224058b09371bc1d5"
CONTROL_SHA = "abe86cfac29a3527efbf97101ef47da68d8258e1c5b8aa881bf8a8fc5b47b76d"


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value, expected=None):
    require(type(value) is int and (expected is None or value == expected), "exact integer differs")
    return value


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def pairs(rows):
    out = {}
    for key, value in rows:
        require(key not in out, "duplicate key")
        out[key] = value
    return out


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))


class Raw:
    def __init__(self):
        self.values = {}

    def take(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), "regular input required")
        data = path.read_bytes()
        after = path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, name) == getattr(after, name) for name in fields)
                and len(data) == after.st_size, "read changed or short")
        if expected is not None:
            require(type(expected) is dict and set(expected) == {"bytes", "sha256"}, "exact pin shape differs")
            integer(expected["bytes"])
            require(type(expected["sha256"]) is str and pin(data) == expected, "consumed bytes differ")
        require(self.values.setdefault(path, data) == data, "repeat consumption differs")
        return data

    def json(self, path, expected=None):
        return parse(self.take(path, expected))

    def unchanged(self):
        for path, raw in self.values.items():
            require(path.read_bytes() == raw, "terminal complete raw reread differs")

    def inventory(self):
        return {str(path): pin(raw) for path, raw in sorted(self.values.items(), key=lambda row: str(row[0]))}


def decode_original_process_streams(record_raw, request_raw, stored_streams, *, label):
    """Decode actual retained bytes; never manufacture a missing old response.

    This DATA-only helper does not import either observer or its producer. The
    caller must independently capture/reread these files and bind the returned
    raw bytes to the original request, process state and protocol observations.
    """
    limit = 16 * 1024 * 1024
    require(type(record_raw) is bytes and len(record_raw) <= 65536
            and type(request_raw) is bytes and type(label) is str
            and type(stored_streams) is dict and set(stored_streams) == {'stdout', 'stderr'},
            'original stream evidence inputs differ')
    record = parse(record_raw)
    require(type(record) is dict and set(record) == {'schema', 'request_sha256', 'returncode',
            'timed_out', 'decoded_stream_limit_bytes', 'streams'}
            and record['schema'] == 'hepta.hia.observer-original-process-streams.v1'
            and json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n' == record_raw,
            'original stream evidence schema or canonical bytes differ')
    integer(record['decoded_stream_limit_bytes'], limit)
    require(record['request_sha256'] == sha256(request_raw).hexdigest()
            and type(record['timed_out']) is bool
            and (record['returncode'] is None if record['timed_out'] else type(record['returncode']) is int),
            'original stream request/exit/timeout binding differs')
    require(type(record['streams']) is dict and set(record['streams']) == {'stdout', 'stderr'},
            'original stream pair inventory differs')
    originals = {}
    for name in ('stdout', 'stderr'):
        row, stored = record['streams'][name], stored_streams[name]
        require(type(row) is dict and set(row) == {'file', 'encoding', 'compression_level',
                'raw_bytes', 'raw_sha256', 'stored_bytes', 'stored_sha256'}
                and row['file'] == Path(label + '.process.' + name + '.zlib').name
                and row['encoding'] == 'zlib', 'original stream record differs')
        integer(row['compression_level'], 1)
        require(type(row['raw_bytes']) is int and 0 <= row['raw_bytes'] <= limit
                and type(row['stored_bytes']) is int and 0 <= row['stored_bytes'] <= limit
                and type(stored) is bytes and pin(stored) == {'bytes': row['stored_bytes'], 'sha256': row['stored_sha256']},
                'original stream compressed bytes/extent differ')
        decoder = zlib.decompressobj()
        try:
            raw = decoder.decompress(stored, limit + 1)
        except zlib.error as error:
            raise ValueError('original process stream is not a complete zlib stream') from error
        require(len(raw) <= limit and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
                'original process stream is oversized, truncated or followed by extra bytes/streams')
        require(pin(raw) == {'bytes': row['raw_bytes'], 'sha256': row['raw_sha256']},
                'original process stream full decoded bytes differ')
        originals[name] = raw
    return record, originals



# Source relation only: these exact successor bytes are not a past PASS.
# The original R3 fixture remains immutable. Reviewed allocation/copy changes,
# lossless original-stream retention, three additional controls and the v9
# linked-compiler preparation reconstruct the complete original byte files.
OBSERVER_GATE_SHA = "8720447c115e1737dc395271ebb91bb4c8bd5a83bc89558224058b09371bc1d5"
OBSERVER_ADDITIONAL_IDS = [
    "tests.test_hia_selfhost_native_observer.NativeObserverFrameValidationTests.test_frame_bytes_and_descriptor_domain_remain_exact",
    "tests.test_hia_selfhost_native_observer.NativeObserverFrameValidationTests.test_invalid_frame_is_refused_before_shared_output_allocation",
    "tests.test_hia_selfhost_native_observer.NativeObserverTests.test_workspace_fields_require_complete_words_at_every_boundary"
]
OBSERVER_SUCCESSORS = {
    "tools/hia_selfhost_native_observer.py": {
        "old": {
            "bytes": 14486,
            "sha256": "aacff6857ecbc88f6f541c06db5427065d86fbb331f1fa83ddf8bb3dfa3361af"
        },
        "current": {
            "bytes": 17287,
            "sha256": "f22de547e7e8905bf55f1d81d5da6604291afc84cfef3362f843d3c4b54c422d"
        },
        "splices": [
            {
                "old_offset": 725,
                "new_offset": 725,
                "old_hex": "696d706f72742074696d650a",
                "new_hex": "696d706f72742074696d650a696d706f7274207a6c69620a"
            },
            {
                "old_offset": 4806,
                "new_offset": 4818,
                "old_hex": "646566206672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f66643d4e6f6e65293a0a",
                "new_hex": "646566205f76616c69646174655f6672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f66643d4e6f6e65293a0a"
            },
            {
                "old_offset": 5373,
                "new_offset": 5395,
                "old_hex": "202020202020202072616973652056616c75654572726f7228276e6174697665206f62736572766572206672616d6520657863656564732074686520756e6368616e676564206279746520414249206c696d69747327290a",
                "new_hex": "202020202020202072616973652056616c75654572726f7228276e6174697665206f62736572766572206672616d6520657863656564732074686520756e6368616e676564206279746520414249206c696d69747327290a0a0a646566206672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f66643d4e6f6e65293a0a202020205f76616c69646174655f6672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f6664290a"
            },
            {
                "old_offset": 7639,
                "new_offset": 7835,
                "old_hex": "0a",
                "new_hex": "0a6465662072657461696e5f70726f636573735f73747265616d73286469726563746f72792c206c6162656c2c207374646f75742c207374646572722c202a2c20726571756573742c2072657475726e636f64652c2074696d65645f6f7574293a0a2020202022222252657461696e206f6e6c79207468652061637475616c20636f6d706c657465642f7061727469616c2062696e6172792070726f63657373206f62736572766174696f6e732e0a0a20202020436f6d7072657373696f6e206973206c6f73736c6573732065766964656e63652073746f726167652e20497420646f6573206e6f74206368616e67652074686520726573706f6e73652c0a202020206368696c6420646561646c696e652c206f726967696e616c2072656365697074206f7220627974652d414249206672616d696e672e2054686520756e6368616e67656420617263686976650a202020206d656d6265722063617020616c736f20626f756e64732065616368206465636f646564206f726967696e616c2073747265616d3b20616e206f76657273697a65642073747265616d206f720a202020206661696c6564207772697465206c656176657320746865207175616c696669636174696f6e20696e636f6d706c65746520696e7374656164206f662064726f7070696e672062797465732e0a202020202222220a202020206c696d6974203d203136202a2031303234202a20313032340a202020206966202874797065287374646f757429206973206e6f74206279746573206f7220747970652873746465727229206973206e6f742062797465730a2020202020202020202020206f7220747970652874696d65645f6f757429206973206e6f7420626f6f6c0a2020202020202020202020206f72202874696d65645f6f757420616e642072657475726e636f6465206973206e6f74204e6f6e65290a2020202020202020202020206f7220286e6f742074696d65645f6f757420616e6420747970652872657475726e636f646529206973206e6f7420696e74290a2020202020202020202020206f72206c656e287374646f757429203e206c696d6974206f72206c656e2873746465727229203e206c696d6974293a0a202020202020202072616973652056616c75654572726f7228276f726967696e616c2070726f636573732073747265616d73206578636565642074686520756e6368616e6765642065766964656e636520646f6d61696e27290a202020206469726563746f7279203d2050617468286469726563746f7279290a20202020726571756573745f726177203d20286a736f6e2e64756d707328726571756573742c20736f72745f6b6579733d5472756529202b20275c6e27292e656e636f646528290a20202020696620286469726563746f7279202f20286c6162656c202b20272e726571756573742e6a736f6e2729292e726561645f6279746573282920213d20726571756573745f7261773a0a202020202020202072616973652056616c75654572726f7228276f726967696e616c2070726f636573732072657175657374206368616e676564206265666f72652073747265616d20726574656e74696f6e27290a20202020726f7773203d207b7d0a20202020666f72206e616d652c2072617720696e202828277374646f7574272c207374646f7574292c202827737464657272272c2073746465727229293a0a202020202020202073746f726564203d207a6c69622e636f6d7072657373287261772c206c6576656c3d31290a20202020202020206966206c656e2873746f72656429203e206c696d69743a0a20202020202020202020202072616973652056616c75654572726f722827636f6d707265737365642070726f636573732073747265616d20657863656564732074686520756e6368616e6765642061726368697665206d656d6265722063617027290a202020202020202070617468203d206469726563746f7279202f20286c6162656c202b20272e70726f636573732e27202b206e616d65202b20272e7a6c696227290a2020202020202020706174682e77726974655f62797465732873746f726564290a2020202020202020696620706174682e726561645f6279746573282920213d2073746f7265643a0a20202020202020202020202072616973652056616c75654572726f7228276f726967696e616c20636f6d707265737365642070726f636573732073747265616d206368616e676564207768696c652072657461696e696e6720697427290a2020202020202020726f77735b6e616d655d203d207b2766696c65273a20706174682e6e616d652c2027656e636f64696e67273a20277a6c6962272c2027636f6d7072657373696f6e5f6c6576656c273a20312c0a202020202020202020202020277261775f6279746573273a206c656e28726177292c20277261775f736861323536273a2064696765737428726177292c0a2020202020202020202020202773746f7265645f6279746573273a206c656e2873746f726564292c202773746f7265645f736861323536273a206469676573742873746f726564297d0a202020207265636f7264203d207b27736368656d61273a202768657074612e6869612e6f627365727665722d6f726967696e616c2d70726f636573732d73747265616d732e7631272c0a202020202020202027726571756573745f736861323536273a2064696765737428726571756573745f726177292c202772657475726e636f6465273a2072657475726e636f64652c202774696d65645f6f7574273a2074696d65645f6f75742c0a2020202020202020276465636f6465645f73747265616d5f6c696d69745f6279746573273a206c696d69742c202773747265616d73273a20726f77737d0a20202020286469726563746f7279202f20286c6162656c202b20272e70726f636573732d73747265616d732e6a736f6e2729292e77726974655f74657874280a20202020202020206a736f6e2e64756d7073287265636f72642c20736f72745f6b6579733d547275652c20736570617261746f72733d28272c272c20273a27292c20616c6c6f775f6e616e3d46616c736529202b20275c6e27290a0a0a"
            },
            {
                "old_offset": 8525,
                "new_offset": 10987,
                "old_hex": "202020206672616d6528696d6167655f62797465732c736f757263652c63617061636974792c776f726b73706163655f73697a652c776f726b73706163655f66696c6c290a",
                "new_hex": "202020205f76616c69646174655f6672616d6528696d6167655f62797465732c736f757263652c63617061636974792c776f726b73706163655f73697a652c776f726b73706163655f66696c6c290a"
            },
            {
                "old_offset": 10070,
                "new_offset": 12542,
                "old_hex": "20202020202020202020202020202020737464657272203d206578632e737464657272206f72206227270a",
                "new_hex": "20202020202020202020202020202020737464657272203d206578632e737464657272206f72206227270a2020202020202020202020202020202072657461696e5f70726f636573735f73747265616d73286469726563746f72792c206c6162656c2c206578632e7374646f7574206f72206227272c207374646572722c0a2020202020202020202020202020202020202020726571756573743d726571756573742c2072657475726e636f64653d4e6f6e652c2074696d65645f6f75743d54727565290a"
            },
            {
                "old_offset": 10318,
                "new_offset": 12944,
                "old_hex": "20202020202020202020202020202020737464657272203d2070726f636573732e7374646572720a",
                "new_hex": "20202020202020202020202020202020737464657272203d2070726f636573732e7374646572720a2020202020202020202020202020202072657461696e5f70726f636573735f73747265616d73286469726563746f72792c206c6162656c2c2070726f636573732e7374646f75742c207374646572722c0a2020202020202020202020202020202020202020726571756573743d726571756573742c2072657475726e636f64653d70726f636573732e72657475726e636f64652c2074696d65645f6f75743d46616c7365290a"
            },
            {
                "old_offset": 11433,
                "new_offset": 14225,
                "old_hex": "202020202020202020202020202020202020202020202020776f726b7370616365203d207261775b32342b6c656e28736f75726365292b63617061636974793a5d0a",
                "new_hex": "202020202020202020202020202020202020202020202020776f726b73706163655f6f6666736574203d2032342b6c656e28736f75726365292b63617061636974790a"
            },
            {
                "old_offset": 12168,
                "new_offset": 14961,
                "old_hex": "2020202020202020202020202020202020202020202020202020202027776f726b73706163655f686561646572273a7b737472286174293a696e742e66726f6d5f627974657328776f726b73706163655b61743a61742b385d2c276c6974746c6527290a",
                "new_hex": "2020202020202020202020202020202020202020202020202020202027776f726b73706163655f686561646572273a7b737472286174293a7374727563742e756e7061636b5f66726f6d28273c51272c7261772c776f726b73706163655f6f66667365742b6174295b305d0a"
            }
        ]
    },
    "tests/test_hia_selfhost_native_observer.py": {
        "old": {
            "bytes": 11041,
            "sha256": "d88346f9278cb38efe42c96db83ac1d088c62c59c2a0d0ccda093956b8f1d49a"
        },
        "current": {
            "bytes": 14102,
            "sha256": "abb072533dcde5a042e8e522f881a8b2402fc035dbae61cecc30a8e1850e1d3f"
        },
        "splices": [
            {
                "old_offset": 302,
                "new_offset": 302,
                "old_hex": "40756e6974746573742e736b6970556e6c65737328706c6174666f726d2e73797374656d28293d3d274c696e75782720616e6420706c6174666f726d2e6d616368696e6528292e6c6f776572282920696e2028277838365f3634272c27616d64363427290a",
                "new_hex": "636c617373204e61746976654f627365727665724672616d6556616c69646174696f6e546573747328756e6974746573742e5465737443617365293a0a2020202064656620746573745f6672616d655f62797465735f616e645f64657363726970746f725f646f6d61696e5f72656d61696e5f65786163742873656c66293a0a2020202020202020666f722064657363726970746f7220696e20284e6f6e652c332c32313437343833363437293a0a202020202020202020202020776974682073656c662e73756254657374286f75747075745f66643d64657363726970746f72293a0a2020202020202020202020202020202065787065637465643d62274849414f42533032272b7374727563742e7061636b28273c3651272c322c332c313c3c32302c313c3c32302c3235352c0a202020202020202020202020202020202020202028313c3c3634292d312069662064657363726970746f72206973204e6f6e6520656c73652064657363726970746f72292b62275c7863335c783930415c305c786666270a2020202020202020202020202020202073656c662e617373657274457175616c286672616d652862275c7863335c783930272c6227415c305c786666272c313c3c32302c313c3c32302c3235352c64657363726970746f72292c6578706563746564290a2020202020202020666f722064657363726970746f7220696e202846616c73652c547275652c2d312c302c312c322c323134373438333634382c332e302c273327293a0a202020202020202020202020776974682073656c662e73756254657374286f75747075745f66643d64657363726970746f72293a0a20202020202020202020202020202020776974682073656c662e6173736572745261697365732856616c75654572726f72293a0a20202020202020202020202020202020202020206672616d652862275c786333272c6227272c302c302c302c64657363726970746f72290a0a2020202064656620746573745f696e76616c69645f6672616d655f69735f726566757365645f6265666f72655f7368617265645f6f75747075745f616c6c6f636174696f6e2873656c66293a0a202020202020202066726f6d20756e6974746573742e6d6f636b20696d706f72742070617463680a2020202020202020696e76616c69643d5b284e6f6e652c302c302c30292c2862797465617272617928292c302c302c30295d0a2020202020202020666f7220636170616369747920696e20282d312c547275652c312e302c312b28313c3c323029293a0a202020202020202020202020696e76616c69642e617070656e6428286227272c63617061636974792c302c3029290a2020202020202020666f722073697a6520696e20282d312c547275652c312e302c312b28313c3c323029293a0a202020202020202020202020696e76616c69642e617070656e6428286227272c302c73697a652c3029290a2020202020202020666f722066696c6c20696e20282d312c547275652c312e302c323536293a0a202020202020202020202020696e76616c69642e617070656e6428286227272c302c302c66696c6c29290a2020202020202020776974682074656d7066696c652e54656d706f726172794469726563746f7279287072656669783d276869612d6e61746976652d6672616d652d646f6d61696e2d2729206173206469726563746f72793a0a202020202020202020202020726f6f743d50617468286469726563746f7279290a202020202020202020202020696d6167653d726f6f742f27696d6167652e62696e273b696d6167652e77726974655f62797465732862275c78633327290a2020202020202020202020206f627365727665723d726f6f742f276f627365727665722e656c66273b6f627365727665722e77726974655f62797465732862276e6f742d657865637574656427290a202020202020202020202020776974682070617463682827746f6f6c732e6869615f73656c66686f73745f6e61746976655f6f627365727665722e7368617265645f6f75747075742729206173207368617265643a0a20202020202020202020202020202020666f7220736f757263652c63617061636974792c73697a652c66696c6c20696e20696e76616c69643a0a2020202020202020202020202020202020202020776974682073656c662e7375625465737428736f757263653d736f757263652c63617061636974793d63617061636974792c73697a653d73697a652c66696c6c3d66696c6c293a0a202020202020202020202020202020202020202020202020776974682073656c662e6173736572745261697365732856616c75654572726f72293a0a202020202020202020202020202020202020202020202020202020206e61746976655f696e766f6b6528726f6f742c27696e76616c6964272c6f627365727665722c696d6167652c736f757263652c63617061636974793d63617061636974792c0a2020202020202020202020202020202020202020202020202020202020202020776f726b73706163655f73697a653d73697a652c776f726b73706163655f66696c6c3d66696c6c2c6f6273657276655f747261705f7772697465733d54727565290a202020202020202020202020202020207368617265642e6173736572745f6e6f745f63616c6c656428290a20202020202020202020202073656c662e617373657274457175616c28736f7274656428706174682e6e616d6520666f72207061746820696e20726f6f742e697465726469722829292c5b27696d6167652e62696e272c276f627365727665722e656c66275d290a0a0a40756e6974746573742e736b6970556e6c65737328706c6174666f726d2e73797374656d28293d3d274c696e75782720616e6420706c6174666f726d2e6d616368696e6528292e6c6f776572282920696e2028277838365f3634272c27616d64363427290a"
            },
            {
                "old_offset": 3259,
                "new_offset": 5320,
                "old_hex": "2020202064656620746573745f736f757263655f6d75746174696f6e5f69735f61637475616c6c795f6f627365727665645f6e6f745f617373756d65642873656c66293a0a",
                "new_hex": "2020202064656620746573745f776f726b73706163655f6669656c64735f726571756972655f636f6d706c6574655f776f7264735f61745f65766572795f626f756e646172792873656c66293a0a202020202020202023204e6f6e656d70747920736f757263652f6f7574707574206d616b652074686520776f726b7370616365206f6666736574206e6f6e7a65726f20616e6420756e616c69676e65642e0a20202020202020206669656c64733d28302c382c31362c32342c34302c34382c35362c36342c37322c38302c38382c39362c3130342c3131322c3232342c3234382c31303234290a202020202020202073697a65733d736f72746564287b302c2a2861742b64656c746120666f7220617420696e206669656c647320666f722064656c746120696e2028372c3829297d290a2020202020202020736f757263653d6227415c305c786666272a31330a2020202020202020666f722073697a6520696e2073697a65733a0a202020202020202020202020776974682073656c662e7375625465737428776f726b73706163655f73697a653d73697a65293a0a20202020202020202020202020202020726573756c742c6f75747075743d73656c662e63616c6c2827776f726b73706163652d626f756e646172792d272b7374722873697a65292c0a202020202020202020202020202020202020202062797465732e66726f6d6865782827333120633020633327292c736f757263652c31332c73697a652c313939290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b27737461747573275d2c2772657475726e656427290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b27636f72655f753332275d2c30290a2020202020202020202020202020202073656c662e6173736572745472756528726573756c745b27736f757263655f756e6368616e676564275d290a2020202020202020202020202020202073656c662e617373657274457175616c286f75747075742c62275c786135272a3133290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b27776f726b73706163655f686561646572275d2c0a20202020202020202020202020202020202020207b737472286174293a30786337633763376337633763376337633720666f7220617420696e206669656c64732069662061742b383c3d73697a657d290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b276c696d697473275d5b27776f726b73706163655f6279746573275d2c73697a65290a0a2020202064656620746573745f736f757263655f6d75746174696f6e5f69735f61637475616c6c795f6f627365727665645f6e6f745f617373756d65642873656c66293a0a"
            }
        ]
    },
    "tests/test_hia_selfhost_linked_observer.py": {
        "old": {
            "bytes": 52874,
            "sha256": "e15cb7183ce6737ebc0287b10e5368110e9bc55613bd4b3f9013786a3229d2eb"
        },
        "current": {
            "bytes": 52986,
            "sha256": "b093864e5e5830c724d99d421e22878480f3dcbcac965d31575ba0f2baca86c4"
        },
        "splices": [
            {
                "old_offset": 22454,
                "new_offset": 22454,
                "old_hex": "2020202020202020736f757263653d6f726967696e616c2e534f555243452e726561645f627974657328292e7265706c61636528622268657074612e6869612e70726f6772616d2e76382073656c66686f73745c6e222c622268657074612e6869612e70726f6772616d2e76382073656c66686f73745f656c665c6e222c31290a",
                "new_hex": "2020202020202020736f757263653d6f726967696e616c2e534f555243452e726561645f627974657328290a202020202020202073656c662e6173736572745472756528736f757263652e737461727473776974682862226869612d61736d2e76312068657074612e6869612e70726f6772616d2e76392073656c66686f73745c6e2229290a2020202020202020736f757263653d736f757263652e7265706c61636528622268657074612e6869612e70726f6772616d2e76392073656c66686f73745c6e222c622268657074612e6869612e70726f6772616d2e76392073656c66686f73745f656c665c6e222c31290a"
            }
        ]
    },
    "tools/hia_selfhost_linked_observer.py": {
        "old": {
            "bytes": 23812,
            "sha256": "d178ab772101822e3ebad06614e6c9968c5e0134033960ae43032c452caf59e5"
        },
        "current": {
            "bytes": 24203,
            "sha256": "3afc277fac4cd18f4744047079da1917d00e79220c4a7a7c50aba2811e75c2f7"
        },
        "splices": [
            {
                "old_offset": 1413,
                "new_offset": 1413,
                "old_hex": "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206672616d652c207368617265645f6f75747075742c20726561645f63617074757265290a",
                "new_hex": "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206672616d652c207368617265645f6f75747075742c20726561645f636170747572652c0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202072657461696e5f70726f636573735f73747265616d73290a"
            },
            {
                "old_offset": 17903,
                "new_offset": 17974,
                "old_hex": "20202020202020202020202020202020737464657272203d206578632e737464657272206f72206227270a",
                "new_hex": "20202020202020202020202020202020737464657272203d206578632e737464657272206f72206227270a2020202020202020202020202020202072657461696e5f70726f636573735f73747265616d73286469726563746f72792c206c6162656c2c206578632e7374646f7574206f72206227272c207374646572722c0a2020202020202020202020202020202020202020726571756573743d726571756573742c2072657475726e636f64653d4e6f6e652c2074696d65645f6f75743d54727565290a"
            },
            {
                "old_offset": 18151,
                "new_offset": 18376,
                "old_hex": "20202020202020202020202020202020737464657272203d2070726f636573732e7374646572720a",
                "new_hex": "20202020202020202020202020202020737464657272203d2070726f636573732e7374646572720a2020202020202020202020202020202072657461696e5f70726f636573735f73747265616d73286469726563746f72792c206c6162656c2c2070726f636573732e7374646f75742c207374646572722c0a2020202020202020202020202020202020202020726571756573743d726571756573742c2072657475726e636f64653d70726f636573732e72657475726e636f64652c2074696d65645f6f75743d46616c7365290a"
            }
        ]
    }
}


def restore_observer_source(name, data, original_pin):
    """Independent segment construction; never import the producer/helper."""
    if name not in OBSERVER_SUCCESSORS:
        require(pin(data) == original_pin, "unchanged original observer/test source differs")
        return data
    row = OBSERVER_SUCCESSORS[name]
    require(type(data) is bytes and pin(data) == row["current"] and original_pin == row["old"],
            "observer successor complete original/current source differs")
    pieces, entries = [], []
    old_end = new_end = displacement = 0
    for item in row["splices"]:
        old_at, new_at = item["old_offset"], item["new_offset"]
        before, after = bytes.fromhex(item["old_hex"]), bytes.fromhex(item["new_hex"])
        require(type(old_at) is int and type(new_at) is int
                and old_at >= old_end and new_at >= new_end
                and old_at + displacement == new_at
                and before and after and before != after
                and data[new_at:new_at + len(after)] == after,
                "observer successor disjoint byte segments differ")
        pieces.extend((data[new_end:new_at], before))
        entries.append((old_at, new_at, before, after))
        old_end, new_end = old_at + len(before), new_at + len(after)
        displacement += len(after) - len(before)
    pieces.append(data[new_end:])
    restored = b"".join(pieces)
    require(pin(restored) == original_pin, "observer inverse does not restore complete original")
    pieces, old_end = [], 0
    for old_at, new_at, before, after in entries:
        require(restored[old_at:old_at + len(before)] == before, "observer restored segment differs")
        pieces.extend((restored[old_end:old_at], after))
        old_end = old_at + len(before)
    pieces.append(restored[old_end:])
    require(b"".join(pieces) == data, "observer complete forward replay differs")
    return restored

def observer_source_profile(root, capture):
    root = Path(root)
    fixture = capture.take(root / "tests/fixtures/cold_native_transport_original_gates_v3.json")
    if sha256(fixture).hexdigest() != OBSERVER_GATE_SHA:
        raise ValueError("original observer fixture changed")
    plan = parse(fixture)
    originals = plan["original_method_ids"]
    if (plan["original_method_count"] != 44 or not (len(originals) == len(set(originals)) == 44)):
        raise ValueError("complete original observer method inventory differs")
    # Compare every current complete source against the frozen original through
    # only the exact reviewed source relations above.
    for name, expected in plan["original_tests"].items():
        restore_observer_source(name, capture.take(root / name), expected)
    for item in plan["original_observers"]:
        source = capture.take(root / item["path"])
        tail, execute = item["selection_tail"].encode(), item["execute_source"].encode()
        if not source.endswith(tail):
            raise ValueError("observer exact selection tail differs")
        body = source[:-len(tail)]
        restore_observer_source(item["path"], body, item["before"])
        if body.count(execute) != 1 or pin(execute) != item["execute"]:
            raise ValueError("original observer execute function differs")
    all_ids = originals + list(OBSERVER_ADDITIONAL_IDS)
    current = [identity for module in plan["original_modules"]
               for identity in sorted(all_ids) if identity.startswith(module + ".")]
    if (len(current) != 47 or len(set(current)) != 47
            or [identity for identity in current if identity in originals] != originals):
        raise ValueError("complete current47/original44 observer domains differ")
    capture.unchanged()
    return plan, current, {
        "scope": "CURRENT_OBSERVER47_RETAINING_EXACT_ORIGINAL44",
        "original_fixture_sha256": OBSERVER_GATE_SHA,
        "original_method_ids": list(originals),
        "current_method_ids": current,
        "additional_method_ids": list(OBSERVER_ADDITIONAL_IDS),
        "source_relations": {name: {"original": row["old"], "current": row["current"],
            "exact_splices": len(row["splices"]), "whole_inverse_and_forward_verified": True}
            for name, row in OBSERVER_SUCCESSORS.items()},
        "original_execute_functions_unchanged": True,
        "selection_tails_unchanged": True,
        "past_results_are_current_qualification": False,
    }


def owned(raw, directory, expected_argv, cwd, seconds):
    directory = Path(directory)
    command = raw.json(directory / "command.json")
    result = raw.json(directory / "result.json")
    require(command == result["command"], "actual command/result differs")
    require(command["argv"] == list(map(str, expected_argv))
            and command["cwd"] == str(Path(cwd).resolve()), "actual argv/cwd differs")
    integer(command["timeout_seconds"], seconds);integer(command["cleanup_seconds"], 3)
    require(command["new_session"] is True, "owned session was not declared")
    pid = integer(command["pid"]);require(pid > 0, "actual child PID missing")
    integer(command["pgid"], pid);integer(result["pid"], pid)
    integer(result["exit_code"], 0)
    require(result["timed_out"] is False and result["interruption"] is None, "child interrupted or timed out")
    cleanup = result["owned_cleanup"]
    require(type(cleanup) is dict and cleanup["reaped"] is True
            and cleanup["after"] == [] and cleanup["signals"] == [], "owned child did not terminate naturally and clear")
    raw.take(directory / "stdout.log", result["stdout"])
    raw.take(directory / "stderr.log", result["stderr"])
    start = integer(command["started_monotonic_ns"])
    end = integer(result["ended_monotonic_ns"])
    require(0 < start <= end, "actual command times differ")
    return command, result, start, end


def child(raw, path, expected, source, selected, extra, source_profile):
    row = raw.json(path)
    require(row["schema"] == "hepta.cold-native-transport.original-gate-child.r3"
            and row["status"] == "COMPLETE_CURRENT_METHODS_PASS_RETAINING_ORIGINALS",
            "child current/original gate is not complete")
    require(row.get("observer_source_profile") == source_profile,
            "child current/original source relation differs")
    require(row["selected"] is selected and row["extra_handoff_controls"] is extra, "actual selection differs")
    require(row["planned"] == expected and row["started"] == expected and row["stopped"] == expected,
            "complete ordered original methods differ")
    integer(row["tests_run"], len(expected))
    require(row["statuses"] == {identity: "ok" for identity in expected}, "method outcomes differ")
    for key in ("problems", "errors", "failures", "skips", "expected_failures", "unexpected_successes"):
        require(row[key] == [], "original method anomaly: " + key)
    require(row["source_before"] == source and row["source_after"] == source
            and row["source_stable"] is True, "full component source changed")
    if selected and not extra:
        require(row["native_profiles"], "actual native public profile receipts absent")
        require(sum(integer(profile["calls"]) for profile in row["native_profiles"]) > 0,
                "no real selected public calls")
        for profile in row["native_profiles"]:
            require(integer(profile["entries"]) >= integer(profile["calls"]), "native entries missing")
    if not selected:
        require(row["native_profiles"] == [], "original lane used native selection")
    require(row["whole_native"] is False and row["qualification_complete"] is False,
            "child overstates its scope")
    for path, expected_pin in row["consumed"].items():
        raw.take(path, expected_pin)
    return row


def read(evidence, *, manifest_path, manifest_pin, source_root):
    evidence, source_root = Path(evidence).resolve(strict=True), Path(source_root).resolve(strict=True)
    raw = Raw()
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest = raw.json(manifest_path, manifest_pin)
    require(manifest["schema"] == "hepta.cold-native-transport.hosted-build.r3"
            and manifest["status"] == "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT"
            and manifest["whole_native"] is False, "unknown native build selection")
    require(manifest["source_root"] == str(source_root)
            and set(manifest["inputs"]) == set(SOURCE_INPUTS), "complete source closure differs")
    source = {}
    for name in SOURCE_INPUTS:
        source[name] = pin(raw.take(source_root / name, manifest["inputs"][name]))
    plan_raw = raw.take(source_root / "tests/fixtures/cold_native_transport_original_gates_v3.json")
    controls_raw = raw.take(source_root / "tests/fixtures/cold_native_transport_controls_v3.json")
    require(sha256(plan_raw).hexdigest() == GATE_SHA and sha256(controls_raw).hexdigest() == CONTROL_SHA,
            "independent original control authority changed")
    plan, controls = parse(plan_raw), parse(controls_raw)
    plan, expected, source_profile = observer_source_profile(source_root, raw)
    retained = plan["original_method_ids"]
    require(integer(plan["original_method_count"], 44) and len(retained) == 44
            and len(set(retained)) == 44, "complete original 44 identities differ")
    for key in ("policy", "extension", "probe", "handoff_controls", "compiler", "build_tool", "python_library"):
        item = manifest[key];raw.take(item["path"], item["pin"])
    runtime = manifest["runtime"]
    raw.take(runtime["path"], runtime["pin"])
    raw.take(runtime["subprocess_path"], runtime["subprocess_pin"])
    for path, expected_pin in manifest["python_headers"].items():
        raw.take(path, expected_pin)
    report = raw.json(evidence / "report.json")
    require(report["schema"] == "hepta.cold-native-transport.gates.r3"
            and report["scope"] == "regression"
            and report["status"] == "CURRENT47_RETAINED44_SELECTED47_HANDOFF8_PASS_NOT_WHOLE_COLD"
            and report.get("observer_source_profile") == source_profile,
            "not a complete current47/original44 regression report")
    require(report["source_before"] == source and report["source_after"] == source
            and report["source_stable"] is True
            and report["whole_native"] is False and report["qualification_complete"] is False,
            "regression source/scope differs")
    lanes = ("original-1", "original-2", "selected", "atomic-handoff-8")
    require([row["lane"] for row in report["lanes"]] == list(lanes)
            and len(report["commands"]) == 4, "full original-before-candidate lanes differ")
    previous_end = 0
    children = []
    for ordinal, lane in enumerate(lanes):
        selected, extra = ordinal >= 2, ordinal == 3
        command = [runtime["path"], "-I", "-S", "-B",
                   str(source_root / "tools/qualify_hia_cold_native_transport.py"),
                   "--child", str(evidence / lane)]
        if selected:command.append("--selected")
        if extra:command.append("--handoff")
        actual, result, start, end = owned(raw, evidence / (lane + "-owned"), command, source_root, 1800)
        require(previous_end <= start and result == report["commands"][ordinal], "lane order or complete receipt differs")
        previous_end = end
        environment = actual["environment"]
        require(("HEPTA_HIA_COLD_NATIVE_TRANSPORT_MANIFEST" in environment) is selected, "lane selector differs")
        if selected:
            require(environment["HEPTA_HIA_COLD_NATIVE_TRANSPORT_MANIFEST"] == str(manifest_path)
                    and environment["HEPTA_HIA_COLD_NATIVE_TRANSPORT_ALLOW_DEVELOPMENT"] == "1",
                    "selected actual manifest differs")
        expected_ids = (["tests.test_hia_cold_native_transport.ColdNativeTransportHandoffTests.test_all_eight_actual_atomic_handoff_controls"]
                        if extra else expected)
        expected_pin = report["lanes"][ordinal]["report"]
        raw.take(evidence / lane / "report.json", expected_pin)
        children.append(child(raw, evidence / lane / "report.json", expected_ids, source, selected, extra,
                              source_profile))
    authority = raw.json(evidence / "original-authority.json")
    require(authority["schema"] == "hepta.cold-native-transport.original-method-authority.r3"
            and authority["planned"] == retained and authority["current_planned"] == expected
            and authority["observer_source_profile"] == source_profile and authority["source"] == source
            and authority["method_outcomes_only"] is True, "original authority differs")
    require(authority["reports"] == [pin(raw.take(evidence / lane / "report.json")) for lane in lanes[:2]]
            and children[0]["statuses"] == children[1]["statuses"], "two complete original reports differ")
    control_dir = evidence / "actual-handoff-8"
    executable = manifest["handoff_controls"]["path"]
    control_command = [executable, runtime["path"], str(control_dir / "controls.json")]
    owned(raw, control_dir / "owned", control_command, source_root, 60)
    require(raw.take(control_dir / "owned/stdout.log") == b"" and raw.take(control_dir / "owned/stderr.log") == b"",
            "atomic handoff control emitted unexpected output or unraisable diagnostics")
    observed = raw.json(control_dir / "controls.json")
    required = controls["handoff_controls"]
    integer(observed["planned"], 8)
    require(observed["schema"] == "hepta.cold-native-transport.handoff-controls.r3"
            and observed["status"] == "CONTROLS_PASS"
            and observed["whole_native"] is False and len(observed["controls"]) == 8,
            "actual native handoff controls incomplete")
    for actual, expected_row in zip(observed["controls"], required):
        require(actual["id"] == expected_row["id"] and actual["passed"] is True,
                "declared handoff control differs")
        integer(actual["handoff_return"], expected_row["expected_return"])
        require(actual["actual_pending"] is expected_row["expected_pending"], "actual pending-error observation differs")
        integer(actual["failure_line"], 0)
    for index in (0, 1, 4, 5):
        require(observed["controls"][index]["real_number_reuse_checked"] is True,
                "failed adoption did not test actual replacement descriptor survival")
    nested = raw.json(control_dir / "readback.json")
    require(nested["controls"] == [row["id"] for row in required]
            and nested["source_stable"] is True and nested["whole_native"] is False
            and nested["qualification_complete"] is False, "test's full control readback differs")
    for path, expected_pin in nested["consumed"].items():raw.take(path, expected_pin)
    for path, expected_pin in report["consumed"].items():raw.take(path, expected_pin)
    raw.unchanged()
    result = {"schema": "hepta.cold-native-transport.regression-readback.r3",
              "evidence_integrity": "PASS", "original_methods_each": 44,
              "original_runs": 2, "selected_methods": 47, "actual_handoff_controls": 8,
              "current_methods_each": 47, "additional_methods_each": 3,
              "complete_original_id_order": retained, "complete_current_id_order": expected,
              "observer_source_profile": source_profile, "all_consumed": raw.inventory(),
              "source_stable": True, "whole_native": False, "qualification_complete": False,
              "cold_complete_17_references_38_phases": "SEPARATE_ORIGINAL_FULL_RAW_READER_REQUIRED",
              "broader_CT36": "DECLARED_NOT_SUBSTITUTED_BY_HANDOFF8"}
    raw.unchanged()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-bytes", type=int, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("independent readback is create-only")
    result = read(args.evidence, manifest_path=args.manifest,
                  manifest_pin={"bytes": args.manifest_bytes, "sha256": args.manifest_sha256},
                  source_root=args.source_root)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"evidence_integrity": result["evidence_integrity"],
                      "qualification_complete": False, "whole_native": False}, sort_keys=True))


if __name__ == "__main__":
    main()

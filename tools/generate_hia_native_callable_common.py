"""Shared wire and mechanical offsets for source-bound native HIA callables."""
import re
from tools.generate_hia_result_value_common import ROOT, document, render_assembly, resolve

CONSTANTS = {
    'NC_REQUEST': int.from_bytes(b'HIACODQ1', 'little'),
    'NC_REPLY': int.from_bytes(b'HIACODR1', 'little'),
    'NC_STATE': int.from_bytes(b'HIACODW1', 'little'),
    'NC_FINAL_REQUEST': int.from_bytes(b'HIAVRFQ1', 'little'),
    'NC_FINAL_REPLY': int.from_bytes(b'HIAVRFR1', 'little'),
    'NC_ARENA': int.from_bytes(b'HIACODA1', 'little'),
    'NC_OBJECT': int.from_bytes(b'HIACOBJ1', 'little'),
    'NC_TOKEN': int.from_bytes(b'HIACCAP1', 'little'),
    'NC_BODY_REPLY': int.from_bytes(b'HIACBR01', 'little'),
    'NC_BODY_VALUE': int.from_bytes(b'HIACVA01', 'little'),
    'NC_PHASE': 128, 'NC_FEEDBACK': 136, 'NC_SELF': 144, 'NC_PID': 152,
    'NC_HELD': 160, 'NC_STATUS': 168, 'NC_ROLE': 176, 'NC_SELECT': 184, 'NC_ARG': 192,
    'NR_OP': 256, 'NR_OBJ': 264, 'NR_TOKEN': 272, 'NR_KIND': 280,
    'NR_CODE': 288, 'NR_CODE_SIZE': 296, 'NR_CODE_LENGTH': 304,
    'NR_SOURCE': 312, 'NR_SOURCE_SIZE': 320, 'NR_SOURCE_LENGTH': 328,
    'NR_WORK': 336, 'NR_WORK_SIZE': 344, 'NR_PARENT': 352, 'NR_STATE': 360,
    'NR_FIELD': 368, 'NR_ADDRESS': 376, 'NR_EXTENT': 384, 'NR_LENGTH': 392,
    'NC_GROW': 400, 'NC_OLD': 408, 'NC_RANDOM': 416, 'NC_RANDOM_USED': 432,
    'NC_CREATED': 440, 'NC_CONTINUE': 448, 'NC_DISPATCH': 456, 'NC_MAIN_STATUS': 464,
    'NC_PENDING': 472, 'NC_CONSUMED': 480, 'NC_KNOWN': 488,
    'NC_EXEC': 496, 'NC_EXEC_BYTES': 504, 'NC_OBJECT_SAVED': 512,
    'NC_BODY_ACTION': 520, 'NC_CLEANUP_STATUS': 528,
    'NC_BUILDER': 536, 'NC_INPUT_LENGTH': 544, 'NC_BUFFER': 552, 'NC_BUFFER_BYTES': 560,
    'NC_AFTER_UNLOCK': 568, 'NC_FINALIZER': 576, 'NC_FINAL_MODE': 584, 'NC_RETRY_ACK': 592,
    'NC_RESULT': 4096, 'NC_MIN_OUTPUT': 8192,
    'NC_LIMIT': 1048576, 'NC_EXEC_SIZE': 3145728,
}


def source(entry, body):
    for name, value in sorted(CONSTANTS.items(), key=lambda item: -len(item[0])):
        body = re.sub(r'\b' + name + r'\b', str(value), body)
    return resolve(entry, body)

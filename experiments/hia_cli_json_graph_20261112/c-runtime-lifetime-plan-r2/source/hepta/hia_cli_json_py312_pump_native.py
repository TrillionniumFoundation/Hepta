"""One-use admission wrapper for the private C lifetime transport.

The mapped HIA image still chooses every effect and reference-release order.
After admission, one PYFUNCTYPE call runs the entire terminal/yield plan in
C. Its actual status, counters and optional fixed-buffer trace are written
before returning to Python. No Python callback drives a leaf. The existing
per-leaf adapter is retained as a separate unqualified comparison path.

This component does not implement the body driver's CALL/SEND/UNPACK or
entry/monitoring ports. It does not claim full frame/evaluator or JSON graph
equivalence. The public CLI does not select it. No new source/native/17/46
result is supplied by this source file.
"""
from __future__ import annotations

import ctypes
import sys

from hepta.hia_cli_json_py312_lifetime_native import Py312LifetimeSession


PUMP_MAGIC = int.from_bytes(b'HCLIPMP1', 'little')
PUMP_WORDS = 64
TRACE_WORDS = 32
TRACE_BYTES = TRACE_WORDS * 8
REQUEST_FIELDS = (
    'magic', 'profile', 'component', 'permission', 'context', 'context_bytes',
    'entry', 'state', 'state_bytes', 'generator', 'code', 'parent',
    'instruction', 'mode', 'traceback_handled', 'trace', 'trace_capacity',
    'trace_stride', 'reserved18', 'reserved19', 'result_status',
    'native_attempts', 'native_returns', 'effect_attempts', 'effect_returns',
    'last_issued', 'last_consumed', 'trace_written', 'trace_dropped',
    'blocked_operation', 'refusal_reason', 'result_address', 'error_address',
    'external_address', 'state_before', 'state_after', 'top_before', 'top_after',
    'last_native_return', 'last_leaf_return', 'last_leaf_marker',
    'unexpected_pyerr', 'unexpected_owned_error_address',
)


class BatchedPy312LifetimeSession(Py312LifetimeSession):
    """A complete lifetime run, with all C originals retained on refusal.

    The caller must keep the actual generator, parent and admitted images
    alive. This wrapper deliberately stores borrowed object addresses only.
    It must itself remain alive if ``quarantined`` is true: the request can
    contain an additional owned unexpected-error address on a protocol
    failure, and the raw context/frame can still own committed references.
    No Python destructor guesses a cleanup order for those references.
    """

    def __init__(self, image, raw, *, generator_pointer, code_pointer,
                 parent_pointer, instruction, mode, traceback_handled=False,
                 trace_records=0):
        if type(trace_records) is not int or not 0 <= trace_records <= sys.maxsize // TRACE_BYTES:
            raise ValueError('an exact representable observer-buffer extent is required')
        super().__init__(image, raw, generator_pointer=generator_pointer,
                         code_pointer=code_pointer, parent_pointer=parent_pointer,
                         instruction=instruction, mode=mode,
                         traceback_handled=traceback_handled)
        self.pump_returned = False
        self.pump_returncode = None
        self.batched_receipt = None
        self.trace_records = trace_records
        self.trace = (ctypes.c_ubyte * (trace_records * TRACE_BYTES))() if trace_records else None
        self.request = (ctypes.c_uint64 * PUMP_WORDS)()
        address = ctypes.cast(raw.leaves.library.hia_cli_json_py312_lifetime_run,
                              ctypes.c_void_p).value
        if not address:
            raise ValueError('the independently admitted leaf DSO has no C lifetime pump')
        self.pump_entry = ctypes.PYFUNCTYPE(
            ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint64)(address)
        native_address = ctypes.cast(self.entry, ctypes.c_void_p).value
        if not native_address:
            raise ValueError('the independently admitted lifetime HIA entry is absent')
        fields = (
            PUMP_MAGIC, 31214, 1, 0,
            ctypes.addressof(raw.context), raw.leaves.context_bytes,
            native_address, ctypes.addressof(self.state), ctypes.sizeof(self.state),
            self.generator_pointer, self.code_pointer, self.parent_pointer,
            self.instruction, self.mode, int(traceback_handled),
            ctypes.addressof(self.trace) if self.trace is not None else 0,
            trace_records, TRACE_BYTES,
        )
        for index, value in enumerate(fields):
            self.request[index] = value
        self.admitted_request = tuple(fields)

    def step(self):
        raise RuntimeError('this session has one C run, not a Python step permission')

    def observe(self):
        raise RuntimeError('this session has no Python leaf callback')

    def run_raw(self):
        if (self.finished or self.busy or self.quarantined or self.pump_returned
                or self.raw.active or self.raw.external_pending
                or self.raw.protocol_failed or self.raw.nested_active is not None):
            raise RuntimeError('C lifetime session is active, terminal, or inadmissible')
        if (tuple(self.request[:18]) != self.admitted_request
                or any(self.request[index] for index in range(18, PUMP_WORDS))):
            raise RuntimeError('C lifetime request changed before its one-use admission')
        self.busy = True
        self.raw.active = True
        try:
            # The C request validates the complete fresh workspace before its
            # first HIA call. Do not call self.views(): that would prefill its
            # initially-zero dynamic slot/error words from Python.
            returned = self.pump_entry(self.request, PUMP_WORDS)
            self.pump_returned = True
            self.pump_returncode = returned
            # C has already committed closure or quarantine and every owner
            # before these Python allocations/observations can fail.
            request = tuple(self.request)
            self.batched_receipt = {
                'schema': 'hia.cli-json.py312-lifetime-C-pump-return.v1',
                'returncode': returned,
                'raw_request_words': request,
                'fields': dict(zip(REQUEST_FIELDS, request)),
                'trace_records': request[27],
                'trace_records_omitted': request[28],
                'trace_is_complete': request[28] == 0,
                'body_driver_qualified': False,
                'native_or_C_qualification_inherited': False,
            }
            if returned != 0 or request[3] != 2 or request[30] or request[41] or request[42]:
                raise RuntimeError('C lifetime pump refused; retain its request and raw owners')
            if any(request[i] != self.admitted_request[i] for i in range(18) if i != 3):
                raise RuntimeError('C lifetime immutable input binding differs after return')
            if (request[21] != request[22] or request[23] != request[24]
                    or request[25] != request[26] or not request[22]
                    or request[29] or request[27] > self.trace_records
                    or request[38] != request[20]
                    or request[27] + request[28] != request[22] + request[24]
                    or any(request[43:])):
                raise RuntimeError('C lifetime actual-return accounting differs')
            status = request[20]
            view = self.raw.refresh()
            if (request[31], request[32], request[33]) != (view[5], view[8], 0):
                raise RuntimeError('C lifetime final raw ownership differs')
            if ((status == 0 and (self.mode != 0 or view[5] or view[8]))
                    or (status == 1 and (self.mode != 1 or view[5] or not view[8]))
                    or (status == 3 and (self.mode != 2 or not view[5] or view[8]))
                    or status not in (0, 1, 3)
                    or self.get(112) != status + 1):
                raise RuntimeError('C lifetime terminal status/owned result differs')
            self.status = status
            self.result_address, self.error_address = view[5], view[8]
            self.pending = self.finish_pending = False
            self.finished = True
            return status
        except BaseException as error:
            self.seal_failure(error)
            raise
        finally:
            self.raw.active = False
            self.busy = False

    def trace_bytes(self):
        """Read only whole returned records after closure or quarantine.

        This observation is not made inside the C loop. An incomplete trace
        remains explicitly incomplete; no prefix is promoted to a full trace.
        """
        if self.busy or not self.pump_returned:
            raise RuntimeError('C lifetime output has no returned boundary')
        count = int(self.request[27])
        if count > self.trace_records:
            raise RuntimeError('C lifetime trace extent exceeds the admitted buffer')
        if not count:
            return b''
        return ctypes.string_at(ctypes.addressof(self.trace), count * TRACE_BYTES)

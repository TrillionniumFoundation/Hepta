"""Mechanical foreign observations for the HIA ELF PowerSort continuation.

STATIC CANDIDATE: not imported or executed. HIA chooses all array ordering,
tuple traversal, comparator selection and fallback. This module performs only
the exact foreign primitive named by one pending HIA request. It contains no
sorting algorithm and never calls sorted() or list.sort().

The rich-comparison and handled-exception APIs below are public CPython C APIs.
The preserved official source pins document their ownership conventions:
PyErr_GetHandledException returns a new reference; PyErr_SetHandledException
increments its argument rather than stealing it.
"""
from __future__ import annotations
import ctypes
import struct
import sys

_PY_LT = 0
_PY_EQ = 2
_PY_TP_RICHCOMPARE = 67

def _function(name, result, arguments):
    function = getattr(ctypes.pythonapi, name)
    function.restype = result
    function.argtypes = arguments
    return function

_TYPE_SLOT = _function('PyType_GetSlot', ctypes.c_void_p,
                      [ctypes.py_object, ctypes.c_int])
_RICH_BOOL = _function('PyObject_RichCompareBool', ctypes.c_int,
                      [ctypes.py_object, ctypes.py_object, ctypes.c_int])
_IS_TRUE = _function('PyObject_IsTrue', ctypes.c_int, [ctypes.c_void_p])
_DECREF = _function('Py_DecRef', None, [ctypes.c_void_p])
_HANDLED_GET = _function('PyErr_GetHandledException', ctypes.c_void_p, [])
_HANDLED_SET = _function('PyErr_SetHandledException', None, [ctypes.c_void_p])
_RICH_SLOT = ctypes.PYFUNCTYPE(ctypes.c_void_p, ctypes.py_object,
                              ctypes.py_object, ctypes.c_int)
_NOT_IMPLEMENTED = id(NotImplemented)
_TRUE = id(True)
_FALSE = id(False)


class SortObservation:
    def __init__(self, session, kind):
        if kind not in (1, 2, 3, 4):
            raise RuntimeError('unknown issued ELF sort key shape')
        self.session = session
        self.kind = kind
        self.keys = {}
        self.slots = {}
        self.result_pointer = 0

    def key(self, node):
        if node not in self.keys:
            session = self.session
            if self.kind == 1:
                value = (session.atom(session.word(node + 24)),
                         session.atom(session.word(node + 32)))
            elif self.kind == 2:
                value = session.atom(session.word(node + 24))
            elif self.kind == 3:
                value = session.atom(session.word(node + 40))
            else:
                raise RuntimeError('pure ELF name ordering issued a foreign key')
            self.keys[node] = value
        return self.keys[node]

    def tuple_item(self, node, index):
        value = self.key(node)
        if type(value) is not tuple:
            raise RuntimeError('HIA tuple observation lacks an exact tuple')
        return tuple.__getitem__(value, index)

    def selected(self, node, first_item):
        if first_item == 0:
            return self.key(node)
        if first_item == 1:
            return self.tuple_item(node, 0)
        raise RuntimeError('unknown issued ELF comparator operand')

    def slot(self, value):
        address = _TYPE_SLOT(type(value), _PY_TP_RICHCOMPARE) or 0
        if address and address not in self.slots:
            self.slots[address] = _RICH_SLOT(address)
        return address

    def metadata(self, node):
        key = self.key(node)
        key_type = type(key)
        is_tuple = key_type is tuple
        length = tuple.__len__(key) if is_tuple else 0
        candidate = tuple.__getitem__(key, 0) if is_tuple and length else key
        candidate_type = type(candidate)
        # Raw type identity and slot addresses are observations. No type object
        # is retained and no Python __class__/attribute hook is consulted.
        return (id(key_type), int(is_tuple), length, id(candidate_type),
                int(candidate_type is tuple), self.slot(candidate), self.slot(key), 0)

    def slot_call(self, left, right, first_item, address):
        if self.result_pointer:
            raise RuntimeError('foreign ELF comparison result is still pending')
        if address not in self.slots:
            raise RuntimeError('unobserved ELF rich comparison slot')
        # Selection and the left-slot equality test were already performed by
        # HIA. This is one raw richcmpfunc call, not a comparison dispatcher.
        pointer = self.slots[address](self.selected(left, first_item),
                                      self.selected(right, first_item), _PY_LT)
        if not pointer:
            raise RuntimeError('foreign rich comparison returned NULL without an exception')
        self.result_pointer = pointer
        if pointer == _NOT_IMPLEMENTED:
            return 0, 0
        if pointer == _TRUE or pointer == _FALSE:
            return 1, int(pointer == _TRUE)
        return 2, 0

    def drop_result(self):
        pointer, self.result_pointer = self.result_pointer, 0
        if pointer:
            _DECREF(pointer)

    def result_truth_and_release(self):
        pointer, self.result_pointer = self.result_pointer, 0
        if not pointer:
            raise RuntimeError('foreign ELF truth result is not pending')
        ambient = _HANDLED_GET()
        try:
            try:
                value = _IS_TRUE(pointer)
            except BaseException:
                # listobject.c decrefs this result with the caller's handled
                # exception active, after the truth primitive has failed.
                # Temporarily restore that exact handled exception while
                # releasing the raw result, then restore the actual failure
                # before the bare rethrow. No synthetic raise is performed.
                failure = _HANDLED_GET()
                try:
                    _HANDLED_SET(ambient)
                    _DECREF(pointer)
                finally:
                    _HANDLED_SET(failure)
                    if failure:
                        _DECREF(failure)
                raise
            else:
                _DECREF(pointer)
                return value
        finally:
            if ambient:
                _DECREF(ambient)

    def close(self):
        self.drop_result()
        self.keys.clear()
        self.slots.clear()
        self.session = None


def close_sort_observation(session):
    selected = getattr(session, '_elf_sort_observation', None)
    if selected is not None:
        session._elf_sort_observation = None
        selected.close()


def observe_sort(session, operation, a, b, c, d):
    if operation == 17:
        if getattr(session, '_elf_sort_observation', None) is not None:
            raise RuntimeError('foreign ELF sort context is already pending')
        session._elf_sort_observation = SortObservation(session, a)
        session.answer(payload=struct.pack('<2Q', sys.version_info.major,
                                           sys.version_info.minor))
        return
    selected = getattr(session, '_elf_sort_observation', None)
    if selected is None:
        raise RuntimeError('foreign ELF sort observation has no active context')
    if operation == 18:
        session.answer(payload=struct.pack('<8Q', *selected.metadata(a)))
    elif operation == 19:
        value = _RICH_BOOL(selected.selected(a, c), selected.selected(b, c), _PY_LT)
        session.answer(payload=struct.pack('<Q', value))
    elif operation == 20:
        left, right = selected.key(a), selected.key(b)
        if type(left) is not tuple or type(right) is not tuple:
            raise RuntimeError('HIA tuple lengths require exact tuples')
        session.answer(payload=struct.pack('<2Q', tuple.__len__(left), tuple.__len__(right)))
    elif operation == 21:
        value = _RICH_BOOL(selected.tuple_item(a, c), selected.tuple_item(b, c), _PY_EQ)
        session.answer(payload=struct.pack('<Q', value))
    elif operation == 22:
        value = _RICH_BOOL(selected.tuple_item(a, c), selected.tuple_item(b, c), _PY_LT)
        session.answer(payload=struct.pack('<Q', value))
    elif operation == 23:
        session.answer(payload=struct.pack('<Q', selected.slot(selected.selected(a, b))))
    elif operation == 24:
        session.answer(payload=struct.pack('<2Q', *selected.slot_call(a, b, c, d)))
    elif operation == 25:
        session.answer(payload=struct.pack('<Q', selected.result_truth_and_release()))
    elif operation == 26:
        selected.drop_result()
        session.answer()
    elif operation == 27:
        selected.keys.pop(a, None)
        session.answer()
    elif operation == 28:
        close_sort_observation(session)
        session.answer()
    else:
        raise RuntimeError('unknown native ELF sorting observation')

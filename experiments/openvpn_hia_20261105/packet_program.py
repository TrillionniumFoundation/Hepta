# SPDX-License-Identifier: GPL-2.0-only
# OpenVPN 2.7.8 packet-ID semantics: dc1f569087135894ac2703aeabd7a960ee9452d4.
"""Construct a finite, borrowed-buffer HIA packet-ID codec.

All wire decoding, sender transitions and partial-failure updates are Core
instructions. The C adapter only translates OpenVPN's struct representation.
The source contract is OpenVPN 2.7.8 packet_id.c, fixed by packet-source-lock.json.
"""
from __future__ import annotations

import json
from pathlib import Path

INVALID_STATE = 0xFFFE0001
MAX_BYTES = 65536
STATE_BYTES = 32


def param(name, typ):
    return {"name": name, "type": typ}


class Block:
    def __init__(self, label, params):
        self.label, self.ops, self.counter = label, [], 0
        self.params = [param(label + "_" + name, typ) for name, typ in params]
        self.values = {name: p["name"] for (name, _), p in zip(params, self.params)}
        self.types = dict(params)

    def op(self, op, args=(), typ=None, **attrs):
        self.counter += 1
        name = self.label + "_v" + str(self.counter)
        self.ops.append({"op": op, "args": list(args),
                         "out": [] if typ is None else [param(name, typ)], "attrs": attrs})
        return name if typ else None

    def c(self, value, typ="u64"):
        return self.op("const", typ=typ, value=value)

    def cast(self, value, typ="u64"):
        return self.op("int.cast", [value], typ, mode="wrap")

    def byte_base(self, offset):
        # Entry admits wire capacity <=MAX_BYTES and exactly 32 state bytes.
        # Metadata and per-word room checks dominate all dynamic indices. The
        # u32 round-trip is therefore exact; widening before +i exposes a
        # non-wrapping address calculation to LLVM without unchecked access.
        return self.cast(self.cast(offset, "u32"), "usize")

    def word(self, buf, offset, width=8, endian="little"):
        result = self.c(0)
        base = self.byte_base(offset)
        # A complete word has already passed its room check. Highest index
        # first lets its checked access dominate all lower byte indices.
        for i in reversed(range(width)):
            at = self.op("int.add.wrap", [base, self.c(i, "usize")], "usize")
            byte = self.op("buffer.load", [buf, at], "u8")
            wide = self.cast(byte)
            shift = i * 8 if endian == "little" else (width - 1 - i) * 8
            part = self.op("int.shl.checked", [wide, self.c(shift)], "u64")
            result = self.op("bit.or", [result, part], "u64")
        return result

    def put(self, buf, offset, value, width=8, endian="little"):
        base = self.byte_base(offset)
        # This reorders bytes only inside a fully admitted word. Word ordering
        # (ID then time for append, time then ID for prepend) remains unchanged,
        # so upstream partial failures and sender transitions are preserved.
        for i in reversed(range(width)):
            shift = i * 8 if endian == "little" else (width - 1 - i) * 8
            part = self.op("int.shr.checked", [value, self.c(shift)], "u64")
            byte = self.cast(part, "u8")
            at = self.op("int.add.wrap", [base, self.c(i, "usize")], "usize")
            self.op("buffer.store", [buf, at, byte])

    def state_write(self, index, value):
        self.put(self.values["state"], self.c(index * 8, "usize"), value)

    def ret(self, value):
        self.term = {"op": "ret", "values": [value]}

    def edge(self, target, values):
        return {"target": target, "args": list(values)}

    def jump(self, target, values=()):
        self.term = {"op": "jump", **self.edge(target, values)}

    def branch(self, cond, yes, yes_values, no, no_values=()):
        self.term = {"op": "branch", "cond": cond, "then": self.edge(yes, yes_values),
                     "else": self.edge(no, no_values)}

    def document(self):
        return {"id": self.label, "params": self.params, "ops": self.ops, "term": self.term}


class Function:
    def __init__(self, name, params):
        self.name, self.params, self.blocks = name, params, []
        self.ctx = [("wire", params[0][1]), ("state", "mutbuf"),
                    ("id", "u64"), ("time", "u64"), ("off", "usize"), ("len", "usize"),
                    ("cap", "usize")] + params[2:]
        b = self.block("entry", params)
        n = b.op("buffer.len", [b.values["state"]], "usize")
        ok = b.op("compare.eq", [n, b.c(STATE_BYTES, "usize")], "bool")
        capacity = b.op("buffer.len", [b.values["wire"]], "usize")
        bounded = b.op("compare.le", [capacity, b.c(MAX_BYTES, "usize")], "bool")
        ok = b.op("bool.and", [ok, bounded], "bool")
        for flag in ("long_form", "prepend"):
            if flag in b.values:
                legal = b.op("compare.le", [b.values[flag], b.c(1, "u32")], "bool")
                ok = b.op("bool.and", [ok, legal], "bool")
        b.branch(ok, "metadata", [b.values[n] for n, _ in params], "invalid")
        b = self.block("metadata", params)
        for i, name in enumerate(("id", "time", "off", "len")):
            val = b.word(b.values["state"], b.c(i * 8, "usize"))
            b.values[name] = b.cast(val, "usize") if name in {"off", "len"} else val
        b.values["cap"] = b.op("buffer.len", [b.values["wire"]], "usize")
        off_ok = b.op("compare.le", [b.values["off"], b.values["cap"]], "bool")
        remaining = b.op("int.sub.wrap", [b.values["cap"], b.values["off"]], "usize")
        len_ok = b.op("compare.le", [b.values["len"], remaining], "bool")
        ok = b.op("bool.and", [off_ok, len_ok], "bool")
        b.branch(ok, "start", self.args(b), "invalid")
        for label, value in (("invalid", INVALID_STATE), ("failure", 0), ("success", 1)):
            b = self.block(label, [])
            b.ret(b.c(value, "u32"))

    def args(self, block, changes=None):
        values = dict(block.values)
        values.update(changes or {})
        return [values[n] for n, _ in self.ctx]

    def block(self, label, params=None):
        b = Block(label, self.ctx if params is None else params)
        self.blocks.append(b)
        return b

    def document(self):
        # Generic terminal blocks are included only when a real edge targets them.
        by_name = {b.label: b for b in self.blocks}
        seen, todo = set(), ["entry"]
        while todo:
            label = todo.pop()
            if label in seen:
                continue
            seen.add(label)
            term = by_name[label].term
            if term["op"] == "jump":
                todo.append(term["target"])
            elif term["op"] == "branch":
                todo.extend((term["then"]["target"], term["else"]["target"]))
        # Entry names must exactly match the function's parameter names.
        return {"name": self.name, "params": self.blocks[0].params, "returns": ["u32"],
                "effects": ["read", "write", "trap"], "entry": "entry",
                "blocks": [b.document() for b in self.blocks if b.label in seen]}


def packet_read(epoch=False):
    params = [("wire", "readbuf"), ("state", "mutbuf")]
    if not epoch:
        params.append(("long_form", "u32"))
    f = Function("ovpn_hia_packet_id_read" + ("_epoch" if epoch else ""), params)
    b = f.block("start")
    if not epoch:
        b.state_write(0, b.c(0)); b.state_write(1, b.c(0))
    enough = b.op("compare.ge", [b.values["len"], b.c(8 if epoch else 4, "usize")], "bool")
    b.branch(enough, "read_id", f.args(b), "failure")
    b = f.block("read_id")
    value = b.word(b.values["wire"], b.values["off"], 8 if epoch else 4, "big")
    pid = b.op("bit.and", [value, b.c((1 << 48) - 1)], "u64") if epoch else value
    b.state_write(0, pid)
    off = b.op("int.add.wrap", [b.values["off"], b.c(8 if epoch else 4, "usize")], "usize")
    size = b.op("int.sub.wrap", [b.values["len"], b.c(8 if epoch else 4, "usize")], "usize")
    b.state_write(2, b.cast(off)); b.state_write(3, b.cast(size))
    if epoch:
        ep = b.op("int.shr.checked", [value, b.c(48)], "u64")
        b.ret(b.cast(ep, "u32"))
    else:
        long = b.op("compare.ne", [b.values["long_form"], b.c(0, "u32")], "bool")
        b.branch(long, "maybe_time", f.args(b, {"off": off, "len": size}), "success")
        b = f.block("maybe_time")
        enough = b.op("compare.ge", [b.values["len"], b.c(4, "usize")], "bool")
        b.branch(enough, "read_time", f.args(b), "failure")
        b = f.block("read_time")
        timestamp = b.word(b.values["wire"], b.values["off"], 4, "big")
        b.state_write(1, timestamp)
        off = b.op("int.add.wrap", [b.values["off"], b.c(4, "usize")], "usize")
        size = b.op("int.sub.wrap", [b.values["len"], b.c(4, "usize")], "usize")
        b.state_write(2, b.cast(off)); b.state_write(3, b.cast(size))
        b.jump("success")
    return f.document()


def packet_write(epoch=False):
    params = [("wire", "mutbuf"), ("state", "mutbuf"), ("now", "i64")]
    params += [("epoch", "u16")] if epoch else [("long_form", "u32"), ("prepend", "u32")]
    f = Function("ovpn_hia_packet_id_write" + ("_epoch" if epoch else ""), params)
    b = f.block("start")
    zero = b.op("compare.eq", [b.values["time"], b.c(0)], "bool")
    now_bits = b.cast(b.values["now"])
    timestamp = b.op("select", [zero, now_bits, b.values["time"]], "u64")
    b.state_write(1, timestamp)
    atmax = b.op("compare.eq", [b.values["id"], b.c((1 << (48 if epoch else 32)) - 1)], "bool")
    if epoch:
        b.branch(atmax, "failure", [], "update", f.args(b, {"time": timestamp}))
    else:
        long = b.op("compare.ne", [b.values["long_form"], b.c(0, "u32")], "bool")
        newer = b.op("compare.gt", [b.values["now"], b.cast(timestamp, "i64")], "bool")
        allowed = b.op("bool.and", [long, newer], "bool")
        nowrap = b.op("bool.not", [atmax], "bool")
        good = b.op("bool.or", [nowrap, allowed], "bool")
        before_id = b.op("select", [atmax, b.c(0), b.values["id"]], "u64")
        timestamp = b.op("select", [atmax, now_bits, timestamp], "u64")
        b.branch(good, "update", f.args(b, {"id": before_id, "time": timestamp}), "failure")
    b = f.block("update")
    pid = b.op("int.add.wrap", [b.values["id"], b.c(1)], "u64")
    b.state_write(0, pid); b.state_write(1, b.values["time"])
    if epoch:
        b.jump("append_check", f.args(b, {"id": pid}))
    else:
        prepend = b.op("compare.ne", [b.values["prepend"], b.c(0, "u32")], "bool")
        b.branch(prepend, "prepend_select", f.args(b, {"id": pid}), "append_check", f.args(b, {"id": pid}))
    b = f.block("append_check")
    end = b.op("int.add.wrap", [b.values["off"], b.values["len"]], "usize")
    free = b.op("int.sub.wrap", [b.values["cap"], end], "usize")
    enough = b.op("compare.ge", [free, b.c(8 if epoch else 4, "usize")], "bool")
    b.branch(enough, "append_id", f.args(b), "failure")
    b = f.block("append_id")
    end = b.op("int.add.wrap", [b.values["off"], b.values["len"]], "usize")
    value = b.values["id"]
    if epoch:
        high = b.op("int.shl.checked", [b.cast(b.values["epoch"]), b.c(48)], "u64")
        value = b.op("bit.or", [high, value], "u64")
    b.put(b.values["wire"], end, value, 8 if epoch else 4, "big")
    size = b.op("int.add.wrap", [b.values["len"], b.c(8 if epoch else 4, "usize")], "usize")
    b.state_write(3, b.cast(size))
    if epoch:
        b.jump("success")
        return f.document()
    long = b.op("compare.ne", [b.values["long_form"], b.c(0, "u32")], "bool")
    b.branch(long, "append_time_check", f.args(b, {"len": size}), "success")
    b = f.block("append_time_check")
    end = b.op("int.add.wrap", [b.values["off"], b.values["len"]], "usize")
    free = b.op("int.sub.wrap", [b.values["cap"], end], "usize")
    enough = b.op("compare.ge", [free, b.c(4, "usize")], "bool")
    b.branch(enough, "append_time", f.args(b), "failure")
    b = f.block("append_time")
    end = b.op("int.add.wrap", [b.values["off"], b.values["len"]], "usize")
    b.put(b.values["wire"], end, b.values["time"], 4, "big")
    size = b.op("int.add.wrap", [b.values["len"], b.c(4, "usize")], "usize")
    b.state_write(3, b.cast(size)); b.jump("success")
    b = f.block("prepend_select")
    long = b.op("compare.ne", [b.values["long_form"], b.c(0, "u32")], "bool")
    b.branch(long, "prepend_time_check", f.args(b), "prepend_id_check", f.args(b))
    for word in ("time", "id"):
        b = f.block("prepend_" + word + "_check")
        enough = b.op("compare.ge", [b.values["off"], b.c(4, "usize")], "bool")
        b.branch(enough, "prepend_" + word, f.args(b), "failure")
        b = f.block("prepend_" + word)
        off = b.op("int.sub.wrap", [b.values["off"], b.c(4, "usize")], "usize")
        size = b.op("int.add.wrap", [b.values["len"], b.c(4, "usize")], "usize")
        b.put(b.values["wire"], off, b.values[word], 4, "big")
        b.state_write(2, b.cast(off)); b.state_write(3, b.cast(size))
        b.jump("prepend_id_check", f.args(b, {"off": off, "len": size})) if word == "time" else b.jump("success")
    return f.document()


def program():
    return {"schema": "hepta.hia.program.v1", "module": "openvpn_packet_id_278",
            "functions": [packet_read(), packet_write(), packet_read(True), packet_write(True)]}


def write_program(path):
    data = program()
    Path(path).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    return data


if __name__ == "__main__":
    import sys
    write_program(sys.argv[1])

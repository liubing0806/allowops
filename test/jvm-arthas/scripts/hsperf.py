#!/usr/bin/env python3
"""Minimal reader for HotSpot's /tmp/hsperfdata_<user>/<pid> file (test-only; stage 1 owns the real parser)."""
import glob
import struct
import subprocess


def read_hsperf(host_pid, nspid):
    """Reads the file through /proc/<pid>/root as root and returns {counter name: value}."""
    paths = glob.glob(f"/proc/{host_pid}/root/tmp/hsperfdata_*/{nspid}")
    if not paths:
        # the directory may only be listable by root
        out = subprocess.run(["sudo", "sh", "-c", f"ls /proc/{host_pid}/root/tmp/hsperfdata_*/{nspid}"], capture_output=True, text=True).stdout.split()
        paths = out
    if not paths:
        return None
    data = subprocess.run(["sudo", "cat", paths[0]], capture_output=True).stdout
    if len(data) < 32:
        return None
    magic = struct.unpack(">I", data[0:4])[0]
    order = "<" if data[4] == 1 else ">"
    major, minor, accessible = data[5], data[6], data[7]
    used, overflow = struct.unpack(order + "ii", data[8:16])
    entry_offset, num_entries = struct.unpack(order + "ii", data[24:32])
    out = {}
    off = entry_offset
    for _ in range(num_entries):
        if off + 20 > len(data):
            break
        length, name_off, vec_len = struct.unpack(order + "iii", data[off:off + 12])
        dtype, flags, units, var = data[off + 12], data[off + 13], data[off + 14], data[off + 15]
        data_off = struct.unpack(order + "i", data[off + 16:off + 20])[0]
        end = data.index(b"\0", off + name_off)
        name = data[off + name_off:end].decode()
        if vec_len > 0 and chr(dtype) == "B":
            raw = data[off + data_off:off + data_off + vec_len]
            val = raw.split(b"\0", 1)[0].decode(errors="replace")
        elif chr(dtype) == "J":
            val = struct.unpack(order + "q", data[off + data_off:off + data_off + 8])[0]
        else:
            val = None
        out[name] = val
        if length <= 0:
            break
        off += length
    out["_prologue"] = {"magic": hex(magic), "major": major, "minor": minor, "accessible": accessible, "used": used, "overflow": overflow, "entries": num_entries}
    return out

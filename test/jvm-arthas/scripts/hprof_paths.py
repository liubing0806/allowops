#!/usr/bin/env python3
"""Reference paths from the GC roots to objects of a heap dump (docs/arthas-logger-classloader-report.md).

Reads an HPROF file (JAVA PROFILE 1.0.2, as `jcmd <pid> GC.heap_dump` writes it) and searches breadth-first from
the GC roots along strong references. The referent of a java.lang.ref.Reference subclass is not followed
(--follow-soft follows it for SoftReference subclasses). Besides its static fields, a class has the references of its
CLASS DUMP record: <super>, <loader>, <signers> and <protection domain>. For every instance of --target the shortest
path from a GC root is printed; an instance no path reaches is reported as such.

--exclude LABEL does not follow references with that label, OWNER:LABEL only those from objects of class OWNER (for a
class, OWNER is the class itself; an OWNER ending in * matches by prefix). Whether the targets are still reachable
then shows which references keep them. --kept also searches with every reference and counts what only the excluded
references keep (classes, instances by class, capacity of java.nio.DirectByteBuffer). --helpers PREFIX lists the
classes whose name starts with PREFIX, with their loader and the class loader of their protection domain. Every run
prints the direct-buffer counters of java.nio.Bits and of Netty's PlatformDependent (one per class loader).

  hprof_paths.py dump.hprof --target com.taobao.arthas.agent.ArthasClassloader
  hprof_paths.py dump.hprof --target com.taobao.arthas.agent.ArthasClassloader --exclude '<protection domain>' --kept
"""
import argparse
import collections
import json
import mmap
import struct
import sys

# Sub-record tag of a GC root: (number of u4 after the object id, name). JNI global has a second id instead.
ROOTS = {0xFF: (0, "unknown"), 0x01: (0, "JNI global"), 0x02: (2, "JNI local"), 0x03: (2, "Java frame"),
         0x04: (1, "native stack"), 0x05: (0, "sticky class"), 0x06: (1, "thread block"), 0x07: (0, "monitor used"),
         0x08: (2, "thread object")}
# Basic type sizes; 2 (object) is the id size.
SIZES = {4: 1, 5: 2, 6: 4, 7: 8, 8: 1, 9: 2, 10: 4, 11: 8}


class Dump:
    def __init__(self, path):
        f = open(path, "rb")
        self.m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        end = self.m.find(b"\0")
        self.version = self.m[:end].decode()
        self.idsize = struct.unpack(">I", self.m[end + 1:end + 5])[0]
        assert self.idsize in (4, 8), self.idsize
        self.idfmt = ">Q" if self.idsize == 8 else ">I"
        self.strings, self.class_names = {}, {}
        self.classes = {}  # class id -> dict
        self.objects = {}  # object id -> offset of its sub-record (instance and object array)
        self.prims = {}  # primitive array id -> offset of its sub-record
        self.roots = []  # (object id, root kind, thread serial or None)
        self.thread_objs = {}  # thread serial -> thread object id
        self._scan(end + 1 + 4 + 8)
        self._layouts()

    def id_at(self, p):
        return struct.unpack_from(self.idfmt, self.m, p)[0]

    def _scan(self, p):
        m, n, ids = self.m, len(self.m), self.idsize
        while p < n:
            tag, _, length = struct.unpack_from(">BII", m, p)
            body = p + 9
            if tag == 0x01:
                self.strings[self.id_at(body)] = m[body + ids:body + length].decode("utf-8", "replace")
            elif tag == 0x02:
                cid, nid = self.id_at(body + 4), self.id_at(body + 8 + ids)
                self.class_names[cid] = nid
            elif tag in (0x0C, 0x1C):
                self._heap(body, body + length)
            p = body + length

    def _heap(self, p, end):
        m, ids = self.m, self.idsize
        while p < end:
            sub = m[p]
            q = p + 1
            if sub in ROOTS:
                extra, _ = ROOTS[sub]
                oid = self.id_at(q)
                serial = None
                if sub in (0x02, 0x03, 0x04, 0x06):
                    serial = struct.unpack_from(">I", m, q + ids)[0]
                if sub == 0x08:
                    serial = struct.unpack_from(">I", m, q + ids)[0]
                    self.thread_objs[serial] = oid
                self.roots.append((oid, sub, serial))
                q += ids + (ids if sub == 0x01 else 4 * extra)
            elif sub == 0x20:
                cid = self.id_at(q)
                c = {"id": cid, "super": self.id_at(q + 4 + ids), "loader": self.id_at(q + 4 + 2 * ids),
                     "signers": self.id_at(q + 4 + 3 * ids), "pd": self.id_at(q + 4 + 4 * ids)}
                q += 4 + 7 * ids
                c["isize"] = struct.unpack_from(">I", m, q)[0]
                q += 4
                ncp = struct.unpack_from(">H", m, q)[0]
                q += 2
                for _ in range(ncp):
                    t = m[q + 2]
                    q += 3 + (ids if t == 2 else SIZES[t])
                nst = struct.unpack_from(">H", m, q)[0]
                q += 2
                statics = []
                for _ in range(nst):
                    name, t = self.id_at(q), m[q + ids]
                    q += ids + 1
                    if t == 2:
                        statics.append((name, self.id_at(q)))
                        q += ids
                    else:
                        q += SIZES[t]
                c["statics"] = statics
                nf = struct.unpack_from(">H", m, q)[0]
                q += 2
                fields = []
                for _ in range(nf):
                    fields.append((self.id_at(q), m[q + ids]))
                    q += ids + 1
                c["fields"] = fields
                self.classes[cid] = c
            elif sub == 0x21:
                self.objects[self.id_at(q)] = p
                q += 4 + 2 * ids
                q += 4 + struct.unpack_from(">I", m, q)[0]
            elif sub == 0x22:
                self.objects[self.id_at(q)] = p
                count = struct.unpack_from(">I", m, q + ids + 4)[0]
                q += ids + 8 + ids + count * ids
            elif sub == 0x23:
                self.prims[self.id_at(q)] = p
                count = struct.unpack_from(">I", m, q + ids + 4)[0]
                t = m[q + ids + 8]
                q += ids + 9 + count * SIZES[t]
            else:
                raise ValueError(f"unknown heap sub-record 0x{sub:02x} at {p}")
            p = q

    def name(self, cid):
        return self.strings.get(self.class_names.get(cid), f"<class 0x{cid:x}>").replace("/", ".")

    def _layouts(self):
        """Per class: (offset, field name) of its object fields in an instance, own fields first, then the super's."""
        by_name = {self.name(c): c for c in self.classes}
        ref = by_name.get("java.lang.ref.Reference")
        soft = by_name.get("java.lang.ref.SoftReference")
        self.layout, self.prim_layout, self.reference, self.soft = {}, {}, set(), set()
        for cid in self.classes:
            offs, prims, off, k, chain = [], {}, 0, cid, []
            while k:
                chain.append(k)
                c = self.classes[k]
                for fname, t in c["fields"]:
                    if t == 2:
                        offs.append((off, self.strings.get(fname, "?")))
                    else:
                        prims.setdefault(self.strings.get(fname, "?"), (off, t))
                    off += self.idsize if t == 2 else SIZES[t]
                k = c["super"]
            self.layout[cid] = offs
            self.prim_layout[cid] = prims
            if ref in chain:
                self.reference.add(cid)
            if soft in chain:
                self.soft.add(cid)

    def class_of(self, oid):
        if oid in self.classes:
            return None
        p = self.objects.get(oid)
        if p is None:
            return None
        if self.m[p] == 0x22:  # object array: the id of its array class follows the element count
            return self.id_at(p + 1 + self.idsize + 8)
        return self.id_at(p + 1 + self.idsize + 4)

    def describe(self, oid):
        if oid in self.classes:
            return f"class {self.name(oid)} @0x{oid:x}"
        p = self.objects.get(oid)
        if p is None:
            return f"0x{oid:x} (not in dump)"
        return f"{self.name(self.class_of(oid))} @0x{oid:x}"

    def refs(self, oid, follow_soft=False):
        """(label, target id) of the references of one object."""
        if oid in self.classes:
            c = self.classes[oid]
            out = [("<super>", c["super"]), ("<loader>", c["loader"]), ("<signers>", c["signers"]), ("<protection domain>", c["pd"])]
            out += [("static " + self.strings.get(n, "?"), v) for n, v in c["statics"]]
            return [(l, v) for l, v in out if v]
        p = self.objects.get(oid)
        if p is None:
            return []
        m, ids = self.m, self.idsize
        if m[p] == 0x22:
            count = struct.unpack_from(">I", m, p + 1 + ids + 4)[0]
            base = p + 1 + ids + 8 + ids
            out = [("<class>", self.id_at(p + 1 + ids + 8))]
            for i in range(count):
                v = self.id_at(base + i * ids)
                if v:
                    out.append((f"[{i}]", v))
            return out
        cid = self.id_at(p + 1 + ids + 4)
        base = p + 1 + ids + 4 + ids + 4
        weak = cid in self.reference and not (follow_soft and cid in self.soft)
        out = []
        for off, fname in self.layout.get(cid, ()):
            if weak and fname == "referent":
                continue
            v = self.id_at(base + off)
            if v:
                out.append((fname, v))
        out.append(("<class>", cid))
        return out

    def field(self, oid, fname):
        for l, v in self.refs(oid, True):
            if l == fname:
                return v
        return None

    def prim_field(self, oid, fname):
        p = self.objects.get(oid)
        if p is None or self.m[p] != 0x21:
            return None
        cid = self.class_of(oid)
        off, t = self.prim_layout.get(cid, {}).get(fname, (None, None))
        if off is None:
            return None
        fmt = {4: ">?", 5: ">H", 6: ">f", 7: ">d", 8: ">b", 9: ">h", 10: ">i", 11: ">q"}[t]
        return struct.unpack_from(fmt, self.m, p + 1 + self.idsize + 4 + self.idsize + 4 + off)[0]

    def text(self, oid):
        """Text of a java.lang.String (JDK 8: char[] value; JDK 9+: byte[] value and coder) or of a char[]."""
        if not oid:
            return None
        if oid in self.objects:
            coder = self.prim_field(oid, "coder")
            v = self.field(oid, "value")
            return self._prim_text(v, coder) if v else None
        return self._prim_text(oid, None)

    def _prim_text(self, aid, coder):
        p = self.prims.get(aid)
        if p is None:
            return None
        ids = self.idsize
        count = struct.unpack_from(">I", self.m, p + 1 + ids + 4)[0]
        t = self.m[p + 1 + ids + 8]
        data = self.m[p + 1 + ids + 9:p + 1 + ids + 9 + count * SIZES[t]]
        if t == 5:
            return data.decode("utf-16-be", "replace")
        # byte[] of a JDK 9+ String: coder 0 is Latin-1, 1 is UTF-16 in the byte order of the platform (little-endian here)
        return data.decode("utf-16-le", "replace") if coder == 1 else data.decode("latin-1")

    def root_label(self, kind, serial):
        label = ROOTS[kind][1]
        if serial is not None and serial in self.thread_objs:
            name = self.text(self.field(self.thread_objs[serial], "name"))
            label += f" (thread {name!r})"
        return label


def excluded(d, oid, label, rules):
    for owner, lab in rules:
        if lab != label:
            continue
        if owner is None:
            return True
        cname = d.name(oid) if oid in d.classes else d.name(d.class_of(oid) or 0)
        if cname == owner or owner.endswith("*") and cname.startswith(owner[:-1]):
            return True
    return False


def search(d, rules, follow_soft):
    parent = {}
    q = collections.deque()
    for oid, kind, serial in d.roots:
        if oid not in parent:
            parent[oid] = (None, (kind, serial))
            q.append(oid)
    while q:
        oid = q.popleft()
        for label, v in d.refs(oid, follow_soft):
            if v in parent or (v not in d.objects and v not in d.classes):
                continue
            if rules and excluded(d, oid, label, rules):
                continue
            parent[v] = (oid, label)
            q.append(v)
    return parent


def path_to(d, parent, oid):
    steps = []
    while True:
        prev, how = parent[oid]
        if prev is None:
            steps.append({"root": d.root_label(*how), "object": d.describe(oid)})
            break
        steps.append({"object": d.describe(oid), "via": how})
        oid = prev
    return list(reversed(steps))


def direct_counters(d):
    """java.nio.Bits (JDK 8: reservedMemory, totalCapacity, count; JDK 9+: upper case) and Netty's DIRECT_MEMORY_COUNTER."""
    out = []
    for cid, c in d.classes.items():
        name = d.name(cid)
        if name != "java.nio.Bits" and not name.endswith("netty.util.internal.PlatformDependent"):
            continue
        for n, v in c["statics"]:
            field = d.strings.get(n, "?")
            if field.lower().replace("_", "") in ("reservedmemory", "totalcapacity", "count", "directmemorycounter"):
                out.append({"counter": f"{name}.{field}", "loader": d.describe(c["loader"]) if c["loader"] else "bootstrap",
                            "value": d.prim_field(v, "value")})
    return sorted(out, key=lambda c: (c["counter"], c["loader"]))


def kept(d, full, cut):
    """Objects reached with every reference (full) and not reached without the excluded ones (cut)."""
    only = [o for o in full if o not in cut]
    names = collections.Counter()
    ncls = nbuf = cap = 0
    for o in only:
        if o in d.classes:
            ncls += 1
            continue
        cid = d.class_of(o)
        if cid is None:
            continue
        names[d.name(cid)] += 1
        if d.name(cid) == "java.nio.DirectByteBuffer":
            nbuf += 1
            cap += d.prim_field(o, "capacity") or 0
    return {"classes": ncls, "instances": len(only) - ncls, "direct_buffers": nbuf, "direct_capacity": cap,
            "top": names.most_common(12)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hprof")
    ap.add_argument("--target", action="append", default=[], help="class name; every instance is a target")
    ap.add_argument("--exclude", action="append", default=[], help="LABEL or OWNER:LABEL of references not to follow")
    ap.add_argument("--follow-soft", action="store_true", help="follow the referent of SoftReference subclasses")
    ap.add_argument("--kept", action="store_true", help="with --exclude: count what only the excluded references keep")
    ap.add_argument("--helpers", action="append", default=[], help="list classes whose name starts with this prefix")
    ap.add_argument("--json", help="also write the result as JSON to this file")
    a = ap.parse_args()
    d = Dump(a.hprof)
    rules = []
    for e in a.exclude:
        owner, sep, lab = e.rpartition(":") if not e.startswith("<") else ("", "", e)
        rules.append((owner or None, lab))
    res = {"hprof": a.hprof, "version": d.version, "id_size": d.idsize, "classes": len(d.classes), "objects": len(d.objects),
           "roots": len(d.roots), "exclude": a.exclude, "follow_soft": a.follow_soft, "targets": [], "helpers": []}
    print(f"{a.hprof}: {d.version}, id size {d.idsize}, {len(d.classes)} classes, {len(d.objects)} instances and object arrays, "
          f"{len(d.roots)} roots; exclude {a.exclude or 'nothing'}; soft referents {'followed' if a.follow_soft else 'not followed'}")
    for prefix in a.helpers:
        for cid in sorted(d.classes, key=d.name):
            if d.name(cid).startswith(prefix):
                c = d.classes[cid]
                pd_loader = d.field(c["pd"], "classloader") if c["pd"] else None
                h = {"class": d.describe(cid), "loader": d.describe(c["loader"]) if c["loader"] else "bootstrap",
                     "protection_domain": d.describe(c["pd"]) if c["pd"] else None,
                     "protection_domain_classloader": d.describe(pd_loader) if pd_loader else None}
                res["helpers"].append(h)
                print(f"helper {h['class']}\n  loader {h['loader']}\n  protection domain {h['protection_domain']}"
                      f"\n  protection domain classloader {h['protection_domain_classloader']}")
    parent = search(d, rules, a.follow_soft)
    total = len(d.objects) + len(d.classes)
    reached = sum(1 for oid in parent if oid in d.objects or oid in d.classes)
    res["reached"], res["total"] = reached, total
    print(f"reached {reached} of {total} instances, object arrays and classes from the roots")
    res["direct_counters"] = direct_counters(d)
    for c in res["direct_counters"]:
        print(f"{c['counter']} ({c['loader']}): {c['value']}")
    if a.kept and rules:
        res["kept"] = kept(d, search(d, [], a.follow_soft), parent)
        k = res["kept"]
        print(f"kept only through the excluded references: {k['classes']} classes, {k['instances']} instances and object arrays; "
              f"{k['direct_buffers']} DirectByteBuffer, capacity {k['direct_capacity']} bytes")
        for name, n in k["top"]:
            print(f"  {n:7d} {name}")
    for tname in a.target:
        tids = [cid for cid in d.classes if d.name(cid) == tname]
        insts = sorted(oid for oid in d.objects if d.class_of(oid) in tids)
        print(f"\n{tname}: {len(insts)} instances")
        for oid in insts:
            if oid not in parent:
                res["targets"].append({"object": d.describe(oid), "reachable": False})
                print(f"\n{d.describe(oid)}: not reachable")
                continue
            steps = path_to(d, parent, oid)
            res["targets"].append({"object": d.describe(oid), "reachable": True, "path": steps})
            print(f"\n{d.describe(oid)}: path of {len(steps) - 1} references")
            for s in steps:
                print(f"  root: {s['root']}: {s['object']}" if "root" in s else f"    --[{s['via']}]--> {s['object']}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=2)


if __name__ == "__main__":
    sys.exit(main())

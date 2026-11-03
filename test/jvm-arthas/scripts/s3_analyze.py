#!/usr/bin/env python3
"""Tables of the stage-3 acceptance report (docs/arthas-stage3-acceptance-report.md) from the raw data of scripts/run_s3.sh.

Usage: s3_analyze.py <raw dir> [section ...]
Sections: env disturb noise l1 safepoints threads oldgen metaspace interval totals (default: all).
Prints markdown; writes <raw dir>/summary-<section>.json.

Write waits: the seconds covered by a safepoint log write gap of 20 ms or more (pause_logwrite.py) and the seconds of a write of
host_io_probe.py that waited 200 ms or more. They are left out of the latency figures and listed in columns of their own.
Latency is that of the four flows together (hot, ping, work, db) unless a column says hot. Times are milliseconds.
"""
import collections
import json
import pathlib
import re
import statistics
import sys

from accept_analyze import gc_events, java_major
from analyze import CONTROL, GC_OPS, bucket_value_us, load, metrics_window, pct, typical_p99
from l2_threshold import write_waits

FLOWS = ("hot",) + CONTROL
ALL = FLOWS
LINE = re.compile(r"^\[([^\]]+)\]\[([0-9.]+)s\] (.*)$")
SUM17 = re.compile(r'Safepoint "([^"]+)", Time since last: \d+ ns, Reaching safepoint: (\d+) ns, Cleanup: (\d+) ns, At safepoint: (\d+) ns,'
                   r'(?: Leaving safepoint: \d+ ns,)? Total: (\d+) ns')
MIB = 1 << 20
APP_CPUS, LOAD_CPUS, CALL_CPUS = [4, 5, 6, 7], [8, 9], [12, 13, 14, 15]
OWN_COMMS = {"ja-loadgen", "ja-call", "python3", "sudo", "taskset", "docker", "dockerd", "containerd-shim", "containerd"}


def f(x, n=2):
    return "-" if x is None else f"{x:.{n}f}"


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def secs_of(rows, flows):
    out = collections.defaultdict(collections.Counter)
    for r in rows:
        if r["flow"] in flows:
            c = out[int(r["t"])]
            for b, n in r["h"].items():
                c[int(b)] += n
    return out


def pooled(hs):
    tot = collections.Counter()
    for h in hs:
        tot.update(h)
    return {"secs": len(hs), "p99": pct(tot, 0.99) if tot else None, "max": bucket_value_us(max(tot)) / 1000.0 if tot else None,
            "typical_p99": typical_p99(hs) if hs else None}


def hmax(h):
    return bucket_value_us(max(h)) / 1000.0 if h else None


def sp_detail(d, major):
    """Every safepoint: {t, op, total, reach, cleanup, at} in ms (cleanup None where the log does not split it)."""
    out = []
    sp = d / "safepoint.log"
    if major >= 17 and sp.exists():
        for ln in sp.read_text(errors="ignore").splitlines():
            m, s = LINE.match(ln), SUM17.search(ln)
            if m and s:
                from analyze import ts
                out.append({"t": ts(m.group(1)), "op": s.group(1), "total": int(s.group(5)) / 1e6, "reach": int(s.group(2)) / 1e6,
                            "cleanup": int(s.group(3)) / 1e6, "at": int(s.group(4)) / 1e6})
    elif major >= 9 and sp.exists():
        from analyze import ts
        op = None
        for ln in sp.read_text(errors="ignore").splitlines():
            m = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Entering safepoint region: (.+)$", ln)
            if m:
                op = m.group(2).strip()
                continue
            m = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Total time for which application threads were stopped: ([0-9.]+) seconds, Stopping threads took: ([0-9.]+) seconds", ln)
            if m:
                tot, reach = float(m.group(2)) * 1000, float(m.group(3)) * 1000
                out.append({"t": ts(m.group(1)), "op": op or "?", "total": tot, "reach": reach, "cleanup": None, "at": tot - reach})
                op = None
    else:
        import datetime as dt
        p = d / "stdout.log"
        pat = re.compile(r"^(\S+Z) [0-9.]+: (\S+)\s+\[[^\]]*\]\s+\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
        for ln in (p.read_text(errors="ignore").splitlines() if p.exists() else []):
            m = pat.match(ln)
            if m:
                t = dt.datetime.strptime(m.group(1)[:26] + "Z", "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc).timestamp()
                sync, cleanup, vmop = int(m.group(5)), int(m.group(6)), int(m.group(7))
                out.append({"t": t, "op": m.group(2), "total": float(sync + cleanup + vmop), "reach": float(sync), "cleanup": float(cleanup), "at": float(vmop)})
    return out


def call_phase(c, t):
    """Which step of the ja-call record c the time t falls in."""
    s = c["steps"]
    rel = (t - c["start"]) * 1000
    if rel < 0 or t > c["end"] + 1:
        return None
    att = s.get("attach") or [None, None]
    reqs = s.get("requests") or []
    stop = s.get("stop_sent")
    if att[0] is None or rel < att[0]:
        return "checks"
    if rel < (att[1] or att[0]):
        return "attach"
    if reqs and rel < reqs[0]["open"]:
        return "attached, before the first request"
    if stop is None or rel < stop:
        cur = [r for r in reqs if r["open"] <= rel]
        return f"request {cur[-1].get('command') or cur[-1].get('action')}" if cur else "requests"
    if s.get("threads_zero") is None or rel < s["threads_zero"]:
        return "after stop, arthas- threads still alive"
    if t <= c["end"]:
        return "after the arthas- threads exited"
    return "within 1 s after the call"


def pause_events(fs, thr=200.0):
    """[(first second, seconds)] where the p99 of every flow is above thr ms."""
    secs = sorted(set.intersection(*[set(fs[fl]) for fl in FLOWS])) if all(fs[fl] for fl in FLOWS) else []
    hit = [s for s in secs if all(pct(fs[fl][s], .99) > thr for fl in FLOWS)]
    out = []
    for s in hit:
        if out and s == out[-1][0] + out[-1][1]:
            out[-1] = (out[-1][0], out[-1][1] + 1)
        else:
            out.append((s, 1))
    return out


class Run:
    """One accept.py latency run."""

    def __init__(self, d):
        self.d = d
        self.meta = json.loads((d / "meta.json").read_text())
        self.svc, self.scen, self.rep = self.meta["svc"], self.meta["scenario"], self.meta["rep"]
        self.major = java_major(d)
        rows = load(d / "load.jsonl")
        self.errors = sum(r["err"] + r["drop"] for r in rows)
        self.fs = {fl: secs_of(rows, (fl,)) for fl in FLOWS}
        self.all = secs_of(rows, ALL)
        self.hot = self.fs["hot"]
        self.calls = load(d / "calls.jsonl") if (d / "calls.jsonl").exists() and (d / "calls.jsonl").stat().st_size else []
        self.waits = write_waits(d, 20, [])
        self.sps = sp_detail(d, self.major)
        self.gcs = gc_events(d, self.major)
        self.mrows = load(d / "metrics.jsonl")
        self.w = self.meta["windows"]
        self.host = [r for r in load(d / "host_io.jsonl") if r.get("kind") == "write"] if (d / "host_io.jsonl").exists() else []

    def win(self, name):
        return range(*self.w[name])

    def window(self, secs, name, excl=True):
        return [secs[s] for s in self.win(name) if s in secs and not (excl and s in self.waits)]

    def other_cpu(self, name):
        return metrics_window(self.mrows, *self.w[name], self.meta).get("external_cpu_on_app_cpus_pct")

    def call_secs(self, c):
        d0, d1 = self.w["during"]
        return [s for s in range(int(c["start"]), int(c["end"]) + 1) if d0 <= s < d1]

    def owners(self):
        own = {}
        for i, c in enumerate(self.calls):
            for s in self.call_secs(c):
                own.setdefault(s, i)
        return own

    def waits_in(self, name):
        return sorted(s for s in self.waits if s in self.win(name))

    def call_of(self, t):
        return next((c for c in self.calls if c["start"] - 1 <= t <= c["end"] + 1), None)


def runs(root, pred):
    out = []
    for done in sorted((root / "latency").rglob("done")):
        r = Run(done.parent)
        if pred(r.scen):
            out.append(r)
    return sorted(out, key=lambda r: (int(r.svc[3:]), r.scen, r.rep))


# env --------------------------------------------------------------------------------------------------------------------------
def env(root):
    print("## Environment check: where the files are, and one call of each L1 command kind other than logger\n")
    print("| JDK | /tmp | log directory (files) | host /logs | hsperfdata file | attach file (uid, mode) | attach socket | JVM log flags | AsyncLog thread | calls ok / all | clean-up ok | post-check failures |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    out = {}
    for d in sorted((root / "envcheck").iterdir(), key=lambda p: int(p.name[3:])):
        if not (d / "envcheck.json").exists():
            continue
        i = json.loads((d / "envcheck.json").read_text())
        calls = load(d / "calls.jsonl")
        tmp = next((m.split()[2] + " " + m.split()[3].split(",")[-1] for m in i["mounts"] if m.split()[1] == "/tmp"), "?")
        logs = next((m.split()[2] for m in i["mounts"] if m.split()[1] == "/logs-tmpfs"), "?")
        files = [ln.split()[-1] for ln in i["logs_tmpfs_after"][1:]]
        hs = next((ln for ln in i["hsperfdata"] if ln.startswith("tmpfs") or "/hsperfdata_" in ln and " " in ln and not ln.startswith("-")), "?")
        att = {k: v for k, v in i["attach_files_seen"].items()}
        af = next((f"{k} ({v.get('uid')}, {v.get('mode')})" for k, v in att.items() if ".attach_pid" in k), "not seen")
        sock = next((k for k in att if ".java_pid" in k), "not seen")
        flags = [x for x in i["cmdline"].split() if x.startswith(("-Xlog", "-Xloggc", "-XX:+PrintSafepoint", "-XX:+PrintGC"))]
        ok = sum(1 for c in calls if c["status"] == "ok")
        cl = sum(1 for c in calls if c.get("cleanup") == "ok")
        bad = sum(1 for c in calls if c["post"]["listening"] or c["post"]["arthas_threads"] or not c["post"]["procs_same"])
        failed = [f"{c['command']}: {c.get('reason')}" for c in calls if c["status"] != "ok"]
        print(f"| {d.name} | {tmp} | {logs} ({', '.join(files)}) | {len(i['logs_host'])} files | {hs} | {af} | {sock} | {' '.join(flags)} | "
              f"{'yes' if any('AsyncLog' in t for t in i['threads']) else 'no'} | {ok} / {len(calls)} | {cl} / {len(calls)} | {bad} |")
        for x in failed:
            print(f"|  | failed: {x} | | | | | | | | | | |")
        out[d.name] = {"info": i, "calls": [(c["command"], c["status"], c.get("reason")) for c in calls]}
    return out


# disturb ----------------------------------------------------------------------------------------------------------------------
def disturb_of(r):
    """CPU used on the measuring cpus by others during the run, and the host probe's slowest writes."""
    o = load(r.d / "others.jsonl") if (r.d / "others.jsonl").exists() else []
    t0, t1 = r.w["before"][0], r.w["after"][1]
    o = [x for x in o if t0 <= x["t"] <= t1 + 10]
    busy = lambda x, cpus: sum(x["cpu_busy_pct"].get(f"cpu{c}", 0) for c in cpus)
    ext = collections.defaultdict(list)
    for x in o:
        for p in x["top"]:
            own = p["comm"] in OWN_COMMS or (p["comm"] == "java" and p["last_cpu"] in APP_CPUS)
            if not own and p["last_cpu"] in APP_CPUS + LOAD_CPUS + CALL_CPUS:
                ext[(p["comm"], p["pid"])].append(p["cpu_pct"])
    top = sorted(((k, max(v)) for k, v in ext.items()), key=lambda kv: -kv[1])[:3]
    hw = [h for h in r.host if t0 <= h["t"] <= t1]
    # other CPU on the app cpus per metrics interval (about 1 s), its largest 10 s mean in the before and during windows
    m = [x for x in r.mrows if "host_cpu" in x and "cg_cpu_usec" in x and r.w["before"][0] <= x["t"] <= r.w["during"][1]]
    ext_s = []
    for a, b in zip(m, m[1:]):
        dt_s = b["t"] - a["t"]
        busy_s = sum(b["host_cpu"].get(f"cpu{c}", 0) - a["host_cpu"].get(f"cpu{c}", 0) for c in APP_CPUS) / 100.0 / dt_s * 100
        ext_s.append(max(0.0, busy_s - (b["cg_cpu_usec"] - a["cg_cpu_usec"]) / 1e6 / dt_s * 100))
    ext10 = max((sum(ext_s[i:i + 10]) / 10 for i in range(max(1, len(ext_s) - 9))), default=None) if ext_s else None
    load_bd = max((busy(x, LOAD_CPUS) for x in o if x["t"] <= r.w["during"][1] + 10), default=0)
    return {"other_cpu": {w: r.other_cpu(w) for w in ("before", "during", "after")}, "other_cpu_10s_max": ext10,
            "disturbed": (ext10 or 0) > 150 or load_bd > 100 or any((r.other_cpu(w) or 0) > 50 for w in ("before", "during")),
            "load_cpus_busy_max": max((busy(x, LOAD_CPUS) for x in o), default=None),
            "call_cpus_busy_max": max((busy(x, CALL_CPUS) for x in o), default=None),
            "ext_top": [f"{c}({pid}) {v:.0f}%" for (c, pid), v in top],
            "host_writes_50ms": len(hw), "host_write_max_s": max((h["seconds"] for h in hw), default=None),
            "waits": {w: len(r.waits_in(w)) for w in ("before", "during", "after")}}


def disturb(root):
    print("## Other load during each latency run\n")
    print("Other CPU on the app cpus 4-7 = busy time of cpus 4-7 minus the container's CPU (100 = one cpu); the busiest other processes"
          " seen on cpus 4-9 and 12-15 (10 s samples, max); host probe writes of 50 ms or more; write-wait seconds per window.\n")
    print("Disturbed: in the before or during window, the other CPU on cpus 4-7 averaged over 50% over the window or over 150% for 10 s,"
          " or cpus 8-9 (the load generator's) were busier than 100% in a 10 s sample.\n")
    print("| run | other CPU % on 4-7, before / during / after | largest 10 s mean, before and during | cpus 8-9 busy max % | cpus 12-15 busy max % | other processes (max % in a 10 s sample) | host probe writes ≥ 50 ms, slowest (s) | write-wait seconds, before / during / after | disturbed |")
    print("|---|---|---|---|---|---|---|---|---|")
    out = {}
    for r in runs(root, lambda s: True):
        x = disturb_of(r)
        oc = x["other_cpu"]
        print(f"| {r.svc} {r.scen} {r.rep} | {oc['before']} / {oc['during']} / {oc['after']} | {f(x['other_cpu_10s_max'], 0)} | {f(x['load_cpus_busy_max'], 0)} | {f(x['call_cpus_busy_max'], 0)} | "
              f"{', '.join(x['ext_top']) or '-'} | {x['host_writes_50ms']}, {f(x['host_write_max_s'], 3)} | {x['waits']['before']} / {x['waits']['during']} / {x['waits']['after']} | {'yes' if x['disturbed'] else 'no'} |")
        out[f"{r.svc}/{r.scen}/{r.rep}"] = x
    return out


# noise ------------------------------------------------------------------------------------------------------------------------
def noise(root):
    res = runs(root, lambda s: s == "noop")
    print("## Noise calibration: the latency windows without a call (scenario noop)\n")
    print("| JDK | rep | before p99 / typical p99 | during p99 / typical p99, typical vs before | after typical vs before | max latency before / during / after | "
          "pause events (all four flows p99 > 200 ms), seconds | safepoints > 20 ms (op ms) | GC pauses > 20 ms | write-wait seconds | other CPU % b/d/a | disturbed |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    out = []
    for r in res:
        b, du, af = (pooled(r.window(r.all, w)) for w in ("before", "during", "after"))
        mx = [pooled(r.window(r.all, w, excl=False))["max"] for w in ("before", "during", "after")]
        ev = pause_events(r.fs)
        t0, t1 = r.w["before"][0], r.w["after"][1]
        sp = [s for s in r.sps if t0 <= s["t"] < t1 and s["total"] > 20]
        gc = [g for g in r.gcs if t0 <= g[0] < t1 and g[2] > 20]
        dv = lambda x: f"{(x / b['typical_p99'] - 1) * 100:+.1f}%" if x and b["typical_p99"] else "-"
        nw = sum(len(r.waits_in(w)) for w in ("before", "during", "after"))
        oc = [r.other_cpu(w) for w in ("before", "during", "after")]
        dist = disturb_of(r)["disturbed"]
        print(f"| {r.svc} | {r.rep} | {f(b['p99'])} / {f(b['typical_p99'])} | {f(du['p99'])} / {f(du['typical_p99'])}, {dv(du['typical_p99'])} | {dv(af['typical_p99'])} | "
              f"{' / '.join(f(x, 1) for x in mx)} | {[(s - t0, n) for s, n in ev] or 0} | {[(s['op'], round(s['total'], 1)) for s in sp] or 0} | "
              f"{[(k, round(ms, 1)) for _, k, ms in gc] or 0} | {nw} | {'/'.join(str(x) for x in oc)} | {'yes' if dist else 'no'} |")
        out.append({"svc": r.svc, "rep": r.rep, "disturbed": dist, "before": b, "during": du, "after": af, "max": mx, "pauses": ev, "sp": sp, "gc": gc, "waits": nw, "other_cpu": oc})
    print("\n### Baseline per JDK (runs not disturbed: median over the reps of the noop before windows; the during windows in brackets)\n")
    print("| JDK | reps | p99 | typical p99 | max latency, largest of the reps | pause events |\n|---|---|---|---|---|---|")
    by = collections.defaultdict(list)
    for x in out:
        if not x["disturbed"]:
            by[x["svc"]].append(x)
    for svc, xs in sorted(by.items(), key=lambda kv: int(kv[0][3:])):
        print(f"| {svc} | {len(xs)} | {f(med(x['before']['p99'] for x in xs))} ({f(med(x['during']['p99'] for x in xs))}) | "
              f"{f(med(x['before']['typical_p99'] for x in xs))} ({f(med(x['during']['typical_p99'] for x in xs))}) | "
              f"{f(max(max(m for m in x['max'] if m is not None) for x in xs), 1)} | {sum(len(x['pauses']) for x in xs)} |")
    return out


# l1 ---------------------------------------------------------------------------------------------------------------------------
def l1_run(r):
    own = r.owners()
    groups = collections.defaultdict(list)
    excl = collections.defaultdict(list)
    d0, d1 = r.w["during"]
    for s in range(d0, d1):
        if s not in r.all:
            continue
        g = ("tb" if r.calls[own[s]]["command"] == "thread_blocking" else "other") if s in own else "idle"
        (excl if s in r.waits else groups)[g].append(r.all[s])
    b = pooled(r.window(r.all, "before"))
    out = {"svc": r.svc, "rep": r.rep, "disturbed": disturb_of(r)["disturbed"], "before": b, "after": pooled(r.window(r.all, "after")), "errors": r.errors,
           "other_cpu": [r.other_cpu(w) for w in ("before", "during", "after")], "hot_before": pooled(r.window(r.hot, "before"))}
    for g in ("other", "tb", "idle"):
        out[g] = pooled(groups[g])
        out[g + "_excl"] = {"secs": len(excl[g]), "max": max((hmax(h) for h in excl[g]), default=None)}
        out["hot_" + g] = pooled([r.hot[s] for s in range(d0, d1) if s in r.hot and s not in r.waits and
                                   (("tb" if r.calls[own[s]]["command"] == "thread_blocking" else "other") if s in own else "idle") == g])
    out["calls"] = []
    for i, c in enumerate(r.calls):
        hs = [r.all[s] for s in r.call_secs(c) if own.get(s) == i and s in r.all and s not in r.waits]
        sp = [x for x in r.sps if c["start"] <= x["t"] <= c["end"] + 0.5]
        out["calls"].append({"command": c["command"], "status": c["status"], "ms": c["ms"], "lat": pooled(hs),
                             "waits": sum(1 for s in r.call_secs(c) if own.get(s) == i and s in r.waits),
                             "threaddump": max((x["total"] for x in sp if x["op"] == "ThreadDump"), default=None),
                             "post_bad": bool(c["post"]["listening"] or c["post"]["arthas_threads"] or not c["post"]["procs_same"]),
                             "cleanup": c.get("cleanup")})
    return out


def l1(root):
    res = [l1_run(r) for r in runs(root, lambda s: s == "l1all")]
    print("## Item 1: latency of the L1 calls (scenario l1all), write-wait seconds left out\n")
    print("| JDK | rep | before p99 / typical | call secs (but thread -b): secs, p99, ratio, max | thread -b call secs: secs, p99, max | idle typical, vs before | after typical, vs before | "
          "write-wait secs left out: calls, thread -b, idle (max ms in them) | hot only: call secs p99 ratio, max | other CPU % b/d/a | errors | disturbed |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for x in res:
        b = x["before"]
        dv = lambda v: f"{(v / b['typical_p99'] - 1) * 100:+.1f}%" if v and b["typical_p99"] else "-"
        o, tb, idle = x["other"], x["tb"], x["idle"]
        ex = "; ".join(f"{x[g + '_excl']['secs']}" + (f" ({f(x[g + '_excl']['max'], 1)})" if x[g + "_excl"]["secs"] else "") for g in ("other", "tb", "idle"))
        ho, hb = x["hot_other"], x["hot_before"]
        print(f"| {x['svc']} | {x['rep']} | {f(b['p99'])} / {f(b['typical_p99'])} | {o['secs']}, {f(o['p99'])}, {f(o['p99'] / b['p99'] if o['p99'] and b['p99'] else None)}x, {f(o['max'], 1)} | "
              f"{tb['secs']}, {f(tb['p99'])}, {f(tb['max'], 1)} | {f(idle['typical_p99'])}, {dv(idle['typical_p99'])} | {f(x['after']['typical_p99'])}, {dv(x['after']['typical_p99'])} | {ex} | "
              f"{f(ho['p99'] / hb['p99'] if ho['p99'] and hb['p99'] else None)}x, {f(ho['max'], 1)} | {'/'.join(str(v) for v in x['other_cpu'])} | {x['errors']} | {'yes' if x['disturbed'] else 'no'} |")
    print("\n### Per command over all l1all runs (each call's own call seconds, write-wait seconds left out)\n")
    print("| command | calls | statuses | p99 max (ms), ratio to the run's before p99 | max latency (ms) | calls over 50 ms (JDK rep) | duration median / max (ms) | ThreadDump safepoint (ms) | write-wait secs left out |")
    print("|---|---|---|---|---|---|---|---|---|")
    per = collections.defaultdict(list)
    for x in res:
        for c in x["calls"]:
            per[c["command"]].append((x, c))
    for cmd, items in per.items():
        p99 = [(c["lat"]["p99"], c["lat"]["p99"] / x["before"]["p99"]) for x, c in items if c["lat"]["p99"] and x["before"]["p99"]]
        mx = [c["lat"]["max"] for _, c in items if c["lat"]["max"] is not None]
        lim = 100 if cmd == "thread_blocking" else 50
        over = [f"{x['svc']} {x['rep']}: {c['lat']['max']:.1f}" for x, c in items if (c["lat"]["max"] or 0) > lim]
        ms = sorted(c["ms"] for _, c in items)
        td = [c["threaddump"] for _, c in items if c["threaddump"] is not None]
        print(f"| {cmd} | {len(items)} | {dict(collections.Counter(c['status'] for _, c in items))} | {f(max(p for p, _ in p99))}, {f(max(q for _, q in p99))}x | {f(max(mx), 1)} | "
              f"{', '.join(over) or 0} | {ms[len(ms) // 2]:.0f} / {ms[-1]:.0f} | {(f(min(td), 1) + '~' + f(max(td), 1)) if td else '-'} | {sum(c['waits'] for _, c in items)} |")
    for label, sel in (("all runs", res), ("runs not disturbed", [x for x in res if not x["disturbed"]])):
        print(f"\n### Against the thresholds (plan section 1), {label}\n")
        l1_verdict(sel)
    return res


def l1_verdict(res):
    if not res:
        print("- none")
        return
    ratios = [x["other"]["p99"] / x["before"]["p99"] for x in res if x["other"]["p99"] and x["before"]["p99"]]
    maxes = [c["lat"]["max"] for x in res for c in x["calls"] if c["command"] != "thread_blocking" and c["lat"]["max"] is not None]
    tbm = [c["lat"]["max"] for x in res for c in x["calls"] if c["command"] == "thread_blocking" and c["lat"]["max"] is not None]
    idle = [(x["idle"]["typical_p99"] / x["before"]["typical_p99"] - 1) * 100 for x in res if x["idle"]["typical_p99"] and x["before"]["typical_p99"]]
    print(f"- runs {len(res)}, calls {sum(len(x['calls']) for x in res)}, statuses {dict(collections.Counter(c['status'] for x in res for c in x['calls']))}")
    if ratios:
        print(f"- call secs (but thread -b) p99 / before p99: {min(ratios):.2f}~{max(ratios):.2f}x (threshold 4x)")
        print(f"- max latency per call (but thread -b): {sum(1 for m in maxes if m <= 50)} of {len(maxes)} ≤ 50 ms, largest {max(maxes):.1f} ms")
        print(f"- thread -b max latency: {min(tbm):.1f}~{max(tbm):.1f} ms (threshold 100 ms)")
        print(f"- idle typical p99 vs before: {min(idle):+.1f}%~{max(idle):+.1f}% (threshold ±5%)")


# safepoints -------------------------------------------------------------------------------------------------------------------
def safepoints(root):
    print("## Safepoints over 20 ms other than ThreadDump, every latency run, with their phases and the step of the call they fall in\n")
    print("| run | operation | total ms | reaching / cleanup / at safepoint (ms) | window | step of the call (command) | write wait in that second |")
    print("|---|---|---|---|---|---|---|")
    out = []
    for r in runs(root, lambda s: True):
        for s in r.sps:
            if s["total"] <= 20 or s["op"] == "ThreadDump":
                continue
            w = next((k for k, (a, b) in r.w.items() if a <= s["t"] < b), "warm-up or between windows")
            c = r.call_of(s["t"])
            step = f"{call_phase(c, s['t'])} ({c['command']})" if c else "-"
            print(f"| {r.svc} {r.scen} {r.rep} | {s['op']} | {s['total']:.1f} | {f(s['reach'], 1)} / {f(s['cleanup'], 1)} / {f(s['at'], 1)} | {w} | {step} | {r.waits.get(int(s['t']), '-')} |")
            out.append({"run": f"{r.svc}/{r.scen}/{r.rep}", **s, "window": w, "step": step})
    print("\n### Cleanup phases over 20 ms (any operation; JDK 17 and 21 log the phase), and the call steps they fall in\n")
    print("| run | operation | cleanup ms | total ms | window | step of the call |\n|---|---|---|---|---|---|")
    for r in runs(root, lambda s: True):
        for s in r.sps:
            if (s["cleanup"] or 0) > 20 and r.major >= 17:
                w = next((k for k, (a, b) in r.w.items() if a <= s["t"] < b), "warm-up or between windows")
                c = r.call_of(s["t"])
                print(f"| {r.svc} {r.scen} {r.rep} | {s['op']} | {s['cleanup']:.1f} | {s['total']:.1f} | {w} | {(call_phase(c, s['t']) + ' (' + c['command'] + ')') if c else '-'} |")
    return out


# threads ----------------------------------------------------------------------------------------------------------------------
def threads(root):
    res = runs(root, lambda s: s.startswith("tbdeep"))
    print("## Item 7: thread -b with about 1000 live threads, 40 frames deep, 300 of them holding monitors, 50 blocked\n")
    print("| JDK | scenario | rep | threads live at the calls (hsperfdata) | statuses | ThreadDump ms per call (reaching) | thread -b call secs: p99 / max (ms) | hot max | before p99 / max | "
          "write-wait secs in the call secs | duration ms | other CPU % during | disturbed |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    out = []
    for r in res:
        own = r.owners()
        cs = [s for s in own if s in r.all]
        hs = [r.all[s] for s in cs if s not in r.waits]
        lat, b = pooled(hs), pooled(r.window(r.all, "before"))
        hot = pooled([r.hot[s] for s in cs if s in r.hot and s not in r.waits])
        tds = []
        for c in r.calls:
            sp = [x for x in r.sps if c["start"] <= x["t"] <= c["end"] + 0.5 and x["op"] == "ThreadDump"]
            tds.append(f"{max(x['total'] for x in sp):.1f} ({max(x['reach'] for x in sp):.1f})" if sp else "-")
        live = sorted(set(c["perf_before"]["threads_live"] for c in r.calls))
        print(f"| {r.svc} | {r.scen} | {r.rep} | {live} | {dict(collections.Counter(c['status'] for c in r.calls))} | {', '.join(tds)} | {f(lat['p99'])} / {f(lat['max'], 1)} | {f(hot['max'], 1)} | "
              f"{f(b['p99'])} / {f(b['max'], 1)} | {sum(1 for s in cs if s in r.waits)} | {[round(c['ms']) for c in r.calls]} | {r.other_cpu('during')} | {'yes' if disturb_of(r)['disturbed'] else 'no'} |")
        out.append({"svc": r.svc, "scen": r.scen, "rep": r.rep, "live": live, "tds": tds, "lat": lat, "before": b})
    return out


# oldgen -----------------------------------------------------------------------------------------------------------------------
def oldgen(root):
    print("## Item 8: the old generation checks under the p1k load, per collector\n")
    print("Phases: low = calls right after the warm-up; recent = one call 10 s after a Full GC (heap retained up to 80% of the old"
          " generation); near = calls 62 s or more after it, at that occupancy. Reference for the near calls: the 20 s before them.\n")
    print("| case | rep | phase | old % at the checks | statuses (check: reason) | collections during the calls (collector: n) | max latency in the call secs / in the reference (ms) | p99 call secs / reference | write-wait secs |")
    print("|---|---|---|---|---|---|---|---|---|")
    out = []
    for d in sorted((root / "oldgen").glob("*/rep*")):
        if not (d / "done").exists():
            continue
        meta = json.loads((d / "meta.json").read_text())
        ph = meta["phases"]
        rows = load(d / "load.jsonl")
        allf = secs_of(rows, ALL)
        waits = write_waits(d, 20, [])
        calls = load(d / "calls.jsonl")
        refs = {"low": (ph["low_start"] - 20, ph["low_start"]), "recent": (ph["recent_start"] - 8, ph["recent_start"]), "near": (ph["near_ref_start"], ph["near_start"])}
        for phase in ("low", "recent", "near"):
            cs = [c for c in calls if c.get("label", "").endswith("-" + phase)]
            if not cs:
                continue
            secs = sorted({s for c in cs for s in range(int(c["start"]), int(c["end"]) + 1)})
            lat = pooled([allf[s] for s in secs if s in allf and s not in waits])
            ref = pooled([allf[s] for s in range(int(refs[phase][0]), int(refs[phase][1])) if s in allf and s not in waits])
            pcts = []
            for c in cs:
                p = c["perf_before"]
                pcts.append(f(100.0 * p["old_used"] / p["old_max_capacity"], 1) if p.get("old_max_capacity") else "no old counter")
            st = collections.Counter(f"{c['status']}" + (f" ({c.get('check')}: {(c.get('reason') or '')[:70]})" if c["status"] != "ok" else "") for c in cs)
            gcd = collections.Counter()
            for c in cs:
                a, b = c["perf_before"].get("collectors") or {}, c["perf_after"].get("collectors") or {}
                for k in b:
                    n = b[k]["count"] - a.get(k, {}).get("count", 0)
                    if n:
                        gcd[k] += n
            print(f"| {meta['case']} | {meta['rep']} | {phase} | {', '.join(pcts)} | {'; '.join(f'{k} ×{v}' for k, v in st.items())} | {dict(gcd) or 0} | "
                  f"{f(lat['max'], 1)} / {f(ref['max'], 1)} | {f(lat['p99'])} / {f(ref['p99'])} | {sum(1 for s in secs if s in waits)} |")
            out.append({"case": meta["case"], "rep": meta["rep"], "phase": phase, "pcts": pcts, "statuses": dict(st), "gc": dict(gcd), "lat": lat, "ref": ref})
        fulls = [(round(t - ph["retain_end"], 1), k, round(ms, 1)) for t, k, ms in gc_events(d, java_major(d)) if k == "full"]
        print(f"|  |  | Full GCs (s after the retained Full GC, kind, ms): {fulls or 0}; old % after it {f(ph.get('after_full_gc_old_pct'), 1)}, at the end {f(ph.get('end_old_pct'), 1)} | | | | | | |")
    return out


# metaspace --------------------------------------------------------------------------------------------------------------------
def max_meta(cmdline):
    m = re.findall(r"-XX:MaxMetaspaceSize=(\d+)([mMgG])", cmdline)
    if not m:
        return None
    n, u = m[-1]
    return int(n) * (1024 if u in "gG" else 1) * MIB


def metaspace(root):
    print("## Item 6: the metaspace check with a kept state directory (5 calls, 61 s apart, no load)\n")
    print("Room counted by the check = MaxMetaspaceSize − metaspace used in hsperfdata − attaches since the last GC × 20 MiB; it refuses below 64 MiB."
          " Real room = MaxMetaspaceSize − metaspace used (MXBean) before the call.\n")
    print("| case | call | status (reason) | attach | hsperfdata used / MXBean used before (MiB) | room counted / real room (MiB) | MXBean used after (MiB) | GCs during the call | verdict |")
    print("|---|---|---|---|---|---|---|---|---|")
    out = []
    for d in sorted((root / "metaspace").iterdir()):
        if not (d / "done").exists():
            continue
        meta = json.loads((d / "meta.json").read_text())
        limit = max_meta(meta["cmdline"])
        steps = json.loads((d / "steps.json").read_text())
        end = steps[-1]
        calls = load(d / "calls.jsonl")
        # the product's counter (state.go): the GC count seen before the last attach, and the attaches that saw it
        state_gc, since = None, 0
        for c in calls:
            p, q = c["perf_before"], c["perf_after"]
            gcn = sum(v["count"] for v in (p.get("collectors") or {}).values())
            gca = sum(v["count"] for v in (q.get("collectors") or {}).values())
            unseen = since if gcn == state_gc else 0
            hs, mx = p["metaspace_used"], c["diag_before"]["metaspaceUsed"]
            counted = (limit - hs - unseen * 20 * MIB) / MIB if limit else None
            real = (limit - mx) / MIB if limit else None
            after = c["diag_after"]["metaspaceUsed"]
            if real is None:
                verdict = "no MaxMetaspaceSize"
            elif c["status"] == "refused":
                verdict = "refused, real room < 64 MiB" if real < 64 else "refused early: real room ≥ 64 MiB"
            else:
                verdict = ("ran, real room ≥ 64 MiB" if real >= 64 else "ran although the real room was < 64 MiB") + f"; real room after {(limit - after) / MIB:.0f} MiB"
            reason = (c.get("check") or "") + (": " + c["reason"] if c.get("reason") else "")
            print(f"| {d.name} | {c['seq'] + 1} | {c['status']} {('(' + reason[:110] + ')') if c['status'] != 'ok' else ''} | {c.get('attach', '')} | {hs / MIB:.1f} / {mx / MIB:.1f} | "
                  f"{f(counted, 1)} / {f(real, 1)} | {after / MIB:.1f} | {gca - gcn} | {verdict} |")
            out.append({"case": d.name, "seq": c["seq"], "status": c["status"], "reason": reason, "hs": hs, "mx": mx, "after": after, "counted": counted, "real": real})
            if (c.get("steps") or {}).get("attach"):
                since = (since if gcn == state_gc else 0) + 1
                state_gc = gcn
        print(f"|  | end | JVM answers /ping: {end.get('ping') is not None}; OutOfMemoryError in stdout: {end.get('oome_in_stdout')}; counter file: {steps[1].get('counter', '').strip()[:80]} | | | | | | |")
    return out


# interval ---------------------------------------------------------------------------------------------------------------------
def interval(root):
    print("## Item 9: the attach interval check (60 s) with a kept state directory, p1k load\n")
    print("| case | call | seconds since the previous call ended | command | status (check: reason) | attach |\n|---|---|---|---|---|---|")
    out = []
    for d in sorted((root / "interval").iterdir()):
        if not (d / "done").exists():
            continue
        prev = None
        for c in load(d / "calls.jsonl"):
            since = c["start"] - prev if prev else None
            reason = f" ({c.get('check')}: {c.get('reason')})" if c["status"] != "ok" else ""
            print(f"| {d.name} | {c['seq'] + 1 if 'seq' in c else '-'} | {f(since, 1)} | {c['command']} | {c['status']}{reason} | {c.get('attach', '')} |")
            out.append({"case": d.name, "since": since, "status": c["status"], "check": c.get("check"), "reason": c.get("reason")})
            prev = c["end"]
    return out


# totals -----------------------------------------------------------------------------------------------------------------------
def totals(root):
    print("## All calls of every experiment\n")
    print("| experiment | calls | statuses | duration median / max (ms) | stop→port closed max (ms) | stop→no arthas- thread median / max (ms) | clean-ups not ok | post-check failures | new processes |")
    print("|---|---|---|---|---|---|---|---|---|")
    by = collections.defaultdict(list)
    for p in sorted(root.rglob("calls.jsonl")):
        if p.stat().st_size:
            by[p.relative_to(root).parts[0]].extend(load(p))
    out = {}
    for exp, cs in sorted(by.items()) + [("all", [c for cs in by.values() for c in cs])]:
        ok = [c for c in cs if c["status"] == "ok"]
        ms = sorted(c["ms"] for c in ok)
        pc = sorted(c["steps"]["stop_to_port_closed"] for c in ok if c["steps"].get("stop_to_port_closed") is not None)
        tz = sorted(c["steps"]["stop_to_threads_zero"] for c in ok if c["steps"].get("stop_to_threads_zero") is not None)
        notok = sum(1 for c in ok if c.get("cleanup") != "ok")
        bad = sum(1 for c in cs if c["post"]["listening"] or c["post"]["arthas_threads"] or not c["post"]["procs_same"])
        newp = sum(len(c["procs"]["new"] or []) for c in cs if c.get("procs"))
        mm = lambda xs: f"{xs[len(xs) // 2]:.0f} / {xs[-1]:.0f}" if xs else "-"
        print(f"| {exp} | {len(cs)} | {dict(collections.Counter(c['status'] for c in cs))} | {mm(ms)} | {f(pc[-1] if pc else None, 0)} | {mm(tz)} | {notok} | {bad} | {newp} |")
        out[exp] = {"calls": len(cs), "ok": len(ok), "ms_max": ms[-1] if ms else None, "post_bad": bad, "new_procs": newp}
    return out


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1])
    for sec in sys.argv[2:] or ["env", "disturb", "noise", "l1", "safepoints", "threads", "oldgen", "metaspace", "interval", "totals"]:
        try:
            r = globals()[sec](root)
            if r is not None:
                (root / f"summary-{sec}.json").write_text(json.dumps(r, indent=1, default=str))
        except FileNotFoundError as e:
            print(f"{sec}: no data ({e})\n")
        print()

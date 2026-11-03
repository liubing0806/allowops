#!/usr/bin/env python3
"""Tables of the stage-2 acceptance report from the raw data of accept.py.

Usage: accept_analyze.py <raw dir> [section ...]      sections: latency noise pauses threads oldgen cycles leak limits metaspace totals,
       and cycles-<x>, leak-<x> for the runs of accept.py cycles/leak --name cycles-<x>/leak-<x>
Prints markdown; writes <raw dir>/summary-<section>.json. Uses the per-second histograms and log parsers of analyze.py.
"""
import collections
import datetime as dt
import json
import pathlib
import re
import statistics
import sys

from analyze import CONTROL, bucket_value_us, load, pct, per_second, safepoints, typical_p99

FLOWS = {"hot": ("hot",), "all": ("hot",) + CONTROL}


def f(x, n=2):
    return "-" if x is None else f"{x:.{n}f}"


def pooled(hs):
    tot = collections.Counter()
    for h in hs:
        tot.update(h)
    return {"secs": len(hs), "n": sum(tot.values()), "p99": pct(tot, 0.99), "max": bucket_value_us(max(tot)) / 1000.0 if tot else None,
            "typical_p99": typical_p99(hs), "worst_sec_p99": max((pct(h, 0.99) for h in hs if h), default=None)}


def seconds_map(rows, flows, t0, t1):
    secs = collections.defaultdict(collections.Counter)
    for r in rows:
        if r["flow"] in flows and t0 <= r["t"] < t1:
            for b, n in r["h"].items():
                secs[int(r["t"])][int(b)] += n
    return secs


def call_secs(c, t0, t1):
    return [s for s in range(int(c["start"]), int(c["end"]) + 1) if t0 <= s < t1]


def gc_events(d, major):
    """[(epoch, kind, ms)] of the GC pauses in gc.log: kind is young, full, remark, cleanup or mixed."""
    out = []
    p = d / "gc.log"
    if not p.exists():
        return out
    if major >= 9:
        pat = re.compile(r"^\[([^\]]+)\]\[[^\]]+\] GC\(\d+\) Pause (Young|Full|Remark|Cleanup)( \((?:Normal|Mixed|Concurrent Start|Prepare Mixed)\))?.* ([\d.]+)ms$")
        for ln in p.read_text(errors="ignore").splitlines():
            m = pat.match(ln)
            if m:
                kind = m.group(2).lower()
                if kind == "young" and m.group(3) and "Mixed" in m.group(3) and "Prepare" not in m.group(3):
                    kind = "mixed"
                out.append((dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp(), kind, float(m.group(4))))
    else:
        pat = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:.]+[+-]\d{4}): [\d.]+: \[(Full GC|GC pause|GC remark|GC cleanup)(.*?)([\d.]+) secs\]")
        for ln in p.read_text(errors="ignore").splitlines():
            m = pat.match(ln)
            if m:
                kind = {"Full GC": "full", "GC pause": "young", "GC remark": "remark", "GC cleanup": "cleanup"}[m.group(2)]
                if kind == "young" and "(mixed)" in m.group(3):
                    kind = "mixed"
                out.append((dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp(), kind, float(m.group(4)) * 1000))
    return out


def java_major(d):
    m = re.search(r"java major=(\d+)", (d / "stdout.log").read_text(errors="ignore"))
    return int(m.group(1)) if m else 17


def runs(root, section):
    for done in sorted((root / "latency").rglob("done")):
        d = done.parent
        meta = json.loads((d / "meta.json").read_text())
        if section(meta["scenario"]):
            yield d, meta


def other_cpu(mrows, t0, t1, meta):
    from analyze import metrics_window
    return metrics_window(mrows, t0, t1, meta).get("external_cpu_on_app_cpus_pct")


def run_summary(d, meta):
    rows = load(d / "load.jsonl")
    calls = load(d / "calls.jsonl") if (d / "calls.jsonl").exists() else []
    mrows = load(d / "metrics.jsonl")
    (b0, b1), (d0, d1), (a0, a1) = meta["windows"]["before"], meta["windows"]["during"], meta["windows"]["after"]
    major = java_major(d)
    sps = safepoints(d, major)
    gcs = gc_events(d, major)
    out = {"svc": meta["svc"], "scenario": meta["scenario"], "rep": meta["rep"], "major": major, "flows": {}, "calls": [],
           "other_cpu": {w: other_cpu(mrows, *meta["windows"][w], meta) for w in ("before", "during", "after")}}
    owner = {}
    for i, c in enumerate(calls):
        for s in call_secs(c, d0, d1):
            owner.setdefault(s, i)
    for name, flows in FLOWS.items():
        before = seconds_map(rows, flows, b0, b1)
        during = seconds_map(rows, flows, d0, d1)
        after = seconds_map(rows, flows, a0, a1)
        e = {"before": pooled(list(before.values())), "after": pooled(list(after.values()))}
        groups = collections.defaultdict(list)
        for s, h in during.items():
            if s in owner:
                groups["tb" if calls[owner[s]]["command"] == "thread_blocking" else "other"].append(h)
            else:
                groups["idle"].append(h)
        for g in ("other", "tb", "idle"):
            e[g] = pooled(groups[g])
        per_call = []
        for i, c in enumerate(calls):
            hs = [during[s] for s in call_secs(c, d0, d1) if owner.get(s) == i and s in during]
            per_call.append(pooled(hs))
        e["per_call"] = per_call
        out["flows"][name] = e
    err = sum(r["err"] + r["drop"] for r in rows)
    out["errors"] = err
    for i, c in enumerate(calls):
        t0, t1 = c["start"], c["end"]
        sp = [x for x in sps if t0 <= x[0] <= t1 + 0.5]
        gc = [x for x in gcs if t0 <= x[0] <= t1 + 0.5]
        out["calls"].append({
            "command": c["command"], "status": c["status"], "check": c.get("check"), "ms": c["ms"], "cleanup": c.get("cleanup"),
            "attach_ms": (c["steps"]["attach"][1] - c["steps"]["attach"][0]) if c["steps"].get("attach") else None,
            "stop_to_port_closed": c["steps"].get("stop_to_port_closed"), "stop_to_threads_zero": c["steps"].get("stop_to_threads_zero"),
            "post": c["post"], "new_procs": c["procs"]["new"], "threads_live": c["perf_before"]["threads_live"],
            "threaddump_ms": max((x[2] for x in sp if x[1] == "ThreadDump"), default=None),
            "non_gc_sp_max": max((x[2] for x in sp if not re.match(r"^(G1|GC|Cleanup|CGC|Parallel|Full)", x[1])), default=None),
            "gc": [(k, round(ms, 1)) for _, k, ms in gc],
            "old_pct": 100.0 * c["perf_before"]["old_used"] / c["perf_before"]["old_max_capacity"] if c["perf_before"].get("old_max_capacity") else None,
            "mem_delta": c["memory"]["after"] - c["memory"]["before"], "mem_peak_delta": c["memory"]["peak"] - c["memory"]["before"],
        })
    out["gc_before"] = collections.Counter(k for t, k, _ in gcs if b0 <= t < b1)
    out["gc_during"] = collections.Counter(k for t, k, _ in gcs if d0 <= t < d1)
    out["gc_full_ms"] = [round(ms, 1) for t, k, ms in gcs if k == "full" and b0 <= t < a1]
    live = d / "live.json"
    out["live"] = json.loads(live.read_text()) if live.exists() else None
    return out


def latency(root):
    res = [run_summary(d, m) for d, m in runs(root, lambda s: s == "l1all")]
    print("## Item 1: latency of the L1 calls (scenario l1all)\n")
    print("| svc | rep | flow | before p99 / typical | other calls: secs, p99, max, ratio p99 | thread -b: secs, p99, max | idle typical p99, vs before | after typical, vs before | other CPU % b/d/a | errors |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in res:
        for flow in ("hot", "all"):
            e = r["flows"][flow]
            bp, bt = e["before"]["p99"], e["before"]["typical_p99"]
            o, tb, idle, af = e["other"], e["tb"], e["idle"], e["after"]
            ratio = o["p99"] / bp if o["p99"] and bp else None
            dv = lambda x: f((x / bt - 1) * 100, 1) if x and bt else "-"
            oc = r["other_cpu"]
            print(f"| {r['svc']} | {r['rep']} | {flow} | {f(bp)} / {f(bt)} | {o['secs']}, {f(o['p99'])}, {f(o['max'], 1)}, {f(ratio)}x | {tb['secs']}, {f(tb['p99'])}, {f(tb['max'], 1)} | "
                  f"{f(idle['typical_p99'])}, {dv(idle['typical_p99'])}% | {f(af['typical_p99'])}, {dv(af['typical_p99'])}% | {oc['before']}/{oc['during']}/{oc['after']} | {r['errors']} |")
    print("\n### Per command, over all runs (hot+control flows): max of the per-call p99 and of the max latency; call duration\n")
    print("| command | calls | statuses | p99 max (ms) | ratio to before p99, max | max latency max (ms) | duration median / max (ms) | ThreadDump safepoint max (ms) |")
    print("|---|---|---|---|---|---|---|---|")
    per = collections.defaultdict(list)
    for r in res:
        bp = r["flows"]["all"]["before"]["p99"]
        for c, pc in zip(r["calls"], r["flows"]["all"]["per_call"]):
            per[c["command"]].append((c, pc, bp, r["svc"]))
    for cmd, items in per.items():
        p99s = [pc["p99"] for _, pc, _, _ in items if pc["p99"]]
        ratios = [pc["p99"] / bp for _, pc, bp, _ in items if pc["p99"] and bp]
        maxes = [pc["max"] for _, pc, _, _ in items if pc["max"]]
        ms = sorted(c["ms"] for c, _, _, _ in items)
        td = [c["threaddump_ms"] for c, _, _, _ in items if c["threaddump_ms"] is not None]
        st = collections.Counter(c["status"] for c, _, _, _ in items)
        print(f"| {cmd} | {len(items)} | {dict(st)} | {f(max(p99s))} | {f(max(ratios))} | {f(max(maxes), 1)} | {ms[len(ms) // 2]:.0f} / {ms[-1]:.0f} | {f(max(td) if td else None)} |")
    print("\n### Per JDK: call duration (ms), first call of each JVM, and the clean-up timings\n")
    print("| svc | calls | median | max | first call of the JVM (median of reps) | attach ms median / max | stop→port closed max (ms) | stop→no arthas- thread max (ms) | post-check failures | new processes |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    by = collections.defaultdict(list)
    for r in res:
        by[r["svc"]].append(r)
    for svc, rs in sorted(by.items(), key=lambda x: int(x[0][3:])):
        cs = [c for r in rs for c in r["calls"]]
        ms = sorted(c["ms"] for c in cs)
        att = sorted(c["attach_ms"] for c in cs if c["attach_ms"])
        firsts = sorted(r["calls"][0]["ms"] for r in rs)
        bad = sum(1 for c in cs if c["post"]["listening"] or c["post"]["arthas_threads"] or not c["post"]["procs_same"])
        newp = sum(len(c["new_procs"] or []) for c in cs)
        pc = [c["stop_to_port_closed"] for c in cs if c["stop_to_port_closed"] is not None]
        tz = [c["stop_to_threads_zero"] for c in cs if c["stop_to_threads_zero"] is not None]
        print(f"| {svc} | {len(cs)} | {ms[len(ms) // 2]:.0f} | {ms[-1]:.0f} | {firsts[len(firsts) // 2]:.0f} | {att[len(att) // 2]:.0f} / {att[-1]:.0f} | {max(pc):.0f} | {max(tz):.0f} | {bad} | {newp} |")
    print("\nlive.json (enhanced classes after the run):", collections.Counter(json.dumps(r["live"], sort_keys=True) for r in res))
    print("full GCs in any window:", sum(len(r["gc_full_ms"]) for r in res))
    return res


def noise(root):
    """The noop runs (accept.py latency --kinds none): the same windows without a call."""
    res = [run_summary(d, m) for d, m in runs(root, lambda s: s == "noop")]
    print("## Item 1, noise reference: the l1all windows without a call (scenario noop)\n")
    print("| svc | rep | flow | before p99 / typical | during typical p99, vs before | after typical, vs before | during max (ms) | other CPU % b/d/a |")
    print("|---|---|---|---|---|---|---|---|")
    for r in res:
        for flow in ("hot", "all"):
            e = r["flows"][flow]
            bt = e["before"]["typical_p99"]
            dv = lambda x: f((x / bt - 1) * 100, 1) if x and bt else "-"
            oc = r["other_cpu"]
            print(f"| {r['svc']} | {r['rep']} | {flow} | {f(e['before']['p99'])} / {f(bt)} | {f(e['idle']['typical_p99'])}, {dv(e['idle']['typical_p99'])}% | "
                  f"{f(e['after']['typical_p99'])}, {dv(e['after']['typical_p99'])}% | {f(e['idle']['max'], 1)} | {oc['before']}/{oc['during']}/{oc['after']} |")
    return res


def pauses(root):
    """Every safepoint over 20 ms in the latency runs, other than ThreadDump, with its window and the call it falls in."""
    print("## Safepoints over 20 ms other than ThreadDump, all latency runs\n")
    print("| run | operation | ms | window | call (command) |\n|---|---|---|---|---|")
    out = []
    for d, meta in runs(root, lambda s: True):
        calls = load(d / "calls.jsonl") if (d / "calls.jsonl").exists() else []
        for t, op, ms in safepoints(d, java_major(d)):
            if ms <= 20 or op == "ThreadDump":
                continue
            w = next((k for k, (a, b) in meta["windows"].items() if a <= t < b), "warm-up or between windows")
            near = [c["command"] for c in calls if c["start"] - 1 <= t <= c["end"] + 1]
            print(f"| {d.relative_to(root)} | {op} | {ms:.1f} | {w} | {', '.join(near) or '-'} |")
            out.append({"run": str(d.relative_to(root)), "op": op, "ms": ms, "window": w, "calls": near})
    return out


def threads(root):
    res = [run_summary(d, m) for d, m in runs(root, lambda s: s.startswith("tb"))]
    print("## Item 7: thread -b and the number of live threads\n")
    print("| svc | scenario | rep | threads live at the calls | statuses | ThreadDump safepoint ms per call | call secs p99 / max (ms, all flows) | before p99 | other CPU % during | duration ms |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(res, key=lambda r: (r["scenario"], int(r["svc"][3:]), r["rep"])):
        e = r["flows"]["all"]
        cs = r["calls"]
        print(f"| {r['svc']} | {r['scenario']} | {r['rep']} | {sorted(set(c['threads_live'] for c in cs))} | {dict(collections.Counter(c['status'] for c in cs))} | "
              f"{[f(c['threaddump_ms'], 1) for c in cs]} | {f(e['tb']['p99'])} / {f(e['tb']['max'], 1)} | {f(e['before']['p99'])} | {r['other_cpu']['during']} | {[round(c['ms']) for c in cs]} |")
    return res


def oldgen(root):
    res = [run_summary(d, m) for d, m in runs(root, lambda s: s.startswith("og"))]
    print("## Item 8: L1 calls at different old generation occupancy\n")
    print("| svc | scenario | old gen % at the calls (hsperfdata) | statuses | GC pauses before window | GC pauses during window | GC pauses in the calls | full GC ms (all windows) | before p99 / max | call secs p99 / max | heap MiB before→after call (MXBean) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(res, key=lambda r: (int(r["svc"][3:]), int(r["scenario"][2:]))):
        e = r["flows"]["all"]
        cs = r["calls"]
        print(f"| {r['svc']} | {r['scenario']} | {[f(c['old_pct'], 0) for c in cs]} | {dict(collections.Counter(c['status'] for c in cs))} | {dict(r['gc_before'])} | {dict(r['gc_during'])} | "
              f"{[c['gc'] for c in cs]} | {r['gc_full_ms']} | {f(e['before']['p99'])} / {f(e['before']['max'], 0)} | {f(e['other']['p99'])} / {f(e['other']['max'], 0)} | - |")
    return res


MIB = 1 << 20


def mb(x):
    return None if x is None else x / MIB


def cycles(root, name="cycles"):
    print(f"## Items 2, 4, 5 ({name}): 50 calls per JVM, the four JVMs at once, no load\n")
    print("| svc | baseline metaspace (hsperfdata after 3 full GC / MXBean) | after 50 calls (MXBean) | after 3 full GC (hsperfdata / MXBean) | Δ vs baseline (MXBean) | committed after | cgroup MiB baseline → after calls → after GC | statuses | duration median / max (ms) | post-check failures | new processes | live |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    out = {}
    for d in sorted((root / name).iterdir(), key=lambda p: int(p.name[3:])):
        st = json.loads((d / "steps.json").read_text())["steps"]
        by = {s["what"]: s for s in st}
        base, after, final = by["baseline"], by["after calls"], by["after full gc 3"]
        calls = load(d / "calls.jsonl")
        ms = sorted(c["ms"] for c in calls)
        bad = sum(1 for c in calls if c["post"]["listening"] or c["post"]["arthas_threads"] or not c["post"]["procs_same"])
        newp = sum(len(c["procs"]["new"] or []) for c in calls)
        st_c = collections.Counter(c["status"] for c in calls)
        dm = (final["diag"]["metaspaceUsed"] - base["diag"]["metaspaceUsed"]) / MIB
        print(f"| {d.name} | {f(mb(base['snap']['perf']['metaspace_used']), 1)} / {f(mb(base['diag']['metaspaceUsed']), 1)} | {f(mb(after['diag']['metaspaceUsed']), 1)} | "
              f"{f(mb(final['snap']['perf']['metaspace_used']), 1)} / {f(mb(final['diag']['metaspaceUsed']), 1)} | {dm:+.1f} | {f(mb(final['diag']['metaspaceCommitted']), 1)} | "
              f"{f(mb(base['snap']['memory_current']), 0)} → {f(mb(after['snap']['memory_current']), 0)} → {f(mb(final['snap']['memory_current']), 0)} | {dict(st_c)} | {ms[len(ms) // 2]:.0f} / {ms[-1]:.0f} | {bad} | {newp} | {by['live'].get('live')} |")
        out[d.name] = {"calls": calls, "steps": by}
    print("\n### Per call: cgroup memory and metaspace (MXBean) increments, MiB: first call; calls 2-5; calls 6-50 (median, max)\n")
    print("| svc | first: mem after / peak, metaspace | 2-5: mem median, max; metaspace median, max | 6-50: mem median, max; metaspace median, max | heap (MXBean) Δ per call median | classes loaded per call median |")
    print("|---|---|---|---|---|---|")
    for svc, o in out.items():
        cs = o["calls"]
        md = lambda c: (c["memory"]["after"] - c["memory"]["before"]) / MIB
        mp = lambda c: (c["memory"]["peak"] - c["memory"]["before"]) / MIB
        ma = lambda c: (c["diag_after"]["metaspaceUsed"] - c["diag_before"]["metaspaceUsed"]) / MIB
        hp = lambda c: (c["diag_after"]["heapUsed"] - c["diag_before"]["heapUsed"]) / MIB
        cl = lambda c: c["diag_after"]["classesLoaded"] - c["diag_before"]["classesLoaded"]
        mm = lambda xs: f"{statistics.median(xs):.1f}, {max(xs):.1f}"
        print(f"| {svc} | {md(cs[0]):.1f} / {mp(cs[0]):.1f}, {ma(cs[0]):.1f} | {mm([md(c) for c in cs[1:5]])}; {mm([ma(c) for c in cs[1:5]])} | "
              f"{mm([md(c) for c in cs[5:]])}; {mm([ma(c) for c in cs[5:]])} | {statistics.median([hp(c) for c in cs]):.1f} | {statistics.median([cl(c) for c in cs]):.0f} |")
    print("\n### Item 2, the four JVMs at once: duration per command (ms, median / max over the four JVMs)\n")
    per = collections.defaultdict(list)
    for svc, o in out.items():
        for c in o["calls"]:
            per[c["command"]].append(c["ms"])
    print("| command | calls | median | max |\n|---|---|---|---|")
    for cmd, v in per.items():
        v.sort()
        print(f"| {cmd} | {len(v)} | {v[len(v) // 2]:.0f} | {v[-1]:.0f} |")
    pc = [c["steps"].get("stop_to_port_closed") for o in out.values() for c in o["calls"] if c["steps"].get("stop_to_port_closed") is not None]
    tz = [c["steps"].get("stop_to_threads_zero") for o in out.values() for c in o["calls"] if c["steps"].get("stop_to_threads_zero") is not None]
    print(f"\nstop→port closed: n={len(pc)} max {max(pc):.0f} ms; stop→no arthas- thread: n={len(tz)} median {statistics.median(tz):.0f} max {max(tz):.0f} ms")
    return out


def totals(root):
    print("## Items 2, 3: all calls of every experiment\n")
    print("| experiment | calls | statuses | duration median / max (ms) | stop→port closed median / max (ms) | stop→no arthas- thread median / max (ms) | clean-ups not ok | post-check failures | new processes |")
    print("|---|---|---|---|---|---|---|---|---|")
    by = collections.defaultdict(list)
    for p in sorted(root.rglob("calls.jsonl")):
        by[p.relative_to(root).parts[0]].extend(load(p))
    groups = sorted(by.items())
    groups += [("all but latency", [c for e, cs in by.items() if e != "latency" for c in cs]), ("all", [c for cs in by.values() for c in cs])]
    out = {}
    for exp, cs in groups:
        ok = [c for c in cs if c["status"] == "ok"]
        ms = sorted(c["ms"] for c in ok)
        pc = sorted(c["steps"]["stop_to_port_closed"] for c in ok if c["steps"].get("stop_to_port_closed") is not None)
        tz = sorted(c["steps"]["stop_to_threads_zero"] for c in ok if c["steps"].get("stop_to_threads_zero") is not None)
        notok = sum(1 for c in ok if c["cleanup"] != "ok")
        bad = sum(1 for c in cs if c["post"]["listening"] or c["post"]["arthas_threads"] or not c["post"]["procs_same"])
        newp = sum(len(c["procs"]["new"] or []) for c in cs)
        mm = lambda xs: f"{xs[len(xs) // 2]:.0f} / {xs[-1]:.0f}" if xs else "-"
        print(f"| {exp} | {len(cs)} | {dict(collections.Counter(c['status'] for c in cs))} | {mm(ms)} | {mm(pc)} | {mm(tz)} | {notok} | {bad} | {newp} |")
        out[exp] = {"calls": len(cs), "ok": len(ok), "ms_max": ms[-1] if ms else None, "port_max": pc[-1] if pc else None, "threads_max": tz[-1] if tz else None, "post_bad": bad, "new_procs": newp}
    return out


def leak(root, name="leak"):
    print(f"## Item 4 ({name}): metaspace left after some calls of one command kind and Full GCs (MXBean, MiB)\n")
    print("| svc | command | calls ok | baseline | after calls | Δ after full GC 1 / 2 / 3 / 4 | ArthasClassloader instances after | other Arthas classes in the histogram |")
    print("|---|---|---|---|---|---|---|---|")
    out = {}
    for sd in sorted((root / name).iterdir(), key=lambda p: int(p.name[3:])):
        for d in sorted(sd.iterdir()):
            if not (d / "steps.json").exists():
                continue
            st = {x["what"]: x for x in json.loads((d / "steps.json").read_text())}
            base = st["baseline"]["diag"]["metaspaceUsed"]
            gcs = [st[k]["diag"]["metaspaceUsed"] for k in sorted(k for k in st if k.startswith("after full gc"))]
            hist = st["histogram"]["arthas"]
            loaders = sum(int(ln.split()[1]) for ln in hist if ln.split()[-1].endswith("ArthasClassloader"))
            others = [ln.split()[-1] for ln in hist if not ln.split()[-1].endswith("ArthasClassloader")]
            calls = load(d / "calls.jsonl")
            ok = sum(1 for c in calls if c["status"] == "ok")
            print(f"| {sd.name} | {d.name} | {ok}/{len(calls)} | {base / MIB:.1f} | {st['after calls']['diag']['metaspaceUsed'] / MIB:.1f} | "
                  f"{' / '.join(f'{(g - base) / MIB:+.1f}' for g in gcs)} | {loaders} | {', '.join(others[:6])} |")
            out[f"{sd.name}/{d.name}"] = {"base": base, "gcs": gcs, "hist": hist, "loaders": st["histogram"].get("loaders")}
    return out


def limits(root):
    print("## Items 5, 9: a call every 61 s with the default checks, 1 GiB containers under light load\n")
    print("| svc | call | command | status | check / reason | attach | cgroup MiB before → peak → after | headroom MiB before (1 GiB - before) | metaspace MiB (MXBean) before → after | hsperfdata metaspace at the check | anon / file MiB before |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for d in sorted((root / "limits").iterdir(), key=lambda p: int(p.name[3:]) if p.is_dir() else 99):
        if not d.is_dir():
            continue
        for c in load(d / "calls.jsonl"):
            m = c["memory"]
            reason = (c.get("check") or "") + (": " + c["reason"] if c.get("reason") else "")
            print(f"| {d.name} | {c['seq'] + 1} | {c['command']} | {c['status']} | {reason[:90]} | {c.get('attach', '')} | {m['before'] / MIB:.0f} → {m['peak'] / MIB:.0f} → {m['after'] / MIB:.0f} | "
                  f"{(1073741824 - m['before']) / MIB:.0f} | {c['diag_before']['metaspaceUsed'] / MIB:.1f} → {c['diag_after']['metaspaceUsed'] / MIB:.1f} | {c['perf_before']['metaspace_used'] / MIB:.1f} | "
                  f"{m['anon_before'] / MIB:.0f} / {m['file_before'] / MIB:.0f} |")
        mrows = load(d / "metrics.jsonl")
        calls = load(d / "calls.jsonl")
        gaps = []
        for i, c in enumerate(calls[:-1]):
            nxt = calls[i + 1]["start"]
            after = [x["mem"] for x in mrows if "mem" in x and c["end"] + 1 <= x["t"] <= c["end"] + 3]
            later = [x["mem"] for x in mrows if "mem" in x and nxt - 3 <= x["t"] <= nxt - 1]
            meta_a = [x["diag"]["metaspaceUsed"] for x in mrows if "diag" in x and c["end"] + 1 <= x["t"] <= c["end"] + 3]
            meta_l = [x["diag"]["metaspaceUsed"] for x in mrows if "diag" in x and nxt - 3 <= x["t"] <= nxt - 1]
            if after and later and meta_a and meta_l:
                gaps.append(f"{(later[-1] - after[0]) / MIB:+.0f} MiB mem, {(meta_l[-1] - meta_a[0]) / MIB:+.1f} MiB metaspace")
        print(f"\n{d.name}: change between 1 s after a call and 1 s before the next: {gaps}\n")


def metaspace(root):
    print("## Item 6: JVMs with a MaxMetaspaceSize\n")
    print("| case | call | status | check / reason | metaspace MiB at the check: hsperfdata / MXBean | MXBean after | full GCs during the call | JVM alive, OOME |")
    print("|---|---|---|---|---|---|---|---|")
    for d in sorted((root / "metaspace").iterdir()):
        steps = json.loads((d / "steps.json").read_text())
        end = steps[-1]
        alive = f"{end.get('ping')}, {end.get('oome_in_stdout')}"
        for c in load(d / "calls.jsonl"):
            full = lambda p: sum(v["count"] for k, v in p["collectors"].items() if "full" in k.lower() or "marksweep" in k.lower())
            reason = (c.get("check") or "") + (": " + c["reason"] if c.get("reason") else "")
            print(f"| {d.name} | {c['seq'] + 1} | {c['status']} | {reason[:100]} | {c['perf_before']['metaspace_used'] / MIB:.1f} / {c['diag_before']['metaspaceUsed'] / MIB:.1f} | "
                  f"{c['diag_after']['metaspaceUsed'] / MIB:.1f} | {full(c['perf_after']) - full(c['perf_before'])} | {alive} |")


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1])
    for sec in sys.argv[2:] or ["cycles", "leak", "limits", "metaspace", "latency", "noise", "pauses", "threads", "oldgen", "totals"]:
        try:
            # cycles-<x> and leak-<x> read the runs of accept.py cycles/leak --name <section>.
            base = sec.split("-")[0]
            r = globals()[base](root, sec) if base in ("cycles", "leak") else globals()[sec](root)
            if r is not None:
                (root / f"summary-{sec}.json").write_text(json.dumps(r, indent=1, default=str))
        except FileNotFoundError as e:
            print(f"{sec}: no data ({e})\n")
        print()

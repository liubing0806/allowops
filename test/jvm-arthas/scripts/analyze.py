#!/usr/bin/env python3
"""Turns the raw output of bench.py into per-window latency / stall / CPU tables.

Usage: analyze.py <bench-root> [--md]      e.g. analyze.py <raw-dir>/bench
Every run directory (the ones with a `done` file) gets a summary.json; with --md a markdown table of all runs is printed.
"""
import collections
import datetime as dt
import json
import math
import pathlib
import random
import re
import sys

BASE = 1.01
CONTROL = ("ping", "work", "db")
GC_OPS = re.compile(r"^(G1|Parallel|CollectFor|GenCollect|GC|Shenandoah|Z|Cleanup|ICBuffer|CGC|Full)", re.I)


def bucket_value_us(b):
    return BASE ** (int(b) + 0.5) - 1


def load(path):
    rows = []
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                rows.append(json.loads(ln))
    return rows


def merge(rows, flows, t0, t1):
    h = collections.Counter()
    sent = ok = err = drop = 0
    for r in rows:
        if r["flow"] in flows and t0 <= r["t"] < t1:
            sent += r["sent"]
            ok += r["ok"]
            err += r["err"]
            drop += r["drop"]
            for b, c in r["h"].items():
                h[int(b)] += c
    return {"sent": sent, "ok": ok, "err": err, "drop": drop, "h": h}


def pct(h, q):
    n = sum(h.values())
    if n == 0:
        return None
    target = q * n
    acc = 0
    for b in sorted(h):
        acc += h[b]
        if acc >= target:
            return bucket_value_us(b) / 1000.0
    return None


def over(h, ms):
    lim = ms * 1000.0
    return sum(c for b, c in h.items() if BASE ** int(b) - 1 >= lim)


def stats(m):
    h = m["h"]
    n = sum(h.values())
    return {"n": n, "err": m["err"], "drop": m["drop"], "err_pct": round(100.0 * m["err"] / n, 4) if n else None,
            "p50": pct(h, 0.50), "p99": pct(h, 0.99), "p999": pct(h, 0.999), "max": (bucket_value_us(max(h)) / 1000.0 if h else None),
            "over50ms": over(h, 50), "over100ms": over(h, 100)}


# per-second histograms: typical p99 and a confidence interval for the change of p99 between two windows --------
def per_second(rows, flows, t0, t1):
    secs = collections.defaultdict(collections.Counter)
    for r in rows:
        if r["flow"] in flows and t0 <= r["t"] < t1:
            c = secs[int(r["t"])]
            for b, n in r["h"].items():
                c[int(b)] += n
    return [secs[k] for k in sorted(secs)]


def pooled_pct(hs, q):
    tot = collections.Counter()
    for h in hs:
        tot.update(h)
    return pct(tot, q)


def typical_p99(hs):
    """Median over the seconds of the window of that second's p99 (a single stall does not move it)."""
    v = sorted(x for x in (pct(h, 0.99) for h in hs) if x is not None)
    return v[len(v) // 2] if v else None


def boot_delta(hs_a, hs_b, q=0.99, n=300, seed=7):
    """95% interval (percent) of pooled-p99(b) / pooled-p99(a) - 1 when the seconds of each window are resampled with replacement."""
    if len(hs_a) < 10 or len(hs_b) < 10:
        return None
    rnd = random.Random(seed)
    out = []
    for _ in range(n):
        a = [hs_a[rnd.randrange(len(hs_a))] for _ in hs_a]
        b = [hs_b[rnd.randrange(len(hs_b))] for _ in hs_b]
        pa, pb = pooled_pct(a, q), pooled_pct(b, q)
        if pa and pb:
            out.append((pb - pa) / pa * 100)
    out.sort()
    if len(out) < 50:
        return None
    return [round(out[int(0.025 * len(out))], 1), round(out[int(0.975 * len(out)) - 1], 1)]


# safepoints ---------------------------------------------------------------------------------------------
def ts(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def safepoints(d, java_major):
    """[(epoch seconds, operation, stopped milliseconds)] from the JVM's own logs."""
    out = []
    sp = d / "safepoint.log"
    if java_major >= 17 and sp.exists():
        pat = re.compile(r'^\[([^\]]+)\]\[[^\]]+\] Safepoint "([^"]+)".*Total: (\d+) ns')
        for ln in sp.read_text(errors="ignore").splitlines():
            m = pat.match(ln)
            if m:
                out.append((ts(m.group(1)), m.group(2), int(m.group(3)) / 1e6))
    elif java_major >= 9 and sp.exists():
        op = None
        for ln in sp.read_text(errors="ignore").splitlines():
            m = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Entering safepoint region: (.+)$", ln)
            if m:
                op = m.group(2).strip()
                continue
            m = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Total time for which application threads were stopped: ([0-9.]+) seconds", ln)
            if m:
                out.append((ts(m.group(1)), op or "?", float(m.group(2)) * 1000))
                op = None
    else:
        # JDK 8: -XX:+PrintSafepointStatistics prints one line per safepoint to stdout (docker timestamp, uptime, operation,
        # [threads ...] [time: spin block sync cleanup vmop] page_trap_count); the time spent stopped is sync + cleanup + vmop.
        stdout = d / "stdout.log"
        pat = re.compile(r"^(\S+Z) [0-9.]+: (\S+)\s+\[[^\]]*\]\s+\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
        if stdout.exists():
            for ln in stdout.read_text(errors="ignore").splitlines():
                m = pat.match(ln)
                if m:
                    t = dt.datetime.strptime(m.group(1)[:26] + "Z", "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc).timestamp()
                    sync, cleanup, vmop = int(m.group(5)), int(m.group(6)), int(m.group(7))
                    out.append((t, m.group(2), float(sync + cleanup + vmop)))
    return out


def sp_window(events, t0, t1):
    ev = [e for e in events if t0 <= e[0] < t1]
    by_op = collections.defaultdict(lambda: [0, 0.0, 0.0])
    for _, op, ms in ev:
        r = by_op[op]
        r[0] += 1
        r[1] += ms
        r[2] = max(r[2], ms)
    non_gc = [e for e in ev if not GC_OPS.match(e[1])]
    redef = [e for e in ev if "redefine" in e[1].lower() or "retransform" in e[1].lower()]
    return {"redefine_count": len(redef), "redefine_total_ms": round(sum(e[2] for e in redef), 2), "redefine_max_ms": round(max((e[2] for e in redef), default=0), 2),
            "count": len(ev), "total_ms": round(sum(e[2] for e in ev), 2), "max_ms": round(max((e[2] for e in ev), default=0), 2),
            "non_gc_total_ms": round(sum(e[2] for e in non_gc), 2), "non_gc_max_ms": round(max((e[2] for e in non_gc), default=0), 2),
            "top_ops": sorted(({"op": k, "n": v[0], "total_ms": round(v[1], 2), "max_ms": round(v[2], 2)} for k, v in by_op.items()),
                              key=lambda x: -x["total_ms"])[:6]}


def cpu_list(spec):
    out = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b or a) + 1))
    return out


def metrics_window(rows, t0, t1, meta=None):
    r = [x for x in rows if t0 <= x["t"] < t1 and "ticks" in x and "diag" in x]
    if len(r) < 2:
        return {}
    hz = 100.0
    dtm = r[-1]["t"] - r[0]["t"]
    d0, d1 = r[0]["diag"], r[-1]["diag"]
    extra = {}
    if "rundelay_ns" in r[0] and "rundelay_ns" in r[-1]:
        extra["jvm_rundelay_ms_per_s"] = round((r[-1]["rundelay_ns"] - r[0]["rundelay_ns"]) / 1e6 / dtm, 1)
    if meta and r[0].get("host_cpu") and r[-1].get("host_cpu"):
        def busy(cpus):
            return sum(r[-1]["host_cpu"].get(f"cpu{c}", 0) - r[0]["host_cpu"].get(f"cpu{c}", 0) for c in cpus) / hz / dtm * 100
        app_busy = busy(cpu_list(meta["app_cpuset"]))
        cont = (r[-1]["cg_cpu_usec"] - r[0]["cg_cpu_usec"]) / 1e6 / dtm * 100
        extra["host_busy_app_cpus_pct"] = round(app_busy, 1)           # 100 = one cpu fully busy
        extra["external_cpu_on_app_cpus_pct"] = round(max(0.0, app_busy - cont), 1)
        extra["host_busy_load_cpus_pct"] = round(busy(cpu_list(meta["load_cpus"])), 1)
    return {**extra, "jvm_cpu_pct": round((r[-1]["ticks"] - r[0]["ticks"]) / hz / dtm * 100, 1),
            "container_cpu_pct": round((r[-1]["cg_cpu_usec"] - r[0]["cg_cpu_usec"]) / 1e6 / dtm * 100, 1),
            "mem_max_mb": round(max(x["mem"] for x in r) / 1e6, 1), "threads_max": max(x["diag"]["threads"] for x in r),
            "gc_count": d1["gcCount"] - d0["gcCount"], "gc_ms": d1["gcMillis"] - d0["gcMillis"],
            "classes_loaded_delta": d1["classesLoaded"] - d0["classesLoaded"],
            "metaspace_used_mb_start_end": [round(d0["metaspaceUsed"] / 1e6, 1), round(d1["metaspaceUsed"] / 1e6, 1)]}


def call_seconds(calls, t0, t1, transition_s=3):
    """Classifies the integer seconds of [t0, t1) around Arthas calls.
    transition: seconds overlapping an attach, command, reset or stop call (plus one more second), and the first `transition_s` seconds of a job;
    job: the remaining seconds of a long job (a watch / trace / stack / monitor that keeps classes enhanced).
    The call_total summary records are skipped."""
    transition, job = set(), set()
    for c in calls:
        if c["kind"] == "call_total":
            continue
        if c["kind"] in ("job", "async_exec") and c["ms"] > 5000:
            first = int(c["start"])
            for sec in range(first, int(c["end"]) + 1):
                if t0 <= sec < t1:
                    (transition if sec < first + transition_s else job).add(sec)
            continue
        for sec in range(int(c["start"]), int(c["end"]) + 1):
            if t0 <= sec < t1:
                transition.add(sec)
    return transition, job - transition


def split_by_seconds(rows, flows, classes, t0, t1):
    """classes: list of sets of seconds; returns one list of per-second histograms per set, plus one for all other seconds."""
    per = collections.defaultdict(collections.Counter)
    for r in rows:
        if r["flow"] in flows and t0 <= r["t"] < t1:
            c = per[int(r["t"])]
            for b, n in r["h"].items():
                c[int(b)] += n
    out = [[] for _ in classes] + [[]]
    for sec in sorted(per):
        for i, cl in enumerate(classes):
            if sec in cl:
                out[i].append(per[sec])
                break
        else:
            out[-1].append(per[sec])
    return out


def pooled_stats(hs):
    tot = collections.Counter()
    for h in hs:
        tot.update(h)
    n = sum(tot.values())
    return {"secs": len(hs), "n": n, "p50": pct(tot, 0.5), "p99": pct(tot, 0.99), "p999": pct(tot, 0.999), "typical_p99": typical_p99(hs),
            "max": (bucket_value_us(max(tot)) / 1000.0 if tot else None)}


def summarize(d):
    meta = json.loads((d / "meta.json").read_text())
    rows = load(d / "load.jsonl")
    mrows = load(d / "metrics.jsonl")
    ver = (d / "stdout.log").read_text(errors="ignore")
    major = 8
    m = re.search(r"java major=(\d+)", ver)
    if m:
        major = int(m.group(1))
    sps = safepoints(d, major)
    out = {"svc": meta["svc"], "scenario": meta["scenario"], "rep": meta["rep"], "profile": meta["profile"], "java_major": major, "windows": {}, "delta_p99_pct": {}}
    secs = {}
    for flow, flows in (("hot", ("hot",)), ("control", CONTROL)):
        for w, (t0, t1) in meta["windows"].items():
            secs[(flow, w)] = per_second(rows, flows, t0, t1)
    for w, (t0, t1) in meta["windows"].items():
        e = {"hot": stats(merge(rows, ("hot",), t0, t1)), "control": stats(merge(rows, CONTROL, t0, t1)),
             "all": stats(merge(rows, ("hot",) + CONTROL, t0, t1)), "safepoints": sp_window(sps, t0, t1), "jvm": metrics_window(mrows, t0, t1, meta)}
        for f in ("ping", "work", "db"):
            e[f] = stats(merge(rows, (f,), t0, t1))
        for flow in ("hot", "control"):
            e[flow]["typical_p99"] = typical_p99(secs[(flow, w)])
        out["windows"][w] = e
    for flow in ("hot", "control"):
        for w in ("during", "after"):
            a, b = out["windows"]["before"][flow]["p99"], out["windows"][w][flow]["p99"]
            out["delta_p99_pct"][f"{flow}:{w}"] = {"pct": delta(a, b), "ci95": boot_delta(secs[(flow, "before")], secs[(flow, w)]),
                                                   "typical_pct": delta(out["windows"]["before"][flow]["typical_p99"], out["windows"][w][flow]["typical_p99"])}
    calls = []
    if (d / "calls.jsonl").exists():
        calls = load(d / "calls.jsonl")
    agg = collections.defaultdict(list)
    for c in calls:
        agg[c["kind"]].append(c["ms"])
    out["calls"] = {k: {"n": len(v), "min": min(v), "median": sorted(v)[len(v) // 2], "max": max(v)} for k, v in agg.items()}
    if calls:
        dt0, dt1 = meta["windows"]["during"]
        transition, job = call_seconds(calls, dt0, dt1)
        out["call_seconds"] = {}
        for flow, flows in (("hot", ("hot",)), ("control", CONTROL)):
            tr, jb, idle = split_by_seconds(rows, flows, [transition, job], dt0, dt1)
            before = pooled_stats(secs[(flow, "before")])
            e = {"transition": pooled_stats(tr), "job": pooled_stats(jb), "idle": pooled_stats(idle), "before": before}
            for k in ("transition", "job", "idle"):
                e[k + "_vs_before_p99_pct"] = delta(before["p99"], e[k]["p99"])
                e[k + "_typical_vs_before_pct"] = delta(before["typical_p99"], e[k]["typical_p99"])
            out["call_seconds"][flow] = e
    out["events"] = [(round(e["t"] - meta["windows"]["before"][0], 1), e["what"]) for e in meta["events"]]
    (d / "summary.json").write_text(json.dumps(out, indent=2))
    return out


def delta(a, b):
    if a is None or b is None or a == 0:
        return None
    return round((b - a) / a * 100, 1)


def md_table(runs):
    lines = ["| svc | scenario | profile | rep | flow | window | n | err | p50 ms | p99 ms | typical p99 ms | p99.9 ms | max ms | >100ms | Δp99 vs before [95% CI] | STW total ms | STW max ms | non-GC STW max ms | JVM CPU % | other CPU on app cpus % | JVM run delay ms/s |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in runs:
        for flow in ("hot", "control"):
            base = r["windows"]["before"][flow]["p99"]
            for w in ("before", "during", "after"):
                e = r["windows"][w]
                s = e[flow]
                f = lambda x: "-" if x is None else f"{x:.2f}"
                lines.append(f"| {r['svc']} | {r['scenario']} | {r['profile']} | {r['rep']} | {flow} | {w} | {s['n']} | {s['err']} | {f(s['p50'])} | {f(s['p99'])} | {f(s['typical_p99'])} | {f(s['p999'])} | {f(s['max'])} | {s['over100ms']} | "
                             f"{'' if w == 'before' else (str(r['delta_p99_pct'][flow + ':' + w]['pct']) + '% ' + str(r['delta_p99_pct'][flow + ':' + w]['ci95']))} | {e['safepoints']['total_ms']} | {e['safepoints']['max_ms']} | {e['safepoints']['non_gc_max_ms']} | {e['jvm'].get('jvm_cpu_pct', '-')} | {e['jvm'].get('external_cpu_on_app_cpus_pct', '-')} | {e['jvm'].get('jvm_rundelay_ms_per_s', '-')} |")
    out = "\n".join(lines)
    cs = [r for r in runs if r.get("call_seconds")]
    if cs:
        f = lambda x: "-" if x is None else f"{x:.2f}"
        out += "\n\n### Seconds around Arthas calls vs the other seconds of the during window (transition = attach/command/reset/stop seconds and the first 3 s of a job; job = the rest of a job)\n\n"
        out += ("| svc | scenario | profile | rep | flow | transition secs | p99 ms | max ms | job secs | p99 ms | typical p99 ms | idle secs | p99 ms | typical p99 ms | before p99 ms | before typical p99 ms | "
                "transition vs before | job vs before | idle vs before | redefine STW count | redefine STW max ms | non-GC STW max ms |\n")
        out += "|" + "---|" * 22 + "\n"
        for r in cs:
            for flow in ("hot", "control"):
                c = r["call_seconds"][flow]
                sp = r["windows"]["during"]["safepoints"]
                out += (f"| {r['svc']} | {r['scenario']} | {r['profile']} | {r['rep']} | {flow} | {c['transition']['secs']} | {f(c['transition']['p99'])} | {f(c['transition']['max'])} | "
                        f"{c['job']['secs']} | {f(c['job']['p99'])} | {f(c['job']['typical_p99'])} | {c['idle']['secs']} | {f(c['idle']['p99'])} | {f(c['idle']['typical_p99'])} | "
                        f"{f(c['before']['p99'])} | {f(c['before']['typical_p99'])} | {c['transition_vs_before_p99_pct']}% | {c['job_vs_before_p99_pct']}% | {c['idle_vs_before_p99_pct']}% | "
                        f"{sp['redefine_count']} | {sp['redefine_max_ms']} | {sp['non_gc_max_ms']} |\n")
        out += "\n### Duration of the Arthas calls (ms)\n\n| svc | scenario | profile | rep | kind | n | min | median | max |\n|---|---|---|---|---|---|---|---|---|\n"
        for r in cs:
            for k, v in r["calls"].items():
                out += f"| {r['svc']} | {r['scenario']} | {r['profile']} | {r['rep']} | {k} | {v['n']} | {v['min']} | {v['median']} | {v['max']} |\n"
    return out


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1])
    runs = []
    for done in sorted(root.rglob("done")):
        d = done.parent
        try:
            runs.append(summarize(d))
        except Exception as ex:
            print("failed", d, repr(ex), file=sys.stderr)
    if "--md" in sys.argv:
        print(md_table(runs))
    else:
        for r in runs:
            print(r["svc"], r["scenario"], r["profile"], r["rep"],
                  {w: (r["windows"][w]["hot"]["p99"], r["windows"][w]["control"]["p99"]) for w in r["windows"]})

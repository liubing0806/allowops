#!/usr/bin/env python3
"""Tables of the stage-3 L2 acceptance report (docs/arthas-stage3-l2-report.md) from the raw data of scripts/run_s3_l2.sh
(s3_l2.py run and func).

A run of s3_l2.py holds five calls on one JVM. For every call this script builds a view directory under <out>/views/: meta.json
with the before window of the run and the call as the during window, calls.jsonl with the call in the form of bench.py (attach,
job, reset, cleanup), and links to the run's load, metrics, safepoint and host probe files. l2_threshold.analyze_run() computes
the transient and the steady state of each view; the group table and its verdicts are l2_threshold.print_groups().
The job of watch, trace, stack and monitor runs from the async_exec request to the first request after it that is not
pull_results (interrupt_job, close_session or the exec of reset); the job of jad is its exec request.

Usage: s3_l2_analyze.py <raw dir> [--out <dir>] [--json <file>]
Sections: runs and their disturbance, calls (status, attach, cpu_before, affect, enhanced_classes, state after the call), transient,
steady, groups and verdicts, jad, plain, busy-thread runs, the first enhancement of each JVM against the later ones, JVM CPU
after the start of the enhancement, cpu_before, errors, noise references, 20 s windows without a call against the before window
(the null distribution of the steady statistic), write waits, functional checks. Times are milliseconds unless a column says
otherwise; CPU 100% is one CPU unless it says "of the limit".
"""
import argparse
import collections
import json
import pathlib
import re
import statistics
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import l2_threshold as L2  # noqa: E402
from analyze import bucket_value_us, load, pct, typical_p99  # noqa: E402

ENHANCING = ("watch", "trace", "stack", "monitor")
LINKS = ("load.jsonl", "metrics.jsonl", "safepoint.log", "gc.log", "redefine.log", "stdout.log", "host_io.jsonl")
OWN = {"ja-loadgen", "ja-call", "python3", "sudo", "taskset", "java", "docker", "dockerd", "containerd", "containerd-shim",
       "containerd-shim-runc-v2", "docker-proxy", "tini", "docker-init"}
CPU_BEFORE = re.compile(r"^(\d+)% of the CPU limit \(([0-9.]+) CPUs\)")


def cpus(spec):
    return [c for part in spec.split(",") for c in range(int(part.split("-")[0]), int(part.split("-")[-1]) + 1)]


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def fmt(x, n=1):
    return "-" if x is None else f"{x:.{n}f}"


def pctf(x):
    return "-" if x is None else f"{x:+.0f}%"


# raw data ----------------------------------------------------------------------------------------------------------------------
def runs(raw):
    for p in sorted((raw / "l2").rglob("run.json")):
        if (p.parent / "done").exists():
            yield p.parent, json.loads(p.read_text())


def call_spans(rec):
    """(job start, job end, job command, start of the first reset after the job, async_exec requests), in epoch seconds; None when
    the call sent no job (refused before the attach, for example)."""
    reqs = sorted(rec["steps"].get("requests") or [], key=lambda r: r["open"])
    t = rec["start"]
    if rec["command"] == "jad":
        idx = next((i for i, r in enumerate(reqs) if r.get("action") == "exec" and (r.get("command") or "").startswith("jad ")), None)
        if idx is None:
            return None
        j0, j1, n = reqs[idx]["open"], reqs[idx]["close"], 1
    else:
        idxs = [i for i, r in enumerate(reqs) if r.get("action") == "async_exec"]
        if not idxs:
            return None
        idx = idxs[0]
        j0 = reqs[idx]["open"]
        end = next((r for r in reqs[idx + 1:] if r.get("action") not in ("pull_results", "async_exec")), None)
        j1 = end["open"] if end else reqs[-1]["close"]
        n = len(idxs)
    rs = next((r for r in reqs[idx + 1:] if (r.get("command") or "") == "reset"), None)
    return t + j0 / 1000, t + j1 / 1000, reqs[idx].get("command") or "", (t + rs["open"] / 1000) if rs else None, n


def build_view(vroot, d, meta, rec):
    sp = call_spans(rec)
    if sp is None:
        return None, None
    j0, j1, cmd, rs, _ = sp
    prefix = meta.get("variant") or ("l2" if meta["mode"] == "steady" else "l2u")
    v = vroot / (meta["mode"] + (f"-{meta['variant']}" if meta.get("variant") else "")) / meta["svc"] / meta["profile"] / f"rep{meta['rep']}" / f"{rec['seq']}-{rec['command']}"
    v.mkdir(parents=True, exist_ok=True)
    for f in LINKS:
        src, dst = d / f, v / f
        if src.exists() and not dst.is_symlink():
            dst.symlink_to(src.resolve())
    rows = [{"kind": "attach", "start": rec["start"], "end": j0}, {"kind": "job", "start": j0, "end": j1, "cmd": cmd}]
    if rs:
        rows.append({"kind": "reset", "start": rs, "end": rec["end"]})
    rows.append({"kind": "cleanup", "start": j1, "end": rec["end"]})
    (v / "calls.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    end = int(rec["end"]) + 1
    vm = {"svc": meta["svc"], "scenario": f"{prefix}:{rec['command']}", "rep": meta["rep"], "profile": meta["profile"],
          "windows": {"before": meta["windows"]["before"], "during": [int(rec["start"]), end], "after": [end, end]}}
    (v / "meta.json").write_text(json.dumps(vm, indent=1))
    return v, sp


def jvm_cpu(d):
    """{epoch second: JVM CPU % of one CPU over the sample interval that ended in it}"""
    out, prev = {}, None
    for r in load(d / "metrics.jsonl"):
        if "ticks" not in r:
            continue
        if prev is not None and r["t"] > prev["t"]:
            out[int(r["t"])] = (r["ticks"] - prev["ticks"]) / (r["t"] - prev["t"])
        prev = r
    return out


def thread_groups(d):
    """[(epoch, {group: % of one CPU})] from threads.jsonl of thread_cpu.py; [] when the run has none."""
    f = d / "threads.jsonl"
    return [(r["t"], r["cpu"], r["threads"]) for r in load(f)] if f.exists() else []


def cpu_stat(raw):
    """{epoch second: {cpu: busy % over the second that ended in it}} from <raw>/cpu_stat.jsonl (cpu_stat.py), without the double
    count of guest time; {} when the file is missing."""
    f = raw / "cpu_stat.jsonl"
    out, prev = {}, None
    for r in (load(f) if f.exists() else []):
        if prev is not None and r["t"] > prev["t"]:
            dt = r["t"] - prev["t"]
            busy = lambda c, x: x[c]["user"] + x[c]["nice"] + x[c]["system"] + x[c]["irq"] + x[c]["softirq"] + x[c]["steal"] - x[c]["guest"] - x[c]["guest_nice"]
            out[int(r["t"])] = {c: (busy(c, r) - busy(c, prev)) / dt for c in r if c.startswith("cpu") and c in prev}
        prev = r
    return out


def other_app_cpu(d, meta, cstat):
    """({epoch second: CPU % of the app cpus not used by the JVM's container}, {second: busy % of the load cpus}, source). The busy
    time comes from cpu_stat.jsonl when it covers the run, else from bench.Collector's host_cpu, which counts the guest time of
    virtual machines twice (source "host_cpu")."""
    app = [f"cpu{c}" for c in cpus(meta.get("app_cpuset", "4-7"))]
    lc = [f"cpu{c}" for c in cpus(meta.get("load_cpus", "8-9"))]
    rows = [r for r in load(d / "metrics.jsonl") if "host_cpu" in r and "cg_cpu_usec" in r]
    b0 = meta["windows"]["before"][0]
    src = "cpu_stat" if b0 in cstat and meta["windows"]["after"][1] - 1 in cstat else "host_cpu"
    if src == "host_cpu" and (not rows or not all(c in rows[0]["host_cpu"] for c in app)):
        rows = []  # bench.Collector records the cpus from APP_CPUS to LOAD_CPUS; none when the load cpus come first
    other, lbusy = {}, {}
    for p, q in zip(rows, rows[1:]):
        dt = q["t"] - p["t"]
        if dt <= 0:
            continue
        s = int(q["t"])
        cg = (q["cg_cpu_usec"] - p["cg_cpu_usec"]) / 1e4 / dt
        if src == "cpu_stat":
            if s in cstat:
                other[s] = sum(cstat[s].get(c, 0) for c in app) - cg
                lbusy[s] = sum(cstat[s].get(c, 0) for c in lc)
        else:
            other[s] = sum(q["host_cpu"].get(c, 0) - p["host_cpu"].get(c, 0) for c in app) / dt - cg
            lbusy[s] = sum(q["host_cpu"].get(c, 0) - p["host_cpu"].get(c, 0) for c in lc) / dt
    return other, lbusy, src


def disturbance(d, meta, cstat):
    """Per second of the before and during windows: CPU of the app cpus not used by the JVM's container (busy time of the cpus
    minus the container's usage), and the busy CPU of the load cpus; the busiest other processes of others.jsonl."""
    other, lbusy, src = other_app_cpu(d, meta, cstat)
    out = {"source": src}
    for w in ("before", "during"):
        a, b = meta["windows"][w]
        xs = [other[s] for s in range(a, b) if s in other]
        out[w] = {"other_app_med": med(xs), "other_app_max": max(xs, default=None), "other_app_ge50": sum(1 for x in xs if x >= 50),
                  "load_cpus_med": med([lbusy[s] for s in range(a, b) if s in lbusy])}
    foreign = collections.defaultdict(float)
    measured = set(cpus("4-9,12-15"))
    if (d / "others.jsonl").exists():
        for r in load(d / "others.jsonl"):
            for p in r["top"]:
                if p["comm"] not in OWN and p["last_cpu"] in measured:
                    foreign[p["comm"]] = max(foreign[p["comm"]], p["cpu_pct"])
    out["foreign"] = sorted(foreign.items(), key=lambda kv: -kv[1])[:4]
    return out


def flows_per_second(d):
    secs = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    counts = collections.defaultdict(lambda: collections.Counter())
    for r in load(d / "load.jsonl"):
        c = secs[int(r["t"])][r["flow"]]
        for b, n in r["h"].items():
            c[int(b)] += n
        for k in ("sent", "ok", "err", "drop"):
            counts[int(r["t"])][k] += r[k]
    return secs, counts


def merged(secs, s, flows):
    c = collections.Counter()
    for f in flows:
        c.update(secs[s].get(f, {}))
    return c


def noise_refs(d, meta, recs):
    """Typical p99 of the unobserved flows in the before window, in the seconds of the during window that no call touches (from 1 s
    before its start to 3 s after its end) and in the after window; and the changes against the before window."""
    secs, _ = flows_per_second(d)
    b0, b1 = meta["windows"]["before"]
    d0, d1 = meta["windows"]["during"]
    a0, a1 = meta["windows"]["after"]
    busy = {s for r in recs for s in range(int(r["start"]) - 1, int(r["end"]) + 4)}
    typ = lambda rng: typical_p99([merged(secs, s, L2.UNOBSERVED) for s in rng if s in secs])
    tb, tq, ta = typ(range(b0, b1)), typ([s for s in range(d0, d1) if s not in busy]), typ(range(a0, a1))
    ch = lambda x: (x / tb - 1) * 100 if x and tb else None
    # the null distribution of the steady statistic: 20 s windows without a call (from 3 s after a call to the next one, and the
    # after window), each against the before window, like the steady window of a call
    th = typical_p99([merged(secs, s, L2.HOT) for s in range(b0, b1) if s in secs])
    wins = [(int(r["end"]) + 3, int(n["start"])) for r, n in zip(recs, recs[1:])] + [(int(recs[-1]["end"]) + 3, d1)] if recs else []
    wins = [(a, a + 20) for a, b in wins if b - a >= 20] + [(a0, a0 + 20), (a0 + 20, a0 + 40)]
    null = []
    for a, b in wins:
        if b > a1:
            continue
        u = typ(range(a, b))
        h = typical_p99([merged(secs, s, L2.HOT) for s in range(a, b) if s in secs])
        null.append(((h / th - 1) * 100 if h and th else None, ch(u)))
    return {"before": tb, "quiet": tq, "quiet_n": len([s for s in range(d0, d1) if s not in busy]), "after": ta,
            "quiet_change": ch(tq), "after_change": ch(ta), "null": null}


def errors(d, meta):
    _, counts = flows_per_second(d)
    out = {}
    for w in ("before", "during", "after"):
        a, b = meta["windows"][w]
        c = collections.Counter()
        for s in range(a, b):
            c.update(counts.get(s, {}))
        out[w] = dict(c)
    tot = collections.Counter()
    for c in counts.values():
        tot.update(c)
    out["run"] = dict(tot)
    return out


# analysis ----------------------------------------------------------------------------------------------------------------------
def analyse(raw, vroot):
    calls, views, rinfo = [], [], []
    cstat = cpu_stat(raw)
    for d, meta in runs(raw):
        recs = load(d / "calls.jsonl") if (d / "calls.jsonl").exists() else []
        cpu = jvm_cpu(d)
        tg = thread_groups(d)
        other, _, _ = other_app_cpu(d, meta, cstat)
        seen_enh = False
        b0, b1 = meta["windows"]["before"]
        cpu_before_win = med([cpu[s] for s in range(b0, b1) if s in cpu])
        live = {}
        if (d / "live.json").exists():
            try:
                live = json.loads((d / "live.json").read_text())
            except ValueError:
                live = {"error": (d / "live.json").read_text()[:200]}
        waits = L2.write_waits(d, 20, [])
        a0, a1 = meta["windows"]["after"]
        rinfo.append({"dir": str(d), "meta": meta, "disturb": disturbance(d, meta, cstat), "errors": errors(d, meta),
                      "noise": noise_refs(d, meta, recs), "jvm_cpu_before": cpu_before_win, "live": live,
                      "waits": sorted((s, w) for s, w in waits.items() if b0 <= s < a1), "calls": len(recs)})
        for pos, rec in enumerate(recs):
            v, sp = build_view(vroot, d, meta, rec)
            # the first call of the run that enhanced a method: the first enhancement of this JVM
            first = rec["command"] in ENHANCING and sp is not None and not seen_enh
            seen_enh = seen_enh or (rec["command"] in ENHANCING and sp is not None)
            m = CPU_BEFORE.match(rec.get("cpu_before") or "")
            c = {"svc": meta["svc"], "mode": meta["mode"] + (f"-{meta['variant']}" if meta.get("variant") else ""), "profile": meta["profile"], "rep": meta["rep"], "pos": pos + 1, "cmd": rec["command"],
                 "status": rec["status"], "check": rec.get("check"), "reason": rec.get("reason"), "attach": rec.get("attach"),
                 "cpu_before": int(m.group(1)) if m else None, "cpu_limit": float(m.group(2)) if m else None,
                 "affect": rec.get("affect"), "enhanced": rec.get("enhanced_classes"), "cleanup": rec.get("cleanup"), "ms": rec["ms"],
                 "post": rec.get("post"), "stop_to_port_closed": rec["steps"].get("stop_to_port_closed"),
                 "stop_to_threads_zero": rec["steps"].get("stop_to_threads_zero"), "new_procs": rec["procs"].get("new"),
                 "async_exec": sp[4] if sp else 0, "job_s": (sp[1] - sp[0]) if sp else None, "jvm_cpu_before_win": cpu_before_win,
                 "first_enh": first}
            if sp:
                rel = {s - int(sp[0]): cpu[s] for s in range(int(sp[0]), int(sp[0]) + 13) if s in cpu}
                c["cpu_after_start"] = rel
                c["cpu_0_2"] = max((rel[k] for k in (0, 1, 2) if k in rel), default=None)
                c["cpu_3_5"] = max((rel[k] for k in (3, 4, 5) if k in rel), default=None)
                c["cpu_6_10"] = max((rel[k] for k in range(6, 11) if k in rel), default=None)
                # seconds from the start of the enhancement until the JVM's CPU is back under max(100, 2 x the before window)
                lim = max(100.0, 2 * (cpu_before_win or 0))
                c["hot_s"] = next((k for k in range(0, 40) if (int(sp[0]) + k) in cpu and cpu[int(sp[0]) + k] <= lim and k > 0), None)
                o10 = [other[s] for s in range(int(sp[0]), int(sp[0]) + 10) if s in other]
                c["other_10s_max"] = max(o10, default=None)
                c["other_10s_mean"] = statistics.mean(o10) if o10 else None
                if tg:
                    w = [(t - sp[0], g, n) for t, g, n in tg if 0 < t - sp[0] <= 30]
                    c["c2_cpu_s_30"] = round(sum(g.get("C2", 0) for _, g, _ in w) / 100, 1)
                    c["c2_full_s"] = sum(1 for _, g, _ in w if g.get("C2", 0) >= 150)
                    c["nio_max_5"] = max((g.get("http-nio", 0) for k, g, _ in w if k <= 5), default=None)
                    c["threads_before"] = next((n for t, _, n in reversed(tg) if t < sp[0]), None)
                    c["threads_max_30"] = max((n for _, _, n in w), default=None)
                c["waits_in_call"] = sorted(s - int(sp[0]) for s, _ in rinfo[-1]["waits"] if int(rec["start"]) <= s <= int(rec["end"]))
            calls.append(c)
            if v is not None:
                res = L2.analyze_run(v, 10, 20, [])
                if res:
                    res["mode"], res["variant"], res["pos"], res["call"] = meta["mode"], meta.get("variant") or "", pos + 1, c
                    views.append(res)
    return rinfo, calls, views


# tables ------------------------------------------------------------------------------------------------------------------------
def sort_key(r):
    return (int(re.sub(r"\D", "", r["svc"]) or 0), r.get("profile", ""), r.get("rep", 0), r.get("pos", 0))


def p_runs(rinfo):
    print("### 运行与干扰\n")
    print("| 模式 | JDK | 负载 | 重复 | 命令顺序 | 开始 | 应用 CPU 上其他进程 %（前 / 期间：中位，最大，≥ 50% 的秒数；来源） | 负载 CPU 忙碌（期间中位 %） | 测量 CPU 上最忙的其他进程（最大 %） | 磁盘写入 MB/s（前 / 后） | 主机负载（前 / 后） |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rinfo, key=lambda r: (r["meta"]["mode"], r["meta"]["rep"], sort_key(r["meta"]))):
        m, ds = r["meta"], r["disturb"]
        mode = m["mode"] + (f"-{m['variant']}" if m.get("variant") else "")
        hb, ha = m.get("host_before", {}), m.get("host_after", {})
        print(f"| {mode} | {m['svc']} | {m['profile']} | {m['rep']} | {','.join(m['order'])} | {time_hm(m['windows']['before'][0])} | "
              f"{fmt(ds['before']['other_app_med'], 0)}，{fmt(ds['before']['other_app_max'], 0)}，{ds['before']['other_app_ge50']} / "
              f"{fmt(ds['during']['other_app_med'], 0)}，{fmt(ds['during']['other_app_max'], 0)}，{ds['during']['other_app_ge50']}；{ds['source']} | "
              f"{fmt(ds['during']['load_cpus_med'], 0)} | {'，'.join(f'{k} {v:.0f}' for k, v in ds['foreign']) or '-'} | "
              f"{hb.get('disk', {}).get('write_mb_s', '-')} / {ha.get('disk', {}).get('write_mb_s', '-')} | {(hb.get('loadavg') or ['-'])[0]} / {(ha.get('loadavg') or ['-'])[0]} |")


def time_hm(t):
    import time
    return time.strftime("%H:%M", time.localtime(t))


def p_calls(calls):
    print("\n### 每次调用的结果\n")
    print("| 模式 | JDK | 负载 | 重复 | 位置 | 命令 | status | attach | cpu_before（限额的 %） | affect | enhanced_classes | 用时 (s) | 作业 (s) | 调用后端口 / arthas- 线程 / 进程不变 | stop 到端口关闭 (ms) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for c in sorted(calls, key=lambda c: (c["mode"], sort_key(c))):
        p = c["post"] or {}
        print(f"| {c['mode']} | {c['svc']} | {c['profile']} | {c['rep']} | {c['pos']} | {c['cmd']} | {c['status']}{' ' + c['check'] if c['check'] else ''} | "
              f"{c['attach'] or '-'} | {c['cpu_before'] if c['cpu_before'] is not None else '-'} | {c['affect'] or '-'} | {c['enhanced'] or '-'} | "
              f"{c['ms'] / 1000:.1f} | {fmt(c['job_s'])} | {p.get('listening')} / {p.get('arthas_threads')} / {p.get('procs_same')} | {fmt(c['stop_to_port_closed'], 0)} |")
    n = len(calls)
    ok = [c for c in calls if c["status"] == "ok"]
    zero = [c for c in calls if (c["enhanced"] or "").startswith("0 ")]
    clean = [c for c in calls if c["post"] and not c["post"].get("listening") and c["post"].get("arthas_threads") == 0 and c["post"].get("procs_same")]
    print(f"\n- 调用 {n} 次：status ok {len(ok)} 次；enhanced_classes 为 0 的 {len(zero)} 次；调用后没有 Arthas 端口、没有 arthas- 线程、进程不变的 {len(clean)} 次。")
    other = [c for c in calls if c["status"] != "ok" or not (c["enhanced"] or "").startswith("0 ")]
    for c in other:
        print(f"  - 例外：{c['mode']} {c['svc']} {c['profile']} 重复 {c['rep']} {c['cmd']}：{c['status']} {c['check']} {c['reason']} enhanced_classes {c['enhanced']}")


def p_transient(views, title):
    print(f"\n### {title}\n")
    print("| JDK | 命令 | 速率 | 重复 | 位置 | 超阈值的秒数，hot / 全部流 / 全部流去掉写入等待 | 这些秒内所有流的最大延迟，含 / 去掉写入等待 | 10 秒内所有流的最大延迟 | "
          "最差一秒 hot p50 / p99 / 最大 | 该秒 JVM CPU % | RedefineClasses（次数，最大 ms） | reset 后 3 秒内最差 p99 / 最大 | 10 秒内的写入等待秒 | "
          "10 秒内应用 CPU 上其他进程 %：平均 / 最大 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(views, key=lambda r: (sort_key(r), r["cmd"])):
        t = r["transient"]
        w = t["worst"]
        rs = f"{t['reset'][0]:.1f} / {t['reset'][1]:.1f}" if t["reset"] else "-"
        print(f"| {r['svc']} | {r['cmd']} | {r['rate']} | {r['rep']} | {r['pos']}{'*' if r['call']['first_enh'] else ''} | {t['affected_hot']} / {t['affected_all']} / {t['affected_all_excl']} | "
              f"{fmt(t['max_all_in_affected'])} / {fmt(t['max_all_in_affected_excl'])} | {fmt(t['max_all_10s'])} | {w[0]:.1f} / {w[1]:.1f} / {w[2]:.1f} | "
              f"{t['worst_cpu']:.0f} | {t['redefine'][0]}, {t['redefine'][1]:.1f} | {rs} | {t['waits_in_window'] or '-'} | "
              f"{fmt(r['call'].get('other_10s_mean'), 0)} / {fmt(r['call'].get('other_10s_max'), 0)} |")
    if any(r["call"]["first_enh"] for r in views):
        print("\n位置后的 * 表示这次调用是该 JVM 的第一次增强。")


def p_steady(views):
    print("\n### 稳态（增强开始 10 秒后到作业结束，每次调用）\n")
    print("| JDK | 命令 | 速率 | 重复 | 位置 | 作业秒数（其中写入等待） | 前窗口典型 p99，被观察 / 未被观察 | 作业期间典型 p99，被观察 / 未被观察 | 变化，被观察 / 未被观察 | 去掉写入等待后的变化 |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(views, key=lambda r: (sort_key(r), r["cmd"])):
        s = r["steady"]
        h, u = s["hot"], s["unobserved"]
        print(f"| {r['svc']} | {r['cmd']} | {r['rate']} | {r['rep']} | {r['pos']}{'*' if r['call']['first_enh'] else ''} | {s['secs']}（{s['waits']}） | {fmt(h['before'], 2)} / {fmt(u['before'], 2)} | "
              f"{fmt(h['during'], 2)} / {fmt(u['during'], 2)} | {pctf(h['change'])} / {pctf(u['change'])} | {pctf(h['change_excl'])} / {pctf(u['change_excl'])} |")


def p_summary(views, jad):
    """Verdicts over all groups, with the rules of l2_threshold.print_groups."""
    g = collections.defaultdict(list)
    for r in views:
        g[(r["svc"], r["cmd"], r["rate"])].append(r)
    rows = []
    for (svc, cmd, rate), rs in g.items():
        aff = [r["transient"]["affected_all_excl"] for r in rs]
        mx = [r["transient"]["max_all_in_affected_excl"] or 0.0 for r in rs]
        un = [r["steady"]["unobserved"]["change_excl"] for r in rs if r["steady"]["unobserved"]["change_excl"] is not None]
        ob = [r["steady"]["hot"]["change_excl"] for r in rs if r["steady"]["hot"]["change_excl"] is not None]
        rows.append({"svc": svc, "cmd": cmd, "rate": rate, "n": len(rs), "trans_ok": max(aff) <= 5 and max(mx) <= 2000, "aff_max": max(aff),
                     "mx_max": max(mx), "un_ok": (max(un) <= 15 and statistics.median(un) <= 5) if len(un) >= 3 else None,
                     "un_med": med(un), "un_max": max(un) if un else None,
                     "ob_ok": (max(ob) <= 20) if rate <= 1000 and len(ob) >= 3 else None, "ob_max": max(ob) if ob else None})
    print("\n### 判定汇总（watch、trace、stack、monitor；每组 3 次重复）\n")
    print("| 项 | 组数 | 达到 | 未达到 | 未达到的组 |")
    print("|---|---|---|---|---|")
    for key, name in (("trans_ok", "增强开始瞬态：超阈值的秒数 ≤ 5，这些秒内最大延迟 ≤ 2000 ms"), ("un_ok", "未被观察接口稳态：每次 ≤ 15%，中位数 ≤ 5%"),
                      ("ob_ok", "被观察方法稳态（1000 次/秒）：≤ 20%")):
        sel = [x for x in rows if x[key] is not None]
        bad = [x for x in sel if not x[key]]
        detail = "；".join(f"{x['svc']} {x['cmd']} {x['rate']}（" + (f"秒数最大 {x['aff_max']}，延迟最大 {x['mx_max']:.0f} ms" if key == "trans_ok" else
                                                                  f"中位 {pctf(x['un_med'])}，最大 {pctf(x['un_max'])}" if key == "un_ok" else
                                                                  f"最大 {pctf(x['ob_max'])}") + "）" for x in sorted(bad, key=sort_key))
        print(f"| {name} | {len(sel)} | {len(sel) - len(bad)} | {len(bad)} | {detail or '-'} |")
    first = [r for r in views if r["call"]["first_enh"]]
    later = [r for r in views if not r["call"]["first_enh"]]
    ok = lambda r: r["transient"]["affected_all_excl"] <= 5 and (r["transient"]["max_all_in_affected_excl"] or 0.0) <= 2000
    for sel, name in ((first, "瞬态，只看每个 JVM 的第一次增强（每次调用）"), (later, "瞬态，只看后续的增强（每次调用）")):
        if sel:
            bad = [r for r in sel if not ok(r)]
            detail = "；".join(f"{r['svc']} {r['cmd']} {r['rate']} 重复 {r['rep']}（{r['transient']['affected_all_excl']} 秒，"
                              f"{r['transient']['max_all_in_affected_excl'] or 0:.0f} ms）" for r in sorted(bad, key=sort_key))
            print(f"| {name} | {len(sel)} 次 | {len(sel) - len(bad)} | {len(bad)} | {detail or '-'} |")
    if jad:
        aff = [r["transient"]["affected_all_excl"] for r in jad]
        mx = [r["transient"]["max_all_in_affected_excl"] or 0.0 for r in jad]
        print(f"| jad：超阈值的秒数 ≤ 5，这些秒内最大延迟 ≤ 2000 ms（每次调用） | {len(jad)} 次 | {sum(1 for a, m in zip(aff, mx) if a <= 5 and m <= 2000)} | "
              f"{sum(1 for a, m in zip(aff, mx) if not (a <= 5 and m <= 2000))} | 秒数最大 {max(aff)}，延迟最大 {max(mx):.0f} ms |")
    return rows


def p_first(views):
    """The first enhancement of each JVM against the later ones."""
    print("\n### 每个 JVM 的第一次增强与后续增强（watch、trace、stack、monitor）\n")
    print("| 模式 | JDK | 速率 | 增强 | 调用数 | 达到瞬态阈值 | 超阈值的秒数中位 / 最大 | 这些秒内最大延迟 (ms) 中位 / 最大 | JVM CPU 回到 max(100, 2×前窗口) 以下的秒中位 / 最大 | "
          "30 秒内 C2 线程 CPU 秒中位 / 最大 | C2 ≥ 150% 的秒中位 / 最大 | 5 秒内 http-nio 线程 CPU 最大 % 中位 | 线程数：前 → 30 秒内最大（中位） | "
          "稳态变化，未被观察：中位 / 最大 | 稳态变化，被观察：中位 / 最大 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    g = collections.defaultdict(list)
    for r in views:
        if r["call"]["cmd"] in ENHANCING:
            g[(r["call"]["mode"], r["svc"], r["rate"], r["call"]["first_enh"])].append(r)
    mm = lambda xs, n=0: f"{fmt(med([x for x in xs if x is not None]), n)} / {fmt(max((x for x in xs if x is not None), default=None), n)}"
    for (mode, svc, rate, first), rs in sorted(g.items(), key=lambda kv: (kv[0][0], int(kv[0][1][3:]), kv[0][2], not kv[0][3])):
        cs = [r["call"] for r in rs]
        ok = sum(1 for r in rs if r["transient"]["affected_all_excl"] <= 5 and (r["transient"]["max_all_in_affected_excl"] or 0.0) <= 2000)
        print(f"| {mode} | {svc} | {rate} | {'第一次' if first else '后续'} | {len(rs)} | {ok} | {mm([r['transient']['affected_all_excl'] for r in rs], 1)} | "
              f"{mm([r['transient']['max_all_in_affected_excl'] or 0.0 for r in rs])} | {mm([c.get('hot_s') for c in cs], 1)} | "
              f"{mm([c.get('c2_cpu_s_30') for c in cs], 1)} | {mm([c.get('c2_full_s') for c in cs])} | {fmt(med([c.get('nio_max_5') for c in cs if c.get('nio_max_5') is not None]), 0)} | "
              f"{fmt(med([c.get('threads_before') for c in cs if c.get('threads_before') is not None]), 0)} → {fmt(med([c.get('threads_max_30') for c in cs if c.get('threads_max_30') is not None]), 0)} | "
              f"{pctf(med([r['steady']['unobserved']['change_excl'] for r in rs]))} / {pctf(max((r['steady']['unobserved']['change_excl'] for r in rs if r['steady']['unobserved']['change_excl'] is not None), default=None))} | "
              f"{pctf(med([r['steady']['hot']['change_excl'] for r in rs]))} / {pctf(max((r['steady']['hot']['change_excl'] for r in rs if r['steady']['hot']['change_excl'] is not None), default=None))} |")


def p_cpu(calls, views):
    print("\n### 增强开始后的 JVM CPU（% of one CPU；guard 从增强开始 5 秒后评估）\n")
    print("| 模式 | JDK | 负载 | 命令 | 调用数 | 前窗口 JVM CPU 中位 | 0~2 s 最大：中位 / 最大 | 3~5 s 最大：中位 / 最大 | 6~10 s 最大：中位 / 最大 | 回到 max(100, 2×前窗口) 以下的秒：各次 |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    g = collections.defaultdict(list)
    for c in calls:
        if c.get("cpu_after_start") is not None:
            g[(c["mode"], c["svc"], c["profile"], c["cmd"])].append(c)
    for (mode, svc, prof, cmd), cs in sorted(g.items(), key=lambda kv: (kv[0][0], int(kv[0][1][3:]), kv[0][2], kv[0][3])):
        f = lambda k: f"{fmt(med([c[k] for c in cs]), 0)} / {fmt(max((c[k] for c in cs if c[k] is not None), default=None), 0)}"
        print(f"| {mode} | {svc} | {prof} | {cmd} | {len(cs)} | {fmt(med([c['jvm_cpu_before_win'] for c in cs]), 0)} | {f('cpu_0_2')} | {f('cpu_3_5')} | {f('cpu_6_10')} | {', '.join(f"{c['hot_s']}（位置 {c['pos']}{'*' if c['first_enh'] else ''}）" for c in sorted(cs, key=lambda c: c['rep']))} |")


def p_cpu_before(calls):
    print("\n### CPU 预检（cpu_before，限额 4 CPU 的 %；阈值 50%）\n")
    print("| 模式 | JDK | 负载 | 调用数 | cpu_before 最小 / 中位 / 最大 | 前窗口 JVM CPU 中位（% of one CPU） | 拒绝次数 |")
    print("|---|---|---|---|---|---|---|")
    g = collections.defaultdict(list)
    for c in calls:
        g[(c["mode"], c["svc"], c["profile"])].append(c)
    for (mode, svc, prof), cs in sorted(g.items(), key=lambda kv: (kv[0][0], int(kv[0][1][3:]), kv[0][2])):
        v = [c["cpu_before"] for c in cs if c["cpu_before"] is not None]
        print(f"| {mode} | {svc} | {prof} | {len(cs)} | {min(v) if v else '-'} / {fmt(med(v), 0)} / {max(v) if v else '-'} | "
              f"{fmt(med([c['jvm_cpu_before_win'] for c in cs]), 0)} | {sum(1 for c in cs if c['check'] == 'cpu_usage')} |")


def p_errors_noise(rinfo):
    print("\n### 错误、噪声对照、会话后的状态（每次运行）\n")
    print("| 模式 | JDK | 负载 | 重复 | 请求：发出 / 成功 / 错误 / 丢弃（整个运行） | 未被观察典型 p99：前 / 调用之间 / 后窗口 (ms) | 变化：调用之间（秒数） / 后窗口 | /diag/live enhanced | 写入等待秒数（前窗口到后窗口） |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rinfo, key=lambda r: (r["meta"]["mode"], sort_key(r["meta"]))):
        m, e, n = r["meta"], r["errors"]["run"], r["noise"]
        print(f"| {m['mode']} | {m['svc']} | {m['profile']} | {m['rep']} | {e.get('sent', 0)} / {e.get('ok', 0)} / {e.get('err', 0)} / {e.get('drop', 0)} | "
              f"{fmt(n['before'], 2)} / {fmt(n['quiet'], 2)} / {fmt(n['after'], 2)} | {pctf(n['quiet_change'])}（{n['quiet_n']}） / {pctf(n['after_change'])} | "
              f"{r['live'].get('enhanced', r['live'].get('error', '-'))} | {len(r['waits'])} |")
    tot = collections.Counter()
    for r in rinfo:
        tot.update(r["errors"]["run"])
    print(f"\n- 合计：发出 {tot['sent']}，成功 {tot['ok']}，错误 {tot['err']}，丢弃 {tot['drop']}。")


def p_null(rinfo):
    print("\n### 噪声对照：没有调用的 20 秒窗口与前窗口之比（与稳态的计算相同）\n")
    print("| 模式 | 负载 | 窗口数 | 未被观察：中位 / p95 / 最大 | 未被观察 > 5% / > 15% 的窗口 | 被观察：中位 / p95 / 最大 | 被观察 > 20% 的窗口 |")
    print("|---|---|---|---|---|---|---|")
    g = collections.defaultdict(list)
    for r in rinfo:
        m = r["meta"]
        g[(m["mode"] + (f"-{m['variant']}" if m.get("variant") else ""), m["profile"])] += r["noise"]["null"]
    for (mode, prof), xs in sorted(g.items()):
        u = sorted(x[1] for x in xs if x[1] is not None)
        h = sorted(x[0] for x in xs if x[0] is not None)
        q = lambda v, p: v[min(len(v) - 1, int(p * len(v)))] if v else None
        print(f"| {mode} | {prof} | {len(xs)} | {pctf(med(u))} / {pctf(q(u, .95))} / {pctf(max(u, default=None))} | {sum(1 for x in u if x > 5)} / {sum(1 for x in u if x > 15)} | "
              f"{pctf(med(h))} / {pctf(q(h, .95))} / {pctf(max(h, default=None))} | {sum(1 for x in h if x > 20)} |")


def p_waits(rinfo):
    print("\n### 写入等待所在的秒（单独列出，不计入 Arthas 的影响）\n")
    anyw = False
    for r in sorted(rinfo, key=lambda r: (r["meta"]["mode"], sort_key(r["meta"]))):
        if not r["waits"]:
            continue
        anyw = True
        m = r["meta"]
        b0 = m["windows"]["before"][0]
        print(f"- {m['mode']} {m['svc']} {m['profile']} 重复 {m['rep']}：" + "；".join(f"+{s - b0} s {w}" for s, w in r["waits"][:10]) + ("……" if len(r["waits"]) > 10 else ""))
    if not anyw:
        print("- 无")


def p_func(raw):
    root = raw / "l2func"
    if not root.exists():
        return
    print("\n### 功能验证（s3_l2.py func）\n")
    print("| JDK | 检查 | 结果 | 依据 |")
    print("|---|---|---|---|")
    for f in sorted(root.glob("*/results.json"), key=lambda p: int(p.parent.name[3:])):
        for x in json.loads(f.read_text()):
            print(f"| {f.parent.name} | {x['check'].split(' ', 1)[1]} | {'通过' if x['pass'] else '未通过'} | {x['detail'][:400]} |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("raw")
    ap.add_argument("--out", help="directory for the views (default <raw>/analysis)")
    ap.add_argument("--json", help="write the per-call results here")
    a = ap.parse_args()
    raw = pathlib.Path(a.raw)
    out = pathlib.Path(a.out) if a.out else raw / "analysis"
    rinfo, calls, views = analyse(raw, out / "views")
    steady = [v for v in views if v["mode"] == "steady" and not v["variant"]]
    variant = [v for v in views if v["variant"]]
    enh = [v for v in steady if v["call"]["cmd"] in ENHANCING]
    jad = [v for v in steady if v["call"]["cmd"] == "jad"]
    plain = [v for v in views if v["mode"] == "plain" and not v["variant"]]
    p_runs(rinfo)
    p_calls(calls)
    p_summary(enh, jad)
    L2.print_groups(enh)
    p_transient(enh, "增强开始瞬态（steady：增强持续 30 秒，每次调用）")
    p_steady(enh)
    p_transient(jad, "jad（retransform 一次，每次调用）")
    if plain:
        p_transient(plain, "不带条件的调用（plain：count 1，作业在第一个结果后结束）")
    if variant:
        p_transient(variant, "JVM 已使用部分 CPU 限额（--burn，忙线程从预热开始）：增强开始瞬态")
        p_steady(variant)
    p_first(views)
    p_cpu(calls, views)
    p_cpu_before(calls)
    p_errors_noise(rinfo)
    p_null(rinfo)
    p_waits(rinfo)
    p_func(raw)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps({"runs": rinfo, "calls": calls, "views": views}, indent=1, default=str))


if __name__ == "__main__":
    main()

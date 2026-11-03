#!/usr/bin/env python3
"""The L2 thresholds of section 1 of docs/java-diagnostics-arthas-plan.md, computed from the raw data of a latency run with L2 jobs.

Works on bench.py runs (stage 0: calls.jsonl rows of kind "job", "reset", "stop", ...) and on runs whose calls.jsonl comes from
ja-call (stage 3D: rows of kind "jvm_arthas"; the job is the HTTP request whose command starts with an L2 command, see jobs()).
Per run:
  transient  from the second in which the first L2 job started: of the next 10 seconds, those whose p99 is above max(10 ms, 3 x
             the typical p99 of the before window) are affected. Counted on the observed flow (hot, as in stage 0) and on all
             flows together; the largest latency of any flow in those seconds; the worst second of the hot flow (p50 / p99 / max)
             and the JVM CPU in it; RedefineClasses safepoints in the first 5 s; the worst second of the 3 s after the first reset.
  steady     the seconds of the jobs from --settle seconds after each job's start to its end, without the seconds of the other
             calls (attach, reset, stop): typical p99 (median of the per-second p99) of the observed flow (hot) and of the
             unobserved flows (ping, work, db), and the change against the before window.
  write waits  seconds covered by a safepoint log write gap (pause_logwrite.py, >= --log-gap ms) or by a write of host_io_probe.py
             that waited >= 200 ms (host_io.jsonl in the run directory, or --host). They are listed separately; the "excl" columns
             are computed without them.
Groups (svc, command, rate): the median over the repetitions; with 3 or more, a verdict against the thresholds: transient
<= 5 affected seconds (all flows) and <= 2000 ms; unobserved steady change <= 15 % in every repetition and median <= 5 %;
observed steady change <= 20 % when the observed method runs at most 1000 times a second (no threshold above).

Usage: l2_threshold.py [--settle 10] [--log-gap 20] [--host host_io.jsonl] [--check-stage0 docs/arthas-stage0-report.md] <run dir | root>...
Times in the tables are milliseconds. Typical p99 and the change use the per-second histograms of ja-loadgen (bucket ratio 1.01).
"""
import argparse
import collections
import json
import pathlib
import re
import statistics
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pause_logwrite  # noqa: E402
from analyze import GC_OPS, bucket_value_us, load, pct, safepoints, typical_p99  # noqa: E402

HOT, UNOBSERVED = ("hot",), ("ping", "work", "db")
ALL = HOT + UNOBSERVED
L2_VERBS = ("watch", "trace", "stack", "monitor", "tt")
HOST_WAIT_S = 0.2


def per_second(rows, flows):
    secs = collections.defaultdict(collections.Counter)
    for r in rows:
        if r["flow"] in flows:
            c = secs[int(r["t"])]
            for b, n in r["h"].items():
                c[int(b)] += n
    return secs


def hmax(h):
    return bucket_value_us(max(h)) / 1000.0 if h else None


def java_major(d):
    m = re.search(r"java major=(\d+)", (d / "stdout.log").read_text(errors="ignore")) if (d / "stdout.log").exists() else None
    return int(m.group(1)) if m else 17


def jobs(calls):
    """(job spans [(start, end, command)], other call spans [(start, end)], first reset start or None), in epoch seconds.
    bench.py: rows of kind job / async_exec are jobs, the others (attach, reset, stop, cmd) are other calls.
    ja-call: one row per jvm_arthas call; steps.requests holds the HTTP requests with open/close in ms from the row's start. The
    first request whose command starts with an L2 command is the job; it ends where the next request other than pull_results (sent
    every 0.1 to 2 s while the job runs, each on a new connection) and a retried async_exec opens (interrupt_job, close_session,
    reset), or at its own close. The rest of the call (attach before, clean-up after) counts as other call time."""
    spans, other, reset = [], [], None
    for c in calls:
        if c.get("kind") == "call_total":
            continue
        if c.get("kind") in ("job", "async_exec"):
            spans.append((c["start"], c["end"], c.get("cmd", "")))
            continue
        if c.get("kind") == "jvm_arthas":
            reqs = sorted((c.get("steps") or {}).get("requests") or [], key=lambda r: r["open"])
            idx = next((i for i, r in enumerate(reqs) if (r.get("command") or "").split(" ")[0] in L2_VERBS), None)
            if idx is None:
                other.append((c["start"], c["end"]))
                continue
            j0 = c["start"] + reqs[idx]["open"] / 1000
            nxt = [r for r in reqs[idx + 1:] if r["open"] >= reqs[idx]["open"] and r.get("action") not in ("pull_results", "async_exec")]
            j1 = c["start"] + (nxt[0]["open"] if nxt else reqs[idx]["close"]) / 1000
            spans.append((j0, j1, reqs[idx]["command"]))
            other += [(c["start"], j0), (j1, c["end"])]
            rs = [r for r in reqs[idx + 1:] if r.get("command") == "reset" or r.get("action") == "reset"]
            if rs and reset is None:
                reset = c["start"] + rs[0]["open"] / 1000
            continue
        other.append((c["start"], c["end"]))
        if c.get("kind") == "reset" and reset is None:
            reset = c["start"]
    return sorted(spans), other, reset


def write_waits(d, log_gap_ms, host):
    """{second: reason} for the seconds of log write gaps and of host probe writes that waited 200 ms or more."""
    out = {}
    sp = d / "safepoint.log"
    if sp.exists():
        for a, b, op, where, lost in pause_logwrite.spans(sp, log_gap_ms):
            for s in range(int(a), int(b) + 1):
                out.setdefault(s, f"log write gap {lost:.0f} ms ({op})")
    hrows = list(host)
    if (d / "host_io.jsonl").exists():
        hrows += load(d / "host_io.jsonl")
    for r in hrows:
        if r.get("kind") == "write" and r["seconds"] >= HOST_WAIT_S:
            for s in range(int(r["t"]), int(r["t"] + r["seconds"]) + 1):
                out.setdefault(s, f"host probe write {r['seconds']:.2f} s ({pathlib.Path(r['dir']).name})")
    return out


def jvm_cpu(d):
    cpu, prev = {}, None
    for r in load(d / "metrics.jsonl"):
        if "ticks" not in r:
            continue
        if prev is not None:
            cpu[int(r["t"])] = (r["ticks"] - prev["ticks"]) / (r["t"] - prev["t"])
        prev = r
    return cpu


def analyze_run(d, settle, log_gap_ms, host):
    meta = json.loads((d / "meta.json").read_text())
    rows = load(d / "load.jsonl")
    calls = load(d / "calls.jsonl") if (d / "calls.jsonl").exists() else []
    spans, other, reset = jobs(calls)
    if not spans:
        return None
    hot, unob, allf = per_second(rows, HOT), per_second(rows, UNOBSERVED), per_second(rows, ALL)
    b0, b1 = meta["windows"]["before"]
    typ = lambda secs, excl=(): typical_p99([secs[s] for s in range(b0, b1) if s in secs and s not in excl])
    waits = write_waits(d, log_gap_ms, host)
    t_hot, t_unob, t_all = typ(hot), typ(unob), typ(allf)
    # transient
    s0 = int(spans[0][0])
    win = [s for s in range(s0, s0 + 10) if s in hot]
    thr_hot, thr_all = max(10.0, 3 * t_hot), max(10.0, 3 * t_all)
    aff_hot = [s for s in win if pct(hot[s], .99) > thr_hot]
    aff_all = [s for s in win if s in allf and pct(allf[s], .99) > thr_all]
    worst = max(win, key=lambda s: pct(hot[s], .99))
    cpu = jvm_cpu(d)
    sps = safepoints(d, java_major(d))
    first5 = [e for e in sps if s0 <= e[0] < s0 + 6]
    red = [e for e in first5 if "redefine" in e[1].lower()]
    rs = None
    if reset is not None:
        r0 = int(reset)
        cand = [s for s in range(r0, r0 + 3) if s in hot]
        if cand:
            w = max(cand, key=lambda s: pct(hot[s], .99))
            rs = (pct(hot[w], .99), hmax(hot[w]))
    trans = {"start": s0, "thr_hot": thr_hot, "affected_hot": len(aff_hot), "affected_all": len(aff_all),
             "affected_all_excl": len([s for s in aff_all if s not in waits]),
             "max_all_in_affected": max((hmax(allf[s]) for s in aff_all), default=None),
             "max_all_in_affected_excl": max((hmax(allf[s]) for s in aff_all if s not in waits), default=None),
             "max_all_10s": max((hmax(allf[s]) for s in range(s0, s0 + 10) if s in allf), default=None),
             "worst": (pct(hot[worst], .5), pct(hot[worst], .99), hmax(hot[worst])), "worst_cpu": cpu.get(worst, 0.0),
             "redefine": (len(red), max((e[2] for e in red), default=0.0)),
             "other_stw_max": max((e[2] for e in first5 if not GC_OPS.match(e[1]) and "redefine" not in e[1].lower()), default=0.0),
             "reset": rs, "waits_in_window": sorted(s - s0 for s in range(s0, s0 + 10) if s in waits)}
    # steady
    other_secs = {s for a, b in other for s in range(int(a), int(b) + 1)}
    job_secs = sorted({s for a, b, _ in spans for s in range(int(a) + settle, int(b) + 1)} - other_secs)
    st = {}
    for name, secs, base in (("hot", hot, t_hot), ("unobserved", unob, t_unob)):
        v = typical_p99([secs[s] for s in job_secs if s in secs])
        ve = typical_p99([secs[s] for s in job_secs if s in secs and s not in waits])
        be = typ(secs, waits)
        st[name] = {"before": base, "during": v, "change": (v / base - 1) * 100 if v and base else None,
                    "before_excl": be, "during_excl": ve, "change_excl": (ve / be - 1) * 100 if ve and be else None}
    st["secs"] = len(job_secs)
    st["waits"] = len([s for s in job_secs if s in waits])
    scen = meta.get("scenario", "")
    cmd = scen.split(":")[1] if ":" in scen else (spans[0][2].split(" ")[0] if spans[0][2] else "?")
    rate = {"p10k": 10000, "p1k": 1000}.get(meta.get("profile"), meta.get("rate"))
    win_waits = sorted((s, waits[s]) for s in waits if b0 <= s < (meta["windows"].get("after") or meta["windows"]["during"])[1])
    prefix = scen.split(":")[0]
    return {"dir": str(d), "svc": meta["svc"], "scenario": scen, "cmd": cmd + (f"（{prefix}）" if prefix not in ("l2", "") else ""),
            "rate": rate, "rep": meta["rep"], "typ_before": {"hot": t_hot, "unobserved": t_unob, "all": t_all},
            "transient": trans, "steady": st, "waits": win_waits}


def fmt(x, n=1):
    return "-" if x is None else f"{x:.{n}f}"


def pctf(x):
    return "-" if x is None else f"{x:+.0f}%"


def print_runs(res):
    print("### 增强开始瞬态（每次运行）\n")
    print("| JDK | 命令 | 速率 | 重复 | 超阈值的秒数，hot / 全部流 / 全部流去掉写入等待 | 这些秒内所有流的最大延迟 (ms)，含 / 去掉写入等待 | 10 秒内所有流的最大延迟 (ms) | "
          "最差一秒 p50 / p99 / 最大 (ms) | 该秒 JVM CPU % | RedefineClasses（次数，最大 ms） | reset 后 3 秒内最差 p99 / 最大 (ms) | 10 秒内的写入等待秒（相对开始） |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in res:
        t = r["transient"]
        w = t["worst"]
        rs = f"{t['reset'][0]:.1f} / {t['reset'][1]:.1f}" if t["reset"] else "-"
        print(f"| {r['svc']} | {r['cmd']} | {r['rate']} | {r['rep']} | {t['affected_hot']} / {t['affected_all']} / {t['affected_all_excl']} | "
              f"{fmt(t['max_all_in_affected'])} / {fmt(t['max_all_in_affected_excl'])} | {fmt(t['max_all_10s'])} | {w[0]:.1f} / {w[1]:.1f} / {w[2]:.1f} | "
              f"{t['worst_cpu']:.0f} | {t['redefine'][0]}, {t['redefine'][1]:.1f} | {rs} | {t['waits_in_window'] or '-'} |")
    print("\n### 稳态（每次运行）\n")
    print("| JDK | 命令 | 速率 | 重复 | 统计的作业秒数（其中写入等待） | 前窗口典型 p99，被观察 / 未被观察 (ms) | 作业期间典型 p99，被观察 / 未被观察 (ms) | 变化，被观察 / 未被观察 | 去掉写入等待后的变化，被观察 / 未被观察 |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in res:
        s = r["steady"]
        h, u = s["hot"], s["unobserved"]
        print(f"| {r['svc']} | {r['cmd']} | {r['rate']} | {r['rep']} | {s['secs']}（{s['waits']}） | {fmt(h['before'], 2)} / {fmt(u['before'], 2)} | "
              f"{fmt(h['during'], 2)} / {fmt(u['during'], 2)} | {pctf(h['change'])} / {pctf(u['change'])} | {pctf(h['change_excl'])} / {pctf(u['change_excl'])} |")
    print("\n### 写入等待所在的秒（单独列出）\n")
    any_w = False
    for r in res:
        if r["waits"]:
            any_w = True
            s0 = r["transient"]["start"]
            print(f"- {r['svc']} {r['cmd']} {r['rate']} 重复 {r['rep']}：" + "；".join(f"作业开始 {s - s0:+d} 秒 {why}" for s, why in r["waits"][:12])
                  + ("……" if len(r["waits"]) > 12 else ""))
    if not any_w:
        print("- 无")


def print_groups(res):
    print("\n### 按 JDK、命令、速率汇总（重复的中位数；3 次以上给出判定）\n")
    print("| JDK | 命令 | 速率 | 重复次数 | 超阈值的秒数（全部流，去掉写入等待）中位 / 最大 | 这些秒内最大延迟 (ms) 中位 / 最大 | 未被观察变化：中位 / 最大 | 被观察变化：中位 / 最大 | 判定 |")
    print("|---|---|---|---|---|---|---|---|---|")
    g = collections.defaultdict(list)
    for r in res:
        g[(r["svc"], r["cmd"], r["rate"])].append(r)
    for (svc, cmd, rate), rs in sorted(g.items(), key=lambda kv: (int(re.sub(r"\D", "", kv[0][0]) or 0), kv[0][1], kv[0][2] or 0)):
        aff = [r["transient"]["affected_all_excl"] for r in rs]
        mx = [r["transient"]["max_all_in_affected_excl"] or 0.0 for r in rs]
        un = [r["steady"]["unobserved"]["change_excl"] for r in rs if r["steady"]["unobserved"]["change_excl"] is not None]
        ob = [r["steady"]["hot"]["change_excl"] for r in rs if r["steady"]["hot"]["change_excl"] is not None]
        verdict = "重复不足 3 次，不判定"
        if len(rs) >= 3 and un:
            parts = [f"瞬态{'达到' if max(aff) <= 5 and max(mx) <= 2000 else '未达到'}",
                     f"未被观察{'达到' if max(un) <= 15 and statistics.median(un) <= 5 else '未达到'}"]
            if rate is not None and rate <= 1000 and ob:
                parts.append(f"被观察{'达到' if max(ob) <= 20 else '未达到'}")
            else:
                parts.append("被观察：速率高于 1000 次/秒，不承诺")
            verdict = "；".join(parts)
        med = lambda xs: statistics.median(xs) if xs else None
        print(f"| {svc} | {cmd} | {rate} | {len(rs)} | {med(aff)} / {max(aff)} | {fmt(med(mx))} / {fmt(max(mx))} | {pctf(med(un))} / {pctf(max(un) if un else None)} | "
              f"{pctf(med(ob))} / {pctf(max(ob) if ob else None)} | {verdict} |")


# --check-stage0: the two tables of section 3.5.5 of the stage-0 report -----------------------------------------------------------
def report_tables(path):
    text = pathlib.Path(path).read_text()
    sec = text.split("#### 3.5.5", 1)[1].split("#### 3.5.6", 1)[0]
    tables, cur = [], None
    for ln in sec.splitlines():
        if ln.startswith("|"):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if cur is None:
                cur = [cells]
            elif not cells[0].startswith("---"):
                cur.append(cells)
        elif cur is not None:
            tables.append(cur)
            cur = None
    if cur:
        tables.append(cur)
    return tables[0], tables[1]


def nums(s):
    return [float(x) for x in re.findall(r"-?\d+(?:\.\d+)?", s.replace("−", "-"))]


def check_stage0(res, path):
    """The stage-0 steady state left out the first 3 s of each job (analyze.call_seconds); compare with --settle 3."""
    trans, steady = report_tables(path)
    by = {(r["svc"].replace("jdk", ""), r["cmd"], r["rate"], r["rep"]): r for r in res}
    mism, n = [], 0
    for row in trans[1:]:
        jdk, cmd, rate, rep = row[0], row[1], int(nums(row[2])[0]), int(row[3])
        r = by.get((jdk, cmd, rate, rep))
        if not r:
            mism.append(f"瞬态 {row[:4]}：没有这次运行")
            continue
        t = r["transient"]
        mine = [t["affected_hot"], *[round(x, 1) for x in t["worst"]], round(t["worst_cpu"]), t["redefine"][0], round(t["redefine"][1], 1)]
        if t["reset"]:
            mine += [round(t["reset"][0], 1), round(t["reset"][1], 1)]
        want = nums(row[4]) + nums(row[5]) + nums(row[6]) + nums(row[7]) + nums(row[8])[:2]
        n += 1
        if [float(x) for x in mine] != want[:len(mine)]:
            mism.append(f"瞬态 JDK {jdk} {cmd} {rate} 重复 {rep}：报告 {want}，脚本 {mine}")
    for row in steady[1:]:
        jdk, cmd = row[0], row[1]
        rn = nums(row[2])
        rate, rep = int(rn[0]), int(rn[1]) if len(rn) > 1 else 1
        r = by.get((jdk, cmd, rate, rep))
        if not r:
            mism.append(f"稳态 {row[:3]}：没有这次运行")
            continue
        s = r["steady"]
        if s["hot"]["during"] is None:
            mism.append(f"稳态 JDK {jdk} {cmd} {row[2]}：脚本没有作业秒")
            continue
        # The stage-0 report took the change from the p99 values rounded to 0.01 ms.
        hb, ub, hd, ud = (round(x, 2) for x in (s["hot"]["before"], s["unobserved"]["before"], s["hot"]["during"], s["unobserved"]["during"]))
        mine = [hb, ub, hd, ud, round((hd / hb - 1) * 100), round((ud / ub - 1) * 100)]
        want = nums(row[3]) + nums(row[4]) + nums(row[5])[:2]
        n += 1
        if [float(x) for x in mine] != want:
            mism.append(f"稳态 JDK {jdk} {cmd} {row[2]}：报告 {want}，脚本 {mine}")
    print(f"\n### 与阶段 0 报告 3.5.5 的核对：{n} 行，不一致 {len(mism)} 行\n")
    for m in mism:
        print("- " + m)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--settle", type=int, default=10, help="seconds after each job's start left out of the steady state")
    ap.add_argument("--log-gap", type=float, default=20, help="safepoint log write gaps at or over this many ms are write waits")
    ap.add_argument("--host", help="host_io.jsonl of a host probe that ran beside the runs")
    ap.add_argument("--check-stage0", help="compare with the two tables of section 3.5.5 of this report")
    ap.add_argument("--json", help="also write the per-run results here")
    ap.add_argument("dirs", nargs="+")
    a = ap.parse_args()
    host = load(pathlib.Path(a.host)) if a.host else []
    res = []
    for x in a.dirs:
        p = pathlib.Path(x)
        for d in ([p] if (p / "meta.json").exists() else sorted(q.parent for q in p.rglob("meta.json"))):
            r = analyze_run(d, a.settle, a.log_gap, host)
            if r:
                res.append(r)
    res.sort(key=lambda r: (int(re.sub(r"\D", "", r["svc"]) or 0), r["cmd"], -(r["rate"] or 0), r["rep"]))
    print_runs(res)
    print_groups(res)
    if a.check_stage0:
        check_stage0(res, a.check_stage0)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(res, indent=1, default=str))


if __name__ == "__main__":
    main()

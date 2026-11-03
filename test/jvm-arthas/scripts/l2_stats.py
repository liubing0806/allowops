#!/usr/bin/env python3
"""Per-second statistics of the item 5 runs that analyze.py does not print (docs/arthas-stage0-report.md, section 3.5).

Usage: l2_stats.py <bench root> freeze    L2 runs: seconds of the jobs (without the first 10 s of each job) whose p99 of the hot flow is above 20 ms / 100 ms
       l2_stats.py <bench root> cpu       L2 runs: mean JVM CPU in the before window, in the job seconds and in the after window
       l2_stats.py <bench root> stalls    all runs: windows that contain at least one second with a p99 above 100 ms, and what happened in them
"""
import json
import pathlib
import statistics
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import transitions as T


def runs(root, l2_only):
    for done in sorted(pathlib.Path(root).rglob("done")):
        d = done.parent
        m = json.load(open(d / "meta.json"))
        if l2_only and (not m["scenario"].startswith("l2") or m["scenario"].startswith("l2stuck")):
            continue
        yield d, m


def label(m):
    cmd = m["scenario"].split(":")[1]
    return cmd + ("（保持）" if m["scenario"].startswith("l2keep") else "")


def jvm_cpu(d):
    cpu, prev = {}, None
    for ln in open(d / "metrics.jsonl"):
        r = json.loads(ln)
        if "ticks" not in r:
            continue
        if prev is not None:
            cpu[int(r["t"])] = (r["ticks"] - prev["ticks"]) / (r["t"] - prev["t"])
        prev = r
    return cpu


def job_seconds(d, per):
    jobs = [json.loads(x) for x in open(d / "calls.jsonl")]
    jobs = [c for c in jobs if c["kind"] == "job"]
    return jobs, [x for j in jobs for x in range(int(j["start"]) + 10, int(j["end"]) - 1) if x in per]


def freeze(root):
    print("| JDK | 命令 | 观察速率 | 重复 | 统计的作业秒数 | p99 > 20 ms 的秒数 | p99 > 100 ms 的秒数 | 最差一秒的 p99 / 最大延迟 (ms) | p99 > 20 ms 的秒（相对第一个作业开始） |")
    print("|---|---|---|---|---|---|---|---|---|")
    for d, m in runs(root, True):
        per = T.per_second_hist(d)
        jobs, secs = job_seconds(d, per)
        if not jobs:
            continue
        first = int(jobs[0]["start"])
        p = {x: T.pct(per[x], .99) for x in secs}
        worst = max(secs, key=lambda x: p[x])
        over = [x - first for x in secs if p[x] > 20]
        print(f"| {m['svc']} | {label(m)} | {'10000' if m['profile'] == 'p10k' else '1000'} 次/秒 | {m['rep']} | {len(secs)} | {len(over)} | "
              f"{sum(1 for x in secs if p[x] > 100)} | {p[worst]:.1f} / {T.val(max(per[worst])):.1f} | {over[:12]} |")


def cpu(root):
    print("| JDK | 命令 | 观察速率 | 重复 | 前窗口 JVM CPU % | 作业期间 JVM CPU % | 后窗口 JVM CPU % | 作业 / 前 |")
    print("|---|---|---|---|---|---|---|---|")
    for d, m in runs(root, True):
        per = T.per_second_hist(d)
        jobs, secs = job_seconds(d, per)
        c = jvm_cpu(d)
        if not jobs:
            continue
        avg = lambda a, b: statistics.mean(c[x] for x in range(a, b) if x in c)
        b, j, a = avg(*m["windows"]["before"]), statistics.mean(c[x] for x in secs if x in c), avg(*m["windows"]["after"])
        print(f"| {m['svc']} | {label(m)} | {'10000' if m['profile'] == 'p10k' else '1000'} 次/秒 | {m['rep']} | {b:.1f} | {j:.1f} | {a:.1f} | {j / b:.2f} |")


def stalls(root):
    rows = []
    for d, m in runs(root, False):
        per = T.per_second_hist(d)
        r = {"run": f"{m['svc']} {m['scenario']} {m['profile']} rep {m['rep']}", "scenario": m["scenario"]}
        for name, (a, b) in m["windows"].items():
            r[name] = [x - a for x in range(a, b) if x in per and T.pct(per[x], .99) > 100]
        rows.append(r)
    print(f"运行数：{len(rows)}")
    for name in ("before", "after"):
        k = [r for r in rows if r[name]]
        print(f"- {name} 窗口含 p99 > 100 ms 的秒：{len(k)} / {len(rows)}")
        for r in k:
            print(f"    - {r['run']}：窗口内第 {r[name]} 秒")
    noop = [r for r in rows if r["scenario"] == "noop"]
    print(f"- noop 的 during 窗口含这样的秒：{sum(1 for r in noop if r['during'])} / {len(noop)}")
    non_l2 = [r for r in rows if not r["scenario"].startswith("l2")]
    k = [r for r in non_l2 if r["during"]]
    print(f"- 非 L2 场景的 during 窗口含这样的秒：{len(k)} / {len(non_l2)}")
    for r in k:
        print(f"    - {r['run']}：窗口内第 {r['during']} 秒")


if __name__ == "__main__":
    {"freeze": freeze, "cpu": cpu, "stalls": stalls}[sys.argv[2]](sys.argv[1])

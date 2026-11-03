#!/usr/bin/env python3
"""Condensed tables for the item 5 section of docs/arthas-stage0-report.md, read from the markdown that `analyze.py --md` wrote
(and, for `l2`, from the output of `transitions.py --table`).

Usage: report_digest.py <summary.md> noise
       report_digest.py <summary.md> attach
       report_digest.py <summary.md> l1
       report_digest.py <summary.md> l2 <transitions table.md>
       report_digest.py <summary.md> windows
"""
import collections
import sys

ORDER = {"jdk8": 0, "jdk11": 1, "jdk17": 2, "jdk21": 3}


def rows(path):
    """Splits the markdown into the three tables of analyze.py. The 'secs' table repeats column names, so it is kept positional."""
    main, secs, dur = [], [], []
    cur, hdr = None, None
    for ln in open(path):
        if not ln.startswith("|"):
            continue
        c = [x.strip() for x in ln.strip().strip("|").split("|")]
        if c[0] == "svc":
            hdr = c
            cur = main if "window" in c else secs if "transition secs" in c else dur if "kind" in c else None
            continue
        if cur is None or c[0].startswith("---"):
            continue
        cur.append(c if cur is secs else dict(zip(hdr, c)))
    return main, secs, dur


def key(r):
    return (r["svc"], r["scenario"], r["profile"], r["rep"]) if isinstance(r, dict) else tuple(r[:4])


def sort_key(k):
    return (ORDER[k[0]], k[1], k[2], int(k[3]))


# positions in a 'secs' row
S_FLOW, S_TRANS_N, S_TRANS_P99, S_TRANS_MAX, S_JOB_N, S_JOB_P99, S_JOB_TYP, S_IDLE_N, S_IDLE_P99, S_IDLE_TYP, S_B_P99, S_B_TYP, S_NONGC = 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 21


def main():
    path, what = sys.argv[1], sys.argv[2]
    main_rows, sec_rows, dur_rows = rows(path)
    win = collections.defaultdict(dict)
    for r in main_rows:
        win[key(r) + (r["flow"],)][r["window"]] = r
    secs = {tuple(r[:4]) + (r[S_FLOW],): r for r in sec_rows}
    dur = collections.defaultdict(dict)
    for r in dur_rows:
        dur[key(r)][r["kind"]] = r
    keys = sorted({k[:4] for k in win}, key=sort_key)

    if what == "noise":
        print("| JDK | 重复 | 典型 p99 前 / 中 / 后 (ms) | 合并 p99 前 / 中 / 后 (ms) | 合并 p99 增幅，中 [95% CI] | 合并 p99 增幅，后 [95% CI] | 其他进程占用的应用 CPU %，前 / 中 / 后 |")
        print("|---|---|---|---|---|---|---|")
        for k in keys:
            if k[1] != "noop":
                continue
            w = win[k + ("hot",)]
            trio = lambda col: " / ".join(w[x][col] for x in ("before", "during", "after"))
            print(f"| {k[0]} | {k[3]} | {trio('typical p99 ms')} | {trio('p99 ms')} | {w['during']['Δp99 vs before [95% CI]']} | {w['after']['Δp99 vs before [95% CI]']} | {trio('other CPU on app cpus %')} |")
    elif what in ("attach", "l1"):
        print("| JDK | 场景 | 重复 | 调用次数 | 调用相关秒数 | 这些秒的 p99 (ms) | 这些秒的最大延迟 (ms) | 前窗口典型 p99 (ms) | 其余秒的 p99 (ms) | 单次调用总时长，中位 / 最大 (ms) | 命令耗时，中位 (ms) | 非 GC STW 最大 (ms) |")
        print("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for k in keys:
            if not k[1].startswith("attach" if what == "attach" else "l1"):
                continue
            s = secs.get(k + ("hot",))
            if not s:
                continue
            d = dur[k]
            if "call_total" in d:
                tot = f"{d['call_total']['median']} / {d['call_total']['max']}"
            else:
                tot = f"仅 attach：{d['attach']['median']} / {d['attach']['max']}"
            print(f"| {k[0]} | {k[1]} | {k[3]} | {d['attach']['n']} | {s[S_TRANS_N]} | {s[S_TRANS_P99]} | {s[S_TRANS_MAX]} | {s[S_B_TYP]} | {s[S_IDLE_P99]} | {tot} | {d.get('cmd', {}).get('median', '-')} | {s[S_NONGC]} |")
    elif what == "windows":
        print("| JDK | 场景 | 速率 | 重复 | 合并 p99 前 / 中 / 后 (ms) | 增幅 中 [95% CI] | 增幅 后 [95% CI] | 请求数 | 错误 | >100 ms 的请求数 前 / 中 / 后 | 其他进程占用的应用 CPU % 前 / 中 / 后 |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
        for k in keys:
            w = win[k + ("hot",)]
            trio = lambda col: " / ".join(w[x][col] for x in ("before", "during", "after"))
            print(f"| {k[0]} | {k[1]} | {k[2]} | {k[3]} | {trio('p99 ms')} | {w['during']['Δp99 vs before [95% CI]']} | {w['after']['Δp99 vs before [95% CI]']} | "
                  f"{sum(int(w[x]['n']) for x in w)} | {sum(int(w[x]['err']) for x in w)} | {trio('>100ms')} | {trio('other CPU on app cpus %')} |")
    elif what == "l2":
        trans = {}
        for ln in open(sys.argv[3]):
            c = [x.strip() for x in ln.strip().strip("|").split("|")]
            if len(c) > 10 and c[0].startswith("jdk"):
                trans[tuple(c[:4])] = c
        print("| JDK | 命令 | 观察速率 | 重复 | 前窗口典型 p99，被观察 / 未被观察 (ms) | 作业期间典型 p99，被观察 / 未被观察 (ms) | 典型 p99 变化，被观察 / 未被观察 | 增强开始后 10 秒内超阈值的秒数 | 最差一秒 p50 / p99 / 最大 (ms) | 最差一秒 JVM CPU % | redefine STW（次数，最大 ms） | reset 后 3 秒内最差 p99 / 最大 (ms) |")
        print("|---|---|---|---|---|---|---|---|---|---|---|---|")
        change = lambda a, b: f"{(float(b) / float(a) - 1) * 100:+.0f}%"
        for k in keys:
            if not k[1].startswith("l2") or k[1].startswith("l2stuck"):
                continue
            h, c, t = secs.get(k + ("hot",)), secs.get(k + ("control",)), trans.get(k)
            if not (h and c and t):
                continue
            print(f"| {k[0]} | {k[1].split(':')[1]}{'（保持）' if k[1].startswith('l2keep') else ''} | {'10000' if k[2] == 'p10k' else '1000'} 次/秒 | {k[3]} | {h[S_B_TYP]} / {c[S_B_TYP]} | {h[S_JOB_TYP]} / {c[S_JOB_TYP]} | {change(h[S_B_TYP], h[S_JOB_TYP])} / {change(c[S_B_TYP], c[S_JOB_TYP])} | {t[6]} | {t[7]} | {t[8]} | {t[9]} | {t[11]} |")


if __name__ == "__main__":
    main()

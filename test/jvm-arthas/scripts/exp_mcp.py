#!/usr/bin/env python3
"""Follow-up to item 1: with the shipped arthas.properties (arthas.mcpEndpoint=/mcp) and the agent argument mcpEndpoint= (empty),
is the MCP server running? If yes, can it run a command that disabledCommands switched off?"""
from ja import *

EXP = "item1-params"
INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})


def mcp(t, body, hdr=None):
    return t.api(method="POST", path="/mcp", body=body)


def probe(svc, flavor, opts_extra=""):
    t = Target(svc).up()
    dis = disabled_for(L1_COMMANDS)
    raw = f"telnetPort=-1;httpPort=18563;ip=127.0.0.1;password=@PW@;localConnectionNonAuth=false;mcpEndpoint=;disabledCommands={dis}"
    a = t.attach(flavor=flavor, raw_opts=raw)
    time.sleep(2)
    r = {"flavor": flavor, "attach_ok": a["ok"]}
    r["initialize"] = mcp(t, INIT)
    r["initialize_noauth"] = t.api(method="POST", path="/mcp", body=INIT, auth=False)
    r["listeners"] = [x["port"] for x in t.probe(secret=False)["listeners"]]
    r["arthas_threads"] = t.probe(secret=False)["arthas_threads"]
    r["stdout_mcp_lines"] = [ln for ln in t.logs().splitlines() if "mcp" in ln.lower()][:6]
    return r


if __name__ == "__main__":
    res = {"jdk17_stock": probe("jdk17", "stock"), "jdk17_minlog": probe("jdk17", "minlog")}
    write_json(EXP, "mcp-followup.json", res)
    for k, v in res.items():
        print(k, {"init_status": v["initialize"].get("status"), "init_noauth": v["initialize_noauth"].get("status"),
                  "body": (json.dumps(v["initialize"].get("body")) or "")[:300], "raw": (v["initialize"].get("raw_body") or "")[:200], "mcp_log": v["stdout_mcp_lines"][:3]})

#!/usr/bin/env python3
"""Profile the local scale harness with a Go source overlay; product sources stay unchanged."""
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
out.mkdir(mode=0o700, parents=True, exist_ok=True)
replace = {}
def overlay(relative, text):
    path = out / (relative.replace('/', '_'))
    path.write_text(text)
    replace[str(root / relative)] = str(path)

path = 'internal/store/store.go'
text = (root / path).read_text().replace('"context"', '"context"\n "github.com/liubing0806/allowops/test/perfprofile"')
text = text.replace('p, err := pgxpool.New(ctx, dsn)', '''config, err := pgxpool.ParseConfig(dsn)
 if err != nil { return nil, err }
 config.ConnConfig.Tracer = perfprofile.Tracer{}
 p, err := pgxpool.NewWithConfig(ctx, config)''')
overlay(path, text)
overlay('cmd/allowops-gateway/perfprofile.go', '''package main
import "github.com/liubing0806/allowops/test/perfprofile"
func init() { perfprofile.Serve() }
''')
path = 'test/scale/scale_test.go'
text = (root / path).read_text().replace('"bytes"', '"bytes"\n "github.com/liubing0806/allowops/test/perfprofile"')
text = text.replace('result, elapsed, jobErr := g.RunJob', 'perfprofile.Command("start")\n result, elapsed, jobErr := g.RunJob')
text = text.replace('stopDiag()', 'perfprofile.Command("stop")\n stopDiag()')
# Snapshot blocking backend SQL and transaction ages; never include bind values.
text = text.replace('rows.Close()\n\t\t\t}', '''rows.Close()
                rows, err = g.DB.Pool.Query(diagCtx, `SELECT a.pid, b.pid, coalesce(a.wait_event,''), a.query, b.query, extract(epoch from (clock_timestamp()-b.xact_start))::float8 FROM pg_stat_activity a CROSS JOIN LATERAL unnest(pg_blocking_pids(a.pid)) blocker(pid) JOIN pg_stat_activity b ON b.pid=blocker.pid WHERE a.datname=current_database()`)
                if err != nil { continue }
                for rows.Next() {
                    var waiter, holder int; var event, waitingSQL, holdingSQL string; var age float64
                    if rows.Scan(&waiter,&holder,&event,&waitingSQL,&holdingSQL,&age)==nil { t.Logf("LOCK waiter=%d holder=%d event=%s age=%.6f waiting=%q holding=%q", waiter,holder,event,age,waitingSQL,holdingSQL) }
                }
                rows.Close()
            }''')
overlay(path, text)
manifest = out / 'overlay.json'
manifest.write_text(json.dumps({'Replace': replace}))
env = dict(os.environ, ALLOWOPS_PROFILE_DIR=str(out), ALLOWOPS_REQUIRE_DOCKER='1', CGO_ENABLED='0')
subprocess.run(['go', 'build', '-overlay', str(manifest), '-tags=perfprofile', '-o', 'bin/allowops-gateway', './cmd/allowops-gateway'], cwd=root, env=env, check=True)
subprocess.run(['go', 'test', '-overlay', str(manifest), '-tags=scale,perfprofile', './test/scale', '-run=^TestScale$', '-count=1', '-v', '-timeout=30m'], cwd=root, env=env, check=True)

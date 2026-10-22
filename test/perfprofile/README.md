# Local scale profiling

Run from the repository root:

```sh
python3 test/perfprofile/run.py /tmp/allowops-profile-before > /tmp/allowops-profile-before.log 2>&1
```

Use a new private output directory for each run. This builds a temporary gateway
binary using Go source overlays and the `perfprofile` build tag, then runs the
same local Docker scale scenario. `make scale` rebuilds the normal gateway.
No production endpoint, flag, configuration, or dependency setting is changed.
The generated overlay and sources remain beside the profiles for inspection.

The job request window records CPU, blocking and mutex profiles plus SQL call
counts, cumulative/max client-observed durations, and pool acquisition durations.
Query durations include server waits, network and row consumption, but exclude
pool acquisition. SQL bind parameters are never recorded. The harness samples
blocking backend IDs, SQL and holder transaction age every 200 ms. Transaction
age is an upper bound on lock age, not an exact lock holding duration.

Before the job and after the response, the gateway records load average, heap
profiles after GC, Go memory statistics and `/proc/self/status`. Profiling and GC
add overhead; use ordinary `make scale` for acceptance and profile runs for
attribution. The job measurement retains the default batch size and all output,
authorization and audit operations. As in the ordinary harness, the response does
not imply all asynchronous output writes and audits have finished.

```sh
go tool pprof -top /tmp/allowops-profile-before/job.cpu
go tool pprof -top -cum /tmp/allowops-profile-before/job.block
go tool pprof -top /tmp/allowops-profile-before/job.mutex
go tool pprof -top -inuse_space /tmp/allowops-profile-before/online.heap
```

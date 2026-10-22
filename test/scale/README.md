# Local scale acceptance

Run `make scale` explicitly. It is excluded from `make test` by the `scale` build
tag. Docker must expose the local `/var/run/docker.sock`; neither external
database URLs nor remote Docker endpoints are accepted by the dependency fixtures.

The test starts the unchanged `bin/allowops-gateway` as a child process, with
default gateway/job limits, disposable PostgreSQL and SeaweedFS containers.
One simulator process creates 5000 independent Ed25519 keys, calls the real
Join RPC, verifies TLS against its generated CA, and opens 5000 mTLS gRPC
bidirectional streams using the agent's ALPN protocols. Each host pulls and
verifies the signed catalog before reporting a successful catalog load. No
product hooks are used.

The simulator sends increasing heartbeat sequence numbers and reports a
zero-duration, successful `noop` result with both empty output EOF messages and
their SHA-256 metadata. It does not spawn an operating-system command. The real
gateway performs authorization, scheduling, result validation, PostgreSQL
aggregation, audit and SeaweedFS output persistence. Authorization labels are
assigned only in the disposable fixture database, as Join does not grant them.

The three `RESULT` lines report measured values, fixed design thresholds and
pass/fail. A failure returns a nonzero exit code, after still attempting all
three measurements:

* 5000 streams and database ownership entries remain online for 50 seconds
  (longer than the default 45-second heartbeat timeout), with 5000 catalog reports.
* A 1000-host job returns a successful, complete summary within 10 seconds,
  including authorization and submission. The default batch size is 20.
* Restart elapsed time starts before SIGTERM and includes graceful drain,
  new process startup and all 5000 re-established streams. The pass threshold
  is 60 seconds; observation continues for up to 180 seconds to expose overruns.

CPU model/count, physical memory, Go version, Git HEAD and `uptime` are printed
before and after the test. Gateway RSS and PostgreSQL active wait-event samples
at 200ms intervals are printed for bottleneck investigation. Run while other
workers are idle where possible. This harness does not expose a product pprof
endpoint; introducing one requires approval.

`make bench-opa` runs the existing P5A Go benchmark three times, with 500 rules
and 1000 hosts. The benchmark uses identical rule conditions and identical host
labels, so it includes the engine's rule compaction and per-batch label cache.
It measures batch evaluation and allocations, excluding engine initialization.
Its timing does not describe 1000 distinct label sets or 500 distinct conditions.

#!/usr/bin/env bash
set -euo pipefail
/tests/root-tests -test.v -test.run TestContainer
/tests/agent-tests -test.v -test.run TestRootJoinTransfersIdentity

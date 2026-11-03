#!/bin/sh
set -eu
pin=$(sed -n 's/^ca_pin: //p' /etc/allowops/agent.yaml)
upstream=$(sed -n 's/^upstream: //p' /etc/allowops/agent.yaml)
allowops-agent join --upstream "$upstream" --token-file /run/join.token --ca-pin "$pin"
rm -f /run/join.token
exec setpriv --reuid=allowops --regid=allowops --clear-groups /usr/bin/allowops-agent run

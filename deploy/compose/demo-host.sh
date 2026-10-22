#!/bin/sh
set -eu
if [ ! -f /var/lib/allowops/identity.json ]; then
    if [ ! -s "${JOIN_TOKEN_FILE:?}" ]; then
        echo 'A real gateway-issued join token file is required; see README.md (G41).' >&2
        exit 1
    fi
    ca_pin=$(sed -n 's/^ca_pin: //p' /etc/allowops/agent.yaml)
    allowops-agent join --upstream https://gateway:8443 --token-file "$JOIN_TOKEN_FILE" --ca-pin "$ca_pin"
fi
exec setpriv --reuid=65532 --regid=65532 --clear-groups /usr/bin/allowops-agent run

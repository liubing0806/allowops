#!/bin/sh
set -eu

# Debian passes "remove"; RPM passes 0 for removal and 1+ during an upgrade.
case "${1:-}" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl stop allowops-agent.service
        fi
        systemctl --no-reload disable allowops-agent.service
        ;;
esac

#!/bin/sh
set -eu

if command -v visudo >/dev/null 2>&1; then
    visudo -cf /etc/sudoers.d/allowops
else
    echo "allowops: visudo not found, skipping sudoers validation (sudo not installed)" >&2
fi
# dpkg may unpack directory entries using numeric root IDs; set state ownership.
install -d -o allowops -g allowops -m 0700 /var/lib/allowops
install -d -o root -g root -m 0700 /var/lib/allowops-exec

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
# Enable on boot as specified in architecture-decisions.md; never start on install.
systemctl --no-reload enable allowops-agent.service

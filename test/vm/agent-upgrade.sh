#!/bin/sh
# Test-only upgrade action: installs a staged package with the system package
# manager, then restarts the agent from a transient systemd timer so the task
# result reaches the gateway first. Production actions install from a repository.
set -eu
package=/var/tmp/allowops-upgrade/$1
if command -v dpkg >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$package.deb"
else
    yum --disablerepo='*' install -y "$package.rpm"
fi
systemd-run --on-active=5 --timer-property=AccuracySec=1s /usr/bin/systemctl restart allowops-agent.service 2>&1
echo "upgrade installed; restart scheduled"

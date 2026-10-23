#!/bin/sh
# Installs one allowops-agent version from the host's configured package
# repository, then restarts the agent from a transient systemd timer so the
# task result reaches the gateway first. Package signatures are checked by
# apt/yum according to the repository configuration.
set -eu
version=$1

installed() {
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Version}' allowops-agent 2>/dev/null || true
    elif current=$(rpm -q --qf '%{VERSION}' allowops-agent 2>/dev/null); then
        printf %s "$current"
    fi
}

current=$(installed)
if [ "$current" = "$version" ]; then
    echo "allowops-agent $version already installed; no restart"
    exit 0
fi

if command -v dpkg-query >/dev/null 2>&1; then
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q allowops-agent="$version"
else
    yum -q clean expire-cache
    yum upgrade -y -q allowops-agent-"$version"
fi

# Downgrades are refused: apt fails, yum upgrade leaves the package and may exit 0.
current=$(installed)
if [ "$current" != "$version" ]; then
    echo "allowops-agent ${current:-not installed} after install, expected $version; agent not restarted" >&2
    exit 1
fi
systemd-run --on-active=5 --timer-property=AccuracySec=1s /usr/bin/systemctl restart allowops-agent.service 2>&1
echo "allowops-agent $version installed; restart scheduled in 5s"

#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "FAIL at line $LINENO: $BASH_COMMAND (exit $status)" >&2; exit "$status"' ERR

package=/packages/$1
format=$2
version=$3

bootstrap() {
    if [[ $format == rpm ]]; then
        if [[ -f /etc/centos-release ]]; then
            # CentOS 7 repositories are archived; retain RPM GPG verification.
            sed -i \
                -e 's|^mirrorlist=|#mirrorlist=|' \
                -e 's|^#baseurl=http://mirror.centos.org/centos/$releasever|baseurl=https://archive.kernel.org/centos-vault/7.9.2009|' \
                /etc/yum.repos.d/CentOS-*.repo
            yum -y --disablerepo=updates --disablerepo=extras \
                install sudo shadow-utils systemd diffutils procps-ng
        else
            dnf -y install sudo shadow-utils systemd diffutils procps-ng
        fi
    else
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends sudo passwd systemd diffutils procps
    fi
}

if ! bootstrap > /tmp/bootstrap.log 2>&1; then
    cat /tmp/bootstrap.log >&2
    exit 1
fi

install_package() {
    if [[ $format == rpm ]]; then
        rpm -Uvh --replacepkgs "$package"
    else
        dpkg --force-confold -i "$package"
    fi
}

if [[ $format == rpm ]]; then
    rpm -qlvp "$package"
    [[ $(rpm -qp --qf '%{PAYLOADCOMPRESSOR}' "$package") == gzip ]]
    requirements=$(rpm -qp --requires "$package")
    grep -qx sudo <<< "$requirements"
    ! grep -Eq 'rpmlib\((RichDependencies|PayloadIsZstd)\)' <<< "$requirements"
    if [[ ! -f /etc/centos-release ]]; then
        for relation in recommends suggests supplements enhances; do
            [[ -z $(rpm -qp --"$relation" "$package") ]]
        done
    fi
else
    dpkg -c "$package"
    dpkg-deb -e "$package" /tmp/control
    grep -qx /etc/allowops/agent.yaml /tmp/control/conffiles
    [[ $(dpkg-deb -f "$package" Recommends) == sudo ]]
fi

install_package

assert_stat() {
    local expected=$1 path=$2 actual
    actual=$(stat -c '%U:%G %a' "$path")
    if [[ $actual != "$expected" ]]; then
        echo "$path: expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

assert_stat 'root:root 755' /usr/bin/allowops-agent
assert_stat 'root:root 755' /usr/libexec/allowops
assert_stat 'root:root 755' /usr/libexec/allowops/allowops-exec
assert_stat 'root:root 644' /usr/lib/systemd/system/allowops-agent.service
assert_stat 'root:root 440' /etc/sudoers.d/allowops
assert_stat 'root:root 755' /etc/allowops
assert_stat 'root:root 644' /etc/allowops/agent.yaml
assert_stat 'root:root 755' /etc/allowops/catalog-keys
assert_stat 'allowops:allowops 700' /var/lib/allowops
assert_stat 'root:root 700' /var/lib/allowops-exec
cmp /packaging/allowops.sudoers /etc/sudoers.d/allowops
visudo -cf /etc/sudoers.d/allowops
[[ $(id -Gn allowops) == allowops ]]
[[ $(id -u allowops) -lt 1000 ]]
[[ $(getent passwd allowops | cut -d: -f6) == /var/lib/allowops ]]
[[ $(getent passwd allowops | cut -d: -f7) == */nologin ]]
[[ $(/usr/bin/allowops-agent --version) == "$version" ]]
if /usr/libexec/allowops/allowops-exec --version > /tmp/exec-version.log 2>&1; then
    echo 'allowops-exec accepted command-line arguments' >&2
    exit 1
fi
grep -qx ARGUMENTS_FORBIDDEN /tmp/exec-version.log
test ! -e /usr/bin/allowops-exec
test ! -e /usr/bin/allowops-gateway
test ! -e /usr/bin/allowops

grep -qx 'User=allowops' /usr/lib/systemd/system/allowops-agent.service
grep -qx 'ExecStart=/usr/bin/allowops-agent run' /usr/lib/systemd/system/allowops-agent.service
! grep -Eq '^(NoNewPrivileges|StateDirectory|ProtectSystem|PrivateUsers|CapabilityBoundingSet)=' \
    /usr/lib/systemd/system/allowops-agent.service
if command -v systemd-analyze >/dev/null; then
    systemd_version=$(systemd-analyze --version | head -n 1)
    echo "$systemd_version"
    if systemd-analyze verify /usr/lib/systemd/system/allowops-agent.service > /tmp/unit-verify.log 2>&1; then
        cat /tmp/unit-verify.log
    elif [[ $systemd_version == 'systemd 219' && -f /sys/fs/cgroup/cgroup.controllers &&
        $(cat /tmp/unit-verify.log) == $'Cannot determine cgroup we are running in: No such file or directory\nFailed to initalize manager: No such file or directory' ]]; then
        cat /tmp/unit-verify.log
        echo 'SKIP systemd-analyze verify: systemd 219 cannot initialize on cgroup v2'
    else
        cat /tmp/unit-verify.log >&2
        exit 1
    fi
else
    echo 'SKIP systemd-analyze verify: command unavailable'
fi
test -L /etc/systemd/system/multi-user.target.wants/allowops-agent.service
# The container has no systemd PID 1. Enabling must not start the skeleton agent.
! ps -eo comm | grep -qx allowops-agent

# The fixed sudoers permits only the helper with no command-line arguments.
if su -s /bin/sh allowops -c 'sudo -n /usr/libexec/allowops/allowops-exec' < /dev/null > /tmp/sudo-empty.log 2>&1; then
    echo 'helper incorrectly accepted empty stdin' >&2
    exit 1
fi
grep -q '"reason":"INVALID_JSON"' /tmp/sudo-empty.log
if su -s /bin/sh allowops -c 'sudo -n /usr/libexec/allowops/allowops-exec --version' > /tmp/sudo-args.log 2>&1; then
    echo 'sudoers incorrectly allowed helper arguments' >&2
    exit 1
fi

# Reinstallation preserves administrator configuration and application state.
echo '# administrator setting' >> /etc/allowops/agent.yaml
cp /etc/allowops/agent.yaml /tmp/agent.yaml
echo state > /var/lib/allowops/test-state
echo version > /var/lib/allowops-exec/test-version
echo key > /etc/allowops/catalog-keys/test-key
install_package
cmp /tmp/agent.yaml /etc/allowops/agent.yaml
assert_stat 'allowops:allowops 700' /var/lib/allowops
assert_stat 'root:root 700' /var/lib/allowops-exec

if [[ $format == rpm ]]; then
    rpm -e allowops-agent
    ! rpm -q allowops-agent
else
    dpkg -r allowops-agent
    [[ $(dpkg-query -W -f='${db:Status-Status}' allowops-agent) == config-files ]]
fi
test ! -e /usr/bin/allowops-agent
test ! -e /usr/libexec/allowops/allowops-exec
test ! -e /usr/lib/systemd/system/allowops-agent.service
test ! -e /etc/sudoers.d/allowops
test ! -L /etc/systemd/system/multi-user.target.wants/allowops-agent.service
getent passwd allowops >/dev/null
grep -qx state /var/lib/allowops/test-state
grep -qx version /var/lib/allowops-exec/test-version
grep -qx key /etc/allowops/catalog-keys/test-key
if [[ $format == rpm ]]; then
    cmp /tmp/agent.yaml /etc/allowops/agent.yaml.rpmsave
else
    cmp /tmp/agent.yaml /etc/allowops/agent.yaml
fi

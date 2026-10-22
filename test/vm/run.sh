#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd "$(dirname "$0")/../.." && pwd)
operation=$1
work=$2
mkdir -p "$work"

guest() {
    ssh -q -i "$work/ssh-key" -p "$(cat "$work/port")" \
        -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$work/known-hosts" -o ConnectTimeout=3 \
        vmtester@127.0.0.1 "$@"
}

case "$operation" in
start)
    distro=$3
    for tool in qemu-system-x86_64 qemu-img mkisofs ssh ssh-keygen python3 curl; do
        command -v "$tool" >/dev/null || { echo "required tool missing: $tool" >&2; exit 1; }
    done
    image=$(python3 "$repo/test/vm/images.py" "$distro" "${VM_IMAGE_CACHE:-/tmp/allowops-vm-images}")
    ssh-keygen -q -t ed25519 -N '' -f "$work/ssh-key"
    python3 - "$work" "$distro" <<'PY'
import json, socket, sys
from pathlib import Path
work = Path(sys.argv[1])
config = {"hostname": "allowops-" + sys.argv[2], "manage_etc_hosts": True,
          "ssh_pwauth": False, "users": [{"name": "vmtester", "lock_passwd": True,
          "sudo": "ALL=(ALL) NOPASSWD:ALL", "shell": "/bin/bash",
          "ssh_authorized_keys": [(work / "ssh-key.pub").read_text().strip()]}]}
(work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
(work / "meta-data").write_text(json.dumps({"instance-id": "p10a-" + sys.argv[2]}))
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    (work / "port").write_text(str(listener.getsockname()[1]))
PY
    mkisofs -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/user-data" "$work/meta-data"
    qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$work/disk.qcow2" 10G
    accel=tcg
    cpu=max
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then accel=kvm; cpu=host; fi
    echo "QEMU distro=$distro accelerator=$accel memory_mb=2048 cpus=2"
    qemu-system-x86_64 -accel "$accel" -cpu "$cpu" -m 2048 -smp 2 \
        -display none -monitor none -serial "file:$work/serial.log" \
        -drive "file=$work/disk.qcow2,if=virtio,format=qcow2" \
        -drive "file=$work/seed.iso,media=cdrom,readonly=on" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$(cat "$work/port")-:22" \
        -device virtio-net-pci,netdev=net0 -pidfile "$work/qemu.pid" -daemonize
    for ((i=0;i<180;i++)); do
        if guest 'sudo cloud-init status --wait' > "$work/cloud-init.log" 2>&1; then
            echo 'PASS cloud-init and local SSH'
            exit 0
        fi
        kill -0 "$(cat "$work/qemu.pid")" || break
        sleep 2
    done
    tail -60 "$work/serial.log" >&2
    echo 'VM boot/cloud-init timeout' >&2
    exit 1
    ;;
configure)
    package=$3
    key=$4
    # Join credentials arrive on stdin, never on the local SSH command line.
    cat > "$work/input.json"
    python3 - "$work" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
data = json.loads((p / "input.json").read_text())
(p / "agent.yaml").write_text(json.dumps({"upstream": data["upstream"], "ca_pin": data["pin"]}))
PY
    scp -q -i "$work/ssh-key" -P "$(cat "$work/port")" \
        -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/known-hosts" \
        "$package" "$key" "$work/agent.yaml" vmtester@127.0.0.1:/tmp/
    package_name=$(basename "$package")
    key_name=$(basename "$key")
    guest "sudo bash -s -- '$package_name' '$key_name'" <<'SH'
set -euo pipefail
trap 'echo "installation check failed at line $LINENO" >&2' ERR
case "$1" in
    *.deb) sudo dpkg -i "/tmp/$1" ;;
    *.rpm) sudo rpm -Uvh "/tmp/$1" ;;
esac
systemctl is-enabled allowops-agent
loaded=$(systemctl show allowops-agent --property=LoadState)
active=$(systemctl show allowops-agent --property=ActiveState)
echo "service state after install: $loaded $active"
[[ $loaded == LoadState=loaded && $active == ActiveState=inactive ]]
install -o root -g root -m 0644 "/tmp/$2" /etc/allowops/catalog-keys/catalog.pem
install -o root -g root -m 0644 /tmp/agent.yaml /etc/allowops/agent.yaml
visudo -cf /etc/sudoers.d/allowops
[[ $(stat -c '%U:%G:%a' /etc/sudoers.d/allowops) == root:root:440 ]]
[[ $(stat -c '%U:%G:%a' /usr/libexec/allowops/allowops-exec) == root:root:755 ]]
[[ $(stat -c '%U:%G:%a' /var/lib/allowops) == allowops:allowops:700 ]]
[[ $(systemctl show allowops-agent --property=User) == User=allowops ]]
grep -qx 'allowops ALL=(root) NOPASSWD: /usr/libexec/allowops/allowops-exec ""' /etc/sudoers.d/allowops
if sudo -u allowops sudo -n /usr/libexec/allowops/allowops-exec forbidden </dev/null; then exit 1; fi
echo 'PASS install, systemd and sudoers'
SH
    # JSON is decoded in the guest; only fresh local test credentials are used.
    guest "sudo \$(command -v python3 || command -v python || { test -x /usr/libexec/platform-python && echo /usr/libexec/platform-python; }) -c 'import json,subprocess,sys; d=json.load(sys.stdin); subprocess.check_call([\"allowops-agent\",\"join\",\"--upstream\",d[\"upstream\"],\"--ca-pin\",d[\"pin\"],\"--token\",d[\"token\"]])'" < "$work/input.json"
    rm "$work/input.json"
    guest 'sudo systemctl start allowops-agent; systemctl is-active allowops-agent; sudo -u allowops allowops-agent status'
    echo 'PASS join and systemd start'
    ;;
uninstall)
    guest 'sudo journalctl -u allowops-agent --no-pager -n 15; if command -v dpkg >/dev/null; then sudo dpkg --purge allowops-agent; else sudo rpm -e allowops-agent; fi; test ! -e /usr/bin/allowops-agent; test ! -e /etc/sudoers.d/allowops; test ! -e /usr/lib/systemd/system/allowops-agent.service'
    echo 'PASS uninstall'
    ;;
stop)
    if [[ -f $work/qemu.pid ]]; then
        pid=$(cat "$work/qemu.pid")
        # Refuse to signal a reused PID belonging to another worker.
        if [[ -r /proc/$pid/cmdline ]] && tr '\0' '\n' < "/proc/$pid/cmdline" | grep -Fq "file=$work/disk.qcow2,"; then
            kill "$pid" 2>/dev/null || true
            for ((i=0;i<50;i++)); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
        fi
    fi
    ;;
*) echo 'usage: run.sh start|configure|uninstall|stop WORK [arguments]' >&2; exit 2 ;;
esac

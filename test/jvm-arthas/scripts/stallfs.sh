#!/bin/sh
# A small ext4 file system whose block device can be stopped on purpose, for the JVM pause measurements
# (docs/arthas-jvm-pause-report.md). The storage is a new zram device (memory; added through /sys/class/zram-control, because
# the loop module cannot be loaded on the measuring host), a device-mapper "linear" device sits on top of it, and `stall`
# suspends that device without freezing the file system (dmsetup suspend --nolockfs --noflush): requests
# already sent and new ones wait until the resume, the way they wait when a disk stops answering. Needs sudo.
#   scripts/stallfs.sh setup            create and mount it at run/stallfs (mode 1777)
#   scripts/stallfs.sh stall <seconds>  suspend the device for that long, then resume it; prints the start and end (epoch seconds)
#   scripts/stallfs.sh freeze <seconds> freeze the file system instead (fsfreeze -f, then -u): every write and every write fault on
#                                       a memory-mapped file of it waits until the thaw, whatever the journal is doing
#   scripts/stallfs.sh dev              the kernel name of the device (dm-N), for /proc/diskstats
#   scripts/stallfs.sh teardown         unmount and remove everything
set -eu
cd "$(dirname "$0")/.."
NAME=jvmpause-stall
MNT=$PWD/run/stallfs
IDF=$PWD/run/stallfs.zram

case "${1:-}" in
setup)
  id=$(sudo -n cat /sys/class/zram-control/hot_add)
  echo "$id" > "$IDF"
  echo 512M | sudo -n tee /sys/block/zram$id/disksize > /dev/null
  sectors=$(sudo -n blockdev --getsz /dev/zram$id)
  sudo -n dmsetup create "$NAME" --table "0 $sectors linear /dev/zram$id 0"
  sudo -n mkfs.ext4 -q -F /dev/mapper/$NAME
  mkdir -p "$MNT"
  sudo -n mount -o noatime /dev/mapper/$NAME "$MNT"
  sudo -n chmod 1777 "$MNT"
  echo "mounted /dev/mapper/$NAME ($(basename "$(readlink -f /dev/mapper/$NAME)")) on $MNT, on /dev/zram$id"
  ;;
stall)
  t0=$(date +%s.%N)
  sudo -n dmsetup suspend --nolockfs --noflush "$NAME"
  t1=$(date +%s.%N)
  sleep "$2"
  t2=$(date +%s.%N)
  sudo -n dmsetup resume "$NAME"
  t3=$(date +%s.%N)
  echo "{\"suspend_called\": $t0, \"suspended\": $t1, \"resume_called\": $t2, \"resumed\": $t3}"
  ;;
freeze)
  t0=$(date +%s.%N)
  sudo -n fsfreeze -f "$MNT"
  t1=$(date +%s.%N)
  sleep "$2"
  t2=$(date +%s.%N)
  sudo -n fsfreeze -u "$MNT"
  t3=$(date +%s.%N)
  echo "{\"suspend_called\": $t0, \"suspended\": $t1, \"resume_called\": $t2, \"resumed\": $t3}"
  ;;
dev)
  basename "$(readlink -f /dev/mapper/$NAME)"
  ;;
teardown)
  sudo -n dmsetup resume "$NAME" 2>/dev/null || true
  sudo -n fsfreeze -u "$MNT" 2>/dev/null || true
  if mountpoint -q "$MNT"; then sudo -n umount "$MNT"; fi
  sudo -n dmsetup remove "$NAME" 2>/dev/null || true
  if [ -f "$IDF" ]; then
    id=$(cat "$IDF")
    echo 1 | sudo -n tee /sys/block/zram$id/reset > /dev/null
    echo "$id" | sudo -n tee /sys/class/zram-control/hot_remove > /dev/null
    rm -f "$IDF"
  fi
  rmdir "$MNT" 2>/dev/null || true
  echo "removed"
  ;;
*)
  echo "usage: $0 setup | stall <seconds> | freeze <seconds> | dev | teardown" >&2
  exit 2
  ;;
esac

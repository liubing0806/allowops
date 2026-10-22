#!/bin/sh
set -eu

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
# Retain the account, administrator keys and nonempty state directories.

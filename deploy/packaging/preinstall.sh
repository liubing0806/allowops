#!/bin/sh
set -eu

if ! getent passwd allowops >/dev/null; then
    useradd --system --user-group --home-dir /var/lib/allowops \
        --no-create-home --shell "$(command -v nologin)" allowops
fi

install -d -o allowops -g allowops -m 0700 /var/lib/allowops
install -d -o root -g root -m 0700 /var/lib/allowops-exec

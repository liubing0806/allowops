#!/bin/sh
set -eu

dist=dist
licenses="$dist/licenses"
go run github.com/google/go-licenses/v2@"${GO_LICENSES_VERSION:-v2.0.1}" save \
    ./cmd/... --ignore github.com/liubing0806/allowops --save_path "$licenses"

{
    printf 'Third-party licenses for the shipped Go binaries\n'
    find "$licenses" -type f | LC_ALL=C sort | while IFS= read -r file; do
        printf '\n===== %s =====\n\n' "${file#"$licenses"/}"
        cat "$file"
    done
} > "$dist/THIRD_PARTY_NOTICES"

#!/usr/bin/env bash
set -euo pipefail

unset CDPATH
module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
pkg=./cmd/allowops
target_list=linux/amd64,darwin/arm64,darwin/amd64,windows/amd64

while (( $# > 0 )); do
    case "$1" in
        --module-dir|--pkg|--targets) ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
    if (( $# < 2 )) || [[ $1 != --targets && -z $2 ]]; then
        printf 'Usage: %s [--module-dir DIR] [--pkg PACKAGE] [--targets OS/ARCH,...]\n' "$0" >&2
        exit 2
    fi
    case "$1" in
        --module-dir) module_dir=$2 ;;
        --pkg) pkg=$2 ;;
        --targets) target_list=$2 ;;
    esac
    shift 2
done

# Validate the whole list before splitting it. Bash read drops trailing empty fields.
target_pattern='[a-z0-9]+/[a-z0-9]+'
if [[ ! $target_list =~ ^$target_pattern(,$target_pattern)*$ ]]; then
    printf 'Invalid --targets %q: expected comma-separated os/arch pairs\n' "$target_list" >&2
    exit 2
fi
IFS=, read -r -a targets <<< "$target_list"

cd -- "$module_dir"
build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT

failed=0
for target in "${targets[@]}"; do
    goos=${target%/*}
    goarch=${target#*/}
    output="$build_dir/allowops-$goos-$goarch"
    if [[ $goos == windows ]]; then
        output+=.exe
    fi
    if CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -buildvcs=false -o "$output" -- "$pkg" >"$build_dir/build.log" 2>&1; then
        printf 'PASS %s\n' "$target"
    else
        printf 'FAIL %s\n' "$target"
        cat "$build_dir/build.log" >&2
        failed=$((failed + 1))
    fi
done

printf 'Summary: %d passed, %d failed\n' "$((${#targets[@]} - failed))" "$failed"
(( failed == 0 ))

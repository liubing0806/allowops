#!/bin/sh
# Installs and removes the allowops-arthas package in clean local containers
# (debian:12 for the deb, rockylinux:9 for the rpm) without a network.
#
#   test-install.sh /absolute/path/to/dist/arthas/packages
set -eu

version=4.3.5
files="LICENSE NOTICE SHA256SUMS THIRD_PARTY_NOTICES arthas-agent.jar arthas-core.jar arthas-spy.jar arthas.properties logback.xml"

if [ "${1:-}" = inside ]; then
    format=$2
    dir=/usr/share/allowops/arthas/$version
    fail() { echo "FAIL: $*" >&2; exit 1; }

    case $format in
        deb) dpkg -i /packages/allowops-arthas_*.deb ;;
        rpm) rpm -Uvh /packages/allowops-arthas-*.rpm ;;
    esac

    want=$(printf '%s\n' $files | LC_ALL=C sort | tr '\n' ' ')
    have=$(ls -A "$dir" | LC_ALL=C sort | tr '\n' ' ')
    [ "$have" = "$want" ] || fail "files in $dir: $have"
    [ "$(find /usr/share/allowops -mindepth 1 | wc -l)" -eq 11 ] || fail "unexpected entries under /usr/share/allowops"
    [ -z "$(find /usr/share/allowops -type l)" ] || fail "symbolic link in the package"

    for path in /usr/share/allowops /usr/share/allowops/arthas "$dir"; do
        [ "$(stat -c '%a %U %G' "$path")" = '755 root root' ] || fail "$path: $(stat -c '%a %U %G' "$path")"
    done
    for name in $files; do
        [ "$(stat -c '%a %U %G' "$dir/$name")" = '644 root root' ] || fail "$name: $(stat -c '%a %U %G' "$dir/$name")"
    done

    (cd "$dir" && sha256sum --check --strict SHA256SUMS)
    [ "$(sha256sum < "$dir/SHA256SUMS")" = "$(sha256sum < "/packages/allowops-arthas-$version.SHA256SUMS")" ] \
        || fail "SHA256SUMS differs from the build output"
    if grep -q '^[[:space:]]*arthas\.mcp' "$dir/arthas.properties"; then fail "arthas.properties sets an MCP key"; fi
    # The package has no scripts and no dependency on allowops-agent.
    if getent passwd allowops >/dev/null; then fail "the allowops account exists"; fi
    # The SHA-256 table in README.md must list the installed files.
    for name in arthas-agent.jar arthas-core.jar arthas-spy.jar arthas.properties logback.xml; do
        digest=$(sha256sum < "$dir/$name" | cut -d ' ' -f 1)
        grep -q "^| \`$name\` | \`$digest\` |$" /README.md || fail "README.md has no SHA-256 $digest for $name"
    done
    echo "installed: $(cd "$dir" && sha256sum arthas-agent.jar arthas-core.jar arthas-spy.jar arthas.properties logback.xml | tr '\n' ';')"

    case $format in
        deb) dpkg -r allowops-arthas ;;
        rpm) rpm -e allowops-arthas ;;
    esac
    [ ! -e /usr/share/allowops ] || fail "/usr/share/allowops remains after removal: $(find /usr/share/allowops)"
    echo "removed: /usr/share/allowops is gone"
    exit 0
fi

packages=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)

# Refuse a remote Docker endpoint: this test only installs into local containers.
if [ -n "${DOCKER_CONTEXT:-}" ]; then
    endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{(index .Endpoints "docker").Host}}')
else
    endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')}
fi
case $endpoint in unix://*) ;; *) echo "remote Docker endpoint refused: $endpoint" >&2; exit 1 ;; esac

for target in debian:12:deb rockylinux:9:rpm; do
    image=${target%:*}
    format=${target##*:}
    echo "== $image ($format)"
    docker run --rm --network none --platform linux/amd64 \
        --mount "type=bind,src=$packages,dst=/packages,readonly" \
        --mount "type=bind,src=$here/test-install.sh,dst=/test-install.sh,readonly" \
        --mount "type=bind,src=$here/README.md,dst=/README.md,readonly" \
        "$image" sh /test-install.sh inside "$format"
    echo "PASS $image"
done

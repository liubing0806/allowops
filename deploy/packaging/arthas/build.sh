#!/bin/sh
# Builds the optional allowops-arthas deb and rpm packages from the pinned
# Arthas release. The only download is the pinned archive from Maven Central;
# it is verified against the SHA-256 in source.env before anything is read.
#
#   ARTHAS_OUT      output directory (default: dist/arthas)
#   ARTHAS_ZIP      use this local copy of the archive instead of downloading
#   ARTHAS_PKG_VERSION  package version (default: the exact git tag, else 0.0.0-SNAPSHOT-<commit>)
#   GPG_KEY_PATH    private key file; when set, nfpm signs the deb and rpm
#   NFPM_VERSION, SYFT_VERSION  tool versions (set by the Makefile)
#   ARTHAS_SBOM=0   skip the SPDX SBOMs
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# shellcheck source=source.env
. "$here/source.env"

nfpm_version=${NFPM_VERSION:-v2.47.0}
syft_version=${SYFT_VERSION:-v1.54.1}
out=${ARTHAS_OUT:-$repo/dist/arthas}
download="$out/download"
stage="$out/stage"
packages="$out/packages"
zip=${ARTHAS_ZIP:-$download/arthas-packaging-$ARTHAS_VERSION-bin.zip}

if [ -z "${ARTHAS_PKG_VERSION:-}" ]; then
    if tag=$(git -C "$repo" describe --tags --exact-match 2>/dev/null); then
        ARTHAS_PKG_VERSION=${tag#v}
    else
        ARTHAS_PKG_VERSION=0.0.0-SNAPSHOT-$(git -C "$repo" rev-parse --short HEAD)
    fi
fi
# Fixed file times make a rebuild of the same commit byte-identical.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct)}

rm -rf "$stage" "$packages"
mkdir -p "$download" "$packages"

if [ -z "${ARTHAS_ZIP:-}" ] && [ ! -f "$zip" ]; then
    curl --fail --silent --show-error --location --retry 3 \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --output "$zip.part" "$ARTHAS_ZIP_URL"
    mv "$zip.part" "$zip"
fi

python3 -I "$here/stage.py" --archive "$zip" --sha256 "$ARTHAS_ZIP_SHA256" \
    --legal "$here" --out "$stage" > /dev/null
(cd "$stage" && sha256sum --check --strict --quiet SHA256SUMS)
cp "$stage/SHA256SUMS" "$packages/allowops-arthas-$ARTHAS_VERSION.SHA256SUMS"

export ARTHAS_VERSION ARTHAS_PKG_VERSION SOURCE_DATE_EPOCH
export ARTHAS_STAGE="$stage"
export ARTHAS_SIGN_KEY_FILE=${GPG_KEY_PATH:-}
for format in deb rpm; do
    go run github.com/goreleaser/nfpm/v2/cmd/nfpm@"$nfpm_version" package \
        --config "$here/nfpm.yaml" --packager "$format" --target "$packages/"
done

if [ "${ARTHAS_SBOM:-1}" != 0 ]; then
    for package in "$packages"/*.deb "$packages"/*.rpm; do
        SYFT_CHECK_FOR_APP_UPDATE=false go run github.com/anchore/syft/cmd/syft@"$syft_version" \
            scan "$package" --output "spdx-json=$package.sbom.json"
    done
fi

(cd "$packages" && sha256sum -- *.deb *.rpm *.SHA256SUMS > checksums-arthas.txt)
echo "allowops-arthas $ARTHAS_PKG_VERSION (Arthas $ARTHAS_VERSION) built in $packages"

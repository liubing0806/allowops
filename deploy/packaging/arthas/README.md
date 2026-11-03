# allowops-arthas package

Optional deb and rpm package with the Arthas files that the `jvm_arthas`
builtin loads into a Java process. It is built separately from
`allowops-agent`; `make package` does not change.

## Build

```sh
make package-arthas
```

The target writes to `dist/arthas/packages/`. `make package` empties `dist/`, so
run `make package-arthas` after it. The build needs Go, Python 3, `curl`,
`sha256sum` and network access to `repo.maven.apache.org` for the first run.
The archive is cached in `dist/arthas/download/`. Set `ARTHAS_ZIP` to a local
copy of the archive to build without a download.

`source.env` pins the Arthas version, the Maven Central URL and the SHA-256 of
`arthas-packaging-4.3.5-bin.zip`. `stage.py` checks the SHA-256 of the archive
before it reads anything and stops on a mismatch. It then reads five named
members by name, removes the two MCP lines from `arthas.properties`, adds
`LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES` from this directory and writes
`SHA256SUMS`. nfpm (`nfpm.yaml`) packs the result.

Output files:

| File | Content |
|---|---|
| `allowops-arthas_<version>_all.deb`, `allowops-arthas-<version>-1.noarch.rpm` | Packages, signed when `GPG_KEY_PATH` names a private key |
| `*.sbom.json` | SPDX SBOM of each package; `ARTHAS_SBOM=0` skips it |
| `allowops-arthas-4.3.5.SHA256SUMS` | Same content as `SHA256SUMS` inside the package |
| `checksums-arthas.txt` | SHA-256 of the packages and of the manifest |

The package version is the exact git tag without `v`, otherwise
`0.0.0-SNAPSHOT-<commit>`. `ARTHAS_PKG_VERSION` overrides it. File times come
from the commit time, so a rebuild of the same commit is byte-identical.

## Content of the package

All files are in `/usr/share/allowops/arthas/4.3.5/`, owned by root.
Directories are 0755 and files are 0644.

| File | SHA-256 |
|---|---|
| `arthas-agent.jar` | `b5bf8765c7621849889fb6522a296fa177ceb3f5c2c2b6d9f631d761ca9c04f9` |
| `arthas-core.jar` | `7cbc3dc36ec29e96ae044845ad6b690b790a800e45d0694fcfbe90c9725de813` |
| `arthas-spy.jar` | `d11cfc1cee83eb46501d5b9719ea49117db2a9e7cbdab9e83e376716255380a6` |
| `arthas.properties` | `a507ed264d99387b6e1717f8ad6f257dba79de983f5b6617a8c63e38975acec1` |
| `logback.xml` | `e038b9c097cf0fe801483c65871565f6d120c1365c4d55b65666b05d533f7445` |

`LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES` and `SHA256SUMS` complete the
directory. `NOTICE` carries the notices of the Arthas source tree.
`THIRD_PARTY_NOTICES` lists the components in `arthas-core.jar` with the
license that applies to each, the Web UI dependencies, the notices of the jar
and the text of the Eclipse Public License 1.0. The jars and `logback.xml` equal the files in the Arthas archive.
`arthas.properties` differs from the archive only by the lines for
`arthas.mcpEndpoint` and `arthas.mcpProtocol`. Without these removals the
Arthas MCP server starts; without `logback.xml` Arthas writes DEBUG lines to the
target's standard output. `builtin_config` of the signed catalog uses the
SHA-256 values above. Not included: `arthas-boot.jar`, `arthas-client.jar`,
`math-game.jar`, the `as` scripts, `async-profiler/` and `lib/`.

## Licenses

The license of the package is `Apache-2.0 AND BSD-3-Clause AND EPL-1.0 AND MIT AND 0BSD`:
the licenses that occur in the package, taken from `THIRD_PARTY_NOTICES`.

- Arthas and most components of `arthas-core.jar`: Apache-2.0.
- logback 1.2.13: EPL-1.0. Upstream also offers LGPL-2.1, which is not used.
  logback is not on the allowlist of `make licenses`, which checks Go
  dependencies; this package is the exception. The text of EPL-1.0 and the
  locations of the source code are in `THIRD_PARTY_NOTICES`.
- javassist 3.29.0-GA: offered as MPL-1.1, LGPL-2.1 or Apache-2.0; distributed
  under Apache-2.0.
- Web UI files and the JSON Schema documents in `arthas-core.jar`: Apache-2.0 as
  part of Arthas and fastjson2. The Web UI dependencies and their licenses
  (MIT, BSD-3-Clause, Apache-2.0 and, for tslib, 0BSD) are listed in
  `THIRD_PARTY_NOTICES`.

`test-stage.py` checks that the license expression equals the set of licenses
in `THIRD_PARTY_NOTICES` and that the EPL-1.0 text is unchanged.

## Tests

```sh
python3 -I deploy/packaging/arthas/test-stage.py          # offline, part of make script-checks
sh deploy/packaging/arthas/test-install.sh "$PWD/dist/arthas/packages"
```

`test-install.sh` installs and removes the packages in `debian:12` and
`rockylinux:9` containers without a network. It checks the file set, owners,
modes, `SHA256SUMS` and the removal of the directories.

## Update Arthas

Change the three values in `source.env`, then compare the components in the new
`arthas-core.jar` (the `META-INF/maven` entries and the files under `META-INF`)
with `THIRD_PARTY_NOTICES` (including the license of each component, the source
location of logback and the Web UI dependencies), copy the `NOTICE` file of the
new Arthas source tree into `NOTICE`, update this README, and publish the new
SHA-256 values in the signed catalog.

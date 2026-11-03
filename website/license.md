# License and participation

allowops is open source software released under the MIT License. The
[repository LICENSE](https://github.com/liubing0806/allowops/blob/main/LICENSE)
contains the full text. The copyright holder is liubing.

During the MVP, issues and suggestions are welcome; external code contributions
are not accepted. Report bugs with a minimal reproduction and generic data.
Use private reporting for vulnerabilities. See the
[participation policy](https://github.com/liubing0806/allowops/blob/main/CONTRIBUTING.md).

## Third-party software

The optional `allowops-arthas` package redistributes Arthas, which is licensed
under the Apache License 2.0, together with the third-party components bundled
in `arthas-core.jar`. The licenses that occur in the package are Apache-2.0,
BSD-3-Clause, EPL-1.0, MIT and 0BSD, as stated in the package metadata. The
logback library inside `arthas-core.jar` is distributed under the Eclipse
Public License 1.0, and the package carries the license text and the locations
of the source code. The package carries `LICENSE`, `NOTICE` and
`THIRD_PARTY_NOTICES`. The repository keeps the same files in
[deploy/packaging/arthas](https://github.com/liubing0806/allowops/tree/main/deploy/packaging/arthas).
The notices for the Go dependencies are in `THIRD_PARTY_NOTICES` of the release
archive and of `allowops-agent`.

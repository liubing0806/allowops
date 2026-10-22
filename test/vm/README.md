# Local QEMU guest matrix

Prerequisites: `qemu-system-x86_64`, `qemu-img`, `mkisofs`, OpenSSH, Python 3.11+,
curl, Go and local Docker. KVM is used when `/dev/kvm` is accessible; otherwise
the runner uses QEMU TCG. No host packages or virtualization services are installed
by the script. Guests need sudo, systemd, cloud-init and Python in their official
cloud image. A missing dependency is reported as a failure.

Build local packages using the existing release configuration without publishing:

```sh
GO_LICENSES_VERSION=v2.0.1 go run github.com/goreleaser/goreleaser/v2@v2.18.3 \
  release --snapshot --clean --skip=sign,publish,docker,sbom
make vm
# A selected distribution or a comma-separated subset:
VM_DISTROS=ubuntu2404,rocky9 make vm
python3 -m unittest discover -s test/vm -p 'test_*.py'
```

The default order is Ubuntu 24.04, Rocky 9, Rocky 8, Ubuntu 20.04, Debian 12,
CentOS 7. Each has its own subtest, disposable gateway/database/object store,
cloud-init seed, SSH key, disk overlay and QEMU process. A failure in one
distribution does not prevent later subtests. Two vCPUs and 2048 MiB RAM are
allocated per guest, sequentially. All SSH/SCP connections use `127.0.0.1` with
QEMU user-network port forwarding and a locally generated key. The guest reaches
only the test gateway via QEMU's host alias `10.0.2.2`; that gateway listens on
loopback. A per-run known-hosts file records the guest SSH host key.

`images.py` downloads checksum manifests from distribution-owned HTTPS addresses
declared in `IMAGES`. Images use those addresses, except the exact Debian 12 URL
authorized by G63 below. It rejects redirects and missing/ambiguous
manifest entries and verifies SHA-256 (Debian: SHA-512) before booting. Cached
images under `${VM_IMAGE_CACHE:-/tmp/allowops-vm-images}` are checked on every run.
Downloads use `.partial` files until complete. Mutable `latest` images may change;
logs record both image and manifest hosts and the verified digest. Checksum
verification relies on the official HTTPS source;
this script does not verify manifest GPG signatures.

G63 authorizes the Debian 12 image at
`https://chuangtzu.ftp.acc.umu.se/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2`,
as designated by the official Debian download entry. Its `SHA512SUMS` is fetched
only from `https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS`.
A mismatch deletes the cached image and stops before QEMU starts; record that
distribution as unverified. Further redirects remain rejected. Images are kept
in the external cache and are never committed to the repository.

The runner installs the locally built deb/rpm, confirms the service is enabled
and inactive immediately after installation, checks the service's `allowops`
user, helper permissions, state directory ownership and the fixed sudoers rule.
It rejects an argument-bearing sudo helper invocation, joins with a fresh test
token, starts systemd and waits for the signed catalog load report.

The gateway executes the existing `system_load` example and a signed
`root_identity` action using `run_as: root`. The latter exercises sudo and the
installed helper and must return UID `0`. The runner then uninstalls the package,
checks removal of the binaries/unit/sudoers, and stops only its own QEMU process.
Temporary guest state and keys are cleaned up; the verified image cache is kept.
The fresh Join token is transferred on SSH stdin; the current product CLI exposes
it in the guest's transient `join --token` process arguments.

CentOS 7 is EOL. If its old official image/checksum URL is removed or redirected,
the test fails before boot instead of substituting an unverified mirror. Report
the exact failure and choose an official archived image/checksum pair before
attempting that distribution again.

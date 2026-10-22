# Catalog publishing pipelines

These are templates for a reviewed catalog repository. They validate, build,
sign and publish using the real `allowops` CLI. They do not install a pipeline,
create credentials or publish anything merely by being present here.

| Platform | Template | Credential delivery |
|---|---|---|
| GitHub Actions | [github-actions.yml](github-actions.yml) | Protected environment secrets; PEM key and publisher token are injected into the publishing step. |
| Jenkins | [Jenkinsfile](Jenkinsfile) | Credentials Binding secret files for key/CA and secret text for publisher token. |
| Flow | [flow.yml](flow.yml) | UI-bound private variable group from the CI credential store; no private values in YAML. |

## Required platform settings

Protect `main` with review and restrict who can edit or invoke the publishing
pipeline. Credential access must be enforced by CI permissions/environment
protection, not only by a branch condition in editable repository code. Do not
give PR/fork builds signing credentials. Flow variables can apply to an entire
pipeline, so use a separate publishing-only pipeline that checks out protected
main, and restrict manual/API source and variable overrides. Jenkins credentials
must be unavailable to untrusted multibranch/PR jobs. Use isolated publishing
runners without unrelated workloads or access to other users' processes.

Preinstall a pinned, checksum/signature-verified allowops CLI release on the
runner. The GitHub hosted-runner template needs an operator-supplied installation
step before publication; no unverified download is included. Copy
[publish.sh](publish.sh) and this directory into the catalog repository. Set
`ALLOWOPS_CATALOG_DIR` if its catalog is not at `examples/catalog`.

The shared script expects these environment bindings:

- `ALLOWOPS_PUBLISH_BRANCH`: the platform's authenticated branch metadata, `main`.
- `ALLOWOPS_GATEWAY`: the gateway HTTPS origin, such as `https://gateway.example.org`.
- `ALLOWOPS_GATEWAY_CA_FILE`: the trusted gateway TLS CA file.
- `ALLOWOPS_SIGNING_KEY_FILE` (CI secret-file binding) or
  `ALLOWOPS_SIGNING_KEY_PEM` (CI private variable): the Ed25519 PKCS8 key.
- `ALLOWOPS_PUBLISHER_TOKEN`: a service account with only `publish_catalog`.

GitHub Actions and Flow write the non-secret CA from `ALLOWOPS_GATEWAY_CA_PEM`.
PEM signing bindings are written to an isolated mode-0600 temporary file because
the signing CLI reads files. Shell tracing is disabled; private key bytes and
token values never become CLI arguments. Temporary files are removed on exit.
Do not archive the temporary directory, dump environments, or cache credential
files. Jenkins creates its secret-file binding outside the browsable workspace;
do not move the binding into a nested workspace directory.

Serialize publishing per catalog. Versions are build-time UTC timestamps and
must strictly increase; simultaneous publishers can conflict. These templates
serialize within GitHub/Jenkins, and Flow requires its pipeline concurrency
setting to allow only one run. Use one publishing platform for each catalog.
After publication, check host catalog distribution and unsupported actions.

## Local checks

Run `sh -n examples/pipelines/publish.sh` to check shell syntax. Run
`allowops catalog validate examples/catalog` to validate the source catalog.
The templates require platform-specific credential/environment/source setup.
They have not been executed against a live CI service by local documentation
checks. Do not run the publishing script locally with production credentials.

Official references: [Flow job conditions](https://www.alibabacloud.com/help/en/yunxiao/user-guide/use-the-condition-syntax-to-control-whether-a-task-is-executed),
[Flow private variables](https://www.alibabacloud.com/help/zh/yunxiao/user-guide/variables),
[Jenkins Credentials Binding](https://www.jenkins.io/doc/pipeline/steps/credentials-binding/),
and [GitHub environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

# Security

allowops constrains execution to signed actions and typed inputs. A signed
catalog is a privilege boundary: review commands, script bytes, allowed roots,
URL prefixes, run identities and output before trusting its key on a host.
Protect the CI publishing pipeline as carefully as a root-capable operator.

Use least-privilege service accounts and gateway-managed authorization labels.
The default admin can execute all signed actions on labeled hosts, including
dangerous actions. Unlabeled hosts deny execution. Separate read and write
identities and review broad action or risk rules.

## Deployment boundaries

Preserve TLS/ALPN through Layer 4 load balancing. Pin the gateway TLS CA during
host registration and use the separate host CA for mutual TLS. Use secure
OIDC/LDAP configuration and verified certificates. Store private keys and tokens
through your credential manager, never in the catalog or public documentation.

Run the agent as its dedicated low-privilege user without extra groups. The
root helper accepts only its fixed stdin protocol. Do not widen sudoers or add
an interactive shell action. Interpreter exceptions and signed scripts need
review of the actual program and all caller-controlled inputs.

## Limits of protection

A compromised gateway can call all already signed actions across hosts and read
output. A compromised signing key can authorize arbitrary commands, including
root operations. No local host risk ceiling further limits a compromised gateway.
Host-root compromise makes that host's identity and output untrustworthy.

Redaction occurs before output leaves a host but can miss secrets or remove
harmless content. Output returned to a model is visible to the model provider.
`output_trust: untrusted` and plain-text rendering do not eliminate prompt
injection. Never treat host output as instructions. Disconnecting or cancelling
an action cannot undo its previous side effects.

Malicious database or object-storage administrators and hosts compromised before
installation are outside the protection scope. Audit hash chains need independent
checkpoints to detect a complete rewrite by a database administrator.

The [repository security policy](https://github.com/liubing0806/allowops/blob/main/SECURITY.md)
lists all threats T1–T15 and their controls. Those controls are a model, not a
claim of independent verification of every deployment. [Operations](operations.md)
covers backups, upgrades and rotation.

## Vulnerability reports

Use the repository's GitHub **Security → Advisories → Report a vulnerability**
private reporting path. If it is unavailable, ask for a private contact in an
issue without publishing vulnerability details. See
[GitHub's private reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).
Provide a version/commit, impact and a reproduction using synthetic data.

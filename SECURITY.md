# Security policy

## Private vulnerability reporting

Use GitHub private vulnerability reporting: open this repository's **Security**
tab, select **Advisories**, then **Report a vulnerability**. Include the affected
version or commit, the component, impact and a reproduction with synthetic data.
Exclude real credentials, customer data and production host details.
See [GitHub's reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

If the button is unavailable, open an issue asking for a private security contact
without disclosing the vulnerability. Repository administrators must enable
private vulnerability reporting before public release. This file does not
enable it. No response-time or supported-version guarantee is currently stated.

## Trust boundaries and threats

The protected assets are host privileges, catalog signing keys, the gateway host
CA key, tokens, output, policies and audit integrity. A signed action defines the
maximum execution capability; gateway policy limits who may call it. The gateway
cannot change the catalog public keys trusted by a host.

| ID | Threat | Measures and limits |
|---|---|---|
| T1 | AI agent misuse or prompt injection | Per-target policy, exact selector counts, batches, failure thresholds and concurrency limits. Separate read/write accounts. Output is marked untrusted; this cannot eliminate prompt injection. |
| T2 | Stolen API token | Expiry, revocation, hash-only storage, source-network policy and audit. The attacker can act with the stolen identity until it is revoked or expires. |
| T3 | Compromised gateway | Hosts independently verify catalogs, parameters and action digests. The gateway cannot add commands or trusted keys. It can call all already signed actions on all hosts and read output. |
| T4 | Compromised CI or signing key | Protected branches, review, credentials restricted to publishing, catalog expiry and key rotation. A stolen signing key can authorize arbitrary commands, including root execution. |
| T5 | Compromised host root | Host-bound certificates, gateway-managed authorization labels, message/rate limits and gateway output bounds. That host's output and identity are no longer trustworthy. |
| T6 | Compromised low-privilege host agent | Dedicated user without extra groups. Privileged execution is restricted to the signed catalog through the fixed helper. |
| T7 | Privileged helper vulnerability | Fixed paths, cleared environment, single-open in-memory signature verification, restricted input and descriptor-based filesystem checks that reject symlinks. A helper defect can still cause root compromise. |
| T8 | Network interception or leaked join token | Mutual TLS after registration, pinned gateway TLS CA during registration, bounded token expiry/uses, unique hostnames and no initial authorization labels. |
| T9 | Console XSS, CSRF or stolen session | Output displayed as text, Content Security Policy, Secure/HttpOnly/SameSite=Strict cookies, Origin/CSRF checks and audited policy simulation. |
| T10 | Argument or path injection | Fixed argv, whole-element placeholders, typed parameters, leading-option rejection for strings/paths, resolved allowed roots, executable checks, fixed environment and process-group timeouts. |
| T11 | Clock skew | Bounded activation-time tolerance, certificate/expiry checks and synchronized host clocks. Excessive skew can make hosts unavailable. |
| T12 | Resource exhaustion | Request, message, output, scan, queue, concurrency and rate limits. Operators must size dependencies and validate capacity. |
| T13 | Audit tampering | Hash chain, restricted runtime database privileges, durable export and independently retained checkpoints. Internal consistency alone cannot detect a complete chain rewrite by a database administrator. |
| T14 | Supply-chain compromise | Release checksums/signatures, software bills of materials, pinned dependencies and vulnerability checks. Verify artifacts against a separately trusted signing key. |
| T15 | LDAP attacks | LDAPS or StartTLS, certificate verification, escaped filters, login throttling and no stored user passwords. |

These are the threat model's controls, not a claim that every deployment or
attack scenario has been independently verified. Operators must retain the
required trust, privilege and deployment boundaries.

## Residual risks

- A compromised gateway can invoke every signed action on every host with valid
  parameters. There is no separate host-local risk ceiling.
- Compromised CI or catalog signing keys can sign arbitrary commands. Protect
  publishing as a host privilege boundary, including root where `run_as` permits.
- Host output returned to a model is visible to the AI model provider. Redaction
  can miss secrets and can remove harmless text.
- Prompt injection cannot be completely prevented by marking output untrusted.
- Disconnecting or cancelling execution cannot undo side effects already made.

Malicious PostgreSQL or object-storage administrators and hosts compromised
before installation are outside the protection scope. Audit exports need an
independent trust domain to provide evidence against a full database rewrite.

See the [security guide](website/security.md) and
[operations guide](website/operations.md) for deployment and rotation practices.

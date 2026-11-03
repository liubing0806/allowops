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
| T6 | Compromised low-privilege host agent | Dedicated user without extra groups. Privileged execution is restricted to the signed catalog through the fixed helper. The only other helper request, the recovery of Arthas sessions, has no fields; it acts only on session records the helper wrote in a root-only directory. |
| T7 | Privileged helper vulnerability | Fixed paths, cleared environment, single-open in-memory signature verification, restricted input and descriptor-based filesystem checks that reject symlinks. A helper defect can still cause root compromise. For the `jvm_arthas` builtin the helper also sends SIGQUIT to a target JVM, creates a file in its mount namespace, connects to its attach socket as the JVM's user, loads the Arthas agent into it and opens TCP connections in its network namespace; see [Java diagnostics with Arthas](#java-diagnostics-with-arthas). |
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

### Java diagnostics with Arthas

The `jvm_arthas` builtin loads Arthas into a JVM named in the signed catalog,
runs one fixed read-only command and removes Arthas again. The caller names a
target and the structured arguments of one command kind; it never supplies a
process ID, a path or command text. The target is resolved from a signed
systemd unit or container name and the JVM's main class. The helper gains these
capabilities against that JVM:

- **SIGQUIT to the target.** It is sent only when the JVM's hsperfdata allows
  attach, the JVM catches SIGQUIT, no attach socket exists yet and the attach
  file was created first. Without the attach file, SIGQUIT makes a JVM print a
  thread dump, and it ends a process that does not catch it. The signal goes
  through a pidfd opened before the process start time is compared again, so a
  reused process ID is not signalled. Kernels without pidfd get `kill(2)` after
  the same comparison, which leaves a short window for process ID reuse.
- **Creating a file in the target's mount namespace.** The only file is the
  empty attach file `.attach_pid<pid>` in `/tmp`, or in the JVM's working
  directory when `/tmp` refuses it. It is created exclusively, without
  following a symbolic link at its name, on a thread that has switched to the
  JVM's effective user and group, so it can only be created where that user
  can create files. Paths are resolved inside the target's root and symbolic
  links cannot lead out of it. The file is removed on every path. The helper
  does not copy Arthas files into the target.
- **Connecting to the attach socket as the JVM's user.** The socket must be a
  socket owned by the JVM's effective user; the helper connects to the checked
  inode through its descriptor, on a thread that has switched to the JVM's user
  and group, and the reply is limited to 64 KiB and a timeout.
- **Loading code into the JVM.** Only the agent jar from the Arthas directory
  of the signed configuration is loaded, after the five Arthas files in the
  target's file system match the SHA-256 values of the signed configuration.
  The agent arguments disable telnet, bind the HTTP API to 127.0.0.1 on a port
  from the signed range, require a 32-character random password generated for
  the call, require the password from local connections too, disable every
  command except the one the call runs and set a session timeout. Command text
  is assembled from fixed words and arguments that match strict patterns; no
  OGNL expression is accepted and no class is enhanced. Before the attach the
  helper checks memory and metaspace headroom, the number of earlier attaches
  and the time since the last one; while the command runs it can abort on CPU,
  garbage collection and health-check thresholds. Afterwards it interrupts the
  job, closes the session, resets and stops Arthas, and checks that the port is
  closed and no Arthas thread is left. A session record (mode 0600 in a
  root-only directory) lets a later call or the recovery request stop a server
  that a failed call left behind.
- **TCP connections in the target's network namespace.** The namespace is
  entered on a dedicated thread that exits afterwards, only after the process
  start time is compared again, and only to connect to 127.0.0.1 on a port
  where the JVM itself holds the listening socket. HTTP responses are limited
  in size, including the status line and headers, and in time.

The target JVM, its container and other processes in its namespaces are
untrusted. The helper reads their files, sockets and replies only through the
checks above, and every reply is bounded in size and time. A process that
controls the target JVM controls what Arthas reports about it.

## Residual risks

- A compromised gateway can invoke every signed action on every host with valid
  parameters. There is no separate host-local risk ceiling.
- Compromised CI or catalog signing keys can sign arbitrary commands. Protect
  publishing as a host privilege boundary, including root where `run_as` permits.
- Host output returned to a model is visible to the AI model provider. Redaction
  can miss secrets and can remove harmless text.
- Prompt injection cannot be completely prevented by marking output untrusted.
- Disconnecting or cancelling execution cannot undo side effects already made.
- During an Arthas session, any process in the target's network namespace can
  connect to the Arthas port; running a command needs the random password. A
  process with `CAP_NET_RAW` in that namespace can capture the password from
  loopback traffic, and the JVM's own attach records, such as the JFR
  `jdk.JavaAgent` event, contain it. The password is valid only until the
  session ends and allows only the command of the call, `reset` and `stop`.
- When the helper connects to the Arthas port, the JVM can close its listener
  between the listener check and the connection, and another process in the
  namespace can bind the port in that moment.
- A process in the target's network namespace can make `jvm_arthas` calls and
  their clean-up fail by binding ports of the configured range.
- Whoever can write the Arthas directory in the target's file system can make
  the JVM load their code during an attach: the files can be replaced after
  the SHA-256 check, and Arthas also loads jars from a `commands` directory
  there, which is not checked. The helper does not check the directory's owner
  or mode. Keep it writable only by root.
- When the configured JVM of a container or unit is not running or publishes no
  hsperfdata, another process there with the same main class is attached
  instead and its answers are reported.
- Arthas output contains real application data such as thread names, class
  names and allowed system properties. Output filtering cannot recognise every
  secret.
- After an attach, Arthas classes such as `arthas-spy` stay loaded in the
  target JVM until the process exits.

Malicious PostgreSQL or object-storage administrators and hosts compromised
before installation are outside the protection scope. Audit exports need an
independent trust domain to provide evidence against a full database rewrite.

See the [security guide](website/security.md) and
[operations guide](website/operations.md) for deployment and rotation practices.

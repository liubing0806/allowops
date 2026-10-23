# Identity

People authenticate through OpenID Connect (OIDC) or LDAP. Service accounts use
expiring Bearer tokens. There is no built-in local password user. Effective user
roles are the union of group mappings and manually assigned roles; the current
identity data is read on each authenticated request.

A gateway accepts at most one LDAP identity source and supports multiple
OIDC sources. More than one LDAP entry causes startup to fail. The console shows
one LDAP login form and one button per OIDC provider. Use a unique provider ID
for each configured source.

## OIDC

Configure a generic provider and a fixed gateway HTTPS origin. Register the
gateway callback `https://gateway.example.org/auth/oidc/callback` with the
identity provider. This is a configuration fragment; gateway TLS, database and
output settings are also required.

```yaml
identity:
  origin: https://gateway.example.org
  bootstrap_admins: [admin@example.org]
  role_mappings:
    - provider_id: identity
      group: ops-admin
      roles: [admin]
providers:
  - id: identity
    display_name: Operations identity
    kind: oidc
    issuer_url: https://idp.example.org
    client_id: allowops
    client_secret_env: ALLOWOPS_OIDC_CLIENT_SECRET
```

Deliver the provider secret through the process environment. With the Helm
chart, list each variable in `gateway.providerSecretEnv` (`name`, `secretName`,
`key`); the chart injects it from a Kubernetes Secret and keeps the value out of
the ConfigMap. The gateway checks
issuer, audience, nonce, state and the bound browser transaction. OIDC CLI login
uses a loopback callback and Proof Key for Code Exchange (PKCE); the gateway
exchanges the provider's authorization code. The CLI receives a short-lived,
single-use code and exchanges it for a session. Tokens do not appear in redirect
URLs. Verified email is required where email is used as a trusted identity.

```sh
allowops login --gateway https://gateway.example.org --provider identity
# Print the login URL when the CLI cannot open a browser:
allowops login --gateway https://gateway.example.org --provider identity --no-browser
```

Group mappings are initialized from configuration, then stored in PostgreSQL.
Change existing mappings through the console/API; restarting with different
startup mappings does not overwrite the database.

## LDAP

Only LDAPS or LDAP with StartTLS is accepted. Configure certificate verification,
a bind identity, user/group bases and the directory's attribute names. Bind
passwords come from a named environment variable (on Kubernetes, supply it with
`gateway.providerSecretEnv`); user passwords are not stored.

```yaml
providers:
  - id: directory
    display_name: Operations directory
    kind: ldap
    url: ldaps://directory.example.org:636
    ca_file: /etc/allowops/directory-ca.pem
    bind_dn: cn=reader,dc=example,dc=org
    bind_password_env: ALLOWOPS_LDAP_BIND_PASSWORD
    user_base_dn: ou=people,dc=example,dc=org
    user_attribute: uid
    group_base_dn: ou=groups,dc=example,dc=org
    group_member_attribute: member
    group_name_attribute: cn
```

For StartTLS, use the directory's LDAP URL and `start_tls: true`. Filters escape
user input. The default throttle permits five failed attempts per username and
source address within five minutes; successful login resets that counter.

```sh
allowops login --gateway https://gateway.example.org \
  --provider directory --username operator
```

The CLI reads a hidden terminal password. Automation may use `--password-stdin`
with a secret-store input stream. Never put passwords in arguments. Use
`--ca-file` for a private gateway TLS CA; there is no TLS-verification bypass.

## Service accounts and sessions

Create service accounts in the console. Record a responsible owner, purpose and
explicit roles. Tokens are shown once and stored as SHA-256 hashes, default to
30 days, and may be configured for 1–365 days. Give each client its own token;
revoke unused or leaked tokens. A publisher needs `publish_catalog`, not action
execution. A reader needs explicit execution and output access for its hosts.

Console and CLI sessions default to seven days. CLI credentials are stored in
the user's configuration directory (`~/.config/allowops/credentials` on Linux)
with mode 0600. Console sessions use Secure, HttpOnly, SameSite=Strict cookies
and CSRF checks. Users can list and revoke their own CLI sessions in the console;
administrators can manage other users' sessions.

MCP sends a Bearer header on every request. It does not authenticate through
console cookies or query parameters. MCP OAuth is a roadmap feature; use service
account tokens for client setup. See [MCP clients](mcp.md).

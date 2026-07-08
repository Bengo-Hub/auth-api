# Security Policy

Identity and access management is a critical component of the Codevertex platform. We take security seriously and ask that you do too.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | ✅ |
| Release tags (when published) | ✅ |
| Other forks/branches | ❌ |

Security fixes will be backported to the latest supported release when applicable.

## Reporting a Vulnerability

If you discover a security vulnerability:
1. **Do not** open a public issue.
2. Email the security team at `security@bengobox.com`.
3. Include detailed reproduction steps, impact assessment, and any mitigation ideas.

You will receive an acknowledgement within 48 hours and regular status updates until resolution.

## Handling Sensitive Data

- Never commit secrets, private keys, or production data.
- Use `.env` files (excluded via `.gitignore`) or your secret manager of choice locally.
- Encrypt exports and share via approved secure channels only.

## Coordinated Disclosure

We follow a 90-day disclosure policy unless a fix is ready sooner. We appreciate responsible disclosure and will publicly credit reporters where appropriate.

## Hardening Checklist

- Rotate signing keys regularly and store them in managed KMS/HSM.
- Enforce MFA for privileged accounts.
- Maintain short-lived access tokens with refresh token rotation.
- Monitor audit logs (`audit_logs`, `security_events`) for anomalies.
- Run dependency vulnerability scans (e.g., `govulncheck`, Snyk).

Thank you for helping keep the platform safe.


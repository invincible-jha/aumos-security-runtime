# Security Policy

## Reporting a Vulnerability

The AumOS platform team takes security vulnerabilities seriously. We appreciate your
efforts to responsibly disclose your findings.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Email your findings to: **security@aumos.io**

Include in your report:
- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any proof-of-concept code (if applicable)
- Your recommended fix (if you have one)

You will receive an acknowledgment within **48 hours** and a detailed response
within **5 business days**.

## Scope

The following are in scope for security reports:

- Authentication and authorization bypass
- Tenant isolation violations (RLS bypass, cross-tenant data access)
- Security detection bypass — inputs that should be blocked but are not
- False negative exploitation — deliberate evasion of prompt injection detection
- PII leakage through redaction bypass
- Remote code execution via scanner inputs
- Sensitive data exposure through scan logs or API responses
- API security issues (broken object-level authorization, rate limiting bypass)

The following are out of scope:

- Denial of service attacks against the scanner (high-volume)
- False positives (inputs incorrectly flagged) — report as a bug, not a security issue
- Social engineering of AumOS staff
- Physical security issues
- Vulnerabilities in third-party services we do not control

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Status update | Every 7 days during investigation |
| Fix deployment (critical) | Within 7 days of confirmation |
| Fix deployment (high) | Within 30 days of confirmation |
| Fix deployment (medium/low) | Next scheduled release |

## Disclosure Policy

- We follow a **90-day coordinated disclosure** policy
- We will notify you when the fix is deployed
- We will credit you in our release notes (unless you prefer anonymity)
- We ask that you do not publicly disclose the vulnerability until we have released a fix

## Security Best Practices for Contributors

When contributing to this repository:

1. Never commit secrets, API keys, or credentials (even test credentials)
2. Use parameterized queries — never string concatenation in SQL
3. Validate all inputs at system boundaries using Pydantic
4. Never log sensitive data (tokens, passwords, PII content)
5. Never log the raw content of scanned inputs — log hashes or metadata only
6. Check dependency licenses and security advisories before adding packages
7. When adding new detection patterns, also add evasion test cases
8. Report any security issues you discover, even if you are not sure of the impact

## Special Considerations for a Security Service

This service is specifically designed to detect and prevent security threats. This
creates unique responsibilities:

- **Pattern secrecy**: Detection patterns and ML model weights should not be exposed
  via API responses, logs, or error messages — adversaries could use them to craft
  evasion attacks.
- **Fail-closed behavior**: When in doubt, the service should block rather than allow.
  A false positive is far preferable to a false negative in a security context.
- **Audit trail integrity**: The `sec_security_scans` and `sec_threat_detections` tables
  are security audit logs. Any vulnerability allowing modification of these records is
  critical severity.

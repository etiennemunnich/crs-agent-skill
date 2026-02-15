# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public issue.**

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Scope

This project contains:

- **Agent skill definitions** (SKILL.md, references) -- instructional content
- **Python/Bash scripts** -- rule validation, lint, log analysis
- **Docker Compose files** -- local test environments

Security concerns most likely involve:

- Scripts that process untrusted input (rule files, log files, OpenAPI specs)
- Docker configurations with exposed ports or insecure defaults
- Regex patterns vulnerable to ReDoS (which is ironic given that `lint_regex.py` exists to catch these)

## Response

I will acknowledge receipt within 48 hours and aim to provide a fix or mitigation
within 14 days for confirmed vulnerabilities.

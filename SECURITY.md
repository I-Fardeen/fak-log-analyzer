# Security Policy

## Supported Versions

Security fixes are generally applied to the latest maintained release of FAK Log Analyzer.

| Version | Supported |
| ------- | --------- |
| 0.5.x   | Yes       |
| < 0.5    | No        |

Support for older versions may be discontinued as the project evolves toward the 1.0 release.

---

## Reporting a Vulnerability

Please **do not report security vulnerabilities through public GitHub issues**.

If you discover a potential security vulnerability in FAK Log Analyzer, please report it privately so that it can be investigated and addressed responsibly.

### Preferred Method

Use GitHub's private vulnerability reporting mechanism:

**Repository → Security → Advisories → Report a vulnerability**

Repository:

https://github.com/I-Fardeen/fak-log-analyzer

If private vulnerability reporting is unavailable, contact the project maintainer directly:

**Email:** fardeenahmadkhan786@gmail.com

Please provide enough information to reproduce and assess the vulnerability.

---

## What to Include

Where possible, include:

- A clear description of the vulnerability
- Affected version
- Python version
- Operating system
- Steps to reproduce the issue
- Minimal proof-of-concept input
- Expected behavior
- Actual behavior
- Potential security impact
- Suggested mitigation, if known

Please avoid including confidential information, credentials, personal data, or real production logs.

Use sanitized or synthetic log data whenever possible.

---

## Vulnerability Handling

Security reports will be reviewed by the project maintainer.

Depending on the severity and nature of the issue, the response may include:

1. Confirmation of the report.
2. Reproduction and technical assessment.
3. Identification of affected versions.
4. Development and testing of a fix.
5. Preparation of a security release when necessary.
6. Publication of appropriate release notes.
7. Public disclosure after a reasonable remediation period.

The exact timeline may vary depending on the severity and complexity of the issue.

---

## Scope

Security reports may include issues involving:

- Malicious or unexpected log input
- Parser vulnerabilities
- Input validation weaknesses
- Path or file handling issues
- Dependency vulnerabilities
- CLI security issues
- Data exposure
- Denial-of-service conditions
- Unsafe processing of attacker-controlled log data

Issues that are purely functional bugs without a security impact should generally be reported through GitHub Issues instead.

---

## Responsible Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a security vulnerability.

The project appreciates responsible disclosure and will make reasonable efforts to acknowledge valid security reports.

---

## Security Considerations for Users

FAK Log Analyzer processes potentially untrusted log files.

Users should:

- Avoid running the analyzer with unnecessary privileges.
- Avoid processing sensitive logs on untrusted systems.
- Review generated reports before sharing them.
- Treat log files as potentially sensitive data.
- Avoid committing real production logs containing personal or confidential information.
- Keep project dependencies reasonably up to date.

FAK Log Analyzer does not require a database or external service for its core analysis functionality.

---

## Contact

**Project:** FAK Log Analyzer  
**Repository:** https://github.com/I-Fardeen/fak-log-analyzer  
**Maintainer:** Fardeen Ahmad Khan  
**Email:** fardeenahmadkhan786@gmail.com  
**ORCID:** https://orcid.org/0009-0004-8726-6836

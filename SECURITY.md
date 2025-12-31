# SECURITY.md — security posture and disclosure

## Read-only posture
SCA is designed to be non-invasive:
- never modifies audited repositories
- never executes LLM outputs
- does not auto-apply patches

## Data handling
SCA reads repository content and produces local reports.
The model backend (e.g., Claude Code) may transmit prompts to a model provider depending on your configuration.
You are responsible for ensuring your usage complies with your organization policies.

## Reporting vulnerabilities in SCA
- Use responsible disclosure.
- Provide minimal reproduction steps and affected versions.

## Threat model notes
- SCA outputs are advisory and require human judgment.
- Treat all tool outputs as untrusted until reviewed.


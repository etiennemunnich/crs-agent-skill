# Contributing to CRS Agent Skill

Thank you for your interest in contributing! This project provides agent skills for
ModSecurity, Coraza, and OWASP CRS WAF rule management.

## How to Contribute

### Reporting Issues

- **Bugs**: Use the [bug report template](https://github.com/etiennemunnich/crs-agent-skill/issues/new?template=bug-report.yml)
- **Features**: Use the [feature request template](https://github.com/etiennemunnich/crs-agent-skill/issues/new?template=feature-request.yml)
- **Documentation**: Use the [reference request template](https://github.com/etiennemunnich/crs-agent-skill/issues/new?template=reference-request.yml)

### Pull Requests

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run the checks below
5. Submit a PR against `main`

### Pre-Submission Checklist

Run these before pushing:

```bash
# Markdown lint (install: npm install -g markdownlint-cli2)
markdownlint-cli2 "**/*.md" --ignore research

# Python syntax check
for f in src/waf-rule-management/scripts/*.py; do python -m py_compile "$f"; done

# ShellCheck (install: brew install shellcheck)
shellcheck src/waf-rule-management/scripts/*.sh

# Verify --help flags work
for f in src/waf-rule-management/scripts/*.py; do python "$f" --help > /dev/null; done
```

## What to Contribute

### High-Value Contributions

- **New reference docs**: Fill gaps in WAF rule management guidance
- **Script improvements**: Better validation, new linters, broader format support
- **Platform support**: Install/config instructions for new AI coding agents
- **Test coverage**: More edge cases in validation and lint scripts
- **Bug fixes**: Especially in scripts and Docker configurations

### Reference Documentation Guidelines

- Keep files focused on one topic (progressive loading depends on this)
- Include practical examples, not just theory
- Link to official upstream docs (CRS, ModSecurity, Coraza)
- Add the file to the Progressive Loading Index in `SKILL.md`
- Use tags that help agents route to the right file

### Script Guidelines

- All Python scripts must support `--help`
- Use `argparse` for argument parsing
- Support Python 3.8+ (no walrus operator, etc.)
- Include clear error messages
- Shell scripts must pass ShellCheck

## Code of Conduct

Be respectful, constructive, and collaborative. This project follows the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Questions?

Open a blank issue or reach out via the OWASP Slack `#coreruleset` channel.

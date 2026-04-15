# Code Reviewer AI MCP Server

> By [MEOK AI Labs](https://meok.ai) — Code review with issue detection, security scanning, and improvement suggestions

## Installation

```bash
pip install code-reviewer-ai-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `review_code`
Review code for bugs, security issues, and improvements. Returns categorized findings.

**Parameters:**
- `code` (str): Code to review
- `language` (str): Programming language (default 'python')

### `check_security`
Scan code for OWASP Top 10 vulnerabilities, hardcoded secrets, and injection risks.

**Parameters:**
- `code` (str): Code to scan

### `suggest_improvements`
Suggest refactoring opportunities, performance improvements, and best practices.

**Parameters:**
- `code` (str): Code to analyze

### `check_complexity`
Calculate cyclomatic complexity and identify overly complex functions.

**Parameters:**
- `code` (str): Code to analyze

## Authentication

Free tier: 30 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs

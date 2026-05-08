<div align="center">

# Code Reviewer Ai MCP

**MCP server for code reviewer ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-code-reviewer-ai-mcp)](https://pypi.org/project/meok-code-reviewer-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Code Reviewer Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `review_code` | Comprehensive code review: security, style, complexity, and quality metrics. |
| `check_style` | Check code style against language conventions and best practices. |
| `find_bugs` | Detect common bug patterns: null references, off-by-one errors, resource leaks,  |
| `suggest_improvements` | Suggest refactoring opportunities, performance improvements, and best practices. |
| `security_scan` | Deep security scan for OWASP Top 10, hardcoded secrets, injection risks, and CWE |

## Installation

```bash
pip install meok-code-reviewer-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "code-reviewer-ai": {
      "command": "python",
      "args": ["-m", "meok_code_reviewer_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)

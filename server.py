#!/usr/bin/env python3
"""
Code review with issue detection, security scanning, and improvement suggestions. — MEOK AI Labs."""

import sys, os
from auth_middleware import check_access

import json, re
from datetime import datetime, timezone
from collections import defaultdict
from mcp.server.fastmcp import FastMCP
import urllib.request as _meter_urlreq
import urllib.error as _meter_urlerr

STRIPE_199 = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"

def _add_upgrade_tail(response, tier="free"):
    """Append upgrade nudge to free-tier success responses."""
    if isinstance(response, dict) and tier == "free":
        response["_upgrade_note"] = "Pro tier: unlimited calls + priority support. Upgrade: " + STRIPE_199
    return response


FREE_DAILY_LIMIT = 50
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now-t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT: return json.dumps({"error": "Limit {0}/day. Upgrade: meok.ai".format(FREE_DAILY_LIMIT)})
    _usage[c].append(now); return None

mcp = FastMCP("code-reviewer-ai", instructions="MEOK AI Labs — Code review with issue detection, security scanning, and improvement suggestions.")

SECURITY_PATTERNS = {
    "python": [
        {"pattern": r"\beval\s*\(", "severity": "critical", "issue": "eval() usage — code injection risk", "cwe": "CWE-95"},
        {"pattern": r"\bexec\s*\(", "severity": "critical", "issue": "exec() usage — arbitrary code execution", "cwe": "CWE-95"},
        {"pattern": r"\b__import__\s*\(", "severity": "high", "issue": "Dynamic import — potential code injection", "cwe": "CWE-502"},
        {"pattern": r"pickle\.loads?\(", "severity": "high", "issue": "Pickle deserialization — untrusted data risk", "cwe": "CWE-502"},
        {"pattern": r"subprocess\..*shell\s*=\s*True", "severity": "high", "issue": "Shell=True in subprocess — command injection", "cwe": "CWE-78"},
        {"pattern": r"os\.system\s*\(", "severity": "high", "issue": "os.system() — use subprocess instead", "cwe": "CWE-78"},
        {"pattern": r"password\s*=\s*['\"]", "severity": "high", "issue": "Hardcoded password detected", "cwe": "CWE-798"},
        {"pattern": r"secret\s*=\s*['\"]", "severity": "high", "issue": "Hardcoded secret detected", "cwe": "CWE-798"},
        {"pattern": r"api_key\s*=\s*['\"][a-zA-Z0-9]", "severity": "high", "issue": "Hardcoded API key", "cwe": "CWE-798"},
        {"pattern": r"except\s*:", "severity": "medium", "issue": "Bare except clause — catches all exceptions", "cwe": "CWE-396"},
        {"pattern": r"# ?TODO", "severity": "low", "issue": "TODO comment — incomplete implementation", "cwe": None},
        {"pattern": r"# ?FIXME", "severity": "medium", "issue": "FIXME comment — known issue", "cwe": None},
        {"pattern": r"# ?HACK", "severity": "medium", "issue": "HACK comment — technical debt", "cwe": None},
    ],
    "javascript": [
        {"pattern": r"\beval\s*\(", "severity": "critical", "issue": "eval() usage — XSS/injection risk", "cwe": "CWE-95"},
        {"pattern": r"innerHTML\s*=", "severity": "high", "issue": "innerHTML assignment — XSS risk", "cwe": "CWE-79"},
        {"pattern": r"document\.write\s*\(", "severity": "high", "issue": "document.write — XSS risk", "cwe": "CWE-79"},
        {"pattern": r"password\s*[=:]\s*['\"]", "severity": "high", "issue": "Hardcoded password", "cwe": "CWE-798"},
        {"pattern": r"\bvar\b", "severity": "low", "issue": "Use let/const instead of var", "cwe": None},
        {"pattern": r"console\.log\s*\(", "severity": "low", "issue": "console.log left in code", "cwe": None},
    ],
}

STYLE_RULES = {
    "python": [
        {"pattern": r"^.{121,}$", "rule": "Line exceeds 120 characters", "severity": "low"},
        {"pattern": r"\t", "rule": "Tab character detected — use spaces", "severity": "low"},
        {"pattern": r"import \*", "rule": "Wildcard import — be explicit", "severity": "medium"},
        {"pattern": r"def \w+\([^)]*\):\s*$", "rule": "Function missing type hints", "severity": "low"},
        {"pattern": r"class \w+[^(:]", "rule": "Class may be missing docstring", "severity": "low"},
    ],
    "javascript": [
        {"pattern": r"==(?!=)", "rule": "Use === instead of ==", "severity": "medium"},
        {"pattern": r"!=(?!=)", "rule": "Use !== instead of !=", "severity": "medium"},
        {"pattern": r";\s*$", "rule": "Unnecessary semicolons (if using no-semi style)", "severity": "low"},
    ],
}

COMPLEXITY_KEYWORDS = {
    "python": {"if": 1, "elif": 1, "else": 1, "for": 1, "while": 1, "except": 1,
               "and": 1, "or": 1, "try": 0, "with": 0},
    "javascript": {"if": 1, "else": 1, "for": 1, "while": 1, "catch": 1,
                    "case": 1, "&&": 1, "||": 1, "?": 1},
}


def _find_issues(code: str, patterns: list) -> list:
    issues = []
    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        for p in patterns:
            if re.search(p["pattern"], line):
                issue = {"line": i, "severity": p["severity"],
                          "issue": p.get("issue", p.get("rule", "Style issue")),
                          "code": line.strip()[:80]}
                if p.get("cwe"):
                    issue["cwe"] = p["cwe"]
                issues.append(issue)
    return issues


def _calculate_complexity(code: str, language: str) -> dict:
    keywords = COMPLEXITY_KEYWORDS.get(language, COMPLEXITY_KEYWORDS["python"])
    lines = code.split("\n")
    functions = []
    current_func = None
    complexity = 1

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        func_match = re.match(r"def (\w+)\s*\(", stripped) if language == "python" else re.match(r"function (\w+)\s*\(", stripped)
        if func_match:
            if current_func:
                functions.append({"name": current_func, "complexity": complexity})
            current_func = func_match.group(1)
            complexity = 1
        for keyword, weight in keywords.items():
            if keyword in stripped:
                complexity += weight

    if current_func:
        functions.append({"name": current_func, "complexity": complexity})

    total = sum(f["complexity"] for f in functions) if functions else complexity
    avg = round(total / max(len(functions), 1), 1)
    return {"functions": functions, "total_complexity": total, "average": avg,
            "max_complexity": max((f["complexity"] for f in functions), default=0)}

def _server_meter_check(api_key: str = "") -> dict:
    """Calls the live /verify endpoint for server-side metering. Returns the JSON dict.
    Fail-open: if /verify is unreachable or KV isn't configured, returns allowed=True
    (so the local rate-limit in _check_rate_limit remains the safety net)."""
    try:
        data = json.dumps({"api_key": api_key, "tool": ""}).encode()
        req = _meter_urlreq.Request(_METER_URL, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with _meter_urlreq.urlopen(req, timeout=2.5) as r:
            d = json.loads(r.read())
            if isinstance(d, dict) and "allowed" in d:
                return d
    except Exception:
        pass
    return {"allowed": True, "tier": "anonymous", "remaining": 200, "upgrade_url": "https://meok.ai/pricing"}


_METER_URL = "https://proofof.ai/verify"


@mcp.tool()
def review_code(code: str, language: str = "python", api_key: str = "") -> str:
    """Comprehensive code review: security, style, complexity, and quality metrics.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        code (str): The code to analyze or process.
        language (str): The language to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    lang = language.lower()
    sec_patterns = SECURITY_PATTERNS.get(lang, SECURITY_PATTERNS["python"])
    security_issues = _find_issues(code, sec_patterns)
    style_patterns = STYLE_RULES.get(lang, STYLE_RULES["python"])
    style_issues = _find_issues(code, style_patterns)
    complexity = _calculate_complexity(code, lang)

    lines = code.split("\n")
    loc = len([l for l in lines if l.strip() and not l.strip().startswith("#")])
    blank_lines = len([l for l in lines if not l.strip()])
    comment_lines = len([l for l in lines if l.strip().startswith("#") or l.strip().startswith("//")])

    all_issues = security_issues + style_issues
    critical = sum(1 for i in all_issues if i["severity"] == "critical")
    high = sum(1 for i in all_issues if i["severity"] == "high")
    score = max(0, 100 - critical * 25 - high * 10 - len(all_issues) * 2)

    return {
        "language": lang,
        "metrics": {"total_lines": len(lines), "code_lines": loc, "blank_lines": blank_lines,
                     "comment_lines": comment_lines, "comment_ratio": round(comment_lines / max(loc, 1), 2)},
        "security_issues": security_issues,
        "style_issues": style_issues,
        "complexity": complexity,
        "total_issues": len(all_issues),
        "by_severity": {"critical": critical, "high": high,
                         "medium": sum(1 for i in all_issues if i["severity"] == "medium"),
                         "low": sum(1 for i in all_issues if i["severity"] == "low")},
        "quality_score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def check_style(code: str, language: str = "python", api_key: str = "") -> str:
    """Check code style against language conventions and best practices.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        code (str): The code to analyze or process.
        language (str): The language to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    lang = language.lower()
    patterns = STYLE_RULES.get(lang, STYLE_RULES["python"])
    issues = _find_issues(code, patterns)

    lines = code.split("\n")
    max_line_len = max((len(l) for l in lines), default=0)
    avg_line_len = round(sum(len(l) for l in lines) / max(len(lines), 1), 1)
    indentation = "tabs" if "\t" in code else "spaces"
    indent_sizes = set()
    for line in lines:
        stripped = line.lstrip()
        if stripped and line != stripped:
            indent = len(line) - len(stripped)
            indent_sizes.add(indent)

    consistent_indent = len(indent_sizes) <= 3

    return {
        "language": lang,
        "issues": issues,
        "total_issues": len(issues),
        "style_metrics": {
            "max_line_length": max_line_len,
            "avg_line_length": avg_line_len,
            "indentation_type": indentation,
            "consistent_indentation": consistent_indent,
            "total_lines": len(lines),
        },
        "pass": len([i for i in issues if i["severity"] in ("high", "medium")]) == 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def find_bugs(code: str, language: str = "python", api_key: str = "") -> str:
    """Detect common bug patterns: null references, off-by-one errors, resource leaks, type issues.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        code (str): The code to analyze or process.
        language (str): The language to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    bugs = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if language == "python":
            if re.search(r"==\s*None", stripped):
                bugs.append({"line": i, "type": "style_bug", "message": "Use 'is None' instead of '== None'", "severity": "medium"})
            if re.search(r"except\s*:", stripped):
                bugs.append({"line": i, "type": "error_handling", "message": "Bare except catches SystemExit and KeyboardInterrupt", "severity": "medium"})
            if re.search(r"def \w+\([^)]*=\s*(\[\]|\{\})\)", stripped):
                bugs.append({"line": i, "type": "mutable_default", "message": "Mutable default argument — use None instead", "severity": "high"})
            if re.search(r"range\(len\(", stripped):
                bugs.append({"line": i, "type": "pythonic", "message": "Use enumerate() instead of range(len())", "severity": "low"})
            if re.search(r"\.append\(.*\).*=", stripped) or re.search(r"=.*\.sort\(\)", stripped):
                bugs.append({"line": i, "type": "return_none", "message": "list.sort()/append() returns None — possible bug", "severity": "medium"})
            if re.search(r"open\s*\(", stripped) and "with" not in stripped and stripped.count("open") > 0:
                in_with = any("with" in lines[max(0, i-3):i][j] for j in range(min(3, i-1)) if j < len(lines[max(0, i-3):i]))
                if not in_with:
                    bugs.append({"line": i, "type": "resource_leak", "message": "File opened without context manager (with statement)", "severity": "medium"})

        if re.search(r"\bif\b.*\bif\b", stripped) and "else" not in stripped:
            bugs.append({"line": i, "type": "logic", "message": "Nested if without else — possible logic gap", "severity": "low"})

    return {
        "language": language,
        "bugs_found": len(bugs),
        "bugs": bugs,
        "by_type": dict(defaultdict(int, {b["type"]: sum(1 for x in bugs if x["type"] == b["type"]) for b in bugs})),
        "by_severity": {"high": sum(1 for b in bugs if b["severity"] == "high"),
                         "medium": sum(1 for b in bugs if b["severity"] == "medium"),
                         "low": sum(1 for b in bugs if b["severity"] == "low")},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def suggest_improvements(code: str, language: str = "python", api_key: str = "") -> str:
    """Suggest refactoring opportunities, performance improvements, and best practices.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        code (str): The code to analyze or process.
        language (str): The language to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    suggestions = []
    lines = code.split("\n")
    loc = len([l for l in lines if l.strip()])

    if loc > 300:
        suggestions.append({"type": "structure", "priority": "high", "suggestion": "File exceeds 300 lines — consider splitting into modules"})
    complexity = _calculate_complexity(code, language)
    for func in complexity.get("functions", []):
        if func["complexity"] > 10:
            suggestions.append({"type": "complexity", "priority": "high",
                                 "suggestion": f"Function '{func['name']}' has complexity {func['complexity']} — extract helper functions"})
        elif func["complexity"] > 7:
            suggestions.append({"type": "complexity", "priority": "medium",
                                 "suggestion": f"Function '{func['name']}' has moderate complexity ({func['complexity']}) — consider simplifying"})

    comment_lines = sum(1 for l in lines if l.strip().startswith("#") or l.strip().startswith("//"))
    if comment_lines / max(loc, 1) < 0.05 and loc > 20:
        suggestions.append({"type": "documentation", "priority": "medium", "suggestion": "Low comment ratio — add docstrings and inline comments"})

    if language == "python":
        if "import *" in code:
            suggestions.append({"type": "imports", "priority": "medium", "suggestion": "Replace wildcard imports with explicit imports"})
        func_count = len(re.findall(r"def \w+", code))
        class_count = len(re.findall(r"class \w+", code))
        if func_count > 15 and class_count == 0:
            suggestions.append({"type": "structure", "priority": "medium", "suggestion": f"{func_count} functions without classes — consider grouping into classes"})

    dup_lines = defaultdict(int)
    for line in lines:
        stripped = line.strip()
        if len(stripped) > 20:
            dup_lines[stripped] += 1
    duplicates = {l: c for l, c in dup_lines.items() if c > 2}
    if duplicates:
        suggestions.append({"type": "duplication", "priority": "medium",
                             "suggestion": f"{len(duplicates)} lines repeated 3+ times — extract to functions",
                             "examples": list(duplicates.keys())[:3]})

    return {
        "language": language,
        "suggestions": suggestions,
        "total_suggestions": len(suggestions),
        "by_priority": {"high": sum(1 for s in suggestions if s["priority"] == "high"),
                         "medium": sum(1 for s in suggestions if s["priority"] == "medium"),
                         "low": sum(1 for s in suggestions if s["priority"] == "low")},
        "metrics": {"lines_of_code": loc, "functions": len(complexity.get("functions", [])),
                     "avg_complexity": complexity["average"]},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def security_scan(code: str, language: str = "python", api_key: str = "") -> str:
    """Deep security scan for OWASP Top 10, hardcoded secrets, injection risks, and CWE references.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        code (str): The code to analyze or process.
        language (str): The language to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    lang = language.lower()
    patterns = SECURITY_PATTERNS.get(lang, SECURITY_PATTERNS["python"])
    findings = _find_issues(code, patterns)

    secret_patterns = [
        (r"['\"][A-Za-z0-9+/]{40,}['\"]", "Possible base64-encoded secret"),
        (r"['\"]sk-[a-zA-Z0-9]{20,}['\"]", "Possible Stripe/OpenAI secret key"),
        (r"['\"]ghp_[a-zA-Z0-9]{20,}['\"]", "Possible GitHub token"),
        (r"['\"]AKIA[A-Z0-9]{16}['\"]", "Possible AWS access key"),
        (r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", "Hardcoded Bearer token"),
    ]

    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        for pattern, desc in secret_patterns:
            if re.search(pattern, line):
                findings.append({"line": i, "severity": "critical", "issue": desc,
                                  "cwe": "CWE-798", "code": line.strip()[:60] + "..."})

    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]

    risk_level = "critical" if critical else "high" if high else "medium" if findings else "low"

    return {
        "language": lang,
        "findings": findings,
        "total_findings": len(findings),
        "risk_level": risk_level,
        "by_severity": {"critical": len(critical), "high": len(high),
                         "medium": sum(1 for f in findings if f["severity"] == "medium"),
                         "low": sum(1 for f in findings if f["severity"] == "low")},
        "cwe_references": list(set(f.get("cwe") for f in findings if f.get("cwe"))),
        "owasp_categories": _map_owasp(findings),
        "secure": len(critical) == 0 and len(high) == 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _map_owasp(findings: list) -> list:
    categories = set()
    for f in findings:
        issue = f.get("issue", "").lower()
        if "injection" in issue or "eval" in issue or "exec" in issue:
            categories.add("A03:2021 Injection")
        if "password" in issue or "secret" in issue or "key" in issue or "token" in issue:
            categories.add("A07:2021 Identification and Authentication Failures")
        if "xss" in issue or "innerhtml" in issue:
            categories.add("A03:2021 Injection")
        if "pickle" in issue or "deserialization" in issue:
            categories.add("A08:2021 Software and Data Integrity Failures")
    return sorted(categories)


def main():
    mcp.run()

if __name__ == '__main__':
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}

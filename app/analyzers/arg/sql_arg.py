"""Static SQL analysis.

Statements are tokenised and matched, never sent to an engine.  The two things
that matter most here are *blast radius* (does this statement carry a WHERE
clause, or does it hit the whole table?) and *table sensitivity* (is this
credentials data?).  Those are exactly the differences that a tool-level policy
- which only sees "database.delete" - cannot express.
"""

from __future__ import annotations

import re

from app.analyzers.arg.common import (
    aggregate_risk,
    confidence_from,
    dedupe_findings,
    merge_finding_capabilities,
)
from app.models.enums import Capability, ResourceClass, Scope, Severity
from app.models.tool_call import ArgumentAnalysis, Finding, ResourceDescriptor

ANALYZER = "sql"

STATEMENT_CAPABILITIES: dict[str, tuple[list[Capability], Severity]] = {
    "SELECT": ([Capability.READ, Capability.DATABASE], Severity.INFO),
    "INSERT": ([Capability.WRITE, Capability.DATABASE], Severity.LOW),
    "UPDATE": ([Capability.MODIFY, Capability.DATABASE], Severity.MEDIUM),
    "DELETE": ([Capability.DELETE, Capability.DATABASE], Severity.HIGH),
    "DROP": ([Capability.DELETE, Capability.DATABASE], Severity.CRITICAL),
    "TRUNCATE": ([Capability.DELETE, Capability.DATABASE], Severity.CRITICAL),
    "ALTER": ([Capability.MODIFY, Capability.DATABASE], Severity.HIGH),
    "CREATE": ([Capability.WRITE, Capability.DATABASE], Severity.LOW),
    "GRANT": ([Capability.PRIVILEGE_CHANGE, Capability.DATABASE], Severity.CRITICAL),
    "REVOKE": ([Capability.PRIVILEGE_CHANGE, Capability.DATABASE], Severity.HIGH),
    "ATTACH": ([Capability.DATABASE, Capability.READ], Severity.HIGH),
}

SENSITIVE_TABLE_RE = re.compile(
    r"(user|users|accounts?|credentials?|passwords?|auth|token|session|"
    r"ssn|salary|salaries|payroll|payment|credit_?card|billing|"
    r"confidential|classified|secret|patient|medical|health|hr_)",
    re.I,
)

INJECTION_PATTERNS: tuple[tuple[str, str, Severity], ...] = (
    # `OR 1=1`, `OR '1'='1'`, `OR name = name` - a comparison that is always true
    ("SQL_TAUTOLOGY", r"""(?i)\bor\s+['"]?(\w+)['"]?\s*=\s*['"]?\1['"]?""", Severity.CRITICAL),
    ("SQL_UNION_INJECTION", r"(?i)\bunion\s+(all\s+)?select\b", Severity.HIGH),
    ("SQL_COMMENT_TRUNCATION", r"(--|#)\s*$|/\*.*\*/", Severity.MEDIUM),
    ("SQL_SLEEP_PROBE", r"(?i)\b(sleep|pg_sleep|waitfor\s+delay)\s*\(", Severity.HIGH),
)

FILE_ACCESS_PATTERNS: tuple[tuple[str, str, Severity, list[Capability]], ...] = (
    ("SQL_OUTFILE", r"(?i)\binto\s+(out|dump)file\b", Severity.CRITICAL, [Capability.WRITE, Capability.UPLOAD]),
    ("SQL_LOAD_FILE", r"(?i)\bload_file\s*\(", Severity.CRITICAL, [Capability.READ]),
    ("SQL_COPY_TO", r"(?i)\bcopy\b.+\bto\b\s+'", Severity.HIGH, [Capability.WRITE, Capability.UPLOAD]),
    ("SQL_XP_CMDSHELL", r"(?i)\bxp_cmdshell\b", Severity.CRITICAL, [Capability.EXECUTE, Capability.PRIVILEGE_CHANGE]),
    ("SQL_PG_READ_FILE", r"(?i)\bpg_read_file\s*\(", Severity.CRITICAL, [Capability.READ]),
)

#: The optional article tolerates planner output such as "delete from the users
#: table", which otherwise records a table called `the` and hides `users`.
TABLE_RE = re.compile(
    r"(?is)\b(?:from|into|update|join|table)\s+(?:the\s+)?[\"`\[]?(?!(?:table|where|to|set|values|select|as|with|on|if)\b)([a-zA-Z_][\w$]*(?:\.[a-zA-Z_][\w$]*)?)"
)
STRING_LITERAL_RE = re.compile(r"'([^']|'')*'")


def _statements(query: str) -> list[str]:
    """Split on top-level semicolons (string literals masked first)."""
    masked = STRING_LITERAL_RE.sub(lambda m: "'" + "x" * (len(m.group(0)) - 2) + "'", query)
    parts, start = [], 0
    for i, ch in enumerate(masked):
        if ch == ";":
            parts.append(query[start:i])
            start = i + 1
    parts.append(query[start:])
    return [p.strip() for p in parts if p.strip()]


TAUTOLOGY_WHERE_RE = re.compile(
    r"""(?is)\bwhere\s+(?:true|1|(['"]?)(\w+)\1\s*=\s*\1\2\1)\s*(?:;|$|\b(?:or|order|limit)\b)"""
)
COMMENT_RE = re.compile(r"/\*.*?\*/|--[^\n]*|#[^\n]*", re.S)
DYNAMIC_RE = re.compile(
    r"(?is)^\s*(?:prepare\s+\w+\s+from|execute\s+immediate)\s+'((?:[^']|'')*)'\s*;?\s*(?:execute\s+\w+\s*;?)?\s*$"
)


def _canonical(query: str) -> tuple[str, bool]:
    """The statement the database would actually run, as far as text shows it.

    Comments are removed, because `/* routine */ DELETE ...` is a DELETE and
    must be classified as one; a statement handed to PREPARE or EXECUTE
    IMMEDIATE as a literal is unwrapped, because the literal is the statement.
    Returns the canonical text and whether an unwrapping happened.
    """
    text = COMMENT_RE.sub(" ", query)
    m = DYNAMIC_RE.match(text)
    if m:
        return m.group(1).replace("''", "'").strip(), True
    return text.strip(), False


def analyze_sql(query: str, tool_name: str = "database.select") -> ArgumentAnalysis:
    query = query or ""
    findings: list[Finding] = []
    capabilities: set[Capability] = {Capability.DATABASE}
    resources: list[ResourceDescriptor] = []

    if not query.strip():
        return ArgumentAnalysis(
            tool_name=tool_name, analyzer=ANALYZER, capabilities=[Capability.DATABASE],
            risk=15.0, confidence=0.5, scope=Scope.NONE, explanation="empty query",
        )

    raw_query = query
    query, dynamic = _canonical(query)
    if dynamic:
        findings.append(Finding(
            code="SQL_DYNAMIC_STATEMENT", severity=Severity.HIGH, analyzer=ANALYZER,
            message="statement text is passed to PREPARE/EXECUTE rather than issued directly",
            evidence=raw_query[:120],
        ))

    statements = _statements(query)
    if len(statements) > 1:
        findings.append(Finding(
            code="SQL_STACKED_STATEMENTS", severity=Severity.HIGH, analyzer=ANALYZER,
            message=f"{len(statements)} statements submitted in one call (stacked-query pattern)",
            evidence=query[:120],
        ))

    widest = Scope.SINGLE
    verbs: list[str] = []
    for statement in statements:
        m = re.match(r"(?is)^\s*(\w+)", statement)
        verb = (m.group(1).upper() if m else "UNKNOWN")
        verbs.append(verb)
        caps, severity = STATEMENT_CAPABILITIES.get(verb, ([Capability.DATABASE], Severity.MEDIUM))
        capabilities.update(caps)

        # A WHERE clause that is always true bounds nothing: `DELETE ... WHERE
        # 1=1` and `TRUNCATE` remove the same rows and must score as one act.
        has_where = bool(re.search(r"(?is)\bwhere\b", statement)) and not TAUTOLOGY_WHERE_RE.search(statement)
        unbounded = verb in {"DELETE", "UPDATE"} and not has_where
        if verb in {"DROP", "TRUNCATE"}:
            unbounded = True

        if unbounded:
            severity = Severity.CRITICAL
            widest = Scope.UNBOUNDED
            findings.append(Finding(
                code="SQL_UNBOUNDED_MUTATION", severity=Severity.CRITICAL, analyzer=ANALYZER,
                message=f"{verb} affects every row/object: no WHERE clause",
                evidence=statement[:120], capabilities=caps,
            ))
        elif verb == "SELECT" and re.search(r"(?is)select\s+\*", statement) and not re.search(r"(?is)\blimit\b", statement):
            widest = max(widest, Scope.MULTIPLE, key=lambda s: list(Scope).index(s))
            findings.append(Finding(
                code="SQL_UNBOUNDED_SELECT", severity=Severity.MEDIUM, analyzer=ANALYZER,
                message="SELECT * with no LIMIT reads the full table",
                evidence=statement[:120], capabilities=[Capability.READ],
            ))

        if verb in STATEMENT_CAPABILITIES and severity is not Severity.INFO:
            findings.append(Finding(
                code=f"SQL_{verb}", severity=severity, analyzer=ANALYZER,
                message=f"{verb} statement", evidence=statement[:80], capabilities=caps,
            ))

        for table in {t for t in TABLE_RE.findall(statement)}:
            sensitive = bool(SENSITIVE_TABLE_RE.search(table))
            resources.append(ResourceDescriptor(
                resource_class=ResourceClass.SENSITIVE_TABLE if sensitive else ResourceClass.DATABASE_TABLE,
                scope=Scope.UNBOUNDED if unbounded else Scope.MULTIPLE,
                identifier=f"db:{table.lower()}",
                sensitive=sensitive,
            ))
            if sensitive:
                findings.append(Finding(
                    code="SQL_SENSITIVE_TABLE", severity=Severity.HIGH, analyzer=ANALYZER,
                    message=f"statement touches sensitive table '{table}'", evidence=table,
                ))

    for code, pattern, severity in INJECTION_PATTERNS:
        if re.search(pattern, raw_query):
            findings.append(Finding(
                code=code, severity=severity, analyzer=ANALYZER,
                message=f"query matches injection pattern {code.replace('SQL_', '').lower()}",
                evidence=query[:120],
            ))

    for code, pattern, severity, caps in FILE_ACCESS_PATTERNS:
        if re.search(pattern, query):
            capabilities.update(caps)
            findings.append(Finding(
                code=code, severity=severity, analyzer=ANALYZER,
                message="query reaches outside the database (file or OS access)",
                evidence=query[:120], capabilities=caps,
            ))

    findings = dedupe_findings(findings)
    capabilities = merge_finding_capabilities(findings, capabilities)
    scope = max([widest] + [r.scope for r in resources], key=lambda s: list(Scope).index(s))
    risk = aggregate_risk(findings, scope, base=12.0)
    return ArgumentAnalysis(
        tool_name=tool_name,
        analyzer=ANALYZER,
        capabilities=sorted(capabilities, key=lambda c: c.value),
        resources=resources,
        findings=findings,
        risk=risk,
        confidence=confidence_from(True, findings),
        scope=scope,
        parse_ok=True,
        explanation="; ".join(f.message for f in findings[:4]) or f"{'/'.join(verbs)} statement with bounded scope",
    )

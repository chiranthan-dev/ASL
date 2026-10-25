"""Generic JSON argument analysis.

Fallback for tools without a specialised analyzer.  Walks the argument tree and
classifies every leaf: URLs, paths, credential-shaped values and embedded
code/SQL fragments.  Confidence is deliberately lower than the specialised
analyzers, so the risk engine knows this verdict is weaker evidence.
"""

from __future__ import annotations

import re
from typing import Any

from app.analyzers.arg.common import (
    aggregate_risk,
    classify_path,
    classify_url,
    confidence_from,
    dedupe_findings,
    merge_finding_capabilities,
    scan_secrets,
    widest_scope,
)
from app.models.enums import Capability, ResourceClass, Scope, Severity
from app.models.tool_call import ArgumentAnalysis, Finding, ResourceDescriptor

ANALYZER = "generic"

URL_RE = re.compile(r"^\s*(https?|ftp|file)://", re.I)
PATH_RE = re.compile(r"^\s*(/[^\s]*|~[/\\][^\s]*|[a-zA-Z]:[\\/][^\s]*)\s*$")
SECRET_KEY_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)")
CODE_HINT_RE = re.compile(
    r"(?i)(\bimport\s+os\b|\bsubprocess\b|\beval\s*\(|\bexec\s*\(|\brm\s+-rf\b|\bdrop\s+table\b|"
    r"\bunion\s+select\b|<script\b|\bcurl\s+.*\|\s*(ba)?sh\b)"
)
MAX_DEPTH = 6


def _walk(value: Any, key: str | None, depth: int, out: list[tuple[str | None, Any]]) -> None:
    if depth > MAX_DEPTH:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _walk(v, str(k), depth + 1, out)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _walk(item, key, depth + 1, out)
    else:
        out.append((key, value))


def analyze_generic(arguments: dict[str, Any], tool_name: str = "unknown") -> ArgumentAnalysis:
    leaves: list[tuple[str | None, Any]] = []
    _walk(arguments, None, 0, leaves)

    findings: list[Finding] = []
    capabilities: set[Capability] = set()
    resources: list[ResourceDescriptor] = []
    text_blob_parts: list[str] = []

    for key, value in leaves:
        if not isinstance(value, str):
            continue
        text_blob_parts.append(value)
        stripped = value.strip()

        if URL_RE.match(stripped):
            descriptor, url_findings = classify_url(stripped)
            resources.append(descriptor)
            capabilities.add(Capability.NETWORK)
            findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in url_findings)
        elif PATH_RE.match(stripped):
            descriptor, path_findings = classify_path(stripped)
            resources.append(descriptor)
            findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in path_findings)

        if key and SECRET_KEY_RE.search(key) and stripped:
            capabilities.add(Capability.AUTHENTICATE)
            findings.append(Finding(
                code="GEN_CREDENTIAL_ARGUMENT", severity=Severity.HIGH, analyzer=ANALYZER,
                message=f"argument '{key}' carries credential material", evidence=key,
                capabilities=[Capability.AUTHENTICATE],
            ))

        if CODE_HINT_RE.search(stripped):
            capabilities.add(Capability.EXECUTE)
            findings.append(Finding(
                code="GEN_EMBEDDED_CODE", severity=Severity.HIGH, analyzer=ANALYZER,
                message="argument contains executable code or SQL fragments",
                evidence=stripped[:80], capabilities=[Capability.EXECUTE],
            ))

    blob = "\n".join(text_blob_parts)
    findings.extend(scan_secrets(blob, ANALYZER))

    payload_bytes = len(blob.encode("utf-8", errors="ignore"))
    if payload_bytes > 100_000:
        findings.append(Finding(
            code="GEN_LARGE_PAYLOAD", severity=Severity.LOW, analyzer=ANALYZER,
            message=f"arguments are unusually large ({payload_bytes} bytes)",
        ))

    if not resources:
        resources.append(ResourceDescriptor(
            resource_class=ResourceClass.PUBLIC_CONTENT if not findings else ResourceClass.UNKNOWN,
            scope=Scope.SINGLE if arguments else Scope.NONE,
            identifier=None,
        ))

    findings = dedupe_findings(findings)
    capabilities = merge_finding_capabilities(findings, capabilities)
    scope = widest_scope(resources)
    risk = aggregate_risk(findings, scope, base=6.0)
    return ArgumentAnalysis(
        tool_name=tool_name,
        analyzer=ANALYZER,
        capabilities=sorted(capabilities, key=lambda c: c.value),
        resources=resources,
        findings=findings,
        risk=risk,
        confidence=round(confidence_from(True, findings) * 0.75, 3),
        scope=scope,
        parse_ok=True,
        explanation="; ".join(f.message for f in findings[:4]) or "plain arguments, nothing sensitive detected",
    )

"""HTTP / API payload analysis.

No request is ever issued.  The URL is parsed, the payload is inspected for
credential-shaped material, and the *combination* (sensitive payload leaving
to an external endpoint) is reported as its own finding, because that pairing
is what distinguishes an API call from an exfiltration.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.analyzers.arg.common import (
    aggregate_risk,
    classify_url,
    confidence_from,
    dedupe_findings,
    merge_finding_capabilities,
    scan_secrets,
)
from app.models.enums import Capability, ResourceClass, Scope, Severity
from app.models.tool_call import ArgumentAnalysis, Finding, ResourceDescriptor

ANALYZER = "http"

CREDENTIAL_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization"}
LARGE_PAYLOAD_BYTES = 50_000


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def analyze_http(arguments: dict[str, Any], tool_name: str = "http.get") -> ArgumentAnalysis:
    findings: list[Finding] = []
    capabilities: set[Capability] = {Capability.NETWORK}
    resources: list[ResourceDescriptor] = []

    url = str(arguments.get("url") or arguments.get("endpoint") or "")
    method = str(arguments.get("method") or ("POST" if tool_name.endswith("post") else "GET")).upper()

    descriptor, url_findings = classify_url(url)
    if descriptor.resource_class is not ResourceClass.NONE:
        resources.append(descriptor)
    findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in url_findings)

    if method in {"GET", "HEAD", "OPTIONS"}:
        capabilities.update({Capability.READ, Capability.DOWNLOAD})
    else:
        capabilities.update({Capability.UPLOAD, Capability.WRITE})

    headers = arguments.get("headers") or {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() in CREDENTIAL_HEADERS:
                capabilities.add(Capability.AUTHENTICATE)
                findings.append(Finding(
                    code="HTTP_CREDENTIAL_HEADER", severity=Severity.MEDIUM, analyzer=ANALYZER,
                    message=f"request carries credentials in the {key} header",
                    capabilities=[Capability.AUTHENTICATE],
                ))
            _ = value

    payload_text = " ".join(
        _stringify(arguments.get(key)) for key in ("json", "data", "body", "params", "form")
    ).strip()
    payload_bytes = len(payload_text.encode("utf-8", errors="ignore"))

    secret_findings = scan_secrets(payload_text, ANALYZER)
    findings.extend(secret_findings)
    if scan_secrets(url, ANALYZER):
        findings.append(Finding(
            code="HTTP_SECRET_IN_URL", severity=Severity.HIGH, analyzer=ANALYZER,
            message="credential-shaped material appears in the URL itself", evidence=url[:120],
        ))

    if arguments.get("files") or re.search(r"(?i)multipart/form-data", _stringify(headers)):
        capabilities.add(Capability.UPLOAD)
        findings.append(Finding(
            code="HTTP_FILE_UPLOAD", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message="request uploads file content", capabilities=[Capability.UPLOAD],
        ))

    if payload_bytes > LARGE_PAYLOAD_BYTES:
        findings.append(Finding(
            code="HTTP_LARGE_PAYLOAD", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message=f"payload is large ({payload_bytes} bytes), consistent with bulk transfer",
        ))

    external = descriptor.resource_class in (ResourceClass.EXTERNAL_ENDPOINT, ResourceClass.BINARY)
    if external and (secret_findings or payload_bytes > LARGE_PAYLOAD_BYTES) and method not in {"GET", "HEAD"}:
        findings.append(Finding(
            code="HTTP_EXFILTRATION_SHAPE", severity=Severity.CRITICAL, analyzer=ANALYZER,
            message="sensitive or bulk data is being sent to an external endpoint",
            evidence=descriptor.identifier, capabilities=[Capability.UPLOAD],
        ))

    if descriptor.resource_class is ResourceClass.BINARY:
        capabilities.add(Capability.DOWNLOAD)

    if not url:
        findings.append(Finding(
            code="HTTP_NO_URL", severity=Severity.LOW, analyzer=ANALYZER,
            message="no URL supplied; destination unknown",
        ))

    findings = dedupe_findings(findings)
    capabilities = merge_finding_capabilities(findings, capabilities)
    base = 10.0 if method in {"GET", "HEAD"} else 22.0
    risk = aggregate_risk(findings, Scope.SINGLE, base=base)
    return ArgumentAnalysis(
        tool_name=tool_name,
        analyzer=ANALYZER,
        capabilities=sorted(capabilities, key=lambda c: c.value),
        resources=resources,
        findings=findings,
        risk=risk,
        confidence=confidence_from(True, findings),
        scope=Scope.SINGLE,
        parse_ok=True,
        explanation="; ".join(f.message for f in findings[:4]) or f"{method} request to {descriptor.identifier or 'unspecified host'}",
    )

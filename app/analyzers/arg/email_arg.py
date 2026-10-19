"""Email argument analysis.

Nothing is transmitted.  What matters is who receives the message, how many of
them there are, whether the recipients are outside the organisation, and
whether the body or attachments carry material that should not leave.
"""

from __future__ import annotations

import re
from typing import Any

from app.analyzers.arg.common import (
    aggregate_risk,
    classify_path,
    confidence_from,
    dedupe_findings,
    merge_finding_capabilities,
    scan_secrets,
)
from app.models.enums import Capability, ResourceClass, Scope, Severity
from app.models.tool_call import ArgumentAnalysis, Finding, ResourceDescriptor

ANALYZER = "email"

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

#: Domains treated as inside the organisation.  Configurable in a deployment;
#: kept here as a research default.
INTERNAL_DOMAINS = {"university.edu", "example.edu", "example.com", "internal.local",
                    # The demo corpus addresses colleagues at company.com. Leaving
                    # it out meant every "mail this to a colleague" workflow was
                    # scored as leaving the organisation, which is what made the
                    # read-then-mail chain fire on ordinary work.
                    "company.com"}

DISPOSABLE_DOMAIN_RE = re.compile(
    r"(mailinator|guerrillamail|10minutemail|tempmail|yopmail|throwaway|dropmail)", re.I
)

BULK_RECIPIENT_THRESHOLD = 10
SENSITIVE_ATTACHMENT_RE = re.compile(
    r"(?i)\.(sql|db|sqlite|csv|xlsx?|pem|key|p12|pfx|zip|7z|tar\.gz|exe|dll|scr|js|ps1)$"
)


def _collect_addresses(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return EMAIL_RE.findall(value)
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(_collect_addresses(item))
        return out
    return EMAIL_RE.findall(str(value))


def analyze_email(arguments: dict[str, Any], tool_name: str = "gmail.send") -> ArgumentAnalysis:
    findings: list[Finding] = []
    capabilities: set[Capability] = {Capability.EMAIL, Capability.NETWORK, Capability.WRITE}
    resources: list[ResourceDescriptor] = []

    recipients = (
        _collect_addresses(arguments.get("to"))
        + _collect_addresses(arguments.get("cc"))
        + _collect_addresses(arguments.get("bcc"))
    )
    bcc_count = len(_collect_addresses(arguments.get("bcc")))
    body = str(arguments.get("body") or arguments.get("message") or "")
    subject = str(arguments.get("subject") or "")
    attachments = arguments.get("attachments") or []
    if isinstance(attachments, str):
        attachments = [attachments]

    if not recipients:
        findings.append(Finding(
            code="EMAIL_NO_RECIPIENT", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message="no valid recipient address found",
        ))

    external = []
    for address in recipients:
        domain = address.rsplit("@", 1)[-1].lower()
        internal = domain in INTERNAL_DOMAINS
        resources.append(ResourceDescriptor(
            resource_class=ResourceClass.EMAIL_RECIPIENT_INTERNAL if internal else ResourceClass.EMAIL_RECIPIENT_EXTERNAL,
            scope=Scope.SINGLE,
            identifier=domain,
            sensitive=not internal,
        ))
        if not internal:
            external.append(address)
        if DISPOSABLE_DOMAIN_RE.search(domain):
            findings.append(Finding(
                code="EMAIL_DISPOSABLE_DOMAIN", severity=Severity.HIGH, analyzer=ANALYZER,
                message=f"recipient uses a disposable mail domain ({domain})", evidence=address,
            ))

    if external:
        findings.append(Finding(
            code="EMAIL_EXTERNAL_RECIPIENT", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message=f"{len(external)} recipient(s) outside the organisation",
            evidence=", ".join(external[:3]),
        ))

    if len(recipients) >= BULK_RECIPIENT_THRESHOLD:
        findings.append(Finding(
            code="EMAIL_BULK_SEND", severity=Severity.HIGH, analyzer=ANALYZER,
            message=f"message addressed to {len(recipients)} recipients",
        ))
    if bcc_count >= 5:
        findings.append(Finding(
            code="EMAIL_MASS_BCC", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message=f"{bcc_count} blind recipients hide the true audience",
        ))

    findings.extend(scan_secrets(f"{subject}\n{body}", ANALYZER))

    for attachment in attachments:
        name = str(attachment)
        capabilities.add(Capability.UPLOAD)
        descriptor, path_findings = classify_path(name)
        resources.append(descriptor)
        findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in path_findings)
        if SENSITIVE_ATTACHMENT_RE.search(name):
            findings.append(Finding(
                code="EMAIL_SENSITIVE_ATTACHMENT", severity=Severity.HIGH, analyzer=ANALYZER,
                message=f"attachment type commonly used to move data or code ({name})",
                evidence=name, capabilities=[Capability.UPLOAD],
            ))

    if external and attachments:
        findings.append(Finding(
            code="EMAIL_EXTERNAL_ATTACHMENT", severity=Severity.HIGH, analyzer=ANALYZER,
            message="attachments are being sent outside the organisation",
            capabilities=[Capability.UPLOAD],
        ))

    findings = dedupe_findings(findings)
    capabilities = merge_finding_capabilities(findings, capabilities)
    scope = Scope.MULTIPLE if len(recipients) > 1 else Scope.SINGLE
    # An internal message with no attachments and no sensitive content is one
    # of the most ordinary things an assistant does; base risk reflects that.
    base = 12.0 if (recipients and not external and not attachments) else 20.0
    risk = aggregate_risk(findings, scope, base=base)
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
        explanation="; ".join(f.message for f in findings[:4])
        or f"message to {len(recipients)} recipient(s) with no sensitive content detected",
    )

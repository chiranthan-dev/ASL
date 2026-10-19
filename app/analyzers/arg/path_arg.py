"""Filesystem-path argument analysis.

This is the analyzer that makes `filesystem.delete("temp.txt")` and
`filesystem.delete("/production/database/")` two different security events even
though the tool, the caller and the policy are identical.
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
from app.models.tool_call import ArgumentAnalysis, Finding

ANALYZER = "path"

#: operation -> (capabilities, base risk, severity floor for sensitive targets)
OPERATION_SEMANTICS: dict[str, tuple[list[Capability], float, Severity]] = {
    "read": ([Capability.READ], 12.0, Severity.MEDIUM),
    "write": ([Capability.WRITE, Capability.MODIFY], 28.0, Severity.HIGH),
    "delete": ([Capability.DELETE], 42.0, Severity.CRITICAL),
    "list": ([Capability.READ], 8.0, Severity.LOW),
    # The tool's name states no operation and the payload carries only an
    # operand. Identity stays a read -- that is all the evidence shows -- but
    # risk is scored as if the operation could be the worst one, because
    # opacity must raise risk rather than lower it.
    "unstated": ([Capability.READ], 24.0, Severity.CRITICAL),
}


#: verb tokens that map onto a filesystem operation, most destructive first
OPERATION_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("delete", ("delete", "remove", "unlink", "purge", "destroy", "wipe", "rm")),
    ("write", ("write", "save", "create", "append", "put", "upload", "copy", "move")),
    ("list", ("list", "dir", "walk", "glob")),
    ("read", ("read", "get", "fetch", "open", "cat", "download", "load")),
)


#: files the system runs on its own: login shells, schedulers, service units
PERSISTENCE_RE = re.compile(
    r"(^|/)\.(bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv)$|"
    r"(^|/)(crontab|rc\.local)$|^/etc/cron|^/var/spool/cron|/systemd/.+\.(service|timer)$|"
    r"/autostart/|(^|/)authorized_keys$|/launchagents/|/launchdaemons/"
)


def _analyze_written_code(content: str, target: str) -> "ArgumentAnalysis | None":
    from app.analyzers.arg.python_arg import analyze_python
    from app.analyzers.arg.shell_arg import analyze_shell

    if target.endswith(".py") or content.lstrip().startswith("#!/usr/bin/env python"):
        return analyze_python(content)
    if target.endswith("authorized_keys"):
        return None
    return analyze_shell(content)


def _operation_for(tool_name: str, arguments: dict[str, Any] | None = None) -> str:
    """Infer the operation, biased towards the destructive reading when ambiguous.

    The payload is consulted first where it states the operation: a `content`
    argument is something to write, whatever the tool is called. Otherwise the
    name is read for a verb, and a name with none yields "unstated".
    """
    if arguments and any(arguments.get(k) not in (None, "") for k in ("content", "data", "text_content")):
        return "write"
    lowered = tool_name.lower()
    for operation, tokens in OPERATION_TOKENS:
        if any(token in lowered for token in tokens):
            return operation
    return "unstated"


def analyze_path(arguments: dict[str, Any], tool_name: str = "filesystem.read") -> ArgumentAnalysis:
    operation = _operation_for(tool_name, arguments)
    capabilities_list, base, sensitive_floor = OPERATION_SEMANTICS[operation]
    capabilities = set(capabilities_list)
    findings: list[Finding] = []

    raw_path = str(arguments.get("path") or arguments.get("filename") or arguments.get("target") or "")
    recursive = bool(arguments.get("recursive") or arguments.get("force"))

    descriptor, path_findings = classify_path(raw_path, recursive_hint=recursive)
    findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in path_findings)

    if not raw_path:
        findings.append(Finding(
            code="PATH_MISSING", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message="no path supplied; target unknown",
        ))

    # A sensitive or wide target turns an ordinary operation into a serious one.
    if descriptor.sensitive:
        findings.append(Finding(
            code=f"PATH_SENSITIVE_{operation.upper()}", severity=sensitive_floor, analyzer=ANALYZER,
            message=f"{operation} against a sensitive location ({descriptor.resource_class})",
            evidence=raw_path, capabilities=capabilities_list,
        ))
    if operation == "delete" and descriptor.scope in (Scope.RECURSIVE, Scope.UNBOUNDED):
        findings.append(Finding(
            code="PATH_MASS_DELETE", severity=Severity.CRITICAL, analyzer=ANALYZER,
            message="deletion covers an entire directory tree", evidence=raw_path,
            capabilities=[Capability.DELETE],
        ))
    if operation == "delete" and descriptor.resource_class is ResourceClass.DIRECTORY:
        findings.append(Finding(
            code="PATH_DIRECTORY_DELETE", severity=Severity.HIGH, analyzer=ANALYZER,
            message="target is a directory rather than a single file", evidence=raw_path,
        ))
    if operation == "unstated":
        findings.append(Finding(
            code="PATH_OPERATION_UNSTATED", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message="neither the tool name nor the arguments say what is done to this path",
            evidence=tool_name,
        ))
        if descriptor.scope in (Scope.RECURSIVE, Scope.UNBOUNDED):
            findings.append(Finding(
                code="PATH_WIDE_UNSTATED", severity=Severity.HIGH, analyzer=ANALYZER,
                message="an operation of unknown kind over a whole directory tree", evidence=raw_path,
            ))
    if operation in ("read", "unstated") and descriptor.resource_class is ResourceClass.CREDENTIAL_STORE:
        capabilities.add(Capability.AUTHENTICATE)

    if operation == "write":
        content = str(arguments.get("content") or "")
        findings.extend(scan_secrets(content, ANALYZER))
        persistent = bool(PERSISTENCE_RE.search(descriptor.identifier or ""))
        if persistent:
            capabilities.add(Capability.EXECUTE)
            findings.append(Finding(
                code="PATH_PERSISTENCE", severity=Severity.HIGH, analyzer=ANALYZER,
                message="writes a file the system executes automatically (startup, cron or login)",
                evidence=raw_path, capabilities=[Capability.EXECUTE],
            ))
        # Content written to a script or a startup file is code that will run
        # later, so judge it now as the code it is. Without this, `.bashrc`
        # containing `curl ... | bash` was an ordinary text write.
        if content.strip() and (persistent or descriptor.resource_class in (ResourceClass.BINARY, ResourceClass.CODE)):
            nested = _analyze_written_code(content, descriptor.identifier or "")
            if nested is not None:
                capabilities.update(nested.capabilities)
                findings.extend(
                    f.model_copy(update={"code": f"WRITTEN_{f.code}", "analyzer": ANALYZER})
                    for f in nested.findings
                )
        if descriptor.resource_class in (ResourceClass.BINARY, ResourceClass.CODE):
            capabilities.add(Capability.EXECUTE)
            findings.append(Finding(
                code="PATH_WRITE_EXECUTABLE", severity=Severity.HIGH, analyzer=ANALYZER,
                message="writing code or an executable creates something that can later run",
                evidence=raw_path, capabilities=[Capability.EXECUTE],
            ))

    findings = dedupe_findings(findings)
    capabilities = merge_finding_capabilities(findings, capabilities)
    risk = aggregate_risk(findings, descriptor.scope, base=base)
    return ArgumentAnalysis(
        tool_name=tool_name,
        analyzer=ANALYZER,
        capabilities=sorted(capabilities, key=lambda c: c.value),
        resources=[descriptor] if descriptor.resource_class is not ResourceClass.NONE else [],
        findings=findings,
        risk=risk,
        confidence=confidence_from(True, findings),
        scope=descriptor.scope,
        parse_ok=True,
        explanation="; ".join(f.message for f in findings[:4])
        or f"{operation} of {descriptor.resource_class} with {descriptor.scope} scope",
    )

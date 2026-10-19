"""Shared vocabulary and helpers for the argument sub-analyzers.

Two ideas live here:

1. **Classification** - turn a raw string (path, URL, table, address) into a
   `ResourceDescriptor`.  This is what makes different tools that touch the
   same thing comparable, and it is the input the fingerprint generator
   canonicalises.
2. **Aggregation** - turn a set of `Finding`s into a single 0-100 risk with a
   confidence.  Aggregation is deliberately *not* an average: the worst
   finding sets the floor and the remaining findings add a bounded premium,
   so a dangerous action cannot be diluted by many harmless ones.
"""

from __future__ import annotations

import posixpath
import re
from typing import Iterable
from urllib.parse import urlparse

from app.models.enums import (
    SCOPE_WEIGHT,
    SEVERITY_SCORE,
    Capability,
    ResourceClass,
    Scope,
    Severity,
)
from app.models.tool_call import Finding, ResourceDescriptor

# --------------------------------------------------------------------------
# path classification
# --------------------------------------------------------------------------

SYSTEM_PATH_PATTERNS = (
    r"^/etc(/|$)", r"^/bin(/|$)", r"^/sbin(/|$)", r"^/usr/bin(/|$)", r"^/boot(/|$)",
    r"^/dev(/|$)", r"^/proc(/|$)", r"^/sys(/|$)", r"^/var/log(/|$)", r"^/root(/|$)",
    r"^[a-z]:[\\/]windows(\\|/|$)", r"^[a-z]:[\\/]program files",
    r"^/system(/|$)", r"^/library(/|$)",
)

CREDENTIAL_PATH_PATTERNS = (
    r"\.ssh(/|\\|$)", r"\.aws(/|\\|$)", r"\.gnupg(/|\\|$)", r"(^|/|\\)\.env$",
    r"id_rsa", r"id_ed25519", r"credentials?(\.json|\.yml|\.yaml|\.ini)?$",
    r"secrets?(\.json|\.yml|\.yaml|\.env)?$", r"shadow$", r"passwd$",
    r"\.pem$", r"\.p12$", r"\.pfx$", r"keystore", r"token(s)?\.json$",
)

PRODUCTION_PATH_PATTERNS = (
    r"(^|/|\\)prod(uction)?(/|\\|$)", r"(^|/|\\)live(/|\\|$)",
    r"(^|/|\\)releases?(/|\\|$)", r"(^|/|\\)www(/|\\|$)",
)

USER_DATA_PATH_PATTERNS = (
    r"^/home/", r"^/users/", r"^~", r"^[a-z]:[\\/]users[\\/]",
    r"(^|/|\\)documents(/|\\)", r"(^|/|\\)desktop(/|\\)",
)

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".apk", ".deb", ".rpm",
    ".sh", ".bash", ".ps1", ".bat", ".cmd", ".scr", ".jar", ".com",
}
CODE_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".pl", ".php", ".lua", ".vbs"}

WILDCARD_RE = re.compile(r"[*?]|\[[^\]]+\]")


def normalize_path(raw: str) -> str:
    """Lower-case, forward-slashed, whitespace-trimmed form used for matching."""
    p = (raw or "").strip().strip('"').strip("'")
    p = p.replace("\\", "/")
    p = re.sub(r"/{2,}", "/", p)
    # Resolve `.` and `..` lexically, so `/srv/../production/` is classified as
    # the place it names rather than the place it starts from. Traversal is
    # still reported: classify_path checks the raw form for it separately.
    if p.startswith(("/", "~/")) and re.search(r"/\.\.?(/|$)", p):
        trailing = p.endswith("/")
        resolved = posixpath.normpath(p)
        p = resolved + ("/" if trailing and not resolved.endswith("/") else "")
    return p.lower()


def classify_path(raw: str, recursive_hint: bool = False) -> tuple[ResourceDescriptor, list[Finding]]:
    """Map a filesystem path to a resource class, scope and any findings."""
    findings: list[Finding] = []
    norm = normalize_path(raw)
    if not norm:
        return ResourceDescriptor(resource_class=ResourceClass.NONE, scope=Scope.NONE), findings

    resource_class = ResourceClass.FILE
    sensitive = False

    if any(re.search(p, norm) for p in CREDENTIAL_PATH_PATTERNS):
        resource_class, sensitive = ResourceClass.CREDENTIAL_STORE, True
        findings.append(Finding(
            code="PATH_CREDENTIAL_STORE", severity=Severity.CRITICAL,
            message="path points at credential or secret material",
            evidence=raw, capabilities=[Capability.AUTHENTICATE],
        ))
    elif any(re.search(p, norm) for p in SYSTEM_PATH_PATTERNS):
        resource_class, sensitive = ResourceClass.SYSTEM_PATH, True
        findings.append(Finding(
            code="PATH_SYSTEM", severity=Severity.HIGH,
            message="path points at a system location", evidence=raw,
        ))
    elif any(re.search(p, norm) for p in PRODUCTION_PATH_PATTERNS):
        resource_class, sensitive = ResourceClass.PRODUCTION_RESOURCE, True
        findings.append(Finding(
            code="PATH_PRODUCTION", severity=Severity.HIGH,
            message="path points at a production resource", evidence=raw,
        ))
    elif any(re.search(p, norm) for p in USER_DATA_PATH_PATTERNS):
        resource_class = ResourceClass.USER_DATA

    ext = "." + norm.rsplit(".", 1)[-1] if "." in norm.rsplit("/", 1)[-1] else ""
    if ext in EXECUTABLE_EXTENSIONS:
        # Being an executable artifact outranks "some file in a home directory",
        # but not "this is a credential store / system / production path".
        if resource_class in (ResourceClass.FILE, ResourceClass.USER_DATA):
            resource_class = ResourceClass.BINARY
        findings.append(Finding(
            code="PATH_EXECUTABLE", severity=Severity.MEDIUM,
            message=f"target is an executable artifact ({ext})", evidence=raw,
        ))
    elif ext in CODE_EXTENSIONS and resource_class is ResourceClass.FILE:
        resource_class = ResourceClass.CODE

    # scope
    scope = Scope.SINGLE
    if norm in ("/", "c:/", "~", "~/"):
        scope = Scope.UNBOUNDED
        findings.append(Finding(
            code="PATH_ROOT_SCOPE", severity=Severity.CRITICAL,
            message="operation targets a filesystem root", evidence=raw,
        ))
    elif WILDCARD_RE.search(norm):
        scope = Scope.RECURSIVE if "**" in norm else Scope.MULTIPLE
        findings.append(Finding(
            code="PATH_WILDCARD", severity=Severity.MEDIUM,
            message="path uses a wildcard, affecting multiple targets", evidence=raw,
        ))
    elif norm.endswith("/") or (ext == "" and norm.count("/") >= 1):
        resource_class = ResourceClass.DIRECTORY if resource_class is ResourceClass.FILE else resource_class
        scope = Scope.RECURSIVE if recursive_hint else Scope.MULTIPLE
    if recursive_hint and scope in (Scope.SINGLE, Scope.MULTIPLE):
        scope = Scope.RECURSIVE

    if ".." in (raw or "").replace("\\", "/").split("/"):
        findings.append(Finding(
            code="PATH_TRAVERSAL", severity=Severity.HIGH,
            message="path contains directory traversal", evidence=raw,
        ))

    return (
        ResourceDescriptor(resource_class=resource_class, scope=scope, identifier=norm, sensitive=sensitive),
        findings,
    )


# --------------------------------------------------------------------------
# URL / host classification
# --------------------------------------------------------------------------

PRIVATE_HOST_RE = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|\[?::1\]?|.*\.internal|.*\.local)$",
    re.I,
)
CLOUD_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}
PASTE_OR_TUNNEL_HOSTS = re.compile(
    r"(pastebin|paste\.ee|ghostbin|transfer\.sh|file\.io|anonfiles|ngrok\.io|"
    r"trycloudflare\.com|requestbin|webhook\.site|discord(app)?\.com/api/webhooks|bit\.ly|tinyurl)",
    re.I,
)


def classify_url(raw: str) -> tuple[ResourceDescriptor, list[Finding]]:
    findings: list[Finding] = []
    url = (raw or "").strip()
    if not url:
        return ResourceDescriptor(resource_class=ResourceClass.NONE, scope=Scope.NONE), findings

    parsed = urlparse(url if "://" in url else f"//{url}", scheme="https")
    host = (parsed.hostname or "").lower()
    resource_class = ResourceClass.EXTERNAL_ENDPOINT
    sensitive = False

    if host in CLOUD_METADATA_HOSTS:
        resource_class, sensitive = ResourceClass.CREDENTIAL_STORE, True
        findings.append(Finding(
            code="URL_CLOUD_METADATA", severity=Severity.CRITICAL,
            message="request targets a cloud instance-metadata endpoint", evidence=url,
            capabilities=[Capability.AUTHENTICATE],
        ))
    elif host and PRIVATE_HOST_RE.match(host):
        resource_class = ResourceClass.INTERNAL_ENDPOINT
        findings.append(Finding(
            code="URL_INTERNAL_HOST", severity=Severity.MEDIUM,
            message="request targets an internal or loopback host", evidence=url,
        ))

    if PASTE_OR_TUNNEL_HOSTS.search(url):
        sensitive = True
        findings.append(Finding(
            code="URL_UNTRUSTED_SINK", severity=Severity.HIGH,
            message="host is a paste/tunnel/webhook service commonly used for exfiltration",
            evidence=host or url,
        ))

    if parsed.scheme in ("http", "ftp", "telnet"):
        findings.append(Finding(
            code="URL_INSECURE_SCHEME", severity=Severity.LOW,
            message=f"insecure scheme {parsed.scheme}", evidence=url,
        ))

    path_ext = "." + parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path.rsplit("/", 1)[-1] else ""
    if path_ext in EXECUTABLE_EXTENSIONS:
        resource_class = ResourceClass.BINARY
        findings.append(Finding(
            code="URL_EXECUTABLE_PAYLOAD", severity=Severity.HIGH,
            message=f"URL points at an executable artifact ({path_ext})", evidence=url,
            capabilities=[Capability.DOWNLOAD],
        ))

    return (
        ResourceDescriptor(resource_class=resource_class, scope=Scope.SINGLE, identifier=host or url, sensitive=sensitive),
        findings,
    )


# --------------------------------------------------------------------------
# secret / PII scanning
# --------------------------------------------------------------------------

SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    ("PRIVATE_KEY_BLOCK", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("BEARER_TOKEN", r"\bbearer\s+[A-Za-z0-9\-_\.=]{20,}"),
    ("GENERIC_API_KEY", r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9\-_\.]{8,}"),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("CREDIT_CARD", r"\b(?:\d[ -]?){13,16}\b"),
)


def scan_secrets(text: str, analyzer: str = "argument") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings
    for code, pattern in SECRET_PATTERNS:
        if re.search(pattern, text):
            findings.append(Finding(
                code=f"SECRET_{code}", severity=Severity.HIGH, analyzer=analyzer,
                message=f"payload appears to contain {code.replace('_', ' ').lower()}",
            ))
    return findings


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------

def aggregate_risk(findings: Iterable[Finding], scope: Scope = Scope.SINGLE, base: float = 0.0) -> float:
    """Worst-finding floor plus a bounded premium for corroborating findings.

    Rationale: security risk is not an average.  One CRITICAL finding must not
    be diluted by nine INFO findings, but many independent MEDIUM findings
    should still add up to more than a single MEDIUM.
    """
    scores = sorted((SEVERITY_SCORE[f.severity] for f in findings), reverse=True)
    if not scores:
        risk = base
    else:
        premium = sum(min(8.0, s * 0.15) for s in scores[1:])
        risk = max(base, scores[0]) + premium
    risk *= 1.0 + 0.18 * (SCOPE_WEIGHT[scope] - 1.0)
    return round(min(100.0, max(0.0, risk)), 2)


def confidence_from(parse_ok: bool, findings: Iterable[Finding], analyzed: bool = True) -> float:
    """How much we trust this argument analysis.

    Structured parsing (AST, shlex, urlparse) is high confidence; falling back
    to substring heuristics is not.
    """
    if not analyzed:
        return 0.35
    conf = 0.9 if parse_ok else 0.55
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        conf = min(0.97, conf + 0.05)
    return round(conf, 3)


def merge_finding_capabilities(
    findings: Iterable[Finding], capabilities: set[Capability]
) -> set[Capability]:
    """Fold capabilities discovered by individual findings into the set.

    Classification helpers (`classify_path`, `classify_url`) attach the
    capability a finding implies; without this fold those capabilities would be
    visible in the explanation but absent from the capability set the
    fingerprint is built from.
    """
    for finding in findings:
        capabilities.update(finding.capabilities)
    return capabilities


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.code, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def widest_scope(descriptors: Iterable[ResourceDescriptor]) -> Scope:
    scopes = [d.scope for d in descriptors] or [Scope.SINGLE]
    return max(scopes, key=lambda s: SCOPE_WEIGHT[s])

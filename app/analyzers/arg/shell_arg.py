"""Static shell-command analysis.

The command line is tokenised with `shlex` and split on pipes, sequencing and
redirection operators.  Nothing is ever handed to a shell.  Each segment is
matched against a table of binaries with known semantics, and cross-segment
patterns (download piped into an interpreter, deletion after exfiltration) are
detected because those transitions carry more risk than their parts.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex

from app.analyzers.arg.common import (
    EXECUTABLE_EXTENSIONS,
    aggregate_risk,
    classify_path,
    classify_url,
    confidence_from,
    dedupe_findings,
    merge_finding_capabilities,
    widest_scope,
)
from app.models.enums import Capability, ResourceClass, Scope, Severity
from app.models.tool_call import ArgumentAnalysis, Finding, ResourceDescriptor

ANALYZER = "shell"

BINARY_SEMANTICS: dict[str, tuple[list[Capability], Severity, str]] = {
    "rm": ([Capability.DELETE], Severity.HIGH, "removes files"),
    "rmdir": ([Capability.DELETE], Severity.MEDIUM, "removes directories"),
    "shred": ([Capability.DELETE], Severity.CRITICAL, "irrecoverably destroys files"),
    "del": ([Capability.DELETE], Severity.HIGH, "removes files"),
    "erase": ([Capability.DELETE], Severity.HIGH, "removes files"),
    "format": ([Capability.DELETE], Severity.CRITICAL, "formats a volume"),
    "mkfs": ([Capability.DELETE], Severity.CRITICAL, "creates a filesystem, destroying data"),
    "dd": ([Capability.WRITE, Capability.DELETE], Severity.CRITICAL, "writes raw blocks to a device"),
    "fdisk": ([Capability.PRIVILEGE_CHANGE, Capability.DELETE], Severity.CRITICAL, "repartitions a disk"),
    "mv": ([Capability.MODIFY], Severity.MEDIUM, "moves or renames files"),
    "cp": ([Capability.READ, Capability.WRITE], Severity.LOW, "copies files"),
    "cat": ([Capability.READ], Severity.LOW, "reads file contents"),
    "less": ([Capability.READ], Severity.INFO, "reads file contents"),
    "head": ([Capability.READ], Severity.INFO, "reads file contents"),
    "tail": ([Capability.READ], Severity.INFO, "reads file contents"),
    "ls": ([Capability.READ], Severity.INFO, "lists a directory"),
    "find": ([Capability.READ], Severity.LOW, "searches the filesystem"),
    "grep": ([Capability.READ], Severity.INFO, "searches file contents"),
    "tar": ([Capability.READ, Capability.WRITE], Severity.LOW, "archives files"),
    "zip": ([Capability.READ, Capability.WRITE], Severity.LOW, "archives files"),
    "curl": ([Capability.NETWORK, Capability.DOWNLOAD], Severity.MEDIUM, "transfers data over the network"),
    "wget": ([Capability.NETWORK, Capability.DOWNLOAD], Severity.MEDIUM, "downloads over the network"),
    "scp": ([Capability.NETWORK, Capability.UPLOAD], Severity.HIGH, "copies files to a remote host"),
    "rsync": ([Capability.NETWORK, Capability.UPLOAD], Severity.HIGH, "synchronises files with a remote host"),
    "ssh": ([Capability.NETWORK, Capability.EXECUTE], Severity.HIGH, "opens a remote shell"),
    "nc": ([Capability.NETWORK, Capability.UPLOAD], Severity.HIGH, "opens a raw network channel"),
    "ncat": ([Capability.NETWORK, Capability.UPLOAD], Severity.HIGH, "opens a raw network channel"),
    "netcat": ([Capability.NETWORK, Capability.UPLOAD], Severity.HIGH, "opens a raw network channel"),
    "telnet": ([Capability.NETWORK], Severity.MEDIUM, "opens a remote session"),
    "ftp": ([Capability.NETWORK, Capability.UPLOAD], Severity.MEDIUM, "transfers files"),
    "sudo": ([Capability.PRIVILEGE_CHANGE, Capability.EXECUTE], Severity.CRITICAL, "runs a command as another user"),
    "su": ([Capability.PRIVILEGE_CHANGE, Capability.EXECUTE], Severity.CRITICAL, "switches user"),
    "chmod": ([Capability.PRIVILEGE_CHANGE], Severity.HIGH, "changes file permissions"),
    "chown": ([Capability.PRIVILEGE_CHANGE], Severity.HIGH, "changes file ownership"),
    "setcap": ([Capability.PRIVILEGE_CHANGE], Severity.CRITICAL, "grants process capabilities"),
    "useradd": ([Capability.PRIVILEGE_CHANGE], Severity.CRITICAL, "creates a user account"),
    "usermod": ([Capability.PRIVILEGE_CHANGE], Severity.CRITICAL, "modifies a user account"),
    "passwd": ([Capability.PRIVILEGE_CHANGE, Capability.AUTHENTICATE], Severity.CRITICAL, "changes a password"),
    "sh": ([Capability.EXECUTE], Severity.HIGH, "runs a shell"),
    "bash": ([Capability.EXECUTE], Severity.HIGH, "runs a shell"),
    "zsh": ([Capability.EXECUTE], Severity.HIGH, "runs a shell"),
    "python": ([Capability.EXECUTE], Severity.HIGH, "runs a Python interpreter"),
    "python3": ([Capability.EXECUTE], Severity.HIGH, "runs a Python interpreter"),
    "perl": ([Capability.EXECUTE], Severity.HIGH, "runs a Perl interpreter"),
    "node": ([Capability.EXECUTE], Severity.HIGH, "runs a Node interpreter"),
    "powershell": ([Capability.EXECUTE], Severity.HIGH, "runs PowerShell"),
    "eval": ([Capability.EXECUTE], Severity.CRITICAL, "evaluates a constructed command"),
    "crontab": ([Capability.WRITE, Capability.EXECUTE], Severity.HIGH, "schedules recurring execution"),
    "systemctl": ([Capability.PRIVILEGE_CHANGE, Capability.EXECUTE], Severity.HIGH, "controls system services"),
    "service": ([Capability.PRIVILEGE_CHANGE, Capability.EXECUTE], Severity.HIGH, "controls system services"),
    "kill": ([Capability.MODIFY], Severity.MEDIUM, "terminates a process"),
    "killall": ([Capability.MODIFY], Severity.HIGH, "terminates processes by name"),
    "shutdown": ([Capability.PRIVILEGE_CHANGE], Severity.HIGH, "shuts the system down"),
    "reboot": ([Capability.PRIVILEGE_CHANGE], Severity.HIGH, "reboots the system"),
    "iptables": ([Capability.PRIVILEGE_CHANGE], Severity.HIGH, "changes firewall rules"),
    "mysql": ([Capability.DATABASE], Severity.MEDIUM, "runs database statements"),
    "psql": ([Capability.DATABASE], Severity.MEDIUM, "runs database statements"),
    "mysqldump": ([Capability.DATABASE, Capability.READ], Severity.HIGH, "dumps a database"),
    "pg_dump": ([Capability.DATABASE, Capability.READ], Severity.HIGH, "dumps a database"),
    "mail": ([Capability.EMAIL, Capability.NETWORK], Severity.MEDIUM, "sends mail"),
    "sendmail": ([Capability.EMAIL, Capability.NETWORK], Severity.MEDIUM, "sends mail"),
    "history": ([Capability.READ], Severity.MEDIUM, "reads or clears shell history"),
    "git": ([Capability.READ, Capability.NETWORK], Severity.LOW, "runs a git operation"),
}

INTERPRETERS = {"sh", "bash", "zsh", "python", "python3", "perl", "node", "ruby", "powershell"}
DOWNLOADERS = {"curl", "wget"}
FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{.*\|.*&\s*\}\s*;\s*:")
SPLIT_RE = re.compile(r"(\|\||&&|\||;|\n|\$\(|<\(|`|\))")
B64_EXEC_RE = re.compile(
    r"\becho\s+['\"]?([A-Za-z0-9+/=]{12,})['\"]?\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:ba|z)?sh\b"
)
SUBST_EXEC_RE = re.compile(r"\b(?:ba|z)?sh\b\s+(?:-c\s+)?['\"]?(?:\$\(|<\()")
WORLD_MODE_RE = re.compile(r"^(?:a|o|ugo|go|uo)[+=][rwx]*[wx][rwx]*$")


def _segments(command: str) -> list[list[str]]:
    """Tokenise into argv lists, one per pipeline/sequence segment."""
    segments: list[list[str]] = []
    for chunk in SPLIT_RE.split(command):
        chunk = chunk.strip()
        if not chunk or SPLIT_RE.fullmatch(chunk):
            continue
        try:
            tokens = shlex.split(chunk, comments=False, posix=True)
        except ValueError:
            tokens = chunk.split()
        if tokens:
            segments.append(tokens)
    return segments


def _basename(binary: str) -> str:
    return binary.replace("\\", "/").rsplit("/", 1)[-1].lower()


def analyze_shell(command: str, _depth: int = 0) -> ArgumentAnalysis:
    command = command or ""
    findings: list[Finding] = []
    capabilities: set[Capability] = {Capability.EXECUTE}
    resources: list[ResourceDescriptor] = []
    parse_ok = True

    if not command.strip():
        return ArgumentAnalysis(
            tool_name="shell.execute", analyzer=ANALYZER, capabilities=[Capability.EXECUTE],
            risk=10.0, confidence=0.6, scope=Scope.NONE, explanation="empty command",
        )

    if FORK_BOMB_RE.search(command):
        findings.append(Finding(
            code="SH_FORK_BOMB", severity=Severity.CRITICAL, analyzer=ANALYZER,
            message="command is a fork bomb (resource exhaustion)", evidence=command[:60],
        ))

    try:
        shlex.split(command)
    except ValueError:
        parse_ok = False
        findings.append(Finding(
            code="SH_PARSE_ERROR", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message="command has unbalanced quoting; analysis degraded",
        ))

    segments = _segments(command)
    binaries: list[str] = []

    for tokens in segments:
        binary = _basename(tokens[0])
        offset = 1 if binary in {"sudo", "doas", "env"} and len(tokens) > 1 else 0
        if offset:
            binaries.append(binary)
            _apply_binary(binary, tokens[:1], findings, capabilities, resources)
            binary = _basename(tokens[1])
            tokens = tokens[1:]
        binaries.append(binary)
        _apply_binary(binary, tokens, findings, capabilities, resources)

    _cross_segment_patterns(command, segments, binaries, findings, capabilities)

    for encoded in B64_EXEC_RE.findall(command)[:2]:
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded.strip() and _depth < 2:
            nested = analyze_shell(decoded, _depth=_depth + 1)
            capabilities.update(nested.capabilities)
            resources.extend(nested.resources)
            findings.extend(f.model_copy(update={"code": f"DECODED_{f.code}"}) for f in nested.findings)

    findings = dedupe_findings(findings)
    capabilities = merge_finding_capabilities(findings, capabilities)
    scope = widest_scope(resources) if resources else Scope.SINGLE
    risk = aggregate_risk(findings, scope, base=22.0)
    return ArgumentAnalysis(
        tool_name="shell.execute",
        analyzer=ANALYZER,
        capabilities=sorted(capabilities, key=lambda c: c.value),
        resources=resources,
        findings=findings,
        risk=risk,
        confidence=confidence_from(parse_ok, findings),
        scope=scope,
        parse_ok=parse_ok,
        explanation="; ".join(f.message for f in findings[:4]) or "no dangerous shell operations detected",
    )


def _apply_binary(
    binary: str,
    tokens: list[str],
    findings: list[Finding],
    capabilities: set[Capability],
    resources: list[ResourceDescriptor],
) -> None:
    semantics = BINARY_SEMANTICS.get(binary)
    flags = [t for t in tokens[1:] if t.startswith("-")]
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    recursive = any(f in {"-r", "-R", "-rf", "-fr", "--recursive", "-recurse", "/s"} for f in flags) or any(
        "r" in f.lstrip("-") and f.startswith("-") and not f.startswith("--") for f in flags
    )

    invoked = tokens[0]
    if semantics is None:
        if "/" in invoked or "\\" in invoked or binary.endswith(tuple(EXECUTABLE_EXTENSIONS)):
            descriptor, path_findings = classify_path(invoked)
            resources.append(descriptor)
            findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in path_findings)
            findings.append(Finding(
                code="SH_EXEC_LOCAL_ARTIFACT", severity=Severity.HIGH, analyzer=ANALYZER,
                message=f"executes an artifact from the filesystem ({invoked})",
                evidence=invoked, capabilities=[Capability.EXECUTE],
            ))
        else:
            findings.append(Finding(
                code="SH_UNKNOWN_BINARY", severity=Severity.LOW, analyzer=ANALYZER,
                message=f"unrecognised binary {binary}; capabilities unknown", evidence=binary,
            ))
        return

    caps, severity, description = semantics
    capabilities.update(caps)

    if binary in {"rm", "del", "erase", "shred"} and recursive:
        severity = Severity.CRITICAL
        description += " recursively and without prompting"

    findings.append(Finding(
        code=f"SH_{binary.upper()}", severity=severity, analyzer=ANALYZER,
        message=f"{binary}: {description}", evidence=" ".join(tokens[:6]),
        capabilities=caps,
    ))

    if binary == "chmod" and any(re.fullmatch(r"[0-7]?777", o) or WORLD_MODE_RE.match(o) for o in operands):
        findings.append(Finding(
            code="SH_CHMOD_WORLD_WRITABLE", severity=Severity.CRITICAL, analyzer=ANALYZER,
            message="grants world read/write/execute permissions", evidence=" ".join(tokens[:4]),
            capabilities=[Capability.PRIVILEGE_CHANGE],
        ))

    if binary == "find" and any(t in {"-delete", "-exec"} for t in tokens):
        capabilities.add(Capability.DELETE)
        findings.append(Finding(
            code="SH_FIND_DESTRUCTIVE", severity=Severity.HIGH, analyzer=ANALYZER,
            message="find is used to delete or execute against every match",
            evidence=" ".join(tokens[:8]),
        ))

    if binary == "history" and ("-c" in flags or "-w" in flags):
        findings.append(Finding(
            code="SH_HISTORY_CLEAR", severity=Severity.HIGH, analyzer=ANALYZER,
            message="clears shell history, obscuring the action trail",
        ))

    for operand in operands:
        if re.match(r"^(https?|ftp)://", operand) or binary in DOWNLOADERS and "." in operand and "/" in operand:
            descriptor, url_findings = classify_url(operand)
            resources.append(descriptor)
            findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in url_findings)
        elif "/" in operand or operand.startswith("~") or re.match(r"^[a-zA-Z]:\\", operand):
            descriptor, path_findings = classify_path(operand, recursive_hint=recursive)
            resources.append(descriptor)
            findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in path_findings)

    if binary in {"scp", "rsync", "nc", "ncat", "netcat"} and operands:
        resources.append(ResourceDescriptor(
            resource_class=ResourceClass.EXTERNAL_ENDPOINT, scope=Scope.SINGLE,
            identifier=operands[-1], sensitive=True))


def _cross_segment_patterns(
    command: str,
    segments: list[list[str]],
    binaries: list[str],
    findings: list[Finding],
    capabilities: set[Capability],
) -> None:
    """Patterns that only exist in the *relationship* between segments."""
    piped = "|" in command or bool(SUBST_EXEC_RE.search(command))
    has_download = any(b in DOWNLOADERS for b in binaries)
    has_interpreter = any(b in INTERPRETERS for b in binaries)

    if piped and has_download and has_interpreter:
        capabilities.update({Capability.DOWNLOAD, Capability.EXECUTE})
        findings.append(Finding(
            code="SH_DOWNLOAD_PIPE_EXEC", severity=Severity.CRITICAL, analyzer=ANALYZER,
            message="remote content is downloaded and piped straight into an interpreter",
            evidence=command[:120], capabilities=[Capability.DOWNLOAD, Capability.EXECUTE],
        ))

    if re.search(r"base64\s+(-d|--decode)", command) and has_interpreter:
        findings.append(Finding(
            code="SH_OBFUSCATED_EXEC", severity=Severity.CRITICAL, analyzer=ANALYZER,
            message="base64-decoded payload is executed, defeating static review",
            evidence=command[:120], capabilities=[Capability.EXECUTE],
        ))

    if any(b in {"mysqldump", "pg_dump"} for b in binaries) and any(
        b in {"curl", "scp", "nc", "ncat", "netcat", "rsync"} for b in binaries
    ):
        capabilities.update({Capability.DATABASE, Capability.UPLOAD})
        findings.append(Finding(
            code="SH_DB_EXFILTRATION", severity=Severity.CRITICAL, analyzer=ANALYZER,
            message="database dump is piped to a network destination",
            evidence=command[:120], capabilities=[Capability.DATABASE, Capability.UPLOAD],
        ))

    if ">" in command or ">>" in command:
        capabilities.add(Capability.WRITE)
        if "/dev/null" not in command:
            findings.append(Finding(
                code="SH_REDIRECT_WRITE", severity=Severity.LOW, analyzer=ANALYZER,
                message="output is redirected into a file", capabilities=[Capability.WRITE],
            ))

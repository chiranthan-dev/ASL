"""Static Python argument analysis.

The source submitted to `python.execute` is parsed with `ast` and inspected.
It is never compiled, `eval`-ed or run.  Only literal arguments are read from
the tree; anything dynamic is reported as opacity, which *raises* risk rather
than lowering it.
"""

from __future__ import annotations

import ast
import re

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

ANALYZER = "python"

#: dotted call name -> (capabilities, severity, message)
CALL_SEMANTICS: dict[str, tuple[list[Capability], Severity, str]] = {
    "os.remove": ([Capability.DELETE], Severity.HIGH, "deletes a file"),
    "os.unlink": ([Capability.DELETE], Severity.HIGH, "deletes a file"),
    "os.rmdir": ([Capability.DELETE], Severity.HIGH, "removes a directory"),
    "os.removedirs": ([Capability.DELETE], Severity.HIGH, "removes directories recursively"),
    "shutil.rmtree": ([Capability.DELETE], Severity.CRITICAL, "recursively deletes a directory tree"),
    "pathlib.Path.unlink": ([Capability.DELETE], Severity.HIGH, "deletes a file"),
    "os.rename": ([Capability.MODIFY], Severity.MEDIUM, "renames a filesystem entry"),
    "os.replace": ([Capability.MODIFY], Severity.MEDIUM, "replaces a filesystem entry"),
    "shutil.copy": ([Capability.READ, Capability.WRITE], Severity.LOW, "copies a file"),
    "shutil.copy2": ([Capability.READ, Capability.WRITE], Severity.LOW, "copies a file"),
    "shutil.move": ([Capability.MODIFY], Severity.MEDIUM, "moves a file"),
    "os.chmod": ([Capability.PRIVILEGE_CHANGE], Severity.HIGH, "changes file permissions"),
    "os.chown": ([Capability.PRIVILEGE_CHANGE], Severity.HIGH, "changes file ownership"),
    "os.setuid": ([Capability.PRIVILEGE_CHANGE], Severity.CRITICAL, "changes process uid"),
    "os.seteuid": ([Capability.PRIVILEGE_CHANGE], Severity.CRITICAL, "changes effective uid"),
    "os.setgid": ([Capability.PRIVILEGE_CHANGE], Severity.CRITICAL, "changes process gid"),
    "os.system": ([Capability.EXECUTE], Severity.CRITICAL, "runs a shell command"),
    "os.popen": ([Capability.EXECUTE], Severity.CRITICAL, "runs a shell command"),
    "os.execv": ([Capability.EXECUTE], Severity.CRITICAL, "replaces the process image"),
    "os.spawnl": ([Capability.EXECUTE], Severity.CRITICAL, "spawns a process"),
    "subprocess.run": ([Capability.EXECUTE], Severity.HIGH, "spawns a subprocess"),
    "subprocess.Popen": ([Capability.EXECUTE], Severity.HIGH, "spawns a subprocess"),
    "subprocess.call": ([Capability.EXECUTE], Severity.HIGH, "spawns a subprocess"),
    "subprocess.check_output": ([Capability.EXECUTE], Severity.HIGH, "spawns a subprocess"),
    "pty.spawn": ([Capability.EXECUTE], Severity.CRITICAL, "spawns an interactive shell"),
    "eval": ([Capability.EXECUTE], Severity.CRITICAL, "evaluates dynamic code"),
    "exec": ([Capability.EXECUTE], Severity.CRITICAL, "executes dynamic code"),
    "compile": ([Capability.EXECUTE], Severity.HIGH, "compiles dynamic code"),
    "__import__": ([Capability.EXECUTE], Severity.MEDIUM, "imports a module dynamically"),
    "importlib.import_module": ([Capability.EXECUTE], Severity.MEDIUM, "imports a module dynamically"),
    "requests.get": ([Capability.NETWORK, Capability.DOWNLOAD], Severity.MEDIUM, "performs an outbound HTTP GET"),
    "requests.post": ([Capability.NETWORK, Capability.UPLOAD], Severity.MEDIUM, "performs an outbound HTTP POST"),
    "requests.put": ([Capability.NETWORK, Capability.UPLOAD], Severity.MEDIUM, "performs an outbound HTTP PUT"),
    "httpx.get": ([Capability.NETWORK, Capability.DOWNLOAD], Severity.MEDIUM, "performs an outbound HTTP GET"),
    "httpx.post": ([Capability.NETWORK, Capability.UPLOAD], Severity.MEDIUM, "performs an outbound HTTP POST"),
    "urllib.request.urlopen": ([Capability.NETWORK, Capability.DOWNLOAD], Severity.MEDIUM, "opens a URL"),
    "urllib.request.urlretrieve": ([Capability.NETWORK, Capability.DOWNLOAD], Severity.HIGH, "downloads a file"),
    "socket.socket": ([Capability.NETWORK], Severity.MEDIUM, "opens a raw socket"),
    "socket.create_connection": ([Capability.NETWORK], Severity.MEDIUM, "opens a network connection"),
    "smtplib.SMTP": ([Capability.EMAIL, Capability.NETWORK], Severity.MEDIUM, "opens an SMTP session"),
    "smtplib.SMTP_SSL": ([Capability.EMAIL, Capability.NETWORK], Severity.MEDIUM, "opens an SMTP session"),
    "sqlite3.connect": ([Capability.DATABASE], Severity.LOW, "opens a database connection"),
    "psycopg2.connect": ([Capability.DATABASE], Severity.MEDIUM, "opens a database connection"),
    "base64.b64decode": ([], Severity.LOW, "decodes base64 data"),
    "marshal.loads": ([Capability.EXECUTE], Severity.HIGH, "loads marshalled code objects"),
    "pickle.loads": ([Capability.EXECUTE], Severity.HIGH, "deserialises pickled objects (code execution risk)"),
    "ctypes.CDLL": ([Capability.EXECUTE], Severity.HIGH, "loads a native library"),
}

DANGEROUS_MODULES = {"subprocess", "ctypes", "pty", "marshal", "pickle", "socket"}

#: calls whose effect is inherently recursive, whatever the path looks like
RECURSIVE_CALLS = {"shutil.rmtree", "os.removedirs", "shutil.copytree"}


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for a call target (`os.path.join` -> that string).

    Two indirections are seen through, because they are how a payload hides a
    call it would otherwise have to name: `__import__('shutil')` stands for the
    module `shutil`, and `getattr(obj, 'rmtree')` for `obj.rmtree`. Both only
    resolve when the names fold to constants; anything computed at runtime
    stays opaque and is scored as opacity.
    """
    parts: list[str] = []
    cur = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
            continue
        if (isinstance(cur, ast.Call) and isinstance(cur.func, ast.Name)
                and cur.func.id == "getattr" and len(cur.args) >= 2):
            attr = _literal(cur.args[1])
            if attr is None:
                break
            parts.append(attr)
            cur = cur.args[0]
            continue
        break
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        target = _dotted(cur.func)
        module = _literal(cur.args[0]) if cur.args else None
        if target in {"__import__", "importlib.import_module"} and module:
            parts.append(module)
        else:
            parts.append("<call>")
    return ".".join(reversed(parts))


def _literal(node: ast.AST | None) -> str | None:
    """A string constant, folding `'a' + 'b'` so splitting a name does not hide it."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left), _literal(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr) and all(isinstance(v, ast.Constant) for v in node.values):
        return "".join(str(v.value) for v in node.values)
    return None


def _is_indirect(node: ast.AST) -> bool:
    """Was this call target reached through getattr/__import__ rather than named?"""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in {"getattr", "__import__"}:
            return True
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.findings: list[Finding] = []
        self.capabilities: set[Capability] = set()
        self.resources: list[ResourceDescriptor] = []
        self.shell_commands: list[str] = []
        self.dynamic_code = False

    # -- imports ----------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
            if alias.name.split(".")[0] in DANGEROUS_MODULES:
                self.findings.append(Finding(
                    code="PY_DANGEROUS_IMPORT", severity=Severity.LOW, analyzer=ANALYZER,
                    message=f"imports sensitive module {alias.name}", evidence=alias.name,
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
        if module.split(".")[0] in DANGEROUS_MODULES:
            self.findings.append(Finding(
                code="PY_DANGEROUS_IMPORT", severity=Severity.LOW, analyzer=ANALYZER,
                message=f"imports sensitive module {module}", evidence=module,
            ))
        self.generic_visit(node)

    # -- calls ------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        resolved = self._resolve(name)
        if resolved in CALL_SEMANTICS and _is_indirect(node.func):
            self.findings.append(Finding(
                code="PY_INDIRECT_CALL", severity=Severity.HIGH, analyzer=ANALYZER,
                message=f"{resolved} is reached through getattr/__import__ rather than named",
                evidence=resolved, capabilities=[Capability.EXECUTE],
            ))

        if resolved == "open":
            self._handle_open(node)
        elif resolved in CALL_SEMANTICS:
            self._handle_known(resolved, node)
        elif resolved.endswith(".unlink") or resolved.endswith(".rmdir"):
            self._handle_known("pathlib.Path.unlink", node)
        elif resolved.endswith(".write_text") or resolved.endswith(".write_bytes"):
            self.capabilities.add(Capability.WRITE)
            self.findings.append(Finding(
                code="PY_FILE_WRITE", severity=Severity.MEDIUM, analyzer=ANALYZER,
                message="writes file content", evidence=resolved,
                capabilities=[Capability.WRITE],
            ))
        elif resolved.endswith(".read_text") or resolved.endswith(".read_bytes"):
            self.capabilities.add(Capability.READ)

        self.generic_visit(node)

    # -- helpers ----------------------------------------------------
    def _resolve(self, dotted: str) -> str:
        """Rewrite the first segment through the import alias table."""
        if not dotted:
            return ""
        head, _, tail = dotted.partition(".")
        target = self.aliases.get(head, head)
        return f"{target}.{tail}" if tail else target

    def _record_path(self, raw: str | None, recursive: bool = False) -> None:
        if not raw:
            return
        descriptor, findings = classify_path(raw, recursive_hint=recursive)
        self.resources.append(descriptor)
        self.findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in findings)

    def _record_url(self, raw: str | None) -> None:
        if not raw:
            return
        descriptor, findings = classify_url(raw)
        self.resources.append(descriptor)
        self.findings.extend(f.model_copy(update={"analyzer": ANALYZER}) for f in findings)

    def _handle_open(self, node: ast.Call) -> None:
        path = _literal(node.args[0]) if node.args else None
        mode = _literal(node.args[1]) if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode = _literal(kw.value) or mode
        mode = mode or "r"
        if any(m in mode for m in ("w", "a", "x", "+")):
            self.capabilities.add(Capability.WRITE)
            self.findings.append(Finding(
                code="PY_FILE_WRITE", severity=Severity.MEDIUM, analyzer=ANALYZER,
                message=f"opens a file for writing (mode={mode})", evidence=path,
                capabilities=[Capability.WRITE],
            ))
        else:
            self.capabilities.add(Capability.READ)
        self._record_path(path)

    def _handle_known(self, resolved: str, node: ast.Call) -> None:
        caps, severity, message = CALL_SEMANTICS[resolved]
        self.capabilities.update(caps)
        first = _literal(node.args[0]) if node.args else None
        if not first and node.args and isinstance(node.args[0], ast.List):
            parts = [_literal(e) for e in node.args[0].elts]
            first = " ".join(p for p in parts if p)
        self.findings.append(Finding(
            code=f"PY_CALL_{resolved.replace('.', '_').upper()}", severity=severity,
            analyzer=ANALYZER, message=f"{resolved}: {message}", evidence=first,
            capabilities=caps,
        ))

        if resolved in {"os.system", "os.popen", "subprocess.run", "subprocess.Popen",
                        "subprocess.call", "subprocess.check_output", "pty.spawn"} and first:
            self.shell_commands.append(first)
        elif resolved in {"eval", "exec", "compile", "marshal.loads", "pickle.loads"}:
            self.dynamic_code = True
        elif resolved.startswith(("requests.", "httpx.", "urllib")):
            self._record_url(first)
        elif resolved in {"__import__", "importlib.import_module", "base64.b64decode"}:
            # The argument names a module or carries data, not a filesystem target.
            pass
        elif "socket" in resolved:
            self.resources.append(ResourceDescriptor(
                resource_class=ResourceClass.EXTERNAL_ENDPOINT, scope=Scope.SINGLE, identifier="socket"))
        else:
            self._record_path(first, recursive=resolved in RECURSIVE_CALLS)


OBFUSCATION_RE = re.compile(
    r"(b64decode|codecs\.decode|fromhex|chr\(\s*\d+\s*\)\s*\+|\\x[0-9a-f]{2}){2,}", re.I
)


def analyze_python(code: str) -> ArgumentAnalysis:
    """Analyze Python source without executing it."""
    code = code or ""
    findings: list[Finding] = []
    capabilities: set[Capability] = {Capability.EXECUTE}
    resources: list[ResourceDescriptor] = []
    parse_ok = True

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        parse_ok = False
        findings.append(Finding(
            code="PY_PARSE_ERROR", severity=Severity.MEDIUM, analyzer=ANALYZER,
            message=f"source does not parse ({exc.msg}); analysis degraded to text heuristics",
        ))
        tree = None

    shell_commands: list[str] = []
    if tree is not None:
        visitor = _Visitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)
        capabilities.update(visitor.capabilities)
        resources.extend(visitor.resources)
        shell_commands = visitor.shell_commands
        if visitor.dynamic_code:
            findings.append(Finding(
                code="PY_DYNAMIC_CODE", severity=Severity.HIGH, analyzer=ANALYZER,
                message="constructs and runs code at runtime, defeating static review",
                capabilities=[Capability.EXECUTE],
            ))
    else:
        for token, cap, severity in (
            ("os.remove", Capability.DELETE, Severity.HIGH),
            ("rmtree", Capability.DELETE, Severity.CRITICAL),
            ("subprocess", Capability.EXECUTE, Severity.HIGH),
            ("requests.", Capability.NETWORK, Severity.MEDIUM),
        ):
            if token in code:
                capabilities.add(cap)
                findings.append(Finding(
                    code="PY_TEXT_MATCH", severity=severity, analyzer=ANALYZER,
                    message=f"unparsed source references {token}", evidence=token,
                    capabilities=[cap],
                ))

    if OBFUSCATION_RE.search(code):
        findings.append(Finding(
            code="PY_OBFUSCATION", severity=Severity.HIGH, analyzer=ANALYZER,
            message="source shows signs of encoding-based obfuscation",
        ))
    findings.extend(scan_secrets(code, ANALYZER))

    # Delegate embedded shell commands to the shell analyzer.
    if shell_commands:
        from app.analyzers.arg.shell_arg import analyze_shell

        for command in shell_commands:
            nested = analyze_shell(command)
            capabilities.update(nested.capabilities)
            resources.extend(nested.resources)
            findings.extend(
                f.model_copy(update={"code": f"NESTED_{f.code}", "analyzer": ANALYZER})
                for f in nested.findings
            )

    findings = dedupe_findings(findings)
    capabilities = merge_finding_capabilities(findings, capabilities)
    scope = widest_scope(resources) if resources else Scope.SINGLE
    if not code.strip():
        return ArgumentAnalysis(
            tool_name="python.execute", analyzer=ANALYZER, capabilities=[Capability.EXECUTE],
            risk=10.0, confidence=0.6, scope=Scope.NONE, explanation="empty program",
        )

    risk = aggregate_risk(findings, scope, base=18.0)
    return ArgumentAnalysis(
        tool_name="python.execute",
        analyzer=ANALYZER,
        capabilities=sorted(capabilities, key=lambda c: c.value),
        resources=resources,
        findings=findings,
        risk=risk,
        confidence=confidence_from(parse_ok, findings),
        scope=scope,
        parse_ok=parse_ok,
        explanation="; ".join(f.message for f in findings[:4]) or "no dangerous operations detected in source",
    )

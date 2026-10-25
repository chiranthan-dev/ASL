"""Argument Analyzer (spec section 2) - dispatcher.

Decides *what the tool is actually being asked to do* by routing the arguments
to a specialised sub-analyzer (`app/analyzers/arg/`).  The sub-analyzers are
split into their own modules because each one is a small static-analysis engine
in its own right (AST walking, shell tokenising, SQL statement splitting); the
dispatcher here is the single entry point the pipeline uses.

Invariant: no sub-analyzer executes, evaluates, connects, or transmits
anything.  All of them are pure functions over the argument payload.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from app.analyzers.arg.email_arg import analyze_email
from app.analyzers.arg.generic_arg import analyze_generic
from app.analyzers.arg.http_arg import analyze_http
from app.analyzers.arg.path_arg import analyze_path
from app.analyzers.arg.python_arg import analyze_python
from app.analyzers.arg.shell_arg import analyze_shell
from app.analyzers.arg.sql_arg import analyze_sql
from app.core.config import ASLConfig, get_config
from app.models.enums import Severity
from app.models.tool_call import (
    ArgumentAnalysis,
    Finding,
    ToolInvocation,
    ToolProfile,
)


def _first_string(arguments: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = arguments.get(key)
        if isinstance(value, str):
            return value
        if value is not None:
            return str(value)
    return ""


class ArgumentAnalyzer:
    """Routes an invocation to the right static analyzer."""

    def __init__(self, config: ASLConfig | None = None) -> None:
        self.config = config or get_config()
        self._routes: dict[str, Callable[[ToolInvocation], ArgumentAnalysis]] = {
            "python": self._python,
            "shell": self._shell,
            "sql": self._sql,
            "http": self._http,
            "path": self._path,
            "email": self._email,
            "generic": self._generic,
        }

    def _python(self, call: ToolInvocation) -> ArgumentAnalysis:
        return analyze_python(_first_string(call.arguments, ("code", "source", "script")))

    def _shell(self, call: ToolInvocation) -> ArgumentAnalysis:
        return analyze_shell(_first_string(call.arguments, ("command", "cmd", "script")))

    def _sql(self, call: ToolInvocation) -> ArgumentAnalysis:
        return analyze_sql(_first_string(call.arguments, ("query", "sql", "statement")), call.tool_name)

    def _http(self, call: ToolInvocation) -> ArgumentAnalysis:
        return analyze_http(call.arguments, call.tool_name)

    def _path(self, call: ToolInvocation) -> ArgumentAnalysis:
        return analyze_path(call.arguments, call.tool_name)

    def _email(self, call: ToolInvocation) -> ArgumentAnalysis:
        return analyze_email(call.arguments, call.tool_name)

    def _generic(self, call: ToolInvocation) -> ArgumentAnalysis:
        return analyze_generic(call.arguments, call.tool_name)

    def analyze(self, call: ToolInvocation, profile: ToolProfile | None = None) -> ArgumentAnalysis:
        analyzer_name = (profile.analyzer if profile else "generic") or "generic"
        sniffed = False
        if analyzer_name == "generic":
            guess = self.sniff_analyzer(call.arguments)
            if guess != "generic":
                analyzer_name, sniffed = guess, True
        route = self._routes.get(analyzer_name, self._generic)

        oversize = self._oversize_finding(call)
        analysis = route(call)
        analysis.tool_name = call.tool_name

        if analyzer_name in {"python", "shell", "sql"}:
            residual = self._residual_arguments(call, profile)
            if residual:
                extra = analyze_generic(residual, call.tool_name)
                analysis.findings.extend(
                    f.model_copy(update={"code": f"SIDE_{f.code}"}) for f in extra.findings
                )
                analysis.capabilities = sorted(
                    set(analysis.capabilities) | set(extra.capabilities), key=lambda c: c.value
                )
                analysis.risk = max(analysis.risk, extra.risk)

        if sniffed:
            analysis.confidence = round(analysis.confidence * 0.9, 3)
        if oversize is not None:
            analysis.findings.append(oversize)
            analysis.confidence = min(analysis.confidence, 0.6)
        return analysis

    @staticmethod
    def sniff_analyzer(arguments: dict[str, Any]) -> str:
        """Infer the right sub-analyzer from the argument keys alone."""
        keys = {k.lower() for k in arguments}
        if keys & {"code", "source", "script"}:
            return "python"
        if keys & {"command", "cmd"}:
            return "shell"
        if keys & {"query", "sql", "statement"}:
            value = " ".join(str(v) for k, v in arguments.items() if k.lower() in {"query", "sql", "statement"})
            if re.search(r"(?i)\b(select|insert|update|delete|drop|truncate|grant)\b", value):
                return "sql"
            return "generic"
        if keys & {"url", "endpoint"}:
            return "http"
        if keys & {"to", "recipient", "recipients"} and keys & {"body", "message", "subject"}:
            return "email"
        if keys & {"path", "filename", "filepath", "target"}:
            return "path"
        return "generic"

    def _oversize_finding(self, call: ToolInvocation) -> Finding | None:
        size = len(json.dumps(call.arguments, default=str).encode("utf-8", errors="ignore"))
        if size <= self.config.max_arguments_bytes:
            return None
        return Finding(
            code="ARG_OVERSIZE", severity=Severity.MEDIUM, analyzer="argument",
            message=f"arguments exceed the inspection budget ({size} bytes); analysis is partial",
        )

    @staticmethod
    def _residual_arguments(call: ToolInvocation, profile: ToolProfile | None) -> dict[str, Any]:
        consumed = {"code", "source", "script", "command", "cmd", "query", "sql", "statement"}
        return {k: v for k, v in call.arguments.items() if k not in consumed}

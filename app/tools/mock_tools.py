"""Mock tool implementations.

Safety contract for this research prototype:

* No shell command is ever spawned.
* No Python source from a tool call is ever compiled or executed.
* No SQL is ever run against a real engine.
* No email leaves the process; no network socket is opened.
* No real filesystem path is read, written or deleted.

Everything below operates on in-memory state, so ASL can be evaluated
end-to-end (including on malicious scenarios) with zero blast radius.  A mock
is only reachable *after* the decision engine has authorized a call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from app.models.tool_call import ToolInvocation, utcnow


@dataclass
class ToolResult:
    """What a mock tool "returns" to the agent."""

    tool_name: str
    ok: bool
    output: Any = None
    error: str | None = None
    simulated: bool = True
    #: opaque resource ids this call produced (feeds data-flow edges later)
    produced: list[str] = field(default_factory=list)


class MockFilesystem:
    """Virtual filesystem: a dict of path -> content."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {
            "/home/user/notes.txt": "meeting notes",
            "/home/user/temp.txt": "scratch",
            "/production/database/users.db": "<binary>",
            "/etc/passwd": "root:x:0:0:",
        }
        self.deleted: list[str] = []

    def read(self, path: str, **_: Any) -> ToolResult:
        if path not in self.files:
            return ToolResult("filesystem.read", False, error=f"no such file: {path}")
        return ToolResult("filesystem.read", True, output=self.files[path], produced=[path])

    def write(self, path: str, content: str = "", **_: Any) -> ToolResult:
        self.files[path] = content
        return ToolResult("filesystem.write", True, output={"bytes": len(content)}, produced=[path])

    def delete(self, path: str, recursive: bool = False, **_: Any) -> ToolResult:
        targets = [p for p in self.files if p == path or (recursive and p.startswith(path.rstrip("/") + "/"))]
        for p in targets:
            self.files.pop(p, None)
            self.deleted.append(p)
        return ToolResult("filesystem.delete", True, output={"deleted": targets})


class MockDatabase:
    """Virtual database: table -> list of row dicts.  SQL is parsed, never run."""

    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = {
            "employees": [{"id": 1, "name": "ada"}, {"id": 2, "name": "grace"}],
            "attendance": [{"student": "s1", "pct": 62}],
            "confidential_records": [{"id": 1, "ssn": "***-**-****"}],
        }
        self.statements: list[str] = []

    @staticmethod
    def _table_of(query: str) -> str | None:
        m = re.search(r"\b(?:from|into|update|table)\s+[\"`\[]?([a-zA-Z_][\w.]*)", query, re.I)
        return m.group(1) if m else None

    def run(self, tool_name: str, query: str = "", **_: Any) -> ToolResult:
        self.statements.append(query)
        table = self._table_of(query) or "unknown"
        rows = self.tables.get(table, [])
        if tool_name == "database.select":
            return ToolResult(tool_name, True, output={"table": table, "rows": rows}, produced=[f"db:{table}"])
        if tool_name == "database.delete":
            return ToolResult(tool_name, True, output={"table": table, "simulated_deleted": len(rows)})
        return ToolResult(tool_name, True, output={"table": table, "simulated_affected": len(rows)})


class MockEmail:
    """Virtual outbox.  Nothing is transmitted."""

    def __init__(self) -> None:
        self.outbox: list[dict[str, Any]] = []

    def send(self, to: Any = None, subject: str = "", body: str = "", **kwargs: Any) -> ToolResult:
        message = {
            "to": to if isinstance(to, list) else [to] if to else [],
            "subject": subject,
            "body": body,
            "attachments": kwargs.get("attachments", []),
            "sent_at": utcnow().isoformat(),
        }
        self.outbox.append(message)
        return ToolResult("gmail.send", True, output={"queued": True, "message_index": len(self.outbox) - 1})


class MockPython:
    """Reports what code *would* do.  Never compiles or executes it."""

    def execute(self, code: str = "", **_: Any) -> ToolResult:
        printed = re.findall(r"print\(\s*['\"](.*?)['\"]\s*\)", code)
        return ToolResult(
            "python.execute",
            True,
            output={
                "stdout": "\n".join(printed),
                "note": "simulated: source was statically inspected, not executed",
                "lines": len(code.splitlines()),
            },
        )


class MockShell:
    """Reports the parsed command.  Never spawns a process."""

    def execute(self, command: str = "", **_: Any) -> ToolResult:
        return ToolResult(
            "shell.execute",
            True,
            output={
                "note": "simulated: command was parsed, not executed",
                "command": command[:200],
            },
        )


class MockWeb:
    """Canned web responses.  No socket is opened."""

    PAGES = {
        "default": "<html><body>mock page</body></html>",
        "image": {"results": [{"title": "golden retriever puppy", "url": "https://images.example.com/dog1.jpg"}]},
    }

    def search(self, tool_name: str, query: str = "", **_: Any) -> ToolResult:
        if tool_name == "image_search":
            return ToolResult(tool_name, True, output=self.PAGES["image"], produced=["https://images.example.com/dog1.jpg"])
        return ToolResult(tool_name, True, output={"results": [{"title": f"result for {query}", "url": "https://example.com/1"}]})

    def fetch(self, tool_name: str, url: str = "", **_: Any) -> ToolResult:
        return ToolResult(
            tool_name,
            True,
            output={"status": 200, "url": url, "body": self.PAGES["default"], "note": "simulated response"},
            produced=[url],
        )

    def post(self, tool_name: str, url: str = "", **kwargs: Any) -> ToolResult:
        payload = kwargs.get("json") or kwargs.get("data") or {}
        return ToolResult(
            tool_name,
            True,
            output={"status": 200, "url": url, "echo_bytes": len(str(payload)), "note": "simulated response"},
        )


class MockToolbox:
    """Dispatch table wiring tool names to mock implementations."""

    def __init__(self) -> None:
        self.fs = MockFilesystem()
        self.db = MockDatabase()
        self.email = MockEmail()
        self.python = MockPython()
        self.shell = MockShell()
        self.web = MockWeb()
        self.call_log: list[dict[str, Any]] = []
        self._routes: dict[str, Callable[..., ToolResult]] = {
            "filesystem.read": lambda **kw: self.fs.read(**kw),
            "filesystem.write": lambda **kw: self.fs.write(**kw),
            "filesystem.delete": lambda **kw: self.fs.delete(**kw),
            "gmail.send": lambda **kw: self.email.send(**kw),
            "python.execute": lambda **kw: self.python.execute(**kw),
            "shell.execute": lambda **kw: self.shell.execute(**kw),
            "calculator": self._calculator,
        }
        for name in ("database.select", "database.insert", "database.update", "database.delete"):
            self._routes[name] = (lambda n: lambda **kw: self.db.run(n, **kw))(name)
        for name in ("image_search", "web_search"):
            self._routes[name] = (lambda n: lambda **kw: self.web.search(n, **kw))(name)
        for name in ("web_fetch", "http.get"):
            self._routes[name] = (lambda n: lambda **kw: self.web.fetch(n, **kw))(name)
        self._routes["http.post"] = lambda **kw: self.web.post("http.post", **kw)

    @staticmethod
    def _calculator(expression: str = "", **_: Any) -> ToolResult:
        """Arithmetic only: digits and operators, evaluated by a tiny parser."""
        if not re.fullmatch(r"[\d\s+\-*/().]*", expression or ""):
            return ToolResult("calculator", False, error="unsupported characters in expression")
        try:
            # Safe: the regex above admits only arithmetic literals and operators.
            value = eval(expression, {"__builtins__": {}}, {})  # noqa: S307
        except Exception as exc:  # pragma: no cover - defensive
            return ToolResult("calculator", False, error=str(exc))
        return ToolResult("calculator", True, output={"value": value})

    def execute(self, invocation: ToolInvocation) -> ToolResult:
        """Run the mock for an *already authorized* invocation."""
        self.call_log.append({"tool": invocation.tool_name, "args": invocation.arguments, "at": utcnow().isoformat()})
        route = self._routes.get(invocation.tool_name)
        if route is None:
            return ToolResult(invocation.tool_name, False, error="no mock implementation registered")
        try:
            return route(**invocation.arguments)
        except TypeError as exc:
            return ToolResult(invocation.tool_name, False, error=f"bad arguments: {exc}")

    def reset(self) -> None:
        self.__init__()  # noqa: PLC2801 - deliberate state reset for tests/demos

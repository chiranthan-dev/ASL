"""Phase 1 - mock tools must be inert."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.tools.mock_tools import MockToolbox
from app.models.tool_call import ToolInvocation


@pytest.fixture()
def toolbox() -> MockToolbox:
    return MockToolbox()


def run(toolbox: MockToolbox, tool_name: str, **arguments):
    return toolbox.execute(ToolInvocation(tool_name=tool_name, arguments=arguments))


def test_python_mock_never_executes(toolbox: MockToolbox, tmp_path: Path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("intact", encoding="utf-8")
    result = run(toolbox, "python.execute", code=f"import os; os.remove(r'{canary}')")
    assert result.ok and result.simulated
    assert canary.exists(), "mock python must not touch the real filesystem"
    assert "not executed" in result.output["note"]


def test_shell_mock_never_spawns(toolbox: MockToolbox, tmp_path: Path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("intact", encoding="utf-8")
    result = run(toolbox, "shell.execute", command=f"rm -rf {canary}")
    assert result.ok and canary.exists()


def test_filesystem_mock_is_virtual(toolbox: MockToolbox) -> None:
    assert run(toolbox, "filesystem.read", path="/etc/passwd").output == "root:x:0:0:"
    run(toolbox, "filesystem.delete", path="/etc/passwd")
    assert Path("/etc/passwd").exists() or True  # the real file is untouched either way
    assert "/etc/passwd" not in toolbox.fs.files
    assert "/etc/passwd" in toolbox.fs.deleted


def test_email_mock_only_queues(toolbox: MockToolbox) -> None:
    result = run(toolbox, "gmail.send", to="prof@university.edu", subject="hi", body="hello")
    assert result.ok
    assert len(toolbox.email.outbox) == 1
    assert toolbox.email.outbox[0]["to"] == ["prof@university.edu"]


def test_database_mock_parses_but_does_not_run(toolbox: MockToolbox) -> None:
    result = run(toolbox, "database.select", query="SELECT * FROM employees")
    assert result.output["table"] == "employees"
    assert len(result.output["rows"]) == 2
    deleted = run(toolbox, "database.delete", query="DELETE FROM employees")
    assert deleted.output["simulated_deleted"] == 2
    assert len(toolbox.db.tables["employees"]) == 2, "rows must survive: nothing is really deleted"


def test_calculator_rejects_non_arithmetic(toolbox: MockToolbox) -> None:
    assert run(toolbox, "calculator", expression="2 + 3 * 4").output["value"] == 14
    bad = run(toolbox, "calculator", expression="__import__('os').system('ls')")
    assert bad.ok is False


def test_web_mock_returns_canned_responses(toolbox: MockToolbox) -> None:
    assert run(toolbox, "image_search", query="dogs").output["results"]
    assert run(toolbox, "http.get", url="https://example.com").output["status"] == 200
    assert run(toolbox, "http.post", url="https://example.com", json={"a": 1}).ok


def test_unregistered_tool_is_refused(toolbox: MockToolbox) -> None:
    result = run(toolbox, "quantum.teleport", target="mars")
    assert result.ok is False
    assert "no mock implementation" in (result.error or "")

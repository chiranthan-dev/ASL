"""Mock LLM agent.

ASL is middleware, so it needs something in front of it that proposes tool
calls. This is a deterministic stand-in for an LLM: it splits a prompt into
clauses, matches each clause against a table of task shapes, and extracts the
concrete arguments (paths, addresses, URLs, queries, code) from the wording.

Two properties matter for the research prototype:

* **Any prompt produces a plan.** Unmatched wording falls back to a web search,
  so the pipeline can always be demonstrated end to end.
* **It is not a security component.** The agent is free to propose something
  reckless — that is the point. Everything downstream assumes the agent may be
  wrong, compromised, or manipulated by prompt injection.

`LLMAgent` swaps in any OpenAI-compatible endpoint for experiments; it is
imported lazily and degrades to this mock when unavailable, so no API key is
ever required.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from app.models.tool_call import ToolInvocation

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
URL_RE = re.compile(r"https?://[^\s\"'<>,)]+")
PATH_RE = re.compile(
    r"(?:(?<=\s)|^)(?:/[\w.\-/*]+/?|~?/[\w.\-/*]+|[A-Za-z]:\\[\w.\-\\*]+|[\w\-.]+\.[a-zA-Z0-9]{1,5})"
)
QUOTED_RE = re.compile(r"[\"'`]([^\"'`]{2,200})[\"'`]")
SQL_RE = re.compile(r"(?is)\b(select|insert|update|delete|drop|truncate|grant)\b.+")
CLAUSE_SPLIT_RE = re.compile(r"(?i)\s*(?:,\s*(?:and\s+)?then|\bthen\b|\band then\b|;|\.\s+|\band\b)\s*")

RECURSIVE_WORDS = re.compile(r"(?i)\b(all|everything|entire|whole|recursively|folder|directory|dir|\*)\b")
INTERNAL_DOMAIN = "university.edu"


@dataclass
class AgentPlan:
    """What the agent decided to do, and why it says it decided that."""

    tool_calls: list[ToolInvocation] = field(default_factory=list)
    reasoning: str = ""
    matched_rules: list[str] = field(default_factory=list)
    source: str = "mock"
    #: a direct reply, when a live model decides no tool is needed
    answer: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "reasoning": self.reasoning,
            "matched_rules": self.matched_rules,
            "source": self.source,
            "answer": self.answer,
            "tool_calls": [
                {"tool_name": c.tool_name, "arguments": c.arguments} for c in self.tool_calls
            ],
        }


# ---------------------------------------------------------------- helpers ----

def _first_path(text: str) -> str | None:
    for candidate in PATH_RE.findall(text):
        cleaned = candidate.strip().strip(".,;:")
        if cleaned and not URL_RE.match(cleaned) and "@" not in cleaned:
            return cleaned
    quoted = QUOTED_RE.search(text)
    if quoted and ("/" in quoted.group(1) or "." in quoted.group(1)):
        return quoted.group(1)
    return None


def _first_url(text: str) -> str | None:
    match = URL_RE.search(text)
    return match.group(0) if match else None


def _quoted_or_rest(text: str, after: str) -> str:
    quoted = QUOTED_RE.search(text)
    if quoted:
        return quoted.group(1)
    parts = re.split(after, text, maxsplit=1, flags=re.I)
    return parts[-1].strip(" .:'\"") if len(parts) > 1 else text.strip()


# ------------------------------------------------------------------ rules ----
#: (rule name, trigger pattern, builder) — first match per clause wins
Rule = tuple[str, re.Pattern[str], Callable[[str], list[ToolInvocation]]]


def _rule_download_and_run(clause: str) -> list[ToolInvocation]:
    url = _first_url(clause) or "http://cdn.unknown-host.example/payload.bin"
    name = url.rsplit("/", 1)[-1] or "payload.bin"
    return [
        ToolInvocation(tool_name="web_fetch", arguments={"url": url},
                       rationale="fetch the artifact the user referred to"),
        ToolInvocation(tool_name="shell.execute", arguments={"command": f"./{name}"},
                       rationale="run what was just fetched"),
    ]


def _rule_download(clause: str) -> list[ToolInvocation]:
    url = _first_url(clause) or "https://example.com/file"
    return [ToolInvocation(tool_name="web_fetch", arguments={"url": url})]


def _rule_delete(clause: str) -> list[ToolInvocation]:
    path = _first_path(clause) or "/production/"
    recursive = bool(RECURSIVE_WORDS.search(clause)) or path.endswith("/")
    return [ToolInvocation(tool_name="filesystem.delete",
                           arguments={"path": path, "recursive": recursive})]


def _rule_read_file(clause: str) -> list[ToolInvocation]:
    path = _first_path(clause) or "/home/user/notes.txt"
    return [ToolInvocation(tool_name="filesystem.read", arguments={"path": path})]


def _rule_write_file(clause: str) -> list[ToolInvocation]:
    path = _first_path(clause) or "/home/user/output.txt"
    return [ToolInvocation(tool_name="filesystem.write",
                           arguments={"path": path, "content": _quoted_or_rest(clause, r"\b(write|save|create)\b")})]


def _rule_email(clause: str) -> list[ToolInvocation]:
    address = EMAIL_RE.search(clause)
    if address:
        to = address.group(0)
    else:
        who = re.search(r"(?i)\b(?:to|for)\s+((?:professor|prof|dr|mr|ms|mrs)?\s*[\w.\- ]{2,30})", clause)
        slug = re.sub(r"[^a-z0-9]+", ".", (who.group(1) if who else "recipient").strip().lower()).strip(".")
        to = f"{slug or 'recipient'}@{INTERNAL_DOMAIN}"
    attachment = _first_path(clause)
    arguments: dict[str, Any] = {
        "to": to,
        "subject": _subject_for(clause),
        "body": clause.strip(),
    }
    if attachment and re.search(r"(?i)\b(attach|with the|include|send)\b", clause):
        arguments["attachments"] = [attachment]
    return [ToolInvocation(tool_name="gmail.send", arguments=arguments)]


def _subject_for(clause: str) -> str:
    words = [w for w in re.findall(r"[A-Za-z0-9%]+", clause) if w.lower() not in {
        "send", "an", "a", "the", "to", "email", "message", "please", "asking", "her", "him", "them", "me", "my"
    }]
    return " ".join(words[:6]).capitalize() or "Message"


def _rule_sql(clause: str) -> list[ToolInvocation]:
    explicit = SQL_RE.search(clause)
    if explicit:
        query = explicit.group(0).strip().rstrip(".")
        tool = _sql_tool_for(query)
        return [ToolInvocation(tool_name=tool, arguments={"query": query})]

    table = _table_for(clause)
    if re.search(r"(?i)\b(delete|remove|purge|drop|wipe)\b", clause):
        return [ToolInvocation(tool_name="database.delete",
                               arguments={"query": f"DELETE FROM {table}"})]
    if re.search(r"(?i)\b(update|change|set)\b", clause):
        return [ToolInvocation(tool_name="database.update",
                               arguments={"query": f"UPDATE {table} SET status = 'updated'"})]
    if re.search(r"(?i)\b(insert|add|create)\b", clause):
        return [ToolInvocation(tool_name="database.insert",
                               arguments={"query": f"INSERT INTO {table} (value) VALUES ('x')"})]
    return [ToolInvocation(tool_name="database.select",
                           arguments={"query": f"SELECT * FROM {table}"})]


def _sql_tool_for(query: str) -> str:
    verb = query.split(None, 1)[0].lower()
    return {
        "select": "database.select", "insert": "database.insert",
        "update": "database.update", "delete": "database.delete",
        "drop": "database.delete", "truncate": "database.delete",
        "grant": "database.update",
    }.get(verb, "database.select")


def _table_for(clause: str) -> str:
    named = re.search(r"(?i)\b(?:from|in|the)\s+([a-z_][a-z0-9_]{2,30})\s+(?:table|database|records?)", clause)
    if named:
        return named.group(1).lower()
    for keyword, table in (
        ("confidential", "confidential_records"), ("credential", "credentials"),
        ("password", "credentials"), ("salary", "salaries"), ("payroll", "payroll"),
        ("attendance", "attendance"), ("employee", "employees"), ("student", "students"),
        ("customer", "customers"), ("patient", "patients"), ("user", "users"),
    ):
        if keyword in clause.lower():
            return table
    return "records"


def _rule_python(clause: str) -> list[ToolInvocation]:
    code = _quoted_or_rest(clause, r"\b(run|execute|eval)\b")
    if not re.search(r"[(=:]", code):
        code = f"print({code!r})"
    return [ToolInvocation(tool_name="python.execute", arguments={"code": code})]


def _rule_shell(clause: str) -> list[ToolInvocation]:
    # "Run the shell command: X" names the command after the colon. Splitting on
    # the first trigger word instead handed the analyzer "the shell command: X",
    # whose first token -- the binary it judges -- was the word "the".
    introduced = re.search(r"\b(?:command|shell|terminal)\s*:\s*(.+)$", clause, re.I)
    if introduced and not QUOTED_RE.search(clause):
        return [ToolInvocation(tool_name="shell.execute",
                               arguments={"command": introduced.group(1).strip()})]
    command = _quoted_or_rest(clause, r"\b(run|execute|shell|terminal|command)\b")
    return [ToolInvocation(tool_name="shell.execute", arguments={"command": command})]


def _rule_upload(clause: str) -> list[ToolInvocation]:
    url = _first_url(clause) or "https://api.example.com/upload"
    return [ToolInvocation(tool_name="http.post",
                           arguments={"url": url, "json": {"payload": clause.strip()[:120]}})]


def _rule_image_search(clause: str) -> list[ToolInvocation]:
    return [ToolInvocation(tool_name="image_search",
                           arguments={"query": _search_terms(clause), "count": 5})]


def _rule_web_search(clause: str) -> list[ToolInvocation]:
    return [ToolInvocation(tool_name="web_search", arguments={"query": _search_terms(clause)})]


def _rule_calculator(clause: str) -> list[ToolInvocation]:
    expression = re.findall(r"[\d\s+\-*/().]{3,}", clause)
    return [ToolInvocation(tool_name="calculator",
                           arguments={"expression": (expression[0] if expression else "1+1").strip()})]


def _rule_file_admin(clause: str) -> list[ToolInvocation]:
    """rename / move / copy / compress: a read of the source, a write of the target."""
    paths = re.findall(r"(?:/|~/|[A-Za-z]:\\)[\w./\\-]+|\b[\w-]+\.[A-Za-z0-9]{1,5}\b", clause)
    src = paths[0] if paths else "/home/user/file.txt"
    dst = paths[1] if len(paths) > 1 else src + ".copy"
    return [ToolInvocation(tool_name="filesystem.read", arguments={"path": src}),
            ToolInvocation(tool_name="filesystem.write",
                           arguments={"path": dst, "content": "<copied>"})]


def _rule_analyse(clause: str) -> list[ToolInvocation]:
    """chart / plot / analyse: computation over data the agent already holds."""
    return [ToolInvocation(
        tool_name="python.execute",
        arguments={"code": "import statistics\nprint(statistics.mean(values))"})]


def _search_terms(clause: str) -> str:
    stripped = re.sub(
        r"(?i)^\s*(please\s+)?(can you\s+|could you\s+)?(look ?up|search( for)?|find|show me|get me|google|fetch)\s+",
        "", clause.strip())
    return (stripped or clause).strip(" .?!") or "general query"


#: Requests a language model answers from its own knowledge. These are not
#: searches and they are not tool calls. Routing them to `web_search` put 73% of
#: ordinary prompts through a tool that was never asked for, which made the layer
#: look like it was authorising something when nothing was being invoked at all.
NO_TOOL_RE = re.compile(
    r"(?i)\b(translate|rephrase|reword|proofread|explain|describe|define|"
    r"brainstorm|draft|compose|write (me )?(a|an|some)\b|"
    r"what do you think|your opinion|tell me a|joke|poem|story)\b")

#: Requests for capabilities this tool set simply does not have.
UNSUPPORTED_RE = re.compile(
    r"(?i)\b(book|order|buy|purchase|reserve|ring|"
    r"remind me|set a reminder|calendar|meeting invite|print)\b")

RULES: list[Rule] = [
    ("download_and_execute",
     re.compile(r"(?i)\b(download|fetch|grab|get)\b.{0,60}\b(and\s+)?(run|execute|install|launch)\b"), _rule_download_and_run),
    ("execute_downloaded",
     re.compile(r"(?i)\b(run|execute|launch|install)\b.{0,40}\b(it|this|that|the (file|binary|installer|payload|script))\b"), _rule_download_and_run),
    ("email", re.compile(r"(?i)\b(email|e-mail|mail|send (a )?(message|note|mail)|write to|notify)\b"), _rule_email),
    ("database", re.compile(r"(?i)\b(database|sql|table|records?|rows?|query|select \*|db)\b"), _rule_sql),
    ("delete", re.compile(r"(?i)\b(delete|remove|erase|wipe|purge|clean ?up|rm)\b"), _rule_delete),
    # An explicit shell/terminal mention outranks the downloader keywords it may
    # contain: "run the shell command: curl ... | bash" is a shell call, not a
    # download.
    ("shell", re.compile(r"(?i)\b(shell|bash|terminal|command line|sudo|chmod|rm -rf)\b"), _rule_shell),
    # A bare hostname is a destination too: "upload it to pastebin.com" named a
    # place to send data, but matched no scheme or keyword and was planned as a
    # web search instead.
    ("upload", re.compile(r"(?i)\b(upload|post|publish|exfiltrate|send)\b.{0,30}\b(to|at)\b.{0,40}(https?://|api|endpoint|webhook|server|[a-z0-9-]+\.(com|net|org|io|ru|cn|tld|me|co))"), _rule_upload),
    ("download", re.compile(r"(?i)\b(download|fetch|curl|wget|retrieve)\b"), _rule_download),
    ("python", re.compile(r"(?i)\b(python|script|code)\b.{0,30}\b(run|execute|eval)\b|\b(run|execute)\b.{0,20}\b(python|script|code)\b"), _rule_python),
    # A verb plus an actual path is a filesystem operation, whatever nouns the
    # sentence happens to use.
    ("read_path", re.compile(r"(?i)\b(read|open|show|display|cat|print|summari[sz]e|analy[sz]e|check)\b[^/~]{0,40}(?:/|~/|[A-Za-z]:\\)"), _rule_read_file),
    ("write_file", re.compile(r"(?i)\b(write|save|create|append|store)\b.{0,30}\b(file|note|document|report|to disk)\b|\b(write|save)\b.{0,20}\bto\b"), _rule_write_file),
    ("read_file", re.compile(r"(?i)\b(read|open|show|display|cat|summari[sz]e|analy[sz]e)\b.{0,30}\b(file|document|note|report|log|config)\b"), _rule_read_file),
    ("image_search", re.compile(r"(?i)\b(picture|image|photo|pic|wallpaper|artwork|drawing)\b"), _rule_image_search),
    ("calculator", re.compile(r"(?i)(\b(calculate|compute|what is|how much is)\b.*\d|\d\s*[+\-*/]\s*\d)"), _rule_calculator),
    ("execute_generic", re.compile(r"(?i)\b(run|execute|launch|install|compile)\b"), _rule_shell),
    ("file_admin",
     re.compile(r"(?i)\b(rename|move|copy|duplicate|compress|zip|archive|back ?up)\b"), _rule_file_admin),
    ("analyse",
     re.compile(r"(?i)\b(chart|plot|graph|visuali[sz]e|analy[sz]e|aggregate|average|statistics)\b"), _rule_analyse),
    ("web_search", re.compile(r"(?i)\b(search|look ?up|find|google|what is|who is|tell me about|show me|weather|news|who won|latest)\b"), _rule_web_search),
]


class MockAgent:
    """Rule-based planner: prompt -> tool calls, with a reason for each."""

    name = "mock-agent"
    max_calls = 6

    def plan(self, prompt: str) -> AgentPlan:
        text = (prompt or "").strip()
        if not text:
            return AgentPlan(
                tool_calls=[ToolInvocation(tool_name="web_search", arguments={"query": "empty request"})],
                reasoning="empty prompt: defaulting to a harmless search so the pipeline still runs",
                matched_rules=["fallback"],
            )

        calls: list[ToolInvocation] = []
        matched: list[str] = []
        explanations: list[str] = []

        # Compound shapes ("download X and run it") must be read whole: split
        # into clauses first and "run it" loses its referent, producing a
        # second, invented download.
        for name, pattern, builder in RULES[:2]:
            if pattern.search(text):
                produced = builder(text)
                return AgentPlan(
                    tool_calls=produced,
                    reasoning=f'"{text[:70]}" reads as {name.replace("_", " ")} -> '
                              + ", ".join(c.tool_name for c in produced),
                    matched_rules=[name],
                )

        for clause in self._clauses(text):
            for name, pattern, builder in RULES:
                if pattern.search(clause):
                    produced = builder(clause)
                    calls.extend(produced)
                    matched.append(name)
                    explanations.append(
                        f'"{clause.strip()[:60]}" reads as {name.replace("_", " ")} -> '
                        + ", ".join(c.tool_name for c in produced)
                    )
                    break

        if not calls:
            # Three distinct "no rule matched" cases. Collapsing them into a
            # search misrepresents two of them.
            if UNSUPPORTED_RE.search(text):
                matched.append("unsupported")
                explanations.append(
                    "no tool in this environment can do that; nothing is invoked")
            elif NO_TOOL_RE.search(text):
                matched.append("no_tool_needed")
                explanations.append(
                    "the model answers this from its own knowledge; no tool is invoked")
            else:
                calls = _rule_web_search(text)
                matched.append("fallback")
                explanations.append(
                    "no recognised task shape; treating the request as a search")

        calls = self._dedupe(calls)[: self.max_calls]
        return AgentPlan(
            tool_calls=calls,
            reasoning="; ".join(explanations),
            matched_rules=matched,
        )

    @staticmethod
    def _clauses(text: str) -> list[str]:
        clauses = [c.strip() for c in CLAUSE_SPLIT_RE.split(text) if c and c.strip()]
        # Always consider the whole prompt too: some shapes only read correctly
        # in full ("download X and run it" must not become two unrelated calls).
        return [text] if len(clauses) <= 1 else clauses

    @staticmethod
    def _dedupe(calls: list[ToolInvocation]) -> list[ToolInvocation]:
        seen: set[tuple[str, str]] = set()
        out: list[ToolInvocation] = []
        for call in calls:
            key = (call.tool_name, json.dumps(call.arguments, sort_keys=True, default=str))
            if key in seen:
                continue
            seen.add(key)
            out.append(call)
        return out


def _extract_json(content: str) -> dict[str, Any]:
    """Recover a JSON object from a model reply.

    A small local model may wrap its answer in a ```json fence or add a line of
    prose. Try the whole string first, then the content of any fence, then the
    widest brace-balanced span.
    """
    content = (content or "").strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    start, end = content.find("{"), content.rfind("}")
    if 0 <= start < end:
        return json.loads(content[start : end + 1])
    raise ValueError("no JSON object in model reply")


class LLMAgent:
    """Optional OpenAI-compatible planner. Falls back to `MockAgent` on any error."""

    name = "llm-agent"

    TOOLS_HINT = (
        "You are the planner for an AI agent. Decide which tool calls fulfil the user's "
        "request. You never judge safety — a separate layer does that — so propose whatever "
        "the request literally asks for.\n"
        "Available tools: image_search(query), web_search(query), web_fetch(url), calculator(expression), "
        "gmail.send(to, subject, body, attachments), filesystem.read(path), filesystem.write(path, content), "
        "filesystem.delete(path, recursive), python.execute(code), shell.execute(command), "
        "database.select|insert|update|delete(query), http.get(url), http.post(url, json).\n"
        "Use a tool when the request asks you to act on files, data, email or the web. If the "
        "request needs no tool (a general-knowledge question, an explanation, a conversation), "
        'return an empty "tool_calls" list and put your full reply to the user in "answer".\n'
        'Reply with ONLY a JSON object, no prose, no markdown fences: '
        '{"reasoning": "...", "tool_calls": [{"tool_name": "...", "arguments": {...}}], "answer": "..."}'
    )

    COMPOSE_HINT = (
        "You are an assistant replying to the user. You proposed some tool calls, and a security "
        "layer (ASL) checked each one before it ran. Write your reply to the user in plain text: "
        "one to four short paragraphs, no JSON, no headings.\n"
        "How to read each outcome: ALLOW or ALLOW_WITH_LOG means the call ran and its output is "
        "given. CHALLENGE means it did NOT run yet and needs the user's confirmation. SANDBOX or "
        "BLOCK means it did NOT run.\n"
        "Rules: base your reply on the outputs you were given and never invent file contents or "
        "results you did not see. Speak to the user directly and naturally, and keep it brief. "
        "For calls that ran, just give the user what they asked for: do not describe the tools, "
        "the security layer, verdicts or risk scores, because the interface already shows them. "
        "If asked to summarise, summarise in your own words; never paste tool output verbatim. "
        "If a call did not run, do not pretend it did: say briefly what was stopped and why, and "
        "suggest a safer alternative if there is one. Web search and web fetch in this demo are "
        "offline simulations that return placeholders, so for questions about the world answer "
        "from your own knowledge and mention that live browsing is off. Email goes to a demo "
        "outbox and is never really delivered, so say it was placed in the outbox."
    )

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self._fallback = MockAgent()

    def plan(self, prompt: str) -> AgentPlan:
        try:
            import httpx

            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self.TOOLS_HINT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                    # Force a JSON body. Ollama and the OpenAI API both honour
                    # this; a provider that ignores it still works because the
                    # parser below also recovers JSON from fenced or prose-wrapped
                    # replies.
                    "response_format": {"type": "json_object"},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            parsed = _extract_json(content)
            calls = [
                ToolInvocation(tool_name=c["tool_name"], arguments=c.get("arguments", {}))
                for c in parsed.get("tool_calls", [])
                if isinstance(c, dict) and c.get("tool_name")
            ]
            answer = str(parsed.get("answer") or "").strip()
            if not calls and not answer:
                raise ValueError("model proposed no tool calls and no answer")
            return AgentPlan(
                tool_calls=calls,
                reasoning=str(parsed.get("reasoning", "")),
                matched_rules=["llm"] if calls else ["llm_direct_answer"],
                source=f"llm:{self.model}",
                answer="" if calls else answer,
            )
        except Exception as exc:  # noqa: BLE001 - degrade to the mock, never crash
            plan = self._fallback.plan(prompt)
            plan.reasoning += f" (LLM planner unavailable: {type(exc).__name__})"
            plan.source = "mock-fallback"
            return plan

    def compose(self, prompt: str, outcomes: list[dict[str, Any]]) -> str:
        """Write the reply to the user from what ASL actually allowed.

        Runs after authorization, so the model only ever sees the outputs of
        calls that ran, plus the verdict and reason for those that did not. On
        any failure it returns "" and the UI falls back to its template reply.
        """
        try:
            import httpx

            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            body = json.dumps(outcomes, indent=1, default=str)[:6000]
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self.COMPOSE_HINT},
                        {"role": "user", "content": f"User request: {prompt}\n\nTool calls and outcomes:\n{body}"},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 350,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            return str(response.json()["choices"][0]["message"]["content"] or "").strip()
        except Exception:  # noqa: BLE001 - a missing reply must never break authorization
            return ""

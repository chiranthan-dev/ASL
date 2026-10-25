# ASL — Adaptive Security Layer

**Adaptive runtime authorization for safe tool invocation in agentic AI systems.**

ASL is middleware that sits between an LLM agent and its tools. Every tool call the
agent proposes is intercepted and authorized **before** it runs — keyed not on the
tool's *name* but on a deterministic fingerprint of what the call actually *does*.

```
User  →  LLM agent  →  proposed tool call  →  ASL  →  tool  →  audit + learning
                                               │
                                     allow · log · challenge · sandbox · block
```

<p align="center">
  <img src="docs/images/demo.gif" alt="ASL walkthrough: a request becomes tool calls, each one authorized before it runs" width="760">
</p>

---

## Why the tool name is the wrong key

Most agent stacks decide per tool: a tool is on an allow-list or a deny-list, or the
user is asked once and trusted afterwards. Two facts break that:

- **The same tool is not the same risk.** `filesystem.delete("temp.txt")` and
  `filesystem.delete("/production/", recursive=True)` are one name, one permission —
  and two completely different events.
- **Different tools can be the same act.** `rm -rf` in a shell, `shutil.rmtree` in
  Python and an unregistered plug-in all destroy the same data. A name-keyed policy
  sees three unrelated things, and the tool's name is attacker-controlled anyway.

ASL keys its decision — and its memory of past decisions — on a **tool-name-free
canonical fingerprint** of the call's behaviour (capabilities, resource class, scope).
Familiar, low-risk behaviour becomes cheap to authorize; familiarity is *never* allowed
to relax a decision on outward or destructive behaviour.

---

## See it decide

Same tool (`filesystem`), one request read, the other destructive — two different verdicts,
each with the full 21-stage pipeline shown.

| Routine read → **ALLOW** | Production delete → **BLOCK** |
|---|---|
| ![allow](docs/images/02-allow.jpg) | ![block](docs/images/03-block.jpg) |

Every decision is backed by a library of behavioural fingerprints learned from past
sessions:

![library](docs/images/04-library.jpg)

---

## Run it

Python 3.11+ (developed on 3.12). From the repository root:

```bash
python -m venv .venv
```

```bash
.venv/Scripts/python -m pip install -r requirements.txt
```

Then start the server:

```bash
.venv/Scripts/python -m app.main
```

Open **http://127.0.0.1:8000/** for the ASL Gateway: a chat assistant with ASL's live
decisions and security console beside it (switch to **Chat** for the assistant alone).
**/inspector** is the detailed stage-by-stage dashboard and **/classic** the original
research chat. On macOS/Linux use `.venv/bin/python`.

Everything runs locally with no API key: the agent is a deterministic mock and every
tool (filesystem, database, shell, mail, web) is an inert mock — nothing is ever
executed, connected to or transmitted.

### Drive it with a real local model

The planner can be a live LLM instead of the mock. ASL talks to any
OpenAI-compatible endpoint; [Ollama](https://ollama.com) exposes one locally with no
key:

```bash
ollama pull qwen2.5:7b
```

```bash
.venv/Scripts/python -m app.main --live-model
```

Now the agent's tool calls come from a real model (`qwen2.5:7b` by default), and ASL
authorizes each one exactly as before. The model only ever *proposes* calls — the
security decision is made downstream, so a careless or manipulated model changes
nothing about what ASL will allow. If the model is unreachable, the planner falls back
to the deterministic mock automatically, so the pipeline can never be broken by a
missing model server.

Override the model or endpoint:

```bash
.venv/Scripts/python -m app.main --live-model --model llama3.1:8b --base-url http://127.0.0.1:11434/v1
```

or via environment variables: `ASL_MOCK_LLM=false`, `ASL_LLM_MODEL`, `ASL_LLM_BASE_URL`,
`ASL_LLM_API_KEY`.

### One-click demo on a Windows laptop

[`launch/`](launch) holds a launcher that starts Ollama (if installed), starts the ASL
server with the live model, and opens the browser. Anything already running is reused.
Create the two Desktop shortcuts once:

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File launch/install_shortcuts.ps1
```

* **ASL Demo**: runs everything locally on http://localhost:8000.
* **ASL Demo (public link)**: the same, plus a Cloudflare quick tunnel. The public
  `https://….trycloudflare.com` link is printed and copied to the clipboard; closing
  that window takes the link down.

`launch/stop_demo.ps1` stops the server and the quick tunnel (Ollama keeps running).

### Share a public link by hand (Cloudflare)

A quick tunnel needs no Cloudflare account. With the server running:

1. Install cloudflared once: `winget install --id Cloudflare.cloudflared`
2. Open a new PowerShell window and run (the leading `&` is required in PowerShell):

   ```powershell
   & "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8000
   ```

3. Wait for the box that prints `https://<random-words>.trycloudflare.com` and share that
   link. It can take up to a minute to start working.
4. Press **Ctrl+C** in that window to take the link down. Each run gives a new link.

Anyone with the link uses your laptop's model and demo database, so keep the window open
only while you are presenting. The tools stay mock tools for them too: nothing
destructive runs and mail only reaches the demo outbox.

### Tests and evaluation

```bash
.venv/Scripts/python -m pytest          # 284 tests, ~8 s
```

```bash
.venv/Scripts/python -m evaluation.run  # 200 scenarios, four systems, ~1 min
```

---

## Deploy

The repository is deploy-ready. The public demo runs the deterministic mock planner,
so no API key or model server is needed in the cloud.

**Render** (free tier, one click) — the repo includes [`render.yaml`](render.yaml). On
[render.com](https://render.com): **New → Blueprint**, connect this repository, and
Render provisions the service automatically. Health check: `/health`.

**Docker** (anywhere):

```bash
docker build -t asl .
```

```bash
docker run -p 8000:8000 asl
```

**Any Procfile host** (Railway, Fly, Heroku-likes) — start command:
`uvicorn app.main:app --host 0.0.0.0 --port $PORT`.

---

## How it works

Per intercepted call ASL runs a pipeline of 21 stages:

1. **Request Policy Gate** — reads the user's request for a prohibited *purpose*
   (prompt evidence may only ever add caution, never vouch for a call).
2. **Argument analysis** — shell is tokenised, SQL split into statements, Python parsed
   to an AST, paths/URLs/mail classified. Nothing is executed.
3. **Capabilities, resource class, scope** — what the call can do and what it touches.
4. **Behaviour graph → fingerprint** — a canonical `FPv1|CAPS[…]@RES[class:scope]|…`
   signature with **no tool name** in it.
5. **Fingerprint lookup** — graded similarity against the store, with accumulated risk
   history and confidence.
6. **Fast path** — if similarity, history, confidence and independent provenance checks
   all pass *and* the behaviour is not outward/destructive, skip 7 of the 21 stages.
7. Otherwise **11 analyzer signals** are fused (not averaged) into one risk score and
   mapped to a verdict: `ALLOW · ALLOW_WITH_LOG · CHALLENGE · SANDBOX · BLOCK`.

Three structural rules keep the fast path safe: outward/destructive behaviour is
excluded from it at any history, the store records the risk of the *act* (not its
circumstance), and a fast-pathed run carries history forward instead of re-learning it.

Design notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
[docs/NOVELTY.md](docs/NOVELTY.md) · panel demo: [docs/DEMO.md](docs/DEMO.md).

---

## Evaluation

200 scenarios across nine categories, seeded and reproducible. Full report and threats
to validity: [evaluation/results/REPORT.md](evaluation/results/REPORT.md).

| System | Precision | Recall | F1 | FPR | Over-block | Fast path |
|---|---|---|---|---|---|---|
| No layer | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — |
| Static rules (name + keyword) | 0.876 | 0.829 | 0.852 | 0.146 | 0.022 | 0.000 |
| ASL without fingerprints | 0.980 | 0.901 | 0.939 | 0.022 | 0.000 | 0.000 |
| **ASL** | 0.971 | 0.910 | **0.940** | 0.034 | 0.000 | 0.200 |

Beyond the in-distribution corpus, metamorphic experiments (`evaluation/mutation.py`,
`rewriting.py`, `poisoning.py`) test the actual claim — that authorization survives
**renaming** the tool and **rewriting** the arguments into an equivalent form:

- **Rename the tool, keep the arguments byte-identical:** a name-keyed policy's recall
  collapses from 0.836 to **0.282**; ASL stays between **0.927 and 0.973**.
- **Rewrite the arguments into an equivalent form:** after canonicalisation no verdict
  is weakened in three of four rewrite families and the fingerprint is identical in all
  four.
- **Warm the memory with 100 benign calls, then probe with a look-alike attack:** an
  approval cache keyed on the tool name admits **12 of 12**; ASL admits **0 of 12**.

---

## Project

Research prototype (~13,400 lines, 270 tests) for the Project-I course (BCSE497J),
School of Computer Science and Engineering (SCOPE), Vellore Institute of Technology.

- **Chiranthan H** · **Kevin Jacob** — design and implementation
- **Dr. K. Nivitha** — supervision

The accompanying paper is written up separately. This repository is the running system.

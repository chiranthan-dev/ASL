# ASL — technical disclosure and novelty analysis

**Adaptive Runtime Authorization for Safe Tool Invocation in Agentic AI Systems**

> **What this document is.** An engineering disclosure written to support a patent
> conversation and a conference paper: what the system does, which parts are plausibly
> novel, which parts are plainly not, and what the measurements do and do not show.
>
> **What it is not.** It is not legal advice, and it is not a patentability opinion.
> No prior-art search has been performed — no patent databases, no IEEE/ACM/USENIX
> search, no examination of what OpenAI, Anthropic, Microsoft or the LangChain
> ecosystem may already have filed in this area. Every novelty statement below is
> conditional on a search that has not yet happened, and agentic-AI security is a
> crowded and fast-moving field. Treat the claim language as a starting point for a
> qualified attorney, not as a draft filing.

---

## 1. Field and problem

An LLM agent proposes tool calls; something must decide whether each call may run.
Deployed practice is overwhelmingly **per-tool**: a tool is on an allow-list or a
deny-list, sometimes with a confirmation prompt attached.

Per-tool authorization cannot express two facts that matter:

1. **The same tool is not the same risk.** `filesystem.delete("temp.txt")` and
   `filesystem.delete("/production/database/", recursive=True)` are one tool name, one
   permission, one policy decision — and two completely different events.
2. **Different tools can be the same act.** `filesystem.delete("/production/db/")`,
   `shell.execute("rm -rf /production/db")` and `python.execute("shutil.rmtree(...)")`
   destroy the same data. A policy keyed on tool identity sees three unrelated things,
   and any trust or suspicion learned about one transfers to neither of the others.

A layer that solves (1) by inspecting arguments still faces a second problem: inspecting
every call in full, every time, is expensive, and the cost lands on the 99% of traffic
that is routine. Reducing that cost by remembering *tools* re-introduces (2).

---

## 2. The inventive concept (as currently understood)

A runtime authorization layer in which the unit of authorization memory is a
**deterministic, tool-identity-free canonical signature of observed behaviour**, and in
which that memory may reduce the *cost* of authorization while being structurally
incapable of reducing its *strictness*.

Concretely, per intercepted call the layer:

1. derives semantic **capabilities** from tool metadata *and* from static analysis of the
   actual arguments, and reports the difference as an escalation;
2. classifies what the call touches into a **resource class** and a **blast-radius scope**;
3. records the call in a per-session **behaviour graph** whose edges carry both ordering
   and data-flow relationships;
4. canonicalises that graph into a **fingerprint** containing capabilities, resource
   classes, scopes and capability transitions — **and no tool name**;
5. looks the fingerprint up in a persistent store of previously observed behaviours,
   obtaining graded similarity, accumulated risk history and confidence;
6. admits a **fast path** only when similarity, historical risk and confidence thresholds
   are met *and* independent validation of identity, prior use by this user, environment,
   policy version and anomaly state passes, *and* the behaviour does not fall into a class
   permanently excluded from the fast path;
7. otherwise fuses ~11 analyzer signals into a risk score under a fusion rule that is not
   an average, and maps it to allow / log / challenge / sandbox / block;
8. writes an audit record and folds the outcome back into the fingerprint's statistics.

---

## 3. Elements that may carry novelty

Each is stated with its enabling implementation and, where relevant, the evidence.

### 3.1 Tool-identity-free canonicalisation as the key of authorization memory

`FPv1|CAPS[DELETE]@RES[PRODUCTION_RESOURCE:RECURSIVE]||…||SCOPE:RECURSIVE`

The canonical form deliberately omits the tool name, so *what was done* is the key and
*what did it* is not. Consequence, demonstrated by `demos/compare_fingerprints.py`:
`filesystem.delete("/production/database/")` and an unregistered
`storage.remove_directory(...)` plugin produce **byte-identical fingerprints**, while
`shell.execute("rm -rf ...")` and `python.execute("shutil.rmtree(...)")` also produce a
pair identical to each other. Meanwhile the *same* tool with a smaller blast radius
(`delete("temp.txt")`) scores further away (0.65) than a *different* tool with the same
blast radius (0.73).

*Enablement:* `app/behavior/fingerprint.py` (canonicalisation, Weisfeiler-Lehman graph
hash, graded similarity).

### 3.2 Familiarity may reduce cost but is structurally barred from reducing strictness

Three mechanisms, all enforced in code rather than by policy text:

* **Class exclusion.** Behaviour is classified by *trust boundary* — read-only, internal
  effect, or outward/destructive — and the outward/destructive class has no risk ceiling
  at which the fast path opens. No amount of history admits it.
* **History records behaviour, not circumstance.** A fingerprint stores `behavioural_risk`
  (argument, intent and chain signals only), so a stranger's first visit cannot inflate an
  ordinary behaviour's permanent record, and circumstance cannot be laundered into it.
* **Fast-pathed runs carry history forward unchanged.** A run that skipped the analysis
  learns nothing new, so it re-records the existing value rather than a fresh lower one.
  Without this, repetition drives a behaviour's recorded risk toward zero — an actual
  defect found during development and now locked by
  `tests/test_engine.py::test_fast_path_does_not_launder_risk`.

*Enablement:* `app/trust/fast_path.py`, `app/trust/fingerprint_store.py`,
`app/core/risk_engine.py::behavioural_risk`.

### 3.3 Novelty amplifies severity rather than constituting it

Unfamiliarity is not treated as evidence of harm. The fingerprint signal is
`novelty × severity`, so a never-seen search and a never-seen production wipe are equally
novel and score differently. Measured consequence: the `novel_but_benign` category is
handled correctly **18/18** with zero false positives.

### 3.4 Separation of "action" signals from "circumstance" signals in fusion

Only `argument`, `intent` and `execution_chain` may set the dominance floor. Tool
sensitivity, capability weight, user trust, environment, novelty and anomaly can move the
weighted mean but cannot manufacture a high score on their own. This is what stops an
unfamiliar user doing something harmless from scoring like an attack — the failure mode
an early version of this system actually exhibited (a benign image search scoring 73/100).

### 3.5 Separating "is this action dangerous?" from "is this purpose permissible?"

Two orthogonal gates, with an explicit asymmetry governing the second: prompt evidence is
admissible only in the direction of caution. This lets the layer refuse a hostile request
whose tool call is harmless — measured at 10/10 on the `prohibited_purpose` category
versus 0/10 for tool-name rules — without reintroducing the prompt-injection weakness that
trusting a prompt normally creates.

Coupled to it: a refusal caused by *purpose* is charged to the requester's trust and
explicitly **not** to the behaviour's fingerprint, since the behaviour (a web search) is
shared with entirely legitimate requests.

*Enablement:* `app/analyzers/request_policy.py`, `app/core/risk_engine.py::BEHAVIOURAL_SIGNALS`.

### 3.6 Analyzer disagreement as an independent trigger for human verification

Confirmation is not a risk band. It fires when signals that *should* agree do not, when
confidence is low, or when an action is irreversible and high-impact — so a confidently
wrong pipeline still escalates.

---

## 4. What is explicitly **not** claimed

Stating this plainly is what makes the rest credible:

| Not novel | Why it is here anyway |
|---|---|
| Static analysis of code, shell, SQL, URLs and paths | Decades-old; standard technique used as an input |
| Weisfeiler-Lehman graph hashing | A known graph-isomorphism hash, used from NetworkX |
| Risk scoring / weighted signal fusion | Long-standing in IDS and fraud detection |
| RBAC, capability-based security, allow-lists | Prior art; ASL is compared *against* this |
| Behavioural/statistical anomaly detection | Long-standing in UEBA and intrusion detection |
| Audit logging, human-in-the-loop confirmation | Standard practice |
| Sandboxing as a decision outcome | Standard practice |
| The particular weight values in `config.py` | Explicitly a tunable baseline, not a contribution |

The claim is not "static analysis of tool arguments", which is obvious once stated. It is
the specific combination in §2 — in particular the tool-identity-free canonical signature
as the memory key, together with the structural bars on that memory ever loosening a
decision.

---

## 5. Suggested claim structure (for an attorney to rewrite)

**Independent claim, method:** A computer-implemented method of authorizing tool
invocations proposed by a language-model agent, comprising: intercepting a proposed
invocation; determining a capability set from both declared tool metadata and static
analysis of the invocation arguments; classifying a target resource class and a scope of
effect from those arguments; adding a node representing the invocation to a session graph
having ordering edges and data-flow edges; generating a canonical representation of at
least part of that graph, wherein the canonical representation comprises the capability
set, resource class, scope and capability transitions and **excludes any identifier of the
tool**; retrieving, from a persistent store keyed by such canonical representations, a
similarity measure and accumulated outcome statistics; and, responsive to the similarity,
the accumulated statistics and an independent validation of caller identity, environment,
policy version and anomaly state all satisfying respective criteria **and** the behaviour
not belonging to an excluded class, authorizing the invocation while omitting a subset of
analysis stages; otherwise performing the omitted stages and fusing their outputs into a
risk score that determines the authorization decision.

**Dependent claims** (sketch): storing behaviour-attributable risk separately from
circumstance-modulated risk · re-recording unchanged history when the reduced-analysis
path is taken · excluding classes by trust boundary rather than reversibility · scaling
the novelty contribution by action severity · restricting which signals may set a
dominance floor · triggering human verification on analyzer disagreement independently of
score · maintaining per-user and per-environment provenance of prior observations ·
inferring an argument analyzer from argument shape for tools absent from the registry.

---

## 6. Evidence as measured

From `evaluation/results/REPORT.md`, 200 scenarios, 8 categories, seeded and reproducible
via `python -m evaluation.run`:

| system | precision | recall | F1 | FPR | over-block | fast path |
|---|---|---|---|---|---|---|
| agent without ASL | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — |
| static tool-name rules | 0.876 | 0.829 | 0.852 | 0.146 | 0.022 | — |
| ASL without fingerprints | 0.980 | 0.901 | 0.939 | 0.022 | 0.000 | 0.000 |
| **full ASL** | 0.971 | 0.910 | **0.940** | 0.034 | 0.000 | 0.120 |

**The result that matters for honesty:** the fingerprinting ablation moves F1 by
**+0.001** — statistically nothing. On this corpus, behavioural fingerprinting does **not**
improve detection. What it buys is a **16% fast-path share** at equal accuracy, and it does
so without loosening any decision.

That is a narrower claim than "fingerprinting makes agents safer", and it is the claim the
data supports. The detection advantage in the table belongs to *argument-level analysis*
(FPR 0.030 vs 0.152 for tool-name rules, at comparable recall), which is a weaker novelty
claim. A paper that led with fingerprinting-improves-detection would be overclaiming
against its own evaluation.

Also load-bearing: full ASL over-blocks benign work **0%** of the time versus 2% for the
static baseline, and handles the argument-manipulation category at 70–80% versus 60%.

---

## 7. Weaknesses a reviewer or examiner will find

1. **No prior-art search has been done.** This is the largest gap.
2. **The evaluation is synthetic and self-authored** — corpus and analyzers share an
   author, so it shows controlled comparison, not generalisation.
3. **The headline fingerprinting benefit is efficiency, not accuracy**, and the efficiency
   is measured in skipped stages, not wall-clock (analyzers here cost ~3 ms).
4. **The fast path's benefit scales with repetition**, which the corpus sets by
   construction (16 of 200 scenarios).
5. **`high_impact_legitimate` is the weakest category** (53%): ASL silently allows real
   admin work that arguably deserves confirmation. The static baseline does better there
   by being blunt.
6. **Canonicalisation granularity is a design choice, not a derived optimum.** A coarser
   form collapses distinct behaviours; a finer one never matches. No sensitivity analysis
   has been run over that choice.
7. **The request policy gate is a pattern matcher.** Paraphrase defeats it ("retrieve
   correspondence belonging to coworkers"). It raises the cost of a hostile request; it
   does not close the class, and no novelty should be claimed for the pattern list itself
   — only for the architectural separation and the caution-only asymmetry.
8. **Static analysis is defeatable.** Sufficient obfuscation degrades the argument
   analyzer; the design responds by lowering confidence and escalating rather than by
   claiming robustness, but a determined adversary is not solved here.

---

## 8. Suggested figures

1. The problem: one tool, two arguments, identical tool-level risk, 42 vs 100 argument risk.
2. Pipeline data flow (`docs/ARCHITECTURE.md` §3 Mermaid diagram).
3. Fingerprint canonicalisation: three different tools collapsing to one signature.
4. Similarity matrix from `demos/compare_fingerprints.py`.
5. Fast-path gate as a checklist, with the invariant guard failing a repeated attack.
6. Learning curve: fingerprint confidence 0.55 → 0.98 over five runs, with the fast path
   engaging at run five.
7. Evaluation table and the ablation delta.

---

## 9. Reproducing every number in this document

```bash
python -m pytest                    # 166 tests
python -m evaluation.run            # regenerates the evaluation table
python -m demos.compare_fingerprints  # regenerates the similarity matrix
python -m app.main                  # the chat demo and the inspector
```

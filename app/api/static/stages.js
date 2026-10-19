/* Shared stage rendering.
 *
 * Both surfaces — the inspector dashboard and the chat — show the same trace,
 * so the "what does this stage mean" logic lives here once. If the two ever
 * disagreed about what a stage said, the demo would be lying about the system.
 */

(function (global) {
  "use strict";

  const escapeHtml = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const sevChip = (s) => ({ CRITICAL: "crit", HIGH: "crit", MEDIUM: "warn", LOW: "info", INFO: "" }[s] || "");
  const statusChip = (s) => ({ ok: "ok", warning: "warn", critical: "crit", skipped: "" }[s] || "");
  const decChip = (d) =>
    ({ ALLOW: "ok", ALLOW_WITH_LOG: "ok", CHALLENGE: "warn", SANDBOX: "warn", BLOCK: "crit" }[d] || "");

  const DOMINANT = ["argument", "intent", "execution_chain"];

  function meter(label, value, max) {
    const pct = Math.max(2, Math.min(100, (value / max) * 100));
    const shown = max === 1 ? Number(value).toFixed(2) : Math.round(value);
    return `<div class="signalrow"><span class="sname">${label}</span>
      <span class="bar risk"><i style="width:${pct}%"></i></span><span class="sval">${shown}</span></div>`;
  }

  function signalTable(signals) {
    return (signals || []).slice().sort((a, b) => b.value * b.weight - a.value * a.weight).map((s) => `
      <div class="signalrow ${DOMINANT.includes(s.name) ? "dominant" : ""}" title="${escapeHtml(s.detail || "")}">
        <span class="sname">${s.name.replace(/_/g, " ")}${DOMINANT.includes(s.name) ? " ●" : ""}</span>
        <span class="bar risk"><i style="width:${Math.max(2, s.value)}%"></i></span>
        <span class="sval">${Math.round(s.value)} ×${s.weight}</span>
      </div>`).join("");
  }

  function gaugeSvg(risk) {
    const angle = -90 + (Math.min(100, Math.max(0, risk)) / 100) * 180;
    const color = risk >= 90 ? "var(--crit)" : risk >= 70 ? "#ff9b3c"
      : risk >= 50 ? "var(--warn)" : risk >= 20 ? "#9ad24a" : "var(--ok)";
    return `<svg viewBox="0 0 200 120" width="210" height="128" role="img" aria-label="risk ${Math.round(risk)}">
      <path d="M15 105 A85 85 0 0 1 185 105" fill="none" stroke="#16202c" stroke-width="16" stroke-linecap="round"/>
      <path d="M15 105 A85 85 0 0 1 185 105" fill="none" stroke="url(#gauge-grad)" stroke-width="16"
        stroke-linecap="round" stroke-dasharray="${(risk / 100) * 267} 400" opacity=".92"/>
      <defs><linearGradient id="gauge-grad" x1="0" x2="1"><stop offset="0" stop-color="#35d07f"/>
        <stop offset=".55" stop-color="#f6b93b"/><stop offset="1" stop-color="#ff5c6c"/></linearGradient></defs>
      <line x1="100" y1="105" x2="${100 + 66 * Math.cos((angle * Math.PI) / 180)}"
        y2="${105 + 66 * Math.sin((angle * Math.PI) / 180)}" stroke="${color}" stroke-width="3" stroke-linecap="round"/>
      <circle cx="100" cy="105" r="5" fill="${color}"/>
      <text x="100" y="72" text-anchor="middle" font-size="30" font-weight="700" fill="${color}"
        font-family="ui-monospace, monospace">${Math.round(risk)}</text>
    </svg>`;
  }

  /* ─────────────────────── per-stage renderers ─────────────────────── */
  const RENDERERS = {
    agent: (d) => `
      <div class="why">The agent is <b>not</b> a security component. It may propose something reckless —
        ASL assumes exactly that.</div>
      <div class="kv"><dt>planner</dt><dd>${d.source}</dd>
        <dt>matched rules</dt><dd>${(d.matched_rules || []).join(", ")}</dd></div>
      <p class="muted">${escapeHtml(d.reasoning || "")}</p>
      ${(d.tool_calls || []).map((c) => `
        <div class="code hl">${escapeHtml(c.tool_name)}(${escapeHtml(JSON.stringify(c.arguments, null, 1))})</div>`).join("")}`,

    request_policy: (d) => `
      <div class="why">Every other stage asks <i>is this action dangerous?</i> This one asks
        <i>is this purpose permissible?</i> — because a request to break into a server can
        produce a tool call as harmless as a web search.</div>
      <div class="chips"><span class="chip ${d.severity === "PROHIBITED" ? "crit"
        : d.severity === "RESTRICTED" ? "warn" : "ok"}">${d.severity}</span>
        ${d.category ? `<span class="chip crit">${d.category}</span>` : ""}
        ${d.mitigated ? `<span class="chip info">downgraded by framing</span>` : ""}</div>
      <p class="muted">${escapeHtml(d.explanation || "")}</p>
      ${(d.findings || []).length ? `<table class="mini"><tr><th>category</th><th>severity</th><th>matched</th></tr>
        ${d.findings.map((f) => `<tr><td class="mono">${f.category}</td>
          <td><span class="chip ${f.severity === "PROHIBITED" ? "crit" : "warn"}">${f.severity}</span></td>
          <td class="mono">${escapeHtml(f.matched)}</td></tr>`).join("")}</table>` : ""}
      <div class="why">Prompt evidence is admissible <b>only in the direction of caution</b>:
        it can raise risk or refuse, never lower risk or authorise. An injected prompt that
        causes a refusal is a nuisance; one that causes an approval would be a breach.</div>`,

    tool_analyzer: (d) => `
      <div class="why">What power does this tool have — before any argument is read?
        ${d.known_tool ? "" : "<b>This tool is not in the registry</b>, so its profile is inferred from its name and trusted less."}</div>
      <div class="kv">
        <dt>tool</dt><dd>${d.tool_name}</dd><dt>category</dt><dd>${d.category}</dd>
        <dt>sensitivity</dt><dd>${d.sensitivity}/100</dd><dt>static risk</dt><dd>${d.risk}</dd>
        <dt>confidence</dt><dd>${d.confidence}</dd><dt>reversible</dt><dd>${d.reversible}</dd>
      </div>
      <div class="chips">${(d.capabilities || []).map((c) => `<span class="chip info">${c}</span>`).join("")}</div>
      <p class="muted">${escapeHtml(d.explanation || "")}</p>`,

    argument_analyzer: (d) => `
      <div class="why">The same tool with different arguments is a different security event.
        This is where <code>delete("temp.txt")</code> and <code>delete("/production/")</code> stop being the same call.</div>
      <div class="code">${escapeHtml(JSON.stringify(d.arguments, null, 1))}</div>
      <div class="kv">
        <dt>analyzer</dt><dd>${d.analyzer} (static, never executed)</dd>
        <dt>argument risk</dt><dd>${d.risk}</dd>
        <dt>blast radius</dt><dd>${d.scope}</dd>
        <dt>parsed cleanly</dt><dd>${d.parse_ok}</dd>
      </div>
      ${(d.findings || []).length ? `<table class="mini"><tr><th>finding</th><th>sev</th><th>what it means</th></tr>
        ${d.findings.map((f) => `<tr><td class="mono">${f.code}</td>
          <td><span class="chip ${sevChip(f.severity)}">${f.severity}</span></td>
          <td>${escapeHtml(f.message)}${f.evidence ? `<br><span class="muted mono">${escapeHtml(String(f.evidence).slice(0, 70))}</span>` : ""}</td></tr>`).join("")}
        </table>` : `<p class="muted">no findings — nothing sensitive in these arguments</p>`}
      ${(d.resources || []).length ? `<h3>Resources touched</h3><div class="chips">
        ${d.resources.map((r) => `<span class="chip ${r.sensitive ? "crit" : ""}">${r.class}:${r.scope}</span>`).join("")}</div>` : ""}`,

    capability_extractor: (d) => `
      <div class="why">Low-level actions are mapped to a shared vocabulary, so tools become comparable.
        ${(d.escalations || []).length ? "<b>Escalation detected</b>: the arguments unlock powers the tool profile never declared." : ""}</div>
      <div class="chips">${(d.capabilities || []).map((c) =>
        `<span class="chip ${(d.escalations || []).includes(c) ? "crit" : "ok"}">${c}</span>`).join("")}</div>
      <div class="kv">
        <dt>from tool</dt><dd>${(d.from_tool || []).join(", ") || "—"}</dd>
        <dt>from arguments</dt><dd>${(d.from_arguments || []).join(", ") || "—"}</dd>
        <dt>escalations</dt><dd>${(d.escalations || []).join(", ") || "none"}</dd>
        <dt>capability weight</dt><dd>${d.weight}</dd>
      </div>
      <p class="muted">${escapeHtml(d.explanation || "")}</p>`,

    behavior_graph: (d) => `
      <div class="why">Each call becomes a node; edges record order and data flow.
        A chain like DOWNLOAD → EXECUTE only exists as an <i>edge</i>, which is why the graph is needed.</div>
      <div class="kv">
        <dt>nodes</dt><dd>${(d.nodes || []).length}</dd>
        <dt>edges</dt><dd>${(d.edges || []).length}</dd>
        <dt>sequence</dt><dd>${(d.capability_sequence || []).map((s) => s.join("+")).join("  →  ") || "—"}</dd>
      </div>
      ${graphSvg(d)}`,

    fingerprint: (d) => `
      <div class="why">The canonical form contains <b>no tool name</b>. That is what lets the same behaviour
        through a different tool match, and different behaviour through the same tool not match.</div>
      <div class="code hl">${escapeHtml(d.canonical_representation || "")}</div>
      <div class="kv">
        <dt>call fingerprint</dt><dd>${d.fingerprint_id}</dd>
        <dt>chain fingerprint</dt><dd>${d.chain_fingerprint_id}</dd>
        <dt>graph hash (WL)</dt><dd>${(d.graph_hash || "").slice(0, 24)}…</dd>
        <dt>max scope</dt><dd>${d.max_scope}</dd>
      </div>
      ${(d.transitions || []).length ? `<h3>Transitions</h3><div class="chips">
        ${d.transitions.map((t) => `<span class="chip warn">${t}</span>`).join("")}</div>` : ""}`,

    trust_lookup: (d) => `
      <div class="why">Have we seen this behaviour before? A match is <b>evidence, never permission</b> —
        it can lower cost, never bypass a check.</div>
      ${meter("similarity to nearest known behaviour", d.similarity ?? 0, 1)}
      ${meter("novelty", d.novelty ?? 1, 1)}
      <div class="kv">
        <dt>query</dt><dd>${d.query_fingerprint}</dd>
        <dt>matched</dt><dd>${d.matched_fingerprint || "— nothing comparable"}</dd>
        <dt>seen before</dt><dd>${d.occurrences}×</dd>
        <dt>historical risk</dt><dd>${(d.historical_risk ?? 0).toFixed(1)}</dd>
        <dt>fp confidence</dt><dd>${(d.confidence ?? 0).toFixed(2)}</dd>
        <dt>last outcome</dt><dd>${d.previous_outcome || "—"}</dd>
        <dt>store size</dt><dd>${d.known_fingerprints} fingerprints</dd>
        <dt>user</dt><dd>${escapeHtml(d.user || "")}</dd>
      </div>`,

    anomaly: (d) => `
      <div class="why">Statistical baseline per user: unusual combinations, unseen transitions, rate, timing, volume.
        The interface is pluggable — a learned detector drops in without touching the risk engine.</div>
      ${Object.entries(d.components || {}).map(([k, v]) => meter(k.replace(/_/g, " "), v, 100)).join("")}
      <div class="kv"><dt>anomalous</dt><dd>${d.anomalous}</dd>
        <dt>baseline size</dt><dd>${d.observations_for_user} observations</dd></div>
      <ul class="muted">${(d.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`,

    fast_path: (d) => `
      <div class="why">${d.eligible
        ? "All gates passed: expensive analysis is skipped, <b>security checks are not</b>."
        : "Any single failed check sends this to full analysis. Skipping analysis is a performance decision; skipping checks would be a security hole."}</div>
      <div class="chips"><span class="chip ${d.eligible ? "ok" : "warn"}">${d.path}</span></div>
      <div class="checks">${(d.checks || []).map((c) => `
        <div class="check ${c.passed ? "pass" : "fail"}">
          <span class="mark">${c.passed ? "✓" : "✕"}</span>
          <span><span class="cname">${c.name}</span><br><span class="cdetail">${escapeHtml(c.detail)}</span></span>
        </div>`).join("")}</div>`,

    intent: (d) => `
      <div class="why">Intent is inferred from evidence, not from what the prompt claims —
        under prompt injection the prompt is the thing that lies.</div>
      <div class="chips"><span class="chip ${d.risk >= 85 ? "crit" : d.risk >= 50 ? "warn" : "ok"}">${d.intent}</span></div>
      ${meter("intent risk", d.risk, 100)}
      <p class="muted">${escapeHtml(d.explanation || "")}</p>`,

    context: (d) => `
      <div class="why">Does the action match what was asked? A gap here is the earliest symptom of
        prompt injection or an agent going off-script.</div>
      ${meter("context risk", d.risk, 100)}
      <div class="kv">
        <dt>prompt implies</dt><dd>${(d.expected_capabilities || []).join(", ") || "—"}</dd>
        <dt>call requests</dt><dd>${(d.actual_capabilities || []).join(", ") || "—"}</dd>
        <dt>unexplained</dt><dd>${(d.unexplained_capabilities || []).join(", ") || "none"}</dd>
        <dt>session calls</dt><dd>${d.session_calls}</dd>
      </div>
      ${d.injection_markers ? `<div class="chips"><span class="chip crit">INJECTION PHRASING</span></div>` : ""}`,

    environment: (d) => `
      ${meter("environment risk", d.risk, 100)}
      <div class="kv">
        <dt>environment</dt><dd>${d.environment}</dd>
        <dt>destructive ×</dt><dd>${d.destructive_multiplier}</dd>
        <dt>device</dt><dd>${d.device || "unidentified"}</dd>
        <dt>policy</dt><dd>${d.policy_version}</dd>
      </div>`,

    user_trust: (d) => `
      <div class="why">Trust is earned slowly, lost quickly, and <b>bounded</b>: it can shade a decision,
        never carry one, and never crosses an invariant.</div>
      ${meter("trust score", d.trust_score ?? 0, 1)}
      <div class="kv">
        <dt>known user</dt><dd>${d.known}</dd><dt>allowed</dt><dd>${d.successful_actions ?? 0}</dd>
        <dt>stopped</dt><dd>${d.blocked_actions ?? 0}</dd><dt>anomalies</dt><dd>${d.anomalies ?? 0}</dd>
      </div>`,

    execution_chain: (d) => `
      <div class="why">READ → DOWNLOAD → EXECUTE → DELETE must outrank READ → PROCESS → WRITE.
        Every step can be innocent while the ordering is not.</div>
      ${meter("chain risk", d.risk, 100)}
      <div class="kv">
        <dt>sequence</dt><dd>${(d.capability_sequence || []).map((s) => s.join("+")).join(" → ")}</dd>
        <dt>patterns</dt><dd>${(d.matched_patterns || []).join(", ") || "none"}</dd>
        <dt>data-flow edges</dt><dd>${(d.data_flow_edges || []).join(", ") || "none"}</dd>
      </div>`,

    llm_confidence: (d) => `
      <div class="why">How well did we understand this call? Low understanding is not safety —
        it raises risk and pushes toward human verification.</div>
      ${meter("confidence", d.confidence, 1)}
      ${meter("risk from uncertainty", d.risk, 100)}
      <div class="kv">${Object.entries(d.factors || {}).map(([k, v]) =>
        `<dt>${k.replace(/_/g, " ")}</dt><dd>${v}</dd>`).join("")}</div>
      <p class="muted">${escapeHtml(d.explanation || "")} <span class="chip">${d.source}</span></p>`,

    risk_engine: (d) => `
      <div class="why">Not an average. A confidence-weighted mean, then a dominance floor from the
        <i>action</i> signals, then invariant floors that trust cannot lower.</div>
      <div class="kv">
        <dt>strategy</dt><dd>${d.strategy}</dd><dt>fused risk</dt><dd>${d.risk_score}</dd>
        <dt>confidence</dt><dd>${d.confidence}</dd><dt>disagreement</dt><dd>${d.disagreement}</dd>
        <dt>invariants</dt><dd>${(d.invariants || []).join(", ") || "none fired"}</dd>
      </div>
      ${signalTable(d.signals || [])}`,

    decision: (d) => `
      <div class="chips"><span class="chip ${decChip(d.decision)}">${d.decision}</span>
        <span class="chip">${d.path}</span></div>
      ${meter("final risk", d.risk_score, 100)}
      <h3>Bands</h3>
      <div class="kv">${Object.entries(d.bands || {}).map(([k, v]) =>
        `<dt${k === d.decision ? ' style="color:var(--accent)"' : ""}>${k}</dt><dd>${v}</dd>`).join("")}</div>
      ${d.human_verification ? `<div class="why"><b>Human verification required</b> — an independent trigger, not a band:
        <ul>${(d.human_verification_reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul></div>` : ""}
      <div class="code">${escapeHtml(d.explanation || "")}</div>`,

    execute: (d) => `
      <div class="why">Only mocks ever run. No shell is spawned, no code executed, no file touched.</div>
      <div class="code">${escapeHtml(JSON.stringify(d, null, 1))}</div>`,

    audit: (d) => `
      <div class="why">The decision is written to the audit log and folded back into the fingerprint's
        statistics and the user's trust — this is what makes the next identical run cheaper.</div>
      <div class="kv">
        <dt>audit id</dt><dd>${d.audit_id}</dd>
        <dt>fingerprint</dt><dd>${d.fingerprint_id}</dd>
        <dt>now seen</dt><dd>${d.occurrence_count}×</dd>
        <dt>fp confidence</dt><dd>${(d.fingerprint_confidence ?? 0).toFixed(3)}</dd>
        <dt>historical risk</dt><dd>${(d.historical_risk ?? 0).toFixed(1)}</dd>
        <dt>allowed / stopped</dt><dd>${d.successful_executions} / ${d.blocked_executions}</dd>
        <dt>user trust</dt><dd>${(d.user_trust ?? 0).toFixed(3)}</dd>
      </div>
      ${meter("fingerprint confidence (fast path needs ≥ 0.95)", d.fingerprint_confidence ?? 0, 1)}`,

    session: (d) => `
      <div class="kv">
        <dt>decisions</dt><dd>${(d.decisions || []).join(", ")}</dd>
        <dt>risks</dt><dd>${(d.risks || []).join(", ")}</dd>
        <dt>fast-path calls</dt><dd>${d.fast_path_calls}</dd>
        <dt>total latency</dt><dd>${d.latency_ms} ms</dd>
      </div>`,
  };

  function renderGeneric(d, ev) {
    if (ev.status === "skipped") {
      return `<div class="why">Skipped because the fast path was taken — this is the saving the fast path buys.
        The identity, environment, policy and anomaly checks still ran.</div>`;
    }
    return `<div class="code">${escapeHtml(JSON.stringify(d, null, 1))}</div>`;
  }

  function renderDetail(ev) {
    const body = (RENDERERS[ev.stage] || renderGeneric)(ev.detail || {}, ev);
    return `
      <div class="fadein">
        <div class="dhead">
          <h4>${ev.title}</h4>
          <span class="chip ${statusChip(ev.status)}">${ev.status}</span>
        </div>
        <div class="dsum">${escapeHtml(ev.summary || "")}</div>
        ${body}
        <div class="kv"><dt>stage time</dt><dd>${(ev.duration_ms || 0).toFixed(2)} ms</dd></div>
      </div>`;
  }

  /* ───────────────────────── behavior graph ───────────────────────── */
  function graphSvg(detail) {
    const nodes = (detail.nodes || []).filter((n) => n.kind !== "CAPABILITY");
    const edges = (detail.edges || []).filter((e) =>
      nodes.some((n) => n.id === e.source) && nodes.some((n) => n.id === e.target));
    if (!nodes.length) return `<p class="muted">no graph yet</p>`;

    const invocations = nodes.filter((n) => n.kind === "INVOCATION");
    const resources = nodes.filter((n) => n.kind === "RESOURCE");
    const colW = 200, rowH = 74;
    const width = Math.max(520, 90 + colW * Math.max(invocations.length, 1));
    const height = 90 + rowH * 2;
    const pos = {};
    invocations.forEach((n, i) => { pos[n.id] = { x: 90 + i * colW, y: 46 }; });
    resources.forEach((n, i) => { pos[n.id] = { x: 90 + i * (colW * 0.9), y: 46 + rowH * 1.6 }; });

    const edgeSvg = edges.map((e) => {
      const a = pos[e.source], b = pos[e.target];
      if (!a || !b) return "";
      const d = (a.y === b.y)
        ? `M${a.x + 60} ${a.y} C${a.x + 108} ${a.y}, ${b.x - 108} ${b.y}, ${b.x - 60} ${b.y}`
        : `M${a.x} ${a.y + 20} C${a.x} ${a.y + 50}, ${b.x} ${b.y - 40}, ${b.x} ${b.y - 16}`;
      return `<path class="gedge ${e.type}" d="${d}" marker-end="url(#arrowhead)"><title>${e.type}</title></path>`;
    }).join("");

    const nodeSvg = nodes.map((n) => {
      const p = pos[n.id]; if (!p) return "";
      const label = n.kind === "INVOCATION" ? (n.tool || n.label) : (n.resource_class || n.label);
      const caps = n.kind === "INVOCATION" ? n.label : "";
      // Light palette: tinted fills with dark text, matching the verdict colours
      // used elsewhere. The previous values were dark-theme leftovers, which put
      // near-black ink on near-black rectangles.
      const fill = n.kind === "INVOCATION"
        ? (n.risk >= 80 ? "#fbeceb" : n.risk >= 45 ? "#fbf1e0" : "#e9f0fb") : "#f2f4f7";
      const stroke = n.kind === "INVOCATION"
        ? (n.risk >= 80 ? "#b3261e" : n.risk >= 45 ? "#9a6207" : "#1a56b8") : "#cfd2d7";
      return `<g class="gnode">
        <rect x="${p.x - 60}" y="${p.y - 20}" width="120" height="40" rx="9" fill="${fill}" stroke="${stroke}"/>
        <text x="${p.x}" y="${p.y - 3}" text-anchor="middle">${escapeHtml(String(label).slice(0, 16))}</text>
        <text x="${p.x}" y="${p.y + 11}" text-anchor="middle" fill="#767d85" font-size="8.5">${escapeHtml(caps.slice(0, 24))}</text>
      </g>`;
    }).join("");

    return `<div class="graph"><svg viewBox="0 0 ${width} ${height}" height="${height}">
      <defs><marker id="arrowhead" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M0 0 L10 5 L0 10 z" fill="#8b939c"/></marker></defs>
      ${edgeSvg}${nodeSvg}
      <text x="12" y="${height - 8}" fill="#767d85" font-size="10">
        solid = order · dashed amber = data flow · dotted = resource</text>
    </svg></div>`;
  }

  global.ASLStages = {
    RENDERERS, renderDetail, renderGeneric, graphSvg,
    meter, signalTable, gaugeSvg, escapeHtml, sevChip, statusChip, decChip, DOMINANT,
  };
})(window);

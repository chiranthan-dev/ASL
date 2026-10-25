/* ASL Gateway — chat with ASL's live decisions and console beside it.
 *
 * Every number on this page comes from the server: /api/gateway/chat for a
 * message, /api/gateway/approvals for held calls, /health,
 * /api/gateway/activity and /api/user for the console. The page animates what the engine decided; it never decides.
 */
(function () {
  "use strict";

  const S = window.ASLStages;
  const esc = S.escapeHtml;
  const $ = (id) => document.getElementById(id);

  const SUGGESTIONS = [
    "Summarise my notes in /home/user/atlas/notes.md",
    "What is 245 * 18?",
    "Explain what an API is in two sentences",
    "Email the project notes to alice@university.edu",
    "Delete the file temp.txt",
  ];

  // verdict -> presentation; the lane is where the gate sorts the call
  const VERDICT = {
    ALLOW:          { lane: "allow", cls: "v-allow",   label: "Allowed",          tag: "allowed",            color: "var(--gw-allow)" },
    ALLOW_WITH_LOG: { lane: "allow", cls: "v-log",     label: "Allowed · logged", tag: "allowed and logged", color: "var(--gw-log)" },
    CHALLENGE:      { lane: "hold",  cls: "v-hold",    label: "Needs you",        tag: "held for you",       color: "var(--gw-hold)" },
    SANDBOX:        { lane: "block", cls: "v-sandbox", label: "Sandboxed",        tag: "sandboxed",          color: "var(--gw-sandbox)" },
    BLOCK:          { lane: "block", cls: "v-block",   label: "Blocked",          tag: "blocked",            color: "var(--gw-block)" },
  };
  const verdict = (d) => VERDICT[d] || VERDICT.ALLOW;
  const CARDS_HINT = "Every message appears here as ASL checks it. Click a card to see every stage.";

  const state = {
    session: newSession(),
    busy: false,
    results: {},
    counts: { checked: 0, blocked: 0, calls: 0, fast: 0 },
    lanes: { allow: 0, hold: 0, block: 0 },
  };

  function newSession() {
    return "gw_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  }

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (_) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* storage unavailable */ } },
  };

  /* ───────────────────────────── view switch ── */

  function setMode(mode) {
    $("gwMain").classList.toggle("mode-chat", mode === "chat");
    document.querySelectorAll(".gw-switch button").forEach((b) =>
      b.classList.toggle("on", b.dataset.mode === mode));
    store.set("gw-mode", mode);
  }
  document.querySelectorAll(".gw-switch button").forEach((b) =>
    b.addEventListener("click", () => setMode(b.dataset.mode)));
  setMode(store.get("gw-mode") || "asl");
  const aslVisible = () => !$("gwMain").classList.contains("mode-chat");

  /* ───────────────────────────── input ── */

  $("gwSuggest").innerHTML = SUGGESTIONS.map((s) => `<button type="button">${esc(s)}</button>`).join("");
  $("gwSuggest").querySelectorAll("button").forEach((b, i) =>
    b.addEventListener("click", () => send(SUGGESTIONS[i])));

  const text = $("gwText");
  const autoGrow = () => { text.style.height = "auto"; text.style.height = Math.min(text.scrollHeight, 160) + "px"; };
  text.addEventListener("input", autoGrow);
  text.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("gwForm").requestSubmit(); }
  });
  $("gwForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const value = text.value.trim();
    if (!value || state.busy) return;
    text.value = "";
    autoGrow();
    send(value);
  });

  $("gwNew").addEventListener("click", () => {
    if (state.busy) return;
    state.session = newSession();
    state.results = {};
    state.counts = { checked: 0, blocked: 0, calls: 0, fast: 0 };
    state.lanes = { allow: 0, hold: 0, block: 0 };
    $("gwThread").querySelectorAll(".gw-msg").forEach((m) => m.remove());
    $("gwEmpty").hidden = false;
    $("gwCards").innerHTML = `<p class="gw-hint">${CARDS_HINT}</p>`;
    $("laneAllow").textContent = "0";
    $("laneHold").textContent = "0";
    $("laneBlock").textContent = "0";
    renderStats();
  });

  /* ───────────────────────────── chat ── */

  function scrollThread() {
    const t = $("gwThread");
    requestAnimationFrame(() => t.scrollTo({ top: t.scrollHeight, behavior: "smooth" }));
    setTimeout(() => { t.scrollTop = t.scrollHeight; }, 450);
  }

  function addMessage(role, html) {
    $("gwEmpty").hidden = true;
    const d = document.createElement("div");
    d.className = `gw-msg ${role}`;
    d.innerHTML = `<div class="gw-bubble">${html}</div>`;
    $("gwThread").appendChild(d);
    scrollThread();
    return d;
  }

  async function send(message) {
    if (state.busy) return;
    state.busy = true;
    $("gwSend").disabled = true;
    addMessage("user", esc(message));
    const pending = addMessage("bot",
      `<span class="gw-typing"><i></i><i></i><i></i></span>
       <span class="gw-typing-label">thinking, and ASL is checking each step…</span>`);
    $("gwShield").classList.add("busy");

    let result;
    try {
      const r = await fetch("/api/gateway/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message,
          session_id: state.session,
          user_id: $("gwUser").value.trim() || "demo_user",
          environment: $("gwEnv").value,
        }),
      });
      if (!r.ok) throw new Error(`server said ${r.status}`);
      result = await r.json();
    } catch (err) {
      pending.querySelector(".gw-bubble").innerHTML =
        `<p>I couldn't reach the server (${esc(err.message)}). Is it still running?</p>`;
      finish();
      return;
    }

    const rid = "r" + Object.keys(state.results).length;
    state.results[rid] = result;
    pending.querySelector(".gw-bubble").innerHTML = replyHtml(result, rid);
    wireReply(pending, rid);
    scrollThread();
    showDecisions(result, rid);
    finish();
    refreshConsole();
  }

  function finish() {
    state.busy = false;
    $("gwSend").disabled = false;
    $("gwShield").classList.remove("busy");
    text.focus();
  }

  /* ───────────────────────────── reply ── */

  // A small, safe markdown subset for model replies: everything is escaped
  // first, then **bold**, `code`, bullet and numbered lists, and paragraphs.
  function inline(s) {
    return s.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  }
  function paragraphs(t) {
    const out = [];
    let list = null;
    const close = () => { if (list) { out.push(`</${list}>`); list = null; } };
    esc(t).split(/\n/).forEach((raw) => {
      const line = raw.trim();
      const ul = line.match(/^[-*•]\s+(.*)$/);
      const ol = line.match(/^\d+[.)]\s+(.*)$/);
      if (ul || ol) {
        const kind = ul ? "ul" : "ol";
        if (list !== kind) { close(); out.push(`<${kind}>`); list = kind; }
        out.push(`<li>${inline((ul || ol)[1])}</li>`);
      } else if (!line) {
        close();
      } else {
        close();
        out.push(`<p>${inline(line)}</p>`);
      }
    });
    close();
    return out.join("");
  }

  // Plain-English reason for one call, as the original chat phrased them.
  const DECISION_TEXT = {
    ALLOW: "Routine behaviour ASL already recognises.",
    ALLOW_WITH_LOG: "Permitted, and recorded because it touched something worth logging.",
    CHALLENGE: "Not dangerous enough to refuse, not routine enough to pass unattended.",
    SANDBOX: "Uncertain enough to run in isolation rather than for real.",
    BLOCK: "The combined risk crossed the refusal threshold.",
  };
  const INVARIANT_TEXT = {
    DESTRUCTIVE_PRODUCTION: "This would destroy data in production.",
    CREDENTIAL_ACCESS: "This reaches for credentials.",
    PRIVILEGE_ESCALATION: "This escalates privilege.",
    REMOTE_CODE_EXECUTION: "This would run code fetched from elsewhere.",
    EXFILTRATION_CHAIN: "Data read earlier would be sent outward.",
    PROHIBITED_PURPOSE: "The purpose of the request is not permissible.",
  };
  function callReason(call) {
    const inv = (call.risk_assessment && call.risk_assessment.invariants) || [];
    if (inv.length) return INVARIANT_TEXT[inv[0]] || inv[0].replace(/_/g, " ").toLowerCase();
    const finding = (call.findings || [])[0];
    if (finding) {
      const i = finding.indexOf(": ");
      const text = i > 0 ? finding.slice(i + 2) : finding;
      return text.charAt(0).toUpperCase() + text.slice(1) + (/[.!?]$/.test(text) ? "" : ".");
    }
    return DECISION_TEXT[call.decision] || "Checked by ASL.";
  }

  function purposeRefused(result) {
    const p = (result.trace || []).find((e) => e.stage === "request_policy");
    return Boolean(p && p.detail && p.detail.severity === "PROHIBITED");
  }

  // Used only when no live model wrote the reply (mock planner).
  function templateReply(result) {
    const calls = result.calls || [];
    if (purposeRefused(result)) return "I can't help with that one. ASL declined the request itself.";
    if (!calls.length) return "That one didn't need any tools.";
    const names = [...new Set(calls.map((c) => c.tool_name))].join(", ");
    switch (result.decision) {
      case "ALLOW":
      case "ALLOW_WITH_LOG": return `Done. I ran ${names}.`;
      case "CHALLENGE": return `I've prepared ${names}, but it needs your confirmation before it runs.`;
      case "SANDBOX": return `I kept ${names} in a sandbox, so it didn't run for real.`;
      case "BLOCK": return `I stopped ${names} before it ran.`;
      default: return result.explanation || "Done.";
    }
  }

  function tagHtml(result, rid) {
    const calls = result.calls || [];
    let label, color;
    if (!calls.length && purposeRefused(result)) {
      label = "declined by ASL"; color = verdict("BLOCK").color;
    } else if (!calls.length) {
      label = "no tool needed"; color = "var(--gw-soft)";
    } else {
      const v = verdict(result.decision);
      label = `${v.tag} · ${calls.length} call${calls.length > 1 ? "s" : ""} · risk ${Math.round(result.risk_score)}`;
      color = v.color;
    }
    return `<button type="button" class="gw-tag" data-rid="${rid}" style="--c:${color}">
      <i></i>ASL · ${esc(label)} · open checks ▸</button>`;
  }

  function approvalHtml(a) {
    return `<div class="gw-approve pending" data-approval="${esc(a.approval_id)}">
      <div class="what">Waiting for you: <code>${esc(a.tool_name)}</code> · risk ${esc(a.risk_score)}</div>
      <div class="gw-btns">
        <button type="button" class="gw-btn ok" data-act="yes">Confirm</button>
        <button type="button" class="gw-btn no" data-act="no">Deny</button>
      </div>
      <div class="gw-resolved"></div>
    </div>`;
  }

  function replyHtml(result, rid) {
    const body = result.answer ? paragraphs(result.answer) : `<p>${esc(templateReply(result))}</p>`;
    const approvals = (result.approvals || []).map(approvalHtml).join("");
    return body + approvals + tagHtml(result, rid);
  }

  function wireReply(node, rid) {
    node.querySelectorAll(".gw-tag").forEach((t) =>
      t.addEventListener("click", () => openChecks(t.dataset.rid)));
    node.querySelectorAll(".gw-approve").forEach((box) =>
      box.querySelectorAll(".gw-btn").forEach((b) =>
        b.addEventListener("click", () => resolve(box.dataset.approval, b.dataset.act === "yes"))));
  }

  /* ───────────────────────────── approvals ── */

  async function resolve(id, approve) {
    document.querySelectorAll(`[data-approval="${id}"] .gw-btn`).forEach((b) => { b.disabled = true; });
    let item;
    try {
      const r = await fetch(`/api/gateway/approvals/${encodeURIComponent(id)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approve }),
      });
      if (!r.ok) throw new Error(`server said ${r.status}`);
      item = await r.json();
    } catch (err) {
      document.querySelectorAll(`[data-approval="${id}"] .gw-btn`).forEach((b) => { b.disabled = false; });
      return;
    }
    const word = approve ? "Confirmed" : "Denied";
    const color = approve ? "var(--gw-allow)" : "var(--gw-soft)";
    document.querySelectorAll(`.gw-approve[data-approval="${id}"]`).forEach((box) => {
      box.classList.remove("pending");
      box.classList.add("done");
      box.querySelector(".gw-resolved").innerHTML = `<span style="color:${color}">${word} by you</span>`;
    });
    const card = document.querySelector(`.gw-card[data-call="${item.call_id}"]`);
    if (card) {
      card.classList.remove("waiting");
      const st = card.querySelector(".state");
      if (st) { st.textContent = approve ? "ran after you confirmed" : "you denied it"; st.style.color = color; }
    }
    if (item.answer) addMessage("bot", paragraphs(item.answer));
    refreshConsole();
  }

  /* ───────────────────────────── decisions panel ── */

  function shortReason(text) {
    const t = String(text || "").replace(/\s+/g, " ").trim();
    const first = t.split(/(?<=[.;])\s/)[0] || t;
    return first.length > 140 ? first.slice(0, 137) + "…" : first;
  }

  function stageBar(result, callId) {
    return (result.trace || []).filter((e) => e.call_id === callId).map((e) => {
      const cls = e.status === "critical" ? "crit" : e.status === "warning" ? "warn" : e.status === "skipped" ? "" : "on";
      return `<span class="${cls}"></span>`;
    }).join("");
  }

  function cardHtml(result, call, rid) {
    const v = verdict(call.decision);
    const held = (result.approvals || []).some((a) => a.call_id === call.call_id);
    const state = call.decision === "CHALLENGE" ? (held ? "waiting for you" : "held")
      : call.decision === "BLOCK" || call.decision === "SANDBOX" ? "did not run" : "ran";
    return `<article class="gw-card ${v.cls}${held ? " waiting" : ""}" data-rid="${rid}" data-call="${esc(call.call_id)}">
      <header><code>${esc(call.tool_name)}</code><span class="gw-verdict">${v.label} · ${Math.round(call.risk_score)}</span></header>
      <p>${esc(callReason(call))}</p>
      <div class="gw-stages">${stageBar(result, call.call_id)}</div>
      <footer><span class="state">${state}</span>${call.fast_path ? `<span class="fast">⚡ fast path</span>` : `<span>open checks ▸</span>`}</footer>
    </article>`;
  }

  function policyReason(result) {
    const p = (result.trace || []).find((e) => e.stage === "request_policy");
    const t = String((p && p.summary) || "").replace(/^[A-Z_]+:\s*/, "").replace(/\s*\(matched[^)]*\)\s*$/, "").trim();
    if (!t) return "The purpose of the request is not permissible.";
    return t.charAt(0).toUpperCase() + t.slice(1) + (/[.!?]$/.test(t) ? "" : ".");
  }

  // A message that reached no tool still went through the request gate:
  // either the model answered on its own, or ASL refused the request outright.
  function requestCardHtml(result, rid) {
    const refused = purposeRefused(result);
    const bar = (result.trace || []).filter((e) => !e.call_id && e.stage !== "session").map((e) => {
      const cls = e.status === "critical" ? "crit" : e.status === "warning" ? "warn" : "on";
      return `<span class="${cls}"></span>`;
    }).join("");
    const quote = esc(String(result.prompt || "").slice(0, 60));
    return refused
      ? `<article class="gw-card v-block" data-rid="${rid}">
          <header><code>request refused</code><span class="gw-verdict">Blocked · ${Math.round(result.risk_score)}</span></header>
          <p>${esc(policyReason(result))} ASL refused it before any tool was called.</p>
          <div class="gw-stages">${bar}</div>
          <footer><span class="state">nothing ran</span><span>open checks ▸</span></footer>
        </article>`
      : `<article class="gw-card v-none" data-rid="${rid}">
          <header><code>no tool needed</code><span class="gw-verdict">Answered</span></header>
          <p>“${quote}” was answered from the model's own knowledge, so there was no action to authorise. The request gate still checked it.</p>
          <div class="gw-stages">${bar}</div>
          <footer><span class="state">nothing to run</span><span>open checks ▸</span></footer>
        </article>`;
  }

  function addCard(html, rid, callId) {
    const wrap = document.createElement("div");
    wrap.innerHTML = html;
    const card = wrap.firstElementChild;
    card.addEventListener("click", () => openChecks(rid, callId));
    $("gwCards").prepend(card);
  }

  function hitLane(lane) {
    state.lanes[lane] += 1;
    const laneEl = $(`lane${lane[0].toUpperCase()}${lane.slice(1)}`);
    laneEl.textContent = state.lanes[lane];
    const box = laneEl.parentElement;
    box.classList.add("hit");
    setTimeout(() => box.classList.remove("hit"), 350);
  }

  function showDecisions(result, rid) {
    const calls = result.calls || [];
    const hint = $("gwCards").querySelector(".gw-hint");
    if (hint) hint.remove();

    if (!calls.length) {
      const refused = purposeRefused(result);
      state.counts.checked += 1;
      if (refused) state.counts.blocked += 1;
      const land = () => {
        if (refused) hitLane("block");
        addCard(requestCardHtml(result, rid), rid);
        renderStats();
      };
      if (aslVisible()) flyToken(refused ? "block" : null, 0, land);
      else land();
      return;
    }

    calls.forEach((call, i) => {
      const v = verdict(call.decision);
      state.counts.checked += 1;
      state.counts.calls += 1;
      if (call.decision === "BLOCK") state.counts.blocked += 1;
      if (call.fast_path) state.counts.fast += 1;

      const delay = i * 450;
      const land = () => {
        hitLane(v.lane);
        addCard(cardHtml(result, call, rid), rid, call.call_id);
        renderStats();
      };
      if (aslVisible()) flyToken(v.lane, delay, land);
      else setTimeout(land, delay);
    });
    renderStats();
  }

  // A glowing token travels Agent -> ASL shield -> its lane. With no lane
  // (a message that needed no tool) it is checked at the shield and fades there.
  function flyToken(lane, delay, done) {
    const gate = $("gwGate");
    const g = gate.getBoundingClientRect();
    const agent = gate.querySelector(".gw-agent").getBoundingClientRect();
    const shield = $("gwShield").getBoundingClientRect();
    if (!g.width) { setTimeout(done, delay); return; }

    const at = (r, x) => `translate(${(x ?? r.left + r.width / 2) - g.left - 6}px, ${r.top + r.height / 2 - g.top - 6}px)`;
    const tok = document.createElement("i");
    tok.className = "gw-token";
    gate.appendChild(tok);

    if (!lane) {
      tok.animate([
        { transform: at(agent, agent.right), opacity: 0, backgroundColor: "#ffffff", offset: 0 },
        { transform: at(agent, agent.right), opacity: 1, backgroundColor: "#ffffff", offset: 0.1 },
        { transform: at(shield), opacity: 1, backgroundColor: "#ffffff", offset: 0.6 },
        { transform: at(shield) + " scale(2.4)", opacity: 0, backgroundColor: "#8a94a6", offset: 1 },
      ], { duration: 1000, delay, easing: "cubic-bezier(.45,0,.2,1)", fill: "forwards" })
        .onfinish = () => { tok.remove(); done(); };
      return;
    }

    const target = gate.querySelector(`[data-lane="${lane}"]`).getBoundingClientRect();
    const color = { allow: "#29d391", hold: "#f5a623", block: "#ff5c6c" }[lane];
    tok.animate([
      { transform: at(agent, agent.right), opacity: 0, backgroundColor: "#ffffff", offset: 0 },
      { transform: at(agent, agent.right), opacity: 1, backgroundColor: "#ffffff", offset: 0.08 },
      { transform: at(shield), opacity: 1, backgroundColor: "#ffffff", offset: 0.48 },
      { transform: at(shield), opacity: 1, backgroundColor: color, boxShadow: `0 0 16px ${color}`, offset: 0.58 },
      { transform: at(target, target.left + 14), opacity: 1, backgroundColor: color, boxShadow: `0 0 16px ${color}`, offset: 0.92 },
      { transform: at(target, target.left + 14), opacity: 0, backgroundColor: color, offset: 1 },
    ], { duration: 1400, delay, easing: "cubic-bezier(.45,0,.2,1)", fill: "forwards" })
      .onfinish = () => { tok.remove(); done(); };

    setTimeout(() => {
      const sh = $("gwShield");
      sh.classList.add(`flash-${lane}`);
      setTimeout(() => sh.classList.remove(`flash-${lane}`), 420);
    }, delay + 700);
  }

  /* ───────────────────────────── console ── */

  function setNumber(id, value) {
    const el = $(id);
    const text = String(value);
    if (el.textContent !== text) {
      el.textContent = text;
      el.classList.remove("tick");
      void el.offsetWidth;
      el.classList.add("tick");
    }
  }

  function renderStats(pendingCount) {
    setNumber("statChecked", state.counts.checked);
    setNumber("statBlocked", state.counts.blocked);
    if (pendingCount !== undefined) setNumber("statHeld", pendingCount);
    const pct = state.counts.calls ? Math.round((100 * state.counts.fast) / state.counts.calls) : 0;
    setNumber("statFast", pct + "%");
  }

  function renderQueue(pending) {
    const q = $("gwQueue");
    if (!pending.length) { q.innerHTML = `<p class="gw-hint">Nothing waiting.</p>`; return; }
    q.innerHTML = pending.map((a) => `
      <div class="gw-qitem gw-approve-src" data-approval="${esc(a.approval_id)}">
        <div class="top"><code>${esc(a.tool_name)}</code><span>risk ${esc(a.risk_score)}</span></div>
        <p>${esc(shortReason(a.reason))}</p>
        <div class="gw-btns">
          <button type="button" class="gw-btn ok" data-act="yes">Confirm</button>
          <button type="button" class="gw-btn no" data-act="no">Deny</button>
        </div>
      </div>`).join("");
    q.querySelectorAll(".gw-qitem").forEach((item) =>
      item.querySelectorAll(".gw-btn").forEach((b) =>
        b.addEventListener("click", () => resolve(item.dataset.approval, b.dataset.act === "yes"))));
  }

  function renderAudit(entries) {
    const short = { ALLOW: "ALLOW", ALLOW_WITH_LOG: "LOG", CHALLENGE: "HOLD", SANDBOX: "SANDBOX", BLOCK: "BLOCK",
      REFUSED: "REFUSE", ANSWERED: "ANSWER", CONFIRMED: "YES", DENIED: "NO" };
    $("gwAudit").innerHTML = entries.map((e) => {
      const t = new Date(e.timestamp);
      const time = isNaN(t) ? "" : t.toLocaleTimeString([], { hour12: false });
      const fast = e.path === "FAST_PATH_ALLOW" ? " ⚡" : "";
      return `<div><time>${time}</time><em class="d-${esc(e.decision)}">${short[e.decision] || esc(e.decision)}</em>
        <span>${esc(e.tool_name)}${fast}</span></div>`;
    }).join("");
  }

  async function getJson(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(url);
    return r.json();
  }

  async function refreshConsole() {
    const user = $("gwUser").value.trim() || "demo_user";
    const [health, approvals, audit, trust] = await Promise.allSettled([
      getJson("/health"),
      getJson("/api/gateway/approvals"),
      getJson("/api/gateway/activity?limit=14"),
      getJson(`/api/user/${encodeURIComponent(user)}`),
    ]);
    if (health.status === "fulfilled") {
      const h = health.value;
      $("gwModel").textContent = h.planner_model || "mock planner";
      $("statKnown").textContent = (h.fingerprints && h.fingerprints.count || 0).toLocaleString();
    }
    if (approvals.status === "fulfilled") {
      renderQueue(approvals.value.pending || []);
      renderStats((approvals.value.pending || []).length);
    }
    if (audit.status === "fulfilled") renderAudit(audit.value.entries || []);
    if (trust.status === "fulfilled") {
      const score = Number(trust.value.trust_score || 0);
      $("trustVal").textContent = score.toFixed(2);
      $("trustBar").style.width = Math.round(score * 100) + "%";
      $("trustBar").style.backgroundPosition = `${100 - score * 100}% 0`;
    }
  }

  /* ───────────────────────────── checks drawer ── */

  function stageRow(ev) {
    return `<div class="gw-stage">
      <button type="button"><span class="dot ${esc(ev.status)}"></span>
        <span class="t">${esc(String(ev.title || ev.stage).replace(/^\d+[a-z]?\.\s*/, ""))}</span>
        <span class="s">${esc(ev.summary || "")}</span></button>
      <div class="body" data-index="${ev.index}"></div>
    </div>`;
  }

  function vchip(decision) {
    const map = { ALLOW: ["#e8f4ee", "#17794a"], ALLOW_WITH_LOG: ["#e9f0fb", "#1a56b8"],
      CHALLENGE: ["#fbf1e0", "#9a6207"], SANDBOX: ["#f1ecf9", "#7048a8"], BLOCK: ["#fbeceb", "#b3261e"] };
    const [bg, fg] = map[decision] || ["#f0f1f3", "#4a5057"];
    return `<span class="gw-vchip" style="background:${bg};color:${fg}">${esc(verdict(decision).label)}</span>`;
  }

  function openChecks(rid, focusCall) {
    const result = state.results[rid];
    if (!result) return;
    const trace = result.trace || [];
    const general = trace.filter((e) => !e.call_id && e.stage !== "session");
    const calls = result.calls || [];

    $("gwDrawerTitle").textContent = "ASL checks";
    $("gwDrawerSub").textContent =
      `“${String(result.prompt || "").slice(0, 90)}” · ${calls.length} tool call${calls.length === 1 ? "" : "s"} · ${Math.round(result.latency_ms || 0)} ms`;

    let html = `<section class="gw-dsec"><h4>The request</h4>${general.map(stageRow).join("")}</section>`;
    calls.forEach((c) => {
      html += `<section class="gw-dsec" id="sec-${esc(c.call_id)}">
        <h4><code>${esc(c.tool_name)}</code>${vchip(c.decision)}</h4>
        ${trace.filter((e) => e.call_id === c.call_id).map(stageRow).join("")}
      </section>`;
    });
    if (!calls.length) html += `<p class="gw-hint" style="color:#6b7380">No tool was called, so there was nothing to authorize.</p>`;

    const body = $("gwDrawerBody");
    body.innerHTML = html;
    body.querySelectorAll(".gw-stage").forEach((row) => {
      row.querySelector("button").addEventListener("click", () => {
        const box = row.querySelector(".body");
        if (!box.innerHTML) {
          const ev = trace.find((e) => String(e.index) === box.dataset.index);
          try { box.innerHTML = S.renderDetail(ev); } catch (_) { box.textContent = JSON.stringify(ev.detail, null, 2); }
        }
        row.classList.toggle("open");
      });
    });

    $("gwDrawer").classList.add("on");
    $("gwDrawer").setAttribute("aria-hidden", "false");
    $("gwScrim").classList.add("on");
    if (focusCall) {
      const sec = document.getElementById(`sec-${focusCall}`);
      if (sec) setTimeout(() => sec.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
    }
  }

  function closeChecks() {
    $("gwDrawer").classList.remove("on");
    $("gwDrawer").setAttribute("aria-hidden", "true");
    $("gwScrim").classList.remove("on");
  }
  $("gwDrawerClose").addEventListener("click", closeChecks);
  $("gwScrim").addEventListener("click", closeChecks);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeChecks(); });

  /* ───────────────────────────── start ── */

  $("gwUser").addEventListener("change", refreshConsole);
  refreshConsole();
  setInterval(() => { if (!state.busy) refreshConsole(); }, 8000);
  text.focus();
})();

// HR runs dashboard — reads /api/hr/summary and /api/hr/runs/{id}.
// Candidate names (sample inbox only) and reasons are inserted through esc() only.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let hours = 168, labels = {}, openRun = null;

const DECISION = {
  DENY: ["Blocked (DENY)", "var(--deny)"], APPROVAL: ["Needs human approval", "var(--approval)"],
  ALLOW: ["Allowed", "var(--allow)"], EXECUTED: ["Executed with no checks (OFF)", "var(--deny)"],
  NONE: ["Nothing to do", "var(--muted)"],
};
const STATUS = { running: "running", review: "awaiting review", abandoned: "review abandoned", done: "done",
                 error: "error", empty: "no applications" };
const pill = (d) => d ? `<span class="pill p-${esc(d)}">${esc(d === "EXECUTED" ? "EXECUTED (unchecked)" : d)}</span>` : `<span class="muted">—</span>`;
const fmtS = (x) => x == null ? "—" : `${x} s`;
const when = (ts) => new Date(ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

// ---------------- totals ----------------
function kpis(s) {
  const tile = (l, v, sub) => `<div class="kpi"><div class="l">${l}</div><div class="v">${esc(v)}</div>${sub ? `<div class="s">${sub}</div>` : ""}</div>`;
  $("kpis").innerHTML = [
    tile("Runs", s.runs, `${s.runs_on} protected · ${s.runs_off} unprotected`),
    tile("Applications loaded", s.applications),
    tile("Clean", s.clean, "checked, nothing suspicious"),
    tile("Flagged", s.flagged, "suspicious content"),
    tile("Unchecked", s.unchecked, "Sec-Agent OFF — not scanned"),
    tile("Excluded", s.excluded, "kept out of the agent's context"),
    tile("Included anyway", s.included_anyway, "human override of a flag"),
    tile("Median review time", fmtS(s.median_decision_s), `per flagged application${s.awaiting_review ? ` · ${s.awaiting_review} awaiting` : ""}${s.abandoned ? ` · ${s.abandoned} abandoned` : ""}`),
  ].join("");
}

function hbars(id, items) {
  const el = $(id), max = Math.max(1, ...items.map(x => x.n));
  if (!items.some(x => x.n)) { el.innerHTML = `<div class="empty">Nothing yet</div>`; return; }
  el.innerHTML = items.filter(x => x.n).map(x => `<div class="hbar" title="${esc(x.label)}: ${x.n}">
      <div class="lab">${esc(x.label)}</div>
      <div class="track"><div class="fill" style="width:${(x.n / max) * 100}%;background:${x.color || "var(--series, var(--accent))"}"></div></div>
      <div class="num">${x.n}</div></div>`).join("");
}

function charts(s) {
  hbars("appsBars", [
    { label: "Clean", n: s.clean, color: "var(--allow)" },
    { label: "Flagged", n: s.flagged, color: "var(--approval)" },
    { label: "Unchecked (Sec-Agent OFF)", n: s.unchecked, color: "var(--muted)" },
    { label: "Excluded by a reviewer", n: s.excluded, color: "var(--sec)" },
    { label: "Included anyway by a reviewer", n: s.included_anyway, color: "var(--deny)" },
  ]);
  hbars("catBars", Object.entries(s.categories).sort((a, b) => b[1] - a[1])
    .map(([k, n]) => ({ label: labels[k] || k, n })));
  hbars("decBars", Object.entries(DECISION).map(([k, [label, color]]) => ({ label: `${k} — ${label}`, n: s.decisions[k] || 0, color })));
}

function runsTable(rows) {
  $("runcount").textContent = rows.length ? `${rows.length} shown` : "";
  $("norun").classList.toggle("hidden", rows.length > 0);
  const tb = $("runs").querySelector("tbody");
  tb.innerHTML = rows.map(r => `<tr data-id="${esc(r.run_id)}" tabindex="0" class="${r.run_id === openRun ? "sel" : ""}">
      <td>${esc(when(r.ts))}</td>
      <td class="${r.protection === "ON" ? "mode-on" : "mode-off"}">${esc(r.protection)}</td>
      <td>${esc(r.source === "gmail" ? "Gmail (counts only)" : `Sample · ${r.scenario}`)}</td>
      <td class="n">${r.applications}</td>
      <td class="n">${r.protection === "ON" ? r.flagged : `<span class="muted">unchecked</span>`}</td>
      <td class="n">${r.excluded}</td><td class="n">${r.included_anyway}</td>
      <td>${pill(r.final_decision)}</td>
      <td>${esc(r.human_approval || "—")}</td>
      <td>${esc(STATUS[r.status] || r.status)}</td></tr>`).join("");
  tb.querySelectorAll("tr").forEach(tr => {
    const go = () => showRun(tr.dataset.id);
    tr.addEventListener("click", go);
    tr.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
  });
}

async function load() {
  try {
    const r = await fetch(`/api/hr/summary?hours=${hours}`);
    if (!r.ok) throw new Error(r.statusText);
    const s = await r.json();
    labels = s.category_labels || {};
    kpis(s); charts(s); runsTable(s.recent || []);
    $("updated").textContent = "updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch (e) { $("updated").textContent = "could not load: " + e.message; }
}

// ---------------- one run ----------------
const ICON = { done: "✓", waiting: "…", blocked: "✕", skipped: "–", failed: "!", abandoned: "!", pending: "·" };
const WORD = { done: "Completed", waiting: "Waiting", blocked: "Blocked", skipped: "Skipped", failed: "Failed",
               abandoned: "Abandoned", pending: "Not started" };

function stages(r) {
  const on = r.protection, rv = r.review, fd = r.final_decision, act = r.action;
  const out = [];
  out.push(["Applications loaded", r.applications ? "done" : (r.status === "empty" ? "failed" : "pending"), `${r.applications} application(s)`]);
  out.push(["Input screening", on ? (r.applications ? "done" : "pending") : "skipped",
            on ? `${r.flagged} flagged · ${r.clean} clean` : "Sec-Agent OFF — content unchecked"]);
  let review;
  if (!on) review = ["skipped", "no screening, nothing to review"];
  else if (!r.flagged) review = ["skipped", "nothing flagged"];
  else if (r.status === "review") review = ["waiting", "waiting for the reviewer"];
  else if (r.status === "abandoned") review = ["abandoned", "never continued"];
  else if (rv) review = ["done", `excluded ${rv.excluded} · included anyway ${rv.included_anyway}`];
  else review = ["pending", ""];
  out.push(["Human review", ...review]);
  const proposed = act ? `${act.tool}${act.internal === true ? " → internal" : act.internal === false ? " → external" : ""}` : "";
  out.push(["Agent proposal", act ? "done" : fd === "NONE" ? "skipped" : r.status === "error" ? "failed" : "pending",
            act ? proposed : fd === "NONE" ? "every application excluded" : ""]);
  let pol;
  if (!on) pol = ["skipped", "no security or policy checks"];
  else if (fd === "DENY") pol = ["blocked", "action denied"];
  else if (fd === "APPROVAL") pol = ["done", "needs human approval"];
  else if (fd === "ALLOW") pol = ["done", "allowed"];
  else if (fd === "NONE") pol = ["skipped", "nothing to check"];
  else pol = [r.status === "error" ? "failed" : "pending", ""];
  out.push(["Security & policy", ...pol]);
  let res;
  if (r.status === "error") res = ["failed", "the run stopped with an error"];
  else if (r.executed === true) res = ["done", on ? "executed" : "sent with no checks (stub — nothing really left)"];
  else if (fd === "DENY") res = ["blocked", "nothing was sent"];
  else if (fd === "APPROVAL" && !r.human_approval) res = ["waiting", "awaiting Approve & send"];
  else if (r.human_approval === "rejected") res = ["blocked", "rejected by a human"];
  else if (fd === "NONE") res = ["skipped", "nothing to send"];
  else res = ["pending", ""];
  out.push(["Outcome", ...res]);
  return out;
}

async function showRun(id) {
  const d = $("detail");
  let r;
  try {
    const resp = await fetch(`/api/hr/runs/${encodeURIComponent(id)}`);
    if (!resp.ok) throw new Error(resp.status === 404 ? "run not found" : resp.statusText);
    r = await resp.json();
  } catch (e) { d.classList.remove("hidden"); d.innerHTML = `<div class="muted">${esc(e.message)}</div>`; return; }
  openRun = id;
  history.replaceState(null, "", `?run=${encodeURIComponent(id)}`);
  document.querySelectorAll("#runs tbody tr").forEach(tr => tr.classList.toggle("sel", tr.dataset.id === id));
  const gmail = r.source === "gmail", rv = r.review;
  const kept = r.applications - (rv ? rv.excluded : 0);
  const strip = stages(r).map(([t, s, det]) => `<li class="stage s-${s}"><div class="t">${esc(t)}</div>
      <div class="st"><span class="i" aria-hidden="true">${ICON[s]}</span>${WORD[s]}</div><div class="d">${esc(det)}</div></li>`).join("");
  const next = r.final_decision === "APPROVAL" && !r.human_approval ? "Human approval of the proposed email (on Demo HR)"
             : r.status === "review" ? "Reviewer decides on each flagged application (on Demo HR)" : "—";
  const apps = gmail ? `<p class="muted">Gmail run — counts only. Names, subjects and per-application rows are not stored.</p>`
    : `<table><thead><tr><th>Application</th><th>Screening</th><th>Signals</th><th>Reviewer</th><th>Decision time</th></tr></thead><tbody>${
        r.apps.map(a => `<tr><td>${esc(a.candidate)} <span class="muted">${esc(a.id)}</span></td>
          <td>${esc(a.status)}</td>
          <td>${(a.categories || []).map(c => `<span class="tag">${esc(labels[c] || c)}</span>`).join("") || "—"}</td>
          <td>${esc(a.outcome || (r.status === "review" ? "awaiting" : r.status === "abandoned" ? "never decided" : "—"))}</td>
          <td>${esc(fmtS(a.seconds))}</td></tr>`).join("")}</tbody></table>`;
  d.classList.remove("hidden");
  d.innerHTML = `<div class="bar"><h2 class="grow" style="margin:0">Run ${esc(r.run_id.slice(0, 8))} · ${esc(when(r.ts))}</h2>
      <button class="close" id="closeD" type="button">Close</button></div>
    <div class="muted">Sec-Agent <b>${r.protection ? "ON" : "OFF"}</b> · ${esc(gmail ? "Gmail (counts only)" : `Sample inbox · ${r.scenario}`)} · ${esc(r.agent === "scripted" ? "scripted compromised agent" : "live LLM agent")}</div>
    <ol class="stages">${strip}</ol>
    <div class="decision-card">
      <div class="kv"><b>Final result</b>${pill(r.final_decision)} ${r.status !== "done" ? `<span class="muted">(${esc(STATUS[r.status] || r.status)})</span>` : ""}</div>
      <div class="kv"><b>Proposed action</b>${r.action ? `<code>${esc(r.action.tool)}</code>${r.action.recipient ? ` → <code>${esc(r.action.recipient)}</code>` : ""}${r.action.internal === false ? ` <span class="tag">outside the company</span>` : ""}` : "—"}</div>
      <div class="kv"><b>Executed</b>${r.executed === true ? (r.protection ? "yes" : "yes — with no checks (stub tools; nothing really left)") : r.executed === false ? "no" : "not yet"}</div>
      ${r.top_reason ? `<div class="kv"><b>Top reason</b>${esc(r.top_reason)}</div>` : ""}
      <div class="kv"><b>Applications in scope</b>${esc(`${kept} of ${r.applications}`)}${rv ? ` <span class="muted">after human review</span>` : ""}</div>
      <div class="kv"><b>Shortlist approval</b>${esc(r.human_approval || "—")}${r.approval_seconds != null ? ` <span class="muted">after ${esc(r.approval_seconds)} s</span>` : ""}</div>
      <div class="kv"><b>Next required step</b>${esc(next)}</div>
      ${r.soc ? `<div class="kv"><b>Security event</b><a href="/soc">logged on the SOC dashboard</a></div>` : ""}
    </div>
    <p class="muted">Reviewing a flagged application and approving the shortlist email are two separate human decisions.</p>
    <div class="tblwrap">${apps}</div>`;
  $("closeD").addEventListener("click", () => { d.classList.add("hidden"); openRun = null; history.replaceState(null, "", location.pathname);
    document.querySelectorAll("#runs tbody tr.sel").forEach(tr => tr.classList.remove("sel")); });
  d.focus({ preventScroll: true }); d.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------------- controls ----------------
$("range").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
  hours = +b.dataset.h;
  $("range").querySelectorAll("button").forEach(x => x.classList.toggle("on", x === b));
  $("expCsv").href = `/api/hr/export?format=csv&hours=${hours}`;
  $("expJson").href = `/api/hr/export?format=json&hours=${hours}`;
  load();
}));

load().then(() => { const id = new URLSearchParams(location.search).get("run"); if (id) showRun(id); });
setInterval(() => { if (!document.hidden) load(); }, 15000);

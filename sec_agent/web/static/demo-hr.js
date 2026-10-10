// Demo HR — drives POST /api/hr/run and renders the OFF vs ON comparison.
// SAFETY: every field that comes from an email (subject, from, candidate, preview,
// reasons, body, recipient, result) is untrusted. It is only ever inserted through
// esc() or textContent — never as raw innerHTML — so a poisoned CV cannot inject script.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const INTERNAL = "ourco.example";

const inDomain = (addr) => {
  const at = String(addr || "").lastIndexOf("@");
  return at >= 0 && String(addr).slice(at + 1).toLowerCase() === INTERNAL;
};
const riskColor = (r) => r > 70 ? "var(--deny)" : r > 40 ? "var(--approval)" : "var(--allow)";

// ---------------- per-column state ----------------
const runState = { off: null, on: null };
const setSub = (pfx, t) => { $(pfx + "-sub").textContent = t; };

function resetCol(pfx) {
  ["steps", "action", "outcome"].forEach(k => { const e = $(pfx + "-" + k); e.classList.add("hidden"); e.innerHTML = ""; });
  $(pfx + "-apps").innerHTML = "";
  const v = $(pfx + "-verdict");
  v.className = "verdict v-wait"; v.classList.remove("hidden"); v.textContent = "Running…";
}
function setVerdict(pfx, cls, html, small) {
  const v = $(pfx + "-verdict");
  v.className = "verdict " + cls; v.classList.remove("hidden");
  v.innerHTML = html + (small ? `<small>${small}</small>` : "");
}
function addStep(pfx, html) {
  const s = $(pfx + "-steps"); s.classList.remove("hidden");
  const d = document.createElement("div"); d.innerHTML = html; s.appendChild(d);
}
function appendOutcome(pfx, html) {
  const o = $(pfx + "-outcome"); o.classList.remove("hidden");
  o.insertAdjacentHTML("beforeend", html);
}

// ---------------- applications table ----------------
function renderApps(pfx, emails) {
  const rows = emails.map(e => `
    <tr class="app" data-id="${esc(e.id)}">
      <td class="who"><div class="cand">${esc(e.candidate)}</div><div class="subj">${esc(e.subject)}</div><div class="subj">${esc(e.from)}</div></td>
      <td class="st" id="${esc(pfx)}-st-${esc(e.id)}"><span class="st-pill st-none">pending</span></td>
      <td class="rs" id="${esc(pfx)}-rs-${esc(e.id)}">—</td>
    </tr>
    <tr class="prev hidden" id="${esc(pfx)}-pv-${esc(e.id)}"><td colspan="3"><div class="preview">${esc(e.preview)}</div></td></tr>`).join("");
  $(pfx + "-apps").innerHTML =
    `<table class="apps"><thead><tr><th class="who">Applicant</th><th class="st">Status</th><th>Reasons</th></tr></thead><tbody>${rows}</tbody></table>`;
  $(pfx + "-apps").querySelectorAll("tr.app").forEach(tr => tr.addEventListener("click", () => {
    const pv = $(pfx + "-pv-" + tr.dataset.id); if (pv) pv.classList.toggle("hidden");
  }));
}
function setStatus(pfx, id, { flagged, reasons, unchecked }) {
  const st = $(pfx + "-st-" + id), rs = $(pfx + "-rs-" + id);
  if (!st) return;
  if (unchecked) { st.innerHTML = `<span class="st-pill st-none">Not checked</span>`; rs.textContent = "—"; return; }
  st.innerHTML = flagged ? `<span class="st-pill st-flag">Flagged</span>` : `<span class="st-pill st-clean">Clean</span>`;
  rs.innerHTML = reasons && reasons.length ? `<ul class="reasons">${reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : "—";
}

// ---------------- agent action ----------------
function renderAction(pfx, a) {
  if (!a) return;
  const args = a.arguments || {};
  const recip = args.recipient;
  const out = recip !== undefined && !inDomain(recip);
  let bodyHtml = "";
  if (args.body !== undefined) bodyHtml = `<div class="mono-box" style="margin-top:6px">${esc(args.body)}</div>`;
  else if (args.answer !== undefined) bodyHtml = `<div class="mono-box" style="margin-top:6px">${esc(args.answer)}</div>`;
  else if (Object.keys(args).length) bodyHtml = `<div class="mono-box" style="margin-top:6px">${esc(JSON.stringify(args, null, 1))}</div>`;
  const el = $(pfx + "-action"); el.classList.remove("hidden");
  el.innerHTML = `<div class="lab">Agent proposes</div>
    <div class="kv">tool: <b>${esc(a.tool)}</b></div>` +
    (recip !== undefined ? `<div class="kv">recipient: <span class="${out ? "addr-bad" : "addr-ok"}">${esc(recip)}</span>${out ? ` <span class="muted">(outside ${esc(INTERNAL)})</span>` : ""}</div>` : "") +
    bodyHtml;
}

// ---------------- outcome (ON) ----------------
function renderDecision(pfx, d, sec) {
  const el = $(pfx + "-outcome"); el.classList.remove("hidden");
  let html = `<div class="lab">Why</div>` +
    (d.reasons && d.reasons.length ? `<ul class="reasonlist">${d.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : `<div class="muted">—</div>`);
  if (sec) html += `<div class="secline">Security model: <b>${esc(sec.decision)}</b> · ${esc(sec.classification)} · risk <b>${esc(sec.risk_score)}/100</b>
      <div class="meter"><span style="width:${Number(sec.risk_score) || 0}%;background:${riskColor(sec.risk_score)}"></span></div>${esc(sec.reason)}</div>`;
  el.innerHTML = html;
}
function addApproval(pfx) {
  const bar = document.createElement("div"); bar.className = "approvebar";
  bar.innerHTML = `<button class="approve" type="button">Approve &amp; send</button>
    <button class="reject" type="button">Reject</button><span class="decided" id="${pfx}-decided"></span>`;
  $(pfx + "-outcome").appendChild(bar);
  const t0 = performance.now();
  bar.querySelector(".approve").addEventListener("click", () => decide(pfx, true, t0, bar));
  bar.querySelector(".reject").addEventListener("click", () => decide(pfx, false, t0, bar));
}
async function decide(pfx, approve, t0, bar) {
  bar.querySelectorAll("button").forEach(b => b.disabled = true);
  const secs = ((performance.now() - t0) / 1000).toFixed(1);
  const sid = runState[pfx] && runState[pfx].session_id;
  try {
    const r = await fetch("/execute", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sid, approve }) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
    const v = await r.json();
    $(pfx + "-decided").textContent = `decided in ${secs} s`;
    if (approve && v.executed) {
      setVerdict(pfx, "v-neutral", "Allowed — executed after human approval");
      appendOutcome(pfx, `<div class="lab" style="margin-top:10px">Result</div><div class="mono-box">${esc(v.executed)}</div>`);
    } else {
      setVerdict(pfx, "v-green", "Rejected by a human — nothing was sent");
    }
  } catch (err) { appendOutcome(pfx, `<div class="err">${esc(err.message)}</div>`); }
}

// ---------------- event handling ----------------
function handle(pfx, ev) {
  const st = runState[pfx]; if (!st) return;
  switch (ev.type) {
    case "start": st.session_id = ev.session_id; break;
    case "fetched":
      st.emails = ev.emails || [];
      addStep(pfx, `<b>${st.emails.length}</b> application(s) loaded <span class="muted">(via ${esc(ev.via)})</span>`);
      renderApps(pfx, st.emails);
      break;
    case "candidates":
      addStep(pfx, `candidate database: <b>${esc(ev.count)}</b> record(s) <span class="muted">(via ${esc(ev.via)})</span>`);
      break;
    case "screened":
      if (ev.unchecked) {
        addStep(pfx, `<span class="muted">input guard did not run — content unchecked</span>`);
        st.emails.forEach(e => setStatus(pfx, e.id, { unchecked: true }));
      } else {
        (ev.emails || []).forEach(e => setStatus(pfx, e.id, { flagged: e.flagged, reasons: e.reasons }));
      }
      break;
    case "action":
      st.action = ev.action; renderAction(pfx, ev.action);
      break;
    case "security": st.security = ev.security; break;
    case "decision": {
      st.final = ev.final_decision;
      renderDecision(pfx, ev, st.security);
      if (ev.final_decision === "DENY")
        setVerdict(pfx, "v-green", `Blocked — ${esc((ev.reasons && ev.reasons[0]) || "policy refused the action")}`);
      else if (ev.final_decision === "APPROVAL") { setVerdict(pfx, "v-amber", "Waiting for a human"); addApproval(pfx); }
      else if (ev.final_decision === "ALLOW") setVerdict(pfx, "v-neutral", "Allowed");
      break;
    }
    case "executed": {
      const recip = ev.arguments && ev.arguments.recipient;
      const out = recip !== undefined && !inDomain(recip);
      $(pfx + "-outcome").classList.remove("hidden");
      $(pfx + "-outcome").innerHTML = `<div class="lab">What left the server</div><div class="mono-box">${esc(ev.result)}</div>`;
      if (ev.ok && recip !== undefined)
        setVerdict(pfx, out ? "v-red" : "v-neutral", `Sent to <span style="font-family:var(--mono)">${esc(recip)}</span> — no checks ran`,
          out ? `Recipient domain isn't ${esc(INTERNAL)} — candidate data just left the company.` : null);
      else if (ev.ok)
        setVerdict(pfx, "v-red", `${esc(ev.tool)} executed — no checks ran`);
      else
        setVerdict(pfx, "v-neutral", `Not executed — ${esc(ev.result)}`);
      break;
    }
    case "done":
      if (ev.session_id) st.session_id = ev.session_id;
      setSub(pfx, ev.final_decision ? String(ev.final_decision).toLowerCase() : "done");
      break;
    case "error":
      setVerdict(pfx, "v-neutral", "Error");
      appendOutcome(pfx, `<div class="err">${esc(ev.detail)}</div>`);
      setSub(pfx, "error");
      break;
  }
}

async function readStream(r, onEvent) {
  const reader = r.body.getReader(), dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (line) onEvent(JSON.parse(line));
    }
  }
}

function buildBody(protection) {
  const src = $("source").value;
  const b = { goal: $("goal").value, protection, source: src, compromised: $("agent").value === "scripted" };
  if (src === "sample") b.sample = $("sample").value;
  return b;
}

async function runOne(protection) {
  const pfx = protection ? "on" : "off";
  resetCol(pfx);
  runState[pfx] = { protection, session_id: null, security: null, emails: [] };
  setSub(pfx, "running…");
  try {
    const r = await fetch("/api/hr/run", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildBody(protection)) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
    await readStream(r, ev => handle(pfx, ev));
  } catch (err) { handle(pfx, { type: "error", detail: err.message }); }
}

function busy(on) { $("runBtn").disabled = on; $("runBothBtn").disabled = on; $("status").textContent = on ? "Running…" : ""; }

$("runBtn").addEventListener("click", async () => {
  busy(true);
  await runOne($("protSwitch").classList.contains("on"));
  busy(false);
});
$("runBothBtn").addEventListener("click", async () => {
  busy(true);
  await runOne(false);
  await runOne(true);
  busy(false);
});

// ---------------- protection switch ----------------
const prot = $("protSwitch");
function toggleProt() {
  const on = !prot.classList.contains("on");
  prot.classList.toggle("on", on);
  prot.setAttribute("aria-checked", String(on));
  prot.querySelector(".txt").innerHTML = `Sec-Agent <b>${on ? "ON" : "OFF"}</b>`;
}
prot.addEventListener("click", toggleProt);
prot.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleProt(); } });

// ---------------- source / gmail ----------------
function syncSource() {
  const gmail = $("source").value === "gmail";
  $("sampleField").classList.toggle("hidden", gmail);
  $("gmailBar").classList.toggle("hidden", !gmail);
  if (gmail) gmailStatus();
}
$("source").addEventListener("change", syncSource);

async function gmailStatus() {
  try {
    const s = await (await fetch("/api/gmail/status")).json();
    if (!s.configured) {
      $("gmailDot").classList.remove("ok");
      $("gmailStatus").textContent = "Gmail isn't configured on this server.";
      $("gmailConnect").classList.add("hidden");
    } else if (s.connected) {
      $("gmailDot").classList.add("ok");
      $("gmailStatus").textContent = `Connected as ${s.email || "Gmail"} (read-only).`;
      $("gmailConnect").classList.add("hidden");
    } else {
      $("gmailDot").classList.remove("ok");
      $("gmailStatus").textContent = "Not connected.";
      $("gmailConnect").classList.remove("hidden");
    }
  } catch { $("gmailStatus").textContent = "Gmail status unavailable."; }
}

// Returning from the Google sign-in: land on Gmail source, clean the URL.
if (/[?&]gmail=connected/.test(location.search)) { $("source").value = "gmail"; }
if (/[?&]gmail=/.test(location.search)) history.replaceState(null, "", location.pathname);
syncSource();

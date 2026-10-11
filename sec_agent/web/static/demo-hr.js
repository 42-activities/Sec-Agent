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

// ---------------- human review of flagged applications ----------------
// "Exclude" is the default and applies at once (reversible until Continue). "Include anyway"
// first opens an impact explanation; only "Include application" there changes the choice.
// A flag is a security signal about the email's content, never a judgement of the applicant.
const SIGNALS = [
  [/^instruction aimed at an AI/, "Instructions directed at an AI system"],
  [/^targets sensitive data/, "References to sensitive data such as credentials or keys"],
  [/^asks to hide it from the user/, "Asks to keep something hidden from the recruiter"],
  [/^hidden text/, "Hidden or obfuscated text detected"],
  [/redirects data/, "Request to send data to another destination"],
  [/^Jev risk/, "Prompt-injection classifier (Jev) rated the content as risky"],
];
const signalsOf = (reasons) => [...new Set((reasons || []).flatMap(r => SIGNALS.filter(([re]) => re.test(r)).map(([, l]) => l)))];

const fill = (el, items) => { el.replaceChildren(...items.map(t => { const li = document.createElement("li"); li.textContent = t; return li; })); };

function openIncludeExplanation(pfx, id, onConfirm, trigger) {
  const st = runState[pfx], info = (st.screeningById || {})[id] || {};
  const email = (st.emails || []).find(e => e.id === id) || {};
  const dlg = $("incDialog");
  $("incWho").textContent = email.candidate || id;
  const sig = signalsOf(info.reasons);
  fill($("incSignals"), sig.length ? sig : ["Suspicious content in an untrusted email"]);
  fill($("incReasons"), info.reasons && info.reasons.length ? info.reasons : ["—"]);
  $("incJev").textContent = info.jev_level != null
    ? `${info.jev_level}/100 — a security signal about the email's content` : "not available";
  let confirmed = false;
  const yes = $("incYes"), no = $("incNo");
  const onYes = () => { confirmed = true; dlg.close(); };
  const onNo = () => dlg.close();
  yes.addEventListener("click", onYes); no.addEventListener("click", onNo);
  dlg.addEventListener("close", () => {          // also fires on Escape (cancel)
    yes.removeEventListener("click", onYes); no.removeEventListener("click", onNo);
    onConfirm(confirmed);
    if (trigger && trigger.isConnected) trigger.focus();
  }, { once: true });
  dlg.showModal();
}

function renderReview(pfx, ev) {
  const st = runState[pfx];
  st.choice = {}; st.seconds = {}; st.acknowledged = new Set(); st.shownAt = performance.now();
  st.emails.forEach(e => { st.choice[e.id] = !ev.flagged.includes(e.id); });   // clean = keep
  ev.flagged.forEach(id => {
    const cell = $(pfx + "-rs-" + id); if (!cell) return;
    const bar = document.createElement("div"); bar.className = "choice";
    const timer = document.createElement("span"); timer.className = "muted ch-time";
    const note = document.createElement("span"); note.className = "muted ch-note";
    const drop = document.createElement("button"), keep = document.createElement("button");
    drop.type = keep.type = "button";
    drop.textContent = "Exclude"; drop.className = "ch-drop on";
    keep.textContent = "Include anyway"; keep.className = "ch-keep";
    const show = () => {
      drop.classList.toggle("on", !st.choice[id]); keep.classList.toggle("on", st.choice[id]);
      note.textContent = st.choice[id]
        ? "Included after review — the agent will see this application; its actions are still checked."
        : "This application will not be provided to the agent.";
      if (st.seconds[id] != null) timer.textContent = `decided in ${st.seconds[id].toFixed(1)} s`;
    };
    const stamp = () => { st.seconds[id] = Math.round((performance.now() - st.shownAt) / 100) / 10; };
    drop.addEventListener("click", (evt) => {
      evt.stopPropagation();   // don't also toggle the row's CV preview
      st.choice[id] = false; st.acknowledged.delete(id); stamp(); show();
    });
    keep.addEventListener("click", (evt) => {
      evt.stopPropagation();
      if (st.choice[id]) return;
      openIncludeExplanation(pfx, id, (ok) => {
        stamp();               // time to a confirmed decision (either way)
        if (ok) { st.choice[id] = true; st.acknowledged.add(id); }
        show();
      }, keep);
    });
    bar.append(drop, keep, timer, note);
    cell.appendChild(bar);
    show();
  });
  const go = document.createElement("button"); go.type = "button"; go.className = "go-review";
  go.textContent = "Continue with my decisions";
  go.addEventListener("click", () => continueReview(pfx, go));
  const o = $(pfx + "-outcome"); o.classList.remove("hidden"); o.innerHTML = "";
  const note = document.createElement("div"); note.className = "muted";
  note.textContent = "Flagged applications are held back by default. Excluded ones never reach the agent.";
  o.append(note, go);
}

async function continueReview(pfx, btn) {
  const st = runState[pfx];
  btn.disabled = true;
  document.querySelectorAll(`#${pfx}-apps .choice button`).forEach(b => b.disabled = true);
  const include = st.emails.filter(e => st.choice[e.id]).map(e => e.id);
  try {
    const r = await fetch("/api/hr/continue", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: st.session_id, include, seconds: st.seconds,
                             acknowledged: [...(st.acknowledged || [])].filter(id => st.choice[id]) }) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
    setSub(pfx, "running…");
    await readStream(r, ev => handle(pfx, ev));
  } catch (err) { handle(pfx, { type: "error", detail: err.message }); }
}

// ---------------- event handling ----------------
function handle(pfx, ev) {
  const st = runState[pfx]; if (!st) return;
  switch (ev.type) {
    case "start": st.session_id = st.runId = ev.session_id; break;
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
        st.screeningById = {};
        (ev.emails || []).forEach(e => {
          st.screeningById[e.id] = { flagged: e.flagged, reasons: e.reasons || [], jev_level: e.jev_level };
          setStatus(pfx, e.id, { flagged: e.flagged, reasons: e.reasons });
        });
      }
      break;
    case "review":
      st.session_id = ev.session_id;
      setVerdict(pfx, "v-amber", `Review needed — ${ev.flagged.length} flagged application(s)`,
        "Decide for each flagged application, then continue.");
      renderReview(pfx, ev);
      break;
    case "reviewed":
      $(pfx + "-outcome").innerHTML = "";
      addStep(pfx, `human review: kept <b>${ev.kept.length}</b>, excluded <b>${ev.excluded.length}</b>`);
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
      if (st.runId && !st.linked) {
        st.linked = true;
        addStep(pfx, `<a href="/hr-dashboard?run=${encodeURIComponent(st.runId)}">View this run on the HR runs dashboard →</a>`);
      }
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
      $("gmailLogout").classList.remove("hidden");
    } else {
      $("gmailDot").classList.remove("ok");
      $("gmailStatus").textContent = "Not connected.";
      $("gmailConnect").classList.remove("hidden");
      $("gmailLogout").classList.add("hidden");
    }
  } catch { $("gmailStatus").textContent = "Gmail status unavailable."; }
}

// Log out: ends the session here and revokes the access at Google.
$("gmailLogout").addEventListener("click", async () => {
  $("gmailLogout").disabled = true;
  try { await fetch("/auth/google/logout", { method: "POST" }); } catch {}
  $("gmailLogout").disabled = false;
  gmailStatus();
});

// Returning from the Google sign-in: land on Gmail source, clean the URL.
if (/[?&]gmail=connected/.test(location.search)) { $("source").value = "gmail"; }
if (/[?&]gmail=/.test(location.search)) history.replaceState(null, "", location.pathname);
syncSource();

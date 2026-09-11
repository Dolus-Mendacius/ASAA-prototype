const $ = (id) => document.getElementById(id);
let state = { targets: [], selected: null, data: null, tab: "MODE_1" };

const SEVCLASS = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
const scColor = (s) => s >= 9 ? "var(--crit)" : s >= 7 ? "var(--high)" : s >= 4 ? "var(--med)" : "var(--low)";

async function api(path, method = "GET", body) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, body: j };
}

async function apiForm(path, formData) {
  const r = await fetch(path, { method: "POST", body: formData });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, body: j };
}

function toast(msg, deny = false) {
  const t = $("toast"); t.textContent = msg;
  t.className = "toast show" + (deny ? " deny" : "");
  setTimeout(() => (t.className = "toast"), 3200);
}

async function loadHealth() {
  const { body } = await api("/api/health");
  $("health").textContent = `${body.version} · Mode 3: ${body.reasoning_provider} · CVE≥${body.cve_threshold}`;
}

async function loadCveStatus() {
  const { body } = await api("/api/cve/status");
  $("cve-status").innerHTML =
    `<div class="chip"><b>${body.local_index_size}</b> CVEs in local index</div>
     <div class="chip">threshold <b>CVSS ${body.threshold}</b></div>`;
}

async function loadTargets() {
  const { body } = await api("/api/targets");
  state.targets = body;
  $("targets").innerHTML = body.length ? body.map(t => `
    <div class="titem ${state.selected === t.id ? "active" : ""}" onclick="selectTarget('${t.id}')">
      <div class="n">${esc(t.name)}</div>
      <div class="u">${esc(t.url)}</div>
      <span class="badge ${t.authorized_active ? "auth" : "noauth"}">
        ${t.authorized_active ? "✓ authorised (M2/M3)" : "Mode 1 only"}</span>
      <span class="badge noauth">${t.scans} scans · ${t.alerts} alerts</span>
    </div>`).join("") : `<div class="empty" style="padding:20px">No targets yet.</div>`;
}

async function createTarget() {
  const name = $("t-name").value.trim(), url = $("t-url").value.trim();
  if (!name || !url) return toast("Name and URL required", true);
  const fd = new FormData();
  fd.append("name", name); fd.append("url", url);
  fd.append("owner_email", $("t-email").value.trim());
  const f = $("t-authfile").files[0];
  if (f) fd.append("authorization", f);
  const { ok, status, body } = await apiForm("/api/targets", fd);
  if (!ok) return toast(body.error || `Error ${status}`, true);
  $("t-name").value = $("t-url").value = $("t-email").value = ""; $("t-authfile").value = "";
  toast(body.authorized_active
    ? "Target registered (authorised) · document SHA-256 hashed"
    : "Target registered (Mode 1 only — no authorisation document)");
  await loadTargets(); await loadAudit(); selectTarget(body.id);
}

async function selectTarget(id) {
  state.selected = id;
  await loadTargets();
  await refreshPanel();
}

async function refreshPanel() {
  if (!state.selected) return;
  const { body } = await api(`/api/targets/${state.selected}/findings`);
  state.data = body;
  const t = state.targets.find(x => x.id === state.selected) || {};
  $("panel-title").textContent = body.target.name;
  const authBtn = t.authorized_active
    ? `<a href="/api/targets/${t.id}/authorization" target="_blank" class="badge auth"
          style="align-self:center;text-decoration:none" title="View authorisation document on file">
         ✓ authorised · ${esc(t.auth_doc || "doc")} · ${esc(t.auth_hash || "")}</a>`
    : `<button class="sm" style="background:#b45309;color:#fff" onclick="authorize()">Authorise (upload doc)</button>`;
  $("mode-actions").innerHTML = `
    <button class="sm" onclick="runMode(1)">Run Mode 1</button>
    <button class="sm ghost" onclick="runMode(2)">Run Mode 2</button>
    <button class="sm ghost" onclick="runMode(3)">Run Mode 3</button>
    ${authBtn}
    <button class="sm ghost" onclick="makeReport('en')">Report EN</button>
    <button class="sm ghost" onclick="makeReport('ar')">Report AR</button>
    <input id="email-to" placeholder="email report to…"
      style="width:160px;padding:6px 9px;font-size:12px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;color:var(--ink)">
    <button class="sm ghost" onclick="emailReport('en')">Email report</button>`;
  $("tech").innerHTML = (body.technologies || []).map(tc =>
    `<div class="chip"><b>${esc(tc.product)}</b> ${esc(tc.version || "?")}</div>`).join("")
    || `<div class="chip">No technologies detected yet — run Mode 1</div>`;
  renderTabs(); renderTab();
}

function renderTabs() {
  const m = state.data.modes;
  const defs = [["MODE_1", "Mode 1 · Recon+CVE", m.MODE_1.length],
                ["MODE_2", "Mode 2 · Active", m.MODE_2.length],
                ["MODE_3", "Mode 3 · AI Narrative", state.data.narrative ? "●" : 0]];
  $("tabs").innerHTML = defs.map(([k, label, n]) =>
    `<div class="tab ${state.tab === k ? "active" : ""}" onclick="setTab('${k}')">${label}${n ? ` (${n})` : ""}</div>`).join("");
}
function setTab(k) { state.tab = k; renderTabs(); renderTab(); }

function sevPill(s) { return `<span class="sev ${SEVCLASS[s] || "info"}">${s}</span>`; }

function renderTab() {
  const d = state.data;
  if (state.tab === "MODE_3") {
    if (!d.narrative) { $("panel").innerHTML = `<div class="empty">No Mode 3 narrative yet. Run Mode 3 (requires authorisation).</div>`; return; }
    const att = (d.narrative.techniques || []).map(x => `<span class="tag">${x.id} ${esc(x.name)}</span>`).join("");
    $("panel").innerHTML = `
      <div class="chips"><div class="chip">provider <b>${esc(d.narrative.provider)}</b></div></div>
      <div class="att">${att}</div>
      <div class="narr">${esc(d.narrative.body)}</div>`;
    return;
  }
  const rows = d.modes[state.tab];
  if (!rows.length) {
    const hint = state.tab === "MODE_2" ? "Run Mode 2 (blocked without authorisation — that denial is the demo)." : "Run Mode 1 to populate.";
    $("panel").innerHTML = `<div class="empty">No findings yet. ${hint}</div>`; return;
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  rows.forEach(r => counts[r.severity] !== undefined && counts[r.severity]++);
  const bar = Object.entries(counts).filter(([, n]) => n).map(([s, n]) => `${sevPill(s)}×${n}`).join(" ");
  $("panel").innerHTML = `<div class="sevbar">${bar}</div>
    <table><thead><tr><th>ID</th><th>Finding</th><th>Sev</th><th>CVSS</th><th>Evidence</th></tr></thead><tbody>
    ${rows.map(r => `<tr>
      <td>${esc(r.identifier)}${(r.cves||[]).map(c=>`<div class="tag">${c}</div>`).join("")}</td>
      <td><b>${esc(r.title)}</b><br><span style="color:var(--muted)">${esc(r.category)}</span></td>
      <td>${sevPill(r.severity)}</td>
      <td>${r.cvss ? `<span class="sc" style="background:${scColor(r.cvss)};color:#fff">${r.cvss}</span>` : "-"}</td>
      <td style="color:var(--muted)">${esc((r.evidence||"").slice(0,120))}</td></tr>`).join("")}
    </tbody></table>`;
}

async function runMode(n) {
  const btns = document.querySelectorAll("#mode-actions button"); btns.forEach(b => b.disabled = true);
  toast(`Running Mode ${n}…`);
  const path = `/api/targets/${state.selected}/mode${n}`;
  const { ok, status, body } = await api(path, "POST", n === 3 ? { simulate: false } : {});
  btns.forEach(b => b.disabled = false);
  if (status === 403 || body.denied) {
    toast(`⛔ Mode ${n} DENIED — no authorisation. Click "Authorise M2/M3" first.`, true);
    await loadAudit(); return;
  }
  if (!ok) return toast(body.error || `Error ${status}`, true);
  if (n === 1) toast(`Mode 1 complete · ${(body.cve_matches||[]).length} CVE matches`);
  else if (n === 2) toast(`Mode 2 complete · ${body.tool} · ${body.findings.length} findings`);
  else toast(`Mode 3 complete · provider: ${body.provider}${body.degraded ? " (fallback)" : ""}`);
  if (n === 3) state.tab = "MODE_3"; else state.tab = `MODE_${n}`;
  await refreshPanel(); await loadTargets(); await loadAudit();
}

function authorize() {
  const inp = $("authfile-hidden");
  inp.value = "";
  inp.onchange = async () => {
    const f = inp.files[0];
    if (!f) return;
    const fd = new FormData(); fd.append("authorization", f);
    const { ok, body } = await apiForm(`/api/targets/${state.selected}/authorize`, fd);
    if (!ok) return toast(body.error || "Could not record authorisation", true);
    toast(`Authorisation recorded — ${body.document} · sha256:${(body.hash || "").slice(0, 12)}`);
    await loadTargets(); await refreshPanel(); await loadAudit();
  };
  inp.click();
}

async function emailReport(lang) {
  const to = ($("email-to") ? $("email-to").value.trim() : "");
  toast("Generating and emailing report…");
  const { ok, body } = await api(`/api/targets/${state.selected}/report`, "POST",
    { language: lang, depth: "full", email: true, email_to: to });
  if (!ok) return toast(body.error || "Report error", true);
  const e = body.email || {};
  if (e.sent) toast(`Report emailed to ${e.to} · hash ${body.content_hash}`);
  else toast(`Report generated but NOT emailed: ${e.reason}`, true);
  await loadAudit();
}

async function makeReport(lang) {
  toast(`Generating ${lang.toUpperCase()} report…`);
  const { ok, body } = await api(`/api/targets/${state.selected}/report`, "POST", { language: lang, depth: "full" });
  if (!ok) return toast(body.error || "Report error", true);
  toast(`Report ready · hash ${body.content_hash}`);
  window.open(body.download, "_blank");
  await loadAudit();
}

async function runMonitor() {
  const { body } = await api("/api/monitor/run", "POST");
  toast(`Monitoring sweep · ${body.alerts_created} new alert(s)`);
  await loadAlerts(); await loadTargets(); await loadAudit();
}
async function loadAlerts() {
  const { body } = await api("/api/alerts");
  $("alerts").innerHTML = body.length ? `<table><thead><tr><th>CVE</th><th>Target</th><th>CVSS</th></tr></thead><tbody>
    ${body.map(a => `<tr><td>${a.cve_id}</td><td>${esc(a.target)}</td>
      <td><span class="sc" style="background:${scColor(a.cvss)};color:#fff">${a.cvss}</span></td></tr>`).join("")}</tbody></table>`
    : `<div class="empty" style="padding:14px;font-size:12px">No alerts yet.</div>`;
}

async function loadAudit() {
  const { body } = await api("/api/audit");
  $("audit").innerHTML = body.map(e => `<tr>
    <td>${e.seq}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td>
    <td class="${e.status === "denied" ? "deny" : "ok"}">${e.status}</td>
    <td>${esc((e.detail||"").slice(0,60))}</td>
    <td style="color:var(--muted)">${e.entry_hash}</td></tr>`).join("");
}
async function verifyChain() {
  const { body } = await api("/api/audit/verify");
  $("verify").innerHTML = body.intact
    ? `<div class="verify good">✓ Hash chain intact across ${body.count} entries — log is tamper-evident.</div>`
    : `<div class="verify bad">✗ Chain broken at entry #${body.broken_at_seq}.</div>`;
}

function esc(s) { return (s ?? "").toString().replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

(async function init() {
  await loadHealth(); await loadCveStatus(); await loadTargets(); await loadAlerts(); await loadAudit();
})();

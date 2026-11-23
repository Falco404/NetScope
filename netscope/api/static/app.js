// NetScope frontend: dumb — fetch JSON, render. All logic is server-side.
const $ = (id) => document.getElementById(id);

let devices = [];
let sortKey = "name";
let sortAsc = true;

async function api(path, options) {
  const res = await fetch(path, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
  return body;
}

function renderDevices() {
  const rows = [...devices].sort((a, b) => {
    const av = sortKey === "ports" ? a.open_ports.length : a[sortKey] ?? "";
    const bv = sortKey === "ports" ? b.open_ports.length : b[sortKey] ?? "";
    return (av < bv ? -1 : av > bv ? 1 : 0) * (sortAsc ? 1 : -1);
  });
  const tbody = $("devices").querySelector("tbody");
  tbody.innerHTML = "";
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No devices yet — run a scan.</td></tr>';
    return;
  }
  for (const d of rows) {
    const tr = document.createElement("tr");
    tr.className = "device";
    tr.innerHTML = `
      <td>${d.name}</td>
      <td>${d.ip}</td>
      <td class="status-${d.status}">${d.status}</td>
      <td>${d.os_guess ?? ""}</td>
      <td>${d.vendor ?? ""}</td>
      <td class="ports">${d.open_ports.join(", ")}</td>`;
    tr.addEventListener("click", () => openDetail(d.identity));
    tbody.appendChild(tr);
  }
}

async function loadAll() {
  devices = await api("/api/devices");
  renderDevices();
  const scans = await api("/api/scans");
  $("scans").innerHTML = scans.length
    ? scans.map((s) => `<li>${s.ts} — ${s.target}${s.duration_seconds ? ` (${s.duration_seconds}s)` : ""}</li>`).join("")
    : '<li class="empty">No scans yet.</li>';
  try {
    const diff = await api("/api/diff");
    const items = [
      ...diff.appeared.map((x) => `<li class="appeared">${x.name} appeared</li>`),
      ...diff.disappeared.map((x) => `<li class="disappeared">${x.name} disappeared</li>`),
      ...diff.changed.map((x) => `<li class="changed">${x.name} changed open ports</li>`),
    ];
    $("changes").innerHTML = items.length ? items.join("") : '<li class="empty">Nothing changed.</li>';
  } catch {
    $("changes").innerHTML = '<li class="empty">No comparison available yet.</li>';
  }
}

async function openDetail(identity) {
  const d = await api(`/api/devices/${encodeURIComponent(identity)}`);
  $("detail").hidden = false;
  $("detail-title").textContent = d.name;
  $("detail-fields").innerHTML = [
    ["IP", d.ip],
    ["Identity", d.identity],
    ["MAC", d.mac ?? ""],
    ["Vendor", d.vendor ?? ""],
    ["OS guess", d.os_guess ?? ""],
    ["Last seen", d.last_seen_scan ?? ""],
  ].map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
  $("detail-ports").querySelector("tbody").innerHTML = d.ports.length
    ? d.ports.map((p) => `<tr><td>${p.scan_id}</td><td>${p.port}</td><td>${p.protocol}</td><td>${p.service ?? ""}</td><td>${p.version ?? ""}</td></tr>`).join("")
    : '<tr><td colspan="5" class="empty">No open ports recorded.</td></tr>';
}

async function startScan() {
  $("scan-btn").disabled = true;
  try {
    await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: $("target").value.trim() }),
    });
    pollStatus();
  } catch (e) {
    $("scan-status").textContent = e.message;
    $("scan-btn").disabled = false;
  }
}

function pollStatus() {
  const poll = async () => {
    const s = await api("/api/scan/status");
    if (s.state === "error") {
      $("scan-status").textContent = `error: ${s.error ?? "unknown error"}`;
      $("progress-bar").style.width = "0";
      $("scan-btn").disabled = false;
      return;
    }
    $("scan-status").textContent = `${s.state}${s.hosts_found ? ` — ${s.hosts_found} host(s) found` : ""}`;
    $("progress-bar").style.width = s.state === "running" ? "60%" : s.state === "done" ? "100%" : "0";
    if (s.state === "running") {
      setTimeout(poll, 1000);
      return;
    }
    $("scan-btn").disabled = false;
    if (s.state === "done") await loadAll();
  };
  poll();
}

$("scan-btn").addEventListener("click", startScan);
$("detail-close").addEventListener("click", () => { $("detail").hidden = true; });
document.querySelectorAll("#devices th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort === "ports" ? "ports" : th.dataset.sort;
    sortAsc = sortKey === key ? !sortAsc : true;
    sortKey = key;
    renderDevices();
  });
});

loadAll();

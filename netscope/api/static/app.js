// NetScope frontend: dumb — fetch JSON, render. All logic is server-side.
const $ = (id) => document.getElementById(id);

let devices = [];
let sortKey = "name";
let sortAsc = true;
let detailIdentity = null;
let osDetectionAvailable = true;

async function api(path, options) {
  const res = await fetch(path, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
  return body;
}

// XSS-safe rendering (#32): strings that come from a scan or the DB are
// assigned with textContent, never interpolated into HTML markup. LAN devices
// control hostname/vendor/product strings and they are stored in SQLite, so
// markup in them would otherwise execute script in the UI.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = text ?? "";
  return node;
}

function emptyRow(colspan, text) {
  const tr = document.createElement("tr");
  const td = el("td", "empty", text);
  td.colSpan = colspan;
  tr.appendChild(td);
  return tr;
}

function renderDevices() {
  const rows = [...devices].sort((a, b) => {
    const av = sortKey === "ports" ? a.open_ports.length : a[sortKey] ?? "";
    const bv = sortKey === "ports" ? b.open_ports.length : b[sortKey] ?? "";
    return (av < bv ? -1 : av > bv ? 1 : 0) * (sortAsc ? 1 : -1);
  });
  const tbody = $("devices").querySelector("tbody");
  tbody.replaceChildren();
  if (!rows.length) {
    tbody.appendChild(emptyRow(6, "No devices yet — run a scan."));
    return;
  }
  for (const d of rows) {
    const tr = document.createElement("tr");
    tr.className = "device";
    tr.appendChild(el("td", null, d.name));
    tr.appendChild(el("td", null, d.ip));
    tr.appendChild(el("td", `status-${d.status}`, d.status));
    tr.appendChild(el("td", null, d.os_guess ?? ""));
    tr.appendChild(el("td", null, d.vendor ?? ""));
    tr.appendChild(el("td", "ports", d.open_ports.join(", ")));
    tr.addEventListener("click", () => openDetail(d.identity));
    tbody.appendChild(tr);
  }
}

async function loadOsHint() {
  // #34 polish: the SERVER decides whether the OS column is empty (it owns
  // the inventory); the frontend only renders the sentence. A failed hint
  // must never break the device list, so errors are swallowed.
  try {
    const { hint } = await api("/api/os-hint");
    $("os-hint").textContent = hint ?? "";
    $("os-hint").hidden = !hint;
  } catch {
    $("os-hint").hidden = true;
  }
}

async function loadAll() {
  devices = await api("/api/devices");
  renderDevices();
  await loadOsHint();
  const scans = await api("/api/scans");
  $("scans").replaceChildren(
    ...(scans.length
      ? scans.map((s) =>
          el("li", null, `${s.ts} — ${s.target}${s.duration_seconds ? ` (${s.duration_seconds}s)` : ""}`))
      : [el("li", "empty", "No scans yet.")])
  );
  try {
    const diff = await api("/api/diff");
    const items = [
      ...diff.appeared.map((x) => el("li", "appeared", `${x.name} appeared`)),
      ...diff.disappeared.map((x) => el("li", "disappeared", `${x.name} disappeared`)),
      ...diff.changed.map((x) => el("li", "changed", `${x.name} changed open ports`)),
    ];
    $("changes").replaceChildren(...(items.length ? items : [el("li", "empty", "Nothing changed.")]));
  } catch {
    $("changes").replaceChildren(el("li", "empty", "No comparison available yet."));
  }
}

async function openDetail(identity) {
  const d = await api(`/api/devices/${encodeURIComponent(identity)}`);
  detailIdentity = identity;
  $("detail").hidden = false;
  $("detail-title").textContent = d.name;
  $("detail-fields").replaceChildren(
    ...[
      ["IP", d.ip],
      ["Identity", d.identity],
      ["MAC", d.mac ?? ""],
      ["Vendor", d.vendor ?? ""],
      ["OS guess", d.os_guess ?? ""],
      ["Last seen", d.last_seen_scan ?? ""],
    ].flatMap(([k, v]) => [el("dt", null, k), el("dd", null, v)])
  );
  // Manual name (M8): editable label that beats hostname/vendor in the list.
  $("detail-name").value = d.manual_name ?? "";
  $("name-status").textContent = "";
  $("detail-ports").querySelector("tbody").replaceChildren(
    ...(d.ports.length
      ? d.ports.map((p) => {
          const tr = document.createElement("tr");
          for (const cell of [p.scan_id, p.port, p.protocol, p.service ?? "", p.version ?? ""]) {
            tr.appendChild(el("td", null, cell));
          }
          return tr;
        })
      : [emptyRow(5, "No open ports recorded.")])
  );
}

async function saveName() {
  if (!detailIdentity) return;
  try {
    await api(`/api/devices/${encodeURIComponent(detailIdentity)}/name`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("detail-name").value }),
    });
    $("name-status").textContent = "saved";
    await loadAll();
    await openDetail(detailIdentity);
  } catch (e) {
    $("name-status").textContent = e.message;
  }
}

async function clearName() {
  if (!detailIdentity) return;
  try {
    await api(`/api/devices/${encodeURIComponent(detailIdentity)}/name`, { method: "DELETE" });
    $("name-status").textContent = "cleared";
    await loadAll();
    await openDetail(detailIdentity);
  } catch (e) {
    $("name-status").textContent = e.message;
  }
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

function barWidth(s) {
  // #37: honest progress, not a fixed 60%. Two passes: discovery fills the
  // left half, services the right half.
  if (s.state === "done") return "100%";
  if (s.state !== "running") return "0";
  if (s.phase === "services") {
    // Real denominator now: every discovered host gets fingerprinted.
    const total = s.hosts_found || 1;
    const frac = Math.min(s.hosts_in_phase / total, 1);
    return `${50 + 50 * frac}%`;
  }
  // Discovery: no host denominator exists yet (a /24 has 254 addresses,
  // only N are up), so elapsed-vs-per-pass-limit is the only honest measure.
  if (s.timeout_seconds) {
    const frac = Math.min((s.elapsed_seconds || 0) / s.timeout_seconds, 1);
    return `${50 * frac}%`;
  }
  return "8%"; // limit unknown: a small "working" floor, never a fake number
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
    osDetectionAvailable = s.os_detection_available !== false;
    const limit = s.timeout_seconds ? ` / ${s.timeout_seconds}s limit per pass` : "";
    const osNote = !osDetectionAvailable
      ? " — OS detection unavailable (requires admin/root)"
      : "";
    const phaseLabel =
      s.phase === "discovery" ? "pass 1/2 (discovery)"
      : s.phase === "services" ? "pass 2/2 (services)"
      : "";
    $("scan-status").textContent =
      `${s.state}${phaseLabel ? ` — ${phaseLabel}` : ""}` +
      `${s.elapsed_seconds ? ` — ${s.elapsed_seconds}s${limit}` : ""}` +
      `${s.hosts_found ? ` — ${s.hosts_found} host(s) found` : ""}` +
      osNote;
    $("progress-bar").style.width = barWidth(s);
    if (s.state === "running") {
      setTimeout(poll, 1000);
      return;
    }
    $("scan-btn").disabled = false;
    if (s.state === "done") await loadAll();
  };
  poll();
}

async function prefillTarget() {
  // Default the target to the server's own subnet; a public/unusual network
  // returns null, so the field stays empty and you type the subnet yourself.
  try {
    const { target } = await api("/api/local-subnet");
    if (target && !$("target").value) {
      $("target").value = target;
      $("scan-status").textContent = `target prefilled from this machine: ${target} (/24 assumed)`;
    } else if (!target) {
      $("scan-status").textContent = "could not detect a local subnet — type the target yourself";
    }
  } catch {
    $("scan-status").textContent = "type the target subnet";
  }
}

$("scan-btn").addEventListener("click", startScan);
$("detail-close").addEventListener("click", () => { $("detail").hidden = true; });
$("name-save").addEventListener("click", saveName);
$("name-clear").addEventListener("click", clearName);
document.querySelectorAll("#devices th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort === "ports" ? "ports" : th.dataset.sort;
    sortAsc = sortKey === key ? !sortAsc : true;
    sortKey = key;
    renderDevices();
  });
});

loadAll();
prefillTarget();

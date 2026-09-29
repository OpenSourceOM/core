const nodeColors = {
  Internet: "#ff6b6b",
  Network: "#4dabf7",
  Workload: "#51cf66",
  Identity: "#ffd43b",
  Datastore: "#845ef7",
  Finding: "#ff922b",
  Control: "#868e96",
};

let network = null;
let graphData = { nodes: [], edges: [] };
let lastGraphNodes = [];

async function showBlastRadius(identityID, name) {
  const panel = document.getElementById("blast-radius");
  panel.classList.remove("hidden");
  panel.textContent = "Loading blast radius…";
  try {
    const result = await fetchJSON(`/v1/identity/blast-radius?identity_id=${encodeURIComponent(identityID)}`);
    const items = (result.reachable || []).slice(0, 8).map((n) => `${n.name} (${n.type})`).join(", ");
    panel.innerHTML = `<strong>Blast radius — ${name}</strong><br>${result.summary}${items ? `<br><span class="meta">${items}</span>` : ""}`;
  } catch (err) {
    panel.textContent = `Blast radius failed: ${err.message}`;
  }
}

async function runRules() {
  const btn = document.getElementById("rules-btn");
  btn.disabled = true;
  btn.textContent = "Running rules…";
  try {
    const res = await fetch("/v1/rules/run", { method: "POST", headers: apiHeaders() });
    if (!res.ok) throw new Error(`rules run returned ${res.status}`);
    await refresh();
  } catch (err) {
    alert(`CSPM rules require the API secret: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run CSPM rules";
  }
}

function saveAPIKey() {
  const input = document.getElementById("api-key");
  const key = input.value.trim();

  if (key) {
    localStorage.setItem("om_api_key", key);
  } else {
    localStorage.removeItem("om_api_key");
  }
}

function apiHeaders() {
  const key = localStorage.getItem("om_api_key");
  if (!key) return {};
  return { "X-API-Key": key };
}

async function fetchJSON(path) {
  const res = await fetch(path, { headers: apiHeaders() });
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json();
}

function severityClass(level) {
  return (level || "info").toLowerCase();
}

function renderStats(stats) {
  const el = document.getElementById("stats");
  const cards = [
    ["Nodes", stats.nodes],
    ["Edges", stats.edges],
    ["Findings", stats.by_type?.Finding || 0],
    ["Workloads", stats.by_type?.Workload || 0],
  ];
  el.innerHTML = cards.map(([label, value]) => `
    <div class="stat-card">
      <div class="label">${label}</div>
      <div class="value">${value ?? 0}</div>
    </div>
  `).join("");
}

function renderFindings(findings, partial) {
  const el = document.getElementById("findings");
  const partialNote = partial
    ? "<p class=\"meta\">This list is partial. More findings are past the pages loaded here.</p>"
    : "";
  if (!findings.length) {
    el.innerHTML = "<p class=\"meta\">No findings yet. Run <code>om rules run</code> or <code>om enrich cve</code> after a scan.</p>" + partialNote;
    return;
  }
  el.innerHTML = findings.map((item) => {
    const f = item.finding;
    const props = f.properties || {};
    const severity = props.severity || "info";
    const score = props.normalized_score ?? "";
    return `
      <article class="finding" data-target="${item.affected_resource_id || ""}">
        <span class="severity ${severityClass(severity)}">${severity}${score === "" ? "" : " " + score}</span>
        <div class="title">${f.name}</div>
        <div class="meta">${props.description || props.title || ""}</div>
        <div class="meta">${item.affected_resource_name || "Unknown resource"}</div>
      </article>
    `;
  }).join("") + partialNote;

  el.querySelectorAll(".finding").forEach((card) => {
    card.addEventListener("click", () => highlightNode(card.dataset.target));
  });
}

function toVisNodes(nodes) {
  return nodes.map((n) => ({
    id: n.id,
    label: `${n.name}\n(${n.type})`,
    color: nodeColors[n.type] || "#adb5bd",
    font: { color: "#f8f9fa", size: 12 },
  }));
}

function toVisEdges(edges) {
  return edges.map((e) => ({
    from: e.source_id,
    to: e.target_id,
    label: e.type,
    title: (e.properties && e.properties.reason) || e.type,
    arrows: "to",
    color: { color: "#495057" },
    font: { align: "middle", size: 10, color: "#adb5bd" },
  }));
}

function renderGraph(nodes, edges) {
  lastGraphNodes = nodes;
  const container = document.getElementById("graph");
  graphData = {
    nodes: new vis.DataSet(toVisNodes(nodes)),
    edges: new vis.DataSet(toVisEdges(edges)),
  };
  const options = {
    physics: { stabilization: true },
    interaction: { hover: true },
  };
  network = new vis.Network(container, graphData, options);
  network.on("click", async (params) => {
    if (!params.nodes.length) return;
    const nodeID = params.nodes[0];
    const node = lastGraphNodes.find((n) => n.id === nodeID);
    if (node && node.type === "Identity") {
      await showBlastRadius(node.id, node.name);
    }
  });
}

function highlightNode(nodeID) {
  if (!network || !nodeID) return;
  network.selectNodes([nodeID]);
  network.focus(nodeID, { scale: 1.2, animation: true });
}

async function loadQueries() {
  const data = await fetchJSON("/v1/graph/queries");
  const select = document.getElementById("query-select");
  data.queries.forEach((entry) => {
    const opt = document.createElement("option");
    opt.value = entry.name;
    opt.textContent = `${entry.name} — ${entry.description}`;
    select.appendChild(opt);
  });
  if ([...select.options].some((opt) => opt.value === "internet-to-datastore")) {
    select.value = "internet-to-datastore";
  }
}

function findEdge(edges, sourceID, targetID) {
  return (edges || []).find((edge) => edge.source_id === sourceID && edge.target_id === targetID);
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function renderPathDetail(paths, edges, truncation) {
  const panel = document.getElementById("path-detail");
  if (!paths.length && !truncation) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }
  panel.classList.remove("hidden");
  const note = truncation
    ? `<p class="meta">Results stop at the ${escapeHTML(truncation)}.</p>`
    : "";
  panel.innerHTML = note + paths.map((path, index) => {
    const hops = [];
    for (let i = 1; i < path.length; i++) {
      const edge = findEdge(edges, path[i - 1].id, path[i].id);
      const reason = edge?.properties?.reason || "";
      hops.push(
        `<li><strong>${escapeHTML(path[i - 1].name)} → ${escapeHTML(path[i].name)}</strong> (${escapeHTML(edge?.type || "PATH")})` +
        (reason ? `<br>${escapeHTML(reason)}` : "") +
        `</li>`,
      );
    }
    const names = path.map((node) => escapeHTML(node.name)).join(" → ");
    return `<p><strong>Path ${index + 1}.</strong> ${names}</p><ol>${hops.join("")}</ol>`;
  }).join("");
}

function pathGraph(paths, snapshotEdges) {
  const nodes = [];
  const edges = [];
  const seenNodes = new Set();
  const seenEdges = new Set();
  for (const path of paths) {
    for (let i = 0; i < path.length; i++) {
      const node = path[i];
      if (!seenNodes.has(node.id)) {
        seenNodes.add(node.id);
        nodes.push(node);
      }
      if (i === 0) continue;
      const prev = path[i - 1];
      const key = `${prev.id}->${node.id}`;
      if (seenEdges.has(key)) continue;
      seenEdges.add(key);
      const edge = findEdge(snapshotEdges, prev.id, node.id);
      edges.push(edge || { source_id: prev.id, target_id: node.id, type: "PATH" });
    }
  }
  return { nodes, edges };
}

async function fetchPages(path, listKey) {
  const items = [];
  let cursor = "";
  const maxPages = 50;
  for (let page = 0; page < maxPages; page++) {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    const qs = params.toString();
    const body = await fetchJSON(qs ? `${path}?${qs}` : path);
    items.push(...(body[listKey] || []));
    cursor = body.next_cursor || "";
    if (!cursor) return { items, partial: false };
  }
  return { items, partial: true };
}

function renderPartialGraph(partial) {
  const note = document.getElementById("partial-note");
  if (!partial) {
    note.textContent = "";
    note.classList.add("hidden");
    return;
  }
  note.classList.remove("hidden");
  note.textContent = "This view is partial. More nodes or edges are past the pages loaded here.";
}

async function refresh() {
  const query = document.getElementById("query-select").value;
  const [stats, findingPage, nodePage, edgePage] = await Promise.all([
    fetchJSON("/v1/graph/stats"),
    fetchPages("/v1/findings", "findings"),
    fetchPages("/v1/graph/nodes", "nodes"),
    fetchPages("/v1/graph/edges", "edges"),
  ]);
  renderStats(stats);
  renderFindings(findingPage.items, findingPage.partial);
  renderPartialGraph(nodePage.partial || edgePage.partial);
  const snapshot = { nodes: nodePage.items, edges: edgePage.items };

  if (query) {
    const result = await fetchJSON(`/v1/graph/query?name=${encodeURIComponent(query)}`);
    const paths = result.paths || [];
    renderPathDetail(paths, snapshot.edges, result.truncated ? result.truncation : "");
    const built = pathGraph(paths, snapshot.edges);
    renderGraph(built.nodes, built.edges);
    return;
  }
  document.getElementById("path-detail").classList.add("hidden");
  renderGraph(snapshot.nodes, snapshot.edges);
}

document.getElementById("refresh-btn").addEventListener("click", refresh);
document.getElementById("query-select").addEventListener("change", refresh);
document.getElementById("rules-btn").addEventListener("click", runRules);
document.getElementById("save-api-key-btn").addEventListener("click", saveAPIKey);

(async function init() {
  try {
    await loadQueries();
    await refresh();
  } catch (err) {
    document.body.insertAdjacentHTML("beforeend", `<p style="padding:1rem;color:#ff8787;">Failed to load console: ${err.message}</p>`);
  }
})();

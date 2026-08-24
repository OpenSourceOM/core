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

function renderFindings(findings) {
  const el = document.getElementById("findings");
  if (!findings.length) {
    el.innerHTML = "<p class=\"meta\">No findings yet. Run <code>om rules run</code> or <code>om enrich cve</code> after a scan.</p>";
    return;
  }
  el.innerHTML = findings.map((item) => {
    const f = item.finding;
    const props = f.properties || {};
    const severity = props.severity || "info";
    return `
      <article class="finding" data-target="${item.affected_resource_id || ""}">
        <span class="severity ${severityClass(severity)}">${severity}</span>
        <div class="title">${f.name}</div>
        <div class="meta">${props.title || ""}</div>
        <div class="meta">${item.affected_resource_name || "Unknown resource"}</div>
      </article>
    `;
  }).join("");

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
}

async function loadGraphSnapshot() {
  const snapshot = await fetchJSON("/v1/graph/snapshot");
  renderGraph(snapshot.nodes, snapshot.edges);
}

async function loadPathQuery(name) {
  const result = await fetchJSON(`/v1/graph/query?name=${encodeURIComponent(name)}`);
  const nodes = [];
  const edges = [];
  const seenNodes = new Set();
  const seenEdges = new Set();

  for (const path of result.paths || []) {
    for (let i = 0; i < path.length; i++) {
      const node = path[i];
      if (!seenNodes.has(node.id)) {
        seenNodes.add(node.id);
        nodes.push(node);
      }
      if (i > 0) {
        const prev = path[i - 1];
        const key = `${prev.id}->${node.id}`;
        if (!seenEdges.has(key)) {
          seenEdges.add(key);
          edges.push({
            source_id: prev.id,
            target_id: node.id,
            type: "PATH",
          });
        }
      }
    }
  }
  renderGraph(nodes, edges);
}

async function refresh() {
  const [stats, findings] = await Promise.all([
    fetchJSON("/v1/graph/stats"),
    fetchJSON("/v1/findings"),
  ]);
  renderStats(stats);
  renderFindings(findings);

  const query = document.getElementById("query-select").value;
  if (query) {
    await loadPathQuery(query);
  } else {
    await loadGraphSnapshot();
  }
}

document.getElementById("refresh-btn").addEventListener("click", refresh);
document.getElementById("query-select").addEventListener("change", refresh);
document.getElementById("rules-btn").addEventListener("click", runRules);

(async function init() {
  try {
    await loadQueries();
    await refresh();
  } catch (err) {
    document.body.insertAdjacentHTML("beforeend", `<p style="padding:1rem;color:#ff8787;">Failed to load console: ${err.message}</p>`);
  }
})();

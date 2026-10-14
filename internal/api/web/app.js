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
let currentAdmin = null;

const providerLabels = { google: "Google", github: "GitHub" };
const authErrors = {
  not_admin: "This Google or GitHub account is not an admin. Sign in with the email and password for an existing admin.",
  email_unverified: "The provider has not verified an email address for this account.",
  oauth_denied: "The sign-in was canceled.",
  oauth_state: "The sign-in session expired. Try again.",
  oauth_failed: "Sign-in failed. Try again.",
  provider_unconfigured: "That sign-in provider is not configured on this server.",
};

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
    await fetchJSON("/v1/rules/run", { method: "POST" });
    await refresh();
  } catch (err) {
    showConsoleError(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run CSPM rules";
  }
}

async function readError(res) {
  try {
    const body = await res.json();
    if (body && body.code === "schema_not_ready") res.schemaNotReady = true;
    if (body && body.error) return body.error;
  } catch (err) {
    return `request returned ${res.status}`;
  }
  return `request returned ${res.status}`;
}

async function fetchJSON(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    const error = new Error(await readError(res));
    error.status = res.status;
    if (res.schemaNotReady) error.schemaNotReady = true;
    throw error;
  }
  if (res.status === 204) return null;
  return res.json();
}

function isUnauthorized(err) {
  return err && err.status === 401;
}

function showConsoleError(err) {
  if (err && err.schemaNotReady) {
    const banner = document.getElementById("console-error");
    banner.textContent = err.message;
    banner.classList.remove("hidden");
    return;
  }
  if (isUnauthorized(err)) {
    fetchJSON("/v1/auth/session").then((session) => {
      renderGate(session);
      document.getElementById("gate-message").textContent = "Your session ended. Sign in again.";
    }).catch(() => {
      showSignedOut("Your session ended. Sign in again.");
    });
    return;
  }
  const banner = document.getElementById("console-error");
  banner.textContent = `Failed to load console: ${err.message}`;
  banner.classList.remove("hidden");
}

function clearConsoleError() {
  const banner = document.getElementById("console-error");
  banner.textContent = "";
  banner.classList.add("hidden");
}

function showToken(token, message) {
  const banner = document.getElementById("token-banner");
  const field = document.getElementById("token-value");
  banner.querySelector("p").textContent = message || "This is your API token. Copy it now. It will not be shown again.";
  field.value = token;
  banner.classList.remove("hidden");
  field.focus();
  field.select();
}

function adminLabel(admin) {
  const who = admin.login || admin.name || "Admin";
  const via = providerLabels[admin.provider] || admin.provider;
  return `${who} · ${via}`;
}

function showSignedOut(message) {
  currentAdmin = null;
  document.getElementById("console").classList.add("hidden");
  document.getElementById("stats").classList.add("hidden");
  document.getElementById("account").classList.add("hidden");
  document.getElementById("admins-panel").classList.add("hidden");
  document.getElementById("security-panel").classList.add("hidden");
  document.getElementById("token-banner").classList.add("hidden");
  const gate = document.getElementById("gate");
  gate.classList.remove("hidden");
  document.getElementById("gate-title").textContent = "Sign in";
  document.getElementById("gate-message").textContent = message;
  document.getElementById("gate-actions").replaceChildren();
}

function renderGate(session) {
  const params = new URLSearchParams(window.location.search);
  const errorCode = params.get("error");
  const providers = session.providers || [];
  const gate = document.getElementById("gate");
  gate.classList.remove("hidden");
  document.getElementById("console").classList.add("hidden");
  document.getElementById("stats").classList.add("hidden");
  document.getElementById("account").classList.add("hidden");

  let title = "Sign in";
  let message = "Sign in with the email and password for an admin account.";
  if (!session.login_enabled) {
    title = "Console login is not available";
    message = "The API process does not have an admin store.";
  } else if (params.get("totp") === "1") {
    title = "Two-factor authentication";
    message = "Enter the code from your authenticator app, or a recovery code.";
  } else if (session.needs_setup) {
    title = "Create the admin account";
    message = "Choose an email and password. Whoever can open this page first becomes the admin, so keep the port private until you finish.";
  }

  if (errorCode && authErrors[errorCode]) {
    message = authErrors[errorCode];
  }
  document.getElementById("gate-title").textContent = title;
  document.getElementById("gate-message").textContent = message;

  const actions = document.getElementById("gate-actions");
  actions.replaceChildren();
  if (!session.login_enabled) return;
  if (params.get("totp") === "1") {
    actions.appendChild(totpForm());
    return;
  }
  if (session.needs_setup) {
    actions.appendChild(setupForm(session.setup_email || ""));
    return;
  }
  actions.appendChild(loginForm());
  providers.forEach((provider) => {
    const link = document.createElement("a");
    link.className = "button";
    link.href = `/auth/${provider}/start`;
    link.textContent = `Sign in with ${providerLabels[provider] || provider}`;
    actions.appendChild(link);
  });
}

function field(type, name, label, value) {
  const input = document.createElement("input");
  input.type = type;
  input.name = name;
  input.required = true;
  input.autocomplete = type === "password" ? "current-password" : "username";
  input.setAttribute("aria-label", label);
  input.placeholder = label;
  if (value) {
    input.value = value;
    input.readOnly = true;
  }
  return input;
}

function formStatus() {
  const status = document.createElement("p");
  status.className = "meta";
  return status;
}

function setupForm(pinnedEmail) {
  const form = document.createElement("form");
  form.className = "auth-form";
  const email = field("email", "email", "Email", pinnedEmail);
  const password = field("password", "password", "Password");
  password.autocomplete = "new-password";
  password.minLength = 12;
  const confirm = field("password", "confirm", "Confirm password");
  confirm.autocomplete = "new-password";
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Create admin";
  const status = formStatus();
  form.append(email, password, confirm, submit, status);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (password.value !== confirm.value) {
      status.textContent = "Passwords do not match.";
      return;
    }
    submit.disabled = true;
    try {
      await fetchJSON("/v1/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.value, password: password.value }),
      });
      window.location.href = "/";
    } catch (err) {
      status.textContent = err.message;
      submit.disabled = false;
    }
  });
  return form;
}

function loginForm() {
  const form = document.createElement("form");
  form.className = "auth-form";
  const email = field("email", "email", "Email");
  const password = field("password", "password", "Password");
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Sign in";
  const status = formStatus();
  form.append(email, password, submit, status);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    try {
      const result = await fetchJSON("/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.value, password: password.value }),
      });
      if (result && result.totp_required) {
        window.location.href = "/login?totp=1";
        return;
      }
      window.location.href = "/";
    } catch (err) {
      status.textContent = err.message;
      submit.disabled = false;
    }
  });
  return form;
}

function totpForm() {
  const form = document.createElement("form");
  form.className = "auth-form";
  const code = field("text", "code", "Authentication code");
  code.autocomplete = "one-time-code";
  code.required = true;
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Continue";
  const status = formStatus();
  form.append(code, submit, status);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    try {
      await fetchJSON("/v1/auth/totp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: code.value }),
      });
      window.location.href = "/";
    } catch (err) {
      status.textContent = err.message;
      submit.disabled = false;
    }
  });
  return form;
}

function renderPasswordChange() {
  document.getElementById("console").classList.add("hidden");
  document.getElementById("stats").classList.add("hidden");
  document.getElementById("account").classList.add("hidden");
  const gate = document.getElementById("gate");
  gate.classList.remove("hidden");
  document.getElementById("gate-title").textContent = "Choose a new password";
  document.getElementById("gate-message").textContent = "This temporary password works once. Set a password only you know.";
  const form = document.createElement("form");
  form.className = "auth-form";
  const current = field("password", "current", "Temporary password");
  const next = field("password", "next", "New password");
  next.autocomplete = "new-password";
  next.minLength = 12;
  const confirm = field("password", "confirm", "Confirm password");
  confirm.autocomplete = "new-password";
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Save password";
  const status = formStatus();
  form.append(current, next, confirm, submit, status);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (next.value !== confirm.value) {
      status.textContent = "Passwords do not match.";
      return;
    }
    submit.disabled = true;
    try {
      await fetchJSON("/v1/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current: current.value, next: next.value }),
      });
      window.location.href = "/";
    } catch (err) {
      status.textContent = err.message;
      submit.disabled = false;
    }
  });
  document.getElementById("gate-actions").replaceChildren(form);
}

function showConsole(session) {
  currentAdmin = session.admin;
  if (session.admin && session.admin.must_change_password) {
    renderPasswordChange();
    return;
  }
  document.getElementById("gate").classList.add("hidden");
  document.getElementById("console").classList.remove("hidden");
  document.getElementById("stats").classList.remove("hidden");
  const account = document.getElementById("account");
  account.classList.remove("hidden");
  document.getElementById("account-label").textContent = adminLabel(session.admin);
  if (window.location.pathname !== "/") {
    window.history.replaceState({}, "", "/");
  }
  if (session.api_token) showToken(session.api_token);
}

async function renderAdmins() {
  const panel = document.getElementById("admins-panel");
  panel.classList.remove("hidden");
  const data = await fetchJSON("/v1/admins");
  panel.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent = "Admins";
  panel.appendChild(heading);
  const intro = document.createElement("p");
  intro.className = "meta";
  intro.textContent = "Every admin can run the console. Add another person by email. They get a temporary password and choose their own at the next sign-in.";
  panel.appendChild(intro);

  const list = document.createElement("ul");
  (data.admins || []).forEach((admin) => {
    const row = document.createElement("li");
    row.className = "admin-row";
    const label = document.createElement("span");
    label.textContent = adminLabel(admin);
    row.appendChild(label);
    if ((data.admins || []).length > 1) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => removeAdmin(admin.id));
      row.appendChild(remove);
    }
    list.appendChild(row);
  });
  panel.appendChild(list);

  const form = document.createElement("form");
  form.className = "invite-form";
  const email = document.createElement("input");
  email.type = "email";
  email.required = true;
  email.placeholder = "ada@example.com";
  email.setAttribute("aria-label", "Email");
  const send = document.createElement("button");
  send.type = "submit";
  send.textContent = "Add admin";
  form.append(email, send);
  const status = document.createElement("p");
  status.className = "meta invite-status";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    send.disabled = true;
    try {
      const created = await fetchJSON("/v1/admins", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.value }),
      });
      status.textContent = created.emailed
        ? `Temporary password emailed to ${created.email}. Copy it as well. It is shown once.`
        : `Copy the temporary password for ${created.email}. It is shown once.`;
      showToken(created.password, "Temporary password. Copy it now. It will not be shown again.");
      email.value = "";
    } catch (err) {
      status.textContent = err.message;
    } finally {
      send.disabled = false;
    }
  });
  panel.append(form, status);

  const rotate = document.createElement("button");
  rotate.type = "button";
  rotate.textContent = "Rotate API token";
  rotate.addEventListener("click", async () => {
    rotate.disabled = true;
    try {
      const created = await fetchJSON("/v1/admins/token", { method: "POST" });
      showToken(created.token);
    } catch (err) {
      showConsoleError(err);
    } finally {
      rotate.disabled = false;
    }
  });
  panel.appendChild(rotate);
}

async function removeAdmin(id) {
  const res = await fetch(`/v1/admins/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (res.status === 409) {
    return;
  }
  if (!res.ok) throw new Error(await readError(res));
  if (currentAdmin && currentAdmin.id === id) {
    window.location.href = "/login";
    return;
  }
  await renderAdmins();
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
    const pathLine = Array.isArray(item.path) && item.path.length
      ? `<div class="meta">${item.path.map((id) => escapeHTML(id)).join(" → ")}</div>`
      : "";
    return `
      <article class="finding" data-target="${item.affected_resource_id || ""}">
        <span class="severity ${severityClass(severity)}">${severity}${score === "" ? "" : " " + score}</span>
        <div class="title">${f.name}</div>
        <div class="meta">${props.description || props.title || ""}</div>
        ${pathLine}
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
  const previous = select.value;
  const keepSelection = select.dataset.loaded === "1";
  select.replaceChildren();
  const full = document.createElement("option");
  full.value = "";
  full.textContent = "Full graph snapshot";
  select.appendChild(full);
  data.queries.forEach((entry) => {
    const opt = document.createElement("option");
    opt.value = entry.name;
    opt.textContent = `${entry.name} — ${entry.description}`;
    select.appendChild(opt);
  });
  const preferred = keepSelection ? previous : "internet-to-datastore";
  if ([...select.options].some((opt) => opt.value === preferred)) {
    select.value = preferred;
  }
  select.dataset.loaded = "1";
}

async function loadConsole() {
  clearConsoleError();
  await loadQueries();
  await refresh();
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

function auditsForPath(audits, index) {
  const row = (audits || []).find((item) => item.index === index);
  return row?.events || [];
}

function renderPathDetail(paths, edges, truncation, audits) {
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
    const events = auditsForPath(audits, index).map((event) => {
      const bits = [event.time, event.name, event.principal, event.resource].filter(Boolean);
      return `<li>${escapeHTML(bits.join(" "))}</li>`;
    }).join("");
    const eventList = events ? `<p class="meta">CloudTrail</p><ul>${events}</ul>` : "";
    const names = path.map((node) => escapeHTML(node.name)).join(" → ");
    return `<p><strong>Path ${index + 1}.</strong> ${names}</p><ol>${hops.join("")}</ol>${eventList}`;
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
    renderPathDetail(paths, snapshot.edges, result.truncated ? result.truncation : "", result.audits);
    const built = pathGraph(paths, snapshot.edges);
    renderGraph(built.nodes, built.edges);
    return;
  }
  document.getElementById("path-detail").classList.add("hidden");
  renderGraph(snapshot.nodes, snapshot.edges);
}

document.getElementById("refresh-btn").addEventListener("click", () => {
  loadConsole().catch(showConsoleError);
});
document.getElementById("query-select").addEventListener("change", () => {
  refresh().catch(showConsoleError);
});
document.getElementById("rules-btn").addEventListener("click", runRules);
document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch("/v1/auth/logout", { method: "POST" });
  window.location.href = "/login";
});
async function renderSecurity() {
  const panel = document.getElementById("security-panel");
  panel.classList.remove("hidden");
  panel.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent = "Two-factor authentication";
  const intro = document.createElement("p");
  intro.className = "meta";
  intro.textContent = currentAdmin && currentAdmin.totp_enabled
    ? "An authenticator code is required at sign-in. Recovery codes were shown when you turned this on."
    : "Optional. Use an authenticator app. Recovery codes are shown once when you turn this on.";
  panel.append(heading, intro);
  if (currentAdmin && currentAdmin.totp_enabled) {
    const form = document.createElement("form");
    form.className = "auth-form";
    const password = field("password", "password", "Password");
    const code = field("text", "code", "Authentication code");
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.textContent = "Turn off";
    const status = formStatus();
    form.append(password, code, submit, status);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await fetchJSON("/v1/auth/totp/disable", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: password.value, code: code.value }),
        });
        currentAdmin.totp_enabled = false;
        await renderSecurity();
      } catch (err) {
        status.textContent = err.message;
      }
    });
    panel.appendChild(form);
    return;
  }
  const start = document.createElement("button");
  start.type = "button";
  start.textContent = "Turn on";
  const status = formStatus();
  start.addEventListener("click", async () => {
    start.disabled = true;
    try {
      const begun = await fetchJSON("/v1/auth/totp/setup", { method: "POST" });
      const form = document.createElement("form");
      form.className = "auth-form";
      const secret = document.createElement("input");
      secret.readOnly = true;
      secret.value = begun.secret;
      secret.setAttribute("aria-label", "Authenticator secret");
      const code = field("text", "code", "Authentication code");
      const submit = document.createElement("button");
      submit.type = "submit";
      submit.textContent = "Confirm";
      form.append(secret, code, submit);
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const confirmed = await fetchJSON("/v1/auth/totp/confirm", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: code.value }),
        });
        currentAdmin.totp_enabled = true;
        showToken((confirmed.recovery_codes || []).join("\n"), "Recovery codes. Copy them now. They will not be shown again.");
        await renderSecurity();
      });
      panel.append(form, status);
    } catch (err) {
      status.textContent = err.message;
      start.disabled = false;
    }
  });
  panel.append(start, status);
}

document.getElementById("security-btn").addEventListener("click", () => {
  const panel = document.getElementById("security-panel");
  if (!panel.classList.contains("hidden")) {
    panel.classList.add("hidden");
    return;
  }
  renderSecurity().catch(showConsoleError);
});
document.getElementById("admins-btn").addEventListener("click", () => {
  const panel = document.getElementById("admins-panel");
  if (!panel.classList.contains("hidden")) {
    panel.classList.add("hidden");
    return;
  }
  renderAdmins().catch(showConsoleError);
});

(async function init() {
  localStorage.removeItem("om_api_key");
  try {
    const session = await fetchJSON("/v1/auth/session");
    if (session.authenticated) {
      showConsole(session);
      await loadConsole();
      return;
    }
    renderGate(session);
  } catch (err) {
    renderGate({ login_enabled: false, providers: [], needs_setup: false });
    document.getElementById("gate-message").textContent = err.message;
  }
})();

// trafficam window. Plain JavaScript, no libraries, no network access beyond
// this page's own server. All text from the network is inserted with
// textContent, never as HTML.
"use strict";

const STAGES = [
  ["Listening", 0, "Learning how your programs normally use the network. Only the always-alert rules (known-bad and your watch list) can alert."],
  ["Settling in", 4, "Habits are forming. New programs and new destinations for quiet programs can alert."],
  ["Watching", 11, "The model now judges new behaviour against each program's own habits."],
  ["Guarding", 30, "A full month of habits is known. This is trafficam at full strength."],
];

const $ = (id) => document.getElementById(id);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

async function api(path, opts = {}) {
  const init = { credentials: "same-origin", headers: {} };
  if (opts.post) {
    init.method = "POST";
    init.headers["X-Trafficam"] = "1";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body || {});
  }
  const r = await fetch(path, init);
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r.json();
}

// ---- tabs
let current = "progress";
function show(tab) {
  current = tab;
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  document.querySelectorAll(".tab").forEach((s) => (s.hidden = s.id !== "tab-" + tab));
  refresh();
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => show(b.dataset.tab)));

// ---- progress
function renderStatus(st) {
  $("offline").hidden = true;
  $("live-dot").classList.add("on");
  const r = st.ramp || {};
  $("stage").textContent = r.stage || "Listening";
  const meaning = STAGES.find((s) => s[0] === r.stage);
  $("stage-meaning").textContent = meaning ? meaning[2] : "";
  const ramp = $("ramp");
  ramp.replaceChildren();
  STAGES.forEach(([name, from], i) => {
    const li = el("li", i < r.index ? "done" : i === r.index ? "now" : "");
    li.append(el("b", "", name), document.createTextNode(i === 3 ? "day 30 on" : `days ${from}–${STAGES[i + 1][1] - 1}`));
    ramp.append(li);
  });
  const pct = Math.round(r.percent || 0);
  $("bar-fill").style.width = pct + "%";
  $("bar").setAttribute("aria-valuenow", String(pct));
  $("bar-text").textContent = r.next_name
    ? `Day ${r.day} of 30 · ${pct}% learned · ${r.next_name} starts in ${r.next_in} day${r.next_in === 1 ? "" : "s"}`
    : `Day ${r.day} · fully learned`;
  $("s-flows").textContent = (st.flows || 0).toLocaleString();
  const u = $("unread");
  u.hidden = !st.unread;
  u.textContent = st.unread || "";
  document.title = st.unread ? `(${st.unread}) trafficam` : "trafficam";
  $("tamper").hidden = !st.tamper;
  $("tamper-text").textContent = st.tamper ? st.tamper.split("\n")[0] : "";
}

async function loadProgress() {
  const l = await api("/api/learning");
  $("s-programs").textContent = l.programs.toLocaleString();
  $("s-dests").textContent = l.destinations.toLocaleString();
  $("s-week").textContent = l.alerts_week.toLocaleString();
}

// ---- alerts
function when(t) {
  const d = new Date(t);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function renderAlert(a) {
  const card = el("div", "card alert" + (a.state !== "new" ? " handled" : ""));
  const left = el("div");
  const prog = a.program + (a.service ? ` (${a.service})` : "");
  left.append(el("div", "what", a.dir === "in" ? `${prog} accepted a connection from ${a.host || a.ip}` : `${prog} contacted ${a.host || a.ip}`));
  const ul = el("ul");
  (a.reasons || []).forEach((r) => ul.append(el("li", "", r)));
  left.append(ul);
  const meta = [when(a.at)];
  if (a.count > 1) meta[0] += ` (and ${a.count - 1} more time${a.count > 2 ? "s" : ""}, last ${when(a.last_at)})`;
  meta.push(`${(a.proto || "").toUpperCase()} port ${a.port}`);
  if (a.ip && a.ip !== a.host) meta.push(a.ip);
  if (a.country) meta.push(a.country);
  if (a.path) meta.push(a.path);
  left.append(el("div", "meta", meta.join(" · ")));
  const right = el("div", "actions");
  if (a.state === "new") {
    const ok = el("button", "primary", "OK");
    ok.title = "I know about this";
    ok.addEventListener("click", () => act(a.id, "ok", card));
    right.append(ok);
    // Known-bad and watch-list alerts can't be silenced by the ignore list.
    if (!(a.reasons || []).some((r) => /known-bad list|your watch list/.test(r))) {
      const mute = el("button", "", "Don't show again");
      mute.title = "Add this program and destination to the ignore list";
      mute.addEventListener("click", () => act(a.id, "mute", card));
      right.append(mute);
    }
  } else {
    right.append(el("span", "pill", a.state === "muted" ? "Muted" : "OK"));
  }
  card.append(left, right);
  return card;
}

async function act(id, action, card) {
  card.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    await api(`/api/alerts/${id}/${action}`, { post: true });
  } catch (e) {
    card.querySelector(".error")?.remove();
    card.append(el("p", "error", e.message));
    card.querySelectorAll("button").forEach((b) => (b.disabled = false));
    return; // keep the message on screen
  }
  refresh();
}

async function loadAlerts() {
  const all = $("show-all").checked;
  const list = await api("/api/alerts" + (all ? "?show=all" : ""));
  list.reverse(); // newest first
  $("alerts").replaceChildren(...list.map(renderAlert));
  $("alerts-empty").hidden = list.length > 0;
}
$("show-all").addEventListener("change", () => loadAlerts().catch(offline));

// ---- lists
function ruleItem(r, removable) {
  const li = el("li");
  const t = el("span", "", r.pattern === "*" ? `Every destination of ${r.program}` : r.pattern + (r.program ? `  (only ${r.program})` : ""));
  if (r.note) t.append(el("span", "note", r.note));
  li.append(t);
  if (removable) {
    const b = el("button", "", "Remove");
    b.addEventListener("click", async () => {
      b.disabled = true;
      try { renderLists(await api("/api/lists/ignore/remove", { post: true, body: { pattern: r.pattern, program: r.program || "" } })); }
      catch (e) { li.append(el("span", "error", e.message)); b.disabled = false; }
    });
    li.append(b);
  }
  return li;
}
function renderLists(l) {
  const fill = (ul, rules, removable) => {
    ul.replaceChildren(...rules.map((r) => ruleItem(r, removable)));
    if (!rules.length) ul.append(el("li", "none", "Empty"));
  };
  fill($("watch"), l.watch, false);
  fill($("ignore"), l.ignore, true);
}
$("watch-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("watch-error");
  err.hidden = true;
  try {
    const program = $("w-program").value.trim();
    // An empty destination with a program means "everything this program does".
    const pattern = $("w-pattern").value.trim() || (program ? "*" : "");
    renderLists(await api("/api/lists/watch/add", { post: true, body: { pattern, program } }));
    $("w-pattern").value = "";
    $("w-program").value = "";
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
});

// ---- self-check
async function loadCheck() {
  const rs = await api("/api/check");
  const icons = { pass: "✓", warn: "!", fail: "✗" };
  $("checks").replaceChildren(...rs.map((r) => {
    const li = el("li", r.level);
    li.append(el("span", "icon", icons[r.level] || "?"));
    const body = el("div");
    body.append(el("b", "", r.name + ". "), document.createTextNode(r.detail));
    li.append(body);
    if (r.fix) li.append(el("div", "fix", r.fix));
    return li;
  }));
}
$("recheck").addEventListener("click", () => loadCheck().catch(offline));

// ---- refresh loop
function offline() {
  $("offline").hidden = false;
  $("live-dot").classList.remove("on");
}
async function refresh() {
  try {
    renderStatus(await api("/api/status"));
    if (current === "progress") await loadProgress();
    if (current === "alerts") await loadAlerts();
    if (current === "lists") renderLists(await api("/api/lists"));
    if (current === "check") await loadCheck();
  } catch (e) {
    if (current === "check") loadCheck().catch(() => {}); // the check explains what's wrong
    offline();
  }
}
const hash = location.hash.slice(1);
show(["progress", "alerts", "lists", "check"].includes(hash) ? hash : "progress");
// Refresh every 10 s, but not while the user is reading an error or typing.
setInterval(() => {
  if (document.hidden || current === "lists" || document.querySelector(".alert .error")) return;
  refresh();
}, 10000);

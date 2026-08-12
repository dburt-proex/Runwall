/* Runwall operator console.
   Plain ES modules-free JS. No framework, no build, no CDN: the console has to
   load when the rest of the machine is in a bad state, and a bundler in that
   path is one more thing that can be broken or tampered with. */

(() => {
  "use strict";

  const $ = (s) => document.querySelector(s);
  const el = (t, c, txt) => { const n = document.createElement(t); if (c) n.className = c; if (txt != null) n.textContent = txt; return n; };
  const esc = (s) => String(s ?? "");

  const S = { token: null, operator: null, sitekey: "", status: null, feed: [], es: null, view: "perimeter" };

  // ---- transport ---------------------------------------------------------
  async function api(path, opts = {}) {
    const r = await fetch(path, {
      ...opts,
      headers: { "Content-Type": "application/json", ...(S.token ? { Authorization: "Bearer " + S.token } : {}), ...(opts.headers || {}) },
    });
    let body = null;
    try { body = await r.json(); } catch { body = {}; }
    if (r.status === 401) { signOut(); throw new Error(body.error || "not authenticated"); }
    if (!r.ok) { const e = new Error(body.message || body.error || `HTTP ${r.status}`); e.payload = body; e.status = r.status; throw e; }
    return body;
  }
  const post = (p, b) => api(p, { method: "POST", body: JSON.stringify(b || {}) });

  // ---- auth --------------------------------------------------------------
  async function signIn() {
    const err = $("#loginErr");
    err.classList.add("hide");
    try {
      const r = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({ operator_id: $("#op").value.trim(), password: $("#pw").value, totp: $("#tp").value.trim() }),
      });
      S.token = r.token; S.operator = $("#op").value.trim(); S.sitekey = r.sitekey || "";
      sessionStorage.setItem("rw", JSON.stringify({ t: S.token, o: S.operator, k: S.sitekey }));
      $("#pw").value = ""; $("#tp").value = "";
      start();
    } catch (e) {
      err.textContent = e.message || "authentication failed";
      err.classList.remove("hide");
    }
  }

  function signOut() {
    S.token = null; sessionStorage.removeItem("rw");
    if (S.es) { S.es.close(); S.es = null; }
    $("#app").classList.add("hide"); $("#login").classList.remove("hide");
  }

  /* Step-up is asked for at the moment of the privileged decision, not banked
     at login. A code entered ten minutes ago proves nothing about who is at the
     keyboard now. */
  async function stepUp(why) {
    const code = prompt(`${why}\n\nEnter your current authenticator code:`);
    if (!code) return false;
    try { await post("/auth/stepup", { totp: code.trim() }); return true; }
    catch (e) { alert("Step-up failed: " + e.message); return false; }
  }

  // ---- rendering ---------------------------------------------------------
  function setView(v) {
    S.view = v;
    document.querySelectorAll("[data-panel]").forEach((p) => p.classList.toggle("hide", p.dataset.panel !== v));
    document.querySelectorAll("#nav button").forEach((b) => b.setAttribute("aria-current", String(b.dataset.view === v)));
    if (v === "approvals") loadApprovals();
    if (v === "ledger") loadLedger();
    if (v === "policy") loadPolicy();
    if (v === "sessions") loadSessions();
    if (v === "tunnel") $("#feedCount").classList.add("hide");
  }

  function renderStatus(st) {
    S.status = st;
    const p = st.perimeter, s = p.state;
    $("#ver").textContent = "v" + st.version;
    $("#stateChip").className = "chip s-" + s;
    $("#stateText").textContent = s;
    $("#posture").textContent = "posture: " + st.posture;

    const armed = s === "ARMED";
    $("#armSwitch").dataset.on = String(armed);
    $("#switchTitle").textContent =
      { ARMED: "Armed", DEGRADED: "Degraded", SAFE: "Safe — read-only", DISARMED: "Disarmed" }[s] || s;
    $("#switchSub").textContent = p.reasons.length
      ? p.reasons.join(" · ")
      : "Full mediation. Every instrumented tool call is evaluated before it runs.";

    // banners
    const b = $("#banners"); b.innerHTML = "";
    if (!st.policy.pinned) {
      const bad = st.policy.pin_message.includes("MISMATCH");
      b.append(banner(bad ? "bad" : "warn", (bad ? "Policy hash mismatch. " : "Policy is unpinned. ") + st.policy.pin_message +
        (bad ? "" : " Run `runwall pin` to record the current hash.")));
    }
    if (!st.ledger.chain_ok) b.append(banner("bad", "Ledger chain verification FAILED: " + (st.ledger.problems[0] || "")));
    if (p.disarm) b.append(banner("bad", `Perimeter disarmed by ${p.disarm.operator} — ${p.disarm.remaining_s}s remaining — scope: ${p.disarm.scope || "<all>"} — “${p.disarm.reason}”`));
    if (st.approvals.rubber_stamp_risk) b.append(banner("warn", `Median approval latency ${st.approvals.median_latency_s}s. Approvals in this window are low-assurance — the cards are not being read.`));
    if (p.spooled_events) b.append(banner("warn", `${p.spooled_events} events were recorded while the governor was unreachable and have been ingested behind a gap marker.`));

    // nav badges
    const q = st.approvals.pending + st.approvals.suspended;
    $("#apCount").textContent = q; $("#apCount").classList.toggle("hide", q === 0);

    // stats
    const g = $("#stats"); g.innerHTML = "";
    [["Decisions", st.decisions, "since start"],
     ["Ledger events", st.ledger.events, st.ledger.chain_ok ? "chain intact" : "CHAIN BROKEN"],
     ["Awaiting you", q, `${st.approvals.approved} approved · ${st.approvals.denied} denied`],
     ["Live grants", st.approvals.live_grants, "scoped + time-boxed"],
     ["Gated actions", st.policy.actions, `${st.policy.halt_patterns} halt patterns`],
     ["Operator", st.operator_present ? "present" : "absent", st.operator_present ? "REVIEW can block" : "REVIEW resolves to refusal"],
    ].forEach(([k, v, s2]) => {
      const c = el("div", "card stat");
      c.append(el("div", "k", k), el("div", "v", String(v)), el("div", "s", s2));
      g.append(c);
    });
  }

  const banner = (kind, text) => el("div", "banner " + kind, text);

  // ---- feed --------------------------------------------------------------
  function pushFeed(d) {
    S.feed.unshift(d);
    if (S.feed.length > 300) S.feed.pop();
    const f = $("#feed");
    const row = el("div", "row new");
    const cell = el("span");
    cell.append(el("span", "tag r-" + d.route, d.route));
    row.append(cell,
      el("span", "", d.action),
      el("span", "sum", d.summary || d.tool),
      el("span", "meta", `${d.score || 0} · ${d.latency_ms || 0}ms`));
    f.prepend(row);
    while (f.children.length > 300) f.lastChild.remove();
    if (S.view !== "tunnel") {
      const n = $("#feedCount");
      n.textContent = String((parseInt(n.textContent, 10) || 0) + 1);
      n.classList.remove("hide");
    }
  }

  function connectSSE() {
    if (S.es) S.es.close();
    // EventSource cannot set an Authorization header, so the session token is
    // passed as a query parameter on this endpoint only. It never leaves
    // loopback and the daemon binds 127.0.0.1.
    const es = new EventSource("/api/events?token=" + encodeURIComponent(S.token));
    S.es = es;
    es.onopen = () => { $("#sseState").textContent = "live"; };
    es.onerror = () => { $("#sseState").textContent = "reconnecting"; };
    es.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.kind === "decision") pushFeed(m.data);
      else if (m.kind === "approval_opened" || m.kind === "approval_suspended") { refresh(); if (S.view === "approvals") loadApprovals(); }
      else if (m.kind === "approval_resolved") { if (S.view === "approvals") loadApprovals(); refresh(); }
      else if (m.kind === "state_changed") refresh();
    };
  }

  // ---- approvals ---------------------------------------------------------
  async function loadApprovals() {
    const wrap = $("#apList");
    let r; try { r = await api("/api/queue"); } catch { return; }
    wrap.innerHTML = "";
    if (!r.queue.length) {
      wrap.append(banner("ok", "Nothing waiting. Blocked calls appear here with their blast radius."));
      if (r.grants.length) {
        const c = el("div", "card"); c.style.marginTop = "14px";
        c.append(el("h3", "", "Live grants"));
        r.grants.forEach((g) => c.append(el("div", "pill", `${g.operator} · ${g.remaining_s}s · ${g.uses_left} use(s) · ${g.reason}`)));
        wrap.append(c);
      }
      return;
    }
    r.queue.forEach((a) => wrap.append(approvalCard(a)));
  }

  function approvalCard(a) {
    const high = !!(a.blast && a.blast.is_high);
    const c = el("div", "card ap" + (high ? " high" : ""));
    const hd = el("div"); hd.style.cssText = "display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap";
    hd.append(el("h3", "", `${a.action}  ·  ${a.tool}`),
      el("span", "pill" + (high ? " hot" : ""), high ? "HIGH BLAST RADIUS" : "standard"));
    c.append(hd);
    c.append(el("div", "cmd", a.summary));

    const b = a.blast || {}, pills = el("div", "blast");
    [["scope", b.scope], ["reversibility", b.reversibility], ["propagation", b.propagation],
     ["subjects", b.subjects_affected === -1 ? "unbounded" : b.subjects_affected],
     ["confidence", b.confidence != null ? (b.confidence * 100).toFixed(0) + "%" : "?"],
     ["basis", b.basis]].forEach(([k, v]) => {
      if (v == null) return;
      const hot = ["irreversible", "external", "fan_out", "machine", "unbounded"].includes(String(v));
      pills.append(el("span", "pill" + (hot ? " hot" : ""), `${k}: ${v}`));
    });
    (b.data_classes || []).forEach((d) => pills.append(el("span", "pill" + (["secrets", "personal", "financial"].includes(d) ? " hot" : ""), "data: " + d)));
    c.append(pills);

    if ((a.reasons || []).length) {
      const ul = el("ul", "why");
      a.reasons.slice(0, 6).forEach((r) => ul.append(el("li", "", r)));
      c.append(ul);
    }

    const note = el("input"); note.type = "text"; note.placeholder = "note (recorded in the ledger)";
    note.style.marginTop = "12px";
    c.append(note);

    const act = el("div", "actions");
    const ok = el("button", "btn go", high ? "Approve (needs code)" : "Approve");
    const no = el("button", "btn danger", "Deny");
    const ttl = el("select"); ttl.style.width = "auto";
    [["900", "grant 15 min"], ["300", "grant 5 min"], ["3600", "grant 1 hour"], ["60", "grant 1 min"]]
      .forEach(([v, t]) => { const o = el("option", "", t); o.value = v; ttl.append(o); });

    ok.onclick = async () => {
      ok.disabled = no.disabled = true;
      try {
        await post("/api/approve", { approval_id: a.approval_id, note: note.value, grant_seconds: +ttl.value, grant_uses: 1 });
      } catch (e) {
        if (e.status === 403 && (e.payload || {}).error === "step_up_required") {
          if (await stepUp(e.payload.message || "This action has a high blast radius.")) {
            try { await post("/api/approve", { approval_id: a.approval_id, note: note.value, grant_seconds: +ttl.value, grant_uses: 1 }); }
            catch (e2) { alert(e2.message); }
          }
        } else alert(e.message);
      }
      ok.disabled = no.disabled = false; loadApprovals(); refresh();
    };
    no.onclick = async () => {
      ok.disabled = no.disabled = true;
      try { await post("/api/deny", { approval_id: a.approval_id, note: note.value }); } catch (e) { alert(e.message); }
      loadApprovals(); refresh();
    };

    act.append(ok, no, ttl, el("span", "", `waiting ${Math.round(a.age_s)}s`));
    act.lastChild.style.cssText = "color:var(--fg-3);font-size:12px";
    c.append(act);

    if (S.sitekey) {
      const sk = el("div", "sitekey");
      sk.append(document.createTextNode("Your sitekey: "));
      sk.append(el("b", "", S.sitekey));
      sk.append(document.createTextNode(" — an approval prompt that does not show this did not come from Runwall."));
      c.append(sk);
    }
    return c;
  }

  // ---- ledger / policy / sessions ---------------------------------------
  async function loadLedger() {
    const qs = new URLSearchParams({ limit: "150" });
    if ($("#fRoute").value) qs.set("route", $("#fRoute").value);
    if ($("#fAction").value.trim()) qs.set("action", $("#fAction").value.trim());
    let r; try { r = await api("/api/ledger?" + qs); } catch { return; }
    $("#ledgerStats").textContent = `${r.stats.total} total · ` +
      Object.entries(r.stats.by_route).map(([k, v]) => `${k} ${v}`).join(" · ");
    const t = $("#ledgerTable");
    t.innerHTML = "<thead><tr><th>seq</th><th>time</th><th>route</th><th>action</th><th>tool</th><th>summary</th><th>ops</th></tr></thead>";
    const tb = el("tbody");
    r.events.slice().reverse().forEach((e) => {
      const tr = el("tr");
      const sum = ((e.envelope || {}).raw_params || {});
      tr.append(el("td", "", String(e.seq ?? "")),
        el("td", "", (e.timestamp || "").replace("T", " ").slice(5, 19)),
        tdRoute(e.route), el("td", "", e.action || ""), el("td", "", e.tool || ""),
        el("td", "", String(sum.command || sum.file_path || (e.reasons || [])[0] || "").slice(0, 90)),
        el("td", "", e.operator ? e.operator.id || "" : ""));
      tb.append(tr);
    });
    t.append(tb);
  }
  function tdRoute(r) { const td = el("td"); td.append(el("span", "tag r-" + r, r || "?")); return td; }

  async function loadPolicy() {
    let r; try { r = await api("/api/policy"); } catch { return; }
    const m = $("#policyMeta"); m.innerHTML = "";
    m.append(el("div", "", r.path), el("div", "mono", "sha256 " + r.sha256),
      el("div", "pill" + (r.pinned ? "" : " hot"), r.pinned ? "pinned" : r.pin_message));
    m.firstChild.style.cssText = "color:var(--fg-2);font-size:12px";
    $("#policyRaw").textContent = JSON.stringify(r.raw, null, 2);
  }

  async function loadSessions() {
    let r; try { r = await api("/api/sessions"); } catch { return; }
    const t = $("#sessTable");
    t.innerHTML = "<thead><tr><th>session</th><th>taint</th><th>decisions</th><th>halts</th><th>domains</th><th>denied intents</th><th>sources</th></tr></thead>";
    const tb = el("tbody");
    r.sessions.forEach((s) => {
      const tr = el("tr");
      const taint = ["clean", "exposed", "instructed"][s.taint] || s.taint;
      const td = el("td"); td.append(el("span", "pill" + (s.taint >= 1 ? " hot" : ""), taint));
      tr.append(el("td", "", s.session_id.slice(0, 22)), td, el("td", "", String(s.decisions)),
        el("td", "", String(s.halts)), el("td", "", String(s.domains)),
        el("td", "", String(s.denied_intents)),
        el("td", "", (s.taint_sources || []).join(", ").slice(0, 60)));
      tb.append(tr);
    });
    t.append(tb);
  }

  // ---- perimeter actions -------------------------------------------------
  async function onSwitch() {
    const s = (S.status && S.status.perimeter.state) || "ARMED";
    if (s === "ARMED") { $("#disarmBox").classList.remove("hide"); $("#dReason").focus(); }
    else { try { await post("/api/rearm", {}); } catch (e) { alert(e.message); } refresh(); }
  }

  async function doDisarm() {
    const reason = $("#dReason").value.trim();
    if (!reason) { alert("A typed reason is required. It is recorded in the ledger."); return; }
    const code = $("#dTotp").value.trim();
    if (!code) { alert("Disarming requires a fresh authenticator code."); return; }
    try { await post("/auth/stepup", { totp: code }); }
    catch (e) { alert("Step-up failed: " + e.message); return; }
    try {
      await post("/api/disarm", { reason, scope: $("#dScope").value.trim(), seconds: +$("#dSecs").value || 900 });
      $("#disarmBox").classList.add("hide"); $("#dTotp").value = "";
    } catch (e) { alert(e.message); }
    refresh();
  }

  async function killSwitch() {
    if (!confirm("Kill switch: drop the perimeter to SAFE immediately.\n\nAll agents become read-only — writes, execution and network are refused until you re-arm.\n\nProceed?")) return;
    try { await post("/api/kill", { reason: "operator kill switch" }); } catch (e) { alert(e.message); }
    refresh();
  }

  // ---- lifecycle ---------------------------------------------------------
  async function refresh() { try { renderStatus(await api("/status")); } catch { /* signOut handles 401 */ } }

  function start() {
    $("#login").classList.add("hide"); $("#app").classList.remove("hide");
    refresh(); connectSSE(); setView(S.view);
    clearInterval(start._t); start._t = setInterval(refresh, 5000);
  }

  function initTheme() {
    const saved = localStorage.getItem("rw-theme");
    if (saved) document.documentElement.dataset.theme = saved;
    $("#themeBtn").onclick = () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("rw-theme", next);
    };
  }

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    $("#loginBtn").onclick = signIn;
    $("#logoutBtn").onclick = () => { post("/auth/logout", {}).catch(() => {}); signOut(); };
    ["op", "pw", "tp"].forEach((id) => $("#" + id).addEventListener("keydown", (e) => { if (e.key === "Enter") signIn(); }));
    $("#nav").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) setView(b.dataset.view); });
    $("#armSwitch").onclick = onSwitch;
    $("#disarmGo").onclick = doDisarm;
    $("#disarmCancel").onclick = () => $("#disarmBox").classList.add("hide");
    $("#killBtn").onclick = killSwitch;
    $("#refreshLedger").onclick = loadLedger;
    $("#fRoute").onchange = loadLedger;
    $("#verifyBtn").onclick = async () => {
      try {
        const r = await api("/api/verify");
        alert(r.ok ? `Chain intact — ${r.checked} events verified.`
                   : `CHAIN VERIFICATION FAILED (${r.checked} checked)\n\n${r.problems.join("\n")}`);
      } catch (e) { alert(e.message); }
    };

    const saved = sessionStorage.getItem("rw");
    if (saved) {
      try { const o = JSON.parse(saved); S.token = o.t; S.operator = o.o; S.sitekey = o.k || ""; start(); }
      catch { signOut(); }
    }
  });
})();

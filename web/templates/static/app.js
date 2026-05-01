const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
const state = { tab: "home", theme: localStorage.getItem("theme") || "light", users: [], domain: "", port: 443, version: {}, refreshTimer: 0, loginTitle: "登录", refreshing: false, history: { groups: [], expanded: "", pages: {}, pageSizes: {}, details: {}, meta: {} } };
const titles = { home: ["首页", "连接状态与服务压力"], users: ["用户管理", "用户、流量、期限与分享"], history: ["访问历史", "用户访问目标统计"], service: ["Trojan管理", "服务控制、切换与日志"], system: ["系统监控", "资源、证书与续签"], settings: ["设置", "界面主题与偏好"] };

function rightRotate(v, n) { return (v >>> n) | (v << (32 - n)); }
function sha224(input) {
  const bytes = Array.from(new TextEncoder().encode(input)); const bits = bytes.length * 8; bytes.push(0x80);
  while ((bytes.length % 64) !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i -= 1) bytes.push((bits / (2 ** (i * 8))) & 0xff);
  const k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  let h = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
  for (let o = 0; o < bytes.length; o += 64) {
    const w = new Array(64);
    for (let i = 0; i < 16; i += 1) { const j = o + i * 4; w[i] = ((bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3]) >>> 0; }
    for (let i = 16; i < 64; i += 1) { const s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3); const s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0; }
    let [a,b,c,d,e,f,g,hh] = h;
    for (let i = 0; i < 64; i += 1) { const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25); const ch = (e & f) ^ ((~e) & g); const t1 = (hh + s1 + ch + k[i] + w[i]) >>> 0; const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22); const maj = (a & b) ^ (a & c) ^ (b & c); const t2 = (s0 + maj) >>> 0; hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0; }
    h = h.map((v, i) => (v + [a,b,c,d,e,f,g,hh][i]) >>> 0);
  }
  return h.slice(0, 7).map((v) => v.toString(16).padStart(8, "0")).join("");
}
function bytefmt(value) { const u = ["B", "KiB", "MiB", "GiB", "TiB"]; let n = Number(value || 0), i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; } return `${n.toFixed(i ? 2 : 0)} ${u[i]}`; }
function chinaDateValue(date) { return new Date(date.getTime() + 8 * 60 * 60 * 1000).toISOString().slice(0, 10); }
function setDefaultHistoryDates() { const end = new Date(), start = new Date(); start.setDate(end.getDate() - 7); if (!$("#historyStart").value) $("#historyStart").value = chinaDateValue(start); if (!$("#historyEnd").value) $("#historyEnd").value = chinaDateValue(end); }
function pct(used, limit) { return !limit ? 0 : Math.max(0, Math.min(100, (used / limit) * 100)); }
function b64(value) { return btoa(unescape(encodeURIComponent(value))); }
function passOf(user) { try { return decodeURIComponent(escape(atob(user.Password || ""))); } catch { return ""; } }
function form(data) { const body = new URLSearchParams(); Object.entries(data).forEach(([k, v]) => body.set(k, v)); return { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body }; }
async function api(path, options) { const r = await fetch(path, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" }, ...options }); if (r.status === 401) { showLogin(false); throw new Error("未登录或登录已过期"); } const b = await r.json(); if (b.Msg && b.Msg !== "success") throw new Error(b.Msg); return b.Data || b.data || {}; }
function startAutoRefresh() {
  clearInterval(state.refreshTimer);
  const interval = state.tab === "system" || state.tab === "home" ? 5000 : 0;
  if (interval) state.refreshTimer = setInterval(refresh, interval);
}

function formatUptime(value) {
  if (!value) return "-";
  const raw = String(value).trim();
  const match = raw.match(/^(?:(\d+)-)?(\d{1,2}):(\d{2})(?::\d{2})?$/);
  if (!match) return raw;
  const days = Number(match[1] || 0), hours = Number(match[2] || 0), minutes = Number(match[3] || 0);
  const parts = [];
  if (days) parts.push(`${days}天`);
  if (hours || days) parts.push(`${hours}小时`);
  parts.push(`${minutes}分`);
  return parts.join("");
}
function updateHeaderActions() { $("#refreshBtn").hidden = !(state.tab === "home" || state.tab === "system"); }
function applyTheme() { document.documentElement.dataset.theme = state.theme; const label = state.theme === "dark" ? "Light" : "暗黑"; $("#themeBtnInline").textContent = label; localStorage.setItem("theme", state.theme); }
function switchTheme() { state.theme = state.theme === "dark" ? "light" : "dark"; applyTheme(); }
function switchTab(tab) { state.tab = tab; $$(".tab").forEach((i) => i.classList.toggle("active", i.dataset.tab === tab)); $$(".view").forEach((i) => i.classList.toggle("active", i.dataset.view === tab)); $("#pageTitle").textContent = titles[tab][0]; $("#pageSub").textContent = titles[tab][1]; updateHeaderActions(); startAutoRefresh(); refresh(); }
function showDashboard() { $("#authScreen").hidden = true; $("#appShell").hidden = false; $("#dashboard").hidden = false; setLoginNotice(""); startAutoRefresh(); refresh(); }
function showLogin(isRegister, title) {
  clearInterval(state.refreshTimer);
  $("#appShell").hidden = true;
  $("#dashboard").hidden = true;
  $("#authScreen").hidden = false;
  $("#loginTitle").textContent = isRegister ? "初始化管理员" : (title || state.loginTitle || "登录");
  $("#loginBtn").textContent = isRegister ? "初始化" : "登录";
  $("#loginForm").dataset.mode = isRegister ? "register" : "login";
}
function setNotice(message) { const n = $("#notice"); if (!n) return; n.hidden = !message; n.textContent = message || ""; }
function setLoginNotice(message) { const n = $("#loginNotice"); if (!n) return; n.hidden = !message; n.textContent = message || ""; }

async function loadVersion() { state.version = await api("/common/version"); $("#uptimeCard").textContent = formatUptime(state.version.trojanUptime); }
function renderActive(data) {
  const users = data.onlineUsers || [], p = data.processMetrics || [];
  const tcp = p.reduce((s, i) => s + (i.tcpConnections || 0), 0), fd = p.reduce((s, i) => s + (i.fdCount || 0), 0);
  const tcpLimit = p.reduce((s, i) => s + (i.tcpLimit || 0), 0), fdLimit = p.reduce((s, i) => s + (i.fdLimit || 0), 0);
  const tcpSource = p.map((i) => i.tcpLimitSource).filter(Boolean)[0] || "";
  $("#onlineCount").textContent = users.length; $("#tcpCount").textContent = tcp; $("#fdCount").textContent = fd; $("#tcpLimit").textContent = `上限 ${tcpLimit || "-"}`; $("#tcpLimitSource").textContent = tcpSource ? `依据 ${tcpSource}` : ""; $("#fdLimit").textContent = `上限 ${fdLimit || "-"}`;
  const tp = pct(tcp, tcpLimit), fp = pct(fd, fdLimit); $("#tcpRatio").textContent = tcpLimit ? `${tp.toFixed(1)}%` : "-"; $("#fdRatio").textContent = fdLimit ? `${fp.toFixed(1)}%` : "-"; $("#tcpMeter").style.width = `${tp}%`; $("#fdMeter").style.width = `${fp}%`; $("#updatedAt").textContent = `更新于 ${new Date().toLocaleTimeString()}`; setNotice(data.apiError || "");
  $("#userRows").innerHTML = users.length ? users.map((u) => `<tr><td>${u.username}</td><td><span class="badge online">在线</span></td><td>${u.ipCurrent}</td><td>${bytefmt(u.uploadSpeed)}/s</td><td>${bytefmt(u.downloadSpeed)}/s</td><td>${bytefmt(u.uploadTraffic)}</td><td>${bytefmt(u.downloadTraffic)}</td></tr>`).join("") : '<tr><td colspan="7" class="empty">暂无在线用户</td></tr>';
}
function shareFor(user) {
  const pass = passOf(user), remark = encodeURIComponent(`${state.domain}:${state.port}`);
  const token = b64(JSON.stringify({ user: user.Username, pass }));
  return {
    trojan: `trojan://${encodeURIComponent(pass)}@${state.domain}:${state.port}#${remark}`,
    clash: `${location.origin}/trojan/user/subscribe?token=${encodeURIComponent(token)}`,
    ss: `ss://${b64(`aes-128-gcm:${pass}@${state.domain}:${state.port}`)}#${remark}`,
  };
}
function renderUsers(data) {
  state.users = data.userList || []; state.domain = data.domain || location.hostname; state.port = data.port || 443;
  $("#allUserRows").innerHTML = state.users.length ? state.users.map((u) => `<tr><td>${u.ID}</td><td>${u.Username}</td><td>${passOf(u)}</td><td>${bytefmt(u.Upload)}</td><td>${bytefmt(u.Download)}</td><td>${u.Quota < 0 ? "无限制" : bytefmt(u.Quota)}</td><td>${u.ExpiryDate || "无限制"}</td><td><div class="actionRow"><button data-user-action="edit" data-id="${u.ID}" class="ghost">编辑</button><button data-user-action="quota" data-id="${u.ID}" class="ghost">限流</button><button data-user-action="expire" data-id="${u.ID}" class="ghost">期限</button><button data-user-action="clean" data-id="${u.ID}" class="ghost">清流量</button><button data-user-action="share" data-id="${u.ID}" class="ghost">分享</button><button data-user-action="delete" data-id="${u.ID}" class="ghost">删除</button></div></td></tr>`).join("") : '<tr><td colspan="8" class="empty">暂无用户</td></tr>';
}
async function loadUsers() {
  const users = await api(`/trojan/user?_=${Date.now()}`);
  renderUsers(users);
}
function fillHistoryUsers(users) {
  const current = $("#historyUser").value;
  $("#historyUser").innerHTML = '<option value="">全部用户</option>' + users.map((u) => `<option value="${u.EncryptPass}">${u.Username}</option>`).join("");
  $("#historyUser").value = current;
}
function historyParams(extra = {}) {
  const params = new URLSearchParams(new FormData($("#historyFilter")));
  Object.entries(extra).forEach(([k, v]) => params.set(k, v));
  return params;
}
function renderHistoryDetail(group) {
  const detail = state.history.details[group.userHash];
  if (!detail) return "";
  const totalPages = Math.max(1, Math.ceil((detail.total || 0) / detail.pageSize));
  const rows = (detail.items || []).map((i) => `<tr><td>${i.targetHost}</td><td>${i.accessCount}</td><td>${i.clientIP}</td></tr>`).join("");
  return `<div class="historyDetail">
    <div class="historyDetailHead">
      <span>第 ${detail.page} / ${totalPages} 页，共 ${detail.total} 条目标记录</span>
      <select data-history-size="${group.userHash}"><option value="50"${detail.pageSize === 50 ? " selected" : ""}>每页 50</option><option value="100"${detail.pageSize === 100 ? " selected" : ""}>每页 100</option></select>
    </div>
    <div class="tableWrap"><table><thead><tr><th>目标域名/IP</th><th>访问次数</th><th>客户端IP</th></tr></thead><tbody>${rows || '<tr><td colspan="3" class="empty">暂无访问记录</td></tr>'}</tbody></table></div>
    <div class="pager"><button class="ghost small" data-history-page="${group.userHash}" data-page="${Math.max(1, detail.page - 1)}" ${detail.page <= 1 ? "disabled" : ""}>上一页</button><button class="ghost small" data-history-page="${group.userHash}" data-page="${Math.min(totalPages, detail.page + 1)}" ${detail.page >= totalPages ? "disabled" : ""}>下一页</button></div>
  </div>`;
}
function renderHistory(data) {
  const groups = data.groups || [];
  state.history.groups = groups;
  state.history.meta = { startDate: data.startDate || state.history.meta.startDate, endDate: data.endDate || state.history.meta.endDate, lastCollect: data.lastCollect || state.history.meta.lastCollect };
  $("#historyMeta").textContent = `统计区间 ${data.startDate || "-"} 至 ${data.endDate || "-"}，最后收集 ${data.lastCollect ? new Date(data.lastCollect).toLocaleString() : "未执行"}`;
  $("#historyGroups").innerHTML = groups.length ? groups.map((g) => {
    const open = state.history.expanded === g.userHash;
    return `<section class="historyGroup">
      <button class="historyGroupHead" data-history-toggle="${g.userHash}" type="button">
        <span class="chevron">${open ? "v" : ">"}</span>
        <strong>${g.username || g.userHash}</strong>
        <span>${g.accessCount} 次访问</span>
        <span>${g.targetCount} 个目标</span>
        <span>${g.clientIPCount} 个客户端IP</span>
      </button>
      ${open ? renderHistoryDetail(g) : ""}
    </section>`;
  }).join("") : '<div class="empty historyEmpty">暂无访问记录</div>';
}
async function loadHistory() {
  setDefaultHistoryDates();
  if (!state.users.length) {
    const users = await api("/trojan/user");
    state.users = users.userList || [];
  }
  fillHistoryUsers(state.users);
  const data = await api(`/trojan/access-history?${historyParams().toString()}`);
  state.history.expanded = "";
  state.history.details = {};
  renderHistory(data);
}
async function loadHistoryDetail(userHash, page) {
  const pageSize = state.history.pageSizes[userHash] || 50;
  state.history.pages[userHash] = page;
  state.history.expanded = userHash;
  const params = historyParams({ detailUserHash: userHash, page, pageSize });
  const data = await api(`/trojan/access-history?${params.toString()}`);
  state.history.details[userHash] = data.detail;
  state.history.groups = data.groups || state.history.groups;
  renderHistory(data);
}
function renderService(data) {
  const mux = data.mux || {}, apiInfo = data.api || {};
  $("#h2State").textContent = data.h2Alpn ? "H2 ALPN 已启用" : "H2 ALPN 未启用";
  $("#switchTypeBtn").textContent = `切换为 ${data.trojanType === "trojan-go" ? "trojan" : "trojan-go"}`;
  $("#switchTypeBtn").dataset.target = data.trojanType === "trojan-go" ? "trojan" : "trojan-go";
  $("#serviceInfo").innerHTML = [["Trojan 类型", data.trojanType || "-"], ["ALPN", (data.alpn || []).join(", ") || "-"], ["Mux", mux.Enabled || mux.enabled ? "已启用" : "未启用"], ["Mux 并发", mux.Concurrency || mux.concurrency || "-"], ["API", apiInfo.Enabled || apiInfo.enabled ? "已启用" : "未启用"], ["API 地址", `${apiInfo.APIAddr || apiInfo.api_addr || "127.0.0.1"}:${apiInfo.APIPort || apiInfo.api_port || 10000}`]].map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join("");
}
function pie(name, value, sub) { return `<div class="chartCard"><div class="pie" style="--value:${Math.round(value)}"><span>${value.toFixed(1)}%</span></div><h3>${name}</h3><p>${sub}</p></div>`; }
function renderSystem(info, cert) {
  const cpu = info.cpu && info.cpu[0] !== undefined ? info.cpu[0] : 0, mem = info.memory ? info.memory.usedPercent : 0, disk = info.disk ? info.disk.usedPercent : 0, swap = info.swap ? info.swap.usedPercent : 0;
  $("#chartGrid").innerHTML = pie("CPU", cpu, "处理器占用") + pie("内存", mem, info.memory ? `${bytefmt(info.memory.used)} / ${bytefmt(info.memory.total)}` : "-") + pie("磁盘", disk, info.disk ? `${bytefmt(info.disk.used)} / ${bytefmt(info.disk.total)}` : "-") + pie("Swap", swap, info.swap ? `${bytefmt(info.swap.used)} / ${bytefmt(info.swap.total)}` : "-");
  const names = [...(cert.dnsNames || []), ...(cert.ipAddresses || [])].join(", ") || "-";
  $("#certInfo").innerHTML = [["服务运行时长", formatUptime(state.version.trojanUptime)], ["证书到期", cert.notAfter ? new Date(cert.notAfter).toLocaleString() : "-"], ["剩余天数", cert.daysLeft !== undefined ? `${cert.daysLeft} 天` : "-"], ["签发域名", names], ["颁发者", cert.issuer || "-"], ["证书路径", cert.certPath || "-"]].map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join("");
}
function setQR(img, text) {
  img.src = `/common/qrcode?data=${encodeURIComponent(text)}`;
}

async function refresh() {
  if (state.refreshing) return;
  state.refreshing = true;
  const tab = state.tab, btn = $("#refreshBtn"); btn.disabled = true; btn.textContent = "刷新中";
  try {
    if (tab === "home") {
      const [version, active] = await Promise.all([api("/common/version"), api("/common/activeUsers")]);
      if (state.tab !== tab) return;
      state.version = version; $("#uptimeCard").textContent = formatUptime(state.version.trojanUptime); renderActive(active);
    }
    if (tab === "users") {
      await loadUsers();
      if (state.tab !== tab) return;
    }
    if (tab === "history") {
      await loadHistory();
      if (state.tab !== tab) return;
    }
    if (tab === "service") {
      const service = await api("/trojan/h2");
      if (state.tab !== tab) return;
      renderService(service);
    }
    if (tab === "system") {
      const [version, info, cert] = await Promise.all([api("/common/version"), api("/common/serverInfo"), api("/common/certInfo")]);
      if (state.tab !== tab) return;
      state.version = version; renderSystem(info, cert);
    }
  } catch (e) { setNotice(e.message); } finally { state.refreshing = false; btn.disabled = false; btn.textContent = "刷新"; }
}
function openUserDialog(user) { $("#userDialogTitle").textContent = user ? "编辑用户" : "新增用户"; $("#userId").value = user ? user.ID : ""; $("#userNameInput").value = user ? user.Username : ""; $("#userPassInput").value = user ? passOf(user) : ""; $("#userDialog").showModal(); }
async function handleUserAction(action, id) {
  const user = state.users.find((u) => String(u.ID) === String(id)); if (!user) return;
  if (action === "edit") return openUserDialog(user);
  if (action === "quota") { const q = prompt("请输入流量限额（byte，-1 表示无限制）", user.Quota); if (q !== null) await api("/trojan/data", form({ id, quota: q })); }
  if (action === "expire") { const d = prompt("请输入可使用天数，0 表示取消期限", user.UseDays || 0); if (d !== null && Number(d) === 0) await api(`/trojan/user/expire?id=${id}`, { method: "DELETE" }); else if (d !== null) await api("/trojan/user/expire", form({ id, useDays: d })); }
  if (action === "clean" && confirm(`清空 ${user.Username} 的流量统计？`)) await api(`/trojan/data?id=${id}`, { method: "DELETE" });
  if (action === "delete" && confirm(`删除用户 ${user.Username}？`)) {
    const users = await api(`/trojan/user?id=${id}`, { method: "DELETE" });
    renderUsers(users);
    return;
  }
  if (action === "share") { const s = shareFor(user); $("#trojanShare").value = s.trojan; $("#clashShare").value = s.clash; $("#ssShare").value = s.ss; setQR($("#trojanQr"), s.trojan); setQR($("#clashQr"), s.clash); setQR($("#ssQr"), s.ss); $("#shareDialog").showModal(); return; }
  refresh();
}
function startLog() {
  const box = $("#logBox"); box.textContent = "连接日志中...\n";
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/trojan/log?line=300`);
  ws.onmessage = (event) => { box.textContent += event.data; box.scrollTop = box.scrollHeight; };
  ws.onerror = () => { box.textContent += "\n日志连接失败\n"; };
}
async function boot() {
  applyTheme();
  updateHeaderActions();
  const loginUser = fetch("/auth/loginUser", { credentials: "same-origin" }).catch(() => null);
  try {
    const r = await fetch("/auth/check", { credentials: "same-origin" });
    if (r.status === 201) return showLogin(true);
    let title = "登录";
    if (r.ok) {
      const body = await r.json();
      title = (body.data && body.data.title) || title;
    }
    state.loginTitle = title;
    const u = await loginUser;
    return u && u.ok ? showDashboard() : showLogin(false, title);
  } catch {
    return showLogin(false);
  }
}
async function logout() {
  const btn = $("#logoutBtn");
  btn.disabled = true;
  try {
    await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
  } finally {
    btn.disabled = false;
    $("#password").value = "";
    showLogin(false);
  }
}

$("#loginForm").addEventListener("submit", async (e) => { e.preventDefault(); setLoginNotice(""); const f = new FormData($("#loginForm")); f.set("password", sha224(f.get("password") || "")); const path = $("#loginForm").dataset.mode === "register" ? "/auth/register" : "/auth/login"; const r = await fetch(path, { method: "POST", credentials: "same-origin", body: f }); r.ok ? showDashboard() : setLoginNotice("认证失败"); });
$("#refreshBtn").addEventListener("click", refresh);
$("#logoutBtn").addEventListener("click", logout);
$("#themeBtnInline").addEventListener("click", switchTheme);
$("#addUserBtn").addEventListener("click", () => openUserDialog());
$("#userForm").addEventListener("submit", async (e) => { e.preventDefault(); const id = $("#userId").value, username = $("#userNameInput").value.trim(), password = b64($("#userPassInput").value); await api(id ? "/trojan/user/update" : "/trojan/user", form(id ? { id, username, password } : { username, password })); $("#userDialog").close(); refresh(); });
$("#historyFilter").addEventListener("submit", async (e) => { e.preventDefault(); state.history.expanded = ""; state.history.details = {}; await loadHistory(); });
$("#collectHistoryBtn").addEventListener("click", async () => { const btn = $("#collectHistoryBtn"); btn.disabled = true; btn.textContent = "收集中"; try { await api("/trojan/access-history/collect", { method: "POST" }); await loadHistory(); } finally { btn.disabled = false; btn.textContent = "收集统计"; } });
$$("[data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));
$("#allUserRows").addEventListener("click", (e) => { const b = e.target.closest("[data-user-action]"); if (b) handleUserAction(b.dataset.userAction, b.dataset.id); });
$("#historyGroups").addEventListener("click", async (e) => {
  const toggle = e.target.closest("[data-history-toggle]");
  if (toggle) {
    const userHash = toggle.dataset.historyToggle;
    if (state.history.expanded === userHash) {
      state.history.expanded = "";
      renderHistory({ groups: state.history.groups, ...state.history.meta });
    } else {
      await loadHistoryDetail(userHash, state.history.pages[userHash] || 1);
    }
    return;
  }
  const pageBtn = e.target.closest("[data-history-page]");
  if (pageBtn && !pageBtn.disabled) await loadHistoryDetail(pageBtn.dataset.historyPage, Number(pageBtn.dataset.page || 1));
});
$("#historyGroups").addEventListener("change", async (e) => {
  const select = e.target.closest("[data-history-size]");
  if (!select) return;
  const userHash = select.dataset.historySize;
  state.history.pageSizes[userHash] = Number(select.value);
  await loadHistoryDetail(userHash, 1);
});
$$("[data-action]").forEach((b) => b.addEventListener("click", async () => { await api(`/trojan/${b.dataset.action}`, { method: "POST" }); refresh(); }));
$("#switchTypeBtn").addEventListener("click", async () => { if (confirm(`确认${$("#switchTypeBtn").textContent}？`)) await api("/trojan/switch", form({ type: $("#switchTypeBtn").dataset.target })); refresh(); });
$("#logBtn").addEventListener("click", startLog);
$("#renewCertBtn").addEventListener("click", async () => { if (confirm("证书续签会临时重启 trojan-web，确认执行？")) { await api("/common/cert/renew", { method: "POST" }); alert("续签任务已启动，日志见 /tmp/trojan-cert-renew.log"); } });
$$(".tab").forEach((i) => i.addEventListener("click", () => switchTab(i.dataset.tab)));
boot();


// ── Diagnostics View ────────────────────────────────────────
let _diagOutput = "";
let _diagRunning = false;

function renderDiagnostics(data) {
  return section("Router Network Diagnostics", `
    <div style="max-width:800px; display:flex; flex-direction:column; gap:20px;">
      <div style="background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-md); padding:20px;">
        <h3 style="margin-bottom:12px; font-size:16px;">Connectivity Diagnostic Tools</h3>
        <p style="color:var(--text-muted); font-size:13px; margin-bottom:20px;">Quick checks for host reachability, network latency, DNS resolution, and link status without opening an SSH console.</p>
        
        <div class="form-row" style="align-items:flex-end; gap:12px; margin-bottom:16px;">
          <div class="form-group" style="flex:1;">
            <label style="font-size:12px; color:var(--text-muted); display:block; margin-bottom:6px;">Check Type</label>
            <select class="form-input" id="diagTool">
              <option value="ping">Ping (Reachability & RTT)</option>
              <option value="traceroute">Traceroute (Network Path)</option>
              <option value="nslookup">DNS Nslookup (Domain Resolution)</option>
            </select>
          </div>
          
          <div class="form-group" id="diagTargetWrap" style="flex:2;">
            <label style="font-size:12px; color:var(--text-muted); display:block; margin-bottom:6px;">Target Host or IP Address</label>
            ${sensitiveHtml(`<input class="form-input" id="diagTarget" placeholder="1.1.1.1 or example.com" value="1.1.1.1" autocomplete="off" />`,"diagnostics-target")}
          </div>
          
          <div>
            <button class="btn btn-accent" id="diagRunBtn" onclick="runDiagnosticsTool()">
              <i data-lucide="play"></i> Run
            </button>
          </div>
        </div>
      </div>

      <div style="background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-md); padding:20px;">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
          <h4 style="font-size:14px; font-weight:600;">Diagnostic Output</h4>
          <span id="diagStatusBadge" class="badge" style="display:none;"></span>
        </div>
        ${sensitiveHtml(`<pre id="diagOutputBlock" style="min-height:160px; max-height:400px; background:#000; border:1px solid var(--border); border-radius:var(--radius-sm); padding:14px; font-size:12px; color:#10b981; white-space:pre-wrap; overflow-y:auto; font-family:monospace;">${esc(_diagOutput || "Click 'Run' to execute check...")}</pre>`,"diagnostics-output",true)}
      </div>
    </div>
  `);
}

async function runDiagnosticsTool() {
  if (_diagRunning) return;
  const tool = document.getElementById("diagTool")?.value || "ping";
  const target = document.getElementById("diagTarget")?.value?.trim() || "";
  const outputBlock = document.getElementById("diagOutputBlock");
  const btn = document.getElementById("diagRunBtn");
  const badge = document.getElementById("diagStatusBadge");
  
  if (!target) {
    toast("Enter a target host or IP address", "error");
    return;
  }

  _diagRunning = true;
  if (btn) { btn.disabled = true; btn.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Running...`; }
  if (badge) { badge.style.display = "inline-block"; badge.className = "badge badge-info"; badge.innerText = "Running..."; }
  if (outputBlock) outputBlock.innerText = `Running ${tool.toUpperCase()} ${target ? `on ${target}` : ""}...
`;

  try {
    const res = await post("/api/diagnose/run", { tool, target });
    _diagOutput = res.output || "Completed successfully.";
    if (outputBlock) outputBlock.innerText = _diagOutput;
    if (badge) {
      badge.className = res.ok ? "badge badge-success" : "badge badge-danger";
      badge.innerText = res.ok ? "Success" : "Error";
    }
    toast("Diagnostics completed", res.ok ? "success" : "warning");
  } catch(e) {
    _diagOutput = "Execution error: " + e.message;
    if (outputBlock) outputBlock.innerText = _diagOutput;
    if (badge) { badge.className = "badge badge-danger"; badge.innerText = "Error"; }
    toast("Error: " + e.message, "error");
  } finally {
    _diagRunning = false;
    if (btn) { btn.disabled = false; btn.innerHTML = `<i data-lucide="play"></i> Run`; renderIcons(btn); }
  }
}


// ── Command Palette & Quick Search Logic ─────────────────────
function openCmdPalette() {
  const overlay = document.getElementById("cmdOverlay");
  const input = document.getElementById("cmdInput");
  if (!overlay || !input) return;
  overlay.hidden = false;
  input.value = "";
  renderCmdResults("");
  input.focus();
  renderIcons(overlay);
}

function closeCmdPalette() {
  const overlay = document.getElementById("cmdOverlay");
  if (overlay) overlay.hidden = true;
}

function renderCmdResults(query) {
  const container = document.getElementById("cmdResults");
  if (!container) return;
  const q = query.toLowerCase().trim();
  
  const items = [
    { title: "Overview", view: "overview", icon: "layout-dashboard", type: "View" },
    { title: "WAN & DSL Connection", view: "wan", icon: "globe", type: "View" },
    { title: "Failover Priorities", view: "failover", icon: "route", type: "View" },
    { title: "LAN & DHCP Devices", view: "lan", icon: "network", type: "View" },
    { title: "Firewall & Port Forwarding", view: "firewall", icon: "shield", type: "View" },
    { title: "Amnezia VPN & Policy Routing", view: "amnezia", icon: "lock", type: "View" },
    { title: "DNS AdBlock Filtering", view: "adblock", icon: "badge-x", type: "View" },
    { title: "System CPU/RAM Metrics", view: "system", icon: "activity", type: "View" },
    { title: "Network Diagnostics (Ping/Trace)", view: "diagnostics", icon: "stethoscope", type: "View" },
    { title: "FreeBSD Logs & Services", view: "logs", icon: "terminal", type: "View" },
    { title: "UPS Status", view: "ups", icon: "battery-charging", type: "View" },
    { title: "Configuration Backups", view: "backups", icon: "archive-restore", type: "View" },
    { title: "Administration", view: "admin", icon: "settings", type: "View" },
  ];
  
  const filtered = items.filter(i => !q || i.title.toLowerCase().includes(q));
  if (filtered.length === 0) {
    container.innerHTML = `<div style="padding:16px;text-align:center;color:var(--text-muted)">Nothing found</div>`;
    return;
  }
  
  container.innerHTML = filtered.map(i => `
    <div class="cmd-item" onclick="switchView(${escJs(i.view)});closeCmdPalette();">
      <i data-lucide="${i.icon}"></i>
      <span class="cmd-title">${esc(i.title)}</span>
      <span class="cmd-badge">${esc(i.type)}</span>
    </div>
  `).join("");
  renderIcons(container);
}

document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    openCmdPalette();
  }
  if (e.key === "Escape") {
    closeCmdPalette();
  }
});

document.addEventListener("click", (e) => {
  const overlay = document.getElementById("cmdOverlay");
  if (overlay && e.target === overlay) {
    closeCmdPalette();
  }
});

document.addEventListener("input", (e) => {
  if (e.target && e.target.id === "cmdInput") {
    renderCmdResults(e.target.value);
  }
});

// ── Live Traffic Canvas Drawer ─────────────────────────────
const _trafficHistory = { rx: [], tx: [], maxPoints: 30 };

function drawTrafficCanvas(canvasId, rxKbps, txKbps) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  _trafficHistory.rx.push(rxKbps || 0);
  _trafficHistory.tx.push(txKbps || 0);
  if (_trafficHistory.rx.length > _trafficHistory.maxPoints) {
    _trafficHistory.rx.shift();
    _trafficHistory.tx.shift();
  }

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = rect.height;
  ctx.clearRect(0, 0, w, h);

  const maxVal = Math.max(10, ..._trafficHistory.rx, ..._trafficHistory.tx);
  const ptsRx = _trafficHistory.rx;
  const ptsTx = _trafficHistory.tx;
  const step = ptsRx.length > 1 ? w / (ptsRx.length - 1) : w;

  // Draw Grid lines
  ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
  ctx.lineWidth = 1;
  for (let y = 0; y < h; y += 24) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  // Helper line drawer
  function drawLine(pts, color, fillColor) {
    if (pts.length < 2) return;
    ctx.beginPath();
    ctx.moveTo(0, h - (pts[0] / maxVal) * (h - 10));
    for (let i = 1; i < pts.length; i++) {
      const x = i * step;
      const y = h - (pts[i] / maxVal) * (h - 10);
      ctx.lineTo(x, y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.lineTo((pts.length - 1) * step, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
  }

  drawLine(ptsRx, "#10b981", "rgba(16, 185, 129, 0.08)");
  drawLine(ptsTx, "#3b82f6", "rgba(59, 130, 246, 0.08)");
}

// ── 1-Click Internet Repair ───────────────────────────────
async function doInternetRepair() {
  openModal("Restore Internet", `
    <div id="repairSteps" style="display:flex;flex-direction:column;gap:10px;">
      <div style="display:flex;align-items:center;gap:10px;padding:12px;background:var(--bg2);border-radius:6px;">
        <i data-lucide="loader-2" class="spin" style="width:20px;height:20px;color:var(--accent)"></i>
        <span>Checking connection...</span>
      </div>
    </div>
  `, `<button class="btn" disabled id="repairClose">Please wait...</button>`);
  renderIcons();

  try {
    const r = await post("/api/internet/repair", {});
    const stepsEl = document.getElementById("repairSteps");
    if (!stepsEl) return;

    if (r.already_working) {
      stepsEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;padding:16px;background:rgba(16,185,129,0.1);border:1px solid var(--ok);border-radius:6px;">
          <i data-lucide="check-circle" style="width:24px;height:24px;color:var(--ok)"></i>
          <div><strong style="color:var(--ok)">Internet is working normally</strong><br><span style="font-size:12px;color:var(--text-muted)">All checks passed; no repair needed.</span></div>
        </div>`;
    } else {
      const stepsHtml = (r.steps || []).map(s => `
        <div style="display:flex;align-items:center;gap:10px;padding:10px;background:var(--bg2);border-radius:6px;border-left:3px solid ${s.ok ? 'var(--ok)' : 'var(--bad)'}">
          <i data-lucide="${s.ok ? 'check-circle' : 'x-circle'}" style="width:18px;height:18px;color:${s.ok ? 'var(--ok)' : 'var(--bad)'}"></i>
          <div style="flex:1">
            <div style="font-size:13px;font-weight:600">${esc(s.name)}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px;word-break:break-all">${esc(s.detail || "")}</div>
          </div>
          <span class="pill ${s.ok ? 'ok' : 'bad'}">${s.ok ? 'OK' : 'Error'}</span>
        </div>
      `).join("");

      const verdictColor = r.ok ? 'var(--ok)' : 'var(--bad)';
      const verdictIcon = r.ok ? 'check-circle' : 'alert-circle';
      const verdictText = r.ok ? 'Connectivity restored!' : 'Recovery failed';

      stepsEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;padding:14px;background:${r.ok ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)'};border:1px solid ${verdictColor};border-radius:6px;margin-bottom:12px;">
          <i data-lucide="${verdictIcon}" style="width:24px;height:24px;color:${verdictColor}"></i>
          <strong style="color:${verdictColor};font-size:15px">${verdictText}</strong>
        </div>
        ${stepsHtml}`;
    }
    renderIcons();
  } catch(e) {
    const stepsEl = document.getElementById("repairSteps");
    if (stepsEl) stepsEl.innerHTML = `<div style="color:var(--bad);padding:12px;">Error: ${esc(e.message)}</div>`;
  }

  const closeBtn = document.getElementById("repairClose");
  if (closeBtn) { closeBtn.disabled = false; closeBtn.textContent = "Close"; closeBtn.onclick = closeModal; }
}

// ── 1-Click VPN Health Diagnostic ─────────────────────────
async function doVpnTestTunnel() {
  toast("Starting VPN tunnel check...", "info");
  try {
    const res = await api("/api/vpn");
    const handshake = res.handshake || "OK";
    const status = res.active ? "Active" : "Disabled";
    const ip = res.local_ip || "10.0.0.2";
    
    openModal("VPN Tunnel Diagnostics", `
      <div style="display:flex;flex-direction:column;gap:12px">
        <div class="warning-box" style="border-color:var(--status-up);background:var(--status-up-bg)">
          <strong>Tunnel status:</strong> ${esc(status)}<br>
          <strong>Local tunnel IP:</strong> ${sensitive(ip,"diagnostics-vpn-local-ip")}<br>
          <strong>Handshake:</strong> ${esc(handshake)}
        </div>
        <p style="color:var(--text-muted);font-size:12px">Policy bypass and tunnel routing operate through the local <code>awg0</code> interface.</p>
      </div>
    `, btn("Close", "x", "btn-accent", "closeModal()"));
  } catch(e) {
    toast("Diagnostics error: " + e.message, "error");
  }
}


function renderIcons(container = document.body) {
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    try {
      window.lucide.createIcons({ root: container });
    } catch(e) {
      window.lucide.createIcons();
    }
  }
}

/* global AbortController, MutationObserver, ResizeObserver, WebSocket, lucide */
/* ═══ State ═══ */
const S = { view: "overview", overview: null, cache: new Map(), cacheTs: new Map(), viewErrors: {}, timer: null, lastTs: 0, sections: {}, revealedSensitive: new Set(), sparks: { ram: [], cpu: [], ppp: [], usb: [] } };
const REFRESH = { overview:10000, diagnostics:60000, wan:10000, failover:10000, lan:15000, adblock:60000, firewall:120000, clients:10000, dhcp:30000, amnezia:15000, ups:10000, system:15000, history:30000, backups:60000, admin:30000, logs:30000 };
const EP = {
  overview: ["/api/overview","/api/wan","/api/clients","/api/stats/traffic","/api/amnezia","/api/health","/api/logs?limit=20"],
  diagnostics: [],
  wan: ["/api/interfaces","/api/wan","/api/pppoe","/api/modem","/api/physical_ports","/api/rcconf"],
  failover: ["/api/wan","/api/history","/api/failover","/api/discovery"],
  lan: ["/api/clients","/api/dhcp","/api/interfaces","/api/rcconf"],
  adblock: ["/api/adblock/status","/api/adblock/rules","/api/dns/split"],
  firewall: ["/api/firewall","/api/firewall/detail","/api/port-forwards","/api/reverse-ssh"], clients: ["/api/clients"], dhcp: ["/api/dhcp"],
  amnezia: ["/api/amnezia", "/api/vpn/status", "/api/vpn/profiles", "/api/vpn/exceptions", "/api/dns/split", "/api/secureboot/status"], ups: ["/api/ups", "/api/ups/config"],
  system: ["/api/system","/api/tls/status","/api/memory","/api/disks","/api/services","/api/zfs","/api/disks/io"],
  history: ["/api/history"], backups: ["/api/backups"],
  admin: ["/api/system","/api/services","/api/services/all","/api/backups","/api/system/updates","/api/repo/sources"],
  logs: ["/api/services/all"],
};

/* ═══ Helpers ═══ */
function esc(v){return String(v??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
function jsArg(v){return JSON.stringify(String(v??""))}
function escJs(v){return esc(jsArg(v))}
function sensitiveHtml(html,id,block=false){
  const revealed=S.revealedSensitive.has(id),label=revealed?"Hide sensitive data":"Show sensitive data",tag=block?"div":"span";
  return `<${tag} class="sensitive-value${block?" sensitive-block":""}${revealed?" revealed":""}" data-sensitive-id="${esc(id)}"><${tag} class="sensitive-content"${revealed?"":` inert aria-hidden="true"`}>${html}</${tag}><button type="button" class="sensitive-toggle" onclick="event.preventDefault();event.stopPropagation();toggleSensitive(${esc(JSON.stringify(id))},this)" title="${label}" aria-label="${label}" aria-pressed="${revealed}"><i data-lucide="${revealed?"eye-off":"eye"}"></i></button></${tag}>`;
}
function sensitive(value,id){return sensitiveHtml(esc(value),id)}
function sensitiveBlock(value,id){return sensitiveHtml(`<pre>${esc(Array.isArray(value)?value.join("\n"):value)}</pre>`,id,true)}
function toggleSensitive(id,button){
  const revealed=!S.revealedSensitive.has(id);
  if(revealed)S.revealedSensitive.add(id);else S.revealedSensitive.delete(id);
  const root=button.closest(".sensitive-value"),content=root.querySelector(".sensitive-content");
  root.classList.toggle("revealed",revealed);
  content.inert=!revealed;
  if(revealed)content.removeAttribute("aria-hidden");else content.setAttribute("aria-hidden","true");
  const label=revealed?"Hide sensitive data":"Show sensitive data";
  button.title=label;
  button.setAttribute("aria-label",label);
  button.setAttribute("aria-pressed",String(revealed));
  const icon=button.querySelector("[data-lucide]");
  if(icon)icon.setAttribute("data-lucide",revealed?"eye-off":"eye");
  renderIcons(button);
}
function fmtB(v){if(!Number.isFinite(v))return"n/a";const u=["B","KiB","MiB","GiB","TiB"];let s=v,i=0;while(s>=1024&&i<u.length-1){s/=1024;i++}return`${s.toFixed(i?1:0)} ${u[i]}`}
function fmtRel(ts){const d=Math.floor(Date.now()/1000)-ts;if(d<60)return`${d} s ago`;if(d<3600)return`${Math.floor(d/60)} m ago`;if(d<86400)return`${Math.floor(d/3600)} h ago`;return`${Math.floor(d/86400)} d ago`}
function fmtTime(v){const t=Number(v);return(!Number.isFinite(t)||t<=0)?"":new Date(t*1000).toLocaleString()}
function fmtDomain(value,displayValue){
  const raw=String(value||""),disp=String(displayValue||"");
  return disp&&disp!==raw?`${disp} (${raw})`:raw;
}
function shortHash(v){return v?String(v).slice(0,12):""}
/* Which of the five VPN states the backend measured. The panel used to work
   this out itself as `vpn_is_default || interface.state==="UP"` -- a
   disjunction, so "up but the traffic goes around it" looked exactly like "the
   traffic is in the tunnel". A payload without the field is not evidence that
   everything is fine, so it reads as "not measured": in_tunnel and expected
   stay undefined, and every test below is an explicit `=== true`. */
function vpnPath(o){
  const p=o?.vpn_path;
  if(!p||typeof p!=="object")return{state:"unknown",label:"not measured",in_tunnel:undefined,expected:undefined,warnings:[]};
  return p;
}

async function api(path,opts){
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), 20000);
  try {
    const r=await fetch(path,{cache:"no-store", signal: controller.signal, ...opts});
    clearTimeout(id);
    if(r.status===401 && !path.startsWith("/api/auth/")){
      showLogin();
    }
    if(r.status===429)throw new Error("Too many requests. Wait a minute.");
    const ct=r.headers.get("content-type")||"";
    if(!ct.includes("json")){
      const txt=await r.text();
      throw new Error(txt.slice(0,200)||`HTTP ${r.status}`);
    }
    const j=await r.json();
    if(!r.ok){
      // The whole payload rides along on the error. Some failures say more than
      // their message: whether the change was rolled back is the difference
      // between "nothing happened" and "the device is half moved", and a bare
      // Error string threw that away.
      const err=new Error(j.error||`HTTP ${r.status}`);err.payload=j;throw err;
    }
    S.cache.set(path,j);S.cacheTs.set(path,Date.now());return j;
  } catch (e) {
    clearTimeout(id);
    if (e.name === 'AbortError') throw new Error('API Timeout: ' + path);
    throw e;
  }
}
async function post(path,body){
  return api(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
}
async function authStatus(){
  const r=await fetch("/api/auth/status",{cache:"no-store"});
  return r.json();
}
function showLogin(){
  openModal("GateBSD login",`
    <div class="form-group"><label>Username</label><input class="form-input" id="loginUsername" type="text" autocomplete="username"></div>
    <div class="form-group"><label>Password</label><input class="form-input" id="loginPassword" type="password" autocomplete="current-password"></div>
    <div class="card-detail">Sign in with your FreeBSD system account (same credentials as SSH).</div>
  `,`<button class="btn btn-ok" id="loginSubmit">Sign in</button>`);
  const user=document.getElementById("loginUsername"),input=document.getElementById("loginPassword");
  user.value=localStorage.getItem("gatebsdLastUsername")||"";
  (user.value?input:user).focus();
  async function submit(){
    try{
      await post("/api/auth/login",{username:user.value,password:input.value});
      localStorage.setItem("gatebsdLastUsername",user.value);
      closeModal();
      boot(true);
    }catch(e){toast(e.message)}
  }
  document.getElementById("loginSubmit").onclick=submit;
  user.onkeydown=e=>{if(e.key==="Enter")input.focus()};
  input.onkeydown=e=>{if(e.key==="Enter")submit()};
}
async function doLogout(){
  try{await closeTerminalSession();}catch(e){}
  try{await post("/api/auth/logout",{});}catch(e){}
  location.reload();
}

function toast(msg,type="error"){
  const c=document.getElementById("toasts"),d=document.createElement("div");
  d.className=`toast ${type}`;d.textContent=msg;c.appendChild(d);
  setTimeout(()=>{d.style.animation="toastOut .3s ease forwards";setTimeout(()=>d.remove(),300)},4000);
}

function pill(v,forced=""){
  const t=String(v??"unknown"),lo=t.toLowerCase();
  const cls=["ok","warn","bad"].includes(forced)?forced:["active","running","ol","ok","true","enabled","yes","on","loaded","installed"].includes(lo)?"ok":["inactive","standby","waiting","disabled","no","off","stopped","missing"].includes(lo)?"warn":"bad";
  return`<span class="pill ${cls}">${esc(t)}</span>`;
}
function getSectionIcon(title) {
  const t = title.toLowerCase();
  const SECTION_ICONS_BY_KEYWORD = [
    { keywords: ["system", "status", "diagnostics"], icon: "cpu" },
    { keywords: ["control", "settings", "services", "parameters", "config"], icon: "sliders" },
    { keywords: ["memory", "disk", "storage", "database"], icon: "database" },
    { keywords: ["service", "active", "status"], icon: "activity" },
    { keywords: ["internet", "link", "network", "connection", "wan", "lan", "vpn", "wireguard", "client"], icon: "globe" },
    { keywords: ["update", "pkg", "package"], icon: "package" },
    { keywords: ["terminal", "command", "output", "syntax"], icon: "terminal" },
    { keywords: ["backup", "snapshot", "history", "events"], icon: "archive" },
    { keywords: ["access", "password", "auth", "login"], icon: "lock" },
    { keywords: ["warning", "error"], icon: "alert-triangle" }
  ];
  for (const group of SECTION_ICONS_BY_KEYWORD) {
    if (group.keywords.some(k => t.includes(k))) return group.icon;
  }
  return "folder";
}

function card(label,value,icon="activity",extra="",iconStyle=""){
  const iconHtml=icon.startsWith("<")?`<span class="card-micro-icon" style="${iconStyle}">${icon}</span>`:`<i data-lucide="${icon}" class="card-micro-icon" style="${iconStyle}"></i>`;
  return `<article class="card"><div class="card-header"><div class="card-label">${esc(label)}</div>${iconHtml}</div><div class="card-value">${value}</div>${extra}</article>`;
}

function section(title,body,actions=""){
  const state = S.sections[title] === true;
  const icon = getSectionIcon(title);
  return `<details class="section" ${state ? "open" : ""} data-section="${esc(title)}">
    <summary class="section-header" onclick="if(event.target.closest('button'))event.preventDefault()">
      <div style="display:flex;align-items:center;gap:10px">
        <i data-lucide="chevron-down" class="section-arrow"></i>
        <i data-lucide="${icon}" class="section-icon" style="width:14px;height:14px;color:var(--accent)"></i>
        <h2 style="margin:0">${esc(title)}</h2>
      </div>
      ${actions ? `<div>${actions}</div>` : ""}
    </summary>
    <div class="section-body">${body}</div>
  </details>`;
}
function pre(v){
  const text=Array.isArray(v)?v.join("\n"):String(v??"");
  let hash=0;
  for(let i=0;i<text.length;i++)hash=(hash*31+text.charCodeAt(i))|0;
  return sensitiveBlock(v,`raw-output-${(hash>>>0).toString(36)}-${text.length}`);
}
function details(summary,body){return`<details class="section-details"><summary>${esc(summary)}</summary>${body}</details>`}
function viewError(errors,path){
  const error=errors[path];
  if(!error)return"";
  const previous=S.cache.has(path),ts=S.cacheTs.get(path);
  return`<div class="view-state ${previous?"degraded":"unknown"}" role="status"><strong>${previous?"Refresh failed — showing cached data":"State not measured"}</strong><div>${esc(error?.message||String(error))}</div>${ts?`<div>Previous reading: ${esc(new Date(ts).toLocaleString())}</div>`:""}</div>`;
}

let IFACE_NAMES={lo:"Loopback",primary:"Primary",secondary:"Backup"};
const SVC_NAMES={gatebsd:"Control Panel",gatebsd_failover:"WAN/VPN Failover",gatewayctl_apply:"VPN Gateway",unbound:"DNS resolver",dhcpd:"DHCP server",pf:"Firewall",nut:"UPS server",nut_upsmon:"UPS monitor",sshd:"SSH",cron:"Cron"};
const VIEW_TITLES={overview:"Overview",system:"System",wan:"WAN",failover:"Failover",lan:"Local Network (LAN)",adblock:"AdBlock",amnezia:"Amnezia VPN",firewall:"Firewall / PF",logs:"Logs",diagnostics:"Diagnostics",ups:"UPS",backups:"Backups",history:"History",admin:"Settings"};
const UPS_CMD_LABELS={
  "beeper.enable":{label:"Enable beeper",icon:"volume-2",risk:"normal",group:"Audio",help:"Enables UPS audible alarms if supported by the model."},
  "beeper.disable":{label:"Disable beeper",icon:"volume-x",risk:"normal",group:"Audio",help:"Disables UPS audible alarms if supported by the driver."},
  "beeper.toggle":{label:"Toggle beeper",icon:"volume-1",risk:"normal",group:"Audio",help:"Toggles the UPS beeper state."},
  "test.battery.start":{label:"Battery test",icon:"battery",risk:"normal",group:"Tests",help:"Starts the standard battery test defined by the UPS driver."},
  "test.battery.start.quick":{label:"Quick test",icon:"battery-charging",risk:"normal",group:"Tests",help:"Quick battery self-test without dropping load."},
  "test.battery.start.deep":{label:"Deep test",icon:"battery-warning",risk:"caution",group:"Tests",help:"Extended battery test. Run only with stable mains power."},
  "test.battery.stop":{label:"Stop test",icon:"circle-stop",risk:"normal",group:"Tests",help:"Aborts an active battery test."},
  "driver.reload":{label:"Reload driver",icon:"refresh-cw",risk:"service",group:"Driver",help:"Asks the driver to reload supported configuration live."},
  "driver.reload-or-error":{label:"Reload or fail",icon:"triangle-alert",risk:"service",group:"Driver",help:"Reloads configuration and errors if live apply is unsupported."},
  "driver.reload-or-exit":{label:"Reload or exit",icon:"refresh-ccw",risk:"service",group:"Driver",help:"Reloads configuration or exits so rc.d restarts the driver."},
  "load.off":{label:"Load off",icon:"power",risk:"danger",group:"Power",help:"Cuts UPS output load. Can power off the router and attached gear."},
  "load.on":{label:"Load on",icon:"power",risk:"caution",group:"Power",help:"Restores UPS output load."},
  "shutdown.return":{label:"Shutdown & return",icon:"refresh-ccw",risk:"danger",group:"Power",help:"Cuts load and restores power when mains returns."},
  "shutdown.stayoff":{label:"Shutdown & stay off",icon:"power-off",risk:"danger",group:"Power",help:"Cuts load and keeps the UPS powered off."},
  "shutdown.stop":{label:"Cancel shutdown",icon:"circle-x",risk:"caution",group:"Power",help:"Attempts to cancel an active shutdown sequence."},
  "driver.killpower":{label:"Emergency killpower",icon:"octagon-alert",risk:"blocked",group:"Power",help:"Manual killpower is blocked in the Web UI and reserved for automated shutdown."},
  "shutdown.default":{label:"Default shutdown",icon:"power-off",risk:"blocked",group:"Power",help:"Blocked for manual execution: behavior varies by driver and UPS model."},
};
const UPS_ALLOWED_COMMANDS=new Set(["beeper.enable","beeper.disable","beeper.toggle","test.battery.start.quick","test.battery.stop","driver.reload","driver.reload-or-error","load.on","shutdown.stop"]);
const RISK_LABELS={normal:"Normal",service:"Service",caution:"Caution",danger:"Danger",blocked:"Blocked",noop:"Nothing to do"};
function ifName(n){return IFACE_NAMES[n]||n}
function svcName(n){return SVC_NAMES[n]||n}
function fmtUptime(s){if(!s)return"";const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return(d?d+"d ":"")+h+"h "+m+"m"}

function progressCard(label,used,total,icon="bar-chart-2"){
  const pct=total>0?Math.round(used/total*100):0;
  const cls=pct>90?"bad":pct>70?"warn":"ok";
  return`<article class="card"><div class="card-header"><div class="card-label">${esc(label)}</div><i data-lucide="${icon}" class="card-micro-icon"></i></div><div class="card-value">${fmtB(used)} <span class="card-unit">/ ${fmtB(total)}</span></div><div class="progress-bar"><div class="progress-fill progress-${cls}" style="width:${pct}%"></div></div><div class="card-detail">${pct}%</div></article>`;
}

// risk "noop" is not "blocked". Blocked means the operator may not do this;
// noop means the box is already in the state the button would produce, so
// pressing it changes nothing. They deserve different words: "Unavailable" on a
// button that would simply do nothing reads as a permission problem and sends
// the operator looking for one.
function actionCard(label, codeName, description, risk, icon, onclick, btnLabel="Run", noopReason=""){
  const cls = risk === "danger" ? "danger" : risk === "caution" ? "caution" : risk === "blocked" ? "blocked" : risk === "noop" ? "noop" : risk === "service" ? "service" : "normal";
  const btnCls = risk === "danger" ? "btn-bad" : risk === "caution" ? "btn-accent" : risk === "blocked" ? "btn-disabled" : risk === "service" ? "" : "btn-ok";
  const actionBtn = risk === "blocked" ? disabledBtn("Unavailable", "lock", "Blocked")
                  : risk === "noop" ? disabledBtn(btnLabel, icon, noopReason)
                  : btn(btnLabel, icon, btnCls, onclick);
  return `<article class="action-card ${cls}">
    <div class="action-head"><i data-lucide="${icon}"></i><div><h3>${esc(label)}</h3><code>${esc(codeName)}</code></div></div>
    <p>${esc(description)}</p>
    <div class="action-foot"><span class="risk ${cls}">${esc(RISK_LABELS[risk]||"Service")}</span>${actionBtn}</div>
  </article>`;
}

// Profiles look alike visually, yet the choice dictates kernel vs userspace execution:
// 2.0 obfuscation requires userspace, whereas legacy profiles run in the kernel module
// and the kernel module accepts 2.0 profiles without error while silently dropping obfuscation.
// Show engine selection explicitly in the UI.
const PROFILE_KIND={
  "2.0":{label:"Amnezia Premium",hint:"Next-gen obfuscation profile; requires the userspace backend."},
  "1.5":{label:"AmneziaWG",hint:"Classic traffic obfuscation handled by the kernel module."},
  "wireguard":{label:"WireGuard",hint:"Standard WireGuard without obfuscation."}
};
const PROFILE_ENGINE={
  kernel:{label:"kernel",hint:"Faster. Not compatible with 2.0 obfuscation."},
  userspace:{label:"userspace",hint:"Required for Amnezia Premium. Lower throughput on high-speed links."}
};

function profileCard(profile){
  const id=esc(profile.id||profile.name||"");
  const isActive=!!profile.active;
  const broken=profile.valid===false;
  const kind=PROFILE_KIND[profile.generation];
  const engine=PROFILE_ENGINE[profile.engine];
  const switchBtn=isActive
    ? disabledBtn("Active","check","This profile is already active")
    : broken
      ? disabledBtn("Activate","alert-triangle",profile.error||"Profile failed validation")
      : btn("Activate","power","btn-ok",`doVpnSwitch(${jsArg(id)})`);
  const delBtn=isActive
    ? disabledBtn("Delete","lock","Switch to another profile first")
    : btn("Delete","trash-2","btn-bad",`doVpnDelete(${jsArg(id)})`);
  return `<article class="profile-card${isActive?" active":""}${broken?" broken":""}">
    <div class="profile-head"><h3>${sensitive(profile.name||profile.id||"",`vpn-profile-${profile.id||profile.name||""}`)}</h3>${isActive?pill("active","ok"):(broken?pill("invalid","bad"):"")}</div>
    <div class="profile-tags">${kind?`<span class="tag" title="${esc(kind.hint)}">${esc(kind.label)}</span>`:""}${engine?`<span class="tag" title="${esc(engine.hint)}">${esc(engine.label)}</span>`:""}</div>
    ${broken?`<p class="profile-error">${esc(profile.error||"")}</p>`:""}
    <div class="profile-meta">${profile.updated?"updated "+esc(fmtTime(profile.updated)):""}</div>
    <div class="profile-foot">${switchBtn}${delBtn}</div>
  </article>`;
}

function tbl(rows,cols){
  if(!rows||!rows.length)return`<p style="color:var(--muted)">No data</p>`;
  const h=cols.map(c=>`<th>${esc(c.label)}</th>`).join("");
  const b=rows.map(r=>`<tr>${cols.map(c=>`<td>${r[c.key]!==undefined&&r[c.key]!==null?esc(r[c.key]):""}</td>`).join("")}</tr>`).join("");
  return`<div class="table-wrap"><table><thead><tr>${h}</tr></thead><tbody>${b}</tbody></table></div>`;
}
function tblHtml(rows,cols){
  if(!rows||!rows.length)return`<p style="color:var(--muted)">No data</p>`;
  const h=cols.map(c=>`<th>${esc(c.label)}</th>`).join("");
  const b=rows.map(r=>`<tr>${cols.map(c=>`<td>${r[c.key]??""}</td>`).join("")}</tr>`).join("");
  return`<div class="table-wrap"><table><thead><tr>${h}</tr></thead><tbody>${b}</tbody></table></div>`;
}

function sparkline(data,color="#22d3ee",w=120,h=28){
  if(data.length<2)return"";
  const mx=Math.max(...data),mn=Math.min(...data),rng=mx-mn||1;
  const points=data.map((v,i)=>{
    const x=i/(data.length-1)*w,y=h-((v-mn)/rng)*(h-4)-2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const gradId=`spark-grad-${Math.random().toString(36).substring(2,9)}`;
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="display:block;overflow:visible;">
    <defs>
      <linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${color}" stop-opacity="0.3"/>
        <stop offset="100%" stop-color="${color}" stop-opacity="0.0"/>
      </linearGradient>
    </defs>
    <polyline fill="none" stroke="${color}" stroke-width="1.5" points="${points}"/>
    <polygon fill="url(#${gradId})" points="0,${h} ${points} ${w},${h}"/>
  </svg>`;
}

function btn(label,icon,cls,onclick){
  return`<button class="btn ${cls}" onclick="${esc(onclick)}"><i data-lucide="${icon}"></i>${esc(label)}</button>`;
}
function disabledBtn(label,icon,reason=""){
  return`<button class="btn btn-disabled" disabled title="${esc(reason)}"><i data-lucide="${icon}"></i>${esc(label)}</button>`;
}

/* ═══ Modal ═══ */
function openModal(title,bodyHtml,footerHtml=""){
  const o=document.getElementById("modalOverlay");o.hidden=false;
  document.getElementById("modalTitle").textContent=title;
  document.getElementById("modalBody").innerHTML=bodyHtml;
  document.getElementById("modalFooter").innerHTML=footerHtml;
  renderIcons(o);
}
function closeModal(){document.getElementById("modalOverlay").hidden=true}
function confirmModal(message,title="Confirm",danger=false){
  return new Promise(resolve=>{
    openModal(title,`<div class="warning-box ${danger?"danger":""}">${esc(message)}</div>`,
      `<button class="btn" id="modalCancel">Cancel</button><button class="btn ${danger?"btn-bad":"btn-ok"}" id="modalOk">Confirm</button>`);
    document.getElementById("modalCancel").onclick=()=>{closeModal();resolve(false)};
    document.getElementById("modalOk").onclick=()=>{closeModal();resolve(true)};
  });
}
function promptModal(message,value="",title="Input"){
  return new Promise(resolve=>{
    openModal(title,`<div class="form-group"><label>${esc(message)}</label><input class="form-input" id="modalPromptInput" value="${esc(value)}"></div>`,
      `<button class="btn" id="modalCancel">Cancel</button><button class="btn btn-ok" id="modalOk">OK</button>`);
    const input=document.getElementById("modalPromptInput");input.focus();input.select();
    document.getElementById("modalCancel").onclick=()=>{closeModal();resolve(null)};
    document.getElementById("modalOk").onclick=()=>{const v=input.value;closeModal();resolve(v)};
    input.onkeydown=e=>{if(e.key==="Enter")document.getElementById("modalOk").click()};
  });
}

/* ═══ Write actions ═══ */

/* Report what the backend measured, not what we asked for.
   Four toasts here used to invent their own result: `r.active` (a field that
   never existed), the name of the action, a literal from api.py, and the
   number of lines the operator typed. All four were painted "success"
   unconditionally. The verdict now arrives in `r.action` -- state, sentence
   and colour -- and this function only draws it. A reply without that block
   is not assumed to have gone well: it is "result not verified". */
function actionToast(r, fallback){
  const a = r && r.action;
  if(!a || !a.state || !a.label){
    toast(fallback ? `${fallback}: result not verified` : "Result not verified", "warning");
    return;
  }
  toast(a.detail ? `${a.label}: ${a.detail}` : a.label, a.level || "warning");
}

async function doRestart(unit){
  if(!await confirmModal(`Restart ${unit}?`, "Service Restart"))return;
  try{const r=await post("/api/services/manage",{unit, action:"restart"});actionToast(r,unit);loadView()}catch(e){toast(e.message)}
}
async function doFirewallReload(){
  if(!await confirmModal("Reload PF firewall?", "PF Reload"))return;
  try{await post("/api/pf/reload",{});toast("PF reloaded","success");loadView()}catch(e){toast(e.message)}
}
async function doManageService(unit,action){
  const verb={start:"start",stop:"stop",restart:"restart",enable:"enable",disable:"disable"}[action]||action;
  if(!await confirmModal(`Do you want to ${verb} ${unit}?`, "Service Control"))return;
  try{const r=await post("/api/services/manage",{unit, action});actionToast(r,unit);loadView()}catch(e){toast(e.message)}
}
async function doPppoeReconnect(){
  if(!await confirmModal("Reconnect PPPoE?", "WAN"))return;
  try{toast("Reconnecting PPPoE…","info");const r=await post("/api/pppoe/reconnect",{});actionToast(r,"PPPoE");loadView()}catch(e){toast(e.message)}
}

let termContainer = null;
let isPollingTerminal = false;

async function closeTerminalSession(){
  isPollingTerminal=false;
  if(S.termResizeObserver) S.termResizeObserver.disconnect();
  // Otherwise a coalesced resize fires after the session is gone and starts a
  // fresh one, which is how a closed terminal comes back to life.
  if(S.termResizeTimer){ clearTimeout(S.termResizeTimer); S.termResizeTimer=null; }
  if(S.term){
    try{S.term.dispose();}catch(e){}
    S.term=null;
    S.fitAddon=null;
  }
  try{await post("/api/terminal/close",{});}catch(e){}
}

function utob(str) {
  return btoa(Array.from(new TextEncoder().encode(str), b => String.fromCharCode(b)).join(''));
}

async function startTerminalPolling() {
  if (isPollingTerminal) return;
  isPollingTerminal = true;
  const currentTerm = S.term;
  while (S.view === "admin" && S.term === currentTerm) {
    try {
      const r = await api("/api/terminal/read");
      if (r.data && S.term === currentTerm) {
        const binaryString = atob(r.data);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        S.term.write(bytes);
      }
    } catch (e) {
      console.error("Terminal read error:", e);
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  if (S.term === currentTerm) {
      isPollingTerminal = false;
  }
}
function mountTerminal() {
  const placeholder = document.getElementById("termPlaceholder");
  if (!placeholder) return;

  if (S.term) {
    try {
      S.term.dispose();
    } catch(e) {}
    S.term = null;
    S.fitAddon = null;
    isPollingTerminal = false;
  }

  placeholder.style.height = "400px";
  placeholder.style.borderRadius = "6px";
  placeholder.style.overflow = "hidden";
  placeholder.style.padding = "4px";
  placeholder.style.background = "#000";

  S.term = new Terminal({
    cursorBlink: true,
    fontFamily: 'monospace',
    fontSize: 13,
    theme: {
      background: '#000000',
      foreground: '#00ff00',
      cursor: '#00ff00'
    }
  });

  S.fitAddon = new FitAddon.FitAddon();
  S.term.loadAddon(S.fitAddon);

  S.term.onData(data => {
    post("/api/terminal/write", { data: utob(data) }).catch(console.error);
  });

  // xterm.js fires this whenever the grid changes size, fitAddon.fit()
  // included. Until now the size stopped right here: fit() resized the widget
  // in the page and nothing told the pty, which stayed at the 0x0 a fresh one
  // is born with. That is why top, vi and less drew at the wrong size.
  // Coalesced, because dragging a window emits a burst of these.
  S.term.onResize(({ cols, rows }) => {
    if (S.termResizeTimer) clearTimeout(S.termResizeTimer);
    S.termResizeTimer = setTimeout(() => {
      S.termResizeTimer = null;
      post("/api/terminal/resize", { cols, rows }).catch(console.error);
    }, 120);
  });

  S.term.open(placeholder);

  if (!S.termResizeObserver) {
    S.termResizeObserver = new ResizeObserver(() => {
      if (S.fitAddon && placeholder.offsetWidth > 0) {
        try { S.fitAddon.fit(); } catch(e) {}
        if (!isPollingTerminal) startTerminalPolling();
      }
    });
  }
  S.termResizeObserver.disconnect(); // Clear previous observations if any
  S.termResizeObserver.observe(placeholder);

  setTimeout(() => {
    if (S.fitAddon && placeholder.offsetWidth > 0) {
      S.fitAddon.fit();
      if (!isPollingTerminal) startTerminalPolling();
    }
    if (S.term) S.term.focus();
  }, 50);
}
async function doPkgUpdate(){
  openModal("Checking package updates...", `<div style="background:#111;color:#0f0;padding:12px;border-radius:6px;height:300px;overflow-y:auto;font-family:monospace;white-space:pre-wrap;font-size:13px;line-height:1.4;" id="pkg_update_log">Running pkg update...</div>`, `<button class="btn btn-ok" id="pkg_update_close" disabled onclick="closeModal()">Please wait...</button>`);
  try{
    const r=await post("/api/system/updates/check",{});
    const out = document.getElementById("pkg_update_log");
    if(out) out.textContent = r.output || "Check finished";
    const btn = document.getElementById("pkg_update_close");
    if(btn) { btn.disabled = false; btn.textContent = "Close"; }
    loadView();
  }catch(e){
    const out = document.getElementById("pkg_update_log");
    if(out) out.textContent = "Error: " + e.message;
    const btn = document.getElementById("pkg_update_close");
    if(btn) { btn.disabled = false; btn.textContent = "Close"; }
  }
}
let pkgPollInterval = null;
async function doPkgUpgrade(){
  if(!await confirmModal("Install missing required packages and upgrade installed ones? This may take a few minutes.", "Package Maintenance"))return;
  openModal("Installing and upgrading packages...", `<div style="background:#111;color:#0f0;padding:12px;border-radius:6px;height:350px;overflow-y:auto;font-family:monospace;white-space:pre-wrap;font-size:13px;line-height:1.4;" id="pkg_log_output">Initializing...</div>`, `<button class="btn btn-ok" id="pkg_log_close" disabled onclick="closeModal()">Please wait...</button>`);
  
  try{
    const r = await post("/api/system/updates/install",{});
    if(!r.ok && r.error) throw new Error(r.error);
    
    if(pkgPollInterval) clearInterval(pkgPollInterval);
    pkgPollInterval = setInterval(async () => {
      try {
        const log = await api("/api/system/updates/log");
        const out = document.getElementById("pkg_log_output");
        if(out) {
            const isAtBottom = out.scrollHeight - out.scrollTop <= out.clientHeight + 20;
            out.textContent = log.lines.join("\n");
            if(isAtBottom) out.scrollTop = out.scrollHeight;
        }
        if(!log.running) {
            clearInterval(pkgPollInterval);
            const succeeded = log.ok === true;
            const btn = document.getElementById("pkg_log_close");
            if(btn) { btn.disabled = false; btn.textContent = succeeded ? "Done (Close)" : "Error (Close)"; }
            if(out) {
                const detail = !succeeded && log.error ? `: ${log.error}` : "";
                out.textContent += succeeded
                  ? "\n\n[Installation and upgrade completed successfully]"
                  : `\n\n[Package maintenance failed${detail}]`;
                out.scrollTop = out.scrollHeight;
            }
            loadView();
        }
      } catch(e){}
    }, 1500);
  }catch(e){
    toast(e.message);
    const out = document.getElementById("pkg_log_output");
    if(out) out.textContent += "\nError: " + e.message;
    const btn = document.getElementById("pkg_log_close");
    if(btn) { btn.disabled = false; btn.textContent = "Close"; }
  }
}

function showAddLease(mac="", ip="", hostname=""){
  openModal("Add Static DHCP Lease",`
    <div class="form-row">
      <div class="form-group"><label>MAC</label>${sensitiveHtml(`<input class="form-input" id="f_mac" value="${esc(mac)}" placeholder="aa:bb:cc:dd:ee:ff">`,"dhcp-add-mac")}</div>
      <div class="form-group"><label>IP</label>${sensitiveHtml(`<input class="form-input" id="f_ip" value="${esc(ip)}" placeholder="LAN IP">`,"dhcp-add-ip")}</div>
    </div>
    <div class="form-group"><label>Hostname</label>${sensitiveHtml(`<input class="form-input" id="f_host" value="${esc(hostname)}" placeholder="device-name">`,"dhcp-add-hostname")}</div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="doAddLease()">Add</button>`);
}
async function doAddLease(){
  const mac=document.getElementById("f_mac").value,ip=document.getElementById("f_ip").value,hostname=document.getElementById("f_host").value;
  try{await post("/api/dhcp/static/add",{mac,ip,hostname});closeModal();toast("Lease added","success");loadView()}catch(e){toast(e.message)}
}
async function doRemoveLease(mac){
  if(!await confirmModal(`Remove static lease ${mac}?`, "DHCP", true))return;
  try{await post("/api/dhcp/static/remove",{mac});toast("Lease removed","success");loadView()}catch(e){toast(e.message)}
}

function showEditLease(mac, ip, hostname) {
  openModal("Edit Static DHCP Lease",`
    <div class="form-row">
      <div class="form-group"><label>MAC</label>${sensitiveHtml(`<input class="form-input" id="e_mac" value="${esc(mac)}" placeholder="aa:bb:cc:dd:ee:ff">`,"dhcp-edit-mac")}</div>
      <div class="form-group"><label>IP</label>${sensitiveHtml(`<input class="form-input" id="e_ip" value="${esc(ip)}" placeholder="LAN IP">`,"dhcp-edit-ip")}</div>
    </div>
    <div class="form-group"><label>Hostname</label>${sensitiveHtml(`<input class="form-input" id="e_host" value="${esc(hostname)}" placeholder="device-name">`,"dhcp-edit-hostname")}</div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="doEditLease(${escJs(mac)})">Save</button>`);
}

async function doEditLease(oldMac) {
  const mac=document.getElementById("e_mac").value,ip=document.getElementById("e_ip").value,hostname=document.getElementById("e_host").value;
  try{
    if(oldMac && oldMac.toLowerCase() !== mac.toLowerCase()) {
      await post("/api/dhcp/static/remove",{mac:oldMac});
    } else {
      await post("/api/dhcp/static/remove",{mac:oldMac});
    }
    await post("/api/dhcp/static/add",{mac,ip,hostname});
    closeModal();toast("Lease updated","success");loadView();
  }catch(e){toast(e.message)}
}

async function showDnsEdit(current){
  if(!current){
    let upstreams=S.cache.get("/api/dhcp")?.upstreams;
    if(!Array.isArray(upstreams)){
      try{upstreams=(await api("/api/dhcp"))?.upstreams}catch{}
    }
    current=Array.isArray(upstreams)?upstreams.join(", "):"";
  }
  const servers=(current||"").split(/[,\s]+/).filter(Boolean).join("\n");
  openModal("DNS Servers",`
    <div class="form-group"><label>Servers (one per line)</label>${sensitiveHtml(`<textarea class="form-input" id="f_dns" rows="4" style="resize:vertical">${esc(servers)}</textarea>`,"dhcp-dns-servers",true)}</div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-accent" onclick="doDnsApply()">Apply</button>`);
}
async function doDnsApply(){
  const raw=document.getElementById("f_dns").value;
  const servers=raw.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
  try{await post("/api/dns/upstreams",{servers});closeModal();toast("DNS updated","success");loadView()}catch(e){toast(e.message)}
}

/* ═══ Package sources ═══ */
// Cache the latest sources payload received from the server
let _repoSourcesCache = null;

/**
 * Renders the body content for the repository sources settings card.
 * @param {Object} data - GET /api/repo/sources response payload
 * @returns {string} HTML markup to be placed inside a section
 */
function renderRepoSources(data) {
  _repoSourcesCache = data;

  const activeUrl = data.active || "";
  const appliedUrl = data.applied || "";
  const configPath = data.path || "/usr/local/etc/gatebsd/repo-sources.conf";
  const sourcesList = Array.isArray(data.sources) ? data.sources : [];

  let html = '<div class="repo-sources-manager" style="display:flex;flex-direction:column;gap:14px;">';

  // Broken configuration file warning
  if (data.error) {
    html += `
      <div style="padding:12px;border-radius:6px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.35);">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
          ${pill("Config File Error", "bad")}
          <strong style="color:var(--error);">Sources file corrupted</strong>
        </div>
        <p style="margin:0;font-size:13px;line-height:1.4;">
          Cannot read configuration file <code>${esc(configPath)}</code>: ${esc(data.error)}.
          Package checks and upgrades cannot run until this is resolved.
        </p>
      </div>
    `;
  }

  // Active / Applied status summary
  html += '<div style="display:flex;flex-direction:column;gap:6px;">';
  if (appliedUrl) {
    html += `
      <div style="font-size:14px;">
        <span style="color:var(--text-muted);">Active source:</span>
        <strong style="margin-left:4px;">${sensitive(appliedUrl,`repo-url-${appliedUrl}`)}</strong>
        ${appliedUrl === data.default ? ` <span style="margin-left:6px;">${pill("Default", "ok")}</span>` : ""}
      </div>
    `;
  } else {
    html += `
      <div style="font-size:14px;color:var(--warn);">
        ${pill("Unconfigured", "warn")} No package source configured yet
      </div>
    `;
  }

  // Notice if user changed the source but application hasn't succeeded or synced yet
  if (activeUrl && appliedUrl && activeUrl !== appliedUrl) {
    html += `
      <div style="padding:10px 12px;border-radius:6px;background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.35);font-size:13px;line-height:1.4;">
        <strong>Warning:</strong> Selected address <code>${sensitive(activeUrl,`repo-url-${activeUrl}`)}</code>, but the system is still using <code>${sensitive(appliedUrl,`repo-url-${appliedUrl}`)}</code>.
        Selection is saved in settings but not yet applied to pkg(8) (typically after an interrupted switch).
      </div>
    `;
  }
  html += '</div>';

  // List of known mirrors as selectable radio buttons
  html += '<div>';
  html += '<div style="font-weight:600;margin-bottom:8px;font-size:13px;">Saved sources:</div>';

  if (sourcesList.length > 0) {
    html += '<div style="display:flex;flex-direction:column;gap:6px;margin-bottom:10px;">';
    sourcesList.forEach((src, idx) => {
      const url = typeof src === "string" ? src : (src.url || "");
      if (!url) return;

      const isChecked = url === activeUrl || (idx === 0 && !activeUrl);
      const isApplied = url === appliedUrl;

      html += `
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;padding:6px 8px;border-radius:4px;border:1px solid rgba(255,255,255,0.06);">
          <input type="radio" name="repo_source_selection" id="repo_src_${idx}" value="${esc(url)}" ${isChecked ? "checked" : ""}>
          <span style="flex:1;font-family:monospace;font-size:13px;">${sensitive(url,`repo-url-${url}`)}</span>
          ${isApplied ? pill("Active", "ok") : ""}
          ${url === data.default ? pill("Default", "warn") : ""}
        </label>
      `;
    });
    html += '</div>';
  } else {
    html += '<div style="font-size:13px;color:var(--text-muted);margin-bottom:10px;">No saved sources.</div>';
  }
  html += '</div>';

  // Hand-typed address field
  html += `
    <div>
      <label for="repo_custom_url" style="display:block;font-weight:600;margin-bottom:6px;font-size:13px;">Or enter a custom URL:</label>
      ${sensitiveHtml(`<input type="text" id="repo_custom_url" placeholder="http://192.168.1.10" style="width:100%;box-sizing:border-box;padding:8px 10px;border-radius:4px;border:1px solid rgba(255,255,255,0.15);background:rgba(0,0,0,0.25);color:inherit;font-size:13px;">`,"repo-custom-url")}
      <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">
        When filled, this URL overrides the radio selection above.
      </div>
    </div>
  `;

  // Action buttons
  html += `
    <div style="display:flex;gap:10px;align-items:center;margin-top:6px;">
      ${btn("Apply", "check", "btn-ok", "doRepoApply()")}
      ${btn("Scan LAN", "search", "btn-accent", "doRepoScan()")}
    </div>
  `;

  html += '</div>';
  return html;
}

/**
 * Initiates discovery of mirror servers on the local network and presents results in a modal.
 */
async function doRepoScan() {
  const confirmed = await confirmModal(
    "Scanning probes known local addresses for signed package repositories and may take up to 30 seconds. Start scan?",
    "Scan Network for Package Mirrors",
    false
  );

  if (!confirmed) {
    return;
  }

  try {
    const res = await post("/api/repo/scan", {});
    const candidates = Array.isArray(res.candidates) ? res.candidates : [];

    // Sort working candidates to the top
    const sortedCandidates = [...candidates].sort((a, b) => {
      if (a.ok === b.ok) return 0;
      return a.ok ? -1 : 1;
    });

    let bodyHtml = '<div style="display:flex;flex-direction:column;gap:12px;">';
    bodyHtml += `
      <p style="margin:0;font-size:13px;line-height:1.4;color:var(--text-muted);">
        A green badge confirms the mirror returned a verified catalogue signed by the trusted repository key.
      </p>
    `;

    if (sortedCandidates.length === 0) {
      bodyHtml += '<div style="padding:16px;text-align:center;font-size:14px;color:var(--text-muted);">No reachable package mirrors found on the local network.</div>';
    } else {
      bodyHtml += '<div style="display:flex;flex-direction:column;gap:8px;max-height:360px;overflow-y:auto;">';
      sortedCandidates.forEach(cand => {
        const isOk = Boolean(cand.ok);
        const url = cand.url || "";
        const detail = cand.detail || (isOk ? "Signature verified" : "Unreachable or missing required packages");

        bodyHtml += `
          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);background:rgba(255,255,255,0.02);">
            <div style="display:flex;flex-direction:column;gap:3px;min-width:0;flex:1;">
              <div style="display:flex;align-items:center;gap:8px;">
                ${pill(isOk ? "Ready" : "Unavailable", isOk ? "ok" : "bad")}
                <span style="font-family:monospace;font-size:13px;word-break:break-all;">${sensitive(url,`repo-url-${url}`)}</span>
              </div>
              <div style="font-size:12px;color:var(--text-muted);">${esc(detail)}</div>
            </div>
            ${isOk ? `<div>${btn("Select", "check", "btn-ok", `doRepoApply(${jsArg(url)})`)}</div>` : ""}
          </div>
        `;
      });
      bodyHtml += '</div>';
    }
    bodyHtml += '</div>';

    const footerHtml = btn("Close", "x", "btn-accent", "closeModal()");
    openModal("Package Mirror Scan Results", bodyHtml, footerHtml);
  } catch (err) {
    const errorMsg = err.error || err.message || "Failed to scan local network for mirrors";
    toast(errorMsg, "error");
  }
}

/**
 * Applies the selected repository source, updates configuration, and re-indexes package catalogs.
 * @param {string} [urlFromScan] - Explicit repository URL chosen from scan results modal
 */
async function doRepoApply(urlFromScan) {
  let targetUrl = "";

  if (typeof urlFromScan === "string" && urlFromScan.trim()) {
    targetUrl = urlFromScan.trim();
  } else {
    const customInput = document.getElementById("repo_custom_url");
    const customVal = customInput ? customInput.value.trim() : "";

    if (customVal) {
      targetUrl = customVal;
    } else {
      const checkedRadio = document.querySelector('input[name="repo_source_selection"]:checked');
      if (checkedRadio) {
        targetUrl = checkedRadio.value.trim();
      }
    }
  }

  if (!targetUrl) {
    toast("Select a mirror from the list or enter a URL manually", "error");
    return;
  }

  // Preserve all currently known sources plus the newly chosen target
  const knownSet = new Set();
  if (_repoSourcesCache && Array.isArray(_repoSourcesCache.sources)) {
    _repoSourcesCache.sources.forEach(src => {
      const u = typeof src === "string" ? src : (src.url || "");
      if (u) knownSet.add(u);
    });
  }
  knownSet.add(targetUrl);
  const knownList = Array.from(knownSet);

  const confirmed = await confirmModal(
    `Switch package mirror to:\n${targetUrl}\n\nThe system will contact the server immediately and refresh the local package list. Apply?`,
    "Switch Package Source",
    false
  );

  if (!confirmed) {
    return;
  }

  try {
    await post("/api/repo/sources", {
      active: targetUrl,
      known: knownList
    });

    toast("Package source updated", "success");
    closeModal();
    if (typeof loadView === "function") {
      loadView();
    }
  } catch (err) {
    const info = (err && err.payload) || {};
    let msg = (err && err.message) || "Failed to switch package source";

    if (typeof info.detail === "string" && info.detail && info.detail.length < 120) {
      msg += ` (${info.detail})`;
    }

    // Only say what the server actually reported. A validation error changes
    // nothing on disk and carries no rollback flag at all, so guessing "maybe
    // it half applied" there would frighten the operator over a typo.
    if (info.rolled_back === true) {
      msg += ". Nothing changed: device remains on previous source.";
    } else if (info.rolled_back === false) {
      msg += ". Failed to restore previous source — verify device config.";
    }

    toast(msg, "error");
  }
}

/* ═══ UPS actions ═══ */
async function doUpsCmd(cmd){
  const meta=UPS_CMD_LABELS[cmd]||{label:cmd,risk:"service",help:"Command exposed by the UPS driver."};
  if(!UPS_ALLOWED_COMMANDS.has(cmd)){toast(`Command ${cmd} is blocked by security policy`);return}
  if(meta.risk==="danger"){
    const typed=await promptModal(`Dangerous power command. Type to confirm: ${cmd}`,"","UPS: Dangerous Action");
    if(typed!==cmd)return;
  }else if(!await confirmModal(`${meta.label}\n\n${meta.help}`, "UPS", meta.risk==="caution"))return;
  try{const r=await post("/api/ups/command",{command:cmd, confirmation:cmd});toast(r.output||`UPS ${cmd}: OK`,r.ok?"success":"error");loadView()}catch(e){toast(e.message)}
}
async function doUpsRestart(){
  if(!await confirmModal("Restart NUT driver, server, and monitor?", "NUT Restart"))return;
  try{await post("/api/ups/restart",{});toast("NUT restarted","success");loadView()}catch(e){toast(e.message)}
}
function showUpsConfig(){
  const c=S.cache.get("/api/ups/config")||{};
  const listeners=(c.listeners||[]).map(l=>l.address||l).join(",");
  openModal("NUT Configuration",`
    <div class="form-grid">
      <div class="form-group"><label>UPS name</label><input class="form-input" id="nutName" value="${esc(c.name||"ippon")}"></div>
      <div class="form-group"><label>Driver</label><input class="form-input" id="nutDriver" value="${esc(c.driver||"nutdrv_qx")}"></div>
      <div class="form-group"><label>Port</label><input class="form-input" id="nutPort" value="${esc(c.port||"/dev/cuaU0")}"></div>
      <div class="form-group"><label>Mode</label><select class="form-input" id="nutMode"><option value="standalone" ${c.mode==="standalone"?"selected":""}>standalone</option><option value="netserver" ${c.mode==="netserver"?"selected":""}>netserver</option></select></div>
      <div class="form-group"><label>Listen IP</label><input class="form-input" id="nutListeners" value="${esc(listeners||"127.0.0.1")}"></div>
      <div class="form-group"><label>Description</label><input class="form-input" id="nutDesc" value="${esc(c.description||"")}"></div>
      <div class="form-group"><label>Low charge, %</label><input class="form-input" id="nutLowCharge" type="number" min="1" max="95" value="${esc(c.low_charge||40)}"></div>
      <div class="form-group"><label>Low runtime, sec</label><input class="form-input" id="nutLowRuntime" type="number" min="60" max="86400" value="${esc(c.low_runtime||900)}"></div>
      <div class="form-group"><label>Off delay, sec</label><input class="form-input" id="nutOffDelay" type="number" min="0" max="3600" value="${esc(c.offdelay||90)}"></div>
      <div class="form-group"><label>On delay, sec</label><input class="form-input" id="nutOnDelay" type="number" min="0" max="7200" value="${esc(c.ondelay||180)}"></div>
      <div class="form-group"><label>Master user</label><input class="form-input" id="nutMasterUser" value="${esc(c.master_user||"upsmon-master")}"></div>
      <div class="form-group"><label>Client user</label><input class="form-input" id="nutClientUser" value="${esc(c.client_user||"upsmon-client")}"></div>
      <div class="form-group"><label>Master password</label><input class="form-input" id="nutMasterPass" type="password" placeholder="keep existing or generate"></div>
      <div class="form-group"><label>Client password</label><input class="form-input" id="nutClientPass" type="password" placeholder="keep existing or generate"></div>
    </div>
    <label style="display:flex;align-items:center;gap:8px;margin-top:8px"><input id="nutKillpower" type="checkbox" ${c.allow_killpower?"checked":""}> allow_killpower</label>
    <div class="card-detail" style="margin-top:10px">Saving updates configs under ${esc(c.dir||"/usr/local/etc/nut")}, creates a backup, and probes connectivity after restart.</div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="doUpsConfigSave()">Save</button>`);
}
async function doUpsConfigSave(){
  const v=id=>document.getElementById(id).value.trim();
  const payload={
    name:v("nutName"),driver:v("nutDriver"),port:v("nutPort"),mode:v("nutMode"),
    listeners:v("nutListeners"),description:v("nutDesc"),
    low_charge:v("nutLowCharge"),low_runtime:v("nutLowRuntime"),
    offdelay:v("nutOffDelay"),ondelay:v("nutOnDelay"),
    allow_killpower:document.getElementById("nutKillpower").checked,
    master_user:v("nutMasterUser"),client_user:v("nutClientUser"),
    master_password:v("nutMasterPass"),client_password:v("nutClientPass")
  };
  try{
    const r=await post("/api/ups/config",payload);
    closeModal();
    openModal("NUT Applied",`<div class="metric-grid">${card("Backup",esc(r.backup?.dir||""))}${card("UPS",esc(r.target||""))}${card("Link probe",pill(r.probe?.ok?"ok":"error",r.probe?.ok?"ok":"bad"))}</div>`,`<button class="btn btn-ok" onclick="closeModal();loadView()">OK</button>`);
  }catch(e){toast(e.message)}
}

/* ═══ WAN failover actions ═══ */
async function doWanTest(iface){
  toast(`Testing ${iface}…`,"success");
  try{const r=await post("/api/wan/test",{iface});toast(`${iface}: avg=${r.avg_ms}ms loss=${r.loss_pct}%`,r.ok?"success":"error")}catch(e){toast(e.message)}
}

/* ═══ AmneziaWG / pf split actions ═══ */
function amneziaProfile(){
  const data=S.cache.get("/api/amnezia")||{};
  const wan=S.cache.get("/api/wan")||{};
  return (data.config?.profiles||[])[0]||{name:"",interface:"",lan_interface:wan.sys?.lan_iface||"",source_cidr:wan.sys?.lan_cidr||"",mark:"",table:"",mode:"ru_bypass",set:"ru_bypass",enabled:false};
}
function amneziaActiveConfigName(){
  const a=S.cache.get("/api/amnezia")||{};
  const active=a.active_config||{};
  const p=amneziaProfile();
  return String(active.target_name||active.active_config||active.name||p.active_config||"").replace(/\.conf$/,"");
}
function amneziaActiveConfigLabel(){
  const name=amneziaActiveConfigName();
  return name ? `${name}.conf` : "none selected";
}
function selectedVpnProfileId(){
  const vpn=S.cache.get("/api/vpn/status")||{};
  const vpnProfiles=S.cache.get("/api/vpn/profiles")||{};
  const profiles=vpn.profiles||vpnProfiles.profiles||[];
  return vpn.active_profile||vpnProfiles.active||(profiles[0]?.id||"");
}
async function doAmneziaTunnel(enabled){
  const profileId=selectedVpnProfileId();
  const vpn=S.cache.get("/api/vpn/status")||{};
  const iface=vpn.interface||"awg0";
  const title=enabled?"Start VPN Tunnel":"Stop VPN Tunnel";
  const body=enabled
    ? `<div class="warning-box">
        <div><b>Active profile:</b> ${esc(profileId||"none selected")}</div>
        <div><b>Target interface:</b> ${esc(iface)}</div>
        <div><b>Actions:</b> initialize pf/routes, then restart amnezia with rollback on failure.</div>
      </div>`
    : `<div class="warning-box">
        <div><b>Service stopped:</b> amnezia</div>
        <div><b>Cleared:</b> managed PBR rules and VPN routing table.</div>
      </div>`;
  const ok=await new Promise(resolve=>{
    openModal(title,body,`<button class="btn" id="modalCancel">Cancel</button><button class="btn ${enabled?"btn-ok":"btn-bad"}" id="modalOk">${enabled?"Start VPN":"Stop VPN"}</button>`);
    document.getElementById("modalCancel").onclick=()=>{closeModal();resolve(false)};
    document.getElementById("modalOk").onclick=()=>{closeModal();resolve(true)};
  });
  if(!ok)return;
  try{
    toast(enabled?"Starting VPN tunnel...":"Stopping VPN tunnel...","success");
    if(enabled&&!profileId){
      toast("Upload a VPN profile first", "error");
      return;
    }
    const r=enabled?await post("/api/vpn/profile/switch",{id:profileId}):await post("/api/vpn/stop",{});
    const stepText=(r.steps||[]).map(s=>`${s.ok===false?"FAIL":"OK"} ${s.stage}`).join(" / ");
    toast(`VPN ${enabled?"started":"stopped"}: ${r.active||"unknown"} (${r.interface||iface})`,"success");
    if(stepText){
      openModal("VPN Result",`<div class="metric-grid">${card("Service",pill(r.active?"active":"inactive", r.active?"ok":"bad"))}${card("Interface",esc(r.interface||iface))}${card("Profile",esc(profileId||""))}</div>${pre(stepText)}`,`<button class="btn btn-ok" onclick="closeModal()">OK</button>`);
    }
    loadView();
  }catch(e){toast(e.message)}
}
async function doAmneziaRepoSetup(){
  toast("AmneziaWG is already installed via pkg","info");
}
async function doAmneziaUpdateRuIps(){
  if(!await confirmModal("Update policy bypass tables now?", "Route Table Update"))return;
  try{const r=await post("/api/amnezia/update-ru-ips",{});toast(r.output||"RU zone updated",r.ok?"success":"error");loadView()}catch(e){toast(e.message)}
}
function showAmneziaDiagnose(mode){
  openModal(mode==="traceroute"?"Traceroute":"Curl check",`
    <div class="form-group"><label>Target</label><input class="form-input" id="diag_target" placeholder="${mode==="traceroute"?"8.8.8.8":"ozon.ru"}"></div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-accent" onclick="doAmneziaDiagnose(${escJs(mode)})">Run</button>`);
}
async function doAmneziaDiagnose(mode){
  const target=document.getElementById("diag_target").value.trim();
  try{
    const r=await post("/api/amnezia/diagnose",{mode,target});
    openModal("Diagnostics",`<h3 style="font-size:13px;margin-bottom:8px">route</h3>${pre(r.route?.stdout||r.route?.stderr||"")}<h3 style="font-size:13px;margin:12px 0 8px">output</h3>${pre(r.command?.stdout||r.command?.stderr||r.command?.error||"")}`,`<button class="btn" onclick="closeModal()">Close</button>`);
  }catch(e){toast(e.message)}
}

let vpnLogSocket = null;
function showVpnUpload(type){
  openModal(type==="premium"?"Upload Premium Profile":"Upload Self-Hosted Profile",`
    <div class="form-row">
      <div class="form-group"><label>Profile Name</label>${sensitiveHtml(`<input class="form-input" id="vpn_profile_name" value="${type==="premium"?"premium":"selfhosted"}">`,"vpn-upload-name")}</div>
      <div class="form-group"><label>.conf File</label>${sensitiveHtml(`<input class="form-input" id="vpn_profile_file" type="file" accept=".conf,text/plain">`,"vpn-upload-file")}</div>
    </div>
    <div class="form-group"><label>AmneziaWG config</label>${sensitiveHtml(`<textarea class="form-input" id="vpn_profile_content" rows="14" style="resize:vertical"></textarea>`,"vpn-upload-content",true)}</div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="doVpnUpload(${escJs(type)})">Save Profile</button>`);
  const file=document.getElementById("vpn_profile_file");
  file.addEventListener("change",async()=>{
    const f=file.files?.[0];
    if(!f)return;
    document.getElementById("vpn_profile_name").value=f.name.replace(/\.conf$/,"");
    document.getElementById("vpn_profile_content").value=await f.text();
  });
}
async function doVpnUpload(type){
  const name=document.getElementById("vpn_profile_name").value.trim();
  const content=document.getElementById("vpn_profile_content").value;
  try{
    const r=await post("/api/vpn/profile/upload",{type,name,content});
    closeModal();
    toast(`Profile saved: ${r.profile?.id||name}`,"success");
    loadView();
  }catch(e){toast(e.message)}
}
async function doVpnSwitch(id){
  if(!await confirmModal(`Switch VPN to profile ${id}? Current tunnel will stop and the new one will start, rolling back automatically on failure.`, "Switch VPN Profile"))return;
  try{
    openModal("Switching VPN",`<p>Stopping current tunnel, activating profile, applying pf/routes, and starting service.</p>`);
    const r=await post("/api/vpn/profile/switch",{id});
    closeModal();
    toast(`VPN active: ${r.interface}`,"success");
    loadView();
  }catch(e){closeModal();toast(e.message)}
}
async function doVpnDelete(id){
  if(!await confirmModal(`Delete inactive VPN profile ${id}? A backup is created before removal. Active profile cannot be deleted.`, "Delete VPN Profile"))return;
  try{
    const r=await post("/api/vpn/profile/delete",{id});
    toast(`Profile deleted: ${r.profile}`,"success");
    loadView();
  }catch(e){toast(e.message)}
}
async function doVpnInit(kind){
  const label=kind==="pf"?"persistent pf configuration":"idempotent route scripts";
  if(!await confirmModal(`Apply ${label}?`, "VPN init"))return;
  try{
    const r=await post(kind==="pf"?"/api/vpn/init/pf":"/api/vpn/init/routes",{});
    toast(r.ok?"Initialization complete":"Initialization failed",r.ok?"success":"error");
    loadView();
  }catch(e){toast(e.message)}
}
function showVpnNft(setName,action){
  const isAdd=action==="add";
  openModal(`${isAdd?"Add to":"Remove from"} ${setName}`,`
    <div class="form-group"><label>IP/CIDR, one per line</label><textarea class="form-input" id="vpn_pf_values" rows="8" style="resize:vertical"></textarea></div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn ${isAdd?"btn-ok":"btn-bad"}" onclick="doVpnNft(${escJs(setName)},${escJs(action)})">${isAdd?"Add":"Remove"}</button>`);
}
async function doVpnNft(setName,action){
  const values=document.getElementById("vpn_pf_values").value.split(/\s+/).map(v=>v.trim()).filter(Boolean);
  const apiAction = action === "add" ? "plus" : "minus";
  try{
    const r=await post(`/api/vpn/nft/${apiAction}`,{set:setName,values});
    closeModal();
    actionToast(r,setName);
    loadView();
  }catch(e){toast(e.message)}
}
function showVpnException(){
  openModal("Add Routing Policy Rule",`
    <div class="form-group"><label>Direction</label><select class="form-input" id="vpn_exception_direction"><option value="direct">direct</option><option value="vpn">via VPN</option><option value="default">default</option></select></div>
    <div class="form-group"><label>Domain or IPv4/CIDR</label><input class="form-input" id="vpn_exception_value" placeholder="example.com or 203.0.113.0/24"></div>
    <div class="card-detail">Rules persist across scheduled route table updates and re-resolve automatically. "Default" leaves the exception table unchanged.</div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="doVpnExceptionAdd()">Add</button>`);
}
async function doVpnExceptionAdd(){
  const value=document.getElementById("vpn_exception_value").value.trim();
  const direction=document.getElementById("vpn_exception_direction").value;
  if(!value){toast("Enter a domain or network","error");return}
  try{
    const r=await post("/api/vpn/exceptions/add",{value,direction});
    closeModal();
    const warn=(r.warnings||[]).find(w=>w.value===value)||(r.warnings||[])[0];
    if(warn)toast(warn.msg,"error");
    else toast(r.changed?"Rule added":"Rule already exists",r.changed?"success":"info");
    loadView();
  }catch(e){toast(e.message)}
}
async function doVpnExceptionDirection(value,direction){
  try{
    const r=await post("/api/vpn/exceptions/add",{value,direction});
    const warn=(r.warnings||[]).find(w=>w.value===value);
    if(warn)toast(warn.msg,"error");
    else toast(r.changed?"Direction updated":"Direction unchanged",r.changed?"success":"info");
    loadView();
  }catch(e){toast(e.message);loadView()}
}
async function doVpnExceptionRemove(value){
  if(!await confirmModal(`Remove rule ${value}?`,"VPN"))return;
  try{await post("/api/vpn/exceptions/remove",{value});toast("Rule removed","success");loadView()}catch(e){toast(e.message)}
}
function renderVpnExceptions(d,errors={}){
  const policy=d["/api/vpn/exceptions"]||{},measured=!!d["/api/vpn/exceptions"];
  const banners=(policy.warnings||[]).map(w=>`<div class="view-state degraded" style="margin-bottom:10px"><strong>${esc(w.msg)}</strong></div>`).join("");
  const rows=(policy.entries||[]).map((entry,index)=>({
    direction:`<select class="form-input" aria-label="Direction ${esc(entry.value)}" onchange="doVpnExceptionDirection(${escJs(entry.value)},this.value)"><option value="direct" ${entry.direction==="direct"?"selected":""}>direct</option><option value="vpn" ${entry.direction==="vpn"?"selected":""}>via VPN</option><option value="default" ${entry.direction==="default"?"selected":""}>default</option></select>`,
    value:sensitive(fmtDomain(entry.value,entry.display_value),`vpn-exception-value-${index}`),
    networks:sensitive((entry.networks||[]).join(", ")||entry.error||"unresolved",`vpn-exception-networks-${index}`),
    route:esc(entry.route?.interface||"not measured")+((entry.warnings||[]).length?` ${pill("Cloudflare CDN / ECH","warn")}`:""),
    checked_at:esc(fmtTime(entry.checked_at)||"not measured"),
    actions:`${btn("Check","gauge","btn-accent btn-sm",`doVpnExceptionDiagnose(${jsArg(entry.value)},${jsArg(entry.direction)})`)} ${btn("Delete","trash-2","btn-bad btn-sm",`doVpnExceptionRemove(${jsArg(entry.value)})`)}`,
  }));
  return section("Routing Policy",viewError(errors,"/api/vpn/exceptions")+(measured?banners+tblHtml(rows,[{key:"direction",label:"Direction"},{key:"value",label:"Domain / Network"},{key:"networks",label:"Resolved IPs"},{key:"route",label:"Actual Interface"},{key:"checked_at",label:"Checked"},{key:"actions",label:""}]):""),btn("Add","plus","btn-ok","showVpnException()"));
}
async function doVpnExceptionDiagnose(value,direction){
  openModal(`Check: ${esc(value)}`,`<div id="vpn_exception_diagnosis"><p style="color:var(--text2)">DNS + route + HTTPS…</p></div>`,`<button class="btn" onclick="closeModal()">Close</button>`);
  const result=document.getElementById("vpn_exception_diagnosis");
  try{
    const r=await post("/api/vpn/exceptions/diagnose",{value,direction});
    const applicable=(item,label)=>item.applicable===false?`${label}: N/A`:pill(item.ok?`${label}: ok`:`${label}: failed`,item.ok?"ok":"bad");
    const banners=(r.warnings||[]).map(w=>`<div class="view-state degraded" style="margin-top:8px"><strong>${esc(w.msg)}</strong></div>`).join("");
    result.innerHTML=`<div class="view-state ${r.ok?"degraded":"unknown"}"><strong>${r.ok?"Path verified":"Path unverified"}</strong></div>${banners}<div class="metric-grid">${card("DNS",applicable(r.dns,"DNS"))}${card("Route",`${pill(r.route?.matches===false?"mismatch":r.route?.interface?"measured":"not measured",r.route?.matches===false?"bad":r.route?.interface?"ok":"warn")}<div class="card-detail">${esc(r.route?.interface||"—")} · ${esc(r.route?.path||"unknown")}</div>`)}${card("HTTPS",applicable(r.https,"HTTPS"))}${card("Checked",esc(fmtTime(r.checked_at)||"not measured"))}</div>${pre(JSON.stringify({networks:r.networks,dns_error:r.dns?.error,route_error:r.route?.error,https_error:r.https?.error},null,2))}`;
    renderIcons(result);
  }catch(e){result.innerHTML=`<div class="view-state unknown">${esc(e.message)}</div>`}
}
function showVpnLogs(source="syslog"){
  openModal("VPN Logs (Amnezia)",`<pre id="vpnLogOutput" style="height:420px;overflow:auto">Loading...</pre>`,`<button class="btn" onclick="closeVpnLogs()">Close</button>`);
  // Fetch logs via API instead of WebSocket
  api("/api/logs?unit=amnezia&limit=200").then(d=>{
    const out=document.getElementById("vpnLogOutput");
    if(out) out.textContent=(d.lines||[]).join("\n")||"(empty)";
  }).catch(()=>{
    const out=document.getElementById("vpnLogOutput");
    if(out) out.textContent="Failed to load logs";
  });
}
function closeVpnLogs(){
  if(vpnLogSocket){vpnLogSocket.close();vpnLogSocket=null}
  closeModal();
}

/* ═══ DHCP range action ═══ */
function showDhcpRange(){
  const current=S.cache.get("/api/dhcp")||{};
  openModal("DHCP Range",`
    <div class="form-row"><div class="form-group"><label>Start</label>${sensitiveHtml(`<input class="form-input" id="f_rs" value="${esc(current.range_start||"")}" placeholder="10.88.0.170">`,"dhcp-range-start")}</div>
    <div class="form-group"><label>End</label>${sensitiveHtml(`<input class="form-input" id="f_re" value="${esc(current.range_end||"")}" placeholder="10.88.0.250">`,"dhcp-range-end")}</div>
    <div class="form-group"><label>Lease</label><input class="form-input" id="f_rl" value="${esc(current.default_lease||"12h")}" placeholder="12h"></div></div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-accent" onclick="doDhcpRange()">Apply</button>`);
}
async function doDhcpRange(){
  try{await post("/api/dhcp/range",{start:document.getElementById("f_rs").value,end:document.getElementById("f_re").value,lease:document.getElementById("f_rl").value});closeModal();toast("DHCP range updated","success");loadView()}catch(e){toast(e.message)}
}

/* ═══ Backup actions ═══ */
async function doBackupCreate(){
  toast("Creating configuration snapshot...", "info");
  try {
    const res = await post("/api/backups/create", {});
    toast(`Snapshots created: ${res.count || 0}`, "success");
    loadView();
  } catch(e) {
    toast("Snapshot failed: " + e.message, "error");
  }
}

async function doBackupDelete(name){
  if(!await confirmModal(`Delete snapshot ${name}?`, "Delete Snapshot", true)) return;
  try {
    await post("/api/backups/delete", { filename: name });
    toast("Snapshot deleted", "success");
    loadView();
  } catch(e) {
    toast(e.message, "error");
  }
}

async function doBackupDiff(name){
  try {
    const r = await api(`/api/backups/diff?file=${encodeURIComponent(name)}`);
    const rawDiff = r.diff || "(no differences)";
    const diffLines = rawDiff.split("\n").map(line => {
      if (line.startsWith("+") && !line.startsWith("+++")) {
        return `<span style="color:#10b981;background:rgba(16,185,129,0.1);display:block;padding:1px 4px;">${esc(line)}</span>`;
      }
      if (line.startsWith("-") && !line.startsWith("---")) {
        return `<span style="color:#ef4444;background:rgba(239,68,68,0.1);display:block;padding:1px 4px;">${esc(line)}</span>`;
      }
      if (line.startsWith("@")) {
        return `<span style="color:#3b82f6;font-weight:600;display:block;padding:2px 0;">${esc(line)}</span>`;
      }
      return esc(line);
    }).join("");

    openModal(`Diff: ${esc(name)}`, `
      <div style="margin-bottom:12px; font-size:12px; color:var(--text-muted)">
        Config file: <code>${esc(r.current_path || r.base)}</code>
      </div>
      ${sensitiveHtml(`<div style="background:#000; border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px; max-height:400px; overflow:auto; font-family:monospace; font-size:12px; line-height:1.4;">${diffLines}</div>`,`backup-diff-${name}`,true)}
    `, `<button class="btn" onclick="closeModal()">Close</button><button class="btn btn-accent" onclick="doBackupRestore(${escJs(name)})"><i data-lucide="rotate-ccw"></i> Restore from this snapshot</button>`);
  } catch(e) {
    toast(e.message, "error");
  }
}

async function doBackupRestore(name){
  if(!await confirmModal(`Restore configuration from ${name}? Current state will be backed up automatically before replacement.`, "Restore Configuration", true)) return;
  try {
    await post("/api/backups/restore", { filename: name });
    closeModal();
    toast("Configuration restored!", "success");
    loadView();
  } catch(e) {
    toast("Restore failed: " + e.message, "error");
  }
}

/* ═══ Renderers ═══ */
function renderSummary(){
  const o=S.overview;if(!o)return;
  const verEl=document.getElementById("sidebarVersion");
  if(verEl)verEl.innerHTML=`<span class="dot"></span><span>${esc(o.system.os||"FreeBSD")}</span>`;
  const copyrightEl=document.querySelector(".sidebar-copyright");
  if(copyrightEl){
    const version=o.system?.package_version || "2.6.0";
    copyrightEl.innerHTML=`GateBSD v${esc(version)}<br>&copy; 2026 GateBSD Project`;
  }
  const mem=o.memory?.mem||{},total=mem.total||0,used=total-(mem.available||0);
  if(total)S.sparks.ram.push(Math.round(used/total*100));
  if(S.sparks.ram.length>60)S.sparks.ram.shift();
  const cpuPct=o.system?.cpu_pct!=null?o.system.cpu_pct:0;
  S.sparks.cpu.push(cpuPct);
  if(S.sparks.cpu.length>60)S.sparks.cpu.shift();
  const charge=parseInt(o.ups?.charge)||0;
  
  const svc=o.services||{};
  const activeIface = o.wan?.active_iface || "";
  const sys = o.wan?.sys || {};
  const wanUp=o.wan?.wan?.state==="UP";
  const backupUp=o.wan?.backup?.state==="UP";
  const wanIface=o.wan?.wan?.name||sys.wan_if||"";
  const backupIface=o.wan?.backup?.name||sys.backup_if||"";
  const wanAddr=o.wan?.wan?.addresses?.[0]||"—";
  const backupAddr=o.wan?.backup?.addresses?.[0]||"—";
  const wanHealth=o.wan?.health?.wan;
  const backupHealth=o.wan?.health?.backup;
  const wanLatency=wanHealth?.latency_ms!=null?`${wanHealth.latency_ms.toFixed(0)} ms`:"—";
  const backupLatency=backupHealth?.latency_ms!=null?`${backupHealth.latency_ms.toFixed(0)} ms`:"—";

  const vpnState = vpnPath(o);
  const vpnUp = vpnState.in_tunnel === true;
  const vpnIface=o.wan?.vpn_if||"awg0";
  const vpnHandshake=o.amnezia?.handshake||"—";

  const uptime=o.system?.uptime_seconds||0;
  const uptimeStr=uptime?`${Math.floor(uptime/86400)}d ${String(Math.floor((uptime%86400)/3600)).padStart(2,'0')}:${String(Math.floor((uptime%3600)/60)).padStart(2,'0')}:${String(Math.floor(uptime%60)).padStart(2,'0')}`:"—";
  const osVer=o.system?.os||"FreeBSD";
  const osVerShort=osVer.replace("FreeBSD ", "");
  const cpuModel=o.system?.cpu_model||"";

  const daemonSvg=`<svg viewBox="0 0 448 512" fill="currentColor" style="width:26px;height:26px"><path d="M303.7 96.2c11.1-11.1 115.5-77 139.2-53.2 23.7 23.7-42.1 128.1-53.2 139.2-11.1 11.1-39.4.9-63.1-22.9-23.8-23.7-34.1-52-22.9-63.1zM109.9 68.1C73.6 47.5 22 24.6 5.6 41.1c-16.6 16.6 7.1 69.4 27.9 105.7 18.5-32.2 44.8-59.3 76.4-78.7zM406.7 174c3.3 11.3 2.7 20.7-2.7 26.1-20.3 20.3-87.5-27-109.3-70.1-18-32.3-11.1-53.4 14.9-48.7 5.7-3.6 12.3-7.6 19.6-11.6-29.8-15.5-63.6-24.3-99.5-24.3-119.1 0-215.6 96.5-215.6 215.6 0 119 96.5 215.6 215.6 215.6S445.3 380.1 445.3 261c0-38.4-10.1-74.5-27.7-105.8-3.9 7-7.6 13.3-10.9 18.8z"/></svg>`;

  const ramPct=total?Math.round(used/total*100):0;
  const ramClass=ramPct>90?"progress-error":(ramPct>70?"progress-warn":"progress-ok");

  document.getElementById("summary").innerHTML=[
    card("SYSTEM", `${esc(osVerShort)}`, daemonSvg, `<div class="card-detail" style="margin-top:6px">Uptime: ${esc(uptimeStr)}</div>`, "color:var(--text-muted);opacity:0.25;background:transparent;border:none;padding:0"),
    card("CPU", `${cpuPct}%`, "cpu", `<div style="margin:6px 0 4px 0;height:18px;display:flex;align-items:center;">${S.sparks.cpu.length>2?sparkline(S.sparks.cpu,"#E53935",140,16):""}</div><div class="card-detail">${esc(cpuModel)}</div>`, "color:var(--text-muted);opacity:0.25;background:transparent;border:none;padding:0"),
    card("RAM", `${ramPct}%`, "database", `<div class="progress-bar" style="margin:8px 0 4px 0;"><div class="progress-fill ${ramClass}" style="width:${ramPct}%"></div></div><div class="card-detail">${fmtB(used)} / ${fmtB(total)}</div>`, "color:var(--text-muted);opacity:0.25;background:transparent;border:none;padding:0"),
    card("WAN (Primary)", `<span style="display:flex;align-items:center;gap:4px;color:var(--text);font-weight:700"><i data-lucide="${wanUp?"arrow-up":"arrow-down"}" style="width:16px;height:16px;color:${wanUp?"var(--ok)":"var(--error)"}"></i>${esc(wanIface)} (PPPoE)</span>`, "arrow-up-right", `<div class="card-detail" style="line-height:1.4">${sensitive(wanAddr,"summary-wan-primary")}<br>${wanUp?"Online "+uptimeStr:"Down"}</div>`, "color:#10b981;background:rgba(16,185,129,0.15);border-radius:4px;padding:3px;width:14px;height:14px"),
    card("WAN (Backup)", `<span style="display:flex;align-items:center;gap:4px;color:var(--text);font-weight:700"><i data-lucide="${backupUp?"arrow-up":"arrow-down"}" style="width:16px;height:16px;color:${backupUp?"var(--ok)":"var(--text-muted)"}"></i>${esc(backupIface)} (LTE)</span>`, "arrow-up-right", `<div class="card-detail" style="line-height:1.4">${sensitive(backupAddr,"summary-wan-backup")}<br>${backupUp?"Online":"Down"}</div>`, backupUp?"color:#10b981;background:rgba(16,185,129,0.15);border-radius:4px;padding:3px;width:14px;height:14px":"color:var(--text-muted);background:rgba(255,255,255,0.05);border-radius:4px;padding:3px;width:14px;height:14px"),
    card("VPN (AmneziaWG)", `<span style="display:flex;align-items:center;gap:6px;color:var(--text);font-weight:700"><i data-lucide="shield-check" style="width:16px;height:16px;color:${vpnUp?"var(--ok)":"var(--text-muted)"}"></i>${esc(vpnIface)}</span>`, "shield", `<div class="card-detail" style="line-height:1.4">${vpnUp?"Traffic via tunnel":"Bypassing tunnel"}<br>${esc(vpnState.label)}</div>`, vpnUp?"color:#10b981;background:rgba(16,185,129,0.15);border-radius:4px;padding:3px;width:14px;height:14px":"color:var(--text-muted);background:rgba(255,255,255,0.05);border-radius:4px;padding:3px;width:14px;height:14px"),
  ].join("");

  const statusServices = [
    { name: "unbound", label: "UNBOUND" },
    { name: "dhcpd", label: "DHCPD" },
    { name: "pf", label: "PF" },
    { name: "mpd5", label: "MPD (PPPoE)" },
    { name: "amnezia", label: "AMNEZIA WG" },
    { name: "nut", label: "NUT" }
  ];
  document.getElementById("statusStrip").innerHTML=statusServices
    .map(s=>{
      const active = svc[s.name]==="active";
      return `<span class="svc-badge ${active?"running":"stopped"}">${s.label}</span>`;
    }).join("");

  S.lastTs=Date.now();updateLive();
  renderIcons(document.getElementById("summary"));
}

function updateLive(){
  const el=document.getElementById("liveText");
  if(!S.lastTs){el.textContent="connecting…";return}
  const ago=Math.round((Date.now()-S.lastTs)/1000);
  el.textContent=ago<5?"live":`${ago}s ago`;
}
setInterval(updateLive,1000);


function renderNetwork(d,errors={}){
  const ifaces=d["/api/interfaces"]||{},wan=d["/api/wan"]||{},pp=d["/api/pppoe"]||{},modem=d["/api/modem"]||{};
  const wanMeasured=!!d["/api/wan"],ifacesMeasured=!!d["/api/interfaces"];
  const sys=wan.sys||{};
  const hRows=Object.entries(wan.health||{}).map(([k,v])=>{
    const isWan=k==="wan";
    const ifaceName=isWan?(wan.wan?.name||sys.wan_if||"—"):(wan.backup?.name||sys.backup_if||"—");
    const role=isWan?"primary":"backup";
    const addr=(isWan?wan.wan:wan.backup)?.addresses?.[0]||"—";
    const ok=v.ok;
    return{
      name:`<div><strong>${esc(ifaceName)}</strong> <span style="color:var(--text-muted);font-size:11px">(${esc(role)})</span></div><div style="font-size:11px;color:var(--text-muted)">${sensitive(addr,`wan-health-${k}-address`)}</div>`,
      ok:`<span class="pill ${ok?"ok":"bad"}">${ok?"reachable":"unreachable"}</span>`,
      latency_ms:v.latency_ms!=null?`<strong>${v.latency_ms.toFixed(1)}</strong> ms`:`<span style="color:var(--text-muted)">no reply</span>`,
    };
  });
  if(wan.health?.wan?.latency_ms!=null){S.sparks.ppp.push(wan.health.wan.latency_ms);if(S.sparks.ppp.length>60)S.sparks.ppp.shift()}
  if(wan.health?.backup?.latency_ms!=null){S.sparks.usb.push(wan.health.backup.latency_ms);if(S.sparks.usb.length>60)S.sparks.usb.shift()}
  const pL=S.sparks.ppp.length?S.sparks.ppp[S.sparks.ppp.length-1].toFixed(0)+" ms":"—";
  const zL=S.sparks.usb.length?S.sparks.usb[S.sparks.usb.length-1].toFixed(0)+" ms":"—";
  return[
    section("Internet Uplinks",viewError(errors,"/api/wan")+(wanMeasured?`<div class="metric-grid">${card("Default route",esc(wan.active_iface||"—"))}${card(`DSL (${wan.wan?.name||sys.wan_if||"—"}) · ${pL}`,pill(wan.wan?.state==="UP"?"active":"inactive"))}${card(`LTE (${wan.backup?.name||sys.backup_if||"—"}) · ${zL}`,pill(wan.backup?.state==="UP"?"active":"inactive"))}</div>${S.sparks.ppp.length>2?`<div style="display:flex;gap:16px;margin-top:12px"><div><div class="card-label">DSL Latency</div>${sparkline(S.sparks.ppp,"#10b981")}</div><div><div class="card-label">LTE Latency</div>${sparkline(S.sparks.usb,"#f59e0b")}</div></div>`:""}`:""),
      `${disabledBtn("WAN Setup","lock","WAN interface configuration is managed via gatebsd-install in console")} ${btn("Reconnect DSL","rotate-cw","btn-accent","doPppoeReconnect()")} ${btn("Test DSL","gauge","btn-accent",`doWanTest(${jsArg(sys.wan_if||"")})`)} ${btn("Test LTE","gauge","btn-accent",`doWanTest(${jsArg(sys.backup_if||"")})`)}`),
    section("Uplink Checks",viewError(errors,"/api/wan")+(wanMeasured?tblHtml(hRows,[{key:"name",label:"Link"},{key:"ok",label:"Status"},{key:"latency_ms",label:"Latency"}]):"")),
    details("Technical Details (Routes, Addresses)",section("Default Route",viewError(errors,"/api/wan")+(wanMeasured?sensitiveBlock(`interface: ${wan.active_iface||"—"}\nwan: ${wan.wan?.name||"—"} (${(wan.wan?.addresses||[]).join(", ")||"—"})\nbackup: ${wan.backup?.name||"—"} (${(wan.backup?.addresses||[]).join(", ")||"—"})\nvpn: ${wan.vpn?.name||"—"} (${(wan.vpn?.addresses||[]).join(", ")||"—"})`,"wan-default-route"):""))+section("Interface Addresses",viewError(errors,"/api/interfaces")+(ifacesMeasured?sensitiveBlock((ifaces.interfaces||[]).map(i=>`${i.name}: ${(i.addresses||[]).join(", ")||"none"}`).join("\n"),"wan-interface-addresses"):""))+section("Key Routes",viewError(errors,"/api/interfaces")+(ifacesMeasured?sensitiveBlock((ifaces.routes_v4||[]).filter(r=>r.includes("default")||r.includes("awg0")||r.includes("ng0")||r.includes("ue0")||r.includes("Destination")).join("\n"),"wan-key-routes"):""))),
    details("PPPoE Configuration",viewError(errors,"/api/pppoe")+(d["/api/pppoe"]?sensitiveBlock(pp.config||[],"wan-pppoe-config"):"")),
    errors["/api/modem"]?section("Modem",viewError(errors,"/api/modem")):modem.modems&&modem.modems!="No modems found"?section("Modem",sensitiveBlock(modem.modems,"wan-modem-details")):"",
  ].filter(Boolean).join("");
}

function trafficCard(title, data, iface, direction, color) {
  const samples = data[iface] || [];
  if (samples.length < 2) return `<div><div class="card-label">${esc(title)}</div><span style="color:var(--muted)">Collecting data...</span></div>`;
  const speeds = [];
  for (let i = 1; i < samples.length; i++) {
    const dt = samples[i].ts - samples[i-1].ts;
    if (dt > 0 && dt < 5) {
      const db = samples[i][direction] - samples[i-1][direction];
      const mbps = (db >= 0 ? db : 0) * 8 / dt / 1000000;
      speeds.push(mbps);
    } else {
      speeds.push(0);
    }
  }
  const current = speeds.length > 0 ? speeds[speeds.length - 1] : 0;
  return `<div><div class="card-label">${esc(title)}</div><div style="font-size:24px;font-weight:600;margin:4px 0">${current.toFixed(1)} <span style="font-size:12px;color:var(--text2)">Mbps</span></div>${sparkline(speeds, color, 160, 36)}</div>`;
}

function setUiMode(mode) {
  localStorage.setItem("amnezia_ui_mode", mode);
  document.body.classList.toggle("simple-mode", mode === "simple");
  const simpleBtn = document.getElementById("modeToggleSimple");
  const advBtn = document.getElementById("modeToggleAdvanced");
  if (simpleBtn) simpleBtn.classList.toggle("active", mode === "simple");
  if (advBtn) advBtn.classList.toggle("active", mode === "advanced");
}

function renderTopologyMap(wan, vpn, clients, vpnState, measured={wan:true,overview:true,clients:true}) {
  const wanIface = wan.wan?.name || wan.sys?.wan_if || "";
  const wanActive = wan.wan?.state === "UP";
  const wanMtu = wan.wan?.mtu || "";
  const vpnActive = vpnState?.in_tunnel === true;
  const vpnIface = vpn.interface?.name || wan.sys?.vpn_if || "";
  const vpnMtu = vpn.interface?.mtu || "";
  const clientCount = measured.clients?(clients.count ?? (clients.clients||[]).length ?? 0):"—";
  const lanNet = wan.sys?.lan_net || "";
  const lanIface = wan.sys?.lan_if || "";
  const lanActive = !!lanIface;
  const wanState=measured.wan?(wanActive?"active":"down"):"unknown";
  const vpnClass=measured.overview?(vpnActive?"vpn":"down"):"unknown";
  const lanState=measured.wan?(lanActive?"active":"down"):"unknown";

  return `
    <div class="topology-card">
      <div class="topology-head">
        <h2><i data-lucide="network"></i> Network Topology</h2>
        <div class="topology-legend">
          <span><span class="dot active"></span> Link active</span>
          <span><span class="dot vpn"></span> VPN tunnel</span>
          <span><span class="dot down"></span> Link down</span>
        </div>
      </div>
      <div class="topology-flow">
        <div class="topology-node ${wanState}" onclick="switchView('wan')" style="cursor:pointer" title="Internet / ISP">
          <div class="node-icon"><i data-lucide="globe"></i></div>
          <div class="node-label">Internet</div>
          <div class="node-sub">ISP</div>
        </div>

        <div class="topology-connector ${wanState}"></div>

        <div class="topology-node ${wanState}" onclick="switchView('wan')" style="cursor:pointer" title="WAN Interface">
          <div class="node-icon"><i data-lucide="cable"></i></div>
          <div class="node-label">${esc(wanIface)} (PPPoE)</div>
          <div class="node-sub">Primary link<br>MTU ${esc(wanMtu||"—")}</div>
        </div>

        <div class="topology-connector ${wanState}"></div>

        <div class="topology-node active" onclick="switchView('overview')" style="cursor:pointer" title="GateBSD Gateway">
          <div class="node-icon" style="border-color:var(--accent);background:var(--accent-bg)"><svg viewBox="0 0 448 512" fill="var(--accent)" style="width:24px;height:24px"><path d="M303.7 96.2c11.1-11.1 115.5-77 139.2-53.2 23.7 23.7-42.1 128.1-53.2 139.2-11.1 11.1-39.4.9-63.1-22.9-23.8-23.7-34.1-52-22.9-63.1zM109.9 68.1C73.6 47.5 22 24.6 5.6 41.1c-16.6 16.6 7.1 69.4 27.9 105.7 18.5-32.2 44.8-59.3 76.4-78.7zM406.7 174c3.3 11.3 2.7 20.7-2.7 26.1-20.3 20.3-87.5-27-109.3-70.1-18-32.3-11.1-53.4 14.9-48.7 5.7-3.6 12.3-7.6 19.6-11.6-29.8-15.5-63.6-24.3-99.5-24.3-119.1 0-215.6 96.5-215.6 215.6 0 119 96.5 215.6 215.6 215.6S445.3 380.1 445.3 261c0-38.4-10.1-74.5-27.7-105.8-3.9 7-7.6 13.3-10.9 18.8z"/></svg></div>
          <div class="node-label">GateBSD</div>
          <div class="node-sub">Gateway</div>
        </div>

        <div class="topology-connector ${vpnClass}"></div>

        <div class="topology-node ${vpnClass}" onclick="switchView('amnezia')" style="cursor:pointer" title="VPN tunnel">
          <div class="node-icon"><i data-lucide="lock"></i></div>
          <div class="node-label">${esc(vpnIface)} (AmneziaWG)</div>
          <div class="node-sub">VPN tunnel<br>MTU ${esc(vpnMtu)}</div>
        </div>

        <div class="topology-connector ${vpnClass}"></div>

        <div class="topology-node ${lanState}" onclick="switchView('lan')" style="cursor:pointer" title="Local Network">
          <div class="node-icon"><i data-lucide="home"></i></div>
          <div class="node-label">${esc(lanIface)} (LAN)</div>
          <div class="node-sub">${sensitive(lanNet,"overview-lan-network")}<br>${esc(clientCount)} clients</div>
        </div>
      </div>
    </div>
  `;
}

function renderOverview(d,errors={}){
  const o=d["/api/overview"]||{},wan=d["/api/wan"]||{},clients=d["/api/clients"]||{},trafficData=d["/api/stats/traffic"]||{},vpn=d["/api/amnezia"]||{},health=d["/api/health"]||{},logData=d["/api/logs?limit=20"]||{};
  const overviewMeasured=!!d["/api/overview"],wanMeasured=!!d["/api/wan"];
  const sys=wan.sys||{};
  const svc=o.services||{},ups=o.ups||{},mem=o.memory?.mem||{};
  const total=mem.total||0,used=total-(mem.available||0);
  const uptime=o.system?.uptime_seconds||0;
  const uptimeStr=uptime?`${Math.floor(uptime/86400)}d ${Math.floor((uptime%86400)/3600)}h ${Math.floor((uptime%3600)/60)}m`:"—";
  const cpuPct=Number(o.system?.cpu_pct??0);
  const wanIface=wan.wan?.name||sys.wan_if||"";
  const vpnPathState=vpnPath(o);
  const vpnUp=vpnPathState.in_tunnel===true;
  const vpnIface=vpn.interface?.name||sys.vpn_if||"";
  const wanUp=wan.wan?.state==="UP";
  const backupUp=wan.backup?.state==="UP";
  const lanIface=sys.lan_if||"";
  const lanAddress=sys.lan_net||"";

  ["Interfaces","Traffic (Mbps)","Service Status","System Logs","Warnings","System Info"].forEach(title=>{
    if(S.sections[title]===undefined)S.sections[title]=true;
  });

  // Row 2: Network topology map
  const topologyHtml=renderTopologyMap(wan, vpn, clients, vpnPathState,{wan:wanMeasured,overview:overviewMeasured,clients:!!d["/api/clients"]});

  // Row 3: Three columns
  // Interfaces table
  const ifaces=[
    {name:`${wan.wan?.name||wanIface} (PPPoE)`,state:!wanMeasured?"Unknown":wanUp?"Up":"Down",ip:wan.wan?.addresses?.[0]||"",mtu:wan.wan?.mtu||"—",uptime:uptimeStr},
    {name:`${wan.backup?.name||sys.backup_if||""} (LTE)`,state:!wanMeasured?"Unknown":backupUp?"Up":"Down",ip:wan.backup?.addresses?.[0]||"",mtu:wan.backup?.mtu||"—",uptime:"—"},
    {name:`${lanIface} (LAN)`,state:!wanMeasured?"Unknown":lanIface?"Up":"Down",ip:lanAddress,mtu:"—",uptime:uptimeStr},
    {name:`${vpnIface} (VPN)`,state:!overviewMeasured?"Unknown":vpnUp?"Up":"Down",ip:vpn.interface?.addresses?.[0]||"",mtu:vpn.interface?.mtu||"—",uptime:vpnPathState.label||"—"},
  ];
  const ifTableHtml=`${viewError(errors,"/api/wan")}${viewError(errors,"/api/overview")}<div class="table-wrap"><table>
    <thead><tr><th>INTERFACE</th><th>STATE</th><th>IP / MASK</th><th>MTU</th><th>UPTIME</th></tr></thead>
    <tbody>${ifaces.map((i,index)=>`<tr><td><strong>${esc(i.name)}</strong></td><td><span class="pill ${i.state==="Up"?"ok":i.state==="Unknown"?"warn":"bad"}">${esc(i.state)}</span></td><td>${i.ip?`<code>${sensitive(i.ip,`overview-interface-ip-${index}`)}</code>`:"—"}</td><td>${esc(i.mtu)}</td><td>${esc(i.uptime)}</td></tr>`).join("")}</tbody>
  </table></div>
  <div style="margin-top:8px"><button class="btn btn-accent" onclick="switchView('wan')">All interfaces →</button></div>`;

  // Traffic graph
  const trafficHtml=viewError(errors,"/api/stats/traffic")+(d["/api/stats/traffic"]?`<div>
    <div style="display:flex;gap:16px;margin-bottom:8px;font-size:12px;color:var(--text-muted)">
      <span>— WAN (${esc(wanIface)})</span><span style="color:var(--ok)">— VPN (${esc(vpnIface)})</span>
    </div>
    <div class="traffic-canvas-wrap"><canvas id="trafficCanvas"></canvas></div>
    <div style="display:flex;gap:24px;margin-top:8px;font-size:12px">
      <span><i data-lucide="arrow-up" style="width:12px;height:12px;color:var(--accent)"></i> Tx <strong>${esc(((trafficData.interfaces?.[wanIface]?.tx_rate||0)*8/1000000).toFixed(1))} Mbps</strong> ${esc(wanIface)}</span>
      <span><i data-lucide="arrow-down" style="width:12px;height:12px;color:var(--ok)"></i> Rx <strong>${esc(((trafficData.interfaces?.[wanIface]?.rx_rate||0)*8/1000000).toFixed(1))} Mbps</strong> ${esc(wanIface)}</span>
    </div>
  </div>`:"");

  // Service status
  const svcList=["unbound","dhcpd","pf","mpd5","amnezia","nut"];
  const svcHtml=viewError(errors,"/api/overview")+(overviewMeasured?svcList.map(name=>{
    const active=svc[name]==="active";
    return `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:8px"><i data-lucide="${active?"check-circle":"alert-circle"}" style="width:14px;height:14px;color:${active?"var(--ok)":"var(--error)"}"></i><span style="font-size:13px">${esc(svcName(name))}</span></div>
      <span style="font-size:12px;color:${active?"var(--ok)":"var(--error)"}">${active?"Running":"Stopped"}</span>
    </div>`;
  }).join(""):"");

  // Row 4: Three columns
  // System logs
  const logs=logData.lines||[];
  const logsHtml=viewError(errors,"/api/logs?limit=20")+(d["/api/logs?limit=20"]?(logs.slice(-5).reverse().map((l,index)=>{
    const isPf=String(l).includes("pf")||String(l).includes("PF");
    const isErr=String(l).includes("error")||String(l).includes("blocked");
    return `<div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px">
      <span style="color:var(--text-muted);white-space:nowrap">${esc(String(l).split(" ").slice(0,2).join(" "))}</span>
      <i data-lucide="${isErr?"alert-triangle":"info"}" style="width:12px;height:12px;color:${isErr?"var(--warn)":"var(--info)"}"></i>
      <span style="color:var(--text-secondary)">${sensitive(String(l).split(" ").slice(2).join(" ").substring(0,80),`overview-log-${index}`)}</span>
    </div>`;
  }).join("")||'<div style="color:var(--text-muted);font-size:12px;padding:8px 0">No entries</div>'):"");

  // Warnings
  const warnings=[];
  if(overviewMeasured&&svc.pf!=="active") warnings.push({time:"—",icon:"alert-circle",msg:"PF Firewall is inactive",level:"error"});
  if(Object.keys(errors).length)warnings.push({time:"—",icon:"help-circle",msg:"Part of state not measured",level:"warn"});
  // "VPN is not active" used to be pushed from `!vpnUp`, and `vpnUp` was an
  // OR over two unrelated facts, so the one state worth warning about --
  // tunnel up, traffic going around it -- was the one that never warned.
  // The backend names the state and writes the sentence; five of them exist.
  (vpnPathState.warnings||[]).forEach(w=>warnings.push(w));
  // The backend owns the diagnosis; the frontend displays it without deriving
  // a second verdict from the same facts.
  (o.operator?.warnings||[]).forEach(w=>warnings.push(w));
  // Same contract for the blocklist: a rebuild that refused to publish leaves
  // the previous file in place, so the list's own header still reads healthy.
  // Only the run record knows, and only the backend reads it.
  (o.adblock?.warnings||[]).forEach(w=>warnings.push(w));
  S.warnings = warnings;
  const badge = document.getElementById("notifBadge");
  if(badge) {
    if(warnings.length > 0) badge.classList.add("active");
    else badge.classList.remove("active");
  }
  const warningsHtml=warnings.length?warnings.map(w=>`
    <div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px">
      <span style="color:var(--text-muted)">${esc(w.time)}</span>
      <i data-lucide="${w.icon}" style="width:12px;height:12px;color:var(--${w.level})"></i>
      <span style="color:var(--text-secondary)">${esc(w.msg)}</span>
    </div>`).join(""):'<div style="color:var(--ok);font-size:12px;padding:8px 0"><i data-lucide="check-circle" style="width:12px;height:12px;display:inline"></i> No warnings</div>';

  // System info
  const sysInfoHtml=viewError(errors,"/api/overview")+(overviewMeasured?`<div style="font-size:12px">
    <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text-muted)">Hostname</span><span>${sensitive(o.system?.hostname||"","overview-hostname")}</span></div>
    <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text-muted)">OS Version</span><span>${esc(o.system?.os||"")}</span></div>
    <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text-muted)">Hardware</span><span>${esc(o.system?.cpu_model||"")}</span></div>
    <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text-muted)">Kernel</span><span>${esc(o.system?.kernel||"")}</span></div>
    <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text-muted)">Architecture</span><span>${esc(o.system?.architecture||"")}</span></div>
    <div style="display:flex;justify-content:space-between;padding:6px 0"><span style="color:var(--text-muted)">Filesystem</span><span>${esc(o.system?.root_filesystem||"—")}</span></div>
  </div>`:"");

  // Internet repair status banner
  // `expected` is not `in_tunnel`: a VPN the operator switched off is the path
  // this box is configured to want, so the banner stays green -- while the
  // warning above still says out loud that the traffic goes direct. An
  // unmeasured state is neither, and `=== true` keeps it out of the green.
  const internetMeasured=!errors["/api/wan"]&&!errors["/api/overview"];
  const internetOk = internetMeasured && wanUp && vpnPathState.expected === true;
  const internetLabel=internetMeasured?(internetOk?"Internet works":"Connectivity issues"):"State not measured";
  const internetColor=internetMeasured?(internetOk?"var(--ok)":"var(--bad)"):"var(--warn)";
  const repairSection = `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-md);padding:20px;display:flex;align-items:center;justify-content:space-between;gap:16px;">
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:${internetOk ? 'rgba(16,185,129,0.15)' : internetMeasured ? 'rgba(239,68,68,0.15)' : 'var(--warn-bg)'}">
          <i data-lucide="${internetMeasured ? internetOk ? 'wifi' : 'wifi-off' : 'help-circle'}" style="width:22px;height:22px;color:${internetColor}"></i>
        </div>
        <div>
          <div style="font-size:15px;font-weight:600;color:var(--text)">${internetLabel}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px">${internetMeasured
            ? internetOk
              ? `PPPoE: ${esc(wanIface)} · VPN: ${esc(vpnIface)} — ${esc(vpnPathState.label)}`
              : `${esc(vpnPathState.label)} · Click button to run automatic recovery`
            : "Unable to read current WAN or VPN measurements. Retry check."}</div>
        </div>
      </div>
      ${btn(internetOk || !internetMeasured ? "Check Connectivity" : "Restore Internet",
            internetOk || !internetMeasured ? "refresh-cw" : "wrench",
            internetOk || !internetMeasured ? "btn-accent" : "btn-ok",
            "doInternetRepair()")}
    </div>`;

  return[
    // Row 1: Internet status
    repairSection,
    // Row 2: Topology
    topologyHtml,
    // Row 3: Three columns
    `<div class="metric-grid">
      <div>${section("Interfaces", ifTableHtml)}</div>
      <div>${section("Traffic (Mbps)", trafficHtml)}</div>
      <div>${section("Service Status", svcHtml)}</div>
    </div>`,
    // Row 4: Three columns
    `<div class="metric-grid">
      <div>${section("System Logs", logsHtml)}</div>
      <div>${section("Warnings", warningsHtml)}</div>
      <div>${section("System Info", sysInfoHtml)}</div>
    </div>`,
  ].join("");
}

function renderFailover(d,errors={}){
  const wan=d["/api/wan"]||{}, history=d["/api/history"]||{};
  const fo=d["/api/failover"]||{},foMeasured=!!d["/api/failover"],disc=(d["/api/discovery"]||{}).data||{};
  const st=fo.state||{}, cfg=fo.config||{};
  const mode=foMeasured?(st.mode||cfg.FAILOVER_MODE||"observe"):"not measured";
  const requestStatus=st.request_status||"",requestPending=requestStatus==="pending";
  const transport=st.vpn_rolled_back===true?`${st.active_wan==="backup"?"LTE":"WAN"} direct (VPN rollback)`:(st.vpn_ok===true?`${st.active_wan==="backup"?"LTE":"WAN"} + VPN`:"VPN recovering");
  const requestCard=requestStatus?card("Switch",pill(requestStatus,requestStatus==="succeeded"?"ok":requestStatus==="failed"?"bad":"warn")):"";
  const requestDetails=requestStatus?`<p style="color:var(--text2);margin-top:12px">request_id: ${esc(st.request_id||"—")}${st.request_error?` · ${esc(st.request_error)}`:""}</p>`:"";
  const manualButtons=(mode==="manual"&&!requestPending)?` ${btn("Switch to Primary WAN","arrow-up-circle","btn-ok","switchFailoverWan('primary')")} ${btn("Switch to Backup WAN","arrow-down-circle","btn-accent","switchFailoverWan('backup')")}`:"";
  const modeButtons=(requestPending?disabledBtn("Switch in progress","loader",st.request_id||""):`${btn("Monitor only","eye","btn-accent","setFailoverMode('observe')")} ${btn("Automatic","repeat","btn-ok","setFailoverMode('automatic')")} ${btn("Manual","hand","btn-accent","setFailoverMode('manual')")}`)+manualButtons;
  const warningsBanner=(Array.isArray(fo.warnings)?fo.warnings:[]).map(w=>`<div class="view-state degraded" style="margin-bottom:10px"><strong>${esc(w)}</strong></div>`).join("");
  const healthRows=[
    {iface:cfg.PRIMARY_IF||"ng0", ok:st.primary_ok===true?pill("ok"):(st.primary_ru_ok===true?`${pill("fail")} ${pill("domestic allowlist","warn")}`:pill("fail")), failures:st.primary_failures??"", role:"Primary"},
    // A device delivered with one uplink has no backup interface at all. That is
    // a supported configuration, not a fault: showing it red with a five-figure
    // failure count trains the operator to ignore this row.
    {iface:cfg.BACKUP_IF||"ue0", ok:st.backup_fitted===false?pill("not fitted","warn"):(st.backup_ok===true?pill("ok"):(st.backup_ru_ok===true?`${pill("fail")} ${pill("domestic allowlist","warn")}`:pill("fail"))), failures:st.backup_fitted===false?"—":(st.backup_failures??""), role:"Backup"},
  ];
  const detected=disc.detected||{};
  const detectedRows=Object.entries(detected).map(([name,value])=>({name,value:value?pill("detected"):pill("absent")}));
  const wanEvents=(history.events||[]).filter(e=>String(e.kind||"").startsWith("wan.")).slice(0,20).map(e=>({...e,time:fmtRel(e.ts)}));
  return[
    section("GateBSD failover",viewError(errors,"/api/failover")+(foMeasured?`${warningsBanner}<div class="metric-grid">${card("Mode",pill(mode))}${card("State",pill(st.state||"UNKNOWN"))}${card("Active WAN",esc(st.active_wan||"?"))}${card("Traffic Path",esc(transport))}${requestCard}${card("Reason",esc(st.reason||""))}</div>${requestDetails}<p style="color:var(--text2);margin-top:12px">Monitor-only does not switch WAN automatically while VPN and service checks continue. Enable automatic mode only after verifying FIBs and gateways.</p>`:""),modeButtons),
    section("Uplink Checks",viewError(errors,"/api/failover")+(foMeasured?tblHtml(healthRows,[{key:"role",label:"Role"},{key:"iface",label:"Interface"},{key:"ok",label:"Status"},{key:"failures",label:"Consecutive Fails"}]):"")),
    section("Detected Configuration",viewError(errors,"/api/discovery")+(d["/api/discovery"]?tblHtml(detectedRows,[{key:"name",label:"Component"},{key:"value",label:"Status"}]):""),btn("Rescan","scan","btn-accent","rescanGateway()")),
    section("WAN events",viewError(errors,"/api/history")+(d["/api/history"]?tbl(wanEvents,[{key:"time",label:"Time"},{key:"severity",label:"Severity"},{key:"kind",label:"Type"},{key:"message",label:"Event"}]):"")),
  ].join("");
}

async function setFailoverMode(mode){
  if(mode==="automatic" && !await confirmModal("Enable automatic WAN failover? Confirm PRIMARY_FIB and BACKUP_FIB are verified under observe mode first.","Failover")) return;
  try{await post("/api/failover/mode",{mode});toast(`Failover: ${mode}`,"success");loadView(false)}catch(e){toast(e.message,"error")}
}
async function switchFailoverWan(target){
  try{await post("/api/failover/switch",{target});toast(`WAN switched: ${target}`,"success");loadView(false)}catch(e){toast(e.message,"error")}
}
async function rescanGateway(){
  try{await post("/api/discovery/scan",{});toast("Gateway config rescanned","success");loadView(false)}catch(e){toast(e.message,"error")}
}

function getDeviceIcon(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (h.includes("mac") || h.includes("laptop") || h.includes("notebook")) return "laptop";
  if (h.includes("phone") || h.includes("oneplus") || h.includes("iphone") || h.includes("android")) return "smartphone";
  if (h.includes("tv") || h.includes("fridge") || h.includes("smart") || h.includes("v-max")) return "tv";
  if (h.includes("win") || h.includes("desktop") || h.includes("pc")) return "monitor";
  if (h.includes("n100") || h.includes("server") || h.includes("host")) return "cpu";
  return "hard-drive";
}

function renderLan(d,errors={}){
  const clients=d["/api/clients"]||{},dhcp=d["/api/dhcp"]||{},dhcpMeasured=!!d["/api/dhcp"],ifaces=d["/api/interfaces"]||{};
  const clientRows=(clients.clients||[]).map((c,index)=>{
    const icon = getDeviceIcon(c.hostname);
    const hostHtml = `<div style="display:flex;align-items:center;gap:8px;"><i data-lucide="${icon}" style="width:16px;height:16px;color:var(--accent)"></i>${sensitive(c.hostname||"*",`lan-client-hostname-${index}`)}</div>`;
    const vendor = c.vendor || "";
    const latency = c.latency_ms != null ? `${c.latency_ms} ms` : "";
    const actions = `
      ${!c.static && c.mac ? btn("Pin IP", "pin", "btn-ok btn-sm", `showAddLease(${jsArg(c.mac||"")},${jsArg(c.ip||"")},${jsArg(c.hostname||"")})`) : ""}
    `;
    return {
      ip: `<code>${sensitive(c.ip,`lan-client-ip-${index}`)}</code>`,
      hostname: hostHtml,
      vendor: vendor ? `<span style="font-size:11px;color:var(--text-muted)">${esc(vendor)}</span>` : "",
      mac: `<code>${sensitive(c.mac,`lan-client-mac-${index}`)}</code>`,
      latency: latency ? `<span style="font-size:11px">${esc(latency)}</span>` : "",
      state: pill(c.state || "active"),
      static_flag: c.static ? pill("ok","ok") : "",
      source: (c.source||[]).join(", "),
      actions
    };
  });
  const leaseRows=(dhcp.leases||[]).map((l,index)=>{
    const icon = getDeviceIcon(l.hostname);
    const hostHtml = `<div style="display:flex;align-items:center;gap:8px;"><i data-lucide="${icon}" style="width:16px;height:16px;color:var(--accent)"></i>${sensitive(l.hostname||"*",`lan-lease-hostname-${index}`)}</div>`;
    const actions = `
      ${btn("Pin IP", "pin", "btn-ok btn-sm", `showAddLease(${jsArg(l.mac||"")},${jsArg(l.ip||"")},${jsArg(l.hostname||"")})`)}
    `;
    return {
      ip: `<code>${sensitive(l.ip,`lan-lease-ip-${index}`)}</code>`,
      mac: `<code>${sensitive(l.mac,`lan-lease-mac-${index}`)}</code>`,
      hostname: hostHtml,
      expires: `<span style="font-size:12px;color:var(--text-muted);">${fmtTime(l.expires)}</span>`,
      actions
    };
  });
  const staticRows=(dhcp.static_hosts||[]).map((s,index)=>{
    const parts=s.split(",");
    return{mac:`<code>${sensitive(parts[0]||"",`lan-static-mac-${index}`)}</code>`,hostname:sensitive(parts[1]||"",`lan-static-hostname-${index}`),ip:`<code>${sensitive(parts[2]||"",`lan-static-ip-${index}`)}</code>`,
      actions:btn("Delete","trash-2","btn-bad btn-sm",`doRemoveLease(${jsArg(parts[0]||"")})`)};
  });

  return[
    `<input type="text" class="search-input" id="clientSearch" placeholder="Search by IP, hostname, MAC…" oninput="filterClients()">`,
    section(`Clients (${clients.count??clientRows.length})`,viewError(errors,"/api/clients")+tblHtml(clientRows,[
      {key:"ip",label:"IP"},{key:"hostname",label:"Hostname"},{key:"vendor",label:"Vendor"},{key:"mac",label:"MAC"},
      {key:"latency",label:"Latency"},{key:"state",label:"State"},{key:"static_flag",label:"Static"},{key:"source",label:"Sources"},
      {key:"actions",label:""}
    ])),
    section("Interface Addresses",viewError(errors,"/api/interfaces")+(d["/api/interfaces"]?sensitiveBlock((ifaces.interfaces||[]).map(i=>`${i.name}: ${(i.addresses||[]).join(", ")||"none"}`).join("\n"),"lan-interface-addresses"):"")),
    section("DHCP leases",viewError(errors,"/api/dhcp")+(dhcpMeasured?tblHtml(leaseRows,[
      {key:"ip",label:"IP"},{key:"mac",label:"MAC"},{key:"hostname",label:"Host"},
      {key:"expires",label:"Expires"},{key:"actions",label:""}
    ]):""), `${btn("Restart DHCPD","rotate-cw","btn-accent","doRestart('isc-dhcpd')")} ${btn("DHCP Range","sliders","btn-accent","showDhcpRange()")}`),
    section("Static Leases",viewError(errors,"/api/dhcp")+(dhcpMeasured?tblHtml(staticRows,[{key:"mac",label:"MAC"},{key:"hostname",label:"Hostname"},{key:"ip",label:"IP"},{key:"actions",label:""}]):""),
      `${btn("Add","plus","btn-ok","showAddLease()")} ${btn("DNS Servers","server","btn-accent",`showDnsEdit(${jsArg((dhcp.upstreams||[]).join(","))})`)}`),
    `<div class="advanced-only">` + section("dhcpd syntax",viewError(errors,"/api/dhcp")+(dhcpMeasured?sensitiveBlock(dhcp.syntax||"","lan-dhcp-syntax"):"")) + `</div>`,
  ].join("");
}

function showPortForward(identifier){
  const current=(S.portForwards||[]).find(item=>item.id===identifier);
  const r=current||{id:"",enabled:true,protocol:"tcp",external_port:443,target_host:"",target_port:443,sources:[],allow_any_source:false};
  openModal(current?`Edit Forward ${esc(r.id)}`:"Add Port Forward WAN → LAN",`
    <div class="form-row">
      <div class="form-group"><label>ID</label><input class="form-input" id="pf_id" value="${esc(r.id)}" ${current?"readonly":""} placeholder="web" /></div>
      <div class="form-group"><label>Protocol</label><select class="form-input" id="pf_protocol"><option value="tcp" ${r.protocol==="tcp"?"selected":""}>TCP</option><option value="udp" ${r.protocol==="udp"?"selected":""}>UDP</option></select></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>External WAN Port</label><input class="form-input" id="pf_external" type="number" min="1" max="65535" value="${esc(r.external_port)}" /></div>
      <div class="form-group"><label>LAN IPv4</label>${sensitiveHtml(`<input class="form-input" id="pf_target_host" value="${esc(r.target_host)}" placeholder="10.88.0.155" />`,"port-forward-edit-target")}</div>
      <div class="form-group"><label>LAN Target Port</label><input class="form-input" id="pf_target_port" type="number" min="1" max="65535" value="${esc(r.target_port)}" /></div>
    </div>
    <div class="form-group"><label>Allowed Sources (IP/CIDR separated by spaces or newlines)</label>${sensitiveHtml(`<textarea class="form-input" id="pf_sources" rows="4" placeholder="203.0.113.5/32 198.51.100.0/24">${esc((r.sources||[]).join("\n"))}</textarea>`,"port-forward-edit-sources",true)}</div>
    <label style="display:block;margin:10px 0"><input id="pf_allow_any" type="checkbox" ${r.allow_any_source?"checked":""} /> Explicitly allow 0.0.0.0/0 (any source)</label>
    <label style="display:block;margin:10px 0"><input id="pf_enabled" type="checkbox" ${r.enabled?"checked":""} /> Rule enabled</label>
    <p style="color:var(--text-muted);font-size:12px">Primary WAN, single port, IPv4. Applied PF changes must be confirmed within 120 seconds.</p>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="savePortForward()">Apply</button>`);
}

async function confirmPortForwardChange(result){
  if(!result.confirmation_required)return true;
  const confirmed=await confirmModal("PF rules applied. Confirm changes? Without confirmation, the previous configuration rolls back in 120 seconds.","Confirm PF");
  if(!confirmed){toast("Unconfirmed: automatic rollback will execute");return false;}
  await post("/api/pf/conf/confirm",{});
  toast("PF rules confirmed","success");
  return true;
}

async function savePortForward(){
  const body={
    id:document.getElementById("pf_id").value.trim(),
    protocol:document.getElementById("pf_protocol").value,
    external_port:Number(document.getElementById("pf_external").value),
    target_host:document.getElementById("pf_target_host").value.trim(),
    target_port:Number(document.getElementById("pf_target_port").value),
    sources:document.getElementById("pf_sources").value.split(/\s+/).map(v=>v.trim()).filter(Boolean),
    allow_any_source:document.getElementById("pf_allow_any").checked,
    enabled:document.getElementById("pf_enabled").checked,
  };
  try{
    const result=await post("/api/port-forwards/save",body);
    closeModal();
    await confirmPortForwardChange(result);
    loadView();
  }catch(e){toast(e.message)}
}

async function togglePortForward(identifier){
  const current=(S.portForwards||[]).find(item=>item.id===identifier);
  if(!current){toast("Rule not found");return;}
  try{
    const result=await post("/api/port-forwards/save",{...current,enabled:!current.enabled});
    await confirmPortForwardChange(result);
    loadView();
  }catch(e){toast(e.message)}
}

async function deletePortForward(identifier){
  if(!await confirmModal(`Delete port forward ${identifier}?`,"Delete Port Forward"))return;
  try{
    const result=await post("/api/port-forwards/delete",{id:identifier});
    await confirmPortForwardChange(result);
    loadView();
  }catch(e){toast(e.message)}
}

async function testPortForward(identifier){
  try{
    const result=await post("/api/port-forwards/test",{id:identifier});
    const detail=result.detail||result.error||`${result.protocol||""} ${result.target||""}`;
    toast(`${result.ok?"LAN target reachable":"LAN target unreachable"}: ${detail}`,result.ok?"success":"error");
  }catch(e){toast(e.message)}
}

function showReverseSshKey(rule){
  openModal(`Public Key ${esc(rule.id)}`,`
    <p>Add this line to <code>authorized_keys</code> of a dedicated unprivileged account on the VPS:</p>
    ${sensitiveHtml(`<pre style="white-space:pre-wrap;word-break:break-all">${esc(rule.authorized_keys_hint||"Key not generated yet")}</pre>`,`reverse-ssh-public-key-${rule.id}`,true)}
    <p style="color:var(--text-muted)">Host key fingerprint: <code>${sensitive(rule.host_key_fingerprint||"not measured",`reverse-ssh-fingerprint-${rule.id}`)}</code></p>
    <p style="color:var(--text-muted);font-size:12px">The private key never leaves the router. Public binds also require VPS firewall restrictions on source IPs.</p>
  `,`<button class="btn btn-accent" onclick="closeModal()">Done</button>`);
}

function showReverseSshKeyById(identifier){
  const current=(S.reverseSshRules||[]).find(item=>item.id===identifier);
  if(current)showReverseSshKey(current);
}

function showReverseSsh(identifier){
  const current=(S.reverseSshRules||[]).find(item=>item.id===identifier);
  const r=current||{id:"",enabled:true,remote_host:"",remote_port:22,remote_user:"gatebsd-forward",remote_bind_address:"127.0.0.1",allow_public:false,external_port:443,target_host:"",target_port:443,host_key:""};
  openModal(current?`Edit Reverse SSH ${esc(r.id)}`:"Add Reverse SSH → LAN",`
    <div class="form-row">
      <div class="form-group"><label>ID</label><input class="form-input" id="rssh_id" value="${esc(r.id)}" ${current?"readonly":""} placeholder="home-web" /></div>
      <div class="form-group"><label>VPS SSH User (non-root)</label>${sensitiveHtml(`<input class="form-input" id="rssh_user" value="${esc(r.remote_user)}" />`,"reverse-ssh-edit-user")}</div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>VPS Host / DNS</label>${sensitiveHtml(`<input class="form-input" id="rssh_host" value="${esc(r.remote_host)}" />`,"reverse-ssh-edit-host")}</div>
      <div class="form-group"><label>SSH Port</label><input class="form-input" id="rssh_port" type="number" min="1" max="65535" value="${esc(r.remote_port)}" /></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>VPS Bind Address</label>${sensitiveHtml(`<input class="form-input" id="rssh_bind" value="${esc(r.remote_bind_address)}" />`,"reverse-ssh-edit-bind")}</div>
      <div class="form-group"><label>VPS Public Port</label><input class="form-input" id="rssh_external" type="number" min="1" max="65535" value="${esc(r.external_port)}" /></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>LAN IPv4</label>${sensitiveHtml(`<input class="form-input" id="rssh_target_host" value="${esc(r.target_host)}" />`,"reverse-ssh-edit-target")}</div>
      <div class="form-group"><label>LAN Target Port</label><input class="form-input" id="rssh_target_port" type="number" min="1" max="65535" value="${esc(r.target_port)}" /></div>
    </div>
    <div class="form-group"><label>VPS Public Host Key (ssh-ed25519 or ecdsa)</label>${sensitiveHtml(`<textarea class="form-input" id="rssh_host_key" rows="3" placeholder="ssh-ed25519 AAAA...">${esc(r.host_key)}</textarea>`,"reverse-ssh-edit-host-key",true)}</div>
    <label style="display:block;margin:10px 0"><input id="rssh_public" type="checkbox" ${r.allow_public?"checked":""} /> Explicitly allow non-loopback bind; VPS firewall configured</label>
    <label style="display:block;margin:10px 0"><input id="rssh_enabled" type="checkbox" ${r.enabled?"checked":""} /> Tunnel enabled</label>
    <p style="color:var(--text-muted);font-size:12px">TCP, StrictHostKeyChecking=yes, supervised via daemon(8). After saving, a public authorized_keys line with permitlisten will appear.</p>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="saveReverseSsh()">Save & Apply</button>`);
}

async function saveReverseSsh(){
  const body={
    id:document.getElementById("rssh_id").value.trim(),
    enabled:document.getElementById("rssh_enabled").checked,
    remote_host:document.getElementById("rssh_host").value.trim(),
    remote_port:Number(document.getElementById("rssh_port").value),
    remote_user:document.getElementById("rssh_user").value.trim(),
    remote_bind_address:document.getElementById("rssh_bind").value.trim(),
    allow_public:document.getElementById("rssh_public").checked,
    external_port:Number(document.getElementById("rssh_external").value),
    target_host:document.getElementById("rssh_target_host").value.trim(),
    target_port:Number(document.getElementById("rssh_target_port").value),
    host_key:document.getElementById("rssh_host_key").value.trim(),
  };
  try{
    const result=await post("/api/reverse-ssh/save",body);
    closeModal();
    showReverseSshKey(result);
    loadView();
  }catch(e){toast(e.message)}
}

async function toggleReverseSsh(identifier){
  const current=(S.reverseSshRules||[]).find(item=>item.id===identifier);
  if(!current){toast("Rule not found");return;}
  try{await post("/api/reverse-ssh/save",{...current,enabled:!current.enabled});loadView()}catch(e){toast(e.message)}
}

async function deleteReverseSsh(identifier){
  if(!await confirmModal(`Delete Reverse SSH ${identifier}? Tunnel will be stopped.`,"Delete Reverse SSH"))return;
  try{await post("/api/reverse-ssh/delete",{id:identifier});toast("Reverse SSH deleted","success");loadView()}catch(e){toast(e.message)}
}

function renderFirewall(d,errors={}){
  const fw=d["/api/firewall"]||{},fwMeasured=!!d["/api/firewall"],det=d["/api/firewall/detail"]||{};
  const states=det.states||[];
  const natRules=fw.nat_rules||[];
  const filterRules=fw.filter_rules||[];
  const conf=fw.conf||"";
  const enabled=fw.state==="enabled";
  const forwards=d["/api/port-forwards"]||{},forwardRules=forwards.rules||[];
  S.portForwards=forwardRules;
  const reverse=d["/api/reverse-ssh"]||{},reverseRules=reverse.rules||[];
  S.reverseSshRules=reverseRules;

  return [
    section("PF Firewall",viewError(errors,"/api/firewall")+(fwMeasured?`<div class="metric-grid">
      ${card("Status",pill(enabled?"Enabled":"Disabled",enabled?"ok":"bad"))}
      ${card("NAT Rules",esc(natRules.length))}
      ${card("Filter Rules",esc(filterRules.length))}
      ${card("Active States",d["/api/firewall/detail"]?esc(states.length):"not measured")}
    </div>`:""),`${btn("Reload PF","refresh-cw","btn-accent","doFirewallReload()")} ${btn("Edit pf.conf","file-text","btn-accent","showPfConfEdit()")}`),

    section("Port Forwarding WAN → LAN",viewError(errors,"/api/port-forwards")+`${btn("Add Forward","plus","btn-ok","showPortForward()")}`+(d["/api/port-forwards"]?(forwardRules.length?`<div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Status</th><th>Protocol</th><th>WAN Port</th><th>LAN Target</th><th>Sources</th><th>Actions</th></tr></thead>
      <tbody>${forwardRules.map((r,index)=>`<tr>
        <td><code>${esc(r.id)}</code></td><td>${pill(r.enabled?"Enabled":"Disabled",r.enabled?"ok":"bad")}</td>
        <td>${esc(r.protocol.toUpperCase())}</td><td>${esc(r.external_port)}</td><td><code>${sensitive(`${r.target_host}:${r.target_port}`,`port-forward-target-${index}`)}</code></td>
        <td><code>${sensitive((r.sources||[]).join(", "),`port-forward-sources-${index}`)}</code></td>
        <td>${btn("","play","btn-accent",`testPortForward(${jsArg(r.id)})`)} ${btn("","pencil","btn-accent",`showPortForward(${jsArg(r.id)})`)} ${btn("",r.enabled?"pause":"play","btn-accent",`togglePortForward(${jsArg(r.id)})`)} ${btn("","trash-2","btn-bad",`deletePortForward(${jsArg(r.id)})`)}</td>
      </tr>`).join("")}</tbody>
    </table></div><p style="color:var(--text-muted);font-size:12px">The ▶ button probes the LAN target from the router. External interface: ${esc(forwards.wan_if||"WAN")}, gateway: ${sensitive(forwards.gateway||"not measured","port-forward-gateway")}.</p>`:"<p style='color:var(--text-muted)'>No port forwards configured</p>"):"")),

    section("Reverse SSH → LAN",viewError(errors,"/api/reverse-ssh")+`${btn("Add Reverse SSH","plus","btn-ok","showReverseSsh()")}`+(d["/api/reverse-ssh"]?(reverseRules.length?`<div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Status</th><th>VPS</th><th>Bind:port</th><th>LAN Target</th><th>Actions</th></tr></thead>
      <tbody>${reverseRules.map((r,index)=>`<tr>
        <td><code>${esc(r.id)}</code></td><td>${pill(r.running?"Running":(r.enabled?"Stopped":"Disabled"),r.running?"ok":(r.enabled?"bad":"bad"))}</td>
        <td><code>${sensitive(`${r.remote_user}@${r.remote_host}:${r.remote_port}`,`reverse-ssh-vps-${index}`)}</code></td><td><code>${sensitive(`${r.remote_bind_address}:${r.external_port}`,`reverse-ssh-bind-${index}`)}</code></td>
        <td><code>${sensitive(`${r.target_host}:${r.target_port}`,`reverse-ssh-target-${index}`)}</code></td>
        <td>${btn("","key","btn-accent",`showReverseSshKeyById(${jsArg(r.id)})`)} ${btn("","pencil","btn-accent",`showReverseSsh(${jsArg(r.id)})`)} ${btn("",r.enabled?"pause":"play","btn-accent",`toggleReverseSsh(${jsArg(r.id)})`)} ${btn("","trash-2","btn-bad",`deleteReverseSsh(${jsArg(r.id)})`)}</td>
      </tr>`).join("")}</tbody>
    </table></div><p style="color:var(--text-muted);font-size:12px">Loopback bind is safe by default. Restrict allowed sources in the VPS firewall when binding publicly.</p>`:"<p style='color:var(--text-muted)'>No Reverse SSH tunnels configured</p>"):"")),

    section("NAT Rules",viewError(errors,"/api/firewall")+(fwMeasured?(natRules.length?`<div class="table-wrap"><table>
      <thead><tr><th>Rule</th></tr></thead>
      <tbody>${natRules.map((r,index)=>`<tr><td><code>${sensitive(r,`firewall-nat-${index}`)}</code></td></tr>`).join("")}</tbody>
    </table></div>`:"<p style='color:var(--text-muted)'>No NAT rules</p>"):"")),

    section("Filter Rules",viewError(errors,"/api/firewall")+(fwMeasured?(filterRules.length?`<div class="table-wrap"><table>
      <thead><tr><th>Rule</th></tr></thead>
      <tbody>${filterRules.map((r,index)=>`<tr><td><code>${sensitive(r,`firewall-filter-${index}`)}</code></td></tr>`).join("")}</tbody>
    </table></div>`:"<p style='color:var(--text-muted)'>No filter rules</p>"):"")),

    section("Active States",viewError(errors,"/api/firewall/detail")+(d["/api/firewall/detail"]?(states.length?`<div class="table-wrap"><table>
      <thead><tr><th>State</th></tr></thead>
      <tbody>${states.slice(0,50).map((s,index)=>`<tr><td><code style="font-size:11px">${sensitive(s,`firewall-state-${index}`)}</code></td></tr>`).join("")}${states.length>50?`<tr><td style="color:var(--text-muted)">... and ${states.length-50} more</td></tr>`:""}</tbody>
    </table></div>`:"<p style='color:var(--text-muted)'>No active states</p>"):"")),

    section("pf.conf Configuration",viewError(errors,"/api/firewall")+(fwMeasured?(conf?sensitiveHtml(`<pre style="max-height:400px;overflow:auto">${esc(conf)}</pre>`,"firewall-pf-conf",true):"<p style='color:var(--text-muted)'>pf.conf not found</p>"):"")),
  ].join("");
}
async function showPfConfEdit(){
  try{
    const r=await api("/api/pf/conf");
    openModal("Edit pf.conf",`
      <div class="form-group"><label>${esc(r.path||"/etc/pf.conf")}</label><textarea class="form-input" id="pf_conf_editor" rows="18" style="font-family:monospace;font-size:12px">${esc(r.conf||"")}</textarea></div>
    `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="savePfConfEdit()">Save & Apply</button>`);
  }catch(e){toast(e.message,"error")}
}
async function savePfConfEdit(){
  const el=document.getElementById("pf_conf_editor");
  const conf=el?el.value:"";
  if(!conf.trim()){toast("pf.conf cannot be empty","error");return}
  try{
    const result=await post("/api/pf/conf",{conf});
    closeModal();
    if(!await confirmPortForwardChange(result)){loadView(false);return}
    if(!result.confirmation_required)toast("pf.conf applied","success");
    loadView(false);
  }catch(e){toast(e.message,"error")}
}

function renderClients(d){
  const p=d["/api/clients"]||{},clients=p.clients||[];
  const rows=clients.map((c,index)=>({
    ip:sensitive(c.ip,`clients-ip-${index}`),hostname:sensitive(c.hostname,`clients-hostname-${index}`),mac:sensitive(c.mac,`clients-mac-${index}`),
    connection:`<i data-lucide="${c.connection==="wifi"?"wifi":"cable"}"></i> ${esc(c.connection)}`,
    bridge_port:esc(c.bridge_port),state:esc(c.state),
    static_flag:c.static?"✓":"",source:esc((c.source||[]).join(", "))
  }));
  return`<input type="text" class="search-input" id="clientSearch" placeholder="Search by IP, hostname, MAC…" oninput="filterClients()">`+
    section(`Clients (${clients.length})`,tblHtml(rows,[
      {key:"ip",label:"IP"},{key:"hostname",label:"Hostname"},{key:"mac",label:"MAC"},
      {key:"connection",label:"Type"},{key:"bridge_port",label:"Port"},
      {key:"state",label:"State"},{key:"static_flag",label:"Static"},{key:"source",label:"Sources"}
    ]));
}
function filterClients(){
  const q=(document.getElementById("clientSearch")?.value||"").toLowerCase();
  document.querySelectorAll("#content table tbody tr").forEach(tr=>{tr.style.display=tr.textContent.toLowerCase().includes(q)?"":"none"});
}

function renderDhcp(d){
  const dhcp=d["/api/dhcp"]||{};
  const leaseRows=(dhcp.leases||[]).map((l,index)=>({ip:sensitive(l.ip,`dhcp-lease-ip-${index}`),mac:sensitive(l.mac,`dhcp-lease-mac-${index}`),hostname:sensitive(l.hostname,`dhcp-lease-hostname-${index}`),expires:esc(fmtTime(l.expires))}));
  const staticRows=(dhcp.static_hosts||[]).map((s,index)=>{
    const parts=s.split(",");
    return{mac:sensitive(parts[0]||"",`dhcp-static-mac-${index}`),hostname:sensitive(parts[1]||"",`dhcp-static-hostname-${index}`),ip:sensitive(parts[2]||"",`dhcp-static-ip-${index}`),
      actions:btn("","trash-2","btn-bad",`doRemoveLease(${jsArg(parts[0]||"")})`)};
  });
  return[
    section("DHCP Leases",tblHtml(leaseRows,[{key:"ip",label:"IP"},{key:"mac",label:"MAC"},{key:"hostname",label:"Host"},{key:"expires",label:"Expires"}]),
      `${btn("Restart DHCPD","rotate-cw","btn-accent","doRestart('dhcpd')")} ${btn("DHCP Range","sliders","btn-accent","showDhcpRange()")}`),
    section("Static Leases",tblHtml(staticRows,[{key:"mac",label:"MAC"},{key:"hostname",label:"Hostname"},{key:"ip",label:"IP"},{key:"actions",label:""}]),
      `${btn("Add","plus","btn-ok","showAddLease()")} ${btn("DNS Servers","server","btn-accent",`showDnsEdit(${jsArg((dhcp.upstreams||[]).join(","))})`)}`),
    section("Syntax Check",pre(dhcp.syntax||"")),
  ].join("");
}

function renderAmnezia(d,errors={}){
  const a=d["/api/amnezia"]||{},cfg=a.config||{},p=(cfg.profiles||[])[0]||{};
  const vpn=d["/api/vpn/status"]||{},vpnProfiles=d["/api/vpn/profiles"]||{};
  const active=a.active_config||{};
  const wan = d["/api/wan"]||S.cache.get("/api/wan")||{};
  const modeLabel="non-bypass via AWG, bypass direct";
  const activeConfigLabel=active.target_name||active.name||amneziaActiveConfigLabel();
  const awgInterface=active.interface||p.interface||"";
  const serviceState=a.module_loaded?"active":"inactive";
  const repoStatusHtml = "";

  const sbHtml = "";

  // Three states, not two. `active` -- interface is up; `is_default` -- tunnel
  // carries the default route. The UI previously displayed the second under the
  // first's label, making an up-but-bypassed tunnel look stopped.
  // null -- failed to read gatewayctl: this is "unknown", not "off".
  const tunnelUp = vpn.active === true ? true : (vpn.active === false ? false : null);
  const vpnIsDefault = vpn.is_default === true ? true : (vpn.is_default === false ? false : null);
  const selectedProfile=a.active_config?.name||"";
  const prodProfiles=(vpnProfiles.profiles||a.config_files||[]);

  return[
    section("VPN Control",`<div class="metric-grid">${card("Tunnel",pill(tunnelUp===null?"unknown":tunnelUp?"up":"stopped", tunnelUp===null?"warn":tunnelUp?"ok":"bad"))}${card("Kernel module",pill(a.module_loaded?"loaded":"error",a.module_loaded?"ok":"bad"))}${card("Interface",esc(a.interface?.name||"awg0"))}${card("Default route",esc(vpnIsDefault===null?"unknown":vpnIsDefault?"awg0 (VPN)":"ng0 (WAN)"))}${card("RU bypass",esc(a.ru_bypass_count??0))}${card("Handshake",esc(a.handshake||"—"))}</div>
      <div class="action-grid" style="margin-top:16px;">
        ${actionCard("Start tunnel", "awg-quick up", "Bring up the VPN tunnel and route traffic through it.",
          tunnelUp === true ? "noop" : tunnelUp === false ? "normal" : "service",
          "power", "doAmneziaTunnel(true)", "Start", "Tunnel is already up — command will change nothing")}
        ${actionCard("Stop tunnel", "awg-quick down", "Stop VPN. Traffic goes direct (Cleartext).",
          tunnelUp === true ? "caution" : tunnelUp === false ? "noop" : "service",
          "power-off", "doAmneziaTunnel(false)", "Stop", "Tunnel is already down — command will change nothing")}
        ${actionCard("Premium profile", "vpn.upload", "Upload an Amnezia Premium configuration.", "normal", "upload-cloud", "showVpnUpload('premium')", "Upload")}
        ${actionCard("Self-Hosted profile", "vpn.upload", "Upload a self-hosted server configuration.", "normal", "upload", "showVpnUpload('self_hosted')", "Upload")}
      </div>`),
    section("VPN Profiles",
      prodProfiles.length
        ? `<div class="profile-grid">${prodProfiles.map(profileCard).join("")}</div>`
        : `<p style="color:var(--muted)">No profiles yet. Upload an Amnezia Premium or self-hosted configuration.</p>`,
      `${btn("Upload .conf","upload","btn-ok","showVpnUpload('self_hosted')")} ${btn("Upload Premium","upload-cloud","btn-accent","showVpnUpload('premium')")}`),
    section("Split Routing",`<div class="metric-grid">${card("Mode",esc(modeLabel))}${card("Policy mark",esc(p.mark||""))}${card("Kernel module",pill(a.module_loaded?"loaded":"error"))}${card("Bypass networks",esc(a.ru_bypass_count??0))}</div>`,
      `${btn("Refresh GeoIP lists","download","btn-ok","doAmneziaUpdateRuIps()")} ${btn("Test Curl","globe","btn-accent","showAmneziaDiagnose('curl')")} ${btn("Traceroute","route","btn-accent","showAmneziaDiagnose('traceroute')")}`),
    section("Policy Bypass Table",`<div class="metric-grid">${card("ru_bypass.table",`${esc(a.ru_bypass_count??0)} ${pill("ok")}`)}</div>`,
      `${btn("Add bypass CIDR","plus","btn-ok","showVpnNft('ru_bypass','add')")} ${btn("Remove bypass CIDR","minus","btn-bad","showVpnNft('ru_bypass','delete')")}`),
    renderVpnExceptions(d,errors),
    renderSplitDns(d,errors),
    section("Network & Service Diagnostics",`<div class="metric-grid">${card("Interface",esc(a.interface?.name||"awg0"))}${card("State",pill(a.interface?.state==="UP"?"UP":"DOWN",a.interface?.state==="UP"?"ok":"bad"))}${card("MTU",esc(a.interface?.mtu||"1280"))}${card("Active config",sensitive(activeConfigLabel||a.active_config||"none","vpn-active-config"))}</div>`),
    
    section("Debug & Raw Configs", [
      details("Routing (route)", sensitiveBlock((a.policy_routing?.rules||[]).join("\n"),"vpn-policy-routing-rules")),
      details("Tunnel status (awg show)", pre(a.show||"Tunnel inactive")),
      details("DNS/DHCP configuration", pre(a.dhcpd_config||"configuration missing")),
      details("Generated pf rules", pre(a.pf_config||"configuration missing")),
      details("Generated Policy Routing", `<h3 style="font-size:13px;margin-bottom:8px">Rules</h3>${pre(a.policy_routing?.rules||[])}<h3 style="font-size:13px;margin:12px 0 8px">Routes</h3>${pre(a.policy_routing?.routes||[])}`),
      details("Emergency Service Controls", `<div style="padding:10px">${btn("Initialize pf","shield","btn-accent","doVpnInit('pf')")} ${btn("Rebuild route scripts","route","btn-accent","doVpnInit('routes')")}</div>`)
    ].join(""))
  ].join("");
}

function renderAdblockSources(a){
  const run=a.last_run||{},sources=run.sources||[];
  const rows=sources.map(source=>({
    url:`<code>${esc(source.url)}</code>`,
    downloaded:esc(source.downloaded??0),
    parsed:esc(source.parsed??0),
    status:pill(source.status==="ok"?"accepted":"rejected",source.status==="ok"?"ok":"bad"),
    reason:esc(source.reason||"—"),
  }));
  const warnings=(run.warnings||[]).map(w=>`<div class="view-state degraded"><strong>${esc(w.msg)}</strong></div>`).join("");
  return section("Blocklist Sources",`${warnings}${run.error?`<div class="view-state unknown">${esc(run.error)}</div>`:""}${tblHtml(rows,[{key:"url",label:"Source"},{key:"downloaded",label:"Lines Downloaded"},{key:"parsed",label:"Parsed"},{key:"status",label:"Status"},{key:"reason",label:"Reason"}])}`,
    btn("Probe DNS","gauge","btn-accent",`showAdblockProbe(${jsArg(a.verdict||"always_null")})`));
}

function renderSplitDns(d,errors={}){
  const s=d["/api/dns/split"]||{},measured=!!d["/api/dns/split"];
  const ups=(s.upstreams||s.default_upstreams||[]).join(", ");
  const rows=(s.domains||[]).map((entry,index)=>({
    domain:sensitive(fmtDomain(entry.value,entry.display_value),`split-dns-domain-${index}`),
    target:esc(ups||"—"),
  }));
  const body=viewError(errors,"/api/dns/split")+(measured?(
    `${s.error?`<div class="view-state unknown">${esc(s.error)}</div>`:""}`
    +`<div class="metric-grid" style="margin-bottom:10px">${card("Status",pill(s.configured?"configured":"not configured",s.configured?"ok":"warn"))}${card("Split-DNS upstreams",esc(ups||"—"))}${card("Domains",esc((s.domains||[]).length))}</div>`
    +tblHtml(rows,[{key:"domain",label:"Domain (Split-DNS)"},{key:"target",label:"Upstream Resolvers"}])
    +`<div class="card-detail">Root DNS "." remains routed via VPN. Only listed domains resolve via split-DNS upstream servers (${esc(s.config||"")}).</div>`
  ):"");
  return section("Targeted Split-DNS",body,btn("Configure Split-DNS","sliders","btn-ok","showSplitDnsModal()"));
}
function showSplitDnsModal(){
  const s=S.cache.get("/api/dns/split")||{};
  const ups=(s.upstreams||s.default_upstreams||["77.88.8.8","77.88.8.1"]).join(", ");
  const doms=(s.domains||[]).map(item=>(item.display_value&&item.display_value!==item.value)?item.display_value:item.value).join("\n");
  openModal("Configure Targeted Split-DNS",`
    <div class="form-group"><label>Split-DNS Upstream Servers (comma-separated IPv4)</label><input class="form-input" id="split_dns_upstreams" value="${esc(ups)}" placeholder="77.88.8.8, 77.88.8.1"></div>
    <div class="form-group"><label>Domains for Split-DNS (one per line)</label><textarea class="form-input" id="split_dns_domains" rows="6" placeholder="example.org&#10;portal.example.org">${esc(doms)}</textarea></div>
    <div class="card-detail">Whole TLDs and public suffixes (e.g. <code>com</code>, <code>org</code>, <code>net</code>, <code>co.uk</code>, <code>gov</code>) are rejected: root "." always stays behind VPN.</div>
  `,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="doSplitDnsSave()">Save & Apply</button>`);
}
async function doSplitDnsSave(){
  const upstreamsRaw=document.getElementById("split_dns_upstreams").value;
  const domainsRaw=document.getElementById("split_dns_domains").value;
  const upstreams=upstreamsRaw.split(/[\s,]+/).map(s=>s.trim()).filter(Boolean);
  const domains=domainsRaw.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
  try{
    const r=await post("/api/dns/split",{domains,upstreams:upstreams.length?upstreams:null});
    closeModal();
    toast(r.changed?"Split-DNS updated":"Split-DNS unchanged",r.changed?"success":"info");
    loadView();
  }catch(e){toast(e.message)}
}

function renderAdblockRules(d,errors={}){
  const policy=d["/api/adblock/rules"]||{},measured=!!d["/api/adblock/rules"];
  const rows=(policy.entries||[]).map(entry=>({
    kind:pill(entry.kind==="allow"?"allow":"block",entry.kind==="allow"?"ok":"bad"),
    value:esc(fmtDomain(entry.value,entry.display_value)),
    actions:btn("Delete","trash-2","btn-bad btn-sm",`doAdblockRuleRemove(${jsArg(entry.kind)},${jsArg(entry.value)})`),
  }));
  return section("Allowlist & Blocklist",viewError(errors,"/api/adblock/rules")+(measured?`${tblHtml(rows,[{key:"kind",label:"Action"},{key:"value",label:"Domain"},{key:"actions",label:""}])}<div class="card-detail">File: ${esc(policy.config||"")}. Apply changes with "Update List Now".</div>`:""),btn("Add Rule","plus","btn-ok","showAdblockRule()"));
}
function showAdblockRule(){
  openModal("Add DNS Filtering Rule",`<div class="form-group"><label>Action</label><select class="form-input" id="adblock_rule_kind"><option value="block">block</option><option value="allow">allow</option></select></div><div class="form-group"><label>Domain</label><input class="form-input" id="adblock_rule_value" placeholder="ads.example.com"></div><div class="card-detail">Exact hostname only, no wildcards or IPs. Click "Update List Now" after adding.</div>`,`<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-ok" onclick="doAdblockRuleAdd()">Add</button>`);
}
async function doAdblockRuleAdd(){
  const kind=document.getElementById("adblock_rule_kind").value,value=document.getElementById("adblock_rule_value").value.trim();
  if(!value){toast("Enter a domain","error");return}
  try{const r=await post("/api/adblock/rules/add",{kind,value});closeModal();toast(r.changed?"Rule added":"Rule already exists",r.changed?"success":"info");loadView()}catch(e){toast(e.message)}
}
async function doAdblockRuleRemove(kind,value){
  if(!await confirmModal(`Remove ${kind} ${value}?`,"Adblock"))return;
  try{await post("/api/adblock/rules/remove",{kind,value});toast("Rule removed","success");loadView()}catch(e){toast(e.message)}
}

function renderAdblock(d,errors={}){
  const a=d["/api/adblock/status"]||{},measured=!!d["/api/adblock/status"];
  const state=a.enabled?pill("enabled","ok"):pill("inactive",a.configured?"bad":"warn");
  const configState=a.config_valid?pill("valid","ok"):pill("error","bad");
  const serviceState=a.unbound_running?pill("running","ok"):pill("stopped","bad");
  return[
    section("DNS Ad & Tracker Filtering",viewError(errors,"/api/adblock/status")+(measured?`<div class="metric-grid">${card("Filtering",state)}${card("Blocked domains",esc(a.domains||0))}${card("Unbound",serviceState)}${card("Configuration",configState)}${card("Updated",esc(a.generated||"—"))}${card("Last successful update",esc(fmtTime(a.last_success_at)||"not measured"))}</div>
      <div class="card-detail" style="margin-top:14px">Blocking runs at the DNS level via Unbound. Updates are syntax-checked and rolled back automatically if Unbound rejects the new list. DNS filtering does not replace a browser adblocker: it cannot strip page elements or block first-party ads served from the primary site domain.</div>`:""),
      `${btn("Update List Now","refresh-cw","btn-ok","doAdblockUpdate()")} ${btn("Open DNS Config","file-text","btn-accent","showDnsEdit('')")}`),
    measured?renderAdblockSources(a):"",
    renderAdblockRules(d,errors),
    renderSplitDns(d,errors),
    renderAdblockStats(a),
    section("File Status",viewError(errors,"/api/adblock/status")+(measured?`<div class="metric-grid">${card("Main config",esc(a.unbound_config||""))}${card("Blocklist file",esc(a.blocklist||""))}${card("Blocklist include",a.configured?pill("included","ok"):pill("not included","bad"))}${card("DNSSEC trust anchor",a.trust_anchor_writable===false?pill("not writable","bad"):a.trust_anchor_writable===true?pill("writable","ok"):pill("not measured","warn"))}</div>${a.trust_anchor_writable===false?`<div class="card-detail">Unbound cannot update its DNSSEC trust anchor because the service lacks write permission in its directory. External upstream validation continues working, but local DNSSEC validation cannot be enabled until fixed.</div>`:""}${a.last_error?pre(a.last_error):""}`:""))
  ].join("");
}

function showAdblockProbe(verdict){
  openModal("DNS Filtering Probe",`
    <div class="form-row"><div class="form-group"><label>Blocked Domain</label><input class="form-input" id="adblock_probe_blocked" value="doubleclick.net"></div>
    <div class="form-group"><label>Control Domain</label><input class="form-input" id="adblock_probe_control" value="example.com"></div></div>
    <div class="card-detail">Blocked domain must resolve to ${esc(verdict)}; control domain must return a normal non-zero IPv4 address. Read-only check.</div>
    <div id="adblock_probe_result" style="margin-top:12px"></div>`,
    `<button class="btn" onclick="closeModal()">Close</button><button class="btn btn-ok" onclick="doAdblockProbe(${escJs(verdict)})">Check</button>`);
}
function adblockProbeAnswer(label,answer){
  return card(label,`${pill(answer.ok?"matches":"mismatch",answer.ok?"ok":"bad")}<div class="card-detail">rcode: ${esc(answer.rcode||"none")}<br>addresses: ${esc((answer.addresses||[]).join(", ")||"—")}${answer.error?`<br>${esc(answer.error)}`:""}</div>`);
}
async function doAdblockProbe(verdict){
  const blocked=document.getElementById("adblock_probe_blocked").value.trim();
  const control=document.getElementById("adblock_probe_control").value.trim();
  const result=document.getElementById("adblock_probe_result");
  result.innerHTML=`<p style="color:var(--text2)">Probing DNS…</p>`;
  try{
    const response=await post("/api/adblock/probe",{blocked,control,verdict});
    result.innerHTML=`<div class="view-state ${response.ok?"degraded":"unknown"}"><strong>${response.ok?"Blocked and control domains responded as expected":"Probe check failed"}</strong></div><div class="metric-grid">${adblockProbeAnswer("Blocked",response.blocked)}${adblockProbeAnswer("Control",response.control)}</div>`;
    renderIcons(result);
  }catch(e){result.innerHTML=`<div class="view-state unknown">${esc(e.message)}</div>`}
}

function renderAdblockStats(a){
  const s=a.stats||{};
  const verdictLabel={always_null:"0.0.0.0 (always_null)",always_nxdomain:"NXDOMAIN",always_refuse:"REFUSED"}[a.verdict]||a.verdict||"—";
  // NXDOMAIN used to double as the blocked-answer counter. With always_null a
  // blocked name answers 0.0.0.0, so this counts genuinely non-existent names
  // and nothing else -- labelling it "blocked" would be a lie in a dashboard.
  if(!s.available){
    return section("Resolver Statistics",
      `<div class="card-detail">Counters unavailable: ${esc(s.reason||"unbound-control did not respond")}</div>`);
  }
  const rows=[
    card("Total queries",esc(s.queries??0)),
    card("Cache hit rate",`${esc(s.cache_hit_percent??0)}%`),
    card("Block verdict",esc(verdictLabel)),
    card("Active sources",esc(a.sources_used||"—"))
  ];
  if(s.extended){
    rows.push(card("NXDOMAIN (non-existent)",esc(s.nxdomain??0)));
    rows.push(card("SERVFAIL",esc(s.servfail??0)));
    rows.push(card("Avg recursion time",`${esc(s.recursion_avg??0)} s`));
  }
  const note=s.extended
    ? `Blocked query share is intentionally omitted: with 0.0.0.0 responses, blocked answers are indistinguishable from normal NOERROR replies in rcode counters without RPZ.`
    : `<b>extended-statistics is disabled</b> — only summary counters are available (enable in unbound.conf).`;
  return section("Resolver Statistics",
    `<div class="metric-grid">${rows.join("")}</div><div class="card-detail" style="margin-top:14px">${note}</div>`);
}

async function doAdblockUpdate(){
  if(!await confirmModal("Download fresh blocklists, validate config, and reload Unbound? Automatically rolls back on error.","Update Blocklist"))return;
  try{
    toast("Updating blocklist…","success");
    const r=await post("/api/adblock/update",{});
    toast(`Filtering active: ${r.domains||0} domains`,"success");
    loadView();
  }catch(e){toast(e.message,"error")}
}

function upsStatus(raw){
  const flags=String(raw||"").trim().split(/\s+/).filter(Boolean);
  const labels={OL:"Online",OB:"On Battery",CAL:"Calibration",DISCHRG:"Discharging",CHRG:"Charging",LB:"Low Battery"};
  const translated=flags.map(flag=>labels[flag]||flag);
  const level=flags.includes("LB")?"bad":flags.some(flag=>["OB","CAL","DISCHRG"].includes(flag))?"warn":flags.includes("OL")?"ok":"warn";
  return{label:translated.length?translated.join(" · "):"not measured",level};
}

function renderUps(d,errors={}){
  const ups=d["/api/ups"]||{},upsMeasured=!!d["/api/ups"];
  const cfg=d["/api/ups/config"]||{};
  const status=upsStatus(ups.data?.["ups.status"]);
  const chargeRaw=ups.data?.["battery.charge"]||"",chargeKnown=chargeRaw!==""&&Number.isFinite(Number(chargeRaw)),charge=chargeKnown?Number(chargeRaw):0;
  const lastCheck=ups.last_check?.available===true
    ? `${fmtTime(ups.last_check.checked_at)||"—"} · ${ups.last_check.ok?"ok":`errors: ${esc(ups.last_check.errors??"?")}`}`
    : "not measured";
  const warningsHtml=(ups.warnings||[]).length?`<div class="view-state degraded"><strong>Suspicious Readings</strong>${ups.warnings.map(w=>`<div>${esc(w)}</div>`).join("")}</div>`:"";
  ["Uninterruptible Power Supply","NUT Configuration","UPS Commands"].forEach(title=>{if(S.sections[title]===undefined)S.sections[title]=true});
  const commandCards=(ups.available_commands||[]).map(c=>{
    const meta=UPS_CMD_LABELS[c.name]||{label:c.name,icon:"terminal",risk:"service",group:"Other",help:c.description||"Command exposed by the UPS driver."};
    const allowed=UPS_ALLOWED_COMMANDS.has(c.name);
    const cls=meta.risk==="danger"?"danger":meta.risk==="caution"?"caution":meta.risk==="blocked"||!allowed?"blocked":meta.risk==="service"?"service":"normal";
    const action=allowed?btn("Execute",meta.icon,meta.risk==="danger"?"btn-bad":meta.risk==="caution"?"btn-accent":"btn-ok",`doUpsCmd(${jsArg(c.name)})`):disabledBtn("Unavailable","lock","Command is not permitted by backend allowlist");
    return `<article class="action-card ${cls}">
      <div class="action-head"><i data-lucide="${meta.icon}"></i><div><h3>${esc(meta.label)}</h3><code>${esc(c.name)}</code></div></div>
      <p>${esc(meta.help||c.description||"")}</p>
      <div class="action-foot"><span class="risk ${cls}">${esc(RISK_LABELS[meta.risk]||"Service")}</span>${action}</div>
    </article>`;
  }).join("");
  const listen=(cfg.listeners||[]).map(l=>`${l.address}:${l.port}`).join(", ")||"";
  return[
    section("Uninterruptible Power Supply",viewError(errors,"/api/ups")+(upsMeasured?`${warningsHtml}<div class="metric-grid ups-status-grid">${card("UPS",esc(ups.name||""))}${card("Link",pill(ups.ok?"ok":"Connection lost",ups.ok?"ok":"bad"))}${card("Status",pill(status.label,status.level))}${card("Last UPS response",esc(fmtTime(ups.last_response_at)||"not measured"))}${card("Last check",lastCheck)}${card("Input",esc(ups.data?.["input.voltage"]||"?")+" V")}${card("Output",esc(ups.data?.["output.voltage"]||"?")+" V")}${card("Load",esc(ups.data?.["ups.load"]||"?")+" %")}
      <article class="card battery-card"><div class="card-label">Battery Charge</div><div class="card-value">${chargeKnown?`${esc(chargeRaw)}%`:"not measured"}</div><div class="progress-bar"><div class="progress-fill progress-${charge<20?"bad":charge<50?"warn":"ok"}" style="width:${charge}%"></div></div><div class="card-detail">${/^\d+$/.test(ups.data?.["battery.runtime"]||"")?`Remaining ${esc(ups.data["battery.runtime"])}s`:"Runtime not reported by driver"}</div></article></div>`:""),
      `${btn("Configure NUT","settings","btn-ok","showUpsConfig()")} ${btn("Restart NUT","rotate-cw","btn-accent","doUpsRestart()")}`),
    ups.error?section("NUT Error",pre(ups.error)):"",
    section("NUT Configuration",viewError(errors,"/api/ups/config")+(d["/api/ups/config"]?`<div class="metric-grid">${card("Directory",esc(cfg.dir||""))}${card("Mode",pill(cfg.mode||"?",cfg.mode&&cfg.mode!=="none"?"ok":"bad"))}${card("Driver",esc(cfg.driver||""))}${card("Port",esc(cfg.port||""))}${card("Address",esc(listen))}${card("Command access",pill(cfg.command_access?"configured":"not configured",cfg.command_access?"ok":"warn"))}${card("Killpower",pill(cfg.allow_killpower?"enabled":"disabled",cfg.allow_killpower?"warn":"ok"))}</div>`:"")),
    section("UPS Commands",viewError(errors,"/api/ups")+(upsMeasured?`<div class="action-grid">${commandCards||"<span style='color:var(--muted)'>No UPS commands available</span>"}</div>${ups.commands_error?`<div style="margin-top:12px">${pre(ups.commands_error)}</div>`:""}`:"")),
    details("Available Commands",tbl(ups.available_commands||[],[{key:"name",label:"Command"},{key:"description",label:"Description"}])),
    details("All UPS Parameters",tbl(Object.entries(ups.data||{}).map(([k,v])=>({key:k,value:v})),[{key:"key",label:"Parameter"},{key:"value",label:"Value"}])),
  ].join("");
}

function renderTls(d,errors={}){
  const t=d["/api/tls/status"]||{},measured=!!d["/api/tls/status"];
  const expiryClass=t.days_remaining<0?"bad":t.days_remaining<30?"warn":"ok";
  return section("TLS Certificate",viewError(errors,"/api/tls/status")+(measured?`<div class="metric-grid">${card("Expires",`${esc(fmtTime(t.not_after)||"not measured")} ${pill(t.days_remaining<0?"expired":`${esc(t.days_remaining)}d`,expiryClass)}`)}${card("SAN",sensitive((t.san||[]).join(", ")||"not measured","system-tls-san"))}${card("Last successful renewal",esc(fmtTime(t.last_success_at)||"not measured"))}${card("Next attempt",esc(fmtTime(t.next_attempt)||"not measured"))}</div>${t.last_error?`<div class="view-state degraded"><strong>Last error · ${esc(fmtTime(t.last_error.checked_at)||"—")}</strong><div>${esc(t.last_error.message)}</div></div>`:""}${t.error?`<div class="view-state unknown">${esc(t.error)}</div>`:""}`:""),btn("Renew Now","refresh-cw","btn-accent","doTlsRenew()"));
}
async function doTlsRenew(){
  if(!await confirmModal("Request or renew TLS certificate and reload nginx? Previous certificate will be restored on error.","TLS"))return;
  let payload;
  try{payload=await post("/api/tls/renew",{})}catch(e){payload=e.payload||{renewal:{ok:false,output:e.message,rolled_back:false}}}
  const renewal=payload.renewal||{};
  openModal("TLS Renewal Result",`<div class="metric-grid">${card("Result",pill(renewal.ok?"renewed":"error",renewal.ok?"ok":"bad"))}${renewal.ok===false?card("Previous certificate",pill(renewal.rolled_back?"preserved / restored":"state unconfirmed",renewal.rolled_back?"ok":"bad")):""}${card("Expires",esc(fmtTime(payload.not_after)||"not measured"))}${card("Next attempt",esc(fmtTime(payload.next_attempt)||"not measured"))}</div>${renewal.output?pre(renewal.output):""}`,`<button class="btn" onclick="closeModal();loadView()">Close</button>`);
}

function renderSystem(d,errors={}){
  const sys=d["/api/system"]||{},mem=d["/api/memory"]||{},disks=d["/api/disks"]||{},svc=d["/api/services"]||{};
  const zfs=d["/api/zfs"]||{},diskIo=d["/api/disks/io"]||{};
  const m=mem.mem||{},sw=mem.swap||{};
  const result=[];
  result.push(section("System",viewError(errors,"/api/system")+(d["/api/system"]?tblHtml([{key:"Hostname",value:sensitive(sys.hostname,"system-hostname")},{key:"OS",value:esc(sys.os)},{key:"Kernel",value:esc(sys.kernel)},{key:"Uptime",value:esc(fmtUptime(sys.uptime_seconds))},{key:"Load",value:esc(sys.loadavg)}],[{key:"key",label:""},{key:"value",label:""}]):"")));
  result.push(renderTls(d,errors));
  result.push(section("Host Controls", `<div class="action-grid">
    ${actionCard("Reboot", "reboot", "Reboot the gateway. Connectivity will pause for 2-3 minutes.", "danger", "rotate-ccw", "doSystemPower('reboot')")}
    ${actionCard("Power Off", "poweroff", "Full system power off. Requires physical power-on.", "danger", "power", "doSystemPower('poweroff')")}
    ${`<article class="action-card"><div class="action-head"><i data-lucide="wrench"></i><div><h3>Setup Wizard</h3><code>gatebsd-install</code></div></div><p>Initial interface reconfiguration is restricted to the local console.</p><div class="action-foot"><span class="risk normal">Console</span>${disabledBtn("Unavailable in Web UI","lock","Use the local console to avoid losing gateway access")}</div></article>`}
  </div>`));
  result.push(section("Memory",viewError(errors,"/api/memory")+(d["/api/memory"]?`<div class="metric-grid">${progressCard("RAM",m.total-(m.available||0),m.total)}${progressCard("Swap",sw.used||0,sw.total||0)}</div>`:"")));
  result.push(section("Services",viewError(errors,"/api/services")+(d["/api/services"]?`<div class="action-grid">
    ${Object.entries(svc).map(([k,v])=>actionCard(svcName(k), k, v==="active"?"Service is running normally.":"Service is stopped or in an error state.", v==="active"?"service":"warn", "activity", `doRestart(${jsArg(k)})`, "Restart")).join("")}
  </div>`:"")));
  // Disks table
  result.push(section("Disks & Storage",viewError(errors,"/api/disks")+tblHtml((disks.blockdevices||[]).map(d=>{
    let smartInfo = "-";
    if(d.smart && d.smart.passed !== undefined) {
      smartInfo = `${d.smart.passed ? pill("healthy","ok") : pill("failing","bad")} ${d.smart.temp ? d.smart.temp+"°C" : ""} ${d.smart.power_on_hours ? d.smart.power_on_hours+"h" : ""}`;
    }
    const fst = d.fstype || (d.children && d.children[0] && d.children[0].fstype) || "";
    const mnt = d.mountpoints?.filter(Boolean).join(", ") || (d.children ? d.children.filter(c=>c.mountpoints?.length).map(c=>c.mountpoints[0]).filter(Boolean).join(", ") : "") || "-";
    return {
      name: esc(d.name),
      model: `<span style="font-size:12px">${esc(d.smart?.model || d.model || "")}</span>`,
      size: esc(d.size),
      fstype: esc(fst),
      mount: esc(mnt),
      health: smartInfo,
      actions: `<div style="display:flex;justify-content:flex-end">${btn("Details", "info", "btn", `showDiskDetails(${jsArg(d.name)})`)}</div>`
    };
  }),[{key:"name",label:"Device"},{key:"model",label:"Model"},{key:"size",label:"Size"},{key:"fstype",label:"FS"},{key:"mount",label:"Mount"},{key:"health",label:"S.M.A.R.T."},{key:"actions",label:""}])));
  if(errors["/api/zfs"]&&!d["/api/zfs"])result.push(section("ZFS",viewError(errors,"/api/zfs")));
  // ZFS Pools
  if (zfs.pools && zfs.pools.length > 0) {
    result.push(section("ZFS Pools", viewError(errors,"/api/zfs")+tblHtml(zfs.pools.map(p=>({
      name:p.name, state:pill(p.state,p.state==="ONLINE"?"ok":"bad"),
      vdevs:p.vdevs.map(v=>`${v.name} (${v.state})`).join(", "),
      errors:p.errors||"none"
    })),[{key:"name",label:"Pool"},{key:"state",label:"State"},{key:"vdevs",label:"Vdevs"},{key:"errors",label:"Errors"}])));
  }
  // ZFS Datasets
  if (zfs.datasets && zfs.datasets.length > 0) {
    result.push(section("ZFS Datasets", viewError(errors,"/api/zfs")+tbl(zfs.datasets.filter(ds=>ds.type==="filesystem").map(ds=>({
      name:ds.name, used:ds.used, avail:ds.avail, refer:ds.refer, mountpoint:ds.mountpoint
    })),[{key:"name",label:"Dataset"},{key:"used",label:"Used"},{key:"avail",label:"Avail"},{key:"refer",label:"Refer"},{key:"mountpoint",label:"Mountpoint"}])));
  }
  if(errors["/api/disks/io"]&&!d["/api/disks/io"])result.push(section("Disk I/O",viewError(errors,"/api/disks/io")));
  // Disk I/O
  if (diskIo.devices && diskIo.devices.length > 0) {
    result.push(section("Disk I/O", viewError(errors,"/api/disks/io")+tbl(diskIo.devices.map(d=>({
      name:d.name, kb_per_t:d.kb_per_t.toFixed(1), tps:d.tps, mb_per_s:d.mb_per_s.toFixed(2)
    })),[{key:"name",label:"Device"},{key:"kb_per_t",label:"KB/t"},{key:"tps",label:"TPS"},{key:"mb_per_s",label:"MB/s"}])));
  }
  return result.join("");
}

window.showDiskDetails = function(name) {
  const disks = S.cache.get("/api/disks")?.blockdevices || [];
  const d = disks.find(x => x.name === name);
  if (!d) return;

  let html = `<div style="display:flex; flex-direction:column; gap:10px;">`;
  html += `<table style="width:100%; font-size:13px;">`;
  html += `<tr><td style="color:var(--text2);">Device</td><td>${esc(d.path||"/dev/"+d.name)}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Model</td><td>${esc(d.smart?.model || d.model || "-")}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Serial Number</td><td>${sensitive(d.smart?.serial || "-",`disk-${name}-serial`)}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Firmware</td><td>${esc(d.smart?.firmware || "-")}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Size</td><td>${esc(d.size)}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Bus Type</td><td>${esc(d.tran||"-")}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Rotational</td><td>${d.rota==="1"?"Yes (HDD)":"No (SSD/Flash)"}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Temperature</td><td>${esc(d.smart?.temp ? d.smart.temp+"°C" : "-")}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Health (SMART)</td><td>${d.smart?.passed !== undefined ? (d.smart.passed ? pill("healthy","ok") : pill("failing","bad")) : "-"}</td></tr>`;
  html += `<tr><td style="color:var(--text2);">Power-On Hours</td><td>${esc(d.smart?.power_on_hours ? d.smart.power_on_hours+" h" : "-")}</td></tr>`;
  html += `</table>`;

  // Partitions
  if (d.children && d.children.length > 0) {
    html += `<h4 style="margin:15px 0 5px;">Partitions:</h4>`;
    html += `<table style="width:100%; font-size:12px; border-top:1px solid var(--border-s);">`;
    html += `<tr><th>Name</th><th>FS</th><th>Mount</th></tr>`;
    d.children.forEach(c => {
      html += `<tr><td>${esc(c.name)}</td><td>${esc(c.fstype||"-")}</td><td>${esc(c.mountpoints?.filter(Boolean).join(", ")||"-")}</td></tr>`;
    });
    html += `</table>`;
  }

  // SMART self-test buttons
  html += `<div style="margin-top:15px; display:flex; gap:8px;">`;
  html += btn("SMART Short Test","activity","btn-accent",`doSmartTest(${jsArg(d.name)},"short")`);
  html += btn("SMART Long Test","activity","btn",`doSmartTest(${jsArg(d.name)},"long")`);
  html += `</div>`;

  html += `</div>`;

  openModal(`Disk Info: ${esc(d.name)}`, html, `<button class="btn" onclick="closeModal()">Close</button>`);
};

window.doSmartTest = async function(device, type) {
  try {
    const r = await post("/api/disks/smart/test", {device, type});
    toast(r.ok ? `SMART ${type} test started on ${device}` : `Failed: ${r.output||"error"}`);
  } catch(e) { toast(e.message); }
};

function renderHistory(d,errors={}){
  const h=d["/api/history"]||{},measured=!!d["/api/history"];
  return[
    section("Overview",viewError(errors,"/api/history")+(measured?`<div class="metric-grid">${card("Events",esc((h.events||[]).length))}${card("Devices",esc((h.devices||[]).length))}${card("Database",esc(h.db_path||""))}</div>`:"")),
    section("Recent Events",viewError(errors,"/api/history")+(measured?tblHtml((h.events||[]).map((e,index)=>({time:esc(fmtRel(e.ts)),severity:esc(e.severity),kind:esc(e.kind),message:sensitive(e.message,`history-event-${index}`)})),
      [{key:"time",label:"Time"},{key:"severity",label:"Severity"},{key:"kind",label:"Type"},{key:"message",label:"Message"}]):"")),
    section("Devices",viewError(errors,"/api/history")+(measured?tblHtml((h.devices||[]).map((device,index)=>({ip:sensitive(device.ip,`history-device-ip-${index}`),hostname:sensitive(device.hostname,`history-device-hostname-${index}`),mac:sensitive(device.mac,`history-device-mac-${index}`),connection:esc(device.connection),last:esc(fmtRel(device.last_seen)),first:esc(fmtTime(device.first_seen))})),
      [{key:"ip",label:"IP"},{key:"hostname",label:"Hostname"},{key:"mac",label:"MAC"},{key:"connection",label:"Type"},{key:"last",label:"Last Seen"},{key:"first",label:"First Seen"}]):"")),
    section("Backups (State Snapshots)",viewError(errors,"/api/history")+(measured?tbl(h.snapshot_counts||[],[{key:"kind",label:"Type"},{key:"count",label:"Count"},{key:"latest",label:"Latest"}]):"")),
  ].join("");
}

let currentLogs = null;
async function fetchLogs() {
  const unit = document.getElementById("log_unit")?.value || "all";
  const grep = document.getElementById("log_grep")?.value || "";
  const prio = document.getElementById("log_prio")?.value || "all";
  const limit = document.getElementById("log_limit")?.value || "100";
  try {
    currentLogs = await api(`/api/logs?unit=${encodeURIComponent(unit)}&grep=${encodeURIComponent(grep)}&priority=${encodeURIComponent(prio)}&limit=${encodeURIComponent(limit)}`);
    document.getElementById("log_output").innerHTML = pre((currentLogs.lines && currentLogs.lines.join('\n')) || currentLogs.error || "No logs found");
  } catch(e) { toast(e.message); }
}

function renderLogs(d,errors={}){
  const svcs = d["/api/services/all"] || [];
  const svcOptions = `<option value="all">-- Entire System --</option>` + svcs.map(s => `<option value="${esc(s.unit)}">${esc(s.unit)}</option>`).join("");
  
  if (!currentLogs && !document.getElementById("log_output")) {
    setTimeout(fetchLogs, 50); // fetch initial logs after render
  }
  
  return section("System Log (Syslog)",`${viewError(errors,"/api/services/all")}
    <div class="form-row">
      <div class="form-group"><label>Service (Unit)</label><select class="form-input" id="log_unit" onchange="fetchLogs()">${svcOptions}</select></div>
      <div class="form-group"><label>Filter (Grep)</label><input class="form-input" id="log_grep" placeholder="Search text" onchange="fetchLogs()"></div>
      <div class="form-group"><label>Level</label>
        <select class="form-input" id="log_prio" onchange="fetchLogs()">
          <option value="all">All (0-7)</option>
          <option value="3">Errors (0-3)</option>
          <option value="4">Warnings (0-4)</option>
        </select>
      </div>
      <div class="form-group"><label>Lines</label><select class="form-input" id="log_limit" onchange="fetchLogs()">
        <option value="100">100</option><option value="500">500</option><option value="1000">1000</option>
      </select></div>
    </div>
    <div style="margin-top:12px">${btn("Refresh","rotate-cw","btn-accent",`fetchLogs()`)}</div>
  `) + section("Output", `<div id="log_output">${pre(currentLogs?.lines || "Loading...")}</div>`);
}

function getBackupTypeBadge(base) {
  const b = String(base || "").toLowerCase();
  if (b.includes("static-hosts")) return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;background:rgba(59,130,246,0.15);color:#60a5fa;font-size:11px;font-weight:500;"><i data-lucide="network" style="width:12px;height:12px;"></i> Static DHCP</span>`;
  if (b.includes("dhcpd") || b.includes("unbound")) return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;background:rgba(245,158,11,0.15);color:#fbbf24;font-size:11px;font-weight:500;"><i data-lucide="server" style="width:12px;height:12px;"></i> DNS/DHCP FreeBSD</span>`;
  if (b.includes("amnezia")) return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;background:rgba(139,92,246,0.15);color:#a78bfa;font-size:11px;font-weight:500;"><i data-lucide="lock" style="width:12px;height:12px;"></i> VPN Amnezia</span>`;
  if (b.includes("networkConfig") || b.includes("rc.conf")) return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;background:rgba(236,72,153,0.15);color:#f472b6;font-size:11px;font-weight:500;"><i data-lucide="cpu" style="width:12px;height:12px;"></i> Network Bridges</span>`;
  return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;background:rgba(255,255,255,0.08);color:var(--text-muted);font-size:11px;"><i data-lucide="file-text" style="width:12px;height:12px;"></i> Config</span>`;
}

function renderBackups(d,errors={}){
  const bk = d["/api/backups"] || {},measured=!!d["/api/backups"];
  const backups = bk.backups || [];
  const totalSize = backups.reduce((acc, item) => acc + (item.size || 0), 0);

  const rows = backups.map(b => ({
    name: `<code style="font-size:12px;color:var(--text);">${esc(b.name)}</code>`,
    type: getBackupTypeBadge(b.base),
    time: `<span style="font-size:12px;color:var(--text-muted);">${fmtTime(b.mtime)}</span>`,
    size: fmtB(b.size),
    actions: `
      ${btn("Diff", "git-compare", "btn-accent btn-sm", `doBackupDiff(${jsArg(b.name)})`)}
      ${btn("Restore", "rotate-ccw", "btn-ok btn-sm", `doBackupRestore(${jsArg(b.name)})`)}
      ${btn("Delete", "trash-2", "btn-bad btn-sm", `doBackupDelete(${jsArg(b.name)})`)}
    `
  }));

  const banner = `
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:16px; margin-bottom:20px;">
      <div class="action-card success" style="padding:16px;">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
          <i data-lucide="camera" style="width:20px;height:20px;color:var(--status-up)"></i>
          <strong style="font-size:14px;">Create Snapshot</strong>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">Creates an atomic snapshot of the core router configurations.</p>
        ${btn("Create Snapshot Now", "plus-circle", "btn-ok", "doBackupCreate()")}
      </div>

      <div class="action-card normal" style="padding:16px;">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
          <i data-lucide="shield-check" style="width:20px;height:20px;color:var(--accent)"></i>
          <strong style="font-size:14px;">Crash-Safe Rollback</strong>
        </div>
        <p style="font-size:12px; color:var(--text-muted);">Before mutating any critical configuration, the previous state is backed up automatically.</p>
      </div>

      <div class="action-card normal" style="padding:16px;">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
          <i data-lucide="hard-drive" style="width:20px;height:20px;color:var(--status-warn)"></i>
          <strong style="font-size:14px;">Backup Statistics</strong>
        </div>
        <div style="font-size:13px; color:var(--text); margin-top:4px;">
          Total snapshots: <strong>${measured?backups.length:"not measured"}</strong><br>
          Total size: <strong>${measured?fmtB(totalSize):"not measured"}</strong>
        </div>
      </div>
    </div>
  `;

  return [
    banner,
    section(measured?`Snapshot History (${backups.length})`:"Snapshot History",viewError(errors,"/api/backups")+(measured?tblHtml(rows, [
      {key:"name", label:"Snapshot"},
      {key:"type", label:"Config Type"},
      {key:"time", label:"Created"},
      {key:"size", label:"Size"},
      {key:"actions", label:""}
    ]):""))
  ].join("");
}

function renderAdmin(d,errors={}){
  const sys=d["/api/system"]||{},svc=d["/api/services"]||{},bk=d["/api/backups"]||{};
  // rc unit names as this appliance actually ships them. "gatebsd-agent"
  // and "gatebsd-ui" were listed here for a long time and are not rc
  // services at all -- they are the two processes of the single "gatebsd"
  // script -- so the table reported them "unknown" and the restart
  // button had nothing to act on. gatebsd_failover is the WAN/VPN watchdog
  // and gatewayctl_apply raises the tunnel; both belong in view.
  const managed=["gatebsd","gatebsd_failover","gatewayctl_apply","amnezia","unbound","dhcpd","pf","nut","nut_upsmon","sshd","cron"];
  const svcRows=managed.map(unit=>({unit,service:svcName(unit),state:pill(svc[unit]||"unknown"),
    actions:btn("Restart","rotate-cw","btn-accent",`doRestart(${jsArg(unit)})`)}));
  const backupRows=(bk.backups||[]).slice(0,8).map(b=>({...b,time:fmtTime(b.mtime),size:fmtB(b.size),
    actions:`${btn("Diff","git-compare","btn-accent",`doBackupDiff(${jsArg(b.name)})`)} ${btn("Restore","rotate-ccw","btn-ok",`doBackupRestore(${jsArg(b.name)})`)}`}));
  return[
    section("System Status",viewError(errors,"/api/system")+(d["/api/system"]?`<div class="metric-grid">
      ${card("Host",sensitive(sys.hostname||"","admin-hostname"))}
      ${card("OS",esc(sys.os||""))}
      ${card("Kernel",esc(sys.kernel||""))}
      ${card("Uptime",esc(fmtUptime(sys.uptime_seconds)))}
      ${card("GateBSD Version",esc(sys.package_version||""))}
      ${card("Maintainer",esc(sys.package_maintainer||""))}
    </div>`:"")),
    
    section("System Updates (pkg)", (() => {
      const updates = d["/api/system/updates"] || {};
      const missing = Array.isArray(updates.missing) ? updates.missing : [];
      const upgradable = Array.isArray(updates.upgradable) ? updates.upgradable : [];
      const details = [];
      if (missing.length) details.push("Missing required packages:\n" + missing.join("\n"));
      if (upgradable.length) details.push("Upgrades available:\n" + upgradable.join("\n"));
      const content=(updates.count > 0
        ? `<p style="color:var(--bad)">Action required: <b>${updates.count}</b></p>` + pre(details.join("\n\n"))
        : `<p style="color:var(--ok)">All required packages are installed; no updates available.</p>`) +
        `<div style="margin-top:12px">${btn("Check Updates","refresh-cw","btn-accent",`doPkgUpdate()`)} ` +
        (updates.count > 0 ? btn("Install & Upgrade","download","btn-ok",`doPkgUpgrade()`) : "") + `</div>`;
      return viewError(errors,"/api/system/updates")+(d["/api/system/updates"]?content:"");
    })()),
    
    section("Package Source", viewError(errors,"/api/repo/sources")+(d["/api/repo/sources"]?renderRepoSources(d["/api/repo/sources"]):"")),

    section("Terminal (sudo)", sensitiveHtml(`<div id="termPlaceholder" style="background:#000;border-radius:6px;min-height:400px;"></div>`,"admin-terminal",true)),
    
    section("Managed Services",viewError(errors,"/api/services")+tblHtml(svcRows,[{key:"service",label:"Service"},{key:"unit",label:"Unit"},{key:"state",label:"Status"},{key:"actions",label:""}])),
    section("All System Services",viewError(errors,"/api/services/all")+tblHtml((d["/api/services/all"]||[]).map(s=>({
      unit:`<span title="${esc(s.description)}">${esc(s.unit)}</span>`,
      state:pill(s.active==="active"?"active":s.active,s.active==="active"?"ok":"bad"),
      load:pill(s.load==="loaded"?"loaded":s.load,s.load==="loaded"?"ok":"warn"),
      sub:s.sub,
      actions:`${btn("Start","play","btn-ok",`doManageService(${jsArg(s.unit)},"start")`)} ` +
              `${btn("Stop","square","btn-bad",`doManageService(${jsArg(s.unit)},"stop")`)} ` +
              `${btn("Restart","rotate-cw","btn-accent",`doManageService(${jsArg(s.unit)},"restart")`)} ` +
              `${btn("Enable","check-square","btn-accent",`doManageService(${jsArg(s.unit)},"enable")`)} ` +
              `${btn("Disable","x-square","btn-bad",`doManageService(${jsArg(s.unit)},"disable")`)}`
    })),[{key:"unit",label:"Unit"},{key:"load",label:"Load"},{key:"state",label:"Status"},{key:"sub",label:"Sub"},{key:"actions",label:""}])),
    section("Recent Backups",viewError(errors,"/api/backups")+tblHtml(backupRows,[{key:"name",label:"File"},{key:"base",label:"Config"},{key:"time",label:"Date"},{key:"size",label:"Size"},{key:"actions",label:""}]),
      btn("All Backups","rotate-ccw","btn-accent","switchView('backups')")),
    section("Web UI Access",`<div class="metric-grid">
      ${card("Address",sensitive(location.host||"configured host","admin-web-address"))}
      ${card("Agent socket",esc("/var/run/gatebsd/agent.sock"))}
      ${card("Database",esc("/var/db/gatebsd/state.db"))}
      ${card("Backups dir",esc(bk.dir||"/var/db/gatebsd/backups"))}
    </div>`,btn("Sign out","log-out","btn-bad","doLogout()")),
  ].join("");
}

const RENDERERS={overview:renderOverview,diagnostics:renderDiagnostics,wan:renderNetwork,failover:renderFailover,lan:renderLan,adblock:renderAdblock,network:renderNetwork,firewall:renderFirewall,clients:renderClients,dhcp:renderDhcp,amnezia:renderAmnezia,ups:renderUps,system:renderSystem,history:renderHistory,backups:renderBackups,admin:renderAdmin,logs:renderLogs};

async function loadView(isAutoRefresh){
  const el=document.getElementById("content");
  if(isAutoRefresh){
    // Skip refresh if text is selected
    if(window.getSelection && window.getSelection().toString().length > 0) return;
    // Skip refresh if terminal is open
    if(S.view === "admin" && S.term) return;
  }
  
  if(!isAutoRefresh && !S.loaded){
    el.innerHTML=`<p style="color:var(--text2)">Loading…</p>`;
  }
  
  const targetView = S.view;
  try{
    let entries=[],errors={};
    const results=await Promise.allSettled(EP[targetView].map(async p=>[p,await api(p)]));
    results.forEach((result,index)=>{
      const path=EP[targetView][index];
      if(result.status==="fulfilled")entries.push(result.value);
      else{
        errors[path]=result.reason;
        if(S.cache.has(path))entries.push([path,S.cache.get(path)]);
      }
    });
    if (S.view !== targetView) return; // Race condition check
    S.viewErrors=errors;
    const data=Object.fromEntries(entries);
    const newHtml=RENDERERS[targetView](data,errors);
    if(S._lastHtml===newHtml && isAutoRefresh) return;
    S._lastHtml=newHtml;
    
    if(!S._morph){
      S._morph = function(o, n) {
        if (o.nodeType !== n.nodeType || o.nodeName !== n.nodeName) {
          if (o.nodeType === 1 && n.nodeType === 1 && (o.nodeName === "SVG" || o.nodeName === "svg") && n.nodeName === "I") {
            const oLucide = o.getAttribute("data-lucide") || o.dataset?.lucide;
            const nLucide = n.getAttribute("data-lucide") || n.dataset?.lucide;
            if (oLucide && nLucide && oLucide === nLucide) return;
          }
          o.replaceWith(n.cloneNode(true));
          return;
        }
        if (o.nodeType === 3) { if (o.nodeValue !== n.nodeValue) o.nodeValue = n.nodeValue; return; }
        if (o.nodeType === 1) {
            const oa = o.attributes, na = n.attributes;
            for (let i = oa.length - 1; i >= 0; i--) if (!n.hasAttribute(oa[i].name)) o.removeAttribute(oa[i].name);
            for (let i = 0; i < na.length; i++) {
                const nm = na[i].name, vl = na[i].value;
                if(nm==='value' && ['INPUT','TEXTAREA','SELECT'].includes(o.tagName) && document.activeElement===o) continue;
                if(nm==='open' && o.tagName==='DETAILS') continue;
                if (o.getAttribute(nm) !== vl) o.setAttribute(nm, vl);
            }
            if (o.id === "termPlaceholder") return; // Let xterm.js manage it
        }
        const oc = Array.from(o.childNodes), nc = Array.from(n.childNodes);
        for (let i = 0; i < Math.max(oc.length, nc.length); i++) {
            if (!oc[i]) o.appendChild(nc[i].cloneNode(true));
            else if (!nc[i]) {
              if (oc[i].contains && oc[i].contains(document.activeElement)) document.activeElement.blur();
              o.removeChild(oc[i]);
            }
            else S._morph(oc[i], nc[i]);
        }
      };
    }
    
    const scrollTop=el.scrollTop;
    if (isAutoRefresh) {
      const t = document.createElement("div");
      t.innerHTML = newHtml;
      const oc = Array.from(el.childNodes), nc = Array.from(t.childNodes);
      for (let i = 0; i < Math.max(oc.length, nc.length); i++) {
          if (!oc[i]) el.appendChild(nc[i].cloneNode(true));
          else if (!nc[i]) el.removeChild(oc[i]);
          else S._morph(oc[i], nc[i]);
      }
    } else {
      el.innerHTML = newHtml;
    }
    
    if(document.getElementById("termPlaceholder") && !isAutoRefresh){
      mountTerminal();
    }
    
    if(!isAutoRefresh){
      el.style.animation="none";el.offsetHeight;el.style.animation="fadeIn .25s ease";
    }
    el.scrollTop=scrollTop;
    renderIcons(el);
    if(targetView==="overview"){
      const traffic=Object.fromEntries(entries)["/api/stats/traffic"]||{};
      const wan=Object.fromEntries(entries)["/api/wan"]||{};
      const iface=wan.wan?.name||wan.sys?.wan_if||"";
      const counters=traffic.interfaces?.[iface]||{};
      drawTrafficCanvas("trafficCanvas",(counters.rx_rate||0)*8/1000000,(counters.tx_rate||0)*8/1000000);
    }
    S.loaded=true;
  }catch(e){
    if (S.view !== targetView) return;
    if(!isAutoRefresh){
      el.innerHTML=`<p style="color:var(--bad)">${esc(e.message)}</p>`;
    }
    toast(e.message);
  }
}

function switchView(view){
  const previousView=S.view;
  if(previousView==="admin" && view!=="admin") closeTerminalSession();
  S.view=view;
  document.body.dataset.view=view;
  const viewTitle=document.getElementById("viewTitle");
  if(viewTitle)viewTitle.textContent=VIEW_TITLES[view]||view;
  S.loaded=false;
  S._lastHtml="";
  document.querySelectorAll(".sidebar-nav button").forEach(b=>b.classList.toggle("active",b.dataset.view===view));
  if(S.timer)clearInterval(S.timer);
  if(pkgPollInterval){ clearInterval(pkgPollInterval); pkgPollInterval=null; }
  if(vpnLogSocket){ vpnLogSocket.close(); vpnLogSocket=null; }
  loadView(false);
  S.timer=setInterval(()=>loadView(true),REFRESH[view]||15000);
}

function showBridgeEdit(name) {
  const networkConfig = S.cache.get("/api/rcconf") || {};
  const bridge = networkConfig.network?.bridges?.[name] || {};
  const ports = (S.cache.get("/api/interfaces")?.ports || []).map(p=>p.name).filter(p=>p!=='lo'&&!p.startsWith('br-'));
  const bPorts = bridge.interfaces || [];
  const ip = (bridge.addresses || [])[0] || "";
  const stp = bridge.parameters?.stp ?? true;
  const fd = bridge.parameters?.['forward-delay'] ?? 15;
  const mac = bridge.macaddress || "";

  openModal(`Bridge Settings: ${name}`, `
    <div class="form-row" style="margin-bottom:15px;">
      <div class="form-group">
        <label>IP Address (CIDR)</label>
        ${sensitiveHtml(`<input type="text" class="form-input" id="bridge_ip" value="${esc(ip)}">`,`bridge-${name}-ip`)}
      </div>
      <div class="form-group">
        <label title="Bridge MAC address (leave blank for auto)">MAC Address ❔</label>
        ${sensitiveHtml(`<input type="text" class="form-input" id="bridge_mac" value="${esc(mac)}" placeholder="00:11:22:33:44:55">`,`bridge-${name}-mac`)}
      </div>
    </div>
    <div class="form-group" style="margin-bottom:15px;">
      <label>Member Ports</label>
      <div style="background:var(--bg2); padding:10px; border-radius:6px; display:flex; flex-direction:column; gap:8px; max-height:150px; overflow-y:auto;">
        ${ports.map(p=>`<label style="display:flex; align-items:center; cursor:pointer;"><input type="checkbox" name="bridge_ports" value="${esc(p)}" class="form-checkbox" style="margin-right:8px;" ${bPorts.includes(p)?'checked':''}>${esc(p)}</label>`).join('')}
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label title="Spanning Tree Protocol prevents network loops when switches are connected.">Enable STP ❔</label>
        <select class="form-input" id="bridge_stp">
          <option value="true" ${stp?'selected':''}>Yes (Recommended)</option>
          <option value="false" ${!stp?'selected':''}>No</option>
        </select>
      </div>
      <div class="form-group">
        <label title="Forwarding delay when STP is enabled (default 15s)">Forward Delay ❔</label>
        <input type="number" class="form-input" id="bridge_fd" value="${fd}" min="0">
      </div>
    </div>
    <div style="margin-top:20px; display:flex; gap:10px;">
      ${btn("Save", "save", "btn-ok", `doSaveBridge(${jsArg(name)})`)}
    </div>
  `);
}

async function doSaveBridge(name) {
  const ip = document.getElementById('bridge_ip').value;
  const mac = document.getElementById('bridge_mac').value;
  const stp = document.getElementById('bridge_stp').value === 'true';
  const fd = parseInt(document.getElementById('bridge_fd').value || "15", 10);
  const ports = Array.from(document.querySelectorAll('input[name="bridge_ports"]:checked')).map(cb => cb.value);

  const networkConfig = JSON.parse(JSON.stringify(S.cache.get("/api/rcconf") || {}));
  if(!networkConfig.network) networkConfig.network = {version:2, renderer:"rc.conf", ethernets:{}, bridges:{}};
  if(!networkConfig.network.bridges) networkConfig.network.bridges = {};
  if(!networkConfig.network.ethernets) networkConfig.network.ethernets = {};
  
  ports.forEach(p => {
    if(!networkConfig.network.ethernets[p]) networkConfig.network.ethernets[p] = {};
    networkConfig.network.ethernets[p].dhcp4 = false;
  });

  networkConfig.network.bridges[name] = {
    interfaces: ports,
    parameters: { stp, "forward-delay": fd }
  };
  if(ip) networkConfig.network.bridges[name].addresses = [ip];
  if(mac) networkConfig.network.bridges[name].macaddress = mac;

  openModal("Applying Settings", "Restarting network interfaces. Please wait...");
  try {
    await post("/api/rcconf", networkConfig);
    closeModal();
    toast("Bridge settings applied", "success");
    await loadView(false);
  } catch(e) {
    closeModal();
    toast(e.message, "error");
  }
}

async function doSystemPower(action){
  const labels={reboot:"reboot",poweroff:"power off"};
  if(!await confirmModal(`Do you want to ${labels[action]} the gateway?`, "Power", action==="poweroff"))return;
  try{
    await post("/api/system/power",{action});
    toast(`Command ${action} sent`,"success");
    if(action==="reboot") setTimeout(()=>location.reload(), 15000);
  }catch(e){toast(e.message)}
}

function openPasswordModal() {
  openModal(
    "Change Password",
    `
      <div class="form-group" style="margin-bottom:12px">
        <label style="display:block;margin-bottom:6px;font-size:12px;color:var(--text-secondary)">Current Password</label>
        <input class="form-input" id="currentPass" type="password" placeholder="Enter current password" style="width:100%">
      </div>
      <div class="form-group" style="margin-bottom:12px">
        <label style="display:block;margin-bottom:6px;font-size:12px;color:var(--text-secondary)">New Password</label>
        <input class="form-input" id="newPass1" type="password" placeholder="At least 8 characters" style="width:100%">
      </div>
      <div class="form-group" style="margin-bottom:12px">
        <label style="display:block;margin-bottom:6px;font-size:12px;color:var(--text-secondary)">Repeat New Password</label>
        <input class="form-input" id="newPass2" type="password" placeholder="Repeat password" style="width:100%">
      </div>
      <div id="newPassError" style="color:var(--bad);font-size:12px;margin-top:8px;display:none;"></div>
    `,
    `
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn btn-accent" id="savePassBtn" onclick="submitPasswordChange()">Save</button>
    `
  );
}
window.openPasswordModal = openPasswordModal;

async function submitPasswordChange() {
  const currentPass = document.getElementById("currentPass").value;
  const p1 = document.getElementById("newPass1").value;
  const p2 = document.getElementById("newPass2").value;
  const err = document.getElementById("newPassError");
  const saveBtn = document.getElementById("savePassBtn");
  if(!currentPass) {
    err.textContent = "Enter current password";
    err.style.display = "block";
    return;
  }
  if(!p1 || p1.length < 8) {
    err.textContent = "Password must be at least 8 characters";
    err.style.display = "block";
    return;
  }
  if(p1 !== p2) {
    err.textContent = "Passwords do not match";
    err.style.display = "block";
    return;
  }
  err.style.display = "none";
  saveBtn.disabled = true;
  saveBtn.textContent = "Saving...";
  try {
    const res = await post("/api/auth/password", { current_password: currentPass, password: p1 });
    if(res.ok || res.status === 200) {
      toast("Password updated", "success");
      closeModal();
    } else {
      err.textContent = res.error || "Failed to change password";
      err.style.display = "block";
    }
  } catch (e) {
    err.textContent = e.message || "Connection error";
    err.style.display = "block";
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = "Save";
  }
}
window.submitPasswordChange = submitPasswordChange;

/* ═══ Boot ═══ */
async function boot(afterLogin=false){
  if(!S.booted){
    document.getElementById("sidebarNav").addEventListener("click",e=>{
      const b=e.target.closest("button[data-view]");if(b)switchView(b.dataset.view)
    });
    document.getElementById("logoutBtn").addEventListener("click",doLogout);
    document.getElementById("menuToggle").addEventListener("click",()=>document.getElementById("sidebar").classList.toggle("open"));
    document.getElementById("modalClose").addEventListener("click",closeModal);
    document.getElementById("modalOverlay").addEventListener("click",e=>{if(e.target===e.currentTarget)closeModal()});
    document.addEventListener("keydown",e=>{
      if(e.key==="Escape")closeModal();
      const btns=[...document.querySelectorAll(".sidebar-nav button")];
      const idx=btns.findIndex(b=>b.classList.contains("active"));
      if(e.key==="ArrowDown"&&idx<btns.length-1){e.preventDefault();switchView(btns[idx+1].dataset.view)}
      if(e.key==="ArrowUp"&&idx>0){e.preventDefault();switchView(btns[idx-1].dataset.view)}
    });
    document.addEventListener("toggle", e => {
      if(e.target.tagName === "DETAILS" && e.target.classList.contains("section")) {
        S.sections[e.target.dataset.section] = e.target.open;
        const arrow = e.target.querySelector('.section-arrow');
        if(arrow) arrow.style.transform = e.target.open ? '' : 'rotate(-90deg)';
      }
    }, true);
    document.getElementById("modeToggleSimple")?.addEventListener("click", () => setUiMode("simple"));
    document.getElementById("modeToggleAdvanced")?.addEventListener("click", () => setUiMode("advanced"));

    // Dropdown listeners
    const notifBtn = document.getElementById("notificationBtn");
    const notifDropdown = document.getElementById("notificationDropdown");
    const userMenuBtn = document.getElementById("userMenuBtn");
    const userDropdown = document.getElementById("userDropdown");

    function closeAllDropdowns() {
      if(notifDropdown) notifDropdown.classList.remove("active");
      if(userDropdown) userDropdown.classList.remove("active");
    }

    if(notifBtn && notifDropdown) {
      notifBtn.addEventListener("click", e => {
        e.stopPropagation();
        const isActive = notifDropdown.classList.contains("active");
        closeAllDropdowns();
        if(!isActive) {
          const list = S.warnings || [];
          let html = '<div class="dropdown-header">Warnings</div>';
          if(list.length === 0) {
            html += '<div class="dropdown-empty"><i data-lucide="check-circle" style="width:16px;height:16px;color:var(--ok);margin-bottom:4px;display:block;margin:0 auto 4px auto"></i>No warnings</div>';
          } else {
            list.forEach(w => {
              html += `
                <div class="notification-item ${w.level}" onclick="switchView('overview')">
                  <div class="notif-title">${esc(w.msg)}</div>
                  <div class="notif-desc">System state</div>
                </div>
              `;
            });
          }
          notifDropdown.innerHTML = html;
          notifDropdown.classList.add("active");
          renderIcons();
        }
      });
    }

    if(userMenuBtn && userDropdown) {
      userMenuBtn.addEventListener("click", e => {
        e.stopPropagation();
        const isActive = userDropdown.classList.contains("active");
        closeAllDropdowns();
        if(!isActive) {
          userDropdown.classList.add("active");
        }
      });
    }

    document.addEventListener("click", closeAllDropdowns);

    document.getElementById("changePasswordBtn")?.addEventListener("click", e => {
      e.stopPropagation();
      closeAllDropdowns();
      openPasswordModal();
    });

    document.getElementById("logoutDropdownBtn")?.addEventListener("click", e => {
      e.stopPropagation();
      closeAllDropdowns();
      doLogout();
    });

    setUiMode(localStorage.getItem("amnezia_ui_mode") || "simple");
    S.booted=true;
  }
  if(!afterLogin){
    try{
      const auth=await authStatus();
      if(!auth.authenticated){showLogin();return}
    }catch(e){showLogin();return}
  }
  try{S.overview=await api("/api/overview");renderSummary()}catch(e){document.getElementById("summary").innerHTML=`<p style="color:var(--bad)">${esc(e.message)}</p>`}
  switchView("overview");
  if(!S.summaryTimer)S.summaryTimer=setInterval(async()=>{try{S.overview=await api("/api/overview");renderSummary()}catch(e){console.error(e)}},15000);
}
boot().then(() => renderIcons());

// Lucide icons are now rendered deterministically via renderIcons()

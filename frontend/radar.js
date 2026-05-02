'use strict';

// ─── Constants ───────────────────────────────────────────────────────────────
const GREEN   = '#00ff41';
const CYAN    = '#00d4ff';
const YELLOW  = '#ffd700';
const RED     = '#ff2020';

const NODE_R    = 14;
const REPULSION = 8000;
const SPRING_K  = 0.04;
const REST_LEN  = 160;
const DAMPING   = 0.85;
const GRAVITY   = 0.008;
const SWEEP_SPD = 0.012;

// ─── State ───────────────────────────────────────────────────────────────────
const devices  = new Map();   // ip → device
const nodes    = new Map();   // ip → node
let   sweepAngle  = 0;
let   selectedIP  = null;
let   scanning    = false;
let   frameCount  = 0;
let   drag        = null;
let   mitmActive   = false;
let   soundEnabled = true;
let   audioCtx     = null;

// ─── Filter state ─────────────────────────────────────────────────────────────
let nodeFilter   = 'ALL';
let vendorFilter = '';

// ─── Bandwidth history ────────────────────────────────────────────────────────
const bwHistory = [];   // ring buffer, max 60 entries of {in: float, out: float}
const BW_MAX    = 60;

// ─── Canvas ───────────────────────────────────────────────────────────────────
const canvas = document.getElementById('radar');
const ctx    = canvas.getContext('2d');

function resize() {
  canvas.width  = canvas.offsetWidth;
  canvas.height = canvas.offsetHeight;
}
window.addEventListener('resize', resize);
resize();

// ─── Clock ────────────────────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toTimeString().slice(0, 8);
}, 500);

// ─── Audio ────────────────────────────────────────────────────────────────────
function getAudioCtx() {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  return audioCtx;
}

function playBeep(freq, duration, type) {
  if (!soundEnabled) return;
  freq     = freq     || 880;
  duration = duration || 0.15;
  type     = type     || 'sine';
  try {
    const ac   = getAudioCtx();
    const osc  = ac.createOscillator();
    const gain = ac.createGain();
    osc.connect(gain);
    gain.connect(ac.destination);
    osc.frequency.value = freq;
    osc.type = type;
    gain.gain.setValueAtTime(0.25, ac.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ac.currentTime + duration);
    osc.start(ac.currentTime);
    osc.stop(ac.currentTime + duration);
  } catch (_) {}
}

// ─── Toast notifications ──────────────────────────────────────────────────────
function showToast(level, message) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast toast-' + level;
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => toast.classList.add('show'));
  });
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 400);
  }, 4500);
}

// ─── WebSocket ────────────────────────────────────────────────────────────────
function connect() {
  const ws = new WebSocket('ws://' + location.host + '/ws');

  ws.onopen = () => {
    document.getElementById('scan-status').textContent = 'CONNECTED';
  };

  ws.onclose = () => {
    document.getElementById('scan-status').textContent = 'RECONNECTING...';
    setTimeout(connect, 2000);
  };

  ws.onmessage = (e) => {
    handleEvent(JSON.parse(e.data));
  };
}

function handleEvent(ev) {
  switch (ev.type) {
    case 'full_state':
      (ev.devices || []).forEach(addOrUpdate);
      loadTrafficHistory(ev.traffics);
      if (ev.mitm_on != null) updateMITMState(ev.mitm_on);
      break;

    case 'device_found':
      addOrUpdate(ev.device);
      flash(ev.device.ip, GREEN);
      playBeep(880, 0.15, 'sine');
      break;

    case 'device_updated':
      addOrUpdate(ev.device);
      break;

    case 'device_lost':
      if (devices.has(ev.device.ip)) {
        const d = devices.get(ev.device.ip);
        d.active = false;
        devices.set(ev.device.ip, d);
      }
      break;

    case 'scan_start':
      scanning = true;
      document.getElementById('scan-status').textContent = 'SCANNING...';
      document.getElementById('scan-status').classList.add('pulse-text');
      break;

    case 'scan_end':
      scanning = false;
      document.getElementById('scan-status').textContent = 'IDLE';
      document.getElementById('scan-status').classList.remove('pulse-text');
      updateCount();
      break;

    case 'traffic':
      if (ev.traffic) addTrafficEvent(ev.traffic);
      break;

    case 'bandwidth':
      if (ev.bandwidth) applyBandwidth(ev.bandwidth);
      break;

    case 'alert':
      if (ev.alert) showToast(ev.alert.level || 'info', ev.alert.message);
      break;

    case 'mitm_status':
      if (ev.mitm_on != null) updateMITMState(ev.mitm_on);
      break;

    case 'probe_device':
      if (ev.alert) {
        showToast('warning', ev.alert.message);
        playBeep(440, 0.25, 'square');
      }
      break;

    case 'passive_os':
      if (ev.os_hints) {
        for (const hint of ev.os_hints) {
          if (devices.has(hint.ip)) {
            const d = devices.get(hint.ip);
            d.os = hint.os;
            devices.set(hint.ip, d);
            if (selectedIP === hint.ip) renderDossier(d);
          }
        }
      }
      break;
  }
}

// ─── MITM ─────────────────────────────────────────────────────────────────────
function updateMITMState(active) {
  mitmActive = active;
  const btn   = document.getElementById('mitm-btn');
  const state = document.getElementById('mitm-state');
  if (active) {
    btn.classList.add('active');
    state.textContent = 'ON';
  } else {
    btn.classList.remove('active');
    state.textContent = 'OFF';
  }
}

function toggleMITM() {
  const endpoint = mitmActive ? '/api/mitm/off' : '/api/mitm/on';
  fetch(endpoint, { method: 'POST' })
    .catch((e) => showToast('danger', 'MITM error: ' + e.message));
}

// ─── Export ───────────────────────────────────────────────────────────────────
function exportData() {
  fetch('/api/export')
    .then((r) => r.blob())
    .then((blob) => {
      const url = URL.createObjectURL(blob);
      const a   = document.createElement('a');
      a.href     = url;
      a.download = 'lan-radar-' + Date.now() + '.json';
      a.click();
      URL.revokeObjectURL(url);
    })
    .catch((e) => showToast('danger', 'Export failed: ' + e.message));
}

// ─── Bandwidth ────────────────────────────────────────────────────────────────
function applyBandwidth(stats) {
  let totalIn  = 0;
  let totalOut = 0;

  for (const stat of stats) {
    totalIn  += stat.rate_in  || 0;
    totalOut += stat.rate_out || 0;
    if (devices.has(stat.ip)) {
      const d = devices.get(stat.ip);
      d.rate_in  = stat.rate_in;
      d.rate_out = stat.rate_out;
      if (selectedIP === stat.ip) renderDossier(d);
    }
  }

  bwHistory.push({ in: totalIn, out: totalOut });
  if (bwHistory.length > BW_MAX) bwHistory.shift();
}

function formatBW(bps) {
  if (!bps || bps === 0) return '—';
  if (bps < 1024)         return bps.toFixed(0) + ' B/s';
  if (bps < 1024 * 1024)  return (bps / 1024).toFixed(1) + ' KB/s';
  return (bps / (1024 * 1024)).toFixed(2) + ' MB/s';
}

// ─── Device management ────────────────────────────────────────────────────────
function addOrUpdate(dev) {
  devices.set(dev.ip, dev);
  if (!nodes.has(dev.ip)) {
    const cx    = canvas.width  / 2;
    const cy    = canvas.height / 2;
    const angle = Math.random() * Math.PI * 2;
    const dist  = dev.is_gateway ? 0 : 80 + Math.random() * 200;
    nodes.set(dev.ip, {
      x: cx + Math.cos(angle) * dist,
      y: cy + Math.sin(angle) * dist,
      vx: 0, vy: 0,
      revealed:   false,
      flashT:     0,
      flashColor: GREEN,
      pinned:     dev.is_gateway,
      userPinned: false,
      pulseOff:   Math.random() * Math.PI * 2,
    });
  }
  if (selectedIP === dev.ip) renderDossier(dev);
}

function updateCount() {
  let n = 0;
  devices.forEach((d) => { if (d.active) n++; });
  document.getElementById('count').textContent = n;
}

// ─── Flash ────────────────────────────────────────────────────────────────────
const flashes = new Map();
function flash(ip, color) { flashes.set(ip, { color, t: 1.0 }); }

// ─── Vendor prefix helper ─────────────────────────────────────────────────────
function vendorPrefix(ip) {
  const dev = devices.get(ip);
  return (dev && dev.mac) ? dev.mac.slice(0, 8) : '';
}

// ─── Physics ──────────────────────────────────────────────────────────────────
function applyForces() {
  const ips = [...nodes.keys()];
  const cx  = canvas.width  / 2;
  const cy  = canvas.height / 2;

  // O(n²) repulsion
  for (let i = 0; i < ips.length; i++) {
    for (let j = i + 1; j < ips.length; j++) {
      const a  = nodes.get(ips[i]);
      const b  = nodes.get(ips[j]);
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d2 = dx * dx + dy * dy + 1;
      const d  = Math.sqrt(d2);
      const f  = REPULSION / d2;
      if (!a.pinned && !a.userPinned && !a.dragging) { a.vx -= f * dx / d; a.vy -= f * dy / d; }
      if (!b.pinned && !b.userPinned && !b.dragging) { b.vx += f * dx / d; b.vy += f * dy / d; }
    }
  }

  // Spring toward gateway
  const gwNode = findGatewayNode();
  if (gwNode) {
    for (const [, n] of nodes) {
      if (n.pinned || n.userPinned || n.dragging) continue;
      const dx = gwNode.x - n.x;
      const dy = gwNode.y - n.y;
      const d  = Math.sqrt(dx * dx + dy * dy) + 0.1;
      const f  = SPRING_K * (d - REST_LEN);
      n.vx += f * dx / d;
      n.vy += f * dy / d;
    }
  }

  // Vendor affinity: weak attraction between nodes sharing vendor prefix
  for (let i = 0; i < ips.length; i++) {
    for (let j = i + 1; j < ips.length; j++) {
      const vpI = vendorPrefix(ips[i]);
      const vpJ = vendorPrefix(ips[j]);
      if (!vpI || vpI !== vpJ) continue;
      const a  = nodes.get(ips[i]);
      const b  = nodes.get(ips[j]);
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d2 = dx * dx + dy * dy + 1;
      const d  = Math.sqrt(d2);
      const f  = 1 / (d2 / 1500);  // attractive only, strength ~1500
      if (!a.pinned && !a.userPinned && !a.dragging) { a.vx += f * dx / d; a.vy += f * dy / d; }
      if (!b.pinned && !b.userPinned && !b.dragging) { b.vx -= f * dx / d; b.vy -= f * dy / d; }
    }
  }

  // Center gravity
  for (const [, n] of nodes) {
    if (n.pinned || n.userPinned || n.dragging) continue;
    n.vx += GRAVITY * (cx - n.x);
    n.vy += GRAVITY * (cy - n.y);
  }

  // Integrate
  for (const [, n] of nodes) {
    if (n.dragging) continue;
    if (n.pinned)       { n.x = cx; n.y = cy; continue; }
    if (n.userPinned)   { n.vx = 0; n.vy = 0; continue; }
    n.x  += n.vx;
    n.y  += n.vy;
    n.vx *= DAMPING;
    n.vy *= DAMPING;
    const pad = NODE_R + 20;
    n.x = Math.max(pad, Math.min(canvas.width  - pad, n.x));
    n.y = Math.max(pad, Math.min(canvas.height - pad, n.y));
  }
}

function findGatewayNode() {
  for (const [ip, dev] of devices) {
    if (dev.is_gateway) return nodes.get(ip);
  }
  return null;
}

// ─── Visibility filter ────────────────────────────────────────────────────────
function isVisible(ip) {
  const dev = devices.get(ip);
  if (!dev) return false;
  if (vendorFilter) {
    const v = (dev.vendor || '').toLowerCase();
    if (!v.includes(vendorFilter.toLowerCase())) return false;
  }
  switch (nodeFilter) {
    case 'ACTIVE': return !!dev.active;
    case 'PORTS':  return !!(dev.open_ports && dev.open_ports.length > 0);
    case 'THREAT': return !!dev.threat;
  }
  return true;
}

// ─── Sonar sweep ──────────────────────────────────────────────────────────────
function drawSweep() {
  const cx = canvas.width  / 2;
  const cy = canvas.height / 2;
  const R  = Math.max(cx, cy) * 1.5;

  const sweep = 0.8;
  for (let i = 0; i < 32; i++) {
    const a     = sweepAngle - (sweep * i / 32);
    const a1    = sweepAngle - (sweep * (i + 1) / 32);
    const alpha = (1 - i / 32) * 0.07;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, R, a1, a, false);
    ctx.closePath();
    ctx.fillStyle = 'rgba(0,255,65,' + alpha + ')';
    ctx.fill();
  }

  ctx.save();
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(sweepAngle) * R, cy + Math.sin(sweepAngle) * R);
  const grad = ctx.createLinearGradient(
    cx, cy,
    cx + Math.cos(sweepAngle) * R,
    cy + Math.sin(sweepAngle) * R
  );
  grad.addColorStop(0,   'rgba(0,255,65,0.9)');
  grad.addColorStop(0.5, 'rgba(0,255,65,0.4)');
  grad.addColorStop(1,   'rgba(0,255,65,0)');
  ctx.strokeStyle = grad;
  ctx.lineWidth   = 2;
  ctx.shadowBlur  = 12;
  ctx.shadowColor = GREEN;
  ctx.stroke();
  ctx.restore();

  sweepAngle = (sweepAngle + SWEEP_SPD) % (Math.PI * 2);
}

// ─── Grid ─────────────────────────────────────────────────────────────────────
function drawGrid() {
  const cx   = canvas.width  / 2;
  const cy   = canvas.height / 2;
  const maxR = Math.sqrt(cx * cx + cy * cy);

  ctx.save();
  ctx.strokeStyle = 'rgba(0,255,65,0.08)';
  ctx.lineWidth   = 1;
  for (let r = 80; r < maxR; r += 80) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.stroke();
  }
  ctx.beginPath();
  ctx.moveTo(0, cy);   ctx.lineTo(canvas.width, cy);
  ctx.moveTo(cx, 0);   ctx.lineTo(cx, canvas.height);
  ctx.stroke();
  ctx.restore();
}

// ─── Edges ────────────────────────────────────────────────────────────────────
function drawEdges() {
  const gwNode = findGatewayNode();
  if (!gwNode) return;
  const t = Date.now() * 0.001;

  for (const [ip, n] of nodes) {
    if (!isVisible(ip)) continue;
    const dev = devices.get(ip);
    if (!dev || !dev.active || dev.is_gateway) continue;

    // Traffic heatmap: scale lineWidth and opacity by rate
    const rate     = (dev.rate_in || 0) + (dev.rate_out || 0);
    const MAX_RATE = 2 * 1024 * 1024; // 2 MB/s
    const rateT    = Math.min(rate / MAX_RATE, 1);
    const lw       = 1 + 4 * rateT;
    const alpha    = 0.12 + 0.5 * rateT;

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(gwNode.x, gwNode.y);
    ctx.lineTo(n.x, n.y);
    ctx.strokeStyle = 'rgba(0,212,255,' + alpha + ')';
    ctx.lineWidth   = lw;
    if (rateT > 0.1) {
      ctx.shadowBlur  = 6 * rateT;
      ctx.shadowColor = CYAN;
    }
    ctx.stroke();

    // Animated packet dot
    const pT = ((t * 0.4 + hashIP(ip) * 0.7) % 1);
    const px  = gwNode.x + (n.x - gwNode.x) * pT;
    const py  = gwNode.y + (n.y - gwNode.y) * pT;
    ctx.beginPath();
    ctx.arc(px, py, 2.5, 0, Math.PI * 2);
    ctx.fillStyle   = CYAN;
    ctx.shadowBlur  = 8;
    ctx.shadowColor = CYAN;
    ctx.fill();
    ctx.restore();
  }
}

function hashIP(ip) {
  let h = 0;
  for (const c of ip) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  return h / 0xffff;
}

// ─── Nodes ────────────────────────────────────────────────────────────────────
function nodeColor(dev) {
  if (!dev.active)                              return '#333';
  if (dev.is_gateway)                           return YELLOW;
  if (dev.threat)                               return RED;
  if (dev.open_ports && dev.open_ports.length)  return CYAN;
  return GREEN;
}

function drawNodes() {
  const now = Date.now();

  for (const [ip, n] of nodes) {
    if (!isVisible(ip)) continue;
    const dev = devices.get(ip);
    if (!dev) continue;

    const color  = nodeColor(dev);
    const pulse  = dev.active
      ? 1 + 0.12 * Math.sin(now * 0.003 + n.pulseOff)
      : 1;
    const radius = NODE_R * pulse;

    ctx.save();

    // Bandwidth ring
    if (dev.active) {
      const rate      = (dev.rate_in || 0) + (dev.rate_out || 0);
      const maxRate   = 512 * 1024; // 512 KB/s = full ring
      const intensity = Math.min(rate / maxRate, 1);
      if (intensity > 0.005) {
        const ringR = radius + 5 + 12 * intensity;
        ctx.beginPath();
        ctx.arc(n.x, n.y, ringR, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(0,212,255,' + (0.2 + 0.6 * intensity) + ')';
        ctx.lineWidth   = 1 + 2.5 * intensity;
        ctx.shadowBlur  = 12 * intensity;
        ctx.shadowColor = CYAN;
        ctx.stroke();
      }
    }

    // Flash ring
    if (flashes.has(ip)) {
      const fl = flashes.get(ip);
      ctx.beginPath();
      ctx.arc(n.x, n.y, radius + 20 * (1 - fl.t), 0, Math.PI * 2);
      ctx.strokeStyle = fl.color + Math.floor(fl.t * 255).toString(16).padStart(2, '0');
      ctx.lineWidth   = 2;
      ctx.stroke();
      fl.t -= 0.03;
      if (fl.t <= 0) flashes.delete(ip);
    }

    // Glow
    if (dev.active) {
      ctx.shadowBlur  = dev.threat ? 30 : 20;
      ctx.shadowColor = color;
    }

    // Fill
    ctx.beginPath();
    ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = color + '22';
    ctx.fill();

    // Border
    ctx.beginPath();
    ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
    ctx.strokeStyle = color;
    ctx.lineWidth   = n.dragging ? 3 : (selectedIP === ip ? 2.5 : 1.5);
    if (n.dragging) { ctx.shadowBlur = 35; ctx.shadowColor = color; }
    ctx.stroke();

    // Center dot
    ctx.beginPath();
    ctx.arc(n.x, n.y, 3, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();

    ctx.restore();

    // Labels
    ctx.save();
    ctx.font      = '10px "Courier New"';
    ctx.fillStyle = dev.active ? color : '#555';
    const displayLabel = dev.label || dev.hostname || dev.ip;
    ctx.fillText(displayLabel, n.x + radius + 6, n.y + 3);
    ctx.font      = '9px "Courier New"';
    ctx.fillStyle = dev.active ? 'rgba(0,255,65,0.5)' : '#333';
    ctx.fillText(dev.ip, n.x + radius + 6, n.y + 14);
    if (dev.vendor && dev.vendor !== 'Unknown') {
      ctx.fillStyle = 'rgba(0,212,255,0.5)';
      ctx.fillText(dev.vendor, n.x + radius + 6, n.y + 24);
    }
    ctx.restore();

    // User-pinned indicator: small diamond above node
    if (n.userPinned) {
      ctx.save();
      ctx.font      = '10px "Courier New"';
      ctx.fillStyle = YELLOW;
      ctx.textAlign = 'center';
      ctx.fillText('◆', n.x, n.y - radius - 6);
      ctx.restore();
    }
  }
}

// ─── Bandwidth chart ──────────────────────────────────────────────────────────
function drawBWChart() {
  if (bwHistory.length === 0) return;

  const W      = 200;
  const H      = 50;
  const GAP    = 2;
  const x0     = canvas.width  - W - GAP;
  const y0     = canvas.height - H - GAP;
  const BAR_W  = W / BW_MAX;

  // Find peak for scaling
  let peak = 0;
  for (const s of bwHistory) {
    const tot = (s.in || 0) + (s.out || 0);
    if (tot > peak) peak = tot;
  }
  if (peak === 0) peak = 1024; // avoid division by zero

  ctx.save();

  // Background
  ctx.fillStyle = 'rgba(0,0,0,0.7)';
  ctx.fillRect(x0, y0, W, H);

  // Label
  ctx.font      = '8px "Courier New"';
  ctx.fillStyle = 'rgba(0,255,65,0.5)';
  ctx.fillText('BW/60s', x0 + 3, y0 + 9);

  // Bars
  for (let i = 0; i < bwHistory.length; i++) {
    const s     = bwHistory[i];
    const bxL   = x0 + i * BAR_W;
    const inH   = ((s.in  || 0) / peak) * (H - 12);
    const outH  = ((s.out || 0) / peak) * (H - 12);
    const stackH = Math.min(inH + outH, H - 12);

    // in (green) — bottom portion
    if (inH > 0) {
      ctx.fillStyle = 'rgba(0,255,65,0.7)';
      ctx.fillRect(bxL, y0 + H - inH, BAR_W - 0.5, inH);
    }
    // out (yellow) — on top of in
    if (outH > 0) {
      ctx.fillStyle = 'rgba(255,215,0,0.6)';
      ctx.fillRect(bxL, y0 + H - stackH, BAR_W - 0.5, outH);
    }
  }

  // Border
  ctx.strokeStyle = 'rgba(0,255,65,0.2)';
  ctx.lineWidth   = 1;
  ctx.strokeRect(x0, y0, W, H);

  ctx.restore();
}

// ─── Sparkline ────────────────────────────────────────────────────────────────
function drawSparkline(canvas2d, history) {
  const sc  = canvas2d.getContext('2d');
  const W   = canvas2d.width;
  const H   = canvas2d.height;
  sc.clearRect(0, 0, W, H);

  if (!history || history.length === 0) return;

  // Scale: max of history or 200ms ceiling
  let maxVal = 200;
  for (const v of history) {
    if (v > 0 && v > maxVal) maxVal = v;
  }

  const barW   = Math.max(1, Math.floor(W / history.length));
  const usableH = H - 2;

  for (let i = 0; i < history.length; i++) {
    const v   = history[i];
    const bx  = i * barW;
    if (v < 0) {
      // timeout — gray bar
      sc.fillStyle = 'rgba(100,100,100,0.8)';
      sc.fillRect(bx, 2, barW - 1, usableH);
    } else {
      const bh  = Math.max(2, (v / maxVal) * usableH);
      sc.fillStyle = 'rgba(0,255,65,0.85)';
      sc.fillRect(bx, H - bh, barW - 1, bh);
    }
  }
}

// ─── Main loop ────────────────────────────────────────────────────────────────
function frame() {
  requestAnimationFrame(frame);
  frameCount++;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const bg = ctx.createRadialGradient(
    canvas.width / 2, canvas.height / 2, 0,
    canvas.width / 2, canvas.height / 2, Math.max(canvas.width, canvas.height) / 2
  );
  bg.addColorStop(0, '#080f08');
  bg.addColorStop(1, '#050a05');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  drawGrid();
  drawSweep();
  applyForces();
  drawEdges();
  drawNodes();
  drawBWChart();
}

requestAnimationFrame(frame);

// ─── Drag & Click ─────────────────────────────────────────────────────────────
function canvasMouse(e) {
  const rect = canvas.getBoundingClientRect();
  return { mx: e.clientX - rect.left, my: e.clientY - rect.top };
}

function hitTest(mx, my) {
  let hit = null, minD = Infinity;
  for (const [ip, n] of nodes) {
    if (!isVisible(ip)) continue;
    const dx = mx - n.x, dy = my - n.y;
    const d  = Math.sqrt(dx * dx + dy * dy);
    if (d < NODE_R + 8 && d < minD) { minD = d; hit = ip; }
  }
  return hit;
}

canvas.addEventListener('mousedown', (e) => {
  if (e.button !== 0) return;
  const { mx, my } = canvasMouse(e);
  const hit = hitTest(mx, my);
  if (!hit) return;
  e.preventDefault();
  const n = nodes.get(hit);
  n.dragging = true;
  n.vx = 0; n.vy = 0;
  drag = { ip: hit, startX: mx, startY: my, moved: false };
  canvas.style.cursor = 'grabbing';
});

canvas.addEventListener('mousemove', (e) => {
  const { mx, my } = canvasMouse(e);
  if (drag) {
    const n = nodes.get(drag.ip);
    if (n) {
      n.x = mx; n.y = my;
      n.vx = 0; n.vy = 0;
      const dx = mx - drag.startX, dy = my - drag.startY;
      if (Math.sqrt(dx * dx + dy * dy) > 5) drag.moved = true;
    }
    canvas.style.cursor = 'grabbing';
    return;
  }
  canvas.style.cursor = hitTest(mx, my) ? 'grab' : 'crosshair';
});

canvas.addEventListener('mouseup', (e) => {
  if (!drag) return;
  const n = nodes.get(drag.ip);
  if (n) { n.dragging = false; n.vx = 0; n.vy = 0; }
  if (!drag.moved) {
    selectedIP = drag.ip;
    renderDossier(devices.get(drag.ip));
  }
  drag = null;
  canvas.style.cursor = 'crosshair';
});

canvas.addEventListener('mouseleave', () => {
  if (drag) {
    const n = nodes.get(drag.ip);
    if (n) n.dragging = false;
    drag = null;
  }
  canvas.style.cursor = 'crosshair';
});

canvas.addEventListener('click', (e) => {
  const { mx, my } = canvasMouse(e);
  if (!hitTest(mx, my)) {
    selectedIP = null;
    closeDossier();
  }
});

// ─── Right-click: pin/unpin node ──────────────────────────────────────────────
canvas.addEventListener('contextmenu', (e) => {
  e.preventDefault();
  const { mx, my } = canvasMouse(e);
  const hit = hitTest(mx, my);
  if (!hit) return;
  const dev = devices.get(hit);
  if (!dev || dev.is_gateway) return;  // gateway is always pinned by physics
  const n = nodes.get(hit);
  n.userPinned = !n.userPinned;
  if (n.userPinned) {
    n.vx = 0;
    n.vy = 0;
    showToast('info', hit + ' PINNED');
  } else {
    showToast('info', hit + ' UNPINNED');
  }
});

// ─── Dossier ──────────────────────────────────────────────────────────────────
function renderDossier(dev) {
  if (!dev) return;
  document.getElementById('dossier').classList.remove('hidden');

  set('d-ip',       dev.ip       || '—');
  set('d-mac',      dev.mac      || '—');
  set('d-vendor',   dev.vendor   || '—');
  set('d-hostname', dev.hostname || '—');
  set('d-os',       dev.os       || '—');
  set('d-ttl',      dev.ttl ? String(dev.ttl) : '—');

  // Country with emoji flag
  const flag = dev.country_code ? emojiFlag(dev.country_code) : '';
  set('d-country', flag ? flag + ' ' + (dev.country || dev.country_code) : (dev.country || '—'));

  // Bandwidth
  set('d-bw-in',  '↓ ' + formatBW(dev.rate_in));
  set('d-bw-out', '↑ ' + formatBW(dev.rate_out));

  const statusEl = document.getElementById('d-status');
  statusEl.textContent = dev.active ? '● ONLINE' : '○ OFFLINE';
  statusEl.style.color  = dev.active ? GREEN : '#555';

  set('d-first', formatTime(dev.first_seen));
  set('d-last',  formatTime(dev.last_seen));

  // Sparkline
  const sparkCanvas = document.getElementById('spark-canvas');
  if (dev.ping_history && dev.ping_history.length > 0) {
    sparkCanvas.parentElement.style.display = '';
    drawSparkline(sparkCanvas, dev.ping_history);
  } else {
    sparkCanvas.parentElement.style.display = 'none';
  }

  // Open ports
  const portsEl = document.getElementById('d-ports');
  portsEl.innerHTML = '';
  if (dev.open_ports && dev.open_ports.length > 0) {
    for (const svc of dev.open_ports) {
      const tag = document.createElement('span');
      tag.className   = 'port-tag';
      tag.textContent = svc.port + '/' + svc.name;
      if (svc.banner) tag.title = svc.banner;
      portsEl.appendChild(tag);
    }
  } else {
    portsEl.textContent = 'none detected';
    portsEl.style.color = '#444';
  }

  // Timeline
  renderTimeline(dev.timeline);
}

function renderTimeline(entries) {
  const el = document.getElementById('d-timeline');
  el.innerHTML = '';
  if (!entries || !entries.length) {
    const empty = document.createElement('span');
    empty.textContent = 'no events';
    empty.style.color = '#444';
    empty.style.fontSize = '10px';
    el.appendChild(empty);
    return;
  }
  const recent = entries.slice(-12).reverse();
  for (const entry of recent) {
    const row    = document.createElement('div');
    row.className = 'tentry';
    const isOn   = entry.event === 'online';
    const dot    = document.createElement('span');
    dot.className = 'tdot ' + (isOn ? 'ton' : 'toff');
    const evt    = document.createElement('span');
    evt.className = 'tevent';
    evt.textContent = entry.event.toUpperCase();
    const ts     = document.createElement('span');
    ts.className  = 'ttime';
    ts.textContent = formatTime(entry.time);
    row.appendChild(dot);
    row.appendChild(evt);
    row.appendChild(ts);
    el.appendChild(row);
  }
}

function emojiFlag(code) {
  if (!code || code.length !== 2) return '';
  const base = 0x1F1E6;
  return String.fromCodePoint(base + code.charCodeAt(0) - 65) +
         String.fromCodePoint(base + code.charCodeAt(1) - 65);
}

function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  return d.toLocaleTimeString();
}

function closeDossier() {
  document.getElementById('dossier').classList.add('hidden');
  selectedIP = null;
}

// ─── Activity Feed ────────────────────────────────────────────────────────────
const FEED_MAX   = 200;
const feedAll    = [];
let   feedFilter = 'ALL';
let   feedCount  = 0;
let   feedOpen   = true;

document.querySelectorAll('.fbtn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fbtn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    feedFilter = btn.dataset.f;
    rebuildFeedDOM();
  });
});

document.getElementById('feed-toggle').addEventListener('click', () => {
  feedOpen = !feedOpen;
  document.getElementById('feed').classList.toggle('collapsed', !feedOpen);
  document.getElementById('feed-toggle').textContent = feedOpen ? '▲' : '▼';
});

function addTrafficEvent(ev) {
  feedCount++;
  feedAll.unshift(ev);
  if (feedAll.length > FEED_MAX) feedAll.pop();
  document.getElementById('feed-count').textContent = feedCount;

  if (feedFilter === 'ALL' || ev.proto === feedFilter) {
    prependFeedRow(ev);
  }
}

function prependFeedRow(ev) {
  const list = document.getElementById('feed-list');
  list.insertBefore(buildRow(ev), list.firstChild);
  while (list.children.length > 80) list.removeChild(list.lastChild);
}

function buildRow(ev) {
  const row   = document.createElement('div');
  row.className = 'frow' + (ev.threat ? ' threat' : '');

  const t      = new Date(ev.time).toTimeString().slice(0, 8);
  const proto  = (ev.proto || '').toLowerCase();
  const domain = ev.domain || ev.dst_ip || '—';

  const tEl = document.createElement('span');
  tEl.className = 'ftime';
  tEl.textContent = t;

  const badge = document.createElement('span');
  badge.className = 'fbadge ' + proto;
  badge.textContent = ev.proto || '—';

  const src = document.createElement('span');
  src.className = 'fsrc';
  src.textContent = ev.src_ip || '';

  const arrow = document.createElement('span');
  arrow.className = 'farrow';
  arrow.textContent = '→';

  row.appendChild(tEl);
  row.appendChild(badge);
  row.appendChild(src);
  row.appendChild(arrow);

  if (ev.flag) {
    const flagEl = document.createElement('span');
    flagEl.className   = 'fflag';
    flagEl.textContent = ev.flag;
    row.appendChild(flagEl);
  }

  const domEl = document.createElement('span');
  domEl.className   = 'fdomain ' + proto;
  domEl.textContent = domain;
  if (ev.threat) domEl.style.color = RED;
  row.appendChild(domEl);

  if (ev.details) {
    const det = document.createElement('span');
    det.className   = 'fdetail';
    det.textContent = ev.details;
    row.appendChild(det);
  }

  if (ev.threat) {
    const warn = document.createElement('span');
    warn.className = 'fthreat';
    warn.textContent = '⚠';
    if (ev.threat_msg) warn.title = ev.threat_msg;
    row.appendChild(warn);
  }

  return row;
}

function rebuildFeedDOM() {
  const list     = document.getElementById('feed-list');
  list.innerHTML = '';
  const filtered = feedFilter === 'ALL'
    ? feedAll
    : feedAll.filter((e) => e.proto === feedFilter);
  filtered.slice(0, 80).forEach((ev) => list.appendChild(buildRow(ev)));
}

function loadTrafficHistory(events) {
  if (!events || !events.length) return;
  for (let i = events.length - 1; i >= 0; i--) {
    feedAll.push(events[i]);
  }
  feedCount = feedAll.length;
  document.getElementById('feed-count').textContent = feedCount;
  rebuildFeedDOM();
}

// ─── Filter bar wiring ────────────────────────────────────────────────────────
document.querySelectorAll('.filt').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filt').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    nodeFilter = btn.dataset.filt;
  });
});

document.getElementById('vendor-filter').addEventListener('input', (e) => {
  vendorFilter = e.target.value.trim();
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
connect();

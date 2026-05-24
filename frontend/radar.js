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

// ─── New feature state ────────────────────────────────────────────────────────
let topoMode      = false;
let heatmapMode   = false;
let statsVisible  = false;
let replayMode    = false;
let dnspoofVisible = false;
let spoofActive   = false;

const peerLinks   = new Map();   // "srcIP|dstIP" → {bytes, t}
const domainCounts = new Map();  // domain → count
let encCount      = 0;
let plainCount    = 0;

const blockedIPs      = new Set();   // IPs currently blocked via ARP isolation
const externalTraffic = new Map();   // countryCode → event count
let   worldMapVisible  = false;

let replayEvents  = [];
let replayTimer   = null;
let replayIdx     = 0;

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

// ─── Country centroids [lon, lat] (equirectangular projection) ────────────────
const CENTROIDS = {
  US:[-98,38], GB:[-3,54], DE:[10,51], FR:[2,46], JP:[138,36], CN:[105,35],
  BR:[-51,-10], RU:[100,60], IN:[78,21], AU:[134,-25], CA:[-96,60], NL:[5,52],
  SE:[18,62], NO:[15,65], DK:[10,56], FI:[26,64], CH:[8,47], AT:[15,47],
  BE:[4,50], ES:[-4,40], IT:[12,42], PL:[20,52], CZ:[16,50], HU:[19,47],
  RO:[25,46], UA:[32,49], TR:[35,39], IL:[35,31], SA:[45,24], AE:[54,24],
  SG:[104,1], KR:[128,37], HK:[114,22], TW:[121,24], TH:[101,15], MY:[108,2],
  ID:[118,-5], PH:[122,13], VN:[108,16], MX:[-102,24], AR:[-64,-34],
  CL:[-71,-30], CO:[-74,4], ZA:[25,-29], EG:[30,27], NG:[8,10], KE:[38,1],
  MA:[-7,32], PT:[-8,39], GR:[22,39], IE:[-8,53], IS:[-18,65], NZ:[174,-41],
  LU:[6,50], CY:[33,35], SK:[19,49], SI:[15,46], HR:[16,45], RS:[21,44],
  BG:[25,43], LT:[24,56], LV:[25,57], EE:[25,59], BY:[28,53], MD:[29,47],
  AM:[45,40], GE:[43,42], AZ:[47,40], KZ:[68,48], UZ:[63,41], PK:[70,31],
  BD:[90,24], LK:[81,8], NP:[84,28], MM:[96,19], KH:[105,12], LA:[103,18],
  IQ:[44,33], IR:[53,32], SY:[38,35], JO:[36,31], LB:[36,34], KW:[48,29],
  QA:[51,25], BH:[51,26], OM:[57,23], YE:[48,16], ET:[40,9], TZ:[35,-6],
  MZ:[35,-18], ZW:[30,-20], ZM:[28,-15], UG:[32,1], GH:[2,8], CI:[-6,6],
  SN:[-14,14], CM:[12,6], AO:[18,-12], DZ:[2,28], LY:[17,26], TN:[9,34],
};

// ─── 3D Globe (D3.js + topojson world-atlas) ─────────────────────────────────
let globeRotation  = [0, -20];   // [lon, lat] — D3 geoOrthographic format
let globeVelLon    = 0.25;       // auto-spin deg/frame
let globeAnimId    = null, globeDragging = false, globeDragLast = {x:0, y:0};
let GLOBE_HOME     = null;       // [lat, lon] — set dynamically via /api/geo/me
let _worldGeo      = null;       // loaded once from CDN

// Pre-generated static star field
const STARS = Array.from({length: 280}, (_, i) => {
  const s = (n) => { n = Math.sin(n * 9301 + 49297) * 233280; return n - Math.floor(n); };
  return [s(i) * 500, s(i + 1000) * 500, 0.15 + s(i + 2000) * 0.85];
});

// Great-circle slerp (still needed for animated arc dots)
function slerp3(v1, v2, t) {
  const d  = Math.max(-1, Math.min(1, v1[0]*v2[0]+v1[1]*v2[1]+v1[2]*v2[2]));
  const om = Math.acos(d);
  if (om < 1e-6) return [...v1];
  const s = Math.sin(om);
  return [
    (Math.sin((1-t)*om)*v1[0]+Math.sin(t*om)*v2[0])/s,
    (Math.sin((1-t)*om)*v1[1]+Math.sin(t*om)*v2[1])/s,
    (Math.sin((1-t)*om)*v1[2]+Math.sin(t*om)*v2[2])/s,
  ];
}

// Fetch world topology once from CDN
async function _loadWorldGeo() {
  if (_worldGeo || typeof d3 === 'undefined' || typeof topojson === 'undefined') return;
  try {
    const resp = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
    const topo  = await resp.json();
    _worldGeo = {
      land:     topojson.feature(topo, topo.objects.land),
      borders:  topojson.mesh(topo, topo.objects.countries, (a, b) => a !== b),
      graticule: d3.geoGraticule()(),
    };
  } catch(e) { console.warn('Globe: could not load world topology', e); }
}

// Fetch server's real location from backend
async function _fetchHomeLocation() {
  try {
    const res  = await fetch('/api/geo/me');
    const data = await res.json();
    if (data.lat != null && data.lon != null) {
      GLOBE_HOME = [data.lat, data.lon];
      // Centre globe on home location initially
      globeRotation = [-data.lon, -data.lat * 0.5];
    }
  } catch(e) {}
}

function toggleWorldMap() {
  worldMapVisible = !worldMapVisible;
  document.getElementById('worldmap-panel').classList.toggle('hidden', !worldMapVisible);
  document.getElementById('map-btn').classList.toggle('mode-active', worldMapVisible);
  if (worldMapVisible) startGlobe();
  else stopGlobe();
}

function startGlobe() {
  if (globeAnimId) return;
  _loadWorldGeo();
  if (!GLOBE_HOME) _fetchHomeLocation();
  const cv = document.getElementById('world-map-canvas');
  if (!cv) return;
  cv.addEventListener('mousedown',  _globeDown);
  cv.addEventListener('mousemove',  _globeMove);
  cv.addEventListener('mouseup',    _globeUp);
  cv.addEventListener('mouseleave', _globeUp);
  function loop() { drawGlobe(); globeAnimId = requestAnimationFrame(loop); }
  globeAnimId = requestAnimationFrame(loop);
}

function stopGlobe() {
  if (globeAnimId) { cancelAnimationFrame(globeAnimId); globeAnimId = null; }
  const cv = document.getElementById('world-map-canvas');
  if (!cv) return;
  cv.removeEventListener('mousedown',  _globeDown);
  cv.removeEventListener('mousemove',  _globeMove);
  cv.removeEventListener('mouseup',    _globeUp);
  cv.removeEventListener('mouseleave', _globeUp);
}

function _globeDown(e) {
  globeDragging = true;
  globeDragLast = { x: e.clientX, y: e.clientY };
  globeVelLon = 0;
  e.preventDefault();
}
function _globeMove(e) {
  if (!globeDragging) return;
  const dx = e.clientX - globeDragLast.x;
  const dy = e.clientY - globeDragLast.y;
  globeRotation[0] += dx * 0.35;
  globeRotation[1]  = Math.max(-85, Math.min(85, globeRotation[1] - dy * 0.35));
  globeVelLon = dx * 0.12;
  globeDragLast = { x: e.clientX, y: e.clientY };
}
function _globeUp() {
  globeDragging = false;
  if (Math.abs(globeVelLon) < 0.05) globeVelLon = 0.25;
}

function drawGlobe() {
  const wCanvas = document.getElementById('world-map-canvas');
  if (!wCanvas) return;
  const wc = wCanvas.getContext('2d');
  const W  = wCanvas.width, H = wCanvas.height;
  const cx = W / 2, cy = H / 2;
  const R  = Math.min(W, H) / 2 - 18;

  // Auto-spin with momentum
  if (!globeDragging) {
    globeVelLon = globeVelLon * 0.97 + (globeVelLon > 0 ? 0.004 : -0.004);
    if (Math.abs(globeVelLon) < 0.05) globeVelLon = 0.25;
    globeRotation[0] += globeVelLon;
  }

  // D3 orthographic projection
  const projection = (typeof d3 !== 'undefined')
    ? d3.geoOrthographic()
        .scale(R)
        .translate([cx, cy])
        .rotate([globeRotation[0], globeRotation[1]])
        .clipAngle(90)
    : null;

  const path = projection
    ? d3.geoPath().projection(projection).context(wc)
    : null;

  // ── Draw ─────────────────────────────────────────────────────────────────────
  wc.clearRect(0, 0, W, H);

  // 1. Deep space
  wc.fillStyle = '#00010d';
  wc.fillRect(0, 0, W, H);

  // 2. Stars
  for (const [sx, sy, br] of STARS) {
    wc.globalAlpha = br * 0.85;
    wc.fillStyle = '#ffffff';
    wc.fillRect(sx, sy, br < 0.5 ? 1 : 1.5, br < 0.5 ? 1 : 1.5);
  }
  wc.globalAlpha = 1;

  // 3. Outer atmosphere glow
  const atmOut = wc.createRadialGradient(cx, cy, R * 0.96, cx, cy, R * 1.28);
  atmOut.addColorStop(0,    'rgba(30,110,220,0.50)');
  atmOut.addColorStop(0.35, 'rgba(20,70,160,0.18)');
  atmOut.addColorStop(0.7,  'rgba(10,30,100,0.06)');
  atmOut.addColorStop(1,    'rgba(0,0,0,0)');
  wc.beginPath(); wc.arc(cx, cy, R * 1.28, 0, Math.PI * 2);
  wc.fillStyle = atmOut; wc.fill();

  // 4. Ocean sphere
  const ocean = wc.createRadialGradient(cx - R*0.35, cy - R*0.35, R*0.02, cx + R*0.15, cy + R*0.2, R*1.05);
  ocean.addColorStop(0,    '#2a6faa');
  ocean.addColorStop(0.25, '#16457a');
  ocean.addColorStop(0.55, '#0b2850');
  ocean.addColorStop(0.8,  '#061630');
  ocean.addColorStop(1,    '#020a1a');
  wc.beginPath(); wc.arc(cx, cy, R, 0, Math.PI * 2);
  wc.fillStyle = ocean; wc.fill();

  if (!_worldGeo || !path) {
    // Loading indicator
    wc.fillStyle = 'rgba(40,120,255,0.6)';
    wc.font = '13px "Courier New"';
    wc.textAlign = 'center'; wc.textBaseline = 'middle';
    wc.fillText('LOADING WORLD DATA...', cx, cy);
  } else {
    // 5. Land (D3 geoPath handles hemisphere clipping automatically)
    wc.save();
    wc.beginPath(); wc.arc(cx, cy, R, 0, Math.PI * 2); wc.clip();

    const landGrad = wc.createRadialGradient(cx - R*0.38, cy - R*0.42, 0, cx + R*0.2, cy + R*0.25, R*1.3);
    landGrad.addColorStop(0,    '#6dbb3a');
    landGrad.addColorStop(0.28, '#4a9228');
    landGrad.addColorStop(0.55, '#356e1c');
    landGrad.addColorStop(0.78, '#234d10');
    landGrad.addColorStop(1,    '#102608');

    wc.beginPath();
    path(_worldGeo.land);
    wc.fillStyle = landGrad;
    wc.fill();

    // Country borders
    wc.beginPath();
    path(_worldGeo.borders);
    wc.strokeStyle = 'rgba(0,15,0,0.45)';
    wc.lineWidth = 0.5;
    wc.stroke();

    // Graticule (subtle blue grid)
    wc.beginPath();
    path(_worldGeo.graticule);
    wc.strokeStyle = 'rgba(80,160,255,0.07)';
    wc.lineWidth = 0.35;
    wc.stroke();

    // Limb darkening
    const limb = wc.createRadialGradient(cx, cy, R * 0.72, cx, cy, R);
    limb.addColorStop(0,    'rgba(0,0,0,0)');
    limb.addColorStop(0.75, 'rgba(0,5,20,0.22)');
    limb.addColorStop(1,    'rgba(0,8,40,0.68)');
    wc.beginPath(); wc.arc(cx, cy, R, 0, Math.PI * 2);
    wc.fillStyle = limb; wc.fill();

    wc.restore();
  }

  // 6. Atmosphere inner rim
  const atmIn = wc.createRadialGradient(cx, cy, R * 0.92, cx, cy, R * 1.03);
  atmIn.addColorStop(0,   'rgba(60,140,255,0.0)');
  atmIn.addColorStop(0.5, 'rgba(60,140,255,0.24)');
  atmIn.addColorStop(1,   'rgba(100,180,255,0.0)');
  wc.beginPath(); wc.arc(cx, cy, R * 1.03, 0, Math.PI * 2);
  wc.fillStyle = atmIn; wc.fill();

  // 7. Connection arcs + animated packets
  if (projection) {
    const now      = Date.now();
    const arcPhase = (now * 0.00038) % 1;
    const ARC_STEPS = 80;

    wc.save();
    wc.beginPath(); wc.arc(cx, cy, R, 0, Math.PI * 2); wc.clip();

    for (const [cc, count] of externalTraffic) {
      const pos = CENTROIDS[cc];
      if (!pos) continue;
      const destLonLat = pos;                          // [lon, lat]
      const homeLonLat = GLOBE_HOME ? [GLOBE_HOME[1], GLOBE_HOME[0]] : null;

      // Base arc via D3 great-circle LineString (auto-clipped)
      if (homeLonLat) {
        const arcFeature = { type: 'LineString', coordinates: [destLonLat, homeLonLat] };
        wc.beginPath();
        path(arcFeature);
        wc.strokeStyle = 'rgba(0,220,255,0.30)';
        wc.lineWidth = 1.3;
        wc.stroke();
      }

      // Animated packets using d3.geoInterpolate
      const nPkts = Math.min(3, 1 + Math.floor(Math.log1p(count)));
      const ph0 = ((cc.charCodeAt(0) * 137 + (cc.charCodeAt(1) || 0) * 31) % 1000) / 1000;
      const interp = homeLonLat ? d3.geoInterpolate(destLonLat, homeLonLat) : null;

      if (!interp) continue;
      for (let i = 0; i < nPkts; i++) {
        const t   = (arcPhase + ph0 + i / nPkts) % 1;
        const pos2 = interp(t);                        // [lon, lat]
        const px  = projection(pos2);                  // [sx, sy] or null (back hemisphere)
        if (!px) continue;
        const fade = Math.sin(t * Math.PI);
        if (fade < 0.06) continue;
        // Depth fade: points near limb get darker
        const distR = Math.hypot(px[0] - cx, px[1] - cy) / R;
        const depth = Math.max(0, 1 - distR * distR);
        const alpha = fade * Math.sqrt(depth);
        if (alpha < 0.05) continue;
        wc.beginPath(); wc.arc(px[0], px[1], 2.8 * fade, 0, Math.PI * 2);
        wc.fillStyle  = `rgba(0,220,255,${0.95 * alpha})`;
        wc.shadowBlur = 10; wc.shadowColor = '#00dcff';
        wc.fill(); wc.shadowBlur = 0;
      }
    }

    // 8. Country traffic dots
    for (const [cc, count] of externalTraffic) {
      const pos = CENTROIDS[cc];
      if (!pos) continue;
      const px = projection(pos);
      if (!px) continue;
      const distR = Math.hypot(px[0] - cx, px[1] - cy) / R;
      const fade  = Math.max(0, Math.sqrt(1 - distR * distR));
      if (fade < 0.05) continue;
      const now2  = Date.now();
      const rBase = 3 + Math.min(Math.log1p(count) * 2.5, 11);
      const pulse = 1 + 0.28 * Math.sin(now2 * 0.0025 + cc.charCodeAt(0) * 1.9);
      const r = rBase * pulse * fade;
      const grd = wc.createRadialGradient(px[0], px[1], 0, px[0], px[1], r * 3);
      grd.addColorStop(0,   `rgba(0,255,65,${0.8 * fade})`);
      grd.addColorStop(0.4, `rgba(0,255,65,${0.25 * fade})`);
      grd.addColorStop(1,   'rgba(0,255,65,0)');
      wc.beginPath(); wc.arc(px[0], px[1], r * 3, 0, Math.PI * 2); wc.fillStyle = grd; wc.fill();
      wc.beginPath(); wc.arc(px[0], px[1], Math.max(1.5, r * 0.38), 0, Math.PI * 2);
      wc.fillStyle = `rgba(0,255,65,${fade})`; wc.shadowBlur = 8; wc.shadowColor = '#00ff41';
      wc.fill(); wc.shadowBlur = 0;
      if (fade > 0.5) {
        wc.fillStyle = `rgba(0,255,65,${Math.min(1, fade)})`;
        wc.font = `bold ${Math.max(7, Math.floor(10 * fade))}px "Courier New"`;
        wc.textAlign = 'center'; wc.textBaseline = 'bottom';
        wc.fillText(cc, px[0], px[1] - r - 2);
      }
    }

    // 9. Home marker
    if (GLOBE_HOME) {
      const homeLonLat = [GLOBE_HOME[1], GLOBE_HOME[0]];
      const hpx = projection(homeLonLat);
      if (hpx) {
        const distR = Math.hypot(hpx[0] - cx, hpx[1] - cy) / R;
        const hFade = Math.max(0, Math.sqrt(1 - distR * distR));
        if (hFade > 0.05) {
          const now2   = Date.now();
          const hPulse = 1 + 0.3 * Math.sin(now2 * 0.003);
          wc.beginPath(); wc.arc(hpx[0], hpx[1], 5 * hPulse * hFade, 0, Math.PI * 2);
          wc.fillStyle = `rgba(255,215,0,${hFade})`;
          wc.shadowBlur = 18; wc.shadowColor = '#ffd700';
          wc.fill(); wc.shadowBlur = 0;
        }
      }
    }

    wc.restore();
  }

  // 10. Globe rim (atmospheric blue ring)
  wc.beginPath(); wc.arc(cx, cy, R, 0, Math.PI * 2);
  wc.strokeStyle = 'rgba(50,140,255,0.65)'; wc.lineWidth = 2.2; wc.stroke();

  // 11. Specular highlight
  const shine = wc.createRadialGradient(cx - R*0.4, cy - R*0.42, 0, cx - R*0.2, cy - R*0.2, R*0.6);
  shine.addColorStop(0,   'rgba(255,255,255,0.14)');
  shine.addColorStop(0.4, 'rgba(200,230,255,0.05)');
  shine.addColorStop(1,   'rgba(255,255,255,0)');
  wc.beginPath(); wc.arc(cx, cy, R, 0, Math.PI * 2);
  wc.fillStyle = shine; wc.fill();

  // 12. Legend
  const legEl = document.getElementById('worldmap-legend');
  if (legEl) {
    const top = [...externalTraffic.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
    legEl.innerHTML = top.length
      ? top.map(([cc, n]) => `<span class="map-legend-item">${emojiFlag(cc)} ${cc} <b>${n}</b></span>`).join('')
      : '<span style="color:#334466;font-size:10px">no external traffic yet</span>';
  }
}


// ─── WebSocket ────────────────────────────────────────────────────────────────
function connect() {
  const ws = new WebSocket('ws://' + location.host + '/ws');

  ws.onopen = () => {
    document.getElementById('scan-status').textContent = 'CONNECTED';
    loadBlockedIPs();
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
      updateHealthScore();
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

    case 'peer_link':
      if (ev.peer_links) {
        const now = Date.now();
        for (const pair of ev.peer_links) {
          const key = pair.src_ip + '|' + pair.dst_ip;
          peerLinks.set(key, { bytes: pair.bytes, t: now });
        }
        // Prune entries older than 30 seconds
        for (const [key, val] of peerLinks) {
          if (now - val.t > 30000) peerLinks.delete(key);
        }
      }
      break;

    case 'ssl_strip':
      if (ev.alert) {
        showToast('danger', ev.alert.message);
        playBeep(330, 0.3, 'sawtooth');
        // Add to feed as SSL event
        addTrafficEvent({
          time: new Date().toISOString(),
          proto: 'SSL',
          src_ip: ev.alert.ip || '',
          domain: ev.alert.message,
          threat: true,
          threat_msg: 'SSL Strip detected',
        });
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

// ─── Block / Isolate ──────────────────────────────────────────────────────────
function loadBlockedIPs() {
  fetch('/api/block')
    .then((r) => r.ok ? r.json() : [])
    .then((ips) => { blockedIPs.clear(); (ips || []).forEach((ip) => blockedIPs.add(ip)); })
    .catch(() => {});
}

function toggleBlock() {
  const dev = devices.get(selectedIP);
  if (!dev || dev.is_gateway) return;
  if (blockedIPs.has(selectedIP)) {
    fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: selectedIP })
    }).then(() => {
      blockedIPs.delete(selectedIP);
      renderDossier(dev);
    }).catch((e) => showToast('danger', 'Unblock failed: ' + e.message));
  } else {
    fetch('/api/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: selectedIP, mac: dev.mac })
    }).then(() => {
      blockedIPs.add(selectedIP);
      renderDossier(dev);
    }).catch((e) => showToast('danger', 'Block failed: ' + e.message));
  }
}

// ─── Health Score ─────────────────────────────────────────────────────────────
function calcHealthScore() {
  let score = 100;
  let critCVE = 0, highCVE = 0, threats = 0, unknown = 0;

  for (const [, dev] of devices) {
    if (!dev.active) continue;
    if (dev.cves && dev.cves.length > 0) {
      if (dev.cves.some((c) => c.severity === 'CRITICAL')) critCVE++;
      else if (dev.cves.some((c) => c.severity === 'HIGH'))  highCVE++;
    }
    if (dev.threat) threats++;
    if (!dev.is_gateway && !dev.hostname && !dev.device_type && !dev.label) unknown++;
  }

  score -= Math.min(critCVE * 15, 30);
  score -= Math.min(highCVE  * 8,  16);
  score -= Math.min(threats  * 10, 20);
  score -= Math.min(unknown  * 4,  12);

  const total = encCount + plainCount;
  if (total > 10) {
    const ratio = plainCount / total;
    if      (ratio > 0.5) score -= 20;
    else if (ratio > 0.2) score -= 10;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

function updateHealthScore() {
  const el = document.getElementById('health-score');
  if (!el) return;
  const s = calcHealthScore();
  el.textContent = s;
  if (s >= 70) {
    el.style.color      = 'var(--green)';
    el.style.textShadow = '0 0 8px var(--green)';
  } else if (s >= 40) {
    el.style.color      = 'var(--yellow)';
    el.style.textShadow = '0 0 8px var(--yellow)';
  } else {
    el.style.color      = 'var(--red)';
    el.style.textShadow = '0 0 8px var(--red)';
  }
}

setInterval(updateHealthScore, 5000);

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
  // In topology mode, positions are fixed — skip all physics
  if (topoMode) return;

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

// ─── Topology mode ────────────────────────────────────────────────────────────
function toggleTopoMode() {
  topoMode = !topoMode;
  document.getElementById('topo-btn').classList.toggle('mode-active', topoMode);
  if (topoMode) positionTopoNodes();
}

function positionTopoNodes() {
  const cx = canvas.width  / 2;
  const cy = canvas.height / 2;

  // Group nodes by topo_layer (default to layer 1 if not set, gateway = layer 0)
  const layers = { 0: [], 1: [], 2: [] };
  for (const [ip, dev] of devices) {
    if (!nodes.has(ip)) continue;
    let layer = dev.topo_layer != null ? dev.topo_layer : (dev.is_gateway ? 0 : 1);
    if (layer < 0 || layer > 2) layer = 1;
    layers[layer].push(ip);
  }

  // Layer 0 — gateway: pin to center
  for (const ip of layers[0]) {
    const n = nodes.get(ip);
    if (!n) continue;
    n.x = cx; n.y = cy;
    n.vx = 0; n.vy = 0;
  }

  // Layer 1 — ring at radius 140
  const r1 = 140;
  layers[1].forEach((ip, idx) => {
    const n = nodes.get(ip);
    if (!n) return;
    const angle = (idx / Math.max(layers[1].length, 1)) * Math.PI * 2;
    n.x = cx + Math.cos(angle) * r1;
    n.y = cy + Math.sin(angle) * r1;
    n.vx = 0; n.vy = 0;
  });

  // Layer 2 — ring at radius 260
  const r2 = 260;
  layers[2].forEach((ip, idx) => {
    const n = nodes.get(ip);
    if (!n) return;
    const angle = (idx / Math.max(layers[2].length, 1)) * Math.PI * 2;
    n.x = cx + Math.cos(angle) * r2;
    n.y = cy + Math.sin(angle) * r2;
    n.vx = 0; n.vy = 0;
  });
}

// ─── Heatmap ──────────────────────────────────────────────────────────────────
function toggleHeatmap() {
  heatmapMode = !heatmapMode;
  document.getElementById('heat-btn').classList.toggle('mode-active', heatmapMode);
}

function drawHeatmap() {
  ctx.save();
  ctx.globalCompositeOperation = 'screen';

  for (const [ip, n] of nodes) {
    if (!isVisible(ip)) continue;
    const dev = devices.get(ip);
    if (!dev || !dev.active) continue;

    const rate   = (dev.rate_in || 0) + (dev.rate_out || 0);
    const radius = 80 + rate * 0.00001;

    const isRed  = !!dev.threat;
    const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, radius);
    if (isRed) {
      grad.addColorStop(0,   'rgba(255,32,32,0.14)');
      grad.addColorStop(1,   'rgba(255,32,32,0)');
    } else {
      grad.addColorStop(0,   'rgba(0,255,65,0.12)');
      grad.addColorStop(1,   'rgba(0,255,65,0)');
    }

    ctx.beginPath();
    ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.fill();
  }

  ctx.restore();
}

// ─── Peer links ───────────────────────────────────────────────────────────────
function drawPeerLinks() {
  if (peerLinks.size === 0) return;

  ctx.save();
  ctx.setLineDash([4, 4]);
  ctx.lineWidth   = 0.8;
  ctx.strokeStyle = 'rgba(0,212,255,0.2)';

  for (const [key] of peerLinks) {
    const parts  = key.split('|');
    const srcIP  = parts[0];
    const dstIP  = parts[1];
    if (!nodes.has(srcIP) || !nodes.has(dstIP)) continue;
    if (!isVisible(srcIP) || !isVisible(dstIP)) continue;
    const a = nodes.get(srcIP);
    const b = nodes.get(dstIP);
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }

  ctx.setLineDash([]);
  ctx.restore();
}

// ─── Statistics ───────────────────────────────────────────────────────────────
function toggleStats() {
  statsVisible = !statsVisible;
  document.getElementById('stats-panel').classList.toggle('hidden', !statsVisible);
  document.getElementById('stats-btn').classList.toggle('mode-active', statsVisible);
  if (statsVisible) updateStats();
}

function updateStats() {
  let activeCount  = 0;
  let totalBytesIn = 0;
  let totalBytesOut = 0;

  const bwRanked = [];

  for (const [, dev] of devices) {
    if (dev.active) activeCount++;
    totalBytesIn  += dev.bytes_in  || 0;
    totalBytesOut += dev.bytes_out || 0;
    const rate = (dev.rate_in || 0) + (dev.rate_out || 0);
    bwRanked.push({ ip: dev.ip, rate });
  }

  bwRanked.sort((a, b) => b.rate - a.rate);
  const top3bw = bwRanked.slice(0, 3);

  const topDomains = [...domainCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const totalEnc  = encCount + plainCount;
  const encPct    = totalEnc > 0 ? ((encCount / totalEnc) * 100).toFixed(1) : '0.0';
  const totalBytes = totalBytesIn + totalBytesOut;

  const html = `
<div class="stat-section">
  <span class="stat-title">DEVICES</span>
  <div class="stat-row"><span class="stat-label">Total seen</span><span class="stat-val">${devices.size}</span></div>
  <div class="stat-row"><span class="stat-label">Active now</span><span class="stat-val">${activeCount}</span></div>
  <div class="stat-row"><span class="stat-label">Traffic events</span><span class="stat-val">${feedCount}</span></div>
</div>
<div class="stat-section">
  <span class="stat-title">TOP DOMAINS</span>
  ${topDomains.length > 0
    ? topDomains.map(([d, c]) => `<div class="stat-row"><span class="stat-label">${escHtml(d)}</span><span class="stat-val cyan">${c}</span></div>`).join('')
    : '<div class="stat-row"><span class="stat-label" style="font-style:italic">no data yet</span></div>'
  }
</div>
<div class="stat-section">
  <span class="stat-title">TOP BANDWIDTH</span>
  ${top3bw.length > 0
    ? top3bw.map((entry) => `<div class="stat-row"><span class="stat-label">${escHtml(entry.ip)}</span><span class="stat-val yellow">${formatBW(entry.rate)}</span></div>`).join('')
    : '<div class="stat-row"><span class="stat-label" style="font-style:italic">no data yet</span></div>'
  }
</div>
<div class="stat-section">
  <span class="stat-title">ENCRYPTION</span>
  <div class="stat-row"><span class="stat-label">Encrypted (HTTPS)</span><span class="stat-val">${encCount}</span></div>
  <div class="stat-row"><span class="stat-label">Plaintext (HTTP)</span><span class="stat-val red">${plainCount}</span></div>
  <div class="stat-row"><span class="stat-label">Enc. ratio</span><span class="stat-val">${encPct}%</span></div>
  <div class="stat-row"><span class="stat-label">Total bytes tracked</span><span class="stat-val cyan">${formatBW(totalBytes / 60)}</span></div>
</div>`;

  document.getElementById('stats-body').innerHTML = html;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Session replay ───────────────────────────────────────────────────────────
function toggleReplay() {
  replayMode = !replayMode;
  document.getElementById('replay-panel').classList.toggle('hidden', !replayMode);
  document.getElementById('replay-btn').classList.toggle('mode-active', replayMode);
  if (replayMode) loadSessionDates();
}

function loadSessionDates() {
  fetch('/api/sessions')
    .then((r) => r.json())
    .then((dates) => {
      const sel = document.getElementById('replay-date');
      // Keep first placeholder option
      while (sel.options.length > 1) sel.remove(1);
      if (Array.isArray(dates)) {
        for (const d of dates) {
          const opt = document.createElement('option');
          opt.value = d;
          opt.textContent = d;
          sel.appendChild(opt);
        }
      }
    })
    .catch(() => {
      document.getElementById('replay-status').textContent = 'No session data available.';
    });
}

function loadReplaySession() {
  const sel  = document.getElementById('replay-date');
  const date = sel.value;
  if (!date) return;

  document.getElementById('replay-status').textContent = 'Loading...';

  fetch('/api/sessions/' + encodeURIComponent(date))
    .then((r) => r.text())
    .then((text) => {
      replayEvents = [];
      const lines = text.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const ev = JSON.parse(trimmed);
          replayEvents.push(ev);
        } catch (_) {}
      }
      replayEvents.sort((a, b) => {
        const ta = a.time ? new Date(a.time).getTime() : 0;
        const tb = b.time ? new Date(b.time).getTime() : 0;
        return ta - tb;
      });
      replayIdx = 0;
      document.getElementById('replay-controls').style.display = '';
      document.getElementById('replay-status').textContent =
        replayEvents.length + ' events loaded';
    })
    .catch((e) => {
      document.getElementById('replay-status').textContent = 'Load error: ' + e.message;
    });
}

function playReplay() {
  if (replayEvents.length === 0) return;
  if (replayTimer) return; // already playing

  const btn   = document.getElementById('replay-play-btn');
  btn.textContent = '⏸ PAUSE';

  const speed = parseFloat(document.getElementById('replay-speed').value) || 1;

  // Clear the current scene
  devices.clear();
  nodes.clear();
  replayIdx = 0;

  const firstT = replayEvents[0].time ? new Date(replayEvents[0].time).getTime() : 0;
  const wallStart = Date.now();

  function dispatchNext() {
    if (replayIdx >= replayEvents.length) {
      stopReplay();
      document.getElementById('replay-status').textContent = 'Replay complete.';
      return;
    }

    const ev   = replayEvents[replayIdx];
    const evT  = ev.time ? new Date(ev.time).getTime() : firstT;
    const delay = Math.max(0, (evT - firstT) / speed - (Date.now() - wallStart));

    replayTimer = setTimeout(() => {
      // Dispatch the replay event
      if (ev.type === 'device_found' || ev.type === 'device_updated') {
        const dev = ev.device || {
          ip: ev.ip,
          mac: ev.mac,
          vendor: ev.vendor,
          hostname: ev.hostname,
          active: true,
          first_seen: ev.time,
          last_seen: ev.time,
        };
        addOrUpdate(dev);
        if (ev.type === 'device_found') flash(dev.ip, GREEN);
      } else if (ev.type === 'device_lost') {
        const ip = ev.device ? ev.device.ip : ev.ip;
        if (ip && devices.has(ip)) {
          const d = devices.get(ip);
          d.active = false;
          devices.set(ip, d);
        }
      } else if (ev.type === 'alert') {
        if (ev.alert) showToast(ev.alert.level || 'info', ev.alert.message);
      } else if (ev.type === 'traffic') {
        if (ev.traffic) addTrafficEvent(ev.traffic);
      }

      document.getElementById('replay-status').textContent =
        'Playing ' + (replayIdx + 1) + ' / ' + replayEvents.length;

      replayIdx++;
      dispatchNext();
    }, delay);
  }

  dispatchNext();
}

function stopReplay() {
  if (replayTimer) {
    clearTimeout(replayTimer);
    replayTimer = null;
  }
  const btn = document.getElementById('replay-play-btn');
  if (btn) btn.textContent = '▶ PLAY';
}

// ─── DNS Spoof panel ──────────────────────────────────────────────────────────
function toggleDNSSpoof() {
  dnspoofVisible = !dnspoofVisible;
  document.getElementById('spoof-panel').classList.toggle('hidden', !dnspoofVisible);
  document.getElementById('spoof-btn').classList.toggle('mode-active', dnspoofVisible);
  if (dnspoofVisible) loadSpoofStatus();
}

function loadSpoofStatus() {
  fetch('/api/dnsspoof/status')
    .then((r) => r.json())
    .then((data) => {
      spoofActive = !!data.active;
      const statusEl = document.getElementById('spoof-status');
      const btnEl    = document.getElementById('spoof-toggle-btn');
      statusEl.textContent = spoofActive ? 'ACTIVE' : 'INACTIVE';
      statusEl.style.color  = spoofActive ? '#00ff41' : '#007a20';
      btnEl.textContent     = spoofActive ? 'DISABLE' : 'ENABLE';
      renderSpoofRules(data.rules || []);
    })
    .catch(() => {
      document.getElementById('spoof-status').textContent = 'unavailable';
    });
}

function toggleSpoofActive() {
  const endpoint = spoofActive ? '/api/dnsspoof/off' : '/api/dnsspoof/on';
  fetch(endpoint, { method: 'POST' })
    .then(() => loadSpoofStatus())
    .catch((e) => showToast('danger', 'Spoof toggle error: ' + e.message));
}

function addSpoofRule() {
  const domain = document.getElementById('spoof-domain').value.trim();
  const ip     = document.getElementById('spoof-ip').value.trim();
  if (!domain || !ip) return;

  fetch('/api/dnsspoof/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, ip }),
  })
    .then(() => {
      document.getElementById('spoof-domain').value = '';
      document.getElementById('spoof-ip').value = '';
      loadSpoofStatus();
    })
    .catch((e) => showToast('danger', 'Add rule error: ' + e.message));
}

function removeSpoofRule(domain) {
  fetch('/api/dnsspoof/rules', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  })
    .then(() => loadSpoofStatus())
    .catch((e) => showToast('danger', 'Remove rule error: ' + e.message));
}

function renderSpoofRules(rules) {
  const el = document.getElementById('spoof-rules');
  if (!rules || rules.length === 0) {
    el.innerHTML = '<div style="color:#003d15;font-size:10px;padding:6px 0">no rules defined</div>';
    return;
  }
  el.innerHTML = rules.map((r) => `
    <div class="spoof-rule">
      <span class="spoof-rule-domain">${escHtml(r.domain)}</span>
      <span class="spoof-rule-ip">${escHtml(r.ip)}</span>
      <button class="spoof-rule-del" onclick="removeSpoofRule('${escHtml(r.domain)}')">DEL</button>
    </div>
  `).join('');
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

    const blocked  = blockedIPs.has(ip);
    const rate     = (dev.rate_in || 0) + (dev.rate_out || 0);
    const MAX_RATE = 2 * 1024 * 1024;
    const rateT    = Math.min(rate / MAX_RATE, 1);
    const lw       = 1 + 4 * rateT;
    const alpha    = blocked ? 0.35 : (0.12 + 0.5 * rateT);
    const lineColor = blocked ? 'rgba(255,32,32,' + alpha + ')' : 'rgba(0,212,255,' + alpha + ')';

    // Edge line
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(gwNode.x, gwNode.y);
    ctx.lineTo(n.x, n.y);
    ctx.strokeStyle = lineColor;
    ctx.lineWidth   = blocked ? 1.5 : lw;
    if (blocked) {
      ctx.setLineDash([5, 5]);
    } else if (rateT > 0.1) {
      ctx.shadowBlur  = 6 * rateT;
      ctx.shadowColor = CYAN;
    }
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.restore();

    if (blocked) continue;

    // Traffic particles: count and speed scale with bandwidth
    const numP  = 1 + Math.floor(rateT * 3);
    const speed = 0.15 + 0.35 * rateT;
    const hash  = hashIP(ip);

    for (let i = 0; i < numP; i++) {
      const phase = ((t * speed + hash * 0.7 + i / numP) % 1);
      const fade  = Math.sin(phase * Math.PI);
      if (fade < 0.05) continue;
      const px = gwNode.x + (n.x - gwNode.x) * phase;
      const py = gwNode.y + (n.y - gwNode.y) * phase;
      const pr = 1 + fade * 2;
      ctx.save();
      ctx.globalAlpha  = fade * (0.4 + 0.6 * Math.max(rateT, 0.2));
      ctx.beginPath();
      ctx.arc(px, py, pr, 0, Math.PI * 2);
      ctx.fillStyle   = CYAN;
      ctx.shadowBlur  = 10;
      ctx.shadowColor = CYAN;
      ctx.fill();
      ctx.restore();
    }
  }
}

function hashIP(ip) {
  let h = 0;
  for (const c of ip) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  return h / 0xffff;
}

// ─── Nodes ────────────────────────────────────────────────────────────────────
function deviceIcon(dev) {
  if (dev.is_gateway) return '🌐';
  const t = (dev.device_type || '').toLowerCase();
  const v = (dev.vendor || '').toLowerCase();
  const o = (dev.os || '').toLowerCase();

  if (t.includes('apple tv') || t.includes('airplay')) return '📺';
  if (t.includes('chromecast') || t.includes('google tv')) return '📺';
  if (t.includes('iphone') || t.includes('ipad')) return '📱';
  if (t.includes('printer')) return '🖨';
  if (t.includes('camera')) return '📷';
  if (t.includes('speaker') || t.includes('sonos') || t.includes('audio')) return '🔊';
  if (t.includes('xbox') || t.includes('shield')) return '🎮';
  if (t.includes('homekit') || t.includes('hue') || t.includes('iot')) return '💡';
  if (t.includes('spotify') || t.includes('itunes') || t.includes('daap')) return '🎵';
  if (t.includes('windows pc')) return '🖥';
  if (t.includes('windows') || t.includes('nas')) return '💻';
  if (t.includes('linux') || t.includes('server')) return '🐧';
  if (t.includes('gateway') || t.includes('router') || t.includes('network device') || t.includes('web server')) return '🌐';
  if (t.includes('apple')) return '🍎';
  if (t.includes('samsung')) return '📱';
  if (t.includes('google')) return '🤖';
  if (t.includes('amazon')) return '📦';
  if (t.includes('workstation')) return '🖥';
  if (t.includes('sony')) return '🎮';
  if (t.includes('lg')) return '📺';

  if (v.includes('apple')) return '🍎';
  if (v.includes('samsung')) return '📱';
  if (v.includes('cisco') || v.includes('juniper') || v.includes('mikrotik') || v.includes('ubiquiti')) return '🌐';
  if (v.includes('raspberry')) return '🐧';
  if (v.includes('sony')) return '🎮';
  if (v.includes('google')) return '🤖';
  if (v.includes('amazon')) return '📦';

  if (o.includes('windows')) return '🖥';
  if (o.includes('linux') || o.includes('unix')) return '🐧';
  if (o.includes('ios') || o.includes('mac')) return '🍎';
  if (o.includes('android')) return '🤖';

  return '❓';
}

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

    ctx.restore();

    // Device icon inside node
    ctx.save();
    ctx.font         = '11px sans-serif';
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'middle';
    ctx.shadowBlur   = 0;
    ctx.globalAlpha  = dev.active ? 1 : 0.35;
    ctx.fillText(deviceIcon(dev), n.x, n.y);
    ctx.restore();

    // Blocked indicator: pulsing red ring + badge
    if (blockedIPs.has(ip)) {
      ctx.save();
      const bPulse = radius + 5 + 3 * Math.sin(now * 0.006);
      ctx.beginPath();
      ctx.arc(n.x, n.y, bPulse, 0, Math.PI * 2);
      ctx.strokeStyle = RED;
      ctx.lineWidth   = 2;
      ctx.shadowBlur  = 16;
      ctx.shadowColor = RED;
      ctx.stroke();
      ctx.font         = '9px sans-serif';
      ctx.textAlign    = 'center';
      ctx.textBaseline = 'middle';
      ctx.shadowBlur   = 0;
      ctx.fillText('🚫', n.x + radius - 1, n.y - radius + 1);
      ctx.restore();
    }

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
  if (!topoMode) applyForces();
  if (heatmapMode) drawHeatmap();
  drawEdges();
  drawPeerLinks();
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

// ─── Double-click: rename node ────────────────────────────────────────────────
canvas.addEventListener('dblclick', (e) => {
  const { mx, my } = canvasMouse(e);
  const hit = hitTest(mx, my);
  if (!hit) return;
  const dev = devices.get(hit);
  if (!dev) return;
  const current = dev.label || dev.hostname || '';
  const newLabel = prompt('Nome do dispositivo (' + hit + '):', current);
  if (newLabel === null) return;
  dev.label = newLabel.trim();
  fetch('/api/label', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: hit, label: newLabel.trim() })
  });
  showToast('info', hit + ' → ' + (newLabel.trim() || 'label removido'));
  if (selectedIP === hit) renderDossier(dev);
});

// ─── Dossier ──────────────────────────────────────────────────────────────────
function renderDossier(dev) {
  if (!dev) return;
  document.getElementById('dossier').classList.remove('hidden');

  // Block button
  const blockBtn = document.getElementById('block-btn');
  if (dev.is_gateway) {
    blockBtn.style.display = 'none';
  } else {
    blockBtn.style.display = '';
    const isBlocked = blockedIPs.has(dev.ip);
    blockBtn.textContent = isBlocked ? '✓ UNBLOCK' : '🚫 BLOCK';
    blockBtn.className   = 'tbtn ' + (isBlocked ? 'btn-unblock' : 'btn-block');
  }

  set('d-ip',       dev.ip       || '—');
  const ipv6Row = document.getElementById('d-ipv6-row');
  if (dev.ipv6_addrs && dev.ipv6_addrs.length > 0) {
    set('d-ipv6', dev.ipv6_addrs.join(' / '));
    ipv6Row.style.display = '';
  } else {
    ipv6Row.style.display = 'none';
  }
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

  // CVEs
  const cveSection = document.getElementById('cve-section');
  const cvesEl     = document.getElementById('d-cves');
  if (dev.cves && dev.cves.length > 0) {
    cveSection.style.display = '';
    cvesEl.innerHTML = dev.cves.map((cve) => {
      const sev = (cve.severity || 'LOW').toUpperCase();
      return `<div class="cve-entry">
        <span class="cve-sev ${sev}">${escHtml(sev)}</span>
        <span class="cve-id">${escHtml(cve.id || '')}</span>
        <span class="cve-desc">${escHtml(cve.description || cve.desc || '')}</span>
      </div>`;
    }).join('');
  } else {
    cveSection.style.display = 'none';
    cvesEl.innerHTML = '';
  }

  // SSL certs
  const sslSection = document.getElementById('ssl-section');
  const sslEl      = document.getElementById('d-ssl');
  if (dev.ssl_certs && dev.ssl_certs.length > 0) {
    sslSection.style.display = '';
    sslEl.innerHTML = dev.ssl_certs.map((cert) => {
      const ok       = cert.valid && !cert.self_signed;
      const icon     = ok ? '✓' : (cert.valid ? '⚠' : '✗');
      const icolor   = ok ? 'var(--green)' : (cert.valid ? 'var(--yellow)' : 'var(--red)');
      const days     = cert.days_left;
      const dcolor   = days < 0 ? 'var(--red)' : days < 30 ? 'var(--yellow)' : 'var(--green)';
      const selfTag  = cert.self_signed ? '<span class="ssl-self">SELF</span>' : '';
      return `<div class="ssl-entry">
        <span style="color:${icolor};font-size:11px">${icon}</span>
        <span class="ssl-port">:${cert.port}</span>
        <span class="ssl-cn" title="${escHtml(cert.cn)}">${escHtml(cert.cn || '—')}</span>
        <span class="ssl-issuer" title="${escHtml(cert.issuer)}">${escHtml((cert.issuer || '—').substring(0, 18))}</span>
        <span style="color:${dcolor}">${days}d</span>
        ${selfTag}
      </div>`;
    }).join('');
  } else {
    sslSection.style.display = 'none';
    sslEl.innerHTML = '';
  }

  // Device type
  const deviceTypeField = document.getElementById('device-type-field');
  const deviceTypeEl    = document.getElementById('d-device-type');
  if (dev.device_type) {
    deviceTypeField.style.display = '';
    deviceTypeEl.textContent = dev.device_type;
  } else {
    deviceTypeField.style.display = 'none';
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

  // Track domain counts
  if (ev.domain) {
    domainCounts.set(ev.domain, (domainCounts.get(ev.domain) || 0) + 1);
  }

  // Track encryption ratio
  if (ev.proto === 'HTTPS') {
    encCount++;
  } else if (ev.proto === 'HTTP') {
    plainCount++;
  }

  // Track external country traffic for globe
  const cc = ev.country_code;
  if (cc && cc.length === 2) {
    externalTraffic.set(cc, (externalTraffic.get(cc) || 0) + 1);
  }

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

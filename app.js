/* ============================================================
   OS HARDENING DASHBOARD — APPLICATION LOGIC
   ============================================================ */

'use strict';

/* ─── DATA DEFINITIONS ────────────────────────────────────── */

const CHECKS = {
  windows: {
    passwordPolicy: [
      { id:'pw_length',    name:'Minimum Password Length ≥ 12',      severity:'high',     detail:'MinPwdLength',   cmd:'net accounts /minpwlen:12' },
      { id:'pw_complexity',name:'Password Complexity Required',       severity:'high',     detail:'ComplexityEnabled', cmd:'secedit /export /cfg pw.cfg' },
      { id:'pw_expiry',    name:'Password Expiry ≤ 90 Days',         severity:'medium',   detail:'MaxPwdAge',      cmd:'net accounts /maxpwage:90' },
      { id:'pw_lockout',   name:'Account Lockout After ≤ 5 Attempts',severity:'high',     detail:'LockoutThreshold', cmd:'net accounts /lockoutthreshold:5' },
      { id:'pw_history',   name:'Password History ≥ 10',             severity:'medium',   detail:'PwdHistory',     cmd:'net accounts /uniquepw:10' },
    ],
    firewall: [
      { id:'fw_domain',   name:'Domain Profile Firewall Enabled',   severity:'critical', detail:'Domain',   cmd:'netsh advfirewall set domainprofile state on' },
      { id:'fw_private',  name:'Private Profile Firewall Enabled',  severity:'critical', detail:'Private',  cmd:'netsh advfirewall set privateprofile state on' },
      { id:'fw_public',   name:'Public Profile Firewall Enabled',   severity:'critical', detail:'Public',   cmd:'netsh advfirewall set publicprofile state on' },
      { id:'fw_inbound',  name:'Inbound Traffic Default Block',     severity:'high',     detail:'InboundAction', cmd:'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound' },
      { id:'fw_logging',  name:'Firewall Logging Enabled',          severity:'medium',   detail:'LogEnabled', cmd:'netsh advfirewall set allprofiles logging filename %systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log' },
    ],
  },
  linux: {
    ssh: [
      { id:'ssh_root',   name:'Root SSH Login Disabled',              severity:'critical', detail:'PermitRootLogin no',       cmd:'echo "PermitRootLogin no" >> /etc/ssh/sshd_config && systemctl restart sshd' },
      { id:'ssh_keyonly',name:'Password Authentication Disabled',     severity:'high',     detail:'PasswordAuthentication no', cmd:'echo "PasswordAuthentication no" >> /etc/ssh/sshd_config' },
      { id:'ssh_port',   name:'Non-Default SSH Port Configured',      severity:'medium',   detail:'Port ≠ 22',               cmd:'sed -i "s/#Port 22/Port 2222/" /etc/ssh/sshd_config' },
      { id:'ssh_proto',  name:'Protocol Version 2 Only',              severity:'high',     detail:'Protocol 2',              cmd:'echo "Protocol 2" >> /etc/ssh/sshd_config' },
      { id:'ssh_maxauth',name:'MaxAuthTries ≤ 3',                     severity:'medium',   detail:'MaxAuthTries 3',          cmd:'echo "MaxAuthTries 3" >> /etc/ssh/sshd_config' },
      { id:'ssh_x11',   name:'X11 Forwarding Disabled',               severity:'low',      detail:'X11Forwarding no',        cmd:'echo "X11Forwarding no" >> /etc/ssh/sshd_config' },
    ],
    filePerms: [
      { id:'fp_passwd',  name:'/etc/passwd Permissions (644)',        severity:'high',     detail:'rw-r--r--',  cmd:'chmod 644 /etc/passwd' },
      { id:'fp_shadow',  name:'/etc/shadow Permissions (000/640)',    severity:'critical', detail:'rw-------',  cmd:'chmod 640 /etc/shadow && chown root:shadow /etc/shadow' },
      { id:'fp_sudoers', name:'/etc/sudoers Permissions (440)',       severity:'critical', detail:'r--r-----',  cmd:'chmod 440 /etc/sudoers' },
      { id:'fp_wwfiles', name:'No World-Writable Files Detected',    severity:'high',     detail:'find /–perm -2', cmd:'find / -xdev -perm -0002 -type f -exec chmod o-w {} \\;' },
      { id:'fp_suid',    name:'SUID Files Audit Passed',              severity:'medium',   detail:'SUID audit',    cmd:'find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -print' },
    ],
  },
};

const SEV_WEIGHTS = { critical: 20, high: 10, medium: 5, low: 2 };

const SEV_ORDER = ['critical', 'high', 'medium', 'low'];

/* ─── STATE ────────────────────────────────────────────────── */

const State = {
  loggedIn: false,
  scanTime: null,
  results: {
    windows: { passwordPolicy: [], firewall: [] },
    linux:   { ssh: [], filePerms: [] },
  },
  score: 0,
  scoreLabel: '',
  scoreByCategory: {},
  recs: [],
  reportGenerated: false,
};

/* ─── UTILITIES ────────────────────────────────────────────── */

function $(id) { return document.getElementById(id); }

function setClass(el, cls, add) {
  if (typeof el === 'string') el = $(el);
  if (!el) return;
  if (add) el.classList.add(cls);
  else     el.classList.remove(cls);
}

function showEl(id)   { const e = typeof id === 'string' ? $(id) : id; if(e){ e.style.display=''; setClass(e,'hidden',false); } }
function hideEl(id)   { const e = typeof id === 'string' ? $(id) : id; if(e){ e.style.display='none'; } }

function toast(msg, type = 'success', duration = 3000) {
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${type}`;
  setTimeout(() => el.classList.add('hidden'), duration);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function formatDate(d) {
  return d.toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

function randomBetween(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }

function generateReportId() {
  return 'OSH-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
}

/* ─── PARTICLE BACKGROUND ──────────────────────────────────── */

(function initParticles() {
  const canvas = $('particles-canvas');
  const ctx    = canvas.getContext('2d');
  let W, H, particles;

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function createParticle() {
    return {
      x:    Math.random() * W,
      y:    Math.random() * H,
      r:    Math.random() * 1.5 + 0.5,
      dx:   (Math.random() - 0.5) * 0.3,
      dy:   (Math.random() - 0.5) * 0.3,
      a:    Math.random() * 0.6 + 0.1,
      col:  Math.random() > 0.5 ? '108,99,255' : '0,212,170',
    };
  }

  function init() {
    resize();
    particles = Array.from({ length: 80 }, createParticle);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${p.col},${p.a})`;
      ctx.fill();

      p.x += p.dx;
      p.y += p.dy;

      if (p.x < 0 || p.x > W) p.dx *= -1;
      if (p.y < 0 || p.y > H) p.dy *= -1;
    });

    // Draw connecting lines between close particles
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 90) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(108,99,255,${0.08 * (1 - dist / 90)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', resize);
  init();
  draw();
})();

/* ─── SIMULATION ENGINE ────────────────────────────────────── */

function simulateCheck(check) {
  const roll = Math.random();
  let status;
  if (check.severity === 'critical') {
    status = roll > 0.28 ? 'pass' : (roll > 0.12 ? 'warning' : 'fail');
  } else if (check.severity === 'high') {
    status = roll > 0.22 ? 'pass' : (roll > 0.10 ? 'warning' : 'fail');
  } else if (check.severity === 'medium') {
    status = roll > 0.18 ? 'pass' : (roll > 0.08 ? 'warning' : 'fail');
  } else {
    status = roll > 0.12 ? 'pass' : (roll > 0.05 ? 'warning' : 'fail');
  }
  return { ...check, status };
}

function simulateGroup(checks) {
  return checks.map(simulateCheck);
}

/* ─── SCORE CALCULATION ─────────────────────────────────────── */

function calculateScore(results) {
  const categories = [
    { key: 'Password Policy', checks: results.windows.passwordPolicy },
    { key: 'Firewall',        checks: results.windows.firewall },
    { key: 'SSH Security',    checks: results.linux.ssh },
    { key: 'File Permissions',checks: results.linux.filePerms },
  ];

  let totalWeight = 0;
  let earnedWeight = 0;
  const breakdown = {};

  categories.forEach(cat => {
    let catTotal = 0, catEarned = 0;
    cat.checks.forEach(c => {
      const w = SEV_WEIGHTS[c.severity] || 5;
      catTotal += w;
      if (c.status === 'pass')    catEarned += w;
      else if (c.status === 'warning') catEarned += w * 0.5;
    });
    totalWeight  += catTotal;
    earnedWeight += catEarned;
    breakdown[cat.key] = Math.round((catEarned / catTotal) * 100);
  });

  const score = Math.round((earnedWeight / totalWeight) * 100);
  let label, color;
  if (score >= 85)      { label = 'Excellent'; color = '#2ED573'; }
  else if (score >= 70) { label = 'Good';      color = '#00D4AA'; }
  else if (score >= 55) { label = 'Fair';      color = '#FFA502'; }
  else if (score >= 40) { label = 'Poor';      color = '#FF6B35'; }
  else                  { label = 'Critical';  color = '#FF4757'; }

  return { score, label, color, breakdown };
}

/* ─── RECOMMENDATIONS GENERATOR ─────────────────────────────── */

function generateRecommendations(results) {
  const allChecks = [
    ...results.windows.passwordPolicy,
    ...results.windows.firewall,
    ...results.linux.ssh,
    ...results.linux.filePerms,
  ];

  const recMap = {
    pw_length:    { title:'Enforce Minimum Password Length of 12 Characters', desc:'Short passwords are easily brute-forced. Enforce a minimum of 12 characters to significantly increase resistance to attacks.' },
    pw_complexity:{ title:'Enable Password Complexity Requirements', desc:'Require a mix of uppercase, lowercase, numbers, and special characters to prevent dictionary attacks.' },
    pw_expiry:    { title:'Set Password Maximum Age to 90 Days', desc:'Regular password rotation limits the window of exposure if credentials are compromised.' },
    pw_lockout:   { title:'Configure Account Lockout Policy', desc:'Lock accounts after 5 failed attempts to mitigate brute-force and credential stuffing attacks.' },
    pw_history:   { title:'Enforce Password History of 10 or More', desc:'Prevent users from reusing recent passwords, reducing the risk of credential cycling.' },
    fw_domain:    { title:'Enable Windows Firewall — Domain Profile', desc:'The domain firewall profile must be enabled for all domain-joined systems.' },
    fw_private:   { title:'Enable Windows Firewall — Private Profile', desc:'Enable the private network profile firewall to protect trusted home/office network traffic.' },
    fw_public:    { title:'Enable Windows Firewall — Public Profile', desc:'Public network traffic is the highest-risk. The public firewall profile must be enabled immediately.' },
    fw_inbound:   { title:'Block All Inbound Traffic by Default', desc:'Implement a default-deny inbound policy and only whitelist required ports and services.' },
    fw_logging:   { title:'Enable Firewall Logging', desc:'Log dropped packets and successful connections for security monitoring and incident response.' },
    ssh_root:     { title:'Disable Root Login via SSH', desc:'Root SSH access bypasses the principle of least privilege. Disable it and use sudo for privileged operations.' },
    ssh_keyonly:  { title:'Disable SSH Password Authentication', desc:'SSH key authentication is significantly more secure than passwords. Disable password auth entirely.' },
    ssh_port:     { title:'Change SSH from Default Port 22', desc:'Moving SSH to a non-standard port reduces automated scanning and opportunistic attacks.' },
    ssh_proto:    { title:'Enforce SSH Protocol Version 2 Only', desc:'SSHv1 has known critical vulnerabilities. Restrict the server to Protocol 2 only.' },
    ssh_maxauth:  { title:'Reduce MaxAuthTries to 3 or Less', desc:'Limit authentication attempts per connection to slow brute-force attacks.' },
    ssh_x11:      { title:'Disable X11 Forwarding in SSH', desc:'X11 forwarding can expose the X display server to attack. Disable unless explicitly required.' },
    fp_passwd:    { title:'Correct /etc/passwd File Permissions', desc:'/etc/passwd must be readable (644) but not writable by non-root users.' },
    fp_shadow:    { title:'Secure /etc/shadow File Permissions', desc:'/etc/shadow contains hashed passwords and must be strictly restricted (000 or 640).' },
    fp_sudoers:   { title:'Restrict /etc/sudoers File Permissions', desc:'The sudoers file must be read-only (440) and owned by root to prevent privilege escalation.' },
    fp_wwfiles:   { title:'Remove World-Writable File Permissions', desc:'World-writable files allow any user to modify them, creating significant security risks.' },
    fp_suid:      { title:'Audit and Remove Unnecessary SUID Bits', desc:'SUID binaries run with the owner\'s privileges and can be exploited for privilege escalation.' },
  };

  const failed = allChecks
    .filter(c => c.status === 'fail' || c.status === 'warning')
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  return failed.map(c => ({
    ...c,
    ...(recMap[c.id] || { title: c.name, desc: 'Apply the required hardening configuration for this check.' }),
    isWarning: c.status === 'warning',
  }));
}

/* ─── UI RENDERERS ─────────────────────────────────────────── */

function renderCheckItem(check, delay = 0) {
  const icons = { pass: '✓', fail: '✗', warning: '!' };
  const labels = { pass: 'PASS', fail: 'FAIL', warning: 'WARN' };
  const div = document.createElement('div');
  div.className = 'check-item';
  div.style.animationDelay = `${delay * 60}ms`;
  div.innerHTML = `
    <div class="check-icon ${check.status}">${icons[check.status]}</div>
    <span class="check-name">${check.name}</span>
    <span class="sev-badge ${check.severity}">${check.severity}</span>
    <span class="check-badge ${check.status}">${labels[check.status]}</span>
  `;
  return div;
}

function renderAllChecks(container, results) {
  const groups = [
    { title: '🖥️  Password Policy',        checks: results.windows.passwordPolicy, icon: 'windows' },
    { title: '🔥  Firewall Status',         checks: results.windows.firewall,       icon: 'windows' },
    { title: '🔒  SSH Security',            checks: results.linux.ssh,              icon: 'linux'   },
    { title: '📁  File Permissions',        checks: results.linux.filePerms,        icon: 'linux'   },
  ];

  container.innerHTML = '';
  let delay = 0;

  groups.forEach(group => {
    const groupDiv = document.createElement('div');
    groupDiv.className = 'all-checks-group';

    const pass    = group.checks.filter(c => c.status === 'pass').length;
    const total   = group.checks.length;
    const fails   = group.checks.filter(c => c.status === 'fail').length;
    const warns   = group.checks.filter(c => c.status === 'warning').length;

    groupDiv.innerHTML = `
      <div class="all-checks-group-header">
        <h4>${group.title}</h4>
        <span class="check-badge pass">${pass} Pass</span>
        ${warns ? `<span class="check-badge warning">${warns} Warn</span>` : ''}
        ${fails ? `<span class="check-badge fail">${fails} Fail</span>` : ''}
      </div>
      <div class="all-checks-group-body" id="grp-${group.title.replace(/\W/g,'')}"></div>
    `;
    container.appendChild(groupDiv);

    const body = groupDiv.querySelector('.all-checks-group-body');
    group.checks.forEach((c, i) => body.appendChild(renderCheckItem(c, delay + i)));
    delay += group.checks.length;
  });
}

function renderSeverityCounts(results) {
  const all = [
    ...results.windows.passwordPolicy,
    ...results.windows.firewall,
    ...results.linux.ssh,
    ...results.linux.filePerms,
  ].filter(c => c.status === 'fail' || c.status === 'warning');

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  all.forEach(c => { if (counts[c.severity] !== undefined) counts[c.severity]++; });

  $('sev-crit').textContent  = counts.critical;
  $('sev-high').textContent  = counts.high;
  $('sev-med').textContent   = counts.medium;
  $('sev-low').textContent   = counts.low;

  $('sec-crit').textContent  = counts.critical;
  $('sec-high').textContent  = counts.high;
  $('sec-med').textContent   = counts.medium;
  $('sec-low').textContent   = counts.low;

  return counts;
}

function renderScoreStrip(scoreData) {
  const all = [
    ...State.results.windows.passwordPolicy,
    ...State.results.windows.firewall,
    ...State.results.linux.ssh,
    ...State.results.linux.filePerms,
  ];

  const pass  = all.filter(c => c.status === 'pass').length;
  const warn  = all.filter(c => c.status === 'warning').length;
  const fail  = all.filter(c => c.status === 'fail').length;

  $('stat-pass').textContent  = pass;
  $('stat-warn').textContent  = warn;
  $('stat-fail').textContent  = fail;
  $('gauge-score').textContent = scoreData.score;

  // Animate gauge arc (small gauge)
  const arc = $('gauge-arc');
  const total = 157; // half-circle circumference at r=50
  const offset = total - (scoreData.score / 100) * total;
  arc.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)';
  arc.style.strokeDashoffset = offset;
}

function animateBigGauge(score) {
  const arc = $('big-gauge-arc');
  const total = 251; // half-circle circumference at r=80
  const offset = total - (score / 100) * total;

  // Animate counter
  const scoreEl = $('big-score');
  let current = 0;
  const step = score / 60;
  const interval = setInterval(() => {
    current = Math.min(current + step, score);
    scoreEl.textContent = Math.round(current);
    if (current >= score) clearInterval(interval);
  }, 16);

  arc.style.transition = 'stroke-dashoffset 1.5s cubic-bezier(0.4,0,0.2,1)';
  arc.style.strokeDashoffset = offset;
}

function renderScoreBreakdown(breakdown) {
  const container = $('score-breakdown');
  container.innerHTML = '';
  Object.entries(breakdown).forEach(([key, val]) => {
    const div = document.createElement('div');
    div.className = 'score-cat';
    const color = val >= 80 ? '#2ED573' : val >= 60 ? '#FFA502' : '#FF4757';
    div.innerHTML = `
      <span class="score-cat-name">${key}</span>
      <div class="score-cat-bar-wrap"><div class="score-cat-bar" style="width:${val}%;background:${color}"></div></div>
      <span class="score-cat-val">${val}%</span>
    `;
    container.appendChild(div);
  });
}

function renderRecommendations(recs) {
  const list = $('recs-list');
  list.innerHTML = '';
  if (recs.length === 0) {
    list.innerHTML = '<p style="color:var(--success);text-align:center;padding:20px">🎉 All checks passed! No recommendations.</p>';
    return;
  }
  recs.forEach((r, i) => {
    const div = document.createElement('div');
    div.className = `rec-item ${r.severity}`;
    div.style.animationDelay = `${i * 40}ms`;
    div.innerHTML = `
      <span class="rec-sev-pill ${r.severity}">${r.severity}</span>
      <div class="rec-body">
        <div class="rec-title">${r.title}</div>
        <div class="rec-desc">${r.desc}</div>
        <div class="rec-cmd">${r.cmd}</div>
      </div>
    `;
    list.appendChild(div);
  });
}

function buildFullReport() {
  const s = State;
  const all = [
    ...s.results.windows.passwordPolicy,
    ...s.results.windows.firewall,
    ...s.results.linux.ssh,
    ...s.results.linux.filePerms,
  ];
  const pass  = all.filter(c => c.status === 'pass').length;
  const warn  = all.filter(c => c.status === 'warning').length;
  const fail  = all.filter(c => c.status === 'fail').length;
  const scoreInfo = calculateScore(s.results);
  const reportId  = generateReportId();
  const dateStr   = formatDate(s.scanTime || new Date());

  const statusIcon = { pass: '✅', fail: '❌', warning: '⚠️' };
  const statusLabel = { pass: 'PASS', fail: 'FAIL', warning: 'WARNING' };

  const groupRows = (checks) => checks.map(c => `
    <tr>
      <td>${c.name}</td>
      <td><span class="sev-badge ${c.severity}">${c.severity}</span></td>
      <td><span class="check-badge ${c.status}">${statusIcon[c.status]} ${statusLabel[c.status]}</span></td>
      <td class="check-detail" style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--text-muted)">${c.detail}</td>
    </tr>
  `).join('');

  const recRows = s.recs.map(r => `
    <div class="report-rec-row ${r.severity}">
      <span class="rec-sev-pill ${r.severity}" style="min-width:64px;text-align:center">${r.severity}</span>
      <div>
        <div class="report-rec-title">${r.title}</div>
        <div class="report-rec-desc">${r.desc}</div>
      </div>
    </div>
  `).join('');

  return `
    <div class="report-header">
      <div class="report-brand">
        <svg width="36" height="36" viewBox="0 0 48 48" fill="none"><path d="M24 4L6 12V24C6 33.94 13.76 43.26 24 46C34.24 43.26 42 33.94 42 24V12L24 4Z" fill="url(#rg1)" stroke="url(#rg2)" stroke-width="1.5"/><path d="M16 24L21 29L32 18" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="rg1" x1="6" y1="4" x2="42" y2="46" gradientUnits="userSpaceOnUse"><stop stop-color="#6C63FF"/><stop offset="1" stop-color="#00D4AA"/></linearGradient><linearGradient id="rg2" x1="6" y1="4" x2="42" y2="46" gradientUnits="userSpaceOnUse"><stop stop-color="#8B85FF"/><stop offset="1" stop-color="#00F0C0"/></linearGradient></defs></svg>
        <div>
          <div class="report-brand-name">OS Hardening Assessment</div>
          <div class="report-brand-sub">Security Assessment Platform</div>
        </div>
      </div>
      <div class="report-meta">
        <div class="date">${dateStr}</div>
        <div class="id">Report ID: ${reportId}</div>
      </div>
    </div>

    <div class="report-score-banner">
      <div class="report-big-score" style="color:${scoreInfo.color}">${scoreInfo.score}</div>
      <div class="report-score-details">
        <h3>Overall Security Score — ${scoreInfo.label}</h3>
        <p>${pass} checks passed · ${warn} warnings · ${fail} failures · ${all.length} total checks</p>
        <p style="margin-top:6px;font-size:0.78rem;color:var(--text-dim)">Scanned on ${dateStr} by Admin</p>
      </div>
    </div>

    <div class="report-section">
      <h3>Score Breakdown</h3>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px">
        ${Object.entries(scoreInfo.breakdown).map(([k,v]) => {
          const col = v>=80?'#2ED573':v>=60?'#FFA502':'#FF4757';
          return `<div style="background:var(--surface);border-radius:8px;padding:14px">
            <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">${k}</div>
            <div style="height:6px;background:rgba(255,255,255,.07);border-radius:3px;overflow:hidden;margin-bottom:6px"><div style="height:100%;width:${v}%;background:${col};border-radius:3px"></div></div>
            <div style="font-size:1rem;font-weight:800;color:${col};font-family:'JetBrains Mono',monospace">${v}%</div>
          </div>`;
        }).join('')}
      </div>
    </div>

    <div class="report-section">
      <h3>Windows Hardening — Password Policy</h3>
      <table class="report-checks-table">
        <thead><tr><th>Check</th><th>Severity</th><th>Status</th><th>Parameter</th></tr></thead>
        <tbody>${groupRows(s.results.windows.passwordPolicy)}</tbody>
      </table>
    </div>

    <div class="report-section">
      <h3>Windows Hardening — Firewall Status</h3>
      <table class="report-checks-table">
        <thead><tr><th>Check</th><th>Severity</th><th>Status</th><th>Parameter</th></tr></thead>
        <tbody>${groupRows(s.results.windows.firewall)}</tbody>
      </table>
    </div>

    <div class="report-section">
      <h3>Linux Hardening — SSH Security</h3>
      <table class="report-checks-table">
        <thead><tr><th>Check</th><th>Severity</th><th>Status</th><th>Parameter</th></tr></thead>
        <tbody>${groupRows(s.results.linux.ssh)}</tbody>
      </table>
    </div>

    <div class="report-section">
      <h3>Linux Hardening — File Permissions</h3>
      <table class="report-checks-table">
        <thead><tr><th>Check</th><th>Severity</th><th>Status</th><th>Parameter</th></tr></thead>
        <tbody>${groupRows(s.results.linux.filePerms)}</tbody>
      </table>
    </div>

    <div class="report-section">
      <h3>Security Recommendations (${s.recs.length})</h3>
      <div class="report-recs-list">${recRows || '<p style="color:var(--success)">No critical issues found.</p>'}</div>
    </div>

    <div class="report-footer">
      Generated by OS Hardening Assessment Platform · ${dateStr} · Report ID: ${reportId}<br>
      This report is for informational purposes. Always test changes in a staging environment before applying to production.
    </div>
  `;
}

/* ─── MODULE RUNNER ────────────────────────────────────────── */

async function runModuleChecks(module) {
  const configs = {
    windows: {
      groups: [
        { key: 'passwordPolicy', checks: CHECKS.windows.passwordPolicy, container: 'win-pw-checks',  label: 'Password Policy' },
        { key: 'firewall',       checks: CHECKS.windows.firewall,       container: 'win-fw-checks',  label: 'Firewall' },
      ],
      pbar: 'win-pbar', ptext: 'win-ptext',
      progress: 'win-progress', preview: 'win-preview',
      statusEl: 'win-module-status', scoreEl: 'win-score-display',
      badgeEl: 'win-badge', btnEl: 'btn-windows',
      rerunBtn: 'win-rerun-btn', total: 10,
    },
    linux: {
      groups: [
        { key: 'ssh',       checks: CHECKS.linux.ssh,       container: 'lin-ssh-checks', label: 'SSH Security' },
        { key: 'filePerms', checks: CHECKS.linux.filePerms, container: 'lin-fp-checks',  label: 'File Permissions' },
      ],
      pbar: 'lin-pbar', ptext: 'lin-ptext',
      progress: 'lin-progress', preview: 'lin-preview',
      statusEl: 'lin-module-status', scoreEl: 'lin-score-display',
      badgeEl: 'lin-badge', btnEl: 'btn-linux',
      rerunBtn: 'lin-rerun-btn', total: 11,
    },
  };

  const cfg = configs[module];

  // Reset UI
  const statusEl = $(cfg.statusEl);
  statusEl.innerHTML = `<span class="status-dot running"></span><span>Running</span>`;
  $(cfg.btnEl).disabled = true;
  if ($(cfg.rerunBtn)) $(cfg.rerunBtn).disabled = true;
  hideEl(cfg.preview);
  showEl(cfg.progress);

  let completed = 0;

  for (const group of cfg.groups) {
    const container = $(group.container);
    if (container) container.innerHTML = '';

    for (let i = 0; i < group.checks.length; i++) {
      const check = group.checks[i];
      const delay = randomBetween(200, 600);

      // Show loading placeholder
      if (container) {
        const placeholder = document.createElement('div');
        placeholder.className = 'check-item';
        placeholder.innerHTML = `
          <div class="check-icon loading">↻</div>
          <span class="check-name">${check.name}</span>
          <span class="sev-badge ${check.severity}">${check.severity}</span>
          <span class="check-badge" style="color:var(--text-muted);background:var(--surface)">CHECKING</span>
        `;
        container.appendChild(placeholder);
      }

      await sleep(delay);

      const result = simulateCheck(check);
      State.results[module][group.key][i] = result;

      // Replace with result
      if (container) {
        const item = container.children[container.children.length - 1];
        if (item) {
          const icons  = { pass: '✓', fail: '✗', warning: '!' };
          const labels = { pass: 'PASS', fail: 'FAIL', warning: 'WARN' };
          item.querySelector('.check-icon').className = `check-icon ${result.status}`;
          item.querySelector('.check-icon').textContent = icons[result.status];
          item.querySelector('.check-badge').className = `check-badge ${result.status}`;
          item.querySelector('.check-badge').textContent = labels[result.status];
        }
      }

      completed++;
      const pct = Math.round((completed / cfg.total) * 100);
      $(cfg.pbar).style.width = pct + '%';
      $(cfg.ptext).textContent = `Scanning ${group.label} [${completed}/${cfg.total}]…`;
    }
  }

  // Done
  await sleep(300);
  hideEl(cfg.progress);
  showEl(cfg.preview);
  $(cfg.btnEl).disabled = false;
  if ($(cfg.rerunBtn)) $(cfg.rerunBtn).disabled = false;

  const allResults = [
    ...State.results[module][cfg.groups[0].key],
    ...State.results[module][cfg.groups[1].key],
  ];
  const pass = allResults.filter(c => c.status === 'pass').length;
  const total = allResults.length;
  const fails = allResults.filter(c => c.status !== 'pass').length;

  statusEl.innerHTML = `<span class="status-dot ${fails > 0 ? 'warn' : 'done'}"></span><span>${fails > 0 ? 'Issues Found' : 'All Clear'}</span>`;
  $(cfg.scoreEl).textContent = `${pass} / ${total} passed`;

  // Update nav badge
  const badgeEl = $(cfg.badgeEl);
  if (badgeEl) {
    badgeEl.classList.toggle('visible', fails > 0);
  }

  // Update flow step dot
  const dotId = module === 'windows' ? 'fd-win' : 'fd-lin';
  const dot = $(dotId);
  if (dot) dot.className = `fstep-dot ${fails > 0 ? 'warning' : 'done'}`;

  // Check if both modules done → enable security check
  const winDone = State.results.windows.passwordPolicy.length > 0 && State.results.windows.firewall.length > 0;
  const linDone = State.results.linux.ssh.length > 0 && State.results.linux.filePerms.length > 0;

  if (winDone && linDone) {
    $('btn-seccheck').disabled = false;
    $('fd-sec').className = 'fstep-dot active';
    $('sec-module-status').innerHTML = `<span class="status-dot done"></span><span>Ready</span>`;

    const counts = renderSeverityCounts(State.results);
    const total2 = counts.critical + counts.high + counts.medium + counts.low;
    $('sec-score-display').textContent = `${total2} issue${total2!==1?'s':''} found`;

    // Calculate score for strip
    const scoreData = calculateScore(State.results);
    State.score = scoreData.score;
    State.scoreLabel = scoreData.label;
    State.scoreByCategory = scoreData.breakdown;
    renderScoreStrip(scoreData);

    // Enable security check section calc button
    $('calc-score-btn').disabled = false;

    toast(`${module === 'windows' ? 'Windows' : 'Linux'} checks complete! Both modules done — run Security Check.`, 'success', 4000);
  } else {
    toast(`${module === 'windows' ? 'Windows' : 'Linux'} scan complete — ${pass}/${total} checks passed`, 'success');
  }

  State.scanTime = new Date();
  $('scan-time').textContent = 'Last scan: ' + formatDate(State.scanTime);
}

/* ─── NAVIGATION ─────────────────────────────────────────────── */

const SECTION_LABELS = {
  'dash-overview':  'Overview',
  'dash-windows':   'Windows Hardening',
  'dash-linux':     'Linux Hardening',
  'dash-seccheck':  'Security Check',
  'dash-report':    'Security Report',
};

const NAV_MAP = {
  'dash-overview':  'nav-overview',
  'dash-windows':   'nav-windows',
  'dash-linux':     'nav-linux',
  'dash-seccheck':  'nav-seccheck',
  'dash-report':    'nav-report',
};

/* ─── MAIN APP OBJECT ────────────────────────────────────────── */

const App = {
  navTo(sectionId) {
    document.querySelectorAll('.dash-section').forEach(s => {
      s.classList.toggle('active', s.id === sectionId);
      s.classList.toggle('hidden', s.id !== sectionId);
    });
    document.querySelectorAll('.nav-item').forEach(n => {
      n.classList.toggle('active', n.dataset.target === sectionId);
    });
    $('breadcrumb').textContent = SECTION_LABELS[sectionId] || 'Dashboard';
  },

  startModule(module) {
    // Switch to the module detail section too
    if (module === 'windows') this.navTo('dash-windows');
    if (module === 'linux')   this.navTo('dash-linux');
    runModuleChecks(module);
  },

  async runFullAssessment() {
    const btn = $('run-assessment-btn');
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-loader"></span> Running Assessment…`;

    toast('Starting full OS hardening assessment…', 'success', 2000);
    await sleep(400);

    // Run Windows
    this.navTo('dash-windows');
    $('fd-win').className = 'fstep-dot active';
    await runModuleChecks('windows');
    await sleep(600);

    // Run Linux
    this.navTo('dash-linux');
    $('fd-lin').className = 'fstep-dot active';
    await runModuleChecks('linux');
    await sleep(600);

    // Security Check
    this.navTo('dash-seccheck');
    renderSeverityCounts(State.results);
    renderAllChecks($('all-checks-list'), State.results);
    $('fd-sec').className = 'fstep-dot done';
    await sleep(1000);

    // Score
    this.showScore();

    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none"><polygon points="5,3 19,12 5,21" fill="currentColor"/></svg> Run Full Assessment`;
  },

  showScore() {
    // Build score if not already
    if (!State.results.windows.passwordPolicy.length || !State.results.linux.ssh.length) {
      toast('Please run the assessment first!', 'error');
      return;
    }
    const scoreData = calculateScore(State.results);
    State.score      = scoreData.score;
    State.scoreLabel = scoreData.label;

    $('big-score').textContent = '0';
    $('big-score-label').textContent = scoreData.label;
    $('big-score').style.color = scoreData.color;
    $('big-score-label').style.color = scoreData.color;

    renderScoreBreakdown(scoreData.breakdown);

    $('modal-score').classList.remove('hidden');
    $('fd-score').className = 'fstep-dot done';

    requestAnimationFrame(() => {
      setTimeout(() => animateBigGauge(scoreData.score), 100);
    });
  },

  closeModal(id) {
    $(id).classList.add('hidden');
  },

  showRecommendations() {
    this.closeModal('modal-score');
    State.recs = generateRecommendations(State.results);
    renderRecommendations(State.recs);
    $('modal-recs').classList.remove('hidden');
    $('fd-rec').className = 'fstep-dot done';
  },

  generateReport() {
    this.closeModal('modal-recs');

    const content = buildFullReport();
    $('full-report-content').innerHTML = content;
    $('modal-report').classList.remove('hidden');

    // Also update the dash-report section
    $('report-content').innerHTML = content;

    $('fd-rep').className = 'fstep-dot done';
    State.reportGenerated = true;

    toast('Security report generated successfully!', 'success');
  },
};

/* ─── EVENT LISTENERS ─────────────────────────────────────────── */

// Login form
$('login-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const btn     = $('login-btn');
  const errEl   = $('login-error');
  const user    = $('username').value.trim();
  const pass    = $('password').value;

  errEl.classList.add('hidden');
  btn.querySelector('.btn-text').classList.add('hidden');
  btn.querySelector('.btn-loader').classList.remove('hidden');
  btn.disabled = true;

  await sleep(1200);

  if (user === 'admin' && pass === 'hardening123') {
    $('screen-login').classList.remove('active');
    $('screen-login').classList.add('hidden');
    $('screen-dashboard').classList.remove('hidden');
    $('screen-dashboard').classList.add('active');
    State.loggedIn = true;
    toast('Welcome back, Admin! Dashboard loaded.', 'success');
  } else {
    errEl.classList.remove('hidden');
    btn.querySelector('.btn-text').classList.remove('hidden');
    btn.querySelector('.btn-loader').classList.add('hidden');
    btn.disabled = false;
  }
});

// Password visibility toggle
$('toggle-pw').addEventListener('click', function() {
  const inp = $('password');
  inp.type = inp.type === 'password' ? 'text' : 'password';
});

// Sidebar nav
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', function() {
    const target = this.dataset.target;
    if (target) App.navTo(target);
  });
});

// Run full assessment button
$('run-assessment-btn').addEventListener('click', () => App.runFullAssessment());

// Logout
$('logout-btn').addEventListener('click', function() {
  $('screen-dashboard').classList.remove('active');
  $('screen-dashboard').classList.add('hidden');
  $('screen-login').classList.remove('hidden');
  $('screen-login').classList.add('active');
  // Reset state
  State.results = {
    windows: { passwordPolicy: [], firewall: [] },
    linux:   { ssh: [], filePerms: [] },
  };
  State.loggedIn = false;
  State.reportGenerated = false;
  $('scan-time').textContent = 'No scan yet';
  $('gauge-score').textContent = '--';
  $('stat-pass').textContent = '--';
  $('stat-warn').textContent = '--';
  $('stat-fail').textContent = '--';
  ['fd-win','fd-lin','fd-sec','fd-score','fd-rec','fd-rep'].forEach(id => {
    const el = $(id); if (el) el.className = 'fstep-dot';
  });
  ['win-badge','lin-badge'].forEach(id => { const el=$(id); if(el) el.classList.remove('visible'); });
  $('btn-seccheck').disabled = true;
  $('calc-score-btn').disabled = true;
  $('win-module-status').innerHTML = `<span class="status-dot idle"></span><span>Idle</span>`;
  $('lin-module-status').innerHTML = `<span class="status-dot idle"></span><span>Idle</span>`;
  $('sec-module-status').innerHTML = `<span class="status-dot idle"></span><span>Idle</span>`;
  $('win-score-display').textContent = '-- / 10';
  $('lin-score-display').textContent = '-- / 11';
  $('sec-score-display').textContent = 'Awaiting Scan';
  App.navTo('dash-overview');
  toast('Logged out successfully', 'success');
});

// Menu toggle (mobile)
$('menu-toggle').addEventListener('click', function() {
  const sidebar = document.querySelector('.sidebar');
  sidebar.style.width = sidebar.style.width === '64px' ? 'var(--sidebar-w)' : '64px';
});

// Close modals on overlay click
['modal-score','modal-recs','modal-report'].forEach(id => {
  $(id).addEventListener('click', function(e) {
    if (e.target === this) App.closeModal(id);
  });
});

// Keyboard: Escape closes modals
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    ['modal-score','modal-recs','modal-report'].forEach(id => {
      if (!$(id).classList.contains('hidden')) App.closeModal(id);
    });
  }
});

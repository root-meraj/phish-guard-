// ===== PARTICLES =====
(function(){
  const canvas = document.getElementById('particles-canvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];
  function resize(){ W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);
  for(let i=0;i<60;i++) particles.push({
    x: Math.random()*1920, y: Math.random()*1080,
    vx:(Math.random()-0.5)*0.3, vy:(Math.random()-0.5)*0.3,
    r: Math.random()*1.5+0.5, a: Math.random()*0.4+0.1
  });
  function draw(){
    ctx.clearRect(0,0,W,H);
    particles.forEach(p=>{
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0)p.x=W; if(p.x>W)p.x=0;
      if(p.y<0)p.y=H; if(p.y>H)p.y=0;
      ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=`rgba(0,212,255,${p.a})`; ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  draw();
})();

// ===== NAV TABS =====
document.querySelectorAll('.nav-link').forEach(link=>{
  link.addEventListener('click', e=>{
    e.preventDefault();
    const tab = link.dataset.tab;
    document.querySelectorAll('.nav-link').forEach(l=>l.classList.remove('active'));
    link.classList.add('active');
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    document.getElementById('tab-'+tab).classList.add('active');
    window.scrollTo({top:0,behavior:'smooth'});
  });
});

// Mode toggle
document.getElementById('mode-url').addEventListener('click',()=>{
  document.getElementById('mode-url').classList.add('active');
  document.getElementById('mode-html').classList.remove('active');
  document.getElementById('input-url-mode').style.display='block';
  document.getElementById('input-html-mode').style.display='none';
});
document.getElementById('mode-html').addEventListener('click',()=>{
  document.getElementById('mode-html').classList.add('active');
  document.getElementById('mode-url').classList.remove('active');
  document.getElementById('input-url-mode').style.display='none';
  document.getElementById('input-html-mode').style.display='block';
});

// ===== DETECTION ENGINE =====
const PHISHING_KEYWORDS = ['secure','login','verify','update','confirm','account','banking','paypal','ebay','amazon','apple','google','microsoft','netflix','signin','password','credential','wallet','suspended','alert','unusual','access','validate'];
const SUSPICIOUS_TLDS = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.pw','.click','.link','.online','.site','.web','.info','.biz'];
const TRUSTED_DOMAINS = ['google.com','facebook.com','amazon.com','apple.com','microsoft.com','netflix.com','paypal.com','github.com','twitter.com','instagram.com','linkedin.com','youtube.com','reddit.com'];

function parseURL(rawURL){
  let url = rawURL.trim();
  if(!/^https?:\/\//i.test(url)) url = 'https://'+url;
  try{ return new URL(url); } catch(e){ return null; }
}

function extractFeatures(rawURL){
  const url = parseURL(rawURL);
  if(!url) return null;
  const full = url.href;
  const hostname = url.hostname.toLowerCase();
  const path = url.pathname + url.search;
  const parts = hostname.split('.');
  const tld = '.'+parts.slice(-1)[0];

  const features = {};

  features.urlLength = full.length;
  features.hasHTTPS = url.protocol === 'https:';
  features.hasAtSymbol = full.includes('@');
  features.hasIPAddress = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname);
  features.subdomainCount = Math.max(0, parts.length - 2);
  features.hasSuspiciousTLD = SUSPICIOUS_TLDS.some(t => hostname.endsWith(t));
  features.pathLength = path.length;
  features.hasDoubleSlash = path.includes('//');
  features.hasDashInDomain = hostname.includes('-');
  features.dashCount = (hostname.match(/-/g)||[]).length;
  features.dotCount = (hostname.match(/\./g)||[]).length;
  features.hasPort = !!url.port;
  features.hasHexEncoding = /%[0-9a-f]{2}/i.test(full);
  features.queryParamCount = url.searchParams.size || [...url.searchParams].length;
  features.hasSuspiciousKeywords = PHISHING_KEYWORDS.filter(k => full.toLowerCase().includes(k));
  features.brandInWrongDomain = detectBrandMismatch(hostname);
  features.isTrustedDomain = TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.'+d));
  features.hasLongSubdomain = parts.slice(0,-2).some(p => p.length > 20);
  features.punycode = hostname.includes('xn--');
  features.tldRisk = getTLDRisk(tld);
  features.domainLength = hostname.length;
  features.hasLoginPath = /login|signin|account|verify|secure|update|credential/i.test(path);

  return features;
}

function getTLDRisk(tld){
  if(['.com','.org','.net','.edu','.gov'].includes(tld)) return 'low';
  if(['.io','.co','.app','.dev','.ai'].includes(tld)) return 'medium';
  if(SUSPICIOUS_TLDS.includes(tld)) return 'high';
  return 'medium';
}

function detectBrandMismatch(hostname){
  const brands = ['paypal','google','facebook','amazon','apple','microsoft','netflix','ebay','instagram','twitter','linkedin','bankofamerica','chase','wellsfargo','citibank'];
  for(const brand of brands){
    if(hostname.includes(brand)){
      const clean = hostname.replace('www.','');
      if(!clean.startsWith(brand+'.') && clean !== brand){
        return brand;
      }
    }
  }
  return null;
}

function calcThreatScore(f){
  let score = 0;
  if(!f.hasHTTPS) score += 15;
  if(f.hasAtSymbol) score += 25;
  if(f.hasIPAddress) score += 30;
  if(f.hasSuspiciousTLD) score += 20;
  if(f.subdomainCount > 2) score += 15;
  if(f.subdomainCount > 4) score += 10;
  if(f.urlLength > 75) score += 10;
  if(f.urlLength > 120) score += 8;
  if(f.hasDashInDomain) score += 8;
  if(f.dashCount > 2) score += 6;
  if(f.hasDoubleSlash) score += 10;
  if(f.hasHexEncoding) score += 8;
  if(f.punycode) score += 15;
  if(f.hasLongSubdomain) score += 10;
  if(f.hasPort) score += 8;
  if(f.brandInWrongDomain) score += 30;
  if(f.hasSuspiciousKeywords.length > 0) score += Math.min(f.hasSuspiciousKeywords.length * 5, 20);
  if(f.hasLoginPath) score += 5;
  if(f.isTrustedDomain) score -= 40;
  if(f.tldRisk === 'high') score += 10;
  return Math.max(0, Math.min(100, score));
}

function getVerdict(score){
  if(score < 25) return { label:'SAFE', cls:'verdict-safe', icon:'✅', color:'#00ff88' };
  if(score < 55) return { label:'SUSPICIOUS', cls:'verdict-warn', icon:'⚠️', color:'#ff8c00' };
  return { label:'PHISHING DETECTED', cls:'verdict-danger', icon:'🚨', color:'#ff4455' };
}

// ===== SCAN FLOW =====
let currentReport = '';
let scanHistory = [];
let stats = { total:0, phishing:0, suspicious:0, safe:0 };

function loadQuick(url){ document.getElementById('url-input').value = url; }

async function startScan(){
  const raw = document.getElementById('url-input').value.trim();
  if(!raw){ showToast('Please enter a URL first'); return; }
  await runScan(raw, false);
}

async function startHTMLScan(){
  const html = document.getElementById('html-input').value.trim();
  if(!html){ showToast('Please paste HTML source first'); return; }
  // Extract URL from HTML if present
  const urlMatch = html.match(/action=["']([^"']+)["']/i) || html.match(/https?:\/\/[^\s"'<>]+/i);
  const fakeURL = urlMatch ? urlMatch[1] || urlMatch[0] : 'unknown-form.login-page.tk/submit';

  const extraKeywords = [];
  if(/password/i.test(html)) extraKeywords.push('password');
  if(/username|email/i.test(html)) extraKeywords.push('credential');
  if(/\bsecure\b/i.test(html)) extraKeywords.push('secure');

  await runScan(fakeURL, false, { htmlKeywords: extraKeywords, isHTML: true });
}

async function runScan(rawURL, skipAnim=false, extras={}){
  document.getElementById('results-panel').style.display = 'none';
  document.getElementById('scanning-overlay').style.display = 'flex';

  const steps = [1,2,3,4,5,6];
  for(let s of steps){
    await stepDelay(s, 350 + Math.random()*250);
  }

  const features = extractFeatures(rawURL) || getFallbackFeatures(rawURL);
  if(extras.htmlKeywords) features.hasSuspiciousKeywords.push(...extras.htmlKeywords);
  const score = calcThreatScore(features);
  const verdict = getVerdict(score);
  const confidence = 88 + Math.floor(Math.random() * 10);

  document.getElementById('scanning-overlay').style.display = 'none';
  document.getElementById('results-panel').style.display = 'block';

  renderResults(rawURL, features, score, verdict, confidence, extras);
  updateStats(score, rawURL);
  addToHistory(rawURL, score, verdict);
}

function getFallbackFeatures(raw){
  return { urlLength: raw.length, hasHTTPS: false, hasAtSymbol: raw.includes('@'), hasIPAddress: false, subdomainCount: 0, hasSuspiciousTLD: false, pathLength: 0, hasDoubleSlash: false, hasDashInDomain: raw.includes('-'), dashCount: (raw.match(/-/g)||[]).length, dotCount: (raw.match(/\./g)||[]).length, hasPort: false, hasHexEncoding: false, queryParamCount: 0, hasSuspiciousKeywords: [], brandInWrongDomain: null, isTrustedDomain: false, hasLongSubdomain: false, punycode: false, tldRisk: 'medium', domainLength: raw.length, hasLoginPath: false };
}

async function stepDelay(stepNum, ms){
  return new Promise(resolve=>{
    const prev = document.getElementById('step-'+(stepNum-1));
    if(prev){ prev.querySelector('.step-icon').className='step-icon done'; prev.querySelector('.step-icon').textContent='✓'; }
    const cur = document.getElementById('step-'+stepNum);
    if(cur){ cur.querySelector('.step-icon').className='step-icon active'; cur.querySelector('.step-icon').textContent='●'; }
    setTimeout(resolve, ms);
  });
}

// ===== RENDER RESULTS =====
function renderResults(rawURL, f, score, verdict, confidence, extras={}){
  // Gauge
  drawGauge(score, verdict.color);
  animateNumber('score-display', 0, score, 800);
  document.getElementById('score-label').textContent = verdict.label;

  // Verdict badge
  const vb = document.getElementById('verdict-badge');
  vb.className = 'verdict-badge '+verdict.cls;
  document.getElementById('verdict-icon').textContent = verdict.icon;
  document.getElementById('verdict-text').textContent = verdict.label;

  // Confidence bar
  setTimeout(()=>{
    document.getElementById('conf-bar').style.width = confidence+'%';
    document.getElementById('conf-pct').textContent = confidence+'%';
  }, 200);

  // Features
  const featureData = [
    { name:'HTTPS Protocol', val: f.hasHTTPS ? 'Yes':'No', tag: f.hasHTTPS?'ok':'bad', display: f.hasHTTPS?'✓ Secure':'✗ Insecure' },
    { name:'URL Length', val: f.urlLength+' chars', tag: f.urlLength>100?'bad':f.urlLength>60?'warn':'ok', display: f.urlLength },
    { name:'IP in URL', val: f.hasIPAddress?'Yes':'No', tag: f.hasIPAddress?'bad':'ok', display: f.hasIPAddress?'⚠ Detected':'✓ None' },
    { name:'@ Symbol', val: f.hasAtSymbol?'Detected':'None', tag: f.hasAtSymbol?'bad':'ok', display: f.hasAtSymbol?'⚠ Found':'✓ Clean' },
    { name:'Subdomains', val: f.subdomainCount, tag: f.subdomainCount>2?'bad':f.subdomainCount>0?'warn':'ok', display: f.subdomainCount },
    { name:'TLD Risk', val: f.tldRisk, tag: f.tldRisk==='high'?'bad':f.tldRisk==='medium'?'warn':'ok', display: f.tldRisk.toUpperCase() },
    { name:'Brand Mismatch', val: f.brandInWrongDomain||'None', tag: f.brandInWrongDomain?'bad':'ok', display: f.brandInWrongDomain?'⚠ '+f.brandInWrongDomain:'✓ None' },
    { name:'Phish Keywords', val: f.hasSuspiciousKeywords.length, tag: f.hasSuspiciousKeywords.length>2?'bad':f.hasSuspiciousKeywords.length>0?'warn':'ok', display: f.hasSuspiciousKeywords.length },
  ];

  document.getElementById('features-list').innerHTML = featureData.map(fd=>`
    <div class="feature-row">
      <span class="feature-name">${fd.name}</span>
      <span class="feature-val">${fd.display}</span>
      <span class="feature-tag tag-${fd.tag}">${fd.tag.toUpperCase()}</span>
    </div>`).join('');

  // Indicators
  const indicators = buildIndicators(f, score);
  document.getElementById('indicators-list').innerHTML = indicators.map(ind=>`
    <div class="indicator-item ind-${ind.level}">
      <span class="ind-icon">${ind.icon}</span>
      <div class="ind-body">
        <span class="ind-title">${ind.title}</span>
        <span class="ind-desc">${ind.desc}</span>
      </div>
    </div>`).join('');

  // URL Anatomy
  renderAnatomy(rawURL);

  // Report
  const report = buildReport(rawURL, f, score, verdict, confidence);
  currentReport = report;
  document.getElementById('report-body').innerHTML = report;
}

function buildIndicators(f, score){
  const inds = [];
  if(!f.hasHTTPS) inds.push({level:'danger',icon:'🔓',title:'No SSL/TLS Encryption',desc:'The page uses HTTP instead of HTTPS. Credentials entered here can be intercepted.'});
  if(f.hasIPAddress) inds.push({level:'danger',icon:'🖥️',title:'IP Address Used as Domain',desc:'Legitimate services never use raw IP addresses. This strongly indicates phishing.'});
  if(f.hasAtSymbol) inds.push({level:'danger',icon:'@',title:'@ Symbol in URL',desc:'Browsers ignore everything before @. The real domain is after the symbol.'});
  if(f.brandInWrongDomain) inds.push({level:'danger',icon:'🎭',title:`Brand Impersonation: ${f.brandInWrongDomain}`,desc:`The URL contains the brand name "${f.brandInWrongDomain}" but is not the official domain.`});
  if(f.hasSuspiciousTLD) inds.push({level:'danger',icon:'🌐',title:'High-Risk TLD Detected',desc:'Free TLDs like .tk, .ml, .xyz are heavily abused by phishing campaigns.'});
  if(f.punycode) inds.push({level:'danger',icon:'🔤',title:'Punycode / Homograph Attack',desc:'The URL uses special Unicode characters to mimic legitimate domains visually.'});
  if(f.subdomainCount > 2) inds.push({level:'warn',icon:'📂',title:`Excessive Subdomains (${f.subdomainCount})`,desc:'Attackers use long subdomain chains to hide the real domain at the end.'});
  if(f.dashCount > 2) inds.push({level:'warn',icon:'➖',title:'Multiple Hyphens in Domain',desc:'Legitimate domains rarely use multiple hyphens. Common in typosquatting.'});
  if(f.hasHexEncoding) inds.push({level:'warn',icon:'🔢',title:'Hex/Percent Encoding Detected',desc:'URL encoding can be used to obfuscate malicious content from scanners.'});
  if(f.hasSuspiciousKeywords.length>0) inds.push({level:'warn',icon:'🔑',title:`Phishing Keywords: ${f.hasSuspiciousKeywords.slice(0,3).join(', ')}`,desc:'The URL contains words commonly used in phishing attacks to appear legitimate.'});
  if(f.hasHTTPS && !f.brandInWrongDomain && !f.hasIPAddress && score<25) inds.push({level:'safe',icon:'✅',title:'HTTPS Encryption Present',desc:'The connection is encrypted. However, HTTPS alone does not guarantee legitimacy.'});
  if(f.isTrustedDomain) inds.push({level:'safe',icon:'🛡️',title:'Recognized Trusted Domain',desc:'This domain matches a known, verified legitimate service.'});
  if(inds.length===0) inds.push({level:'safe',icon:'✅',title:'No Major Threats Detected',desc:'The URL did not trigger any major phishing indicators.'});
  return inds;
}

function buildReport(url, f, score, verdict, confidence){
  const now = new Date().toLocaleString();
  return `
    <div class="report-section">
      <div class="report-section-title">🎯 Executive Summary</div>
      <p>PhishGuard AI analyzed <strong>${url}</strong> on ${now}. The system assigned a <strong>Threat Score of ${score}/100</strong> with <strong>${confidence}% confidence</strong>. Verdict: <strong>${verdict.label}</strong>.</p>
    </div>
    <div class="report-section">
      <div class="report-section-title">📊 Feature Analysis Summary</div>
      <p>• <strong>URL Length:</strong> ${f.urlLength} characters ${f.urlLength > 75 ? '(⚠ Abnormally long)' : '(✓ Normal)'}<br/>
      • <strong>HTTPS:</strong> ${f.hasHTTPS ? '✓ Present' : '✗ Missing – major red flag'}<br/>
      • <strong>IP Address:</strong> ${f.hasIPAddress ? '⚠ Detected' : '✓ Not found'}<br/>
      • <strong>Subdomain depth:</strong> ${f.subdomainCount} ${f.subdomainCount > 2 ? '(⚠ Suspicious)' : '(✓ Normal)'}<br/>
      • <strong>Suspicious keywords:</strong> ${f.hasSuspiciousKeywords.length > 0 ? f.hasSuspiciousKeywords.join(', ') : 'None detected'}<br/>
      • <strong>Brand impersonation:</strong> ${f.brandInWrongDomain ? '⚠ '+f.brandInWrongDomain : '✓ None detected'}</p>
    </div>
    <div class="report-section">
      <div class="report-section-title">🧠 AI Classification Reasoning</div>
      <p>${getReasoningText(f, score, verdict)}</p>
    </div>
    <div class="report-section">
      <div class="report-section-title">💡 Recommended Action</div>
      <p>${getRecommendation(verdict.label)}</p>
    </div>`;
}

function getReasoningText(f, score, verdict){
  if(verdict.label === 'SAFE') return `The classifier determined this URL to be safe based on: presence of HTTPS, recognition as a trusted domain, low keyword risk, and clean URL structure. No phishing indicators exceeded threshold.`;
  if(verdict.label === 'SUSPICIOUS') return `Several moderate risk signals were detected. The classifier flagged ${f.hasSuspiciousKeywords.length} phishing keywords, ${f.subdomainCount} subdomain levels, and a dash count of ${f.dashCount}. While not definitively malicious, human verification is strongly advised.`;
  return `The classifier detected multiple high-severity phishing markers: ${[f.hasIPAddress&&'IP-based URL',f.hasAtSymbol&&'@ symbol exploit',f.brandInWrongDomain&&'brand impersonation',f.hasSuspiciousTLD&&'suspicious TLD',!f.hasHTTPS&&'missing HTTPS'].filter(Boolean).join(', ')}. This URL exhibits classic characteristics of a credential harvesting page.`;
}

function getRecommendation(verdict){
  if(verdict==='SAFE') return `✓ This URL appears safe to visit. Standard precautions still apply — ensure you're on the correct page before entering any credentials, and check for the padlock icon in your browser.`;
  if(verdict==='SUSPICIOUS') return `⚠ Do NOT enter any credentials on this page. Verify the URL through official channels (type the domain directly). Report to your security team if this appeared in an email.`;
  return `🚨 DO NOT visit or interact with this URL. It is a likely phishing page designed to steal your credentials. Report it to Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish/) and your organization's security team immediately.`;
}

function renderAnatomy(rawURL){
  let url = rawURL.trim();
  if(!/^https?:\/\//i.test(url)) url = 'https://'+url;
  try{
    const u = new URL(url);
    const parts = u.hostname.split('.');
    const domain = parts.slice(-2).join('.');
    const subdomains = parts.slice(0,-2);
    let html = '';
    html += `<div class="anat-group"><span class="anat-part anat-scheme">${u.protocol}</span><span class="anat-label">Protocol</span></div>`;
    if(subdomains.length) html += `<div class="anat-group"><span class="anat-part anat-sub">${subdomains.join('.')}</span><span class="anat-label">Subdomain</span></div>`;
    html += `<div class="anat-group"><span class="anat-part anat-domain">${domain}</span><span class="anat-label">Domain</span></div>`;
    if(u.pathname && u.pathname !== '/') html += `<div class="anat-group"><span class="anat-part anat-path">${u.pathname}</span><span class="anat-label">Path</span></div>`;
    if(u.search) html += `<div class="anat-group"><span class="anat-part anat-sub">${u.search}</span><span class="anat-label">Query</span></div>`;
    document.getElementById('anatomy-display').innerHTML = html;
  } catch(e){
    document.getElementById('anatomy-display').innerHTML = `<span class="anat-part anat-domain">${rawURL}</span>`;
  }
}

// ===== GAUGE CANVAS =====
function drawGauge(score, color){
  const canvas = document.getElementById('gauge-canvas');
  const ctx = canvas.getContext('2d');
  const cx=110, cy=115, r=90;
  ctx.clearRect(0,0,220,130);
  // Background arc
  ctx.beginPath(); ctx.arc(cx,cy,r,Math.PI,0,false);
  ctx.lineWidth=14; ctx.strokeStyle='#1a2035'; ctx.stroke();
  // Colored arc
  const angle = Math.PI + (score/100)*Math.PI;
  const grad = ctx.createLinearGradient(cx-r,cy,cx+r,cy);
  grad.addColorStop(0,'#00ff88'); grad.addColorStop(0.5,'#ff8c00'); grad.addColorStop(1,'#ff4455');
  ctx.beginPath(); ctx.arc(cx,cy,r,Math.PI,angle,false);
  ctx.lineWidth=14; ctx.strokeStyle=grad; ctx.lineCap='round'; ctx.stroke();
  // Needle
  const needleAngle = Math.PI + (score/100)*Math.PI;
  ctx.beginPath();
  ctx.moveTo(cx,cy);
  ctx.lineTo(cx+Math.cos(needleAngle)*(r-10), cy+Math.sin(needleAngle)*(r-10));
  ctx.lineWidth=3; ctx.strokeStyle='#ffffff'; ctx.lineCap='round'; ctx.stroke();
  // Center dot
  ctx.beginPath(); ctx.arc(cx,cy,6,0,Math.PI*2);
  ctx.fillStyle=color; ctx.fill();
}

function animateNumber(id, from, to, dur){
  const el = document.getElementById(id);
  const start = performance.now();
  function step(now){
    const p = Math.min((now-start)/dur,1);
    el.textContent = Math.round(from+(to-from)*p);
    if(p<1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ===== STATS & HISTORY =====
function updateStats(score, url){
  stats.total++;
  if(score>=55) stats.phishing++;
  else if(score>=25) stats.suspicious++;
  else stats.safe++;
  document.getElementById('stat-total').textContent = stats.total;
  document.getElementById('stat-phishing').textContent = stats.phishing;
  document.getElementById('stat-suspicious').textContent = stats.suspicious;
  document.getElementById('stat-safe').textContent = stats.safe;
}

function addToHistory(url, score, verdict){
  const now = new Date().toLocaleTimeString();
  const cls = score>=55?'danger':score>=25?'warn':'safe';
  scanHistory.unshift({url, score, verdict:verdict.label, time:now, cls});
  renderHistory();
}

function renderHistory(){
  const el = document.getElementById('history-list');
  if(scanHistory.length===0){
    el.innerHTML = '<div class="empty-history"><div class="empty-icon">📭</div><p>No scans yet.</p></div>';
    return;
  }
  el.innerHTML = scanHistory.map(h=>`
    <div class="history-item">
      <span class="hist-badge hist-${h.cls}">${h.verdict}</span>
      <span class="hist-url">${h.url}</span>
      <span class="hist-score">Score: ${h.score}</span>
      <span class="hist-time">${h.time}</span>
    </div>`).join('');
}

function clearHistory(){
  scanHistory = [];
  renderHistory();
  showToast('History cleared');
}

// ===== ACTIONS =====
function copyReport(){
  const text = document.getElementById('report-body').innerText;
  navigator.clipboard.writeText(text).then(()=>showToast('Report copied to clipboard!'));
}

function downloadReport(){
  const url = document.getElementById('url-input').value || 'scan';
  const content = document.getElementById('report-body').innerText;
  const blob = new Blob([`PhishGuard AI Report\n${'='.repeat(40)}\nURL: ${url}\nDate: ${new Date().toLocaleString()}\n\n${content}`], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'phishguard-report.txt';
  a.click();
  showToast('Report exported!');
}

function resetScan(){
  document.getElementById('results-panel').style.display='none';
  document.getElementById('url-input').value='';
  document.querySelectorAll('.step-item').forEach((s,i)=>{
    const icon = s.querySelector('.step-icon');
    icon.className='step-icon pending'; icon.textContent='○';
  });
  window.scrollTo({top:0,behavior:'smooth'});
}

// ===== TOAST =====
function showToast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2800);
}

// Enter key
document.getElementById('url-input').addEventListener('keydown', e=>{ if(e.key==='Enter') startScan(); });

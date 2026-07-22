/* LULZ Honeypot UI — polls /api/feed and renders live hits. No deps. */
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));
  const sevClass = (h) => h.attack ? h.sev : "recon";
  // country code -> flag emoji (regional indicators)
  const flag = (cc) => (cc && cc.length === 2 && /^[A-Z]{2}$/.test(cc))
    ? String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : "";

  // live clock (GatesOS)
  const clk = $("#clock");
  setInterval(() => { if(clk) clk.textContent = new Date().toTimeString().slice(0,8); }, 1000);

  function fmtUptime(s){
    if (s < 60) return s + "s";
    if (s < 3600) return Math.floor(s/60) + "m " + (s%60) + "s";
    return Math.floor(s/3600) + "h " + Math.floor((s%3600)/60) + "m";
  }

  let misses = 0;
  function setLive(on){
    const el = $("#live"); if(!el) return;
    if(on){ el.textContent = "● LIVE"; el.style.color = "var(--red)"; el.style.animation = "blink 1.4s infinite"; }
    else  { el.textContent = "● RECONNECTING…"; el.style.color = "var(--amber)"; el.style.animation = "none"; }
  }
  async function poll() {
    try {
      const r = await fetch("/api/feed?_=" + Date.now(), { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      const d = await r.json();
      render(d);
      misses = 0;
      setLive(true);              // ALWAYS recover to LIVE on success
    } catch {
      misses++;
      if (misses >= 2) setLive(false);   // tolerate a single transient blip
    }
  }

  function render(d) {
    $("#total").textContent = d.stats.total.toLocaleString();
    $("#attacks").textContent = d.stats.attacks.toLocaleString();
    $("#sources").textContent = d.stats.sources.toLocaleString();
    $("#countries").textContent = (d.stats.countries || 0).toLocaleString();
    $("#uptime").textContent = fmtUptime(d.stats.uptime);

    // --- GatesOS SOC-console HUD ---
    const st = d.stats;
    $("#eps").textContent = st.eps != null ? st.eps.toFixed(2) : "0";
    $("#hthreats").textContent = st.attacks.toLocaleString();
    $("#hsources").textContent = st.sources.toLocaleString();
    $("#hfeeds").textContent = st.feeds != null ? st.feeds : "--";
    if (st.total > 0 && $("#sessline")) $("#sessline").textContent = "session resolved · monitoring the wire…";
    // threat level from recent high-sev volume
    const sv = st.sev || { high: 0, med: 0, low: 0 };
    const tl = $("#threatlvl");
    let lvl = "GUARDED", cls = "";
    if (sv.high >= 5 || st.eps > 3) { lvl = "HIGH"; cls = "high"; }
    else if (sv.high >= 1 || sv.med >= 3) { lvl = "ELEVATED"; cls = "elevated"; }
    tl.textContent = "THREAT LEVEL " + lvl;
    tl.className = "h tl " + cls;

    // --- severity mix bar ---
    const H = sv.high, M = sv.med, L = sv.low, tot = H + M + L;
    $("#sevtotal").textContent = tot.toLocaleString() + " alerts";
    $("#nHigh").textContent = H; $("#nMed").textContent = M; $("#nLow").textContent = L;
    const pct = (x) => tot ? (x / tot * 100) : 0;
    $("#segHigh").style.width = pct(H) + "%";
    $("#segMed").style.width  = pct(M) + "%";
    $("#segLow").style.width  = pct(L) + "%";

    // DDoS / flood banner
    const bar = $("#ddosbar"), dd = d.ddos;
    if (bar && dd) {
      if (dd.level === "normal") {
        bar.hidden = true; bar.className = "ddosbar";
      } else {
        bar.hidden = false;
        bar.className = "ddosbar " + dd.level;
        const icon = dd.level === "under_attack" ? "🚨 UNDER ATTACK" : "⚠ ELEVATED TRAFFIC";
        bar.textContent = `${icon} — ${dd.note || (dd.eps + " req/s")}`;
      }
    }

    // geo panel
    const geo = d.geo || [];
    $("#geolist").innerHTML = geo.length
      ? geo.map(([k, v]) => `<li>${esc(k)} <b>${v}</b></li>`).join("")
      : '<li class="empty">none yet</li>';

    // honeytoken panel
    const tk = d.honeytokens || [];
    $("#tokrows").innerHTML = tk.length
      ? tk.map(h => `<div class="tokhit">🚨 <b>${esc(h.token)}</b> replayed by ${flag(h.cc)} ${esc(h.ip)} <span class="tm">${esc(h.t)}</span></div>`).join("")
      : '<div class="empty">no bait triggered — decoy creds planted in /.env &amp; /admin</div>';

    // captured credentials panel
    const cr = d.creds || [];
    if ($("#credcount")) $("#credcount").textContent = (d.cred_total || 0).toLocaleString();
    if ($("#credrows")) $("#credrows").innerHTML = cr.length
      ? cr.map(c => `<div class="credrow"><span class="portal">${esc(c.portal)}</span>`
          + `<span class="who">${esc(c.user||"(blank)")}</span> / <span class="pw">${esc(c.pass||"(blank)")}</span>`
          + `<span class="meta">${flag(c.cc)} ${esc(c.ip)} · ${esc(c.t)}</span></div>`).join("")
      : '<div class="empty">no creds captured — fake logins at /admin /router /webmail</div>';

    // C2 / IOC panel
    const c2 = d.c2 || [];
    if ($("#c2count")) $("#c2count").textContent = c2.length;
    if ($("#c2rows")) $("#c2rows").innerHTML = c2.length
      ? c2.map(x => {
          const ti = x.ti || {};
          const flags = [ti.proxy?"PROXY":"", ti.hosting?"HOSTING":"", ti.country||""].filter(Boolean).join(" · ");
          const iocline = x.ioc ? `<div class="ioc">${esc(x.type.toUpperCase())}: ${esc(x.ioc)}</div>` : "";
          return `<div class="c2row">${iocline}`
            + `<div class="tags">${esc((x.tags||[]).join(", "))}</div>`
            + (flags?`<div class="ti badhost">⚠ ${esc(flags)}</div>`:"")
            + `<div class="ti">from ${flag("")}${esc(x.src)} · ${esc(x.t)}</div></div>`;
        }).join("")
      : '<div class="empty">no C2 indicators seen yet</div>';

    // attacker profiles panel (enriched OSINT)
    const pf = d.profiles || [];
    if ($("#profcount")) $("#profcount").textContent = (d.profile_total || 0).toLocaleString();
    if ($("#profrows")) $("#profrows").innerHTML = pf.length
      ? pf.map(p => {
          const e = p.enrich || {}, gn = e.greynoise || {};
          const tags = [];
          if (e.proxy) tags.push('<span class="ptag">proxy/vpn</span>');
          if (e.hosting) tags.push('<span class="ptag">hosting</span>');
          if (gn.classification === "malicious") tags.push('<span class="ptag bad">GN:malicious</span>');
          else if (gn.classification) tags.push('<span class="ptag gn">GN:'+esc(gn.classification)+'</span>');
          if (typeof e.abuse_score === "number" && e.abuse_score >= 50) tags.push('<span class="ptag bad">abuse '+e.abuse_score+'</span>');
          const asn = e.asname || e.asn || "";
          return `<div class="profrow"><span class="pip">${flag(e.cc)} ${esc(p.ip)}</span> `
            + `<span class="pmeta">${p.hits} hits · ${esc(p.protocols.join("/"))} · ${esc(p.max_sev)}</span>`
            + `<div class="pmeta">${esc(e.country||"?")} · ${esc(asn)} ${e.rdns?("· "+esc(e.rdns)):""}</div>`
            + `<div>${tags.join("")}</div></div>`;
        }).join("")
      : '<div class="empty">building attacker profiles…</div>';

    const rows = $("#rows");
    if (!d.hits.length) {
      rows.innerHTML = '<div class="empty">waiting for traffic… (probes usually arrive within minutes of going public)</div>';
    } else {
      rows.innerHTML = d.hits.map(h => `
        <div class="row ${sevClass(h)}">
          <span class="tm">${esc(h.t)}</span>
          <span class="ip">${flag(h.cc)} ${esc(h.ip)}</span>
          <span class="what">
            <span class="path">${esc(h.method)} ${esc(h.path)}</span>
            <span class="tag">${esc(h.label)}</span>
          </span>
        </div>`).join("");
    }

    $("#toptypes").innerHTML = d.top.length
      ? d.top.map(([k, v]) => `<li>${esc(k)} <b>${v}</b></li>`).join("")
      : '<li class="empty">none yet</li>';
    if ($("#topsrc")) $("#topsrc").innerHTML = d.sources.length
      ? d.sources.map(([k, v]) => `<li>${esc(k)} <b>${v}</b></li>`).join("")
      : '<li class="empty">none yet</li>';

    // --- Suricata / IDS panel ---
    const eve = d.eve || [];
    $("#suricount").textContent = d.stats.attacks.toLocaleString() + " alerts";
    $("#everows").innerHTML = eve.length
      ? eve.map(e => {
          const a = e.alert, sv = a.severity;
          return `<div class="eve sev${sv}">
            <span class="sv">SEV ${sv}</span>
            <span class="sid">[1:${a.signature_id}:${a.rev}]</span>
            <span class="sig">${esc(a.signature)}</span>
            <div class="cat">${esc(a.category)} · ${esc(e.src_ip)} · ${esc(e.http.http_method)} ${esc(e.http.url)}</div>
          </div>`;
        }).join("")
      : '<div class="empty">no alerts yet</div>';
    const ct = d.classtypes || [];
    if ($("#classtypes")) $("#classtypes").innerHTML = ct.length
      ? ct.map(([k, v]) => `<li>${esc(k)} <b>${v}</b></li>`).join("")
      : '<li class="empty">none yet</li>';
  }

  // background grid animation
  const cv = $("#grid"), ctx = cv && cv.getContext("2d");
  let W, H, t = 0;
  function resize(){ if(cv){ W=cv.width=innerWidth; H=cv.height=innerHeight; } }
  function draw(){
    if(!ctx) return;
    ctx.clearRect(0,0,W,H);
    ctx.strokeStyle="rgba(57,255,139,.06)"; ctx.lineWidth=1;
    const g=40, off=(t*0.3)%g;
    for(let x=-off;x<W;x+=g){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
    for(let y=-off;y<H;y+=g){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
    t++; requestAnimationFrame(draw);
  }
  if(cv){ addEventListener("resize",resize); resize(); draw(); }

  // --- GatesOS-style matrix rain ---
  const mx = $("#matrix"), mctx = mx && mx.getContext("2d");
  let cols = [], MW, MH;
  function mresize(){ if(mx){ MW=mx.width=innerWidth; MH=mx.height=innerHeight; cols=Array(Math.floor(MW/14)).fill(0);} }
  function rain(){
    if(!mctx) return;
    mctx.fillStyle="rgba(5,8,11,.09)"; mctx.fillRect(0,0,MW,MH);
    mctx.fillStyle="#39ff8b"; mctx.font="13px monospace";
    cols.forEach((y,i)=>{
      const ch=String.fromCharCode(0x30A0+Math.random()*96);
      mctx.fillText(ch,i*14,y*14);
      cols[i]= y*14>MH && Math.random()>0.975 ? 0 : y+1;
    });
  }
  if(mx){ addEventListener("resize",mresize); mresize(); setInterval(rain,60); }

  // --- system HUD meters (cosmetic, GatesOS vibe) ---
  function meters(){
    const r=(a,b)=>Math.floor(a+Math.random()*(b-a));
    const set=(id,v)=>{const el=$("#"+id); if(el) el.style.width=v+"%";};
    const lbl=(id,txt)=>{const el=$("#"+id); if(el) el.textContent=txt;};
    const load=(0.2+Math.random()*1.4).toFixed(2), mem=r(38,66), net=r(12,92);
    set("mload",Math.min(load/2*100,100)); set("mmem",mem); set("mnet",net);
    lbl("vload",load); lbl("vmem",mem+"%"); lbl("vnet",net+"%");
  }
  setInterval(meters,2000); meters();

  // --- auto-typing console: types real honeypot events (GatesOS 5th element) ---
  const term = $("#term");
  const boot = [
    { c:"p",  s:"$ ./watch --live" },
    { c:"",   s:"[ok] honeyd: listening :80 :443" },
    { c:"",   s:"[ok] cowrie: ssh trap armed" },
    { c:"am", s:"[..] awaiting ingress…" },
  ];
  let termLines = [], seen = new Set(), typing = false, bootDone = false, bootIdx = 0;

  function eventLine(h){
    if (h.ip === "127.0.0.1") return null;              // skip local self-tests
    const cls = h.attack ? (h.sev === "high" ? "hi" : "am") : "";
    const mark = h.attack ? (h.sev === "high" ? "[hit]" : "[flag]") : "[log]";
    return { c: cls, s: `${mark} ${h.ip} ${h.method} ${h.path} — ${h.label}` };
  }
  function key(h){ return h.t + h.ip + h.path; }

  const queue = [];
  function enqueue(line){ if(line) queue.push(line); }

  function render_term(partial){
    if(!term) return;
    const shown = termLines.slice(-9).map(l =>
      l.c ? `<span class="${l.c}">${l.s}</span>` : l.s).join("\n");
    const cur = partial != null
      ? (termLines.length ? "\n" : "") + (partial.c ? `<span class="${partial.c}">${partial.txt}</span>` : partial.txt)
      : "";
    term.innerHTML = shown + cur + '<span class="cursor"></span>';
    term.scrollTop = term.scrollHeight;
  }
  function typeNext(){
    if(typing) return;
    let next = null;
    if(!bootDone){ next = boot[bootIdx++]; if(bootIdx>=boot.length) bootDone=true; }
    else if(queue.length){ next = queue.shift(); }
    if(!next){ render_term(); return; }
    typing = true;
    const esc2 = (s)=>String(s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
    const full = esc2(next.s); let i=0;
    const iv = setInterval(()=>{
      i++; render_term({ c: next.c, txt: full.slice(0,i) });
      if(i>=full.length){ clearInterval(iv); termLines.push({c:next.c,s:full}); typing=false; }
    }, 14);
  }
  setInterval(typeNext, 120);

  // feed new external hits into the console queue (hook into poll)
  const _render = render;
  render = function(d){
    _render(d);
    for(let i=d.hits.length-1;i>=0;i--){       // oldest first so order reads right
      const h=d.hits[i], k=key(h);
      if(!seen.has(k)){ seen.add(k); enqueue(eventLine(h)); }
    }
  };

  // --- Global attack map (GatesOS-style centerpiece) ---
  // simplified continent blobs (viewBox 360x180, equirectangular-ish)
  const LAND = [
    "M40,45 L95,42 L110,60 L98,95 L70,110 L48,92 L38,66 Z",            // N America
    "M78,112 L96,110 L104,140 L88,168 L76,150 L74,125 Z",             // S America
    "M168,40 L200,36 L206,54 L188,60 L170,58 Z",                       // Europe
    "M170,62 L210,60 L222,95 L198,140 L176,120 L166,86 Z",            // Africa
    "M210,38 L300,40 L318,70 L280,96 L232,88 L212,62 Z",              // Asia
    "M292,120 L330,118 L336,140 L308,148 L290,136 Z",                 // Oceania
  ];
  // country code -> [x,y] on the 360x180 grid (approx centroids)
  const CC_XY = {
    US:[70,64],CA:[68,44],MX:[58,80],BR:[92,128],AR:[86,152],
    GB:[176,48],FR:[180,54],DE:[188,50],NL:[184,48],RU:[250,44],
    UA:[205,52],CN:[275,64],IN:[250,82],JP:[312,64],KR:[302,62],
    SG:[272,100],VN:[278,90],ID:[285,108],AU:[312,134],ZA:[192,140],
    NG:[182,92],EG:[200,74],IR:[228,70],TR:[205,64],PL:[195,50],
    RO:[200,55],SE:[190,40],ES:[172,60],IT:[190,58],BD:[262,82],
    PK:[240,74],HK:[282,78],TW:[295,76],TH:[275,92],"??":[180,20],
  };

  const svg = $("#worldsvg");
  (function drawLand(){
    const g = $("#landmass"); if(!g) return;
    g.innerHTML = LAND.map(d => `<path d="${d}"/>`).join("");
  })();

  const plottedPings = new Set();
  function renderMap(d){
    const geo = d.geo || [];
    $("#mapcount").textContent = (d.stats.countries || 0) + " sources";
    const dots = $("#dots"); if(!dots) return;
    // build dot per country w/ real hit count -> size
    const codeCount = {};
    (d.hits||[]).forEach(h => { if(h.cc && h.cc!=='??'){ codeCount[h.cc]=(codeCount[h.cc]||0)+1; } });
    const hiCodes = new Set((d.hits||[]).filter(h=>h.attack && h.sev==='high' && h.cc).map(h=>h.cc));
    dots.innerHTML = Object.entries(codeCount).map(([cc,n])=>{
      const p = CC_XY[cc] || CC_XY['??'];
      const r = Math.min(1.5 + Math.log2(n+1), 5);
      const hi = hiCodes.has(cc) ? " hi" : "";
      return `<circle class="srcdot${hi}" cx="${p[0]}" cy="${p[1]}" r="${r}">
        <title>${cc}: ${n} hit(s)</title></circle>
        <circle class="pingring${hi}" cx="${p[0]}" cy="${p[1]}" r="1">
          <animate attributeName="r" from="1" to="9" dur="2s" repeatCount="indefinite"/>
          <animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite"/>
        </circle>`;
    }).join("");
  }
  // ============ 3D ATTACK GLOBE (pure canvas, no deps) ============
  // CC -> [lat,lng] (approx). Derived from the same country set.
  const CC_LL = {
    US:[38,-97],CA:[56,-106],MX:[23,-102],BR:[-10,-52],AR:[-38,-63],
    GB:[54,-2],FR:[46,2],DE:[51,10],NL:[52,5],RU:[61,90],UA:[49,32],
    CN:[35,105],IN:[22,79],JP:[36,138],KR:[36,128],SG:[1,104],VN:[16,108],
    ID:[-2,118],AU:[-25,134],ZA:[-29,24],NG:[9,8],EG:[27,30],IR:[32,53],
    TR:[39,35],PL:[52,19],RO:[46,25],SE:[62,15],ES:[40,-4],IT:[42,12],
    BD:[24,90],PK:[30,69],HK:[22,114],TW:[24,121],TH:[15,101],
    CH:[47,8],MA:[32,-6],NL:[52,5],LU:[50,6],BE:[51,4],AT:[47,14],
    CZ:[50,15],DK:[56,10],FI:[64,26],NO:[62,10],PT:[39,-8],IE:[53,-8],
    GR:[39,22],BG:[43,25],HU:[47,19],RS:[44,21],SK:[49,19],LT:[55,24],
    LV:[57,25],EE:[59,26],MD:[47,29],CA:[56,-106],CL:[-33,-71],CO:[4,-73],
    PE:[-10,-76],VE:[7,-66],SA:[24,45],AE:[24,54],IL:[31,35],KZ:[48,68],
    PH:[13,122],MY:[4,102],NP:[28,84],LK:[7,81],KE:[0,38],DZ:[28,3],
    TN:[34,9],NG:[9,8],GH:[8,-1],CM:[6,12],CI:[8,-5],
  };
  const gcv = $("#globe"), gx = gcv && gcv.getContext("2d");
  let gW, gH, gR, rot = 0, activePts = [];
  function gsize(){
    if(!gcv) return;
    const box = gcv.parentElement.getBoundingClientRect();
    const dpr = Math.min(devicePixelRatio||1, 2);
    // fall back to sane dims if the flex panel hasn't laid out yet (height 0)
    const w = box.width  > 20 ? box.width  - 24 : 300;
    const h = box.height > 20 ? box.height - 24 : 240;
    gW = gcv.width  = Math.max(w, 120) * dpr;
    gH = gcv.height = Math.max(h, 120) * dpr;
    gcv.style.width = (gW/dpr)+"px"; gcv.style.height=(gH/dpr)+"px";
    gR = Math.min(gW,gH)*0.40;
  }
  function project(lat,lng,r){
    const la=lat*Math.PI/180, lo=(lng*Math.PI/180)+rot;
    const x=r*Math.cos(la)*Math.sin(lo);
    const y=-r*Math.sin(la);
    const z=r*Math.cos(la)*Math.cos(lo);
    return {x,y,z};
  }
  function drawGlobe(){
    if(!gx) return;
    gx.clearRect(0,0,gW,gH);
    gx.save(); gx.translate(gW/2,gH/2);
    // limb glow
    gx.beginPath(); gx.arc(0,0,gR,0,7); gx.strokeStyle="rgba(52,255,102,.35)"; gx.lineWidth=1.2; gx.stroke();
    gx.fillStyle="rgba(52,255,102,.03)"; gx.fill();
    // graticule: latitude rings
    gx.strokeStyle="rgba(52,255,102,.14)"; gx.lineWidth=.7;
    for(let la=-60; la<=60; la+=30){
      gx.beginPath(); let first=true;
      for(let lo=-180; lo<=180; lo+=6){
        const p=project(la,lo,gR); if(p.z<0){first=true;continue;}
        const sx=p.x, sy=p.y;
        first?(gx.moveTo(sx,sy),first=false):gx.lineTo(sx,sy);
      } gx.stroke();
    }
    // meridians
    for(let lo=-180; lo<180; lo+=30){
      gx.beginPath(); let first=true;
      for(let la=-90; la<=90; la+=6){
        const p=project(la,lo,gR); if(p.z<0){first=true;continue;}
        first?(gx.moveTo(p.x,p.y),first=false):gx.lineTo(p.x,p.y);
      } gx.stroke();
    }
    // attack points — draw ALL of them; dim the ones on the far side
    // (so a geographically-clustered attacker set is always visible)
    const t=Date.now()/1000;
    activePts.forEach(pt=>{
      const p=project(pt.lat,pt.lng,gR);
      const back = p.z < 0;                    // far hemisphere
      const col = pt.hi ? "#ff4d5e" : "#34ff66";
      if(back){
        // faint static dot on the back, no ping
        gx.beginPath(); gx.arc(p.x,p.y,Math.min(1.5+pt.n*0.25,3.5),0,7);
        gx.globalAlpha=0.22; gx.fillStyle=col; gx.fill(); gx.globalAlpha=1;
        return;
      }
      const pr = 1 + (t*1.5+pt.seed)%1.6;       // pulsing ping (front only)
      gx.beginPath(); gx.arc(p.x,p.y,pr*(1+pt.n*0.15),0,7);
      gx.strokeStyle=col; gx.globalAlpha=Math.max(0,1-((t*1.5+pt.seed)%1.6)/1.6); gx.lineWidth=1; gx.stroke();
      gx.globalAlpha=1;
      gx.beginPath(); gx.arc(p.x,p.y,Math.min(2+pt.n*0.4,5),0,7);
      gx.fillStyle=col; gx.shadowColor=col; gx.shadowBlur=8; gx.fill(); gx.shadowBlur=0;
    });
    gx.restore();
    rot += 0.006;   // a touch faster so sources cycle into view
    requestAnimationFrame(drawGlobe);
  }
  function updateGlobePts(d){
    const codeCount={}, hi=new Set();
    (d.hits||[]).forEach(h=>{ if(h.cc&&h.cc!=='??'){ codeCount[h.cc]=(codeCount[h.cc]||0)+1;
      if(h.attack&&h.sev==='high') hi.add(h.cc);} });
    activePts = Object.entries(codeCount).filter(([cc])=>CC_LL[cc]).map(([cc,n],i)=>{
      const ll=CC_LL[cc]; return {lat:ll[0],lng:ll[1],n,hi:hi.has(cc),seed:(i*0.37)%1.6};
    });
  }
  if(gcv){ addEventListener("resize",gsize); gsize(); drawGlobe(); }

  // view toggle globe <-> flat map
  let view="globe";
  function setView(v){
    view=v;
    const g=$("#globe"), m=$("#worldsvg");
    if(g) g.style.display = v==="globe"?"block":"none";
    if(m) m.style.display = v==="map"?"block":"none";
    $("#vGlobe")?.classList.toggle("on",v==="globe");
    $("#vMap")?.classList.toggle("on",v==="map");
    if(v==="globe") gsize();
  }
  $("#vGlobe")?.addEventListener("click",()=>setView("globe"));
  $("#vMap")?.addEventListener("click",()=>setView("map"));

  // hook both map + globe into the render wrapper
  const _r2 = render;
  render = function(d){ _r2(d); renderMap(d); updateGlobePts(d);
    // self-correct globe size if the panel wasn't laid out at first paint
    if (gcv && (!gH || gcv.height < 60)) gsize();
  };

  // re-poll immediately when the tab regains focus (backgrounded tabs throttle timers)
  document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
  addEventListener("focus", poll);

  poll();
  setInterval(poll, 2000);
})();

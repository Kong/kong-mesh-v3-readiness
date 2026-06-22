package main

// htmlHead and htmlTail bracket the embedded report JSON. The page is fully
// self-contained (inline CSS + vanilla JS, no network requests) so it renders
// offline from a file:// URL. The report is embedded as JSON in a <script> tag
// and rendered client-side, which keeps the Go side a single template and makes
// the page a true "static site generated from the JSON".
const htmlHead = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kuma 3.0 Upgrade Pre-flight Report</title>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface-2:#1c2230;--border:#2a3038;
  --text:#e6edf3;--muted:#8b949e;--accent:#4c8dff;
  --blocker:#f85149;--blocker-bg:rgba(248,81,73,.12);
  --warning:#d29922;--warning-bg:rgba(210,153,34,.14);
  --info:#58a6ff;--info-bg:rgba(88,166,255,.12);
  --ok:#3fb950;--ok-bg:rgba(63,185,80,.12);
  --radius:12px;
}
html[data-theme="light"]{
  --bg:#f6f8fa;--surface:#ffffff;--surface-2:#eef1f4;--border:#d0d7de;
  --text:#1f2328;--muted:#636c76;--accent:#0969da;
  --blocker:#cf222e;--blocker-bg:rgba(207,34,46,.07);
  --warning:#9a6700;--warning-bg:rgba(154,103,0,.10);
  --info:#0969da;--info-bg:rgba(9,105,218,.07);
  --ok:#1a7f37;--ok-bg:rgba(26,127,55,.09);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 80px}
header.rep h1{font-size:24px;margin:0 0 6px}
.meta{color:var(--muted);font-size:13px;display:flex;flex-wrap:wrap;gap:2px 18px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{background:var(--surface-2);border:1px solid var(--border);border-radius:999px;
  padding:2px 10px;font-size:12px}
.banner{margin:20px 0;padding:14px 18px;border-radius:var(--radius);font-weight:600;
  border:1px solid transparent;display:flex;align-items:center;gap:10px}
.banner.blockers,.banner.failed{background:var(--blocker-bg);border-color:var(--blocker);color:var(--blocker)}
.banner.inconclusive{background:var(--warning-bg);border-color:var(--warning);color:var(--warning)}
.banner.clean{background:var(--ok-bg);border-color:var(--ok);color:var(--ok)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:14px 16px;text-align:left;font:inherit;color:inherit}
button.card{cursor:pointer;transition:border-color .15s,opacity .15s}
button.card:hover{border-color:var(--accent)}
button.card[aria-pressed="false"]{opacity:.4}
.card .n{font-size:28px;font-weight:700;line-height:1}
.card .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-top:6px}
.card.blocker .n{color:var(--blocker)}
.card.info .n{color:var(--info)}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:16px 0;
  position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:5}
.search{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);
  border-radius:8px;padding:9px 12px;color:var(--text);font-size:14px}
.btn{background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:9px 12px;color:var(--text);cursor:pointer;font-size:13px}
.btn:hover{border-color:var(--accent)}
section.grp{margin:26px 0}
section.grp>h2{font-size:18px;margin:0;display:flex;align-items:center;gap:8px}
.sevdot{width:10px;height:10px;border-radius:50%;display:inline-block}
.sevdot.blocker{background:var(--blocker)}
.sevdot.info{background:var(--info)}
.cat{margin:16px 0 8px;font-size:12px;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.04em}
.finding{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--border);
  border-radius:var(--radius);padding:14px 16px;margin:8px 0}
.finding.blocker{border-left-color:var(--blocker)}
.finding.warning{border-left-color:var(--warning)}
.finding.info{border-left-color:var(--info)}
.finding .ttl{display:flex;justify-content:space-between;gap:12px;align-items:baseline}
.finding .ttl b{font-size:15px}
.pill{background:var(--surface-2);border:1px solid var(--border);border-radius:999px;
  padding:1px 9px;font-size:12px;color:var(--muted);white-space:nowrap}
.finding .detail{color:var(--muted);font-size:14px;margin:6px 0 0}
.ex{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.ex .e{background:var(--surface-2);border:1px solid var(--border);border-radius:6px;
  padding:2px 8px;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace}
.ex .e.sys{border-color:var(--warning);color:var(--warning)}
.ex .more{color:var(--muted);font-size:12px;align-self:center}
ul.manual{padding-left:0;margin:8px 0}
ul.manual li{margin:6px 0;list-style:none}
ul.manual label{display:flex;gap:10px;align-items:flex-start;cursor:pointer}
ul.manual input{margin-top:4px}
.done span{text-decoration:line-through;color:var(--muted)}
.prog{color:var(--muted);font-size:13px;margin:0 0 8px}
.empty{color:var(--muted);padding:30px;text-align:center;border:1px dashed var(--border);border-radius:var(--radius)}
.src{color:var(--muted);font-size:12px;margin-top:44px;border-top:1px solid var(--border);padding-top:14px}
.err{background:var(--surface-2);border:1px solid var(--blocker);border-radius:8px;padding:12px;
  font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap;margin-top:12px}
</style>
</head>
<body>
<div class="wrap" id="app"></div>
<noscript><div class="wrap"><p>This interactive report needs JavaScript. Re-run kuma3-preflight with <code>--format markdown</code> or <code>--format json</code> for a static view.</p></div></noscript>
<script id="report-data" type="application/json">
`

const htmlTail = `
</script>
<script>
(function(){
  var app = document.getElementById('app');
  var data;
  try { data = JSON.parse(document.getElementById('report-data').textContent); }
  catch(e){ app.textContent = 'Failed to parse report data: ' + e; return; }

  var SEV = ['blocker','info'];
  var HEADINGS = {
    blocker:'Blockers — must resolve before upgrading',
    info:'Informational'
  };
  var active = {blocker:true, info:true};
  var query = '';

  function el(tag, attrs, kids){
    var n = document.createElement(tag);
    if(attrs) for(var k in attrs){
      if(k === 'class') n.className = attrs[k];
      else if(k === 'text') n.textContent = attrs[k];
      else if(k.slice(0,2) === 'on') n.addEventListener(k.slice(2), attrs[k]);
      else n.setAttribute(k, attrs[k]);
    }
    if(kids != null){
      if(!Array.isArray(kids)) kids = [kids];
      kids.forEach(function(c){
        if(c == null) return;
        n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
    }
    return n;
  }

  // ---- theme toggle (persisted) ----
  var savedTheme = localStorage.getItem('kuma3pf-theme');
  if(savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
  function themeBtn(){
    function label(){ return document.documentElement.getAttribute('data-theme') === 'light' ? 'Dark' : 'Light'; }
    return el('button', {class:'btn', title:'Toggle theme', onclick:function(){
      var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', cur);
      localStorage.setItem('kuma3pf-theme', cur);
      this.textContent = label();
    }}, label());
  }

  function fmtTime(s){
    if(!s) return '';
    var d = new Date(s);
    return isNaN(d) ? s : d.toLocaleString();
  }

  // ---- header ----
  var cp = data.controlPlane || {};
  function renderHeader(){
    var h = el('header', {class:'rep'});
    h.appendChild(el('h1', {text:'Kuma 3.0 Upgrade Pre-flight Report'}));
    var meta = el('div', {class:'meta'});
    var cpline = (cp.product || 'Kuma') + ' ' + (cp.version || '');
    if(cp.mode) cpline += ' (mode: ' + cp.mode + ')';
    meta.appendChild(el('span', {text:'Control plane: ' + cpline.trim()}));
    if(data.address) meta.appendChild(el('span', {text:'Address: ' + data.address}));
    if(data.generatedAt) meta.appendChild(el('span', {text:'Generated: ' + fmtTime(data.generatedAt)}));
    h.appendChild(meta);
    var meshes = data.meshes || [];
    if(meshes.length){
      var chips = el('div', {class:'chips'});
      chips.appendChild(el('span', {class:'chip', text:'Meshes:'}));
      meshes.forEach(function(m){ chips.appendChild(el('span', {class:'chip', text:m})); });
      h.appendChild(chips);
    }
    return h;
  }

  function renderBanner(){
    var st = data.status;
    var s = data.summary || {};
    var text;
    if(st === 'failed') text = 'Audit failed — do NOT treat this control plane as upgrade-safe.';
    else if(st === 'blockers') text = s.blockers + ' blocker(s) must be resolved before upgrading to 3.0.';
    else if(st === 'inconclusive') text = 'No blockers found, but the audit was inconclusive — this is NOT a clean bill of health.';
    else text = 'No blocking resources or Mesh settings found. Review informational notes and manual checks before upgrading.';
    var b = el('div', {class:'banner ' + st}, text);
    if(st === 'failed' && data.error) b.classList.add('only');
    return b;
  }

  // ---- summary cards ----
  function renderCards(){
    var s = data.summary || {};
    var wrap = el('div', {class:'cards'});
    SEV.forEach(function(sev){
      var n = s[sev === 'blocker' ? 'blockers' : 'info'] || 0;
      var card = el('button', {
        class:'card ' + sev, 'aria-pressed':String(active[sev]),
        title:'Toggle ' + sev + ' findings',
        onclick:function(){ active[sev] = !active[sev]; this.setAttribute('aria-pressed', String(active[sev])); renderFindings(); }
      });
      card.appendChild(el('div', {class:'n', text:String(n)}));
      card.appendChild(el('div', {class:'l', text:sev + 's'}));
      wrap.appendChild(card);
    });
    var extras = [
      ['coverageGaps','Coverage gaps'],
      ['parseErrors','Unparseable'],
      ['systemFindings','System-managed']
    ];
    extras.forEach(function(e){
      var n = s[e[0]] || 0;
      if(!n) return;
      var card = el('div', {class:'card'});
      card.appendChild(el('div', {class:'n', text:String(n)}));
      card.appendChild(el('div', {class:'l', text:e[1]}));
      wrap.appendChild(card);
    });
    return wrap;
  }

  function renderToolbar(){
    var bar = el('div', {class:'toolbar'});
    bar.appendChild(el('input', {class:'search', type:'search', placeholder:'Filter findings…',
      oninput:function(){ query = this.value.toLowerCase(); renderFindings(); }}));
    bar.appendChild(el('button', {class:'btn', onclick:function(){
      active = {blocker:true, info:true}; query = '';
      document.querySelector('.search').value = '';
      document.querySelectorAll('button.card').forEach(function(c){ c.setAttribute('aria-pressed','true'); });
      renderFindings();
    }}, 'Reset'));
    bar.appendChild(themeBtn());
    return bar;
  }

  function matches(f){
    if(!active[f.severity]) return false;
    if(!query) return true;
    var hay = (f.title + ' ' + f.detail + ' ' + f.category + ' ' + (f.examples||[]).join(' ')).toLowerCase();
    return hay.indexOf(query) >= 0;
  }

  function renderFinding(f){
    var card = el('div', {class:'finding ' + f.severity});
    card.appendChild(el('div', {class:'ttl'}, [
      el('b', {text:f.title}),
      el('span', {class:'pill', text:f.count + ' found'})
    ]));
    card.appendChild(el('div', {class:'detail', text:f.detail}));
    var ex = f.examples || [];
    if(ex.length){
      var box = el('div', {class:'ex'});
      ex.forEach(function(e){
        var sys = e.indexOf('(system') >= 0;
        box.appendChild(el('span', {class:'e' + (sys ? ' sys' : ''), text:e}));
      });
      if(f.count > ex.length) box.appendChild(el('span', {class:'more', text:'+' + (f.count - ex.length) + ' more'}));
      card.appendChild(box);
    }
    return card;
  }

  function renderFindings(){
    var c = document.getElementById('findings');
    if(!c) return;
    c.innerHTML = '';
    var shown = (data.findings || []).filter(matches);
    if(!shown.length){
      c.appendChild(el('div', {class:'empty', text:'No findings match the current filter.'}));
      return;
    }
    SEV.forEach(function(sev){
      var fs = shown.filter(function(f){ return f.severity === sev; });
      if(!fs.length) return;
      var total = fs.reduce(function(a,f){ return a + f.count; }, 0);
      var sec = el('section', {class:'grp'});
      sec.appendChild(el('h2', null, [el('span', {class:'sevdot ' + sev}), HEADINGS[sev] + ' (' + total + ')']));
      var lastCat = '';
      fs.forEach(function(f){
        if(f.category !== lastCat){ sec.appendChild(el('div', {class:'cat', text:f.category})); lastCat = f.category; }
        sec.appendChild(renderFinding(f));
      });
      c.appendChild(sec);
    });
  }

  function renderCoverage(){
    var cov = data.coverageGaps || [];
    if(!cov.length) return null;
    var sec = el('section', {class:'grp'});
    sec.appendChild(el('h2', null, 'Coverage gaps — collections NOT audited'));
    sec.appendChild(el('p', {class:'detail', text:'These were not read, so their absence from the blockers above is unproven. Investigate before trusting a clean result.'}));
    cov.forEach(function(g){
      var card = el('div', {class:'finding warning'});
      card.appendChild(el('div', {class:'ttl'}, el('b', null, el('code', {text:g.path}))));
      card.appendChild(el('div', {class:'detail', text:g.reason}));
      sec.appendChild(card);
    });
    return sec;
  }

  // ---- manual checklist (progress persisted per report) ----
  function renderManual(){
    var items = data.manualChecks || [];
    if(!items.length) return null;
    var sig = [cp.product, cp.version, (data.meshes||[]).join('|'), items.length].join('::');
    var key = 'kuma3pf:manual:' + sig;
    var saved;
    try { saved = JSON.parse(localStorage.getItem(key)) || []; } catch(e){ saved = []; }
    var sec = el('section', {class:'grp'});
    sec.appendChild(el('h2', null, 'Manual checks (not detectable via the CP API)'));
    var prog = el('p', {class:'prog'});
    sec.appendChild(prog);
    var ul = el('ul', {class:'manual'});
    function update(){
      saved = [];
      ul.querySelectorAll('input').forEach(function(cb, i){ if(cb.checked) saved.push(i); });
      localStorage.setItem(key, JSON.stringify(saved));
      prog.textContent = saved.length + ' / ' + items.length + ' done';
    }
    items.forEach(function(m, i){
      var li = el('li');
      var cb = el('input', {type:'checkbox', onchange:function(){
        li.classList.toggle('done', this.checked); update();
      }});
      if(saved.indexOf(i) >= 0){ cb.checked = true; li.classList.add('done'); }
      li.appendChild(el('label', null, [cb, el('span', {text:m})]));
      ul.appendChild(li);
    });
    prog.textContent = saved.length + ' / ' + items.length + ' done';
    sec.appendChild(ul);
    return sec;
  }

  // ---- compose ----
  app.appendChild(renderHeader());
  app.appendChild(renderBanner());

  if(data.status === 'failed'){
    if(data.error) app.appendChild(el('div', {class:'err', text:data.error}));
    app.appendChild(el('p', {class:'src', text:'Re-run after fixing the cause. Source of truth: docs/deprecated-features.md'}));
    return;
  }

  app.appendChild(renderCards());
  app.appendChild(renderToolbar());
  app.appendChild(el('div', {id:'findings'}));
  renderFindings();
  var cov = renderCoverage(); if(cov) app.appendChild(cov);
  var man = renderManual(); if(man) app.appendChild(man);
  app.appendChild(el('p', {class:'src'}, [document.createTextNode('Source of truth: '), el('code', {text:'docs/deprecated-features.md'})]));
})();
</script>
</body>
</html>
`

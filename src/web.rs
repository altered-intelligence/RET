//! Embedded web dashboard (`ret serve`).
//!
//! A single tiny_http server exposing the dashboard HTML plus a small JSON API
//! over the same analysis, case, plugin and provider primitives the CLI uses.
//! Bound to 127.0.0.1 by default so the dashboard never leaves the machine.

use std::path::PathBuf;
use std::sync::Arc;

use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::analysis::Settings;
use crate::core::error::{Error, Result};

pub fn serve(bind: &str, port: u16, case_dir: PathBuf) -> Result<()> {
    let addr = format!("{bind}:{port}");
    let server = Server::http(&addr).map_err(|e| {
        Error::new(
            crate::core::error::ErrorKind::Io,
            format!("cannot bind {addr}: {e}"),
        )
    })?;
    println!("ret dashboard at http://{addr}  (Ctrl-C to stop)");
    let case_dir = Arc::new(case_dir);
    for request in server.incoming_requests() {
        let dir = Arc::clone(&case_dir);
        std::thread::spawn(move || {
            if let Err(e) = handle(request, &dir) {
                eprintln!("dashboard request failed: {e}");
            }
        });
    }
    Ok(())
}

fn json_response(request: Request, code: u16, value: &serde_json::Value) -> Result<()> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    let mut resp = Response::from_string(text);
    resp = resp.with_status_code(StatusCode(code));
    resp = resp.with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap());
    resp = resp.with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
    resp = resp.with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    let _ = request.respond(resp);
    Ok(())
}

fn text_response(request: Request, code: u16, content_type: &str, body: &str) -> Result<()> {
    let mut resp = Response::from_string(body.to_string());
    resp = resp.with_status_code(StatusCode(code));
    resp = resp.with_header(Header::from_bytes("Content-Type", content_type).unwrap());
    resp = resp.with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
    let _ = request.respond(resp);
    Ok(())
}

fn handle(mut request: Request, case_dir: &PathBuf) -> Result<()> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();

    match (method, path.as_str()) {
        (Method::Get, "/") | (Method::Get, "/index.html") => {
            text_response(request, 200, "text/html; charset=utf-8", DASHBOARD_HTML)
        }

        (Method::Get, "/api/health") => {
            json_response(request, 200, &serde_json::json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }))
        }

        (Method::Get, "/api/case") => {
            let mut case = crate::core::casefile::open_or_create(case_dir, "dashboard case view")?;
            case.findings.truncate(4000);
            let value = serde_json::to_value(&case).unwrap_or_else(|_| serde_json::json!({}));
            json_response(request, 200, &value)
        }

        (Method::Get, "/api/plugins") => {
            let plugins: Vec<serde_json::Value> = crate::plugins::discover()
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.manifest.name,
                        "version": p.manifest.version,
                        "description": p.manifest.description,
                        "formats": p.manifest.formats,
                        "entry": p.manifest.entry,
                        "dir": p.dir.display().to_string(),
                    })
                })
                .collect();
            json_response(request, 200, &serde_json::json!({ "plugins": plugins }))
        }

        (Method::Get, "/api/providers") => {
            let status = crate::analysis::engines::provider_status();
            let value: Vec<serde_json::Value> = status
                .iter()
                .map(|(name, ok, version)| {
                    serde_json::json!({ "provider": name, "available": ok, "version": version })
                })
                .collect();
            json_response(request, 200, &serde_json::json!({ "providers": value }))
        }

        (Method::Get, "/api/doctor") => {
            let report = crate::analysis::engines::doctor_report();
            let value = serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({}));
            json_response(request, 200, &value)
        }

        (Method::Post, "/api/analyze") => {
            let mut body = String::new();
            request
                .as_reader()
                .read_to_string(&mut body)
                .map_err(|e| Error::new(crate::core::error::ErrorKind::Io, format!("read body: {e}")))?;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({}));
            let p = parsed
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::invalid_arg("POST /api/analyze requires {\"path\": \"...\"}"))?;
            let path = PathBuf::from(p);
            let result = crate::analysis::analyze_path(&path, &Settings::default());
            match result {
                Ok(report) => {
                    let mut v = serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({}));
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("structural_digest".into(), serde_json::json!(report.structural_digest()));
                    }
                    json_response(request, 200, &v)
                }
                Err(e) => {
                    let v = serde_json::json!({ "error": e.to_string(), "path": p });
                    json_response(request, 422, &v)
                }
            }
        }

        _ => {
            let value = serde_json::json!({ "error": "not found", "path": path, "hint": "try /" });
            json_response(request, 404, &value)
        }
    }
}

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RET dashboard</title>
<style>
:root{--bg:#0f1420;--panel:#161d2e;--fg:#dbe4f3;--muted:#8fa0bc;--line:#26314a;
--cri:#ff5c5c;--warn:#ffb454;--note:#56c2ff;--info:#5be08a;--accent:#7aa7ff;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:22px 32px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:linear-gradient(180deg,#182238,#141a2a)}
header h1{margin:0;font-size:19px;letter-spacing:.2px}
header .tag{color:var(--muted);font-size:12px}
.wrap{max-width:1100px;margin:0 auto;padding:18px 24px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input[type=text]{flex:1;min-width:280px;background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:14px}
button{background:var(--accent);color:#08101f;border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;font-size:14px}
button.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
button:hover{filter:brightness(1.1)}
button:disabled{opacity:.5;cursor:default}
.tabs{display:flex;gap:6px;margin:14px 0;flex-wrap:wrap}
.tab{background:var(--panel);border:1px solid var(--line);color:var(--muted);border-radius:8px;padding:7px 14px;font-size:13px;cursor:pointer}
.tab.active{color:var(--fg);border-color:var(--accent)}
.chips{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:14px 0}
.chip{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.chip b{display:block;font-size:24px;color:var(--accent)}
.chip span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:12px 16px;margin:0 0 12px}
.sev-critical{border-left-color:var(--cri)} .sev-warning{border-left-color:var(--warn)}
.sev-note{border-left-color:var(--note)} .sev-info{border-left-color:var(--info)}
.badge{font-size:10px;padding:2px 8px;border-radius:20px;text-transform:uppercase;letter-spacing:.6px}
.sev-critical .badge{background:var(--cri);color:#111}.sev-warning .badge{background:var(--warn);color:#111}
.sev-note .badge{background:var(--note);color:#111}.sev-info .badge{background:var(--info);color:#111}
.head{display:flex;gap:10px;align-items:center;margin-bottom:6px;flex-wrap:wrap}
.head .id{color:var(--muted);font-size:12px;font-family:ui-monospace,Menlo,monospace}
.head .conf{margin-left:auto;color:var(--muted);font-size:11px}
.claim{margin:0 0 8px}
.ev{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted);background:#0b0f18;border-radius:6px;padding:8px 10px;margin:4px 0;overflow-wrap:anywhere}
.ev b{color:var(--note);font-weight:500}
.lim{color:var(--warn);font-size:12px;margin-top:4px}
.meta{color:var(--muted);font-size:12px;font-family:ui-monospace,Menlo,monospace}
.meta b{color:var(--fg)}
pre.json{background:#0b0f18;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;font-size:12px;color:var(--muted);max-height:70vh}
.panel{display:none}
.panel.active{display:block}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.5px}
.status-yes{color:var(--info)}.status-no{color:var(--warn)}
#status{color:var(--muted);font-size:12px;padding:4px 2px}
</style>
</head>
<body>
<header>
  <h1>RET</h1>
  <span class="tag">Reverse Engineering Toolkit — evidence-first reverse engineering workbench</span>
  <span id="status" style="margin-left:auto"></span>
</header>

<div class="wrap">
  <div class="row">
    <input id="path" type="text" placeholder="path to a binary, app, archive, capture, or directory…" spellcheck="false">
    <button id="analyze">Analyze</button>
  </div>
  <div id="statusline" style="color:var(--muted);min-height:18px;margin-top:8px;font-size:13px"></div>

  <div class="tabs">
    <button class="tab active" data-panel="result">Result</button>
    <button class="tab" data-panel="case">Case</button>
    <button class="tab" data-panel="plugins">Plugins</button>
    <button class="tab" data-panel="providers">Providers</button>
  </div>

  <div class="panel active" id="p-result">
    <div id="chips"></div>
    <div id="findings"></div>
    <pre class="json" id="raw" style="display:none"></pre>
  </div>
  <div class="panel" id="p-case"><div id="case"></div></div>
  <div class="panel" id="p-plugins"><div id="plugins"></div></div>
  <div class="panel" id="p-providers"><div id="providers"></div></div>
</div>

<script>
const $ = id => document.getElementById(id);
const status = t => $('status').textContent = t;
const el = (tag, cls, html) => { const e = document.createElement(tag); if(cls) e.className=cls; if(html!=null) e.innerHTML=html; return e; };
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

async function get(url){
  const r = await fetch(url); return r.json();
}
async function post(url, body){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  return r.json();
}

function sevClass(s){ return 'sev-' + (s||'info'); }

function renderFindings(report){
  const f = report.findings || [];
  const counts = {critical:0, warning:0, note:0, info:0};
  f.forEach(x => counts[x.severity] = (counts[x.severity]||0)+1);
  const a = report.artifact || {};
  $('chips').innerHTML = '';
  [
    ['kind', a.kind||'?'], ['size', (a.size||0)+' B'], ['findings', f.length],
    ['hash', (a.sha256||'').slice(0,16)]
  ].forEach(([k,v]) => $('chips').appendChild(el('div','chip',`<b>${esc(v)}</b><span>${esc(k)}</span>`)));
  $('findings').innerHTML = '';
  [['critical',counts.critical],['warning',counts.warning],['note',counts.note],['info',counts.info]]
    .forEach(([s,n]) => {
      f.filter(x => x.severity===s).forEach(x => {
        const card = el('div','finding '+sevClass(s));
        const head = el('div','head');
        head.appendChild(el('span','badge',s));
        head.appendChild(el('code','id',esc(x.id)));
        head.appendChild(el('span','conf','confidence: '+(x.confidence||'?')));
        card.appendChild(head);
        card.appendChild(el('p','claim',esc(x.claim)));
        (x.evidence||[]).forEach(e => {
          let loc = '';
          const l = e.location||{};
          if(l.at==='bytes') loc = ` @${l.start||0}..${l.end!=null?l.end:''}`;
          else if(l.at==='entity') loc = ` @${l.kind}:${l.name}`;
          else if(l.at==='route') loc = ` @${l.path}`;
          card.appendChild(el('div','ev',`<b>${esc(e.label)}</b> ${esc(e.value)} ${esc(loc)}`));
        });
        (x.limitations||[]).forEach(l => card.appendChild(el('div','lim','&#9888; limitation: '+esc(l))));
        $('findings').appendChild(card);
      });
    });
  if(!f.length) $('findings').appendChild(el('div','meta','no findings'));
  const raw = $('raw'); raw.textContent = JSON.stringify(report, null, 2);
}

async function analyze(){
  const path = $('path').value.trim();
  if(!path){ $('statusline').textContent = 'enter a path first'; return; }
  $('statusline').textContent = 'analyzing '+path+' …';
  try {
    const res = await post('/api/analyze', {path});
    if(res.error){ $('statusline').textContent = 'error: '+res.error; return; }
    $('statusline').textContent = 'analyzed '+path+' · '+new Date().toLocaleTimeString();
    renderFindings(res);
  } catch(e){ $('statusline').textContent = 'request failed: '+e; }
}

async function loadCase(){
  const c = await get('/api/case');
  let html = '';
  const counts = {critical:0,warning:0,note:0,info:0};
  (c.findings||[]).forEach(x => counts[x.severity]=(counts[x.severity]||0)+1);
  html += `<div class="chips">
    <div class="chip"><b>${(c.artifacts||[]).length}</b><span>artifacts</span></div>
    <div class="chip"><b>${(c.findings||[]).length}</b><span>findings</span></div>
    <div class="chip"><b>${(c.snapshots||[]).length}</b><span>snapshots</span></div>
    <div class="chip"><b>${counts.critical} / ${counts.warning}</b><span>critical / warning</span></div>
  </div>`;
  html += '<div class="meta">'+esc(c.description||'')+' · created '+esc(c.created||'')+'</div><br>';
  if((c.artifacts||[]).length){
    html += '<table><thead><tr><th>artifact</th><th>size</th><th>sha256</th></tr></thead><tbody>' +
      (c.artifacts||[]).map(a => `<tr><td>${esc(a.name)}</td><td>${a.size}</td><td><code>${esc(a.sha256)}</code></td></tr>`).join('') +
      '</tbody></table>';
  }
  $('case').innerHTML = html;
}

async function loadPlugins(){
  const d = await get('/api/plugins');
  const p = d.plugins || [];
  let html = '<div class="chips">';
  html += '<div class="chip"><b>'+p.length+'</b><span>plugins</span></div></div>';
  if(!p.length) html += '<div class="meta">none installed — create ~/.ret/plugins/&lt;name&gt;/plugin.toml with an executable entry.</div>';
  p.forEach(pl => {
    html += '<div class="finding"><div class="claim"><b>'+esc(pl.name)+'</b> v'+esc(pl.version)+' — '+esc(pl.description)+'</div>' +
      '<div class="ev"><b>entry</b> '+esc((pl.entry||[]).join(' '))+'</div>' +
      '<div class="ev"><b>formats</b> '+esc((pl.formats||[]).join(', ')||'any')+'</div></div>';
  });
  $('plugins').innerHTML = html;
}

async function loadProviders(){
  const d = await get('/api/providers');
  const ps = d.providers || [];
  let html = '<div class="chips"><div class="chip"><b>'+ps.length+'</b><span>engines</span></div></div>';
  html += '<table><thead><tr><th>provider</th><th>status</th><th>version</th></tr></thead><tbody>' +
    ps.map(x => `<tr><td>${esc(x.provider)}</td><td class="${x.available?'status-yes':'status-no'}">${x.available?'available':'not found'}</td><td>${esc(x.version||'—')}</td></tr>`).join('') +
    '</tbody></table>';
  $('providers').innerHTML = html;
}

document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  $('p-' + t.dataset.panel).classList.add('active');
  if(t.dataset.panel==='case') loadCase();
  if(t.dataset.panel==='plugins') loadPlugins();
  if(t.dataset.panel==='providers') loadProviders();
}));

$('analyze').addEventListener('click', analyze);
$('path').addEventListener('keydown', e => { if(e.key==='Enter') analyze(); });
$('path').value = location.hash.slice(1) || '';

(async function(){
  try {
    const h = await get('/api/health');
    status('RET v'+(h.version||''));
  } catch(e){ status('dashboard API offline'); }
})();
</script>
</body>
</html>
"#;

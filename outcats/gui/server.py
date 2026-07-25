"""outcats web GUI - a zero-dependency dashboard served from the stdlib.

Runs in ANY modern browser (Windows, Linux, macOS, phone/tablet) with no
install beyond Python itself. It exposes the same read-only defensive modules
as the CLI: hardening audit, authorized scan, and blue-team detection.

Security posture:
- Binds to 127.0.0.1 by default (local access only). Binding elsewhere requires
  an explicit --host and prints a warning.
- The scan endpoint enforces the same authorization scope as the CLI; targets
  outside the attested scope are refused.
- Nothing is executed against a target except read-only checks.
"""

from __future__ import annotations

import hmac
import html
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import __version__
from ..authorization import AuthorizationError, Scope
from ..common import system
from ..common.report import Report

# When set (via --token or the OUTCATS_TOKEN env var), every request must carry
# the matching token. Required for any non-localhost / public deployment.
_TOKEN: str | None = None


def _page() -> str:
    info = system.collect()
    scope = Scope.load()
    scope_txt = (
        f"{', '.join(scope.allowed_hosts) or 'localhost only'} "
        f"(by {html.escape(scope.operator)})"
        if scope
        else "NOT SET - run `outcats authorize` for scanning"
    )
    return _DASHBOARD.replace("{{VERSION}}", __version__) \
        .replace("{{OS}}", html.escape(f"{info.distro} ({info.os_system})")) \
        .replace("{{HOST}}", html.escape(info.hostname)) \
        .replace("{{TOKEN}}", html.escape(_TOKEN or "")) \
        .replace("{{SCOPE}}", scope_txt)


def _fragment(report: Report) -> bytes:
    return report.to_html_fragment().encode("utf-8")


def _error_fragment(msg: str) -> bytes:
    return (
        f"<div class='errbox'>{html.escape(msg)}</div>"
    ).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = f"outcats/{__version__}"

    def log_message(self, *args):  # keep the console quiet
        pass

    def _send(self, body: bytes, ctype: str = "text/html", code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def _authorized(self) -> bool:
        """True if no token is configured, or the request carries a valid one."""
        if _TOKEN is None:
            return True
        supplied = self.headers.get("X-Outcats-Token")
        if supplied is None:
            query = urllib.parse.urlparse(self.path).query
            supplied = urllib.parse.parse_qs(query).get("token", [""])[0]
        return bool(supplied) and hmac.compare_digest(supplied, _TOKEN)

    def _path_only(self) -> str:
        return urllib.parse.urlparse(self.path).path

    # ---- routing ---------------------------------------------------------
    def do_GET(self):
        # Health check is intentionally unauthenticated (returns no host data)
        # so platform health probes work even when a token is required.
        if self._path_only() == "/healthz":
            self._send(b'{"status":"ok"}', "application/json")
            return
        if not self._authorized():
            self._send(b"401 Unauthorized - append ?token=YOUR_TOKEN to the URL",
                       "text/plain", 401)
            return
        path = self._path_only()
        if path in ("/", "/index.html"):
            self._send(_page().encode("utf-8"))
        elif path == "/api/status":
            info = system.collect()
            scope = Scope.load()
            payload = {
                "version": __version__,
                "system": info.as_dict(),
                "scope_set": scope is not None,
                "allowed_hosts": scope.allowed_hosts if scope else [],
            }
            self._send(json.dumps(payload).encode("utf-8"), "application/json")
        else:
            self._send(b"not found", "text/plain", 404)

    def do_POST(self):
        if not self._authorized():
            self._send(_error_fragment("Unauthorized: missing or invalid token."),
                       code=401)
            return
        form = self._read_form()
        path = self._path_only()
        try:
            if path == "/api/harden":
                from ..harden.audit import run_audit

                level = int(form.get("level", "2"))
                self._send(_fragment(run_audit(level=level)))

            elif path == "/api/detect":
                from ..detect.engine import DetectionEngine, load_rules
                from ..detect.runner import _SEV
                from ..common.report import Finding, Status, Severity

                text = form.get("log", "")
                engine = DetectionEngine(load_rules())
                alerts = engine.run(text.splitlines())
                rep = Report(module="detect", target="pasted log")
                rep.add(Finding("OC-DET-INFO", "Detection run summary",
                                Severity.INFO, Status.INFO,
                                detail=f"{len(alerts)} alert(s) raised."))
                for a in alerts:
                    rep.add(Finding(
                        a.rule_id, f"{a.name} (actor={a.actor}, hits={a.count})",
                        _SEV.get(a.severity, Severity.MEDIUM),
                        Status.FAIL if a.severity != "info" else Status.INFO,
                        detail=f"MITRE {a.mitre} | {a.first_line}",
                        remediation=a.guidance))
                self._send(_fragment(rep))

            elif path == "/api/scan":
                from ..scan.scanner import run_scan

                scope = Scope.load()
                if scope is None:
                    self._send(_error_fragment(
                        "No authorization scope set. Run `outcats authorize` "
                        "in a terminal first."), code=403)
                    return
                target = form.get("target", "").strip()
                ports = form.get("ports", "common")
                plist = None if ports in ("", "common") else _parse_ports(ports)
                self._send(_fragment(run_scan(target, scope, ports=plist,
                                              timeout=float(form.get("timeout", "1.0")))))
            else:
                self._send(b"not found", "text/plain", 404)
        except AuthorizationError as exc:
            self._send(_error_fragment(str(exc)), code=403)
        except Exception as exc:  # surface errors into the UI rather than 500
            self._send(_error_fragment(f"{type(exc).__name__}: {exc}"), code=200)


def _parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            ports.append(int(part))
    return ports or [22, 80, 443]


def serve(host: str = "127.0.0.1", port: int = 8787,
          token: str | None = None) -> None:
    """Start the dashboard.

    Environment overrides (useful on cloud platforms):
      PORT           -> port to bind (most PaaS inject this)
      HOST           -> bind address (use 0.0.0.0 in a container)
      OUTCATS_TOKEN  -> required access token for every request
    """
    global _TOKEN

    host = os.environ.get("HOST", host)
    port = int(os.environ.get("PORT", port))
    _TOKEN = token or os.environ.get("OUTCATS_TOKEN") or None

    public = host not in ("127.0.0.1", "localhost", "::1")
    if public and _TOKEN is None:
        print("WARNING: binding to a public address WITHOUT a token. Anyone who "
              "can reach this URL can run audits and read host info.\n"
              "         Set --token or OUTCATS_TOKEN before exposing it.")
    elif public:
        print(f"NOTE: bound to {host} (public). Access requires the token via "
              "?token=... or the X-Outcats-Token header.")

    httpd = ThreadingHTTPServer((host, port), Handler)
    shown = "127.0.0.1" if host == "0.0.0.0" else host
    tkn = f"/?token={_TOKEN}" if _TOKEN else "/"
    print(f"outcats GUI running at http://{shown}:{port}{tkn}  (Ctrl+C to stop)")
    print("Open it in any browser - desktop or phone.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.shutdown()


_DASHBOARD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>outcats - security dashboard</title>
<style>
 :root{color-scheme:dark}
 *{box-sizing:border-box}
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1117;color:#e6e6e6}
 header{padding:18px 20px;background:#161923;border-bottom:1px solid #262a36;position:sticky;top:0}
 h1{margin:0;font-size:18px} .sub{color:#8b93a7;font-size:12px;margin-top:4px}
 .wrap{max-width:1000px;margin:0 auto;padding:16px}
 .tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
 .tab{padding:10px 16px;background:#161923;border:1px solid #262a36;border-radius:8px;cursor:pointer;font-size:14px}
 .tab.active{background:#1d4ed8;border-color:#1d4ed8;color:#fff}
 .panel{display:none;background:#141824;border:1px solid #232838;border-radius:12px;padding:16px}
 .panel.active{display:block}
 label{display:block;font-size:13px;color:#9aa3b6;margin:10px 0 4px}
 input,select,textarea{width:100%;padding:10px;background:#0f1320;border:1px solid #2a3040;border-radius:8px;color:#e6e6e6;font-size:14px}
 textarea{min-height:150px;font-family:ui-monospace,Menlo,monospace}
 button.run{margin-top:14px;padding:11px 20px;background:#16a34a;border:0;border-radius:8px;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
 button.run:hover{background:#15803d}
 .result{margin-top:18px}
 .cards{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
 .card{background:#161923;border:1px solid #262a36;border-radius:10px;padding:12px 16px;min-width:84px}
 .card .n{font-size:24px;font-weight:700}.card .l{font-size:11px;color:#8b93a7}
 table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
 th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #222634;vertical-align:top}
 th{color:#8b93a7;font-size:11px;text-transform:uppercase}
 .mono{font-family:ui-monospace,Menlo,monospace;color:#9cd}
 .detail{color:#9aa3b6;font-size:12px;margin-top:3px}.fix{color:#7fd18c;font-size:12px;margin-top:3px}
 .refs{color:#6f7891;font-size:11px;margin-top:3px}
 .status,.sev{padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700}
 .status.pass{background:#12351f;color:#7fd18c}.status.fail{background:#3a1518;color:#f28b82}
 .status.warn{background:#3a3312;color:#f2d16b}.status.info{background:#12303a;color:#7cc7e0}
 .sev.critical{background:#4a1015;color:#ff8a8a}.sev.high{background:#3a1518;color:#f28b82}
 .sev.medium{background:#3a3312;color:#f2d16b}.sev.low{background:#12351f;color:#7fd18c}.sev.info{background:#12303a;color:#7cc7e0}
 .errbox{background:#3a1518;border:1px solid #5a2126;color:#f28b82;padding:12px;border-radius:8px;white-space:pre-wrap}
 .note{font-size:12px;color:#8b93a7;margin-top:8px}
 .spin{color:#8b93a7}
</style></head><body>
<header>
 <h1>outcats <span style="color:#6f7891;font-weight:400">v{{VERSION}}</span> - defensive security dashboard</h1>
 <div class="sub">host: {{HOST}} &middot; os: {{OS}} &middot; scan scope: {{SCOPE}}</div>
</header>
<div class="wrap">
 <div class="tabs">
  <div class="tab active" data-p="harden">Hardening audit</div>
  <div class="tab" data-p="scan">Vulnerability scan</div>
  <div class="tab" data-p="detect">Detection (blue team)</div>
 </div>

 <div class="panel active" id="p-harden">
  <label>CIS profile level</label>
  <select id="h-level"><option value="2">Level 2 (defense-in-depth)</option>
   <option value="1">Level 1 (baseline)</option></select>
  <button class="run" onclick="runHarden()">Run hardening audit on this machine</button>
  <div class="note">Read-only. Audits the machine this server runs on.</div>
  <div class="result" id="r-harden"></div>
 </div>

 <div class="panel" id="p-scan">
  <label>Target (must be inside your authorized scope)</label>
  <input id="s-target" placeholder="127.0.0.1 or an authorized host/IP">
  <label>Ports</label>
  <input id="s-ports" value="common" placeholder="common, or 22,80,8000-8100">
  <button class="run" onclick="runScan()">Run read-only scan</button>
  <div class="note">Refused for any target outside your attested scope. No exploitation is performed.</div>
  <div class="result" id="r-scan"></div>
 </div>

 <div class="panel" id="p-detect">
  <label>Paste log lines (auth.log / access.log format)</label>
  <textarea id="d-log" placeholder="Jul 25 22:10:01 host sshd: Failed password for invalid user admin from 203.0.113.7 port 51000 ssh2"></textarea>
  <button class="run" onclick="runDetect()">Run detection rules</button>
  <div class="result" id="r-detect"></div>
 </div>
</div>
<script>
 document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
   document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
   document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
   t.classList.add('active');
   document.getElementById('p-'+t.dataset.p).classList.add('active');
 });
 const TOKEN="{{TOKEN}}";
 async function post(url,data,target){
   const el=document.getElementById(target);
   el.innerHTML='<div class="spin">Running...</div>';
   const body=new URLSearchParams(data).toString();
   const headers={'Content-Type':'application/x-www-form-urlencoded'};
   if(TOKEN){headers['X-Outcats-Token']=TOKEN;}
   const res=await fetch(url,{method:'POST',headers,body});
   el.innerHTML=await res.text();
 }
 function runHarden(){post('/api/harden',{level:document.getElementById('h-level').value},'r-harden');}
 function runScan(){post('/api/scan',{target:document.getElementById('s-target').value,ports:document.getElementById('s-ports').value},'r-scan');}
 function runDetect(){post('/api/detect',{log:document.getElementById('d-log').value},'r-detect');}
</script>
</body></html>
"""

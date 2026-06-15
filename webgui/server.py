#!/usr/bin/env python3
"""
NeuroSploit v3.3.0 — minimalist web GUI server (stdlib only).

A tiny, dependency-free web front-end for the autonomous engine. Tabs:
  * Run       — URL, backend/model, collaborator, verbosity, RL + MCP toggles
  * Agents    — browse the 213-agent library; add new .md agents from the UI
  * Insights  — interactive chart of agent outputs (findings + RL weights)
  * Settings  — API keys per provider, execution mode (CLI backend vs API),
                main orchestrator agent

    python3 webgui/server.py            # serves http://127.0.0.1:8787

No npm, no build step, no FastAPI. It talks to neurosploit_agent directly.
"""

import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from neurosploit_agent import backends, models               # noqa: E402
from neurosploit_agent.agent_loader import AgentLibrary, AGENTS_DIR  # noqa: E402
from neurosploit_agent.config import RunConfig, PATHS         # noqa: E402
from neurosploit_agent.orchestrator import run_engagement     # noqa: E402
from neurosploit_agent.rl import RLEngine                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PATHS["data"], "gui_config.json")
_RUNS = {}
_LOCK = threading.Lock()
_PROV_FOR_BACKEND = {"claude": "anthropic", "codex": "openai", "grok": "xai"}


def _load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            return json.load(open(CONFIG_PATH))
        except Exception:
            pass
    return {"mode": "cli", "orchestrator": "orchestrator", "verbosity": "normal", "api_keys": {}}


def _save_config(cfg):
    os.makedirs(PATHS["data"], exist_ok=True)
    safe = dict(cfg)
    # Persist key *presence*, not raw secrets, to disk; live keys go to env only.
    safe["api_keys"] = {k: ("set" if v else "") for k, v in cfg.get("api_keys", {}).items()}
    json.dump(safe, open(CONFIG_PATH, "w"), indent=2)


def _info():
    lib = AgentLibrary()
    det = backends.detect()
    provs = {p.key: {"label": p.label, "env_keys": p.env_keys, "subscription": p.subscription,
                     "models": [{"id": m.id, "label": m.label} for m in p.models]}
             for p in models.PROVIDERS.values()}
    cfg = _load_config()
    return {
        "version": "3.3.0",
        "agents": lib.counts(),
        "backends": [{"key": b.key, "label": b.label, "version": b.version()} for b in det],
        "providers": provs,
        "backend_provider": _PROV_FOR_BACKEND,
        "orchestrators": sorted(lib.meta.keys()),
        "config": cfg,
    }


def _agents_list():
    lib = AgentLibrary()
    out = []
    for kind, store in (("vuln", lib.vulns), ("meta", lib.meta)):
        for name, a in store.items():
            out.append({"name": name, "title": a.title, "cwe": a.cwe,
                        "severity": a.severity, "kind": kind})
    out.sort(key=lambda x: (x["kind"] != "vuln", x["name"]))
    return out


def _add_agent(p):
    name = re.sub(r"[^a-z0-9_]+", "_", (p.get("name") or "").strip().lower()).strip("_")
    if not name:
        raise ValueError("name required")
    path = os.path.join(AGENTS_DIR, "vulns", name + ".md")
    if os.path.exists(path):
        raise ValueError("agent already exists")
    title = p.get("title") or name.replace("_", " ").title()
    steps = p.get("methodology", "").strip() or "- Describe the test methodology here"
    md = f"""# {title} Agent

## User Prompt
You are testing **{{target}}** for {p.get('for', title)}.

**Recon Context:**
{{recon_json}}

**METHODOLOGY:**

### 1. Methodology
{steps}

### 2. Report Format
For each CONFIRMED finding:
```
FINDING:
- Title: {title} at [endpoint]
- Severity: {p.get('severity', 'Medium')}
- CWE: {p.get('cwe', 'CWE-0')}
- Endpoint: [full URL]
- Vector: [parameter/header/flow]
- Payload: [exact payload]
- Evidence: [proof of exploitation]
- Impact: {p.get('impact', 'Describe impact')}
- Remediation: {p.get('fix', 'Describe remediation')}
```

## System Prompt
{p.get('system', 'You are a specialist. Report only reproducible, proven findings with hard evidence. Never report unverified or theoretical issues.')}
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write(md)
    return {"name": name, "path": os.path.relpath(path, ROOT)}


def _rl_state():
    rl = RLEngine(PATHS["rl_state"])
    agents = rl.state.get("agents", {})
    rows = [{"name": n, "weight": r.get("weight", 0.5), "runs": r.get("runs", 0),
             "hits": r.get("validated_hits", 0), "fp": r.get("false_positives", 0)}
            for n, r in agents.items()]
    rows.sort(key=lambda x: x["weight"], reverse=True)
    return {"agents": rows, "updated_for": rl.state.get("updated_for", "")}


def _start_run(params):
    run_id = "run-%d" % (len(_RUNS) + 1)
    with _LOCK:
        _RUNS[run_id] = {"log": [], "done": False, "result": None}

    def progress(msg):
        with _LOCK:
            _RUNS[run_id]["log"].append(msg)

    def worker():
        try:
            cfg_g = _load_config()
            # Apply API keys from settings to env (API execution mode).
            for prov, key in (params.get("api_keys") or cfg_g.get("api_keys") or {}).items():
                p = models.PROVIDERS.get(prov)
                if p and key and p.env_keys:
                    os.environ[p.env_keys[0]] = key
            backend = params.get("backend") or (backends.detect()[0].key if backends.detect() else "claude")
            provider = params.get("provider") or _PROV_FOR_BACKEND.get(backend, "anthropic")
            mlist = models.list_models(provider)
            model = params.get("model") or (mlist[0].id if mlist else "")
            verbosity = params.get("verbosity", cfg_g.get("verbosity", "normal"))
            mode = params.get("mode", cfg_g.get("mode", "cli"))

            # Multi-target: accept "targets" list or single "url".
            raw = params.get("targets") or [params.get("url")]
            targets = []
            for u in raw:
                if not u:
                    continue
                targets.append(u if u.startswith(("http://", "https://")) else "https://" + u)
            if verbosity != "quiet":
                progress(f"verbosity={verbosity}  mode={mode}  provider={provider}  model={model}  targets={len(targets)}")

            all_findings, all_ran, all_activity, reports = [], [], [], {}
            for idx, url in enumerate(targets, 1):
                progress(f"=== target {idx}/{len(targets)}: {url} ===")
                cfg = RunConfig(
                    target=url, scope=params.get("scope") or url, backend=backend,
                    provider=provider, model=model, collaborator=params.get("collaborator", ""),
                    use_rl=bool(params.get("rl", True)), use_mcp=bool(params.get("mcp", True)),
                    dry_run=bool(params.get("dry_run", False)),
                )
                res = run_engagement(cfg, progress=progress)
                for f in res.get("findings", []):
                    f.setdefault("target", url)
                all_findings += res.get("findings", [])
                all_ran += res.get("agents_ran", [])
                all_activity += res.get("activity", [])
                if res.get("reports"):
                    reports = res["reports"]
            with _LOCK:
                _RUNS[run_id]["result"] = {
                    "returncode": 0, "targets": targets,
                    "findings": all_findings, "agents_ran": all_ran,
                    "activity": all_activity, "reports": {
                        k: os.path.relpath(v, ROOT) for k, v in reports.items() if not k.endswith("_error")},
                }
        except Exception as e:
            progress(f"ERROR: {e}")
            with _LOCK:
                _RUNS[run_id]["result"] = {"error": str(e)}
        finally:
            with _LOCK:
                _RUNS[run_id]["done"] = True

    threading.Thread(target=worker, daemon=True).start()
    return run_id


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return None

    def log_message(self, *a):
        pass

    def _serve_file(self):
        # Serve generated reports and finding screenshots (read-only, path-scoped).
        if self.path.startswith("/reports/"):
            base, rel = PATHS["reports"], self.path[len("/reports/"):]
        else:
            base, rel = PATHS["results"], self.path[len("/shots/"):]
        target = os.path.normpath(os.path.join(base, rel))
        if not target.startswith(os.path.normpath(base)) or not os.path.isfile(target):
            return self._send(404, json.dumps({"error": "not found"}))
        ext = os.path.splitext(target)[1].lower()
        ctype = {".pdf": "application/pdf", ".html": "text/html; charset=utf-8",
                 ".png": "image/png", ".typ": "text/plain; charset=utf-8"}.get(ext, "application/octet-stream")
        self._send(200, open(target, "rb").read(), ctype)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, open(os.path.join(HERE, "index.html"), "rb").read(), "text/html; charset=utf-8")
        elif self.path == "/api/info":
            self._send(200, json.dumps(_info()))
        elif self.path == "/api/agents":
            self._send(200, json.dumps({"agents": _agents_list()}))
        elif self.path == "/api/rl":
            self._send(200, json.dumps(_rl_state()))
        elif self.path == "/api/config":
            self._send(200, json.dumps(_load_config()))
        elif self.path == "/api/reports":
            rdir = PATHS["reports"]
            files = []
            if os.path.isdir(rdir):
                for fn in sorted(os.listdir(rdir)):
                    fp = os.path.join(rdir, fn)
                    if os.path.isfile(fp) and fn.lower().endswith((".pdf", ".html", ".typ")):
                        files.append({"name": fn, "size": os.path.getsize(fp),
                                      "url": "/reports/" + fn})
            self._send(200, json.dumps({"reports": files}))
        elif self.path.startswith("/reports/") or self.path.startswith("/shots/"):
            self._serve_file()
        elif self.path.startswith("/api/status/"):
            rid = self.path.rsplit("/", 1)[-1]
            with _LOCK:
                st = _RUNS.get(rid)
            self._send(200 if st else 404, json.dumps(st or {"error": "unknown run"}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        body = self._json_body()
        if body is None:
            return self._send(400, json.dumps({"error": "bad json"}))
        if self.path == "/api/run":
            if not body.get("url") and not body.get("targets"):
                return self._send(400, json.dumps({"error": "url or targets required"}))
            return self._send(200, json.dumps({"run_id": _start_run(body)}))
        if self.path == "/api/agents":
            try:
                return self._send(200, json.dumps({"ok": True, "agent": _add_agent(body)}))
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
        if self.path == "/api/config":
            cfg = _load_config()
            cfg.update({k: v for k, v in body.items() if k in ("mode", "orchestrator", "verbosity")})
            keys = cfg.setdefault("api_keys", {})
            for prov, key in (body.get("api_keys") or {}).items():
                if key:
                    keys[prov] = key
                    p = models.PROVIDERS.get(prov)
                    if p and p.env_keys:
                        os.environ[p.env_keys[0]] = key  # live, in-memory
            _save_config(cfg)
            return self._send(200, json.dumps({"ok": True}))
        self._send(404, json.dumps({"error": "not found"}))


def main():
    host = os.getenv("NEUROSPLOIT_GUI_HOST", "127.0.0.1")
    port = int(os.getenv("NEUROSPLOIT_GUI_PORT", "8787"))
    print(f"NeuroSploit v3.3.0 GUI → http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()

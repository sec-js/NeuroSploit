//! NeuroSploit v3.4.1 — CLI: `run` (black-box) / `whitebox` (source) / `agents` / `models`.

use clap::{Parser, Subcommand};
use harness::{agents, models::ModelRef, pool::ModelPool, types::RunConfig, RunOutput};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "neurosploit",
    version,
    about = "NeuroSploit v3.4.1 — multi-model autonomous pentest harness",
    long_about = "NeuroSploit v3.4.1 — a Rust multi-model harness that drives a pool of LLMs \
(API key or local subscription: Claude/Codex/Gemini/Grok) to autonomously test a target. \
After recon it INTELLIGENTLY selects only the agents matching the discovered surface, runs \
them in parallel, then validates every finding by cross-model voting before reporting.\n\n\
Run with NO arguments for an interactive wizard.\n\n\
EXAMPLES:\n  \
# Black-box against a known test site (subscription, Opus, browser via Playwright if present)\n  \
neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 --mcp -v\n\n  \
# Black-box via API keys with a multi-model voting panel\n  \
neurosploit run http://testphp.vulnweb.com/ --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3\n\n  \
# White-box source review of a cloned repo (DVWA)\n  \
git clone https://github.com/digininja/DVWA /tmp/DVWA\n  \
neurosploit whitebox /tmp/DVWA --subscription --model anthropic:claude-opus-4-8 -v\n\n  \
# Offline pipeline self-test (no keys/login)\n  \
neurosploit run http://testphp.vulnweb.com/ --offline\n\n\
TIP: run inside Kali Linux (or `docker run -it kalilinux/kali-rolling`) so curl/nmap/rustscan/ffuf are available."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Black-box: recon → intelligent agent selection → exploit → vote → report.
    Run {
        url: String,
        /// Models as provider:model (repeatable). First is primary; rest fail over + vote.
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        /// Use local agentic CLI subscription (Claude/Codex/Gemini/Grok login).
        #[arg(long)]
        subscription: bool,
        /// Enable Playwright MCP (auto-installed if missing; backends that don't
        /// support MCP fall back to their built-in tools).
        #[arg(long)]
        mcp: bool,
        /// Verbose: log each agent as it launches, recon, and votes.
        #[arg(short, long)]
        verbose: bool,
    },
    /// White-box: analyse a local repository's source code for vulnerabilities.
    Whitebox {
        path: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 2)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show agent library counts.
    Agents,
    /// List providers and models.
    Models,
}

/// Locate the repo root that holds `agents_md/`.
fn find_base() -> PathBuf {
    if let Ok(b) = std::env::var("NEUROSPLOIT_BASE") {
        return PathBuf::from(b);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        for _ in 0..6 {
            if dir.join("agents_md").is_dir() {
                return dir.to_path_buf();
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let base = find_base();

    let cmd = match cli.cmd {
        Some(c) => c,
        None => interactive(&base).await?, // no args → wizard
    };

    match cmd {
        Cmd::Agents => {
            let lib = agents::load(&base);
            println!(
                "{{\"vulns\":{},\"recon\":{},\"code\":{},\"meta\":{},\"total\":{}}}",
                lib.vulns.len(), lib.recon.len(), lib.code.len(), lib.meta.len(), lib.total()
            );
        }
        Cmd::Models => {
            for p in harness::providers() {
                println!("{:<4} {:<14} {} models  [{}]", p.kind, p.key, p.models.len(), p.label);
                for m in &p.models {
                    println!("      {}:{}", p.key, m);
                }
            }
        }
        Cmd::Run { url, models, max_agents, vote_n, offline, subscription, mcp, verbose } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, mcp, false).await?;
            print_findings(&out);
        }
        Cmd::Whitebox { path, models, max_agents, vote_n, offline, subscription, verbose } => {
            let mut cfg = RunConfig::new(&path);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, false, true).await?;
            print_findings(&out);
        }
    }
    Ok(())
}

/// Shared engagement runner for `run` / `whitebox`.
async fn run_engagement(base: &Path, mut cfg: RunConfig, mcp: bool, whitebox: bool) -> anyhow::Result<RunOutput> {
    let lib = agents::load(base);

    // Unique, sortable run id → runs/<id>/
    let run_id = format!("ns-{}-{}", now_ts(), sanitize(&cfg.target));
    let workdir = base.join("runs").join(&run_id);
    std::fs::create_dir_all(&workdir).ok();
    cfg.workdir = Some(workdir.display().to_string());
    cfg.rl_path = Some(base.join("data").join("rl_state_rs.json").display().to_string());
    write_status(&workdir, "running", &format!("\"target\":{:?}", cfg.target));

    println!("  ┌─ NeuroSploit v3.4.1");
    println!("  │  run id : {run_id}");
    println!("  │  target : {}", cfg.target);
    println!("  │  models : {}", cfg.models.join(", "));
    println!("  │  output : {}", workdir.display());
    println!("  └─ mode   : {}{}{}",
        if whitebox { "white-box" } else { "black-box" },
        if cfg.subscription { " · subscription" } else { " · api" },
        if mcp { " · mcp" } else { "" });

    // Playwright MCP: only for backends that support it; auto-provision if asked.
    let mcp_config = if mcp && cfg.subscription {
        let providers: Vec<String> = cfg.models.iter().map(|m| ModelRef::parse(m).provider).collect();
        if providers.iter().any(|p| harness::mcp_supported(p)) {
            match harness::ensure_playwright_mcp() {
                Ok(()) => match harness::write_mcp_config(&workdir) {
                    Ok(p) => {
                        println!("  [*] Playwright MCP ready → {}", p.display());
                        Some(p.display().to_string())
                    }
                    Err(e) => { eprintln!("  [!] MCP config failed: {e}"); None }
                },
                Err(e) => { eprintln!("  [!] Playwright MCP unavailable ({e}); using built-in tools"); None }
            }
        } else {
            eprintln!("  [!] selected backend(s) don't support MCP; using built-in tools");
            None
        }
    } else {
        None
    };

    let refs: Vec<ModelRef> = cfg.models.iter().map(|s| ModelRef::parse(s)).collect();
    let pool = ModelPool::with_auth(refs, cfg.concurrency, cfg.subscription, mcp_config);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
    let printer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            println!("  [*] {line}");
        }
    });
    let out = if whitebox {
        harness::run_whitebox(cfg, &lib, &pool, tx).await
    } else {
        harness::run(cfg, &lib, &pool, tx).await
    };
    let _ = printer.await;

    // Final report via Typst (PDF if the `typst` binary is present) + HTML/MD already written.
    match harness::report::typst_report(&out.target, &out.findings, &workdir) {
        Ok(p) => println!("  [*] report → {}", p.display()),
        Err(e) => eprintln!("  [!] typst report skipped: {e}"),
    }
    write_status(&workdir, "complete", &format!("\"findings\":{},\"agents_ran\":{}", out.findings.len(), out.agents_ran.len()));
    println!("  ✓ COMPLETE — {} validated finding(s) · status: {}/status.json", out.findings.len(), workdir.display());
    Ok(out)
}

fn print_findings(out: &RunOutput) {
    println!("\n=== {} validated finding(s) ===", out.findings.len());
    println!("{}", serde_json::to_string_pretty(&out.findings).unwrap_or_default());
    if !out.artifacts.is_empty() {
        println!("artifacts: {}", out.artifacts.join(", "));
    }
}

fn sanitize(s: &str) -> String {
    let s = s.replace("https://", "").replace("http://", "");
    let mut o: String = s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect();
    o.truncate(40);
    let o = o.trim_matches('_').to_string();
    if o.is_empty() { "target".into() } else { o }
}

fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn write_status(workdir: &Path, state: &str, extra: &str) {
    let p = workdir.join("status.json");
    let _ = std::fs::write(&p, format!("{{\"state\":\"{state}\",\"ts\":{}{}}}", now_ts(),
        if extra.is_empty() { String::new() } else { format!(",{extra}") }));
}

fn prompt(q: &str, default: &str) -> String {
    use std::io::Write;
    print!("  {q}{}: ", if default.is_empty() { String::new() } else { format!(" [{default}]") });
    std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    let s = s.trim().to_string();
    if s.is_empty() { default.to_string() } else { s }
}

/// Interactive wizard launched when `neurosploit` is run with no subcommand.
async fn interactive(base: &Path) -> anyhow::Result<Cmd> {
    let lib = agents::load(base);
    let backends = harness::installed_cli_backends();
    println!("\n  ┌────────────────────────────────────────────┐");
    println!("  │  NeuroSploit v3.4.1 — interactive            │");
    println!("  └────────────────────────────────────────────┘");
    println!("  agents: {} · detected CLI logins: {}\n",
        lib.total(), if backends.is_empty() { "none".into() } else { backends.join(", ") });

    let mode = prompt("Mode — (b)lack-box URL or (w)hite-box repo?", "b").to_lowercase();
    let whitebox = mode.starts_with('w');
    let target = if whitebox {
        prompt("Repository path", "/tmp/DVWA")
    } else {
        prompt("Target URL", "http://testphp.vulnweb.com/")
    };
    let model = prompt("Model (provider:model)", "anthropic:claude-opus-4-8");
    let sub = prompt("Use subscription login (no API key)? (y/n)", "y").to_lowercase().starts_with('y');
    let mcp = if whitebox { false } else {
        prompt("Use Playwright MCP browser if available? (y/n)", "y").to_lowercase().starts_with('y')
    };
    let max_agents: usize = prompt("Max agents (0 = all matching)", "5").parse().unwrap_or(5);
    let vote_n: usize = prompt("Validator votes (N)", "3").parse().unwrap_or(3);

    let models = vec![model];
    Ok(if whitebox {
        Cmd::Whitebox { path: target, models, max_agents, vote_n, offline: false, subscription: sub, verbose: true }
    } else {
        Cmd::Run { url: target, models, max_agents, vote_n, offline: false, subscription: sub, mcp, verbose: true }
    })
}

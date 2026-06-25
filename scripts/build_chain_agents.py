#!/usr/bin/env python3
"""
NeuroSploit v3.5.1 — attack-chain agents.

Each agent is a multi-stage exploitation-chaining playbook: take a confirmed
entry-point weakness and escalate it through concrete stages to deeper impact
(e.g. SQLi → RCE → local privilege escalation). Writes agents_md/chains/*.md.
Credits: Joas A Santos & Red Team Leaders.
"""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "agents_md", "chains")


def render(a):
    L = [f"# {a['title']} Agent\n", "## User Prompt",
         f"You are executing a multi-stage ATTACK CHAIN against **{{target}}**: {a['chain']}.\n",
         "**Recon Context / prior findings:**\n{recon_json}\n",
         f"**GOAL:** {a['goal']}\n",
         "**CHAIN — advance stage by stage; each stage's output is the next stage's input. "
         "Use the ReAct loop and PROVE every stage with raw tool output before advancing:**\n"]
    for i, (stage, bs) in enumerate(a["stages"], 1):
        L.append(f"### Stage {i}. {stage}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["stages"]) + 1
    L += [f"### {n}. Report Format",
          "Report the chain as ONE finding (plus per-stage evidence):", "```", "FINDING:",
          f"- Title: {a['title']}", f"- Severity: {a['sev']}", f"- CWE: {a['cwe']}",
          "- Endpoint: [entry point]", "- Vector: [the full chain, stage by stage]",
          "- Payload: [the key payloads/commands per stage]",
          "- Evidence: [raw output proving EACH stage actually executed]",
          f"- Impact: {a['impact']}", f"- Remediation: {a['fix']}",
          "- chains_from: [ids of the prerequisite findings this builds on]", "```\n",
          "## System Prompt", a["system"]]
    return "\n".join(L) + "\n"


def A(name, title, chain, goal, cwe, sev, impact, fix, stages):
    return {"name": name, "title": title, "chain": chain, "goal": goal, "cwe": cwe,
            "sev": sev, "impact": impact, "fix": fix, "stages": stages,
            "system": ("You are an exploit-chaining specialist. Only advance a stage after the PREVIOUS one is "
                       "proven with a real tool receipt (raw output) — never assume a stage worked. If a stage "
                       "can't be proven, stop and report the chain up to the last proven stage; do not claim the "
                       "full chain. AUTHORIZED engagement; no destructive/DoS actions. Each reported stage must "
                       "carry its own evidence. Credits: Joas A Santos & Red Team Leaders.")}


CHAINS = [
 A("chain_sqli_to_rce_to_lpe",
   "SQLi → RCE → Local PrivEsc Chain",
   "SQL injection → command execution → local privilege escalation",
   "Turn a database-layer injection into root/SYSTEM on the host.",
   "CWE-89", "Critical",
   "Full host compromise originating from a web injection",
   "Parameterize queries; least-privilege DB account; harden host; patch local vectors",
   [("Exploit the SQL injection", ["Confirm injection (error/boolean/time); identify DBMS and privileges",
                                    "Enumerate whether stacked queries / FILE / xp_cmdshell / INTO OUTFILE are available"]),
    ("Pivot SQLi → RCE", ["MSSQL: enable & use `xp_cmdshell`; MySQL: `INTO OUTFILE` a webshell to a known web path; PostgreSQL: `COPY ... PROGRAM`",
                          "Confirm OS command execution with `id`/`whoami` output"]),
    ("Establish a foothold", ["Drop/upgrade to a stable shell as the web/db service user"]),
    ("Local privilege escalation", ["Enumerate SUID/sudo/cron/kernel (Linux) or token/service/unquoted-path (Windows)",
                                     "Escalate to root/SYSTEM and prove with a privileged command output"])]),
 A("chain_ssrf_to_aws_compromise",
   "SSRF → AWS Credential Compromise Chain",
   "SSRF → cloud metadata → IAM credentials → cloud account access",
   "Convert a server-side request forgery into valid AWS credentials and account access.",
   "CWE-918", "Critical",
   "Cloud account compromise via stolen IAM role credentials",
   "Enforce IMDSv2 hop-limit=1; egress allowlists; SSRF input validation; scoped IAM roles",
   [("Confirm the SSRF primitive", ["Find a server-side fetch you control (url/webhook/import/pdf/image param)",
                                     "Prove it reaches an attacker-controlled / internal host"]),
    ("Reach the metadata service", ["IMDSv2: PUT `/latest/api/token` then GET with the token header; else IMDSv1 GET",
                                     "Retrieve `/latest/meta-data/iam/security-credentials/<role>`"]),
    ("Harvest IAM credentials", ["Capture AccessKeyId/SecretAccessKey/Token from the metadata response"]),
    ("Use the credentials (in scope)", ["`aws sts get-caller-identity` to confirm; enumerate permitted actions read-only",
                                        "Prove access to at least one resource the role can reach"])]),
 A("chain_ssrf_to_rce",
   "SSRF → RCE Chain",
   "SSRF → internal service abuse → remote code execution",
   "Escalate an SSRF into code execution via a reachable internal service.",
   "CWE-918", "Critical",
   "Remote code execution pivoted through an internal service",
   "Egress controls; authenticate internal services; SSRF allowlists",
   [("Confirm SSRF + map internals", ["Prove the SSRF; port-scan internal hosts through it (gopher/http)",
                                       "Identify exploitable internal services (Redis, unauth admin, CI, internal API)"]),
    ("Weaponize the internal service", ["e.g. Redis → write SSH key/cron/module; internal Jenkins/Actuator → job/exec; gopher:// to craft raw protocol payloads"]),
    ("Achieve RCE", ["Trigger command execution on the internal/back-end host"]),
    ("Confirm", ["Prove execution with an OOB callback or command output tied to a unique marker"])]),
 A("chain_upload_to_rce",
   "File Upload → RCE Chain",
   "insecure file upload → webshell → remote code execution",
   "Turn an unrestricted/insecure upload into code execution.",
   "CWE-434", "Critical",
   "Remote code execution via uploaded executable content",
   "Validate type by content; randomize names; store outside webroot; non-exec storage",
   [("Probe the upload", ["Map accepted types/extensions, storage path, and how files are served",
                          "Test bypasses: double extension, content-type spoof, magic-byte prefix, null byte, .htaccess/.phar"]),
    ("Upload a payload", ["Place a minimal webshell/handler in a web-served, executable location"]),
    ("Locate & trigger", ["Find the served URL of the upload; request it to execute"]),
    ("Confirm RCE", ["Run `id`/`whoami`; capture output proving execution"])]),
 A("chain_upload_lfi_rce_lpe",
   "Upload → LFI → RCE → LPE Chain",
   "file upload + local file inclusion → log/session poisoning → RCE → privilege escalation",
   "Chain a benign upload and an LFI into code execution and then root.",
   "CWE-98", "Critical",
   "Host compromise from a non-executable upload chained through LFI",
   "Fix LFI (allowlist includes); validate uploads; harden host",
   [("Confirm the LFI", ["Prove local file inclusion (read /etc/passwd or app config); identify wrappers (php://, data://, zip://)"]),
    ("Plant controllable content via upload", ["Upload a file whose path/content you can later include (image with PHP, zip for zip:// , or use the LFI to read your uploaded file)"]),
    ("LFI → RCE", ["Include the planted file, or poison logs/session/`/proc/self/environ` then include it to execute code"]),
    ("Confirm RCE then escalate", ["Prove command execution; then enumerate and perform local privilege escalation to root/SYSTEM"])]),
 A("chain_xss_to_account_takeover",
   "XSS → Session/Account Takeover Chain",
   "stored/reflected XSS → session or token theft → account takeover",
   "Escalate XSS into full takeover of a victim (incl. admin) account.",
   "CWE-79", "High",
   "Account takeover (incl. privileged) via client-side execution",
   "Output encoding + CSP; HttpOnly/SameSite cookies; rotate tokens",
   [("Prove execution", ["Confirm the payload executes in the victim's browser context (Playwright: alert/DOM), not just reflects"]),
    ("Steal the session", ["Exfiltrate the session cookie/JWT/CSRF token to a collaborator, or perform actions in-context if HttpOnly"]),
    ("Take over the account", ["Replay the stolen session, or change email/password/MFA via in-context requests"]),
    ("Confirm + escalate", ["Prove control of the victim account; target an admin for privilege escalation"])]),
 A("chain_idor_to_takeover",
   "IDOR → Mass Account Takeover Chain",
   "IDOR → cross-account data → credential/role manipulation → takeover",
   "Chain object-level authz failure into taking over arbitrary accounts.",
   "CWE-639", "High",
   "Mass account takeover via broken object-level authorization",
   "Enforce per-object ownership on every endpoint; indirect references",
   [("Confirm the IDOR", ["Access another user's object with your session, proven by their data"]),
    ("Find a state-changing IDOR", ["Locate IDOR on email/password/role/API-key endpoints"]),
    ("Manipulate the victim account", ["Change a victim's email or reset token / elevate role via the IDOR"]),
    ("Confirm takeover", ["Log in as / act as the victim; demonstrate control"])]),
 A("chain_ssti_to_rce_to_cloud",
   "SSTI → RCE → Cloud Pivot Chain",
   "template injection → RCE → host creds → cloud/lateral movement",
   "Go from template injection to code execution to cloud or lateral access.",
   "CWE-1336", "Critical",
   "Cloud/lateral compromise originating from template injection",
   "Never render user input as templates; sandbox; scope host IAM/creds",
   [("Confirm SSTI → RCE", ["Fingerprint the engine (`{{7*7}}` etc.); use the gadget to execute a command; prove with output"]),
    ("Loot the host", ["Read env/config/instance metadata for cloud creds, DB creds, tokens"]),
    ("Pivot", ["Use recovered creds against cloud APIs or adjacent internal hosts"]),
    ("Confirm impact", ["Prove access to a cloud resource or a second host with evidence"])]),
 A("chain_default_creds_to_domain",
   "Default Creds → Foothold → Domain Compromise Chain",
   "default/weak creds → host foothold → AD escalation → domain dominance",
   "Chain an exposed credential into Active Directory domain compromise.",
   "CWE-798", "Critical",
   "Domain compromise from a single weak/default credential",
   "Rotate defaults; unique strong passwords; tiered admin; monitor",
   [("Get the foothold", ["Authenticate with the default/weak/reused credential (SSH/WinRM/SMB/web)"]),
    ("Enumerate AD", ["From the foothold, run BloodHound/netexec; map attack paths, roastable accounts, ACLs"]),
    ("Escalate in AD", ["Kerberoast/AS-REP-roast, abuse an ACL edge, or relay — recover higher-priv creds"]),
    ("Reach domain dominance", ["Demonstrate DCSync or DA-equivalent access (single test account) proving the path"])]),
 A("chain_deserialization_to_rce",
   "Insecure Deserialization → RCE Chain",
   "untrusted deserialization → gadget chain → remote code execution",
   "Turn a deserialization sink into reliable code execution.",
   "CWE-502", "Critical",
   "Remote code execution via unsafe object deserialization",
   "Never deserialize untrusted data; allowlist types; safe formats",
   [("Locate the sink", ["Identify where attacker data is deserialized (cookie/param/file/RPC); fingerprint the format/library"]),
    ("Build the gadget", ["Select a working gadget chain (ysoserial/ysoserial.net/PyYAML/pickle) for the target stack"]),
    ("Execute", ["Deliver the payload to the sink"]),
    ("Confirm", ["Prove execution via OOB callback or command output with a unique marker"])]),
 A("chain_exposed_git_to_rce",
   "Exposed .git/.env → Secret → RCE Chain",
   "exposed source/secrets → recovered credentials → authenticated RCE",
   "Chain leaked source/secrets into authenticated code execution.",
   "CWE-527", "High",
   "Code execution using credentials recovered from exposed source/secrets",
   "Block dotfiles from web; rotate leaked secrets; vault storage",
   [("Recover the source/secrets", ["Dump exposed `.git` (git-dumper) or read `.env`/config; extract keys/creds/tokens"]),
    ("Validate the secrets", ["Confirm a recovered credential/key is live (admin panel, cloud, DB, CI)"]),
    ("Gain execution", ["Use the access to deploy code / run a CI job / write a webshell / exec via admin feature"]),
    ("Confirm RCE", ["Prove command execution with output"])]),
 A("chain_subdomain_takeover_to_phishing",
   "Subdomain Takeover → Trusted Phishing/Cookie Chain",
   "dangling DNS → subdomain takeover → trusted-origin abuse",
   "Chain a dangling record into hosting attacker content on a trusted subdomain.",
   "CWE-350", "High",
   "Trusted-origin abuse (cookie theft / phishing / OAuth) via a taken-over subdomain",
   "Remove dangling DNS; monitor; scope cookies/CSP per-host",
   [("Find the dangling record", ["Identify a CNAME/A pointing to an unclaimed provider resource"]),
    ("Claim it", ["Register the resource so the subdomain serves your content (benign PoC)"]),
    ("Abuse the trust", ["Show impact: wildcard-cookie capture, OAuth redirect trust, or CSP allowlist bypass"]),
    ("Confirm", ["Demonstrate the concrete trusted-origin abuse with evidence"])]),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for a in CHAINS:
        open(os.path.join(OUT, a["name"] + ".md"), "w").write(render(a))
    print(f"wrote {len(CHAINS)} chain agents to {OUT}")


if __name__ == "__main__":
    main()

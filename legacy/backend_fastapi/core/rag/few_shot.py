"""
Few-Shot Example Selector for RAG-enhanced reasoning.

Selects the most relevant real-world bug bounty examples and formats
them as few-shot reasoning demonstrations for the LLM. This teaches
the model HOW to reason about vulnerabilities by showing worked examples.

The key insight: instead of just giving the AI information, we show it
examples of successful reasoning chains, so it learns the PATTERN of
good pentesting analysis.
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FewShotExample:
    """A formatted few-shot example for prompt injection."""
    vuln_type: str
    technology: str
    scenario: str
    reasoning_chain: List[str]
    outcome: str
    payload: str = ""
    proof: str = ""
    score: float = 0.0

    def format(self, include_chain: bool = True) -> str:
        """Format as a prompt-ready example."""
        text = f"--- Example: {self.vuln_type.upper()} in {self.technology} ---\n"
        text += f"Scenario: {self.scenario}\n"

        if include_chain and self.reasoning_chain:
            text += "Reasoning:\n"
            for i, step in enumerate(self.reasoning_chain, 1):
                text += f"  {i}. {step}\n"

        if self.payload:
            text += f"Payload: {self.payload}\n"

        text += f"Outcome: {self.outcome}\n"

        if self.proof:
            text += f"Proof: {self.proof}\n"

        return text


class FewShotSelector:
    """
    Selects and formats few-shot examples for LLM prompts.

    Provides three types of examples:
    1. Testing examples: How to test for a specific vuln type
    2. Verification examples: How to verify if a finding is real
    3. Strategy examples: How to plan an attack approach
    """

    def __init__(self, rag_engine=None, dataset_path: str = None):
        """
        Args:
            rag_engine: RAGEngine instance for semantic retrieval
            dataset_path: Path to bug bounty dataset (fallback if no RAG engine)
        """
        self.rag_engine = rag_engine
        self.dataset_path = dataset_path or "models/bug-bounty/bugbounty_finetuning_dataset.json"
        self._example_cache: Dict[str, List[FewShotExample]] = {}
        self._curated_examples = self._build_curated_examples()

    def get_testing_examples(self, vuln_type: str, technology: str = "",
                              max_examples: int = 3) -> str:
        """
        Get few-shot examples showing how to test for a vulnerability type.
        Demonstrates the reasoning chain: observe → hypothesize → test → verify.
        """
        cache_key = f"test_{vuln_type}_{technology}"
        if cache_key in self._example_cache:
            examples = self._example_cache[cache_key][:max_examples]
            return self._format_examples(examples, "TESTING EXAMPLES")

        examples = []

        # 1. Try curated examples first (highest quality)
        curated = self._get_curated_for_type(vuln_type)
        examples.extend(curated)

        # 2. Get RAG-retrieved examples
        if self.rag_engine:
            rag_examples = self._retrieve_rag_examples(
                vuln_type, technology, "testing", max_examples
            )
            examples.extend(rag_examples)

        # 3. Deduplicate and rank
        examples = self._rank_examples(examples, vuln_type, technology)[:max_examples]

        self._example_cache[cache_key] = examples
        return self._format_examples(examples, "TESTING EXAMPLES")

    def get_verification_examples(self, vuln_type: str, evidence: str = "",
                                    max_examples: int = 2) -> str:
        """
        Get few-shot examples showing how to verify/judge a finding.
        Includes both TRUE POSITIVE and FALSE POSITIVE examples.
        """
        examples = []

        # Get curated verification examples
        curated_tp = self._get_curated_verification(vuln_type, is_tp=True)
        curated_fp = self._get_curated_verification(vuln_type, is_tp=False)

        examples.extend(curated_tp[:1])
        examples.extend(curated_fp[:1])

        # RAG-retrieved
        if self.rag_engine and len(examples) < max_examples:
            rag_examples = self._retrieve_rag_examples(
                vuln_type, "", "verification", max_examples - len(examples)
            )
            examples.extend(rag_examples)

        return self._format_examples(examples[:max_examples], "VERIFICATION EXAMPLES")

    def get_strategy_examples(self, technologies: List[str],
                                max_examples: int = 2) -> str:
        """
        Get few-shot examples showing attack strategy planning.
        """
        examples = []

        for tech in technologies[:2]:
            tech_examples = self._get_curated_strategy(tech)
            examples.extend(tech_examples)

        if self.rag_engine and len(examples) < max_examples:
            query = f"penetration testing strategy {' '.join(technologies[:3])}"
            rag_examples = self._retrieve_rag_examples(
                "strategy", " ".join(technologies[:3]), "strategy",
                max_examples - len(examples)
            )
            examples.extend(rag_examples)

        return self._format_examples(examples[:max_examples], "STRATEGY EXAMPLES")

    def _retrieve_rag_examples(self, vuln_type: str, technology: str,
                                 context: str, max_examples: int) -> List[FewShotExample]:
        """Retrieve and convert RAG chunks into few-shot examples."""
        if not self.rag_engine:
            return []

        query = f"{vuln_type.replace('_', ' ')} {technology} {context}"
        rag_ctx = self.rag_engine.query(
            query_text=query,
            vuln_type=vuln_type if vuln_type != "strategy" else None,
            technology=technology if technology else None,
            top_k=max_examples * 2
        )

        examples = []
        for chunk in rag_ctx.chunks[:max_examples]:
            example = self._chunk_to_example(chunk, vuln_type)
            if example:
                examples.append(example)

        return examples

    def _chunk_to_example(self, chunk, vuln_type: str) -> Optional[FewShotExample]:
        """Convert a retrieved chunk into a few-shot example."""
        text = chunk.text
        meta = chunk.metadata

        # Extract reasoning chain from the text
        chain = self._extract_reasoning_from_text(text)

        # Extract payload
        payload = ""
        payload_match = re.search(r'(?:payload|exploit|poc)[:\s]*[`"]?([^\n`"]{10,200})', text, re.I)
        if payload_match:
            payload = payload_match.group(1).strip()

        # Extract outcome
        outcome = "See methodology above for complete exploitation details."
        if "confirmed" in text.lower() or "success" in text.lower():
            outcome = "Vulnerability confirmed with proof of exploitation."
        elif "impacto" in text.lower() or "impact" in text.lower():
            impact_match = re.search(r'(?:impacto|impact)[:\s]*(.{20,200})', text, re.I)
            if impact_match:
                outcome = impact_match.group(1).strip()

        technology = meta.get("technology", meta.get("technologies", "unknown"))
        if isinstance(technology, str) and "," in technology:
            technology = technology.split(",")[0]

        scenario = text[:200].replace("\n", " ").strip()

        return FewShotExample(
            vuln_type=meta.get("vuln_type", vuln_type),
            technology=str(technology),
            scenario=scenario,
            reasoning_chain=chain,
            outcome=outcome,
            payload=payload,
            score=chunk.score
        )

    def _extract_reasoning_from_text(self, text: str) -> List[str]:
        """Extract reasoning steps from a bug bounty report."""
        steps = []

        # Try numbered steps
        numbered = re.findall(r'(?:^|\n)\s*(\d+)\.\s+(.{10,200})', text)
        if len(numbered) >= 2:
            for num, step in numbered[:6]:
                steps.append(step.strip())
            return steps

        # Try bullet points
        bullets = re.findall(r'(?:^|\n)\s*[-*]\s+(.{10,200})', text)
        if len(bullets) >= 2:
            for bullet in bullets[:6]:
                steps.append(bullet.strip())
            return steps

        # Try section-based extraction
        sections = re.findall(r'###?\s+(.+?)(?:\n|$)', text)
        for section in sections[:6]:
            steps.append(section.strip())

        if not steps:
            # Fall back to sentence extraction
            sentences = re.split(r'[.!]\s+', text[:800])
            for sent in sentences[:4]:
                if len(sent.strip()) > 20:
                    steps.append(sent.strip())

        return steps

    def _rank_examples(self, examples: List[FewShotExample],
                        vuln_type: str, technology: str) -> List[FewShotExample]:
        """Rank examples by relevance to the target vuln type and technology."""
        for example in examples:
            score = example.score

            # Boost exact vuln type match
            if example.vuln_type == vuln_type:
                score += 2.0

            # Boost technology match
            if technology and technology.lower() in example.technology.lower():
                score += 1.5

            # Boost examples with reasoning chains
            if example.reasoning_chain and len(example.reasoning_chain) >= 3:
                score += 1.0

            # Boost examples with payloads
            if example.payload:
                score += 0.5

            # Boost examples with proof
            if example.proof:
                score += 0.5

            example.score = score

        examples.sort(key=lambda e: e.score, reverse=True)

        # Deduplicate by scenario similarity
        seen_starts = set()
        unique = []
        for ex in examples:
            start = ex.scenario[:50].lower()
            if start not in seen_starts:
                seen_starts.add(start)
                unique.append(ex)

        return unique

    def _format_examples(self, examples: List[FewShotExample],
                          header: str) -> str:
        """Format examples into a prompt-ready string."""
        if not examples:
            return ""

        text = f"\n=== {header} (Learn from these real-world cases) ===\n"
        text += "Study these examples to understand the REASONING PATTERN, then apply similar logic.\n\n"

        for i, example in enumerate(examples, 1):
            text += f"[Example {i}]\n"
            text += example.format(include_chain=True)
            text += "\n"

        text += f"=== END {header} ===\n"
        return text

    def _get_curated_for_type(self, vuln_type: str) -> List[FewShotExample]:
        """Get curated examples for a vulnerability type."""
        vtype = vuln_type.lower().replace("-", "_")
        examples = []

        if vtype in self._curated_examples:
            for ex_data in self._curated_examples[vtype].get("testing", []):
                examples.append(FewShotExample(**ex_data, score=10.0))

        # Also check parent types (e.g., xss_reflected -> xss)
        base_type = vtype.split("_")[0]
        if base_type != vtype and base_type in self._curated_examples:
            for ex_data in self._curated_examples[base_type].get("testing", []):
                examples.append(FewShotExample(**ex_data, score=8.0))

        return examples

    def _get_curated_verification(self, vuln_type: str,
                                    is_tp: bool) -> List[FewShotExample]:
        """Get curated verification examples (TP or FP)."""
        vtype = vuln_type.lower().replace("-", "_")
        key = "verification_tp" if is_tp else "verification_fp"
        examples = []

        if vtype in self._curated_examples:
            for ex_data in self._curated_examples[vtype].get(key, []):
                examples.append(FewShotExample(**ex_data, score=10.0))

        base_type = vtype.split("_")[0]
        if base_type != vtype and base_type in self._curated_examples:
            for ex_data in self._curated_examples[base_type].get(key, []):
                examples.append(FewShotExample(**ex_data, score=8.0))

        return examples

    def _get_curated_strategy(self, technology: str) -> List[FewShotExample]:
        """Get curated strategy examples for a technology."""
        tech = technology.lower()
        if tech in self._curated_examples.get("_strategies", {}):
            data = self._curated_examples["_strategies"][tech]
            return [FewShotExample(**data, score=10.0)]
        return []

    def _build_curated_examples(self) -> Dict:
        """
        Build curated high-quality few-shot examples.
        These are hand-crafted to demonstrate ideal reasoning patterns.
        """
        return {
            "xss": {
                "testing": [
                    {
                        "vuln_type": "xss_reflected",
                        "technology": "PHP",
                        "scenario": "Search parameter reflected in HTML body without encoding",
                        "reasoning_chain": [
                            "OBSERVE: Parameter 'q' is reflected verbatim in <div class='results'>",
                            "IDENTIFY CONTEXT: Reflection is inside HTML body (not attribute, not JS)",
                            "TEST FILTERS: Sent <b>test</b> - HTML tags rendered, no encoding",
                            "ESCALATE: Injected <script>alert(document.domain)</script>",
                            "VERIFY: Script executed in browser, alert showed domain name",
                            "PROVE: DOM inspection confirms injected <script> tag is live"
                        ],
                        "outcome": "Confirmed: Reflected XSS via unencoded HTML body injection",
                        "payload": "<script>alert(document.domain)</script>",
                        "proof": "Playwright confirmed script execution, DOM shows injected tag"
                    }
                ],
                "verification_tp": [
                    {
                        "vuln_type": "xss_reflected",
                        "technology": "generic",
                        "scenario": "Verifying XSS finding is a TRUE POSITIVE",
                        "reasoning_chain": [
                            "CHECK 1: Payload appears in response body unencoded? YES",
                            "CHECK 2: Payload is in executable context (inside HTML, not comment)? YES",
                            "CHECK 3: No CSP header blocking inline scripts? CORRECT, no CSP",
                            "CHECK 4: Browser actually executes the script? YES (Playwright confirms)",
                            "VERDICT: All 4 checks pass → TRUE POSITIVE"
                        ],
                        "outcome": "CONFIRMED: True positive - all verification checks passed",
                        "proof": "Browser execution confirmed via Playwright"
                    }
                ],
                "verification_fp": [
                    {
                        "vuln_type": "xss_reflected",
                        "technology": "generic",
                        "scenario": "Verifying XSS finding that is a FALSE POSITIVE",
                        "reasoning_chain": [
                            "CHECK 1: Payload in response? YES, but only inside HTML comment <!-- -->",
                            "CHECK 2: Executable context? NO - HTML comments are not executed",
                            "CHECK 3: Even if we break out of comment, CSP blocks inline scripts",
                            "VERDICT: Payload present but NOT executable → FALSE POSITIVE"
                        ],
                        "outcome": "REJECTED: False positive - payload in non-executable context",
                        "proof": "No browser execution possible due to HTML comment context + CSP"
                    }
                ]
            },
            "sqli": {
                "testing": [
                    {
                        "vuln_type": "sqli",
                        "technology": "PHP/MySQL",
                        "scenario": "Login form with username and password fields",
                        "reasoning_chain": [
                            "OBSERVE: Login form sends POST with username & password params",
                            "PROBE: Single quote in username returns MySQL error: 'syntax error near '''",
                            "IDENTIFY: Error-based SQL injection, MySQL backend confirmed",
                            "TEST UNION: ' UNION SELECT 1,2,3-- - reveals 3 columns",
                            "EXTRACT: ' UNION SELECT user(),database(),version()-- - shows root@localhost",
                            "PROVE: Extracted real DB info (database name, MySQL version, current user)"
                        ],
                        "outcome": "Confirmed: UNION-based SQL injection with full data extraction",
                        "payload": "' UNION SELECT user(),database(),version()-- -",
                        "proof": "Database name, version and user extracted from response"
                    }
                ],
                "verification_tp": [
                    {
                        "vuln_type": "sqli",
                        "technology": "generic",
                        "scenario": "Verifying SQL injection is TRUE POSITIVE",
                        "reasoning_chain": [
                            "CHECK 1: Database error message in response? YES (MySQL syntax error)",
                            "CHECK 2: Error contains our injected syntax? YES (shows the quote)",
                            "CHECK 3: Can we extract data? YES (UNION SELECT returns DB version)",
                            "CHECK 4: Is data extraction real? YES (version string matches known MySQL format)",
                            "VERDICT: Data extraction proven → TRUE POSITIVE"
                        ],
                        "outcome": "CONFIRMED: True positive - actual data extraction achieved"
                    }
                ],
                "verification_fp": [
                    {
                        "vuln_type": "sqli",
                        "technology": "generic",
                        "scenario": "WAF error page mimics SQL error",
                        "reasoning_chain": [
                            "CHECK 1: Error message in response? YES, but it's a generic WAF block page",
                            "CHECK 2: Same error for ANY special character? YES - WAF blocks all",
                            "CHECK 3: Can we extract data? NO - all payloads return same WAF page",
                            "VERDICT: WAF blocking, not SQL processing → FALSE POSITIVE"
                        ],
                        "outcome": "REJECTED: False positive - WAF error page, not database error"
                    }
                ]
            },
            "ssrf": {
                "testing": [
                    {
                        "vuln_type": "ssrf",
                        "technology": "Python/Flask",
                        "scenario": "URL parameter used for fetching external content",
                        "reasoning_chain": [
                            "OBSERVE: Parameter 'url' fetches and displays content from URLs",
                            "PROBE: Sent url=http://127.0.0.1:80 - got response from localhost",
                            "TEST INTERNAL: url=http://169.254.169.254/latest/meta-data/ - got AWS metadata!",
                            "EXTRACT: Retrieved IAM role name and temporary credentials",
                            "PROVE: AWS metadata content (ami-id, instance-type) confirms internal access"
                        ],
                        "outcome": "Confirmed: SSRF to AWS metadata endpoint with credential extraction",
                        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "proof": "AWS IAM credentials retrieved from metadata endpoint"
                    }
                ],
                "verification_fp": [
                    {
                        "vuln_type": "ssrf",
                        "technology": "generic",
                        "scenario": "Status code difference is NOT proof of SSRF",
                        "reasoning_chain": [
                            "CHECK 1: Different status code with internal URL? YES (403→200)",
                            "CHECK 2: But is the CONTENT from internal service? NO - same login page",
                            "CHECK 3: Negative control (random URL) also returns 200? YES",
                            "VERDICT: Status code change is application behavior, NOT SSRF → FALSE POSITIVE"
                        ],
                        "outcome": "REJECTED: Status code diff without internal content is NOT SSRF"
                    }
                ]
            },
            "idor": {
                "testing": [
                    {
                        "vuln_type": "idor",
                        "technology": "REST API",
                        "scenario": "User profile API endpoint with numeric ID",
                        "reasoning_chain": [
                            "OBSERVE: GET /api/users/42 returns user profile (my ID is 42)",
                            "TEST: GET /api/users/1 with my auth token - got different user's data!",
                            "COMPARE DATA: Response contains name='Admin', email='admin@target.com'",
                            "VERIFY: This is NOT my data - different name, email, role",
                            "PROVE: Can access ANY user's profile by changing ID parameter"
                        ],
                        "outcome": "Confirmed: IDOR - can access other users' profiles via ID enumeration",
                        "proof": "Different user's PII (name, email) retrieved with attacker's token"
                    }
                ],
                "verification_fp": [
                    {
                        "vuln_type": "idor",
                        "technology": "generic",
                        "scenario": "Same response for different IDs is NOT IDOR",
                        "reasoning_chain": [
                            "CHECK 1: Different ID returns 200? YES",
                            "CHECK 2: But compare the DATA content - is it actually DIFFERENT user data? NO",
                            "CHECK 3: Both IDs return the SAME profile (my own data)",
                            "VERDICT: Server ignores the ID parameter, always returns current user → FALSE POSITIVE"
                        ],
                        "outcome": "REJECTED: Same data returned regardless of ID - no object-level access violation"
                    }
                ]
            },
            "rce": {
                "testing": [
                    {
                        "vuln_type": "rce",
                        "technology": "Node.js",
                        "scenario": "Template rendering endpoint with user-controlled input",
                        "reasoning_chain": [
                            "OBSERVE: Parameter 'name' rendered in template, endpoint uses eval-like function",
                            "PROBE: Sent {{7*7}} - response shows 49 (template injection confirmed)",
                            "ESCALATE: {{require('child_process').execSync('id')}} - returns uid=0(root)!",
                            "EXTRACT: Read /etc/passwd via command execution",
                            "PROVE: OS command output (uid, file contents) confirms RCE"
                        ],
                        "outcome": "Confirmed: RCE via SSTI in Node.js (template to command execution chain)",
                        "payload": "{{require('child_process').execSync('id')}}",
                        "proof": "Command output 'uid=0(root)' in HTTP response"
                    }
                ]
            },
            "ssti": {
                "testing": [
                    {
                        "vuln_type": "ssti",
                        "technology": "Python/Jinja2",
                        "scenario": "Name field rendered via Jinja2 template engine",
                        "reasoning_chain": [
                            "OBSERVE: Input reflected in response via template rendering",
                            "PROBE: {{7*7}} returns '49' - arithmetic evaluated = SSTI confirmed",
                            "IDENTIFY ENGINE: {{config}} returns Flask config = Jinja2 confirmed",
                            "ESCALATE: Use MRO chain to access subprocess module",
                            "EXECUTE: {{''.__class__.__mro__[1].__subclasses__()}} - list Python classes",
                            "PROVE: Achieved code execution via Popen subclass"
                        ],
                        "outcome": "Confirmed: SSTI in Jinja2 with RCE via Python class chain",
                        "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                        "proof": "OS command output returned in template render"
                    }
                ]
            },
            "lfi": {
                "testing": [
                    {
                        "vuln_type": "lfi",
                        "technology": "PHP",
                        "scenario": "File include parameter loading page templates",
                        "reasoning_chain": [
                            "OBSERVE: Parameter 'page=about' loads about.php template",
                            "TEST: page=../../../etc/passwd - returned 'root:x:0:0:root' content!",
                            "VERIFY: Content matches /etc/passwd format (user:x:uid:gid:...)",
                            "ESCALATE: Read application config via page=../config/database.php",
                            "PROVE: Extracted database credentials from config file"
                        ],
                        "outcome": "Confirmed: LFI with path traversal, read sensitive system and app files",
                        "payload": "../../../etc/passwd",
                        "proof": "/etc/passwd content with valid user entries in response"
                    }
                ]
            },
            "auth_bypass": {
                "testing": [
                    {
                        "vuln_type": "auth_bypass",
                        "technology": "REST API",
                        "scenario": "Admin panel behind authentication check",
                        "reasoning_chain": [
                            "OBSERVE: /admin returns 302 redirect to /login",
                            "TEST: Send request without following redirect - check if body has admin content",
                            "PROBE: Try /admin with modified headers (X-Forwarded-For: 127.0.0.1)",
                            "DISCOVER: /admin/ (trailing slash) bypasses auth check! Returns admin panel",
                            "VERIFY: Compare authenticated vs unauthenticated response - SAME admin content",
                            "PROVE: Full admin functionality accessible without any credentials"
                        ],
                        "outcome": "Confirmed: Auth bypass via trailing slash normalization bug",
                        "proof": "Admin panel content accessible without authentication"
                    }
                ]
            },
            "_strategies": {
                "php": {
                    "vuln_type": "strategy",
                    "technology": "PHP",
                    "scenario": "Planning attack strategy for PHP application",
                    "reasoning_chain": [
                        "PHP apps are prone to: SQL injection (especially with raw queries), LFI/RFI (include/require), XSS (echo without htmlspecialchars), file upload bypass, deserialization (unserialize)",
                        "Priority: Test SQL injection on login/search forms, check for LFI in page/template parameters, test file upload functionality for webshell",
                        "PHP-specific: Check for type juggling (== vs ===), test PHP wrapper protocols (php://input, php://filter), check for exposed phpinfo()",
                        "Framework detection: Look for Laravel (.env exposure, debug mode), WordPress (wp-admin, xmlrpc.php), CodeIgniter (CI paths)"
                    ],
                    "outcome": "Focus on SQLi > LFI > XSS > Upload > Deserialization for PHP targets"
                },
                "node": {
                    "vuln_type": "strategy",
                    "technology": "Node.js",
                    "scenario": "Planning attack strategy for Node.js application",
                    "reasoning_chain": [
                        "Node.js apps are prone to: Prototype pollution, SSTI (pug/ejs/handlebars), NoSQL injection (MongoDB), SSRF, insecure deserialization (node-serialize), path traversal",
                        "Priority: Test prototype pollution via JSON body (__proto__), check for SSTI in template params, test NoSQL injection on MongoDB endpoints",
                        "Node-specific: Check for npm package vulns, test for event loop blocking (ReDoS), look for Express middleware bypasses",
                        "API focus: GraphQL introspection, JWT implementation flaws, WebSocket injection"
                    ],
                    "outcome": "Focus on Prototype Pollution > SSTI > NoSQL > SSRF for Node.js targets"
                },
                "python": {
                    "vuln_type": "strategy",
                    "technology": "Python",
                    "scenario": "Planning attack strategy for Python application",
                    "reasoning_chain": [
                        "Python apps are prone to: SSTI (Jinja2/Mako), SQL injection (raw queries, ORM bypass), SSRF, pickle deserialization, command injection (os.system/subprocess)",
                        "Priority: Test SSTI with {{7*7}} on all input fields, check for pickle endpoints, test SSRF on URL parameters",
                        "Python-specific: Django debug mode, Flask debug/secret key exposure, YAML deserialization (yaml.load), eval/exec injection",
                        "Framework: Django admin exposure, Flask /console (Werkzeug debugger), FastAPI /docs endpoint"
                    ],
                    "outcome": "Focus on SSTI > SQLi > SSRF > Deserialization for Python targets"
                },
                "java": {
                    "vuln_type": "strategy",
                    "technology": "Java",
                    "scenario": "Planning attack strategy for Java application",
                    "reasoning_chain": [
                        "Java apps are prone to: Deserialization (ObjectInputStream), XXE (SAX/DOM parsers), SSTI (Velocity/Freemarker), Expression Language injection, Log4Shell",
                        "Priority: Test deserialization on all serialized object endpoints, check XXE on XML parsing endpoints, test EL injection",
                        "Java-specific: Check for Java serialization magic bytes (aced0005), test Log4j via ${jndi:ldap://} in headers, Struts OGNL injection",
                        "Framework: Spring Boot Actuator endpoints (/env, /heapdump), Tomcat manager exposure, JBoss/WildFly admin"
                    ],
                    "outcome": "Focus on Deserialization > XXE > Log4Shell > SSTI for Java targets"
                }
            }
        }

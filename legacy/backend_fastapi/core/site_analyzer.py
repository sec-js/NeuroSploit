"""
NeuroSploit v3 - Site Analyzer

Downloads and analyzes application architecture for deep understanding.
Crawls the target site, converts to structured markdown, and uses AI
to identify attack surfaces, data flows, and logic flaw candidates.

Usage:
    analyzer = SiteAnalyzer(session, llm)
    mirror = await analyzer.crawl_and_download(target_url)
    markdown = analyzer.convert_to_markdown(mirror)
    analysis = await analyzer.ai_analyze_architecture(markdown)
"""

import asyncio
import hashlib
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class PageInfo:
    """Information about a single crawled page."""
    url: str
    title: str = ""
    status: int = 0
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    js_urls: List[str] = field(default_factory=list)
    css_urls: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    file_path: str = ""  # local file path in temp dir


@dataclass
class JSSink:
    """A dangerous JavaScript sink found in code."""
    sink_type: str  # innerHTML, eval, document.write, etc.
    code_snippet: str  # surrounding code context
    file_url: str = ""
    line_hint: str = ""  # approximate location
    source_connected: bool = False  # if we traced a user-controlled source
    risk: str = "medium"  # low, medium, high


@dataclass
class SiteMirror:
    """Result of crawling and downloading a site."""
    target: str = ""
    pages: List[PageInfo] = field(default_factory=list)
    js_files: Dict[str, str] = field(default_factory=dict)  # url -> content
    forms_inventory: List[Dict] = field(default_factory=list)
    all_urls: Set[str] = field(default_factory=set)
    technologies: List[str] = field(default_factory=list)
    temp_dir: str = ""
    crawl_time_ms: float = 0.0
    total_pages: int = 0
    total_js_files: int = 0


@dataclass
class ArchitectureAnalysis:
    """Result of AI architecture analysis."""
    attack_surface_map: Dict[str, List[str]] = field(default_factory=dict)
    priority_endpoints: List[Dict] = field(default_factory=list)
    logic_flaw_candidates: List[str] = field(default_factory=list)
    auth_flow: str = ""
    data_flows: List[str] = field(default_factory=list)
    technology_notes: str = ""
    zero_day_hypotheses: List[str] = field(default_factory=list)
    raw_analysis: str = ""


# ---------------------------------------------------------------------------
# HTML Parser for link/form/script extraction
# ---------------------------------------------------------------------------

class _PageParser(HTMLParser):
    """Extracts links, forms, scripts, and meta from HTML."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self.js_urls: List[str] = []
        self.css_urls: List[str] = []
        self.meta_tags: Dict[str, str] = {}
        self.title = ""
        self._in_title = False
        self._current_form: Optional[Dict] = None
        self._title_parts: List[str] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "a" and "href" in attr_dict:
            self.links.append(attr_dict["href"])

        elif tag == "link" and attr_dict.get("rel", "").lower() == "stylesheet":
            if "href" in attr_dict:
                self.css_urls.append(attr_dict["href"])

        elif tag == "script" and "src" in attr_dict:
            self.js_urls.append(attr_dict["src"])

        elif tag == "meta":
            name = attr_dict.get("name", attr_dict.get("property", ""))
            content = attr_dict.get("content", "")
            if name and content:
                self.meta_tags[name] = content

        elif tag == "title":
            self._in_title = True
            self._title_parts = []

        elif tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": attr_dict.get("type", "text"),
                "value": attr_dict.get("value", ""),
            })

        elif tag == "select" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": "select",
                "value": "",
            })

        elif tag == "textarea" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": "textarea",
                "value": "",
            })

        elif tag == "img" and "src" in attr_dict:
            self.links.append(attr_dict["src"])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
            self.title = "".join(self._title_parts).strip()
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self._title_parts.append(data)


# ---------------------------------------------------------------------------
# JS Sink Patterns
# ---------------------------------------------------------------------------

JS_SINK_PATTERNS = [
    {
        "name": "innerHTML",
        "pattern": r'\.innerHTML\s*=\s*[^;]+',
        "risk": "high",
        "description": "Direct HTML injection via innerHTML",
    },
    {
        "name": "outerHTML",
        "pattern": r'\.outerHTML\s*=\s*[^;]+',
        "risk": "high",
        "description": "Direct HTML injection via outerHTML",
    },
    {
        "name": "document.write",
        "pattern": r'document\.write(?:ln)?\s*\([^)]+\)',
        "risk": "high",
        "description": "Dynamic document writing",
    },
    {
        "name": "eval",
        "pattern": r'(?<!\w)eval\s*\([^)]+\)',
        "risk": "high",
        "description": "Code execution via eval()",
    },
    {
        "name": "setTimeout_string",
        "pattern": r'setTimeout\s*\(\s*["\'][^"\']+["\']',
        "risk": "high",
        "description": "setTimeout with string argument (implicit eval)",
    },
    {
        "name": "setInterval_string",
        "pattern": r'setInterval\s*\(\s*["\'][^"\']+["\']',
        "risk": "high",
        "description": "setInterval with string argument (implicit eval)",
    },
    {
        "name": "location_assign",
        "pattern": r'(?:window\.)?location(?:\.href)?\s*=\s*[^;]+',
        "risk": "medium",
        "description": "Location assignment (potential open redirect / DOM XSS)",
    },
    {
        "name": "jQuery_html",
        "pattern": r'\$\([^)]*\)\.html\s*\([^)]+\)',
        "risk": "high",
        "description": "jQuery .html() injection",
    },
    {
        "name": "jQuery_append",
        "pattern": r'\$\([^)]*\)\.(?:append|prepend|after|before)\s*\([^)]+\)',
        "risk": "medium",
        "description": "jQuery DOM insertion",
    },
    {
        "name": "v_html",
        "pattern": r'v-html\s*=\s*["\'][^"\']+["\']',
        "risk": "high",
        "description": "Vue.js v-html directive (bypasses sanitization)",
    },
    {
        "name": "dangerouslySetInnerHTML",
        "pattern": r'dangerouslySetInnerHTML\s*=\s*\{',
        "risk": "high",
        "description": "React dangerouslySetInnerHTML",
    },
    {
        "name": "Function_constructor",
        "pattern": r'(?:new\s+)?Function\s*\([^)]*\)',
        "risk": "high",
        "description": "Dynamic function creation",
    },
    {
        "name": "postMessage",
        "pattern": r'\.postMessage\s*\([^)]+\)',
        "risk": "medium",
        "description": "Cross-origin messaging (check origin validation)",
    },
    {
        "name": "insertAdjacentHTML",
        "pattern": r'\.insertAdjacentHTML\s*\([^)]+\)',
        "risk": "high",
        "description": "Direct HTML insertion",
    },
]

# JavaScript source patterns (user-controllable input)
JS_SOURCE_PATTERNS = [
    r'location\.(?:hash|search|href|pathname)',
    r'document\.(?:URL|documentURI|referrer|cookie)',
    r'window\.(?:name|location)',
    r'(?:URLSearchParams|location\.search)',
    r'document\.getElementById\([^)]+\)\.value',
    r'localStorage\.getItem\([^)]+\)',
    r'sessionStorage\.getItem\([^)]+\)',
]

# Framework detection patterns
FRAMEWORK_PATTERNS = {
    "React": [r'react(?:\.min)?\.js', r'react-dom', r'_reactRoot', r'__NEXT_DATA__'],
    "Angular": [r'angular(?:\.min)?\.js', r'ng-app', r'ng-controller', r'@angular/core'],
    "Vue": [r'vue(?:\.min)?\.js', r'v-bind:', r'v-model', r'v-for', r'__vue__'],
    "jQuery": [r'jquery(?:\.min)?\.js', r'\$\(document\)', r'jQuery\('],
    "Bootstrap": [r'bootstrap(?:\.min)?\.(?:js|css)'],
    "Axios": [r'axios(?:\.min)?\.js', r'axios\.(get|post|put)'],
    "Angular.js": [r'angular(?:\.min)?\.js', r'ng-app'],
    "Ember": [r'ember(?:\.min)?\.js'],
    "Backbone": [r'backbone(?:\.min)?\.js'],
    "Svelte": [r'svelte', r'__svelte'],
    "Next.js": [r'_next/', r'__NEXT_DATA__'],
    "Nuxt": [r'_nuxt/', r'__NUXT__'],
}

# API endpoint patterns in JS
JS_API_PATTERNS = [
    r'''fetch\s*\(\s*[`"']([^`"']+)[`"']''',
    r'''axios\.(?:get|post|put|patch|delete)\s*\(\s*[`"']([^`"']+)[`"']''',
    r'''\.(?:ajax|get|post)\s*\(\s*\{[^}]*url\s*:\s*[`"']([^`"']+)[`"']''',
    r'''XMLHttpRequest[^;]*\.open\s*\([^,]*,\s*[`"']([^`"']+)[`"']''',
    r'''(?:api|API)_(?:URL|BASE|ENDPOINT|HOST)\s*[:=]\s*[`"']([^`"']+)[`"']''',
    r'''(?:baseURL|baseUrl)\s*[:=]\s*[`"']([^`"']+)[`"']''',
]


# ---------------------------------------------------------------------------
# Site Analyzer
# ---------------------------------------------------------------------------

class SiteAnalyzer:
    """Downloads and analyzes application architecture."""

    def __init__(self, session=None, llm=None, max_pages: int = 50,
                 max_js_size: int = 500000, request_delay: float = 0.3):
        self.session = session
        self.llm = llm
        self.max_pages = max_pages
        self.max_js_size = max_js_size
        self.request_delay = request_delay
        self._temp_dir: Optional[str] = None

    async def crawl_and_download(self, target: str, session=None,
                                  max_pages: Optional[int] = None) -> SiteMirror:
        """Crawl site and download pages to temp directory."""
        sess = session or self.session
        if not sess:
            return SiteMirror(target=target)

        max_p = max_pages or self.max_pages
        mirror = SiteMirror(target=target)
        start_time = time.monotonic()

        # Create temp directory
        self._temp_dir = tempfile.mkdtemp(prefix="neurosploit_site_")
        mirror.temp_dir = self._temp_dir

        # BFS crawl
        parsed_target = urlparse(target)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        visited: Set[str] = set()
        queue: List[str] = [target]
        js_urls_to_fetch: Set[str] = set()

        while queue and len(visited) < max_p:
            url = queue.pop(0)

            # Normalize URL
            url_parsed = urlparse(url)
            normalized = urlunparse((
                url_parsed.scheme, url_parsed.netloc, url_parsed.path,
                '', url_parsed.query, ''
            ))

            if normalized in visited:
                continue

            # Same-origin check
            if not normalized.startswith(target_origin):
                continue

            # Skip non-page resources
            path_lower = url_parsed.path.lower()
            skip_exts = {'.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.pdf',
                        '.zip', '.tar', '.gz', '.mp4', '.mp3', '.woff', '.woff2',
                        '.ttf', '.eot'}
            if any(path_lower.endswith(ext) for ext in skip_exts):
                continue

            visited.add(normalized)

            try:
                await asyncio.sleep(self.request_delay)
                timeout = aiohttp.ClientTimeout(total=10)
                async with sess.get(url, allow_redirects=True, timeout=timeout) as resp:
                    ct = resp.headers.get('Content-Type', '')
                    if 'text/html' not in ct and 'application/xhtml' not in ct:
                        # Still collect JS URLs
                        if 'javascript' in ct:
                            js_urls_to_fetch.add(url)
                        continue

                    body = ""
                    try:
                        raw = await resp.read()
                        body = raw[:200000].decode('utf-8', errors='replace')
                    except Exception:
                        continue

                    page = PageInfo(
                        url=url,
                        status=resp.status,
                        content_type=ct,
                        headers={k: v for k, v in resp.headers.items()},
                        body=body,
                    )

                    # Parse cookies
                    if 'Set-Cookie' in resp.headers:
                        if hasattr(resp.headers, 'getall'):
                            page.cookies = resp.headers.getall('Set-Cookie', [])
                        else:
                            page.cookies = [resp.headers.get('Set-Cookie', '')]

                    # Parse HTML
                    try:
                        parser = _PageParser()
                        parser.feed(body)
                        page.title = parser.title
                        page.forms = parser.forms
                        page.meta_tags = parser.meta_tags
                        page.js_urls = [urljoin(url, js) for js in parser.js_urls]
                        page.css_urls = [urljoin(url, css) for css in parser.css_urls]

                        # Resolve links and add to queue
                        for link in parser.links:
                            abs_link = urljoin(url, link)
                            abs_parsed = urlparse(abs_link)
                            clean_link = urlunparse((
                                abs_parsed.scheme, abs_parsed.netloc,
                                abs_parsed.path, '', abs_parsed.query, ''
                            ))
                            if clean_link.startswith(target_origin) and clean_link not in visited:
                                queue.append(clean_link)
                            page.links.append(abs_link)

                        # Collect JS URLs for later fetch
                        for js_url in page.js_urls:
                            if js_url.startswith(target_origin):
                                js_urls_to_fetch.add(js_url)

                        # Collect forms
                        for form in page.forms:
                            form_entry = {
                                "page_url": url,
                                "action": urljoin(url, form["action"]) if form["action"] else url,
                                "method": form["method"],
                                "inputs": form["inputs"],
                            }
                            mirror.forms_inventory.append(form_entry)

                    except Exception:
                        pass

                    # Save page to temp dir
                    safe_name = hashlib.md5(url.encode()).hexdigest()[:12]
                    file_path = os.path.join(self._temp_dir, f"{safe_name}.html")
                    try:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(body)
                        page.file_path = file_path
                    except Exception:
                        pass

                    mirror.pages.append(page)
                    mirror.all_urls.add(url)

            except Exception:
                continue

        # Fetch JavaScript files
        for js_url in list(js_urls_to_fetch)[:30]:  # cap at 30 JS files
            try:
                await asyncio.sleep(self.request_delay)
                timeout = aiohttp.ClientTimeout(total=10)
                async with sess.get(js_url, timeout=timeout) as resp:
                    if resp.status == 200:
                        raw = await resp.read()
                        js_content = raw[:self.max_js_size].decode('utf-8', errors='replace')
                        mirror.js_files[js_url] = js_content

                        # Save to temp dir
                        safe_name = hashlib.md5(js_url.encode()).hexdigest()[:12]
                        file_path = os.path.join(self._temp_dir, f"{safe_name}.js")
                        try:
                            with open(file_path, 'w', encoding='utf-8') as f:
                                f.write(js_content)
                        except Exception:
                            pass
            except Exception:
                continue

        # Detect technologies
        mirror.technologies = self.detect_client_side_frameworks(mirror)

        mirror.crawl_time_ms = (time.monotonic() - start_time) * 1000
        mirror.total_pages = len(mirror.pages)
        mirror.total_js_files = len(mirror.js_files)

        return mirror

    def convert_to_markdown(self, site_mirror: SiteMirror) -> str:
        """Convert downloaded site to structured markdown for AI analysis."""
        parts = []

        parts.append(f"# Site Analysis: {site_mirror.target}")
        parts.append(f"\n**Pages crawled**: {site_mirror.total_pages}")
        parts.append(f"**JS files**: {site_mirror.total_js_files}")
        parts.append(f"**Crawl time**: {site_mirror.crawl_time_ms:.0f}ms")

        # Technologies
        if site_mirror.technologies:
            parts.append("\n## Detected Technologies\n")
            for tech in site_mirror.technologies:
                parts.append(f"- {tech}")

        # Pages summary
        parts.append("\n## Pages\n")
        for page in site_mirror.pages:
            parts.append(f"\n### {page.title or 'Untitled'} — `{page.url}`")
            parts.append(f"- Status: {page.status}")

            # Important headers
            interesting_headers = ['Server', 'X-Powered-By', 'X-Frame-Options',
                                   'Content-Security-Policy', 'Set-Cookie',
                                   'X-Content-Type-Options', 'Strict-Transport-Security',
                                   'Access-Control-Allow-Origin']
            for hdr in interesting_headers:
                val = page.headers.get(hdr, '')
                if val:
                    parts.append(f"- {hdr}: `{val[:200]}`")

            # Meta tags
            if page.meta_tags:
                gen = page.meta_tags.get('generator', '')
                if gen:
                    parts.append(f"- Generator: {gen}")

            # Links count
            if page.links:
                parts.append(f"- Links: {len(page.links)}")

            # JS references
            if page.js_urls:
                js_basenames = ', '.join(
                    os.path.basename(urlparse(u).path) or u
                    for u in page.js_urls[:5]
                )
                parts.append(f"- JS files: {js_basenames}")

        # Forms inventory
        if site_mirror.forms_inventory:
            parts.append(f"\n## Forms ({len(site_mirror.forms_inventory)} found)\n")
            for form in site_mirror.forms_inventory:
                parts.append(f"\n### Form: `{form['method']} {form['action']}`")
                parts.append(f"Source page: `{form['page_url']}`")
                if form['inputs']:
                    parts.append("Fields:")
                    for inp in form['inputs']:
                        name = inp.get('name', '(unnamed)')
                        itype = inp.get('type', 'text')
                        val = inp.get('value', '')
                        parts.append(
                            f"  - `{name}` (type={itype}"
                            f"{f', default={val}' if val else ''})"
                        )

        # API endpoints from JS
        all_api_endpoints: Set[str] = set()
        for js_url, js_content in site_mirror.js_files.items():
            for pattern in JS_API_PATTERNS:
                for match in re.finditer(pattern, js_content):
                    endpoint = match.group(1)
                    if endpoint and not endpoint.startswith(('http://cdn', 'https://cdn')):
                        all_api_endpoints.add(endpoint)

        if all_api_endpoints:
            parts.append(
                f"\n## API Endpoints Found in JavaScript ({len(all_api_endpoints)})\n"
            )
            for ep in sorted(all_api_endpoints):
                parts.append(f"- `{ep}`")

        # JS sinks summary
        all_sinks: List[JSSink] = []
        for js_url, js_content in site_mirror.js_files.items():
            sinks = self.analyze_js_sinks(js_content, js_url)
            all_sinks.extend(sinks)

        if all_sinks:
            parts.append(f"\n## JavaScript Security Sinks ({len(all_sinks)} found)\n")
            for sink in all_sinks[:20]:  # cap display
                risk_marker = {"high": "!!!", "medium": "!!", "low": "!"}.get(
                    sink.risk, "!"
                )
                file_label = (
                    os.path.basename(urlparse(sink.file_url).path)
                    if sink.file_url else 'inline'
                )
                parts.append(
                    f"- [{risk_marker}] **{sink.sink_type}** in `{file_label}`"
                )
                parts.append(f"  ```js\n  {sink.code_snippet[:150]}\n  ```")

        # All discovered URLs
        if site_mirror.all_urls:
            parts.append(f"\n## All Discovered URLs ({len(site_mirror.all_urls)})\n")
            for url in sorted(site_mirror.all_urls):
                parts.append(f"- `{url}`")

        return "\n".join(parts)

    async def ai_analyze_architecture(self, markdown: str, llm=None,
                                       budget=None) -> ArchitectureAnalysis:
        """AI analysis of application architecture and attack surface."""
        ai = llm or self.llm
        if not ai:
            return ArchitectureAnalysis(raw_analysis="No LLM available for analysis")

        # Check budget
        if budget and hasattr(budget, 'can_spend'):
            if not budget.can_spend("analysis", 2000):
                return ArchitectureAnalysis(
                    raw_analysis="Token budget exhausted — skipping AI analysis"
                )

        # Truncate markdown if too large
        max_context = 15000
        if len(markdown) > max_context:
            markdown = markdown[:max_context] + "\n\n[... truncated ...]"

        prompt = (
            "Analyze this web application's architecture from a penetration "
            "tester's perspective.\n\n"
            f"{markdown}\n\n"
            "Provide your analysis in the following structured format:\n\n"
            "## Attack Surface Map\n"
            "List each category of attack surface with specific endpoints:\n"
            "- Authentication: [endpoints]\n"
            "- Data entry: [forms, APIs]\n"
            "- File handling: [upload/download endpoints]\n"
            "- Admin/Debug: [any found]\n"
            "- API: [REST/GraphQL endpoints]\n\n"
            "## Priority Endpoints (ranked by risk)\n"
            "For each high-risk endpoint, explain WHY it's high risk and what "
            "to test.\n\n"
            "## Authentication Flow\n"
            "Describe how authentication works based on observed forms, cookies, "
            "and headers.\n\n"
            "## Data Flows\n"
            "Trace where user input goes — stored? reflected? processed? "
            "forwarded?\n\n"
            "## Logic Flaw Candidates\n"
            "Identify potential business logic vulnerabilities based on "
            "workflows observed.\n\n"
            "## Zero-Day Hypotheses\n"
            "Based on the technology stack and observed patterns, hypothesize "
            "potential unknown vulnerabilities (custom code bugs, framework "
            "misconfigurations).\n\n"
            "## Technology Notes\n"
            "Framework versions, known CVEs for detected versions, "
            "configuration issues.\n\n"
            "Be specific and actionable. Focus on what a mid-level pentester "
            "should test first."
        )

        try:
            if hasattr(ai, 'generate'):
                raw = await ai.generate(prompt)
            elif callable(ai):
                raw = await ai(prompt)
            else:
                return ArchitectureAnalysis(
                    raw_analysis="LLM interface not recognized"
                )

            if budget and hasattr(budget, 'record'):
                budget.record("analysis", len(prompt) // 4 + len(str(raw)) // 4)

            raw_text = str(raw) if raw else ""

            analysis = ArchitectureAnalysis(raw_analysis=raw_text)

            # Parse sections from AI response
            sections = self._parse_ai_sections(raw_text)
            analysis.auth_flow = sections.get("authentication_flow", "")
            analysis.technology_notes = sections.get("technology_notes", "")

            # Extract logic flaw candidates
            logic_section = sections.get("logic_flaw_candidates", "")
            if logic_section:
                analysis.logic_flaw_candidates = [
                    line.strip().lstrip('- ').lstrip('* ')
                    for line in logic_section.split('\n')
                    if line.strip() and line.strip() not in ('', '-', '*')
                ]

            # Extract zero-day hypotheses
            zd_section = (
                sections.get("zero_day_hypotheses", "")
                or sections.get("zero-day_hypotheses", "")
            )
            if zd_section:
                analysis.zero_day_hypotheses = [
                    line.strip().lstrip('- ').lstrip('* ')
                    for line in zd_section.split('\n')
                    if line.strip() and line.strip() not in ('', '-', '*')
                ]

            # Extract data flows
            df_section = sections.get("data_flows", "")
            if df_section:
                analysis.data_flows = [
                    line.strip().lstrip('- ').lstrip('* ')
                    for line in df_section.split('\n')
                    if line.strip() and line.strip() not in ('', '-', '*')
                ]

            return analysis

        except Exception as e:
            return ArchitectureAnalysis(
                raw_analysis=f"AI analysis error: {str(e)[:200]}"
            )

    def analyze_js_sinks(self, js_content: str, file_url: str = "") -> List[JSSink]:
        """Find dangerous JavaScript sinks for DOM XSS."""
        sinks: List[JSSink] = []
        if not js_content:
            return sinks

        # Check for sources (user-controllable input)
        has_source = False
        for source_pattern in JS_SOURCE_PATTERNS:
            if re.search(source_pattern, js_content):
                has_source = True
                break

        for sink_def in JS_SINK_PATTERNS:
            for match in re.finditer(sink_def["pattern"], js_content):
                # Get surrounding context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end].strip()

                # Check if a source feeds into this sink
                source_connected = False
                if has_source:
                    # Look for source patterns near the sink (within 500 chars)
                    sink_region_start = max(0, match.start() - 500)
                    sink_region_end = min(len(js_content), match.end() + 200)
                    sink_region = js_content[sink_region_start:sink_region_end]
                    for source_pattern in JS_SOURCE_PATTERNS:
                        if re.search(source_pattern, sink_region):
                            source_connected = True
                            break

                risk = sink_def["risk"]
                if source_connected:
                    risk = "high"  # source -> sink = always high risk

                sinks.append(JSSink(
                    sink_type=sink_def["name"],
                    code_snippet=context,
                    file_url=file_url,
                    source_connected=source_connected,
                    risk=risk,
                ))

        return sinks

    def detect_client_side_frameworks(self, site_mirror: SiteMirror) -> List[str]:
        """Detect React, Angular, Vue, jQuery and other frameworks."""
        detected: Set[str] = set()

        # Check all page bodies and JS content
        all_content = ""
        for page in site_mirror.pages:
            all_content += page.body[:10000] + "\n"
        for js_url, js_content in site_mirror.js_files.items():
            all_content += js_content[:10000] + "\n"
            # Also check JS filename
            for framework, patterns in FRAMEWORK_PATTERNS.items():
                for p in patterns:
                    if re.search(p, js_url, re.I):
                        detected.add(framework)

        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for p in patterns:
                if re.search(p, all_content, re.I):
                    detected.add(framework)
                    break

        # Also detect server-side from headers
        for page in site_mirror.pages:
            server = page.headers.get('Server', '')
            if server:
                detected.add(f"Server: {server}")
            powered = page.headers.get('X-Powered-By', '')
            if powered:
                detected.add(f"X-Powered-By: {powered}")

        return sorted(detected)

    def _parse_ai_sections(self, text: str) -> Dict[str, str]:
        """Parse AI response into named sections."""
        sections: Dict[str, str] = {}
        current_key = ""
        current_lines: List[str] = []

        for line in text.split('\n'):
            # Check for section headers (## Header)
            header_match = re.match(r'^#{1,3}\s+(.+)', line)
            if header_match:
                # Save previous section
                if current_key:
                    sections[current_key] = '\n'.join(current_lines).strip()
                # Start new section
                header = header_match.group(1).strip()
                current_key = re.sub(r'[^a-z0-9_]', '_', header.lower()).strip('_')
                current_key = re.sub(r'_+', '_', current_key)
                current_lines = []
            else:
                current_lines.append(line)

        # Save last section
        if current_key:
            sections[current_key] = '\n'.join(current_lines).strip()

        return sections

    def cleanup(self):
        """Remove temp directory."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            import shutil
            try:
                shutil.rmtree(self._temp_dir)
            except Exception:
                pass
            self._temp_dir = None

    def __del__(self):
        self.cleanup()

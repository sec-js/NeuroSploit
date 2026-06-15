"""
Advanced reconnaissance module for NeuroSploitv2.

Performs deep JS analysis, sitemap/robots parsing, API enumeration,
source map parsing, framework-specific discovery, path fuzzing,
and technology fingerprinting using async HTTP requests.
"""

import re
import json
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from xml.etree import ElementTree as ET
except ImportError:
    ET = None

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10) if HAS_AIOHTTP else None
MAX_JS_FILES = 30
MAX_JS_SIZE = 1024 * 1024  # 1 MB
MAX_SITEMAP_URLS = 500
MAX_SITEMAP_DEPTH = 3  # Recursive sitemap index depth
MAX_ENDPOINTS = 2000  # Global cap to prevent memory bloat

# --- Regex patterns for JS analysis ---

RE_API_ENDPOINT = re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9_/\-{}]+)["\']')
RE_RELATIVE_PATH = re.compile(r'["\'](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-{}]+){1,6})["\']')
RE_FETCH_URL = re.compile(r'fetch\(\s*["\']([^"\']+)["\']')
RE_AXIOS_URL = re.compile(r'axios\.(?:get|post|put|patch|delete|request)\(\s*["\']([^"\']+)["\']')
RE_AJAX_URL = re.compile(r'\$\.ajax\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', re.DOTALL)
RE_XHR_URL = re.compile(r'\.open\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']')
RE_TEMPLATE_LITERAL = re.compile(r'`(/[a-zA-Z0-9_/\-]+\$\{[^}]+\}[a-zA-Z0-9_/\-]*)`')
RE_WINDOW_LOCATION = re.compile(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']')
RE_FORM_ACTION = re.compile(r'action\s*[:=]\s*["\']([^"\']+)["\']')
RE_HREF_PATTERN = re.compile(r'href\s*[:=]\s*["\']([^"\']+)["\']')

RE_API_KEY = re.compile(
    r'(?:sk-[a-zA-Z0-9]{20,}|pk_(?:live|test)_[a-zA-Z0-9]{20,}'
    r'|AKIA[0-9A-Z]{16}'
    r'|ghp_[a-zA-Z0-9]{36}'
    r'|glpat-[a-zA-Z0-9\-]{20,}'
    r'|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'
)

RE_INTERNAL_URL = re.compile(
    r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s"\']*'
)

RE_REACT_ROUTE = re.compile(r'path\s*[:=]\s*["\'](/[^"\']*)["\']')
RE_ANGULAR_ROUTE = re.compile(r'path\s*:\s*["\']([^"\']+)["\']')
RE_VUE_ROUTE = re.compile(r'path\s*:\s*["\'](/[^"\']*)["\']')
RE_NEXTJS_PAGE = re.compile(r'"(/[a-zA-Z0-9_/\[\]\-]+)"')

# Source map patterns
RE_SOURCEMAP_URL = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')
RE_SOURCEMAP_ROUTES = re.compile(r'(?:pages|routes|views)/([a-zA-Z0-9_/\[\]\-]+)\.(?:tsx?|jsx?|vue|svelte)')

# GraphQL patterns
RE_GQL_QUERY = re.compile(r'(?:query|mutation|subscription)\s+(\w+)')
RE_GQL_FIELD = re.compile(r'gql\s*`[^`]*`', re.DOTALL)

# Parameter patterns in JS
RE_URL_PARAM = re.compile(r'[?&]([a-zA-Z0-9_]+)=')
RE_BODY_PARAM = re.compile(r'(?:body|data|params)\s*[:=]\s*\{([^}]+)\}', re.DOTALL)
RE_JSON_KEY = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']')


@dataclass
class JSAnalysisResult:
    """Results from JavaScript file analysis."""
    endpoints: List[str] = field(default_factory=list)
    api_keys: List[str] = field(default_factory=list)
    internal_urls: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    source_map_routes: List[str] = field(default_factory=list)


@dataclass
class APISchema:
    """Parsed API schema from Swagger/OpenAPI or GraphQL introspection."""
    endpoints: List[Dict] = field(default_factory=list)
    version: str = ""
    source: str = ""


@dataclass
class EndpointInfo:
    """Rich endpoint descriptor with method and parameter hints."""
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    source: str = ""  # How this endpoint was discovered
    priority: int = 5  # 1-10, higher = more interesting


def _normalize_url(url: str) -> str:
    """Canonicalize a URL for deduplication."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    # Normalize double slashes
    while "//" in path:
        path = path.replace("//", "/")
    # Sort query parameters
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(params.items()), doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{path}?{sorted_query}"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


class DeepRecon:
    """Advanced reconnaissance: JS analysis, sitemap, robots, API enum, fingerprinting."""

    def __init__(self, session: Optional["aiohttp.ClientSession"] = None):
        self._external_session = session is not None
        self._session = session
        self._seen_urls: Set[str] = set()

    async def _get_session(self) -> "aiohttp.ClientSession":
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=REQUEST_TIMEOUT)
            self._external_session = False
        return self._session

    async def close(self):
        if not self._external_session and self._session and not self._session.closed:
            await self._session.close()

    async def _fetch(self, url: str, max_size: int = 0) -> Optional[str]:
        """Fetch URL text with optional size limit. Returns None on any error."""
        try:
            session = await self._get_session()
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                if resp.status != 200:
                    return None
                if max_size:
                    chunk = await resp.content.read(max_size)
                    return chunk.decode("utf-8", errors="replace")
                return await resp.text()
        except Exception:
            return None

    async def _head_check(self, url: str) -> Optional[int]:
        """Quick HEAD request to check if a URL exists. Returns status or None."""
        try:
            session = await self._get_session()
            async with session.head(url, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                return resp.status
        except Exception:
            return None

    async def _check_url_alive(self, url: str, accept_codes: Set[int] = None) -> bool:
        """Check if URL returns an acceptable status code."""
        if accept_codes is None:
            accept_codes = {200, 201, 301, 302, 307, 308, 401, 403}
        status = await self._head_check(url)
        return status is not None and status in accept_codes

    # ------------------------------------------------------------------
    # JS file analysis (enhanced)
    # ------------------------------------------------------------------

    async def crawl_js_files(self, base_url: str, js_urls: List[str]) -> JSAnalysisResult:
        """Fetch and analyse JavaScript files for endpoints, keys, and secrets."""
        result = JSAnalysisResult()
        urls_to_scan = list(dict.fromkeys(js_urls))[:MAX_JS_FILES]

        tasks = [self._fetch(urljoin(base_url, u), max_size=MAX_JS_SIZE) for u in urls_to_scan]
        bodies = await asyncio.gather(*tasks, return_exceptions=True)

        # Also try to fetch source maps in parallel
        sourcemap_tasks = []
        sourcemap_base_urls = []
        for url, body in zip(urls_to_scan, bodies):
            if not isinstance(body, str):
                continue
            sm = RE_SOURCEMAP_URL.search(body)
            if sm:
                sm_url = sm.group(1)
                if not sm_url.startswith("data:"):
                    full_url = urljoin(urljoin(base_url, url), sm_url)
                    sourcemap_tasks.append(self._fetch(full_url, max_size=MAX_JS_SIZE * 2))
                    sourcemap_base_urls.append(full_url)

        sourcemap_bodies = []
        if sourcemap_tasks:
            sourcemap_bodies = await asyncio.gather(*sourcemap_tasks, return_exceptions=True)

        seen_endpoints: set = set()
        seen_params: Dict[str, Set[str]] = {}

        for body in bodies:
            if not isinstance(body, str):
                continue
            self._extract_from_js(body, seen_endpoints, seen_params, result)

        # Parse source maps for original file paths → route discovery
        for sm_body in sourcemap_bodies:
            if not isinstance(sm_body, str):
                continue
            try:
                sm_data = json.loads(sm_body)
                sources = sm_data.get("sources", [])
                for src in sources:
                    m = RE_SOURCEMAP_ROUTES.search(src)
                    if m:
                        route = "/" + m.group(1).replace("[", "{").replace("]", "}")
                        result.source_map_routes.append(route)
                        seen_endpoints.add(route)
            except (json.JSONDecodeError, ValueError):
                # Not valid JSON source map — might still contain paths
                for m in RE_SOURCEMAP_ROUTES.finditer(sm_body):
                    route = "/" + m.group(1).replace("[", "{").replace("]", "}")
                    result.source_map_routes.append(route)
                    seen_endpoints.add(route)

        # Resolve endpoints relative to base_url
        for ep in sorted(seen_endpoints):
            if ep.startswith("http"):
                resolved = ep
            elif ep.startswith("/"):
                resolved = urljoin(base_url, ep)
            else:
                continue
            normalized = _normalize_url(resolved)
            if normalized not in self._seen_urls:
                self._seen_urls.add(normalized)
                result.endpoints.append(resolved)

        # Convert param sets
        for endpoint, params in seen_params.items():
            result.parameters[endpoint] = sorted(params)

        return result

    def _extract_from_js(
        self, body: str, seen_endpoints: set, seen_params: Dict[str, Set[str]],
        result: JSAnalysisResult,
    ):
        """Extract endpoints, params, keys, and internal URLs from a JS body."""
        # API endpoint patterns (expanded)
        for regex in (RE_API_ENDPOINT, RE_RELATIVE_PATH, RE_FETCH_URL, RE_AXIOS_URL,
                      RE_AJAX_URL, RE_XHR_URL, RE_TEMPLATE_LITERAL, RE_WINDOW_LOCATION,
                      RE_FORM_ACTION, RE_HREF_PATTERN):
            for m in regex.finditer(body):
                ep = m.group(1) if regex.groups else m.group(0)
                # Filter out obvious non-endpoints
                if self._is_valid_endpoint(ep):
                    seen_endpoints.add(ep)

        # Route definitions (React Router, Angular, Vue Router, Next.js)
        for regex in (RE_REACT_ROUTE, RE_ANGULAR_ROUTE, RE_VUE_ROUTE, RE_NEXTJS_PAGE):
            for m in regex.finditer(body):
                route = m.group(1)
                if route.startswith("/") and len(route) < 200:
                    seen_endpoints.add(route)

        # Extract URL parameters
        for m in RE_URL_PARAM.finditer(body):
            param_name = m.group(1)
            # Find the URL this param belongs to (rough heuristic)
            start = max(0, m.start() - 200)
            context = body[start:m.start()]
            for ep_regex in (RE_FETCH_URL, RE_API_ENDPOINT):
                ep_match = ep_regex.search(context)
                if ep_match:
                    ep = ep_match.group(1) if ep_regex.groups else ep_match.group(0)
                    if ep not in seen_params:
                        seen_params[ep] = set()
                    seen_params[ep].add(param_name)

        # Extract JSON body parameters
        for m in RE_BODY_PARAM.finditer(body):
            block = m.group(1)
            for key_m in RE_JSON_KEY.finditer(block):
                key = key_m.group(1)
                if len(key) <= 50 and not key.startswith("__"):
                    if "_body_params" not in seen_params:
                        seen_params["_body_params"] = set()
                    seen_params["_body_params"].add(key)

        # API keys / tokens
        for m in RE_API_KEY.finditer(body):
            val = m.group(0)
            if val not in result.api_keys:
                result.api_keys.append(val)
                result.secrets.append(val)

        # Internal / private URLs
        for m in RE_INTERNAL_URL.finditer(body):
            val = m.group(0)
            if val not in result.internal_urls:
                result.internal_urls.append(val)

    @staticmethod
    def _is_valid_endpoint(ep: str) -> bool:
        """Filter out non-endpoint matches (CSS, images, data URIs, etc.)."""
        if not ep or len(ep) > 500:
            return False
        if ep.startswith(("data:", "javascript:", "mailto:", "tel:", "#", "blob:")):
            return False
        # Skip common static assets
        SKIP_EXT = ('.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                     '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webp', '.avif',
                     '.map', '.ts', '.tsx', '.jsx', '.scss', '.less', '.pdf')
        lower = ep.lower()
        if any(lower.endswith(ext) for ext in SKIP_EXT):
            return False
        # Must look like a path
        if ep.startswith("/") or ep.startswith("http"):
            return True
        return False

    # ------------------------------------------------------------------
    # Sitemap parsing (enhanced with recursive index following)
    # ------------------------------------------------------------------

    async def parse_sitemap(self, target: str) -> List[str]:
        """Fetch and parse sitemap XML files for URLs. Follows sitemap indexes recursively."""
        target = target.rstrip("/")
        candidates = [
            f"{target}/sitemap.xml",
            f"{target}/sitemap_index.xml",
            f"{target}/sitemap1.xml",
            f"{target}/sitemap-index.xml",
            f"{target}/sitemaps.xml",
            f"{target}/post-sitemap.xml",
            f"{target}/page-sitemap.xml",
            f"{target}/category-sitemap.xml",
        ]

        # Also check robots.txt for sitemap directives
        robots_body = await self._fetch(f"{target}/robots.txt")
        if robots_body:
            for line in robots_body.splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    sm_url = line.split(":", 1)[1].strip()
                    if sm_url and sm_url not in candidates:
                        candidates.append(sm_url)

        urls: set = set()
        visited_sitemaps: set = set()

        async def _parse_one(sitemap_url: str, depth: int = 0):
            if depth > MAX_SITEMAP_DEPTH or sitemap_url in visited_sitemaps:
                return
            if len(urls) >= MAX_SITEMAP_URLS:
                return
            visited_sitemaps.add(sitemap_url)

            body = await self._fetch(sitemap_url)
            if not body or ET is None:
                return
            try:
                root = ET.fromstring(body)
            except ET.ParseError:
                return

            sub_sitemaps = []
            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag == "loc" and elem.text:
                    loc = elem.text.strip()
                    # Check if this is a sub-sitemap
                    if loc.endswith(".xml") or "sitemap" in loc.lower():
                        sub_sitemaps.append(loc)
                    else:
                        urls.add(loc)
                    if len(urls) >= MAX_SITEMAP_URLS:
                        return

            # Recursively follow sub-sitemaps
            for sub in sub_sitemaps[:10]:  # Limit sub-sitemap recursion
                await _parse_one(sub, depth + 1)

        # Parse all candidate sitemaps
        for sitemap_url in candidates:
            if len(urls) >= MAX_SITEMAP_URLS:
                break
            await _parse_one(sitemap_url)

        return sorted(urls)[:MAX_SITEMAP_URLS]

    # ------------------------------------------------------------------
    # Robots.txt parsing (enhanced with Sitemap extraction)
    # ------------------------------------------------------------------

    async def parse_robots(self, target: str) -> Tuple[List[str], List[str]]:
        """Parse robots.txt. Returns (paths, sitemap_urls)."""
        target = target.rstrip("/")
        body = await self._fetch(f"{target}/robots.txt")
        if not body:
            return [], []

        paths: set = set()
        sitemaps: list = []

        for line in body.splitlines():
            line = line.strip()
            if line.startswith("#") or ":" not in line:
                continue
            directive, _, value = line.partition(":")
            directive = directive.strip().lower()
            value = value.strip()
            if directive in ("disallow", "allow") and value and value != "/":
                resolved = urljoin(target + "/", value)
                paths.add(resolved)
            elif directive == "sitemap" and value:
                sitemaps.append(value)

        return sorted(paths), sitemaps

    # ------------------------------------------------------------------
    # API enumeration (Swagger / OpenAPI / GraphQL / WADL / AsyncAPI)
    # ------------------------------------------------------------------

    _API_DOC_PATHS = [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/swagger/v2/swagger.json",
        "/.well-known/openapi",
        "/api/swagger.json",
        "/api/openapi.json",
        "/api/v1/swagger.json",
        "/api/v1/openapi.json",
        "/api/docs",
        "/docs/api",
        "/doc.json",
        "/public/swagger.json",
        "/swagger-ui/swagger.json",
        "/api-docs.json",
        "/api/api-docs",
        "/_api/docs",
    ]

    _GRAPHQL_PATHS = [
        "/graphql",
        "/graphiql",
        "/api/graphql",
        "/v1/graphql",
        "/gql",
        "/query",
    ]

    async def enumerate_api(self, target: str, technologies: List[str]) -> APISchema:
        """Discover and parse API documentation (OpenAPI/Swagger, GraphQL, WADL)."""
        target = target.rstrip("/")
        schema = APISchema()

        # Try OpenAPI / Swagger endpoints (parallel batch)
        api_tasks = [self._fetch(f"{target}{path}") for path in self._API_DOC_PATHS]
        api_results = await asyncio.gather(*api_tasks, return_exceptions=True)

        for path, body in zip(self._API_DOC_PATHS, api_results):
            if not isinstance(body, str):
                continue
            try:
                doc = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                continue

            if "paths" in doc or "openapi" in doc or "swagger" in doc:
                schema.version = doc.get("openapi", doc.get("info", {}).get("version", ""))
                schema.source = path
                for route, methods in doc.get("paths", {}).items():
                    if not isinstance(methods, dict):
                        continue
                    for method, detail in methods.items():
                        if method.lower() in ("get", "post", "put", "patch", "delete", "options", "head"):
                            params = []
                            if isinstance(detail, dict):
                                for p in detail.get("parameters", []):
                                    if isinstance(p, dict):
                                        params.append(p.get("name", ""))
                                # Also extract request body schema params
                                req_body = detail.get("requestBody", {})
                                if isinstance(req_body, dict):
                                    content = req_body.get("content", {})
                                    for ct, ct_detail in content.items():
                                        if isinstance(ct_detail, dict):
                                            props = ct_detail.get("schema", {}).get("properties", {})
                                            if isinstance(props, dict):
                                                params.extend(props.keys())
                            schema.endpoints.append({
                                "url": route,
                                "method": method.upper(),
                                "params": [p for p in params if p],
                            })
                logger.info(f"[DeepRecon] Found API schema at {path}: {len(schema.endpoints)} endpoints")
                return schema

        # GraphQL introspection (try multiple paths)
        for gql_path in self._GRAPHQL_PATHS:
            introspection = await self._graphql_introspect(f"{target}{gql_path}")
            if introspection:
                return introspection

        return schema

    async def _graphql_introspect(self, gql_url: str) -> Optional[APISchema]:
        """Attempt GraphQL introspection query at a specific URL."""
        query = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name } } } } } }"}'
        try:
            session = await self._get_session()
            headers = {"Content-Type": "application/json"}
            async with session.post(
                gql_url, data=query, headers=headers, ssl=False,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
        except Exception:
            return None

        if "data" not in data or "__schema" not in data.get("data", {}):
            return None

        parsed_url = urlparse(gql_url)
        source_path = parsed_url.path

        schema = APISchema(version="graphql", source=source_path)
        for type_info in data["data"]["__schema"].get("types", []):
            type_name = type_info.get("name", "")
            if type_name.startswith("__") or type_info.get("kind") in ("SCALAR", "ENUM", "INPUT_OBJECT"):
                continue
            for fld in type_info.get("fields", []) or []:
                params = [a["name"] for a in fld.get("args", []) if isinstance(a, dict)]
                schema.endpoints.append({
                    "url": f"/{type_name}/{fld['name']}",
                    "method": "QUERY",
                    "params": params,
                })
        return schema if schema.endpoints else None

    # ------------------------------------------------------------------
    # Framework-specific endpoint discovery
    # ------------------------------------------------------------------

    _FRAMEWORK_PATHS: Dict[str, List[str]] = {
        "wordpress": [
            "/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/posts",
            "/wp-json/wp/v2/users", "/wp-json/wp/v2/pages",
            "/wp-json/wp/v2/categories", "/wp-json/wp/v2/comments",
            "/wp-json/wp/v2/media", "/wp-json/wp/v2/tags",
            "/wp-json/", "/wp-content/uploads/",
            "/wp-cron.php", "/xmlrpc.php", "/?rest_route=/wp/v2/users",
            "/wp-admin/admin-ajax.php", "/wp-admin/load-scripts.php",
            "/wp-includes/wlwmanifest.xml",
        ],
        "laravel": [
            "/api/user", "/api/login", "/api/register",
            "/sanctum/csrf-cookie", "/telescope",
            "/horizon", "/nova-api/", "/_debugbar/open",
            "/storage/logs/laravel.log", "/env",
        ],
        "django": [
            "/admin/", "/admin/login/", "/api/",
            "/__debug__/", "/static/admin/",
            "/accounts/login/", "/accounts/signup/",
            "/api/v1/", "/api/v2/",
        ],
        "spring": [
            "/actuator", "/actuator/health", "/actuator/env",
            "/actuator/beans", "/actuator/mappings", "/actuator/info",
            "/actuator/configprops", "/actuator/metrics",
            "/swagger-ui.html", "/swagger-ui/index.html",
            "/api-docs", "/v3/api-docs",
        ],
        "express": [
            "/api/", "/api/v1/", "/api/health",
            "/api/status", "/auth/login", "/auth/register",
            "/graphql",
        ],
        "aspnet": [
            "/_blazor", "/swagger", "/swagger/index.html",
            "/api/values", "/api/health",
            "/Identity/Account/Login", "/Identity/Account/Register",
        ],
        "rails": [
            "/rails/info", "/rails/mailers",
            "/api/v1/", "/admin/",
            "/users/sign_in", "/users/sign_up",
            "/assets/application.js",
        ],
        "nextjs": [
            "/_next/data/", "/api/", "/api/auth/session",
            "/api/auth/signin", "/api/auth/providers",
            "/_next/static/chunks/",
        ],
        "flask": [
            "/api/", "/api/v1/", "/admin/",
            "/static/", "/auth/login", "/auth/register",
            "/swagger.json",
        ],
    }

    # Common hidden paths to check regardless of framework
    _COMMON_HIDDEN_PATHS = [
        "/.env", "/.git/config", "/.git/HEAD",
        "/backup/", "/backups/", "/backup.sql", "/backup.zip",
        "/config.json", "/config.yaml", "/config.yml",
        "/debug/", "/debug/vars", "/debug/pprof",
        "/internal/", "/internal/health", "/internal/status",
        "/metrics", "/prometheus", "/health", "/healthz", "/ready",
        "/status", "/ping", "/version", "/info",
        "/.well-known/security.txt", "/security.txt",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/server-status", "/server-info",
        "/phpinfo.php", "/info.php",
        "/web.config", "/WEB-INF/web.xml",
        "/console/", "/manage/", "/management/",
        "/api/debug", "/api/config",
        "/trace", "/jolokia/",
        "/cgi-bin/", "/fcgi-bin/",
        "/.htaccess", "/.htpasswd",
    ]

    async def discover_framework_endpoints(
        self, target: str, technologies: List[str]
    ) -> List[EndpointInfo]:
        """Probe framework-specific endpoints based on detected technologies."""
        target = target.rstrip("/")
        tech_lower = [t.lower() for t in technologies]
        endpoints: List[EndpointInfo] = []
        urls_to_check: List[Tuple[str, str, int]] = []  # (url, source, priority)

        # Match frameworks by technology signatures
        fw_matches = set()
        for fw_name, keywords in {
            "wordpress": ["wordpress", "wp-", "woocommerce"],
            "laravel": ["laravel", "php", "lumen"],
            "django": ["django", "python", "wagtail"],
            "spring": ["spring", "java", "tomcat", "wildfly", "jetty"],
            "express": ["express", "node", "koa", "fastify"],
            "aspnet": ["asp.net", ".net", "blazor", "iis"],
            "rails": ["ruby", "rails", "rack"],
            "nextjs": ["next.js", "nextjs", "react", "vercel"],
            "flask": ["flask", "python", "gunicorn", "werkzeug"],
        }.items():
            for kw in keywords:
                for tech in tech_lower:
                    if kw in tech:
                        fw_matches.add(fw_name)
                        break

        # Add framework-specific paths
        for fw in fw_matches:
            for path in self._FRAMEWORK_PATHS.get(fw, []):
                urls_to_check.append((f"{target}{path}", f"framework:{fw}", 7))

        # Always check common hidden paths
        for path in self._COMMON_HIDDEN_PATHS:
            urls_to_check.append((f"{target}{path}", "common_hidden", 6))

        # Batch check existence (parallel HEAD requests)
        check_tasks = [self._check_url_alive(url) for url, _, _ in urls_to_check]
        results = await asyncio.gather(*check_tasks, return_exceptions=True)

        for (url, source, priority), alive in zip(urls_to_check, results):
            if alive is True:
                endpoints.append(EndpointInfo(
                    url=url, method="GET", source=source, priority=priority,
                ))

        logger.info(f"[DeepRecon] Framework discovery: {len(endpoints)}/{len(urls_to_check)} alive")
        return endpoints

    # ------------------------------------------------------------------
    # Path pattern fuzzing
    # ------------------------------------------------------------------

    async def fuzz_api_patterns(
        self, target: str, known_endpoints: List[str]
    ) -> List[EndpointInfo]:
        """Infer and test related endpoints from discovered patterns."""
        target = target.rstrip("/")
        target_parsed = urlparse(target)
        target_origin = f"{target_parsed.scheme}://{target_parsed.netloc}"

        inferred: Set[str] = set()

        # Extract API path patterns
        api_bases: Set[str] = set()
        api_resources: Set[str] = set()

        for ep in known_endpoints:
            parsed = urlparse(ep)
            path = parsed.path
            # Identify API base paths like /api/v1, /api/v2
            m = re.match(r'(/api(?:/v\d+)?)', path)
            if m:
                api_bases.add(m.group(1))
                # Extract resource name
                rest = path[len(m.group(1)):]
                parts = [p for p in rest.split("/") if p and not p.isdigit() and not re.match(r'^[0-9a-f-]{8,}$', p)]
                if parts:
                    api_resources.add(parts[0])

        # Common REST resource names to try
        COMMON_RESOURCES = [
            "users", "user", "auth", "login", "register", "logout",
            "profile", "settings", "admin", "posts", "articles",
            "comments", "categories", "tags", "search", "upload",
            "files", "images", "media", "notifications", "messages",
            "products", "orders", "payments", "invoices", "customers",
            "dashboard", "reports", "analytics", "logs", "events",
            "webhooks", "tokens", "sessions", "roles", "permissions",
            "config", "health", "status", "version", "docs",
        ]

        # Common REST sub-patterns
        CRUD_SUFFIXES = [
            "", "/1", "/me", "/all", "/list", "/search",
            "/count", "/export", "/import", "/bulk",
        ]

        for base in api_bases:
            # Try common resources under each API base
            for resource in COMMON_RESOURCES:
                if resource not in api_resources:
                    inferred.add(f"{target_origin}{base}/{resource}")
            # Try CRUD variants for known resources
            for resource in api_resources:
                for suffix in CRUD_SUFFIXES:
                    inferred.add(f"{target_origin}{base}/{resource}{suffix}")

        # Remove already-known endpoints
        known_normalized = {_normalize_url(ep) for ep in known_endpoints}
        inferred = {url for url in inferred if _normalize_url(url) not in known_normalized}

        # Batch check (parallel, capped)
        to_check = sorted(inferred)[:100]
        check_tasks = [self._check_url_alive(url) for url in to_check]
        results = await asyncio.gather(*check_tasks, return_exceptions=True)

        discovered = []
        for url, alive in zip(to_check, results):
            if alive is True:
                discovered.append(EndpointInfo(
                    url=url, method="GET", source="api_fuzzing", priority=6,
                ))

        logger.info(f"[DeepRecon] API fuzzing: {len(discovered)}/{len(to_check)} alive")
        return discovered

    # ------------------------------------------------------------------
    # Multi-method discovery
    # ------------------------------------------------------------------

    async def discover_methods(
        self, target: str, endpoints: List[str], sample_size: int = 20
    ) -> Dict[str, List[str]]:
        """Test which HTTP methods each endpoint accepts (OPTIONS + probing)."""
        results: Dict[str, List[str]] = {}
        sampled = endpoints[:sample_size]

        async def _check_options(url: str) -> Tuple[str, List[str]]:
            try:
                session = await self._get_session()
                async with session.options(
                    url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    allow = resp.headers.get("Allow", "")
                    if allow:
                        return url, [m.strip().upper() for m in allow.split(",")]
                    # Also check Access-Control-Allow-Methods
                    cors = resp.headers.get("Access-Control-Allow-Methods", "")
                    if cors:
                        return url, [m.strip().upper() for m in cors.split(",")]
            except Exception:
                pass
            return url, []

        tasks = [_check_options(url) for url in sampled]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, tuple):
                url, methods = resp
                if methods:
                    results[url] = methods

        return results

    # ------------------------------------------------------------------
    # Deep technology fingerprinting
    # ------------------------------------------------------------------

    _FINGERPRINT_FILES = [
        "/readme.txt", "/README.md", "/CHANGELOG.md", "/CHANGES.txt",
        "/package.json", "/composer.json", "/Gemfile.lock",
        "/requirements.txt", "/go.mod", "/pom.xml", "/build.gradle",
    ]

    _WP_PROBES = [
        "/wp-links-opml.php",
        "/wp-includes/js/wp-embed.min.js",
    ]

    _DRUPAL_PROBES = [
        "/CHANGELOG.txt",
        "/core/CHANGELOG.txt",
    ]

    RE_VERSION = re.compile(r'["\']?version["\']?\s*[:=]\s*["\']?(\d+\.\d+[\w.\-]*)')
    RE_WP_VER = re.compile(r'ver=(\d+\.\d+[\w.\-]*)')
    RE_DRUPAL_VER = re.compile(r'Drupal\s+(\d+\.\d+[\w.\-]*)')

    async def deep_fingerprint(
        self, target: str, headers: Dict, body: str
    ) -> List[Dict]:
        """Detect software and versions from well-known files and probes."""
        target = target.rstrip("/")
        results: List[Dict] = []
        seen: set = set()

        def _add(software: str, version: str, source: str):
            key = (software.lower(), version)
            if key not in seen:
                seen.add(key)
                results.append({"software": software, "version": version, "source": source})

        # Generic version files
        tasks = {path: self._fetch(f"{target}{path}") for path in self._FINGERPRINT_FILES}
        bodies = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values(), return_exceptions=True)))

        for path, content in bodies.items():
            if not isinstance(content, str):
                continue
            if path.endswith(".json"):
                try:
                    doc = json.loads(content)
                    name = doc.get("name", "unknown")
                    ver = doc.get("version", "")
                    if ver:
                        _add(name, ver, path)
                except (json.JSONDecodeError, ValueError):
                    pass
            elif path == "/go.mod":
                m = re.search(r'^module\s+(\S+)', content, re.MULTILINE)
                if m:
                    _add(m.group(1), "go-module", path)
                for dep_m in re.finditer(r'^\s+(\S+)\s+(v[\d.]+)', content, re.MULTILINE):
                    _add(dep_m.group(1), dep_m.group(2), path)
            elif path == "/requirements.txt":
                for dep_m in re.finditer(r'^([a-zA-Z0-9_\-]+)==([\d.]+)', content, re.MULTILINE):
                    _add(dep_m.group(1), dep_m.group(2), path)
            elif path == "/Gemfile.lock":
                for dep_m in re.finditer(r'^\s{4}([a-z_\-]+)\s+\(([\d.]+)\)', content, re.MULTILINE):
                    _add(dep_m.group(1), dep_m.group(2), path)
            else:
                m = self.RE_VERSION.search(content)
                if m:
                    _add("unknown", m.group(1), path)

        # WordPress probes
        for wp_path in self._WP_PROBES:
            content = await self._fetch(f"{target}{wp_path}")
            if not content:
                continue
            m = self.RE_WP_VER.search(content)
            if m:
                _add("WordPress", m.group(1), wp_path)
            elif "WordPress" in content or "wp-" in content:
                _add("WordPress", "unknown", wp_path)

        # Drupal probes
        for dp_path in self._DRUPAL_PROBES:
            content = await self._fetch(f"{target}{dp_path}")
            if not content:
                continue
            m = self.RE_DRUPAL_VER.search(content)
            if m:
                _add("Drupal", m.group(1), dp_path)

        return results

    # ------------------------------------------------------------------
    # Comprehensive recon pipeline
    # ------------------------------------------------------------------

    async def full_recon(
        self, target: str, technologies: List[str],
        js_urls: List[str], known_endpoints: List[str],
    ) -> Dict:
        """Run ALL recon phases and return aggregated results."""
        results: Dict = {
            "sitemap_urls": [],
            "robots_paths": [],
            "js_analysis": None,
            "api_schema": None,
            "framework_endpoints": [],
            "fuzzed_endpoints": [],
            "method_map": {},
            "fingerprints": [],
            "all_endpoints": [],
        }

        # Run independent phases in parallel
        sitemap_task = self.parse_sitemap(target)
        robots_task = self.parse_robots(target)
        js_task = self.crawl_js_files(target, js_urls) if js_urls else asyncio.sleep(0)
        api_task = self.enumerate_api(target, technologies)
        fw_task = self.discover_framework_endpoints(target, technologies)

        sitemap_result, robots_result, js_result, api_result, fw_result = \
            await asyncio.gather(sitemap_task, robots_task, js_task, api_task, fw_task,
                                 return_exceptions=True)

        if isinstance(sitemap_result, list):
            results["sitemap_urls"] = sitemap_result
        if isinstance(robots_result, tuple):
            results["robots_paths"] = robots_result[0]
        if isinstance(js_result, JSAnalysisResult):
            results["js_analysis"] = js_result
        if isinstance(api_result, APISchema):
            results["api_schema"] = api_result
        if isinstance(fw_result, list):
            results["framework_endpoints"] = fw_result

        # Aggregate all discovered endpoints
        all_eps = set(known_endpoints)
        all_eps.update(results["sitemap_urls"])
        all_eps.update(results["robots_paths"])
        if results["js_analysis"]:
            all_eps.update(results["js_analysis"].endpoints)
        if results["api_schema"]:
            for ep in results["api_schema"].endpoints:
                url = ep.get("url", "")
                if url.startswith("/"):
                    all_eps.add(urljoin(target, url))
                elif url.startswith("http"):
                    all_eps.add(url)
        for fw_ep in results["framework_endpoints"]:
            all_eps.add(fw_ep.url)

        # Now run API fuzzing with ALL known endpoints
        try:
            fuzzed = await self.fuzz_api_patterns(target, sorted(all_eps))
            if isinstance(fuzzed, list):
                results["fuzzed_endpoints"] = fuzzed
                for ep in fuzzed:
                    all_eps.add(ep.url)
        except Exception as e:
            logger.warning(f"[DeepRecon] API fuzzing error: {e}")

        # Discover methods for a sample
        try:
            methods = await self.discover_methods(target, sorted(all_eps))
            results["method_map"] = methods
        except Exception as e:
            logger.warning(f"[DeepRecon] Method discovery error: {e}")

        results["all_endpoints"] = sorted(all_eps)[:MAX_ENDPOINTS]
        logger.info(f"[DeepRecon] Total endpoints discovered: {len(results['all_endpoints'])}")

        return results

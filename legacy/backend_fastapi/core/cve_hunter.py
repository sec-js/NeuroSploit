"""
CVE and exploit search engine for NeuroSploitv2.

Extracts software versions from HTTP responses, queries NVD for known CVEs,
and searches GitHub for public exploit code. Fully async, self-contained.
"""
import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ── Dataclasses ───────────────────────────────────────────────────────────

@dataclass
class VersionInfo:
    software: str
    version: str
    source: str  # "server_header", "body", "meta_generator", etc.

@dataclass
class CVEResult:
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    cwe_id: str
    affected_versions: str
    published_date: str

@dataclass
class ExploitResult:
    source: str  # "github" or "exploitdb"
    url: str
    description: str
    stars: int
    language: str

@dataclass
class CVEFinding:
    version_info: VersionInfo
    cves: List[CVEResult] = field(default_factory=list)
    exploits: List[ExploitResult] = field(default_factory=list)

# ── Regex patterns ────────────────────────────────────────────────────────

_SERVER_TOKEN_RE = re.compile(r"([A-Za-z][\w\.\-]*)/(\d+(?:\.\d+)+)")
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_JS_LIB_RE = re.compile(
    r"(jquery|react|angular|vue|bootstrap|lodash|moment|backbone)"
    r"[\-@/]?(\d+(?:\.\d+)+)", re.I)
_WP_VERSION_RE = re.compile(r'content=["\']WordPress\s+([\d.]+)', re.I)
_DRUPAL_VERSION_RE = re.compile(r'Drupal\s+([\d.]+)', re.I)
_JOOMLA_VERSION_RE = re.compile(
    r'<meta[^>]+content=["\']Joomla!\s*-?\s*([\d.]+)', re.I)
_GENERIC_VERSION_RE = re.compile(
    r"\b([A-Z][A-Za-z\-]+)\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+)?)\b")

_NVD_RPM_NO_KEY = 6
_NVD_RPM_WITH_KEY = 50
_REQUEST_TIMEOUT = 10

# ── CVEHunter ─────────────────────────────────────────────────────────────

class CVEHunter:
    """Async CVE and exploit search engine."""

    def __init__(self, session=None, nvd_api_key=None, github_token=None):
        self._external_session = session is not None
        self._session = session
        self._nvd_api_key = nvd_api_key
        self._github_token = github_token
        rpm = _NVD_RPM_WITH_KEY if nvd_api_key else _NVD_RPM_NO_KEY
        self._nvd_min_interval = 60.0 / rpm
        self._nvd_last_request: float = 0.0

    async def _get_session(self) -> "aiohttp.ClientSession":
        if aiohttp is None:
            raise RuntimeError("aiohttp is required but not installed")
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT))
        return self._session

    async def close(self):
        if not self._external_session and self._session and not self._session.closed:
            await self._session.close()

    # ── Version extraction ────────────────────────────────────────────

    async def extract_versions(self, headers: Dict[str, str], body: str,
                               technologies: Optional[List[str]] = None) -> List[VersionInfo]:
        seen: set[Tuple[str, str]] = set()
        results: List[VersionInfo] = []

        def _add(sw: str, ver: str, src: str):
            key = (sw.lower(), ver)
            if key not in seen:
                seen.add(key)
                results.append(VersionInfo(software=sw, version=ver, source=src))

        # Server header
        server = headers.get("server") or headers.get("Server") or ""
        for m in _SERVER_TOKEN_RE.finditer(server):
            _add(m.group(1), m.group(2), "server_header")

        # X-Powered-By
        xpb = headers.get("x-powered-by") or headers.get("X-Powered-By") or ""
        for m in _SERVER_TOKEN_RE.finditer(xpb):
            _add(m.group(1), m.group(2), "x_powered_by")
        if xpb and not _SERVER_TOKEN_RE.search(xpb):
            parts = xpb.strip().split("/", 1)
            if len(parts) == 2 and re.match(r"\d", parts[1]):
                _add(parts[0].strip(), parts[1].strip(), "x_powered_by")

        # Meta generator tags
        for m in _META_GENERATOR_RE.finditer(body):
            gp = m.group(1).strip().rsplit(" ", 1)
            if len(gp) == 2 and re.match(r"\d", gp[1]):
                _add(gp[0], gp[1], "meta_generator")

        # CMS-specific patterns
        for m in _WP_VERSION_RE.finditer(body):
            _add("WordPress", m.group(1), "body")
        for m in _DRUPAL_VERSION_RE.finditer(body):
            _add("Drupal", m.group(1), "body")
        for m in _JOOMLA_VERSION_RE.finditer(body):
            _add("Joomla", m.group(1), "body")

        # JS libraries (jquery, react, angular, etc.)
        for m in _JS_LIB_RE.finditer(body):
            _add(m.group(1), m.group(2), "body")

        # Generic "SoftwareName version X.Y.Z"
        for m in _GENERIC_VERSION_RE.finditer(body):
            _add(m.group(1), m.group(2), "body")

        # Supplied technology list
        for tech in (technologies or []):
            tp = re.split(r"[\s/]+", tech.strip(), maxsplit=1)
            if len(tp) == 2 and re.match(r"\d", tp[1]):
                _add(tp[0], tp[1], "technology_list")

        return [v for v in results if v.version]

    # ── NVD search ────────────────────────────────────────────────────

    async def _nvd_rate_limit(self):
        elapsed = time.monotonic() - self._nvd_last_request
        if elapsed < self._nvd_min_interval:
            await asyncio.sleep(self._nvd_min_interval - elapsed)
        self._nvd_last_request = time.monotonic()

    async def search_nvd(self, software: str, version: str) -> List[CVEResult]:
        """Query NVD 2.0 API for CVEs matching software + version."""
        session = await self._get_session()
        await self._nvd_rate_limit()

        params = {"keywordSearch": f"{software} {version}"}
        hdrs: Dict[str, str] = {}
        if self._nvd_api_key:
            hdrs["apiKey"] = self._nvd_api_key

        results: List[CVEResult] = []
        try:
            async with session.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                   params=params, headers=hdrs) as resp:
                if resp.status == 403:
                    logger.warning("NVD rate limit hit (403). Backing off.")
                    await asyncio.sleep(30)
                    return results
                if resp.status != 200:
                    logger.warning("NVD returned %d for %s %s", resp.status, software, version)
                    return results
                data = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            logger.warning("NVD request timed out for %s %s", software, version)
            return results
        except Exception as exc:
            logger.warning("NVD request failed for %s %s: %s", software, version, exc)
            return results

        seen_ids: set[str] = set()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)

            # CVSS: prefer v3.1 → v3.0 → v2
            cvss_score, severity = 0.0, "UNKNOWN"
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ml = cve.get("metrics", {}).get(mk, [])
                if ml:
                    cd = ml[0].get("cvssData", {})
                    cvss_score = cd.get("baseScore", 0.0)
                    severity = cd.get("baseSeverity", "UNKNOWN")
                    break

            # English description
            desc = next((d["value"] for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")

            # CWE ID
            cwe_id = ""
            for w in cve.get("weaknesses", []):
                for wd in w.get("description", []):
                    if wd.get("value", "").startswith("CWE-"):
                        cwe_id = wd["value"]
                        break
                if cwe_id:
                    break

            # Affected version ranges from configurations
            vparts: List[str] = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for cm in node.get("cpeMatch", []):
                        vs = cm.get("versionStartIncluding", "")
                        ve = cm.get("versionEndIncluding", "")
                        vee = cm.get("versionEndExcluding", "")
                        if vs and ve:     vparts.append(f"{vs}-{ve}")
                        elif vs and vee:  vparts.append(f"{vs}-<{vee}")
                        elif ve:          vparts.append(f"<={ve}")
                        elif vee:         vparts.append(f"<{vee}")

            results.append(CVEResult(
                cve_id=cve_id, cvss_score=cvss_score, severity=severity.upper(),
                description=desc[:500], cwe_id=cwe_id,
                affected_versions=", ".join(vparts[:5]),
                published_date=cve.get("published", "")[:10],
            ))

        results.sort(key=lambda c: c.cvss_score, reverse=True)
        return results

    # ── GitHub exploit search ─────────────────────────────────────────

    async def search_github_exploits(self, cve_id: str) -> List[ExploitResult]:
        """Search GitHub for public exploit repos matching a CVE ID."""
        session = await self._get_session()

        params = {"q": cve_id, "sort": "stars", "order": "desc", "per_page": "10"}
        hdrs = {"Accept": "application/vnd.github.v3+json"}
        if self._github_token:
            hdrs["Authorization"] = f"token {self._github_token}"

        results: List[ExploitResult] = []
        try:
            async with session.get("https://api.github.com/search/repositories",
                                   params=params, headers=hdrs) as resp:
                if resp.status != 200:
                    logger.warning("GitHub search returned %d for %s", resp.status, cve_id)
                    return results
                data = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            logger.warning("GitHub search timed out for %s", cve_id)
            return results
        except Exception as exc:
            logger.warning("GitHub search failed for %s: %s", cve_id, exc)
            return results

        for repo in data.get("items", []):
            results.append(ExploitResult(
                source="github", url=repo.get("html_url", ""),
                description=(repo.get("description") or "")[:300],
                stars=repo.get("stargazers_count", 0),
                language=repo.get("language") or "Unknown",
            ))
        results.sort(key=lambda e: e.stars, reverse=True)
        return results

    # ── Full pipeline ─────────────────────────────────────────────────

    async def hunt(self, headers: Dict[str, str], body: str,
                   technologies: Optional[List[str]] = None) -> List[CVEFinding]:
        """
        Full pipeline: extract versions -> NVD lookup -> GitHub exploit search.
        Returns findings sorted by highest CVSS score descending.
        """
        versions = await self.extract_versions(headers, body, technologies or [])
        if not versions:
            logger.info("No software versions detected; nothing to hunt.")
            return []

        logger.info("Detected %d software versions, searching CVEs...", len(versions))
        findings: List[CVEFinding] = []
        seen_cves: set[str] = set()

        for vi in versions:
            cves = await self.search_nvd(vi.software, vi.version)
            unique = [c for c in cves if c.cve_id not in seen_cves]
            seen_cves.update(c.cve_id for c in unique)
            if not unique:
                continue

            exploits: List[ExploitResult] = []
            for c in unique:
                exploits.extend(await self.search_github_exploits(c.cve_id))

            findings.append(CVEFinding(version_info=vi, cves=unique, exploits=exploits))

        findings.sort(key=lambda f: max((c.cvss_score for c in f.cves), default=0.0),
                      reverse=True)
        logger.info("CVE hunt complete: %d findings, %d CVEs, %d exploits",
                     len(findings), sum(len(f.cves) for f in findings),
                     sum(len(f.exploits) for f in findings))
        return findings

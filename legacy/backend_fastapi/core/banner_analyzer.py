"""
Banner / version-to-vulnerability mapping module.

Analyses software version strings extracted during reconnaissance and maps
them to known CVEs, end-of-life status, and security advisories.  Every CVE
entry in KNOWN_VULNS references a real, publicly-documented vulnerability.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BannerFinding:
    """A single vulnerability or advisory derived from a version string."""
    software: str
    version: str
    cve: str
    vuln_type: str
    severity: str          # critical | high | medium | low
    description: str
    source: str            # e.g. "banner_analyzer:known_vulns"


# ---------------------------------------------------------------------------
# Severity ordering (lower index == more severe)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# BannerAnalyzer
# ---------------------------------------------------------------------------

class BannerAnalyzer:
    """Map detected software versions to known vulnerabilities."""

    # Each key is "software/version" (lowercase).  Prefix matching is also
    # attempted so "apache/2.4.49" matches entries keyed as "apache/2.4.49".
    KNOWN_VULNS: Dict[str, Dict] = {
        # ---- Apache HTTPD ------------------------------------------------
        "apache/2.4.49": {
            "cve": "CVE-2021-41773",
            "type": "path_traversal",
            "severity": "critical",
            "description": "Path traversal and file disclosure via crafted URI in Apache 2.4.49.",
        },
        "apache/2.4.50": {
            "cve": "CVE-2021-42013",
            "type": "rce",
            "severity": "critical",
            "description": "Remote code execution via path traversal bypass in Apache 2.4.50 (incomplete fix for CVE-2021-41773).",
        },
        "apache/2.4.51": {
            "cve": "CVE-2021-44790",
            "type": "buffer_overflow",
            "severity": "critical",
            "description": "Buffer overflow in mod_lua multipart parser in Apache <= 2.4.51.",
        },
        "apache/2.4.48": {
            "cve": "CVE-2021-33193",
            "type": "http_request_smuggling",
            "severity": "high",
            "description": "HTTP/2 request smuggling via crafted method in Apache 2.4.48.",
        },
        "apache/2.4.46": {
            "cve": "CVE-2020-35452",
            "type": "stack_overflow",
            "severity": "high",
            "description": "Stack overflow via crafted Digest nonce in mod_auth_digest (Apache <= 2.4.46).",
        },
        "apache/2.4.43": {
            "cve": "CVE-2020-9490",
            "type": "dos",
            "severity": "high",
            "description": "Push Diary crash via crafted Cache-Digest header in Apache 2.4.43.",
        },
        "apache/2.4.41": {
            "cve": "CVE-2020-1927",
            "type": "open_redirect",
            "severity": "medium",
            "description": "Open redirect in mod_rewrite when the URL starts with multiple slashes.",
        },
        "apache/2.4.39": {
            "cve": "CVE-2019-10098",
            "type": "open_redirect",
            "severity": "medium",
            "description": "mod_rewrite self-referential redirect causing open redirect.",
        },
        # ---- Nginx -------------------------------------------------------
        "nginx/1.17.9": {
            "cve": "CVE-2021-23017",
            "type": "dns_resolver_rce",
            "severity": "critical",
            "description": "Off-by-one error in nginx DNS resolver allows RCE via crafted DNS response.",
        },
        "nginx/1.18.0": {
            "cve": "CVE-2021-23017",
            "type": "dns_resolver_rce",
            "severity": "critical",
            "description": "Nginx <= 1.20.0 DNS resolver off-by-one heap write (requires resolver directive).",
        },
        "nginx/1.14.0": {
            "cve": "CVE-2019-9511",
            "type": "dos",
            "severity": "high",
            "description": "HTTP/2 Data Dribble DoS in nginx < 1.16.1 / 1.17.3.",
        },
        "nginx/1.16.0": {
            "cve": "CVE-2019-9513",
            "type": "dos",
            "severity": "high",
            "description": "HTTP/2 Resource Loop DoS in nginx < 1.16.1 / 1.17.3.",
        },
        "nginx/1.13.2": {
            "cve": "CVE-2017-7529",
            "type": "information_disclosure",
            "severity": "medium",
            "description": "Integer overflow in range filter allows memory disclosure in nginx < 1.13.3.",
        },
        # ---- PHP ---------------------------------------------------------
        "php/7.4.21": {
            "cve": "CVE-2021-21706",
            "type": "path_traversal",
            "severity": "medium",
            "description": "ZipArchive::extractTo path traversal on Windows in PHP < 7.4.27.",
        },
        "php/7.4.29": {
            "cve": "CVE-2022-31625",
            "type": "use_after_free",
            "severity": "critical",
            "description": "Use-after-free in pg_query_params() in PHP < 7.4.30.",
        },
        "php/8.0.0": {
            "cve": "CVE-2021-21702",
            "type": "dos",
            "severity": "high",
            "description": "Null pointer dereference in SoapClient in PHP 8.0.0.",
        },
        "php/8.0.12": {
            "cve": "CVE-2021-21707",
            "type": "information_disclosure",
            "severity": "medium",
            "description": "URL validation bypass via null bytes in PHP < 8.0.14.",
        },
        "php/8.1.0": {
            "cve": "CVE-2022-31626",
            "type": "buffer_overflow",
            "severity": "critical",
            "description": "Buffer overflow in mysqlnd/pdo_mysql password handling in PHP < 8.1.8.",
        },
        "php/8.1.2": {
            "cve": "CVE-2022-31628",
            "type": "dos",
            "severity": "medium",
            "description": "phar archive infinite loop denial-of-service in PHP < 8.1.10.",
        },
        "php/8.1.12": {
            "cve": "CVE-2022-37454",
            "type": "buffer_overflow",
            "severity": "critical",
            "description": "SHA-3 buffer overflow (XKCP) in PHP < 8.1.13.",
        },
        "php/7.4.3": {
            "cve": "CVE-2020-7068",
            "type": "use_after_free",
            "severity": "high",
            "description": "Use-after-free in PHAR parsing in PHP < 7.4.10.",
        },
        # ---- WordPress ---------------------------------------------------
        "wordpress/5.6": {
            "cve": "CVE-2021-29447",
            "type": "xxe",
            "severity": "high",
            "description": "XXE via media file upload (iXML) in WordPress 5.6-5.7.",
        },
        "wordpress/5.7": {
            "cve": "CVE-2021-29447",
            "type": "xxe",
            "severity": "high",
            "description": "XXE via media file upload (iXML) in WordPress 5.6-5.7.",
        },
        "wordpress/5.0": {
            "cve": "CVE-2019-8942",
            "type": "rce",
            "severity": "critical",
            "description": "Authenticated RCE via crafted post meta in WordPress < 5.0.1.",
        },
        "wordpress/5.4": {
            "cve": "CVE-2020-28032",
            "type": "object_injection",
            "severity": "critical",
            "description": "PHP Object Injection via SimpleXML deserialization in WordPress < 5.5.2.",
        },
        "wordpress/6.0": {
            "cve": "CVE-2022-43504",
            "type": "csrf",
            "severity": "medium",
            "description": "CSRF token verification bypass in WordPress < 6.0.3.",
        },
        "wordpress/6.1": {
            "cve": "CVE-2023-22622",
            "type": "information_disclosure",
            "severity": "medium",
            "description": "Unauthenticated blind SSRF via DNS rebinding in wp-cron (WordPress < 6.1.1).",
        },
        "wordpress/6.2": {
            "cve": "CVE-2023-38000",
            "type": "xss",
            "severity": "medium",
            "description": "Stored XSS via block editor in WordPress < 6.3.2.",
        },
        # ---- jQuery ------------------------------------------------------
        "jquery/1.12.4": {
            "cve": "CVE-2020-11022",
            "type": "xss",
            "severity": "medium",
            "description": "XSS via passing HTML from untrusted source to jQuery DOM manipulation in jQuery < 3.5.0.",
        },
        "jquery/2.2.4": {
            "cve": "CVE-2020-11022",
            "type": "xss",
            "severity": "medium",
            "description": "XSS via passing HTML from untrusted source to jQuery DOM manipulation in jQuery < 3.5.0.",
        },
        "jquery/3.4.1": {
            "cve": "CVE-2020-11022",
            "type": "xss",
            "severity": "medium",
            "description": "XSS in htmlPrefilter regex in jQuery < 3.5.0.",
        },
        "jquery/3.5.0": {
            "cve": "CVE-2020-11023",
            "type": "xss",
            "severity": "medium",
            "description": "XSS when passing <option> HTML to jQuery DOM manipulation methods in jQuery < 3.5.1.",
        },
        # ---- Spring Framework --------------------------------------------
        "spring/4.3.0": {
            "cve": "CVE-2022-22965",
            "type": "rce",
            "severity": "critical",
            "description": "Spring4Shell: RCE via data binding to ClassLoader in Spring Framework < 5.3.18.",
        },
        "spring/5.2.0": {
            "cve": "CVE-2022-22965",
            "type": "rce",
            "severity": "critical",
            "description": "Spring4Shell: RCE via data binding to ClassLoader in Spring Framework < 5.3.18.",
        },
        "spring/5.3.0": {
            "cve": "CVE-2022-22965",
            "type": "rce",
            "severity": "critical",
            "description": "Spring4Shell: RCE via class loader manipulation on JDK 9+ (Spring < 5.3.18).",
        },
        "spring/5.3.17": {
            "cve": "CVE-2022-22965",
            "type": "rce",
            "severity": "critical",
            "description": "Spring4Shell: RCE via class loader manipulation on JDK 9+ (Spring < 5.3.18).",
        },
        # ---- Log4j -------------------------------------------------------
        "log4j/2.0": {
            "cve": "CVE-2021-44228",
            "type": "rce",
            "severity": "critical",
            "description": "Log4Shell: RCE via JNDI lookup injection in Log4j 2.0-2.14.1.",
        },
        "log4j/2.14.1": {
            "cve": "CVE-2021-44228",
            "type": "rce",
            "severity": "critical",
            "description": "Log4Shell: RCE via JNDI lookup injection in Log4j 2.0-2.14.1.",
        },
        "log4j/2.15.0": {
            "cve": "CVE-2021-45046",
            "type": "rce",
            "severity": "critical",
            "description": "Incomplete fix for Log4Shell; RCE still possible via Thread Context Map in Log4j 2.15.0.",
        },
        "log4j/2.16.0": {
            "cve": "CVE-2021-45105",
            "type": "dos",
            "severity": "high",
            "description": "DoS via uncontrolled recursion in lookup evaluation in Log4j 2.16.0.",
        },
        # ---- Apache Tomcat -----------------------------------------------
        "tomcat/9.0.0": {
            "cve": "CVE-2020-1938",
            "type": "file_read",
            "severity": "critical",
            "description": "Ghostcat: AJP file read/inclusion via default AJP connector in Tomcat < 9.0.31.",
        },
        "tomcat/8.5.0": {
            "cve": "CVE-2020-1938",
            "type": "file_read",
            "severity": "critical",
            "description": "Ghostcat: AJP file read/inclusion via default AJP connector in Tomcat < 8.5.51.",
        },
        "tomcat/9.0.30": {
            "cve": "CVE-2020-1938",
            "type": "file_read",
            "severity": "critical",
            "description": "Ghostcat: AJP file read/inclusion via default AJP connector in Tomcat < 9.0.31.",
        },
        "tomcat/10.0.0": {
            "cve": "CVE-2021-25329",
            "type": "rce",
            "severity": "high",
            "description": "RCE via session persistence deserialization in Tomcat 10.0.0-M1 to 10.0.0.",
        },
        "tomcat/9.0.43": {
            "cve": "CVE-2021-25122",
            "type": "information_disclosure",
            "severity": "high",
            "description": "HTTP/2 request mix-up: responses sent to wrong client in Tomcat < 9.0.44.",
        },
        "tomcat/8.5.50": {
            "cve": "CVE-2020-9484",
            "type": "rce",
            "severity": "high",
            "description": "Deserialization RCE via FileStore session persistence in Tomcat < 8.5.55.",
        },
        # ---- OpenSSL -----------------------------------------------------
        "openssl/1.0.1": {
            "cve": "CVE-2014-0160",
            "type": "information_disclosure",
            "severity": "critical",
            "description": "Heartbleed: memory disclosure via TLS heartbeat extension in OpenSSL 1.0.1-1.0.1f.",
        },
        "openssl/1.0.2": {
            "cve": "CVE-2016-2107",
            "type": "padding_oracle",
            "severity": "high",
            "description": "AES-NI CBC MAC check padding oracle in OpenSSL 1.0.2 before 1.0.2h.",
        },
        "openssl/1.1.0": {
            "cve": "CVE-2017-3735",
            "type": "buffer_overread",
            "severity": "medium",
            "description": "One-byte buffer overread parsing IPAddressFamily in OpenSSL < 1.1.0g.",
        },
        "openssl/1.1.1": {
            "cve": "CVE-2020-1971",
            "type": "dos",
            "severity": "high",
            "description": "Null pointer dereference in GENERAL_NAME_cmp (X.400) in OpenSSL < 1.1.1i.",
        },
        "openssl/3.0.0": {
            "cve": "CVE-2022-3602",
            "type": "buffer_overflow",
            "severity": "high",
            "description": "X.509 email address 4-byte buffer overflow in OpenSSL 3.0.0-3.0.6.",
        },
        "openssl/3.0.6": {
            "cve": "CVE-2022-3786",
            "type": "buffer_overflow",
            "severity": "high",
            "description": "X.509 email address variable-length buffer overflow in OpenSSL 3.0.0-3.0.6.",
        },
        # ---- Node.js -----------------------------------------------------
        "node/14.0.0": {
            "cve": "CVE-2021-22930",
            "type": "use_after_free",
            "severity": "critical",
            "description": "Use-after-free on close http2 on stream canceling in Node.js < 14.17.5.",
        },
        "node/16.0.0": {
            "cve": "CVE-2021-22931",
            "type": "rce",
            "severity": "critical",
            "description": "Improper handling of untypical characters in domain names allowing RCE in Node.js < 16.6.2.",
        },
        "node/16.13.0": {
            "cve": "CVE-2022-21824",
            "type": "prototype_pollution",
            "severity": "medium",
            "description": "Prototype pollution via console.table in Node.js < 16.13.2.",
        },
        "node/18.0.0": {
            "cve": "CVE-2022-32215",
            "type": "http_request_smuggling",
            "severity": "high",
            "description": "HTTP request smuggling due to incorrect Transfer-Encoding parsing in Node.js < 18.5.0.",
        },
        "node/18.12.0": {
            "cve": "CVE-2023-23918",
            "type": "privilege_escalation",
            "severity": "high",
            "description": "Permissions policy bypass via process.mainModule in Node.js < 18.14.1.",
        },
        # ---- Django ------------------------------------------------------
        "django/2.2": {
            "cve": "CVE-2021-35042",
            "type": "sqli",
            "severity": "critical",
            "description": "SQL injection via untrusted data in QuerySet.order_by() in Django < 2.2.25.",
        },
        "django/3.0": {
            "cve": "CVE-2020-9402",
            "type": "sqli",
            "severity": "high",
            "description": "SQL injection via crafted tolerance parameter in GIS functions (Django < 3.0.4).",
        },
        "django/3.1": {
            "cve": "CVE-2021-33571",
            "type": "header_injection",
            "severity": "medium",
            "description": "URLValidator allows leading/trailing whitespace, enabling header injection (Django < 3.1.13).",
        },
        "django/3.2": {
            "cve": "CVE-2021-45115",
            "type": "dos",
            "severity": "high",
            "description": "DoS via UserAttributeSimilarityValidator with a large password (Django < 3.2.11).",
        },
        "django/4.0": {
            "cve": "CVE-2022-28346",
            "type": "sqli",
            "severity": "critical",
            "description": "SQL injection via crafted column aliases in QuerySet.annotate()/aggregate() (Django < 4.0.4).",
        },
        "django/4.1": {
            "cve": "CVE-2023-23969",
            "type": "dos",
            "severity": "high",
            "description": "DoS via large Accept-Language header in Django < 4.1.6.",
        },
        # ---- Laravel -----------------------------------------------------
        "laravel/8.0": {
            "cve": "CVE-2021-3129",
            "type": "rce",
            "severity": "critical",
            "description": "RCE via Ignition debug mode file manipulation in Laravel/Ignition < 2.5.2.",
        },
        "laravel/9.0": {
            "cve": "CVE-2022-40482",
            "type": "information_disclosure",
            "severity": "medium",
            "description": "Route parameter exposure via debug error pages in Laravel < 9.32.0.",
        },
        "laravel/7.0": {
            "cve": "CVE-2021-3129",
            "type": "rce",
            "severity": "critical",
            "description": "RCE via Ignition debug mode (phar deserialization) in Laravel/Ignition <= 2.5.1.",
        },
        # ---- Ruby on Rails -----------------------------------------------
        "rails/5.2.0": {
            "cve": "CVE-2019-5418",
            "type": "file_read",
            "severity": "critical",
            "description": "File content disclosure via Action View render with Accept header manipulation.",
        },
        "rails/6.0.0": {
            "cve": "CVE-2020-8163",
            "type": "rce",
            "severity": "critical",
            "description": "RCE via code injection in Action Pack in Rails < 6.0.3.1.",
        },
        "rails/6.1.0": {
            "cve": "CVE-2021-22885",
            "type": "information_disclosure",
            "severity": "high",
            "description": "Possible information disclosure via unintended method execution in Action Pack.",
        },
        "rails/7.0.0": {
            "cve": "CVE-2022-32224",
            "type": "rce",
            "severity": "critical",
            "description": "Possible RCE via serialized columns in Active Record (Rails < 7.0.3.1).",
        },
        "rails/6.0.3": {
            "cve": "CVE-2021-22904",
            "type": "dos",
            "severity": "high",
            "description": "DoS via crafted Accept header in Action Controller (Rails < 6.0.3.7).",
        },
        # ---- Express.js --------------------------------------------------
        "express/4.17.0": {
            "cve": "CVE-2022-24999",
            "type": "prototype_pollution",
            "severity": "high",
            "description": "Prototype pollution via qs library (< 6.10.3) used in Express < 4.17.3.",
        },
        "express/4.16.0": {
            "cve": "CVE-2022-24999",
            "type": "prototype_pollution",
            "severity": "high",
            "description": "Prototype pollution via qs library in Express < 4.17.3.",
        },
        "express/4.6.0": {
            "cve": "CVE-2014-6393",
            "type": "xss",
            "severity": "medium",
            "description": "XSS via missing Content-Type in Express < 4.11.0.",
        },
        # ---- IIS ---------------------------------------------------------
        "iis/10.0": {
            "cve": "CVE-2021-31166",
            "type": "rce",
            "severity": "critical",
            "description": "HTTP protocol stack RCE (wormable) in IIS on Windows 10 / Server (KB5003173).",
        },
        "iis/7.5": {
            "cve": "CVE-2017-7269",
            "type": "buffer_overflow",
            "severity": "critical",
            "description": "Buffer overflow in WebDAV service in IIS 6.0/7.5 allows RCE.",
        },
        # ---- Drupal ------------------------------------------------------
        "drupal/7.0": {
            "cve": "CVE-2018-7600",
            "type": "rce",
            "severity": "critical",
            "description": "Drupalgeddon2: RCE via Form API render array injection in Drupal 7.x < 7.58.",
        },
        "drupal/8.0": {
            "cve": "CVE-2019-6340",
            "type": "rce",
            "severity": "critical",
            "description": "RCE via REST module deserialization in Drupal 8.5.x < 8.5.11 / 8.6.x < 8.6.10.",
        },
        # ---- Joomla ------------------------------------------------------
        "joomla/3.9.0": {
            "cve": "CVE-2023-23752",
            "type": "information_disclosure",
            "severity": "high",
            "description": "Unauthenticated information disclosure via Rest API in Joomla 4.0.0-4.2.7.",
        },
        # ---- Elasticsearch -----------------------------------------------
        "elasticsearch/1.2.0": {
            "cve": "CVE-2014-3120",
            "type": "rce",
            "severity": "critical",
            "description": "RCE via MVEL scripting engine enabled by default in Elasticsearch < 1.2.1.",
        },
    }

    # End-of-life version prefixes: any detected version starting with one of
    # these is considered unsupported and should be flagged.
    EOL_VERSIONS: Dict[str, List[str]] = {
        "php": ["4.", "5.", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0"],
        "python": ["2.", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7"],
        "node": ["8.", "10.", "12.", "14.", "15.", "16.", "17.", "19."],
        "django": ["1.", "2.0", "2.1", "2.2", "3.0", "3.1"],
        "rails": ["4.", "5.0", "5.1", "5.2", "6.0"],
        "angular": ["1.", "2.", "4.", "5.", "6.", "7.", "8.", "9.", "10.", "11."],
        "jquery": ["1.", "2."],
        "wordpress": ["3.", "4."],
        "apache": ["2.2.", "2.0.", "1.3."],
        "nginx": ["1.14.", "1.16.", "1.17."],
        "openssl": ["0.", "1.0.", "1.1.0"],
        "tomcat": ["6.", "7.", "8.0."],
        "dotnet": ["1.", "2.", "3.0", "3.1", "5."],
        "java": ["6.", "7.", "8.", "9.", "10.", "11."],
        "laravel": ["5.", "6.", "7."],
        "express": ["3.", "2.", "1."],
        "drupal": ["6.", "7.", "8."],
        "iis": ["6.", "7.", "7.5", "8."],
        "elasticsearch": ["1.", "2.", "5.", "6."],
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, version_info: List[Dict]) -> List[BannerFinding]:
        """Analyse a list of detected software/version dicts.

        Each dict should contain at minimum ``software`` and ``version`` keys.
        Returns a list of :class:`BannerFinding` sorted by severity
        (critical first).
        """
        findings: List[BannerFinding] = []

        for entry in version_info:
            software = str(entry.get("software", "")).strip().lower()
            version = str(entry.get("version", "")).strip()
            if not software or not version:
                continue

            # --- exact match ---
            key = f"{software}/{version}"
            vuln = self.KNOWN_VULNS.get(key)
            if vuln:
                findings.append(self._to_finding(software, version, vuln, "exact"))

            # --- prefix match (catches minor-version ranges) ---
            for known_key, known_vuln in self.KNOWN_VULNS.items():
                if known_key == key:
                    continue  # already handled
                ks, kv = known_key.split("/", 1)
                if ks == software and (version.startswith(kv) or kv.startswith(version)):
                    findings.append(self._to_finding(software, version, known_vuln, "prefix"))

            # --- EOL check ---
            if self.is_eol(software, version):
                findings.append(BannerFinding(
                    software=software,
                    version=version,
                    cve="N/A",
                    vuln_type="eol_software",
                    severity="medium",
                    description=f"{software} {version} has reached end-of-life and no longer receives security updates.",
                    source="banner_analyzer:eol_check",
                ))

        # Deduplicate by (software, version, cve)
        seen: set = set()
        unique: List[BannerFinding] = []
        for f in findings:
            ident = (f.software, f.version, f.cve)
            if ident not in seen:
                seen.add(ident)
                unique.append(f)

        unique.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        return unique

    def is_eol(self, software: str, version: str) -> bool:
        """Return True if *version* matches an end-of-life prefix for *software*."""
        software = software.strip().lower()
        version = version.strip()
        prefixes = self.EOL_VERSIONS.get(software, [])
        return any(version.startswith(p) for p in prefixes)

    @staticmethod
    def check_version_range(
        software: str,
        version: str,
        min_affected: str,
        max_fixed: str,
    ) -> bool:
        """Return True if *version* falls within [min_affected, max_fixed).

        Uses tuple comparison on integer version parts so that
        ``"2.4.49" >= "2.4.49"`` and ``"2.4.49" < "2.4.52"`` hold.
        """
        def _parse(v: str) -> Tuple[int, ...]:
            parts: List[int] = []
            for segment in v.split("."):
                # Strip non-numeric suffixes (e.g. "3.0.0-beta")
                num = ""
                for ch in segment:
                    if ch.isdigit():
                        num += ch
                    else:
                        break
                parts.append(int(num) if num else 0)
            return tuple(parts)

        try:
            v = _parse(version)
            lo = _parse(min_affected)
            hi = _parse(max_fixed)
            return lo <= v < hi
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_finding(
        software: str,
        version: str,
        vuln: Dict,
        match_type: str,
    ) -> BannerFinding:
        return BannerFinding(
            software=software,
            version=version,
            cve=vuln["cve"],
            vuln_type=vuln["type"],
            severity=vuln["severity"],
            description=vuln["description"],
            source=f"banner_analyzer:known_vulns:{match_type}",
        )

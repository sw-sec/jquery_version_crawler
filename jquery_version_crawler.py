#python3 jquery_version_crawler.py -u https://target.com

#!/usr/bin/env python3
"""
jQuery Version Crawler
======================
Author  : SW/SEC Security Consulting
Purpose : Crawl a web application and enumerate all jQuery versions loaded
          across discovered pages. Useful for SCA checks and OWASP WSTG-CLNT
          assessments.

Usage:
    python3 jquery_version_crawler.py -u https://example.com
    python3 jquery_version_crawler.py -u https://example.com -d 3 --timeout 15
    python3 jquery_version_crawler.py -u https://example.com --output results.json

Flags:
    -u / --url          Target application base URL (required)
    -d / --depth        Max crawl depth (default: 3)
    -t / --threads      Concurrent threads (default: 10)
    --timeout           HTTP request timeout in seconds (default: 10)
    --user-agent        Custom User-Agent string
    --cookies           Cookie header string (e.g. "session=abc123")
    --headers           Extra headers as JSON string
    --ignore-ssl        Disable SSL certificate verification
    --scope-only        Stay within the base domain (default: True)
    --output            Save findings to a JSON file
    --verbose           Verbose output
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.robotparser import RobotFileParser

try:
    import requests
    from bs4 import BeautifulSoup
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    print("[!] Missing dependencies. Install with:")
    print("    pip install requests beautifulsoup4")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns for jQuery version detection
# ─────────────────────────────────────────────────────────────────────────────

# Matches src attributes like:
#   jquery-3.6.0.min.js
#   jquery/3.6.0/jquery.min.js
#   cdn.../jquery@3.6.0/...
JQUERY_SRC_RE = re.compile(
    r'jquery[.-]?(?:min\.|core\.)?'   # file-name based
    r'(\d+\.\d+(?:\.\d+)?)'           # version group
    r'(?:\.min)?\.js',
    re.IGNORECASE
)

# Matches inline JS: jQuery.fn.jquery / $.fn.jquery = "3.6.0"
JQUERY_INLINE_RE = re.compile(
    r'(?:jQuery|\\$)\.fn\.jquery\s*[=:]\s*["\'](\d+\.\d+(?:\.\d+)?)["\']'
)

# Matches the canonical version string baked into jQuery source
JQUERY_CANONICAL_RE = re.compile(
    r'(?:var\s+version\s*=\s*|jQuery\.fn\.jquery\s*=\s*)["\'](\d+\.\d+(?:\.\d+)?)["\']'
)

# Common CDN URL patterns
JQUERY_CDN_URL_RE = re.compile(
    r'(?:jquery(?:ui)?|cdn\.jsdelivr\.net/npm/jquery|cdnjs\.cloudflare\.com/'
    r'ajax/libs/jquery|ajax\.googleapis\.com/ajax/libs/jquery|code\.jquery\.com)'
    r'.*?(\d+\.\d+(?:\.\d+)?).*?\.js',
    re.IGNORECASE
)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class JQueryFinding:
    version: str
    source_url: str          # URL of the JS file or "inline"
    discovered_on: str       # Page URL where it was found
    detection_method: str    # e.g. "filename", "cdn_url", "inline_var"
    vulnerable: Optional[bool] = None
    cve_notes: str = ""


@dataclass
class CrawlResult:
    target_url: str
    pages_visited: int = 0
    pages_failed: int = 0
    jquery_findings: list = field(default_factory=list)
    unique_versions: list = field(default_factory=list)
    crawl_duration_seconds: float = 0.0

    def summary(self) -> dict:
        d = asdict(self)
        d["jquery_findings"] = [asdict(f) for f in self.jquery_findings]
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Known vulnerable jQuery versions (simplified — add CVE mappings as needed)
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_VERSIONS: dict[str, str] = {
    # version_prefix : note
    "1.": "All 1.x — multiple XSS/prototype-pollution CVEs (CVE-2015-9251, CVE-2019-11358, etc.)",
    "2.": "All 2.x — CVE-2019-11358 (prototype pollution), jQuery-migrate issues",
    "3.0": "CVE-2019-11358 (prototype pollution)",
    "3.1": "CVE-2019-11358 (prototype pollution)",
    "3.2": "CVE-2019-11358 (prototype pollution)",
    "3.3": "CVE-2019-11358 (prototype pollution)",
    "3.4": "CVE-2020-11022, CVE-2020-11023 (XSS via .html()/.load())",
    "3.5": "CVE-2020-11022, CVE-2020-11023 (XSS via .html()/.load())",
}

SAFE_VERSION = "3.6.0"  # First widely considered safe; 3.7.1+ recommended


def assess_vulnerability(version: str) -> tuple[bool, str]:
    """Return (is_vulnerable, cve_notes) for a jQuery version string."""
    for prefix, note in VULNERABLE_VERSIONS.items():
        if version.startswith(prefix):
            return True, note
    # Compare against safe version
    try:
        parts = [int(x) for x in version.split(".")]
        safe = [int(x) for x in SAFE_VERSION.split(".")]
        if parts < safe:
            return True, f"Version older than {SAFE_VERSION} — check NVD for applicable CVEs"
    except ValueError:
        pass
    return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Core crawler
# ─────────────────────────────────────────────────────────────────────────────

class JQueryCrawler:
    def __init__(self, args: argparse.Namespace):
        self.base_url = args.url.rstrip("/")
        self.base_domain = urllib.parse.urlparse(self.base_url).netloc
        self.max_depth = args.depth
        self.threads = args.threads
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.scope_only = args.scope_only
        self.output_file = args.output

        # HTTP session
        self.session = requests.Session()
        self.session.verify = not args.ignore_ssl
        if args.ignore_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        ua = args.user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 "
            "JQuerySecurityAudit/1.0"
        )
        self.session.headers.update({"User-Agent": ua})

        if args.cookies:
            self.session.headers["Cookie"] = args.cookies

        if args.headers:
            try:
                extra = json.loads(args.headers)
                self.session.headers.update(extra)
            except json.JSONDecodeError:
                self._warn("Could not parse --headers JSON; ignoring.")

        # State
        self.visited: set[str] = set()
        self.findings: list[JQueryFinding] = []
        self.seen_js_urls: set[str] = set()
        self.lock = __import__("threading").Lock()

    # ── Logging helpers ───────────────────────────────────────────────────────

    def _log(self, msg: str):
        print(f"[*] {msg}")

    def _info(self, msg: str):
        if self.verbose:
            print(f"    {msg}")

    def _warn(self, msg: str):
        print(f"[!] {msg}", file=sys.stderr)

    def _found(self, finding: JQueryFinding):
        tag = "VULN" if finding.vulnerable else "OK  "
        print(
            f"  [jQuery {finding.version}] [{tag}] "
            f"src={finding.source_url[:80]}"
        )
        if finding.cve_notes:
            print(f"           ^ {finding.cve_notes}")

    # ── URL helpers ───────────────────────────────────────────────────────────

    def _normalise(self, url: str, base: str) -> Optional[str]:
        """Resolve relative URLs, strip fragments, enforce scope."""
        url = url.strip()
        if url.startswith(("javascript:", "mailto:", "data:", "#", "")):
            return None
        resolved = urllib.parse.urljoin(base, url)
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme not in ("http", "https"):
            return None
        if self.scope_only and parsed.netloc != self.base_domain:
            return None
        # Strip fragment
        clean = parsed._replace(fragment="").geturl()
        return clean

    def _is_in_scope(self, url: str) -> bool:
        if not self.scope_only:
            return True
        return urllib.parse.urlparse(url).netloc == self.base_domain

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            resp.raise_for_status()
            return resp
        except requests.exceptions.SSLError:
            self._warn(f"SSL error on {url} — try --ignore-ssl")
        except requests.exceptions.ConnectionError:
            self._warn(f"Connection error: {url}")
        except requests.exceptions.Timeout:
            self._warn(f"Timeout: {url}")
        except requests.exceptions.HTTPError as e:
            self._info(f"HTTP {e.response.status_code}: {url}")
        except Exception as e:
            self._info(f"Error fetching {url}: {e}")
        return None

    # ── Detection helpers ─────────────────────────────────────────────────────

    def _extract_version_from_js_url(self, js_url: str) -> Optional[str]:
        """Try to extract version from the JS file URL/path alone."""
        for pattern in (JQUERY_SRC_RE, JQUERY_CDN_URL_RE):
            m = pattern.search(js_url)
            if m:
                return m.group(1)
        return None

    def _extract_version_from_js_content(self, content: str) -> Optional[str]:
        """Parse inline JS content for version strings."""
        for pattern in (JQUERY_CANONICAL_RE, JQUERY_INLINE_RE):
            m = pattern.search(content)
            if m:
                return m.group(1)
        return None

    def _record_finding(self, version: str, source_url: str,
                        page_url: str, method: str):
        vuln, notes = assess_vulnerability(version)
        finding = JQueryFinding(
            version=version,
            source_url=source_url,
            discovered_on=page_url,
            detection_method=method,
            vulnerable=vuln,
            cve_notes=notes,
        )
        with self.lock:
            self.findings.append(finding)
        self._found(finding)

    # ── JS file analysis ──────────────────────────────────────────────────────

    def _analyse_js_file(self, js_url: str, page_url: str):
        """Fetch a JS file and attempt version extraction."""
        if js_url in self.seen_js_urls:
            return
        with self.lock:
            if js_url in self.seen_js_urls:
                return
            self.seen_js_urls.add(js_url)

        # Method 1: URL-based detection (fast, no download needed)
        version = self._extract_version_from_js_url(js_url)
        if version:
            self._record_finding(version, js_url, page_url, "filename/url")
            return

        # Method 2: Fetch first 8KB of the JS file and scan content
        self._info(f"Fetching JS: {js_url}")
        resp = self._get(js_url)
        if not resp:
            return

        content_type = resp.headers.get("Content-Type", "")
        if "javascript" not in content_type and "text" not in content_type:
            return  # Skip binary responses

        # Only scan JS that looks like it could be jQuery
        snippet = resp.text[:8192]
        if "jquery" not in snippet.lower() and "jQuery" not in snippet:
            return

        version = self._extract_version_from_js_content(resp.text)
        if version:
            self._record_finding(version, js_url, page_url, "js_content_scan")

    # ── Page analysis ─────────────────────────────────────────────────────────

    def _analyse_page(self, url: str, depth: int) -> list[str]:
        """
        Fetch a page, detect jQuery references, and return discovered links.
        Returns list of (url, depth+1) tuples to enqueue.
        """
        self._info(f"[depth={depth}] {url}")
        resp = self._get(url)
        if not resp:
            return []

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        next_links: list[str] = []

        # ── Script tags ───────────────────────────────────────────────────────
        for tag in soup.find_all("script"):
            src = tag.get("src", "")
            if src:
                js_url = self._normalise(src, url)
                if js_url and "jquery" in src.lower():
                    self._analyse_js_file(js_url, url)
                elif js_url:
                    # Still queue non-jQuery scripts for inline version checks
                    # (only if they look like they might include jQuery bundles)
                    if any(k in src.lower() for k in ("bundle", "vendor", "lib", "main", "app")):
                        self._analyse_js_file(js_url, url)
            else:
                # Inline script — scan for jQuery version declarations
                inline = tag.get_text()
                if "jquery" in inline.lower() or "jQuery" in inline:
                    version = self._extract_version_from_js_content(inline)
                    if version:
                        self._record_finding(
                            version, "inline", url, "inline_script_block"
                        )

        # ── Collect links for further crawling ────────────────────────────────
        if depth < self.max_depth:
            for a in soup.find_all("a", href=True):
                link = self._normalise(a["href"], url)
                if link:
                    next_links.append(link)

        return next_links

    # ── Main crawl loop ───────────────────────────────────────────────────────

    def crawl(self) -> CrawlResult:
        result = CrawlResult(target_url=self.base_url)
        start = time.time()

        self._log(f"Target     : {self.base_url}")
        self._log(f"Max depth  : {self.max_depth}")
        self._log(f"Threads    : {self.threads}")
        self._log(f"Scope-only : {self.scope_only}")
        print()

        # BFS queue: (url, depth)
        queue: list[tuple[str, int]] = [(self.base_url, 0)]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while queue:
                # Batch submit all current queue items
                batch = []
                for url, depth in queue:
                    with self.lock:
                        if url in self.visited:
                            continue
                        self.visited.add(url)
                    batch.append((url, depth))

                if not batch:
                    break

                queue = []
                futures = {
                    executor.submit(self._analyse_page, url, depth): (url, depth)
                    for url, depth in batch
                }

                for future in as_completed(futures):
                    url, depth = futures[future]
                    try:
                        links = future.result()
                        result.pages_visited += 1
                        if depth < self.max_depth:
                            for link in links:
                                with self.lock:
                                    if link not in self.visited:
                                        queue.append((link, depth + 1))
                    except Exception as e:
                        result.pages_failed += 1
                        self._warn(f"Error processing {url}: {e}")

        result.crawl_duration_seconds = round(time.time() - start, 2)
        result.jquery_findings = self.findings
        result.unique_versions = sorted(
            set(f.version for f in self.findings)
        )
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_report(result: CrawlResult):
    print()
    print("=" * 65)
    print("  jQuery Version Audit — Final Report")
    print("=" * 65)
    print(f"  Target         : {result.target_url}")
    print(f"  Pages crawled  : {result.pages_visited}")
    print(f"  Pages failed   : {result.pages_failed}")
    print(f"  Duration       : {result.crawl_duration_seconds}s")
    print(f"  Unique versions: {', '.join(result.unique_versions) or 'None found'}")
    print()

    if not result.jquery_findings:
        print("  No jQuery instances detected.")
    else:
        # Group by version
        by_version: dict[str, list[JQueryFinding]] = defaultdict(list)
        for f in result.jquery_findings:
            by_version[f.version].append(f)

        for version in sorted(by_version):
            findings = by_version[version]
            vuln = findings[0].vulnerable
            cve = findings[0].cve_notes
            status = "⚠  VULNERABLE" if vuln else "✓  OK"
            print(f"  jQuery v{version}  [{status}]")
            if cve:
                print(f"    CVE Notes : {cve}")
            pages = sorted(set(f.discovered_on for f in findings))
            for p in pages[:5]:
                print(f"    Found on  : {p}")
            if len(pages) > 5:
                print(f"    ... and {len(pages) - 5} more pages")
            print()

    print("=" * 65)


def save_json(result: CrawlResult, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.summary(), fh, indent=2)
    print(f"\n[+] Results saved to: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jquery_version_crawler",
        description="Crawl a web application and enumerate all jQuery versions (security audit tool).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jquery_version_crawler.py -u https://example.com
  python3 jquery_version_crawler.py -u https://example.com -d 4 --threads 15
  python3 jquery_version_crawler.py -u https://app.internal -d 2 --ignore-ssl --verbose
  python3 jquery_version_crawler.py -u https://example.com --output findings.json
  python3 jquery_version_crawler.py -u https://example.com \\
      --cookies "sessionid=abc123; csrftoken=xyz" \\
      --headers '{"X-Custom": "value"}' \\
      --output results.json
        """
    )

    p.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Base URL of the target web application (required)"
    )
    p.add_argument(
        "-d", "--depth",
        type=int,
        default=3,
        metavar="N",
        help="Maximum crawl depth (default: 3)"
    )
    p.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Number of concurrent threads (default: 10)"
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="HTTP request timeout in seconds (default: 10)"
    )
    p.add_argument(
        "--user-agent",
        default=None,
        metavar="UA",
        help="Custom User-Agent string"
    )
    p.add_argument(
        "--cookies",
        default=None,
        metavar="COOKIES",
        help='Cookie header string, e.g. "session=abc; csrf=xyz"'
    )
    p.add_argument(
        "--headers",
        default=None,
        metavar="JSON",
        help='Additional HTTP headers as a JSON object, e.g. \'{"Authorization":"Bearer token"}\''
    )
    p.add_argument(
        "--ignore-ssl",
        action="store_true",
        help="Disable SSL/TLS certificate verification"
    )
    p.add_argument(
        "--scope-only",
        action="store_true",
        default=True,
        help="Stay within the base domain (default: enabled)"
    )
    p.add_argument(
        "--no-scope",
        dest="scope_only",
        action="store_false",
        help="Follow links outside the base domain"
    )
    p.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Save results to a JSON file"
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print verbose crawl progress"
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Basic URL validation
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        parser.error(f"Invalid URL: {args.url}  (must start with http:// or https://)")

    crawler = JQueryCrawler(args)

    try:
        result = crawler.crawl()
    except KeyboardInterrupt:
        print("\n[!] Crawl interrupted by user.")
        sys.exit(1)

    print_report(result)

    if args.output:
        save_json(result, args.output)


if __name__ == "__main__":
    main()
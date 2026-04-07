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
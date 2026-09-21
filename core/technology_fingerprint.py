import re
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests


REQUEST_TIMEOUT = 10
COOKIE_TECHNOLOGIES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java / Servlet",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel",
    "wordpress_logged_in": "WordPress",
}


def _target_url(target_input: str) -> str:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def _add_finding(findings: List[Dict[str, str]], name: str, evidence: str, category: str) -> None:
    if not any(item["name"] == name and item["category"] == category for item in findings):
        findings.append({"name": name, "category": category, "evidence": evidence[:180]})


def fingerprint_technology(target_input: str) -> Dict[str, Any]:
    target_url = _target_url(target_input)
    findings: List[Dict[str, str]] = []

    try:
        response = requests.get(
            target_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Signal-Recon/1.0"},
        )
        headers = {key.lower(): value for key, value in response.headers.items()}
        body = response.text[:500000]

        for header_name in ("server", "x-powered-by", "x-generator", "via"):
            if header_name in headers:
                _add_finding(findings, headers[header_name], header_name, "response header")

        if "x-vercel-id" in headers or "vercel" in headers.get("server", "").lower():
            _add_finding(findings, "Vercel", "Vercel response headers", "hosting / CDN")
        if "cf-ray" in headers or "cloudflare" in headers.get("server", "").lower():
            _add_finding(findings, "Cloudflare", "Cloudflare response headers", "CDN / WAF")
        if "x-amzn-trace-id" in headers or "amazonaws.com" in headers.get("via", ""):
            _add_finding(findings, "Amazon Web Services", "AWS response headers", "hosting / CDN")
        if "akamai" in headers.get("server", "").lower() or "akamai" in headers.get("via", "").lower():
            _add_finding(findings, "Akamai", "Akamai response headers", "CDN / WAF")

        for cookie in response.cookies:
            cookie_name = cookie.name
            for known_name, technology in COOKIE_TECHNOLOGIES.items():
                if cookie_name.lower() == known_name.lower():
                    _add_finding(findings, technology, f"Cookie: {cookie_name}", "cookie")

        signatures = [
            ("WordPress", r"(?:wp-content|wp-includes|wordpress)", "HTML signature", "CMS"),
            ("Drupal", r"(?:drupalSettings|sites/default/files|generator[^>]+Drupal)", "HTML signature", "CMS"),
            ("Joomla", r"(?:/media/system/js|generator[^>]+Joomla)", "HTML signature", "CMS"),
            ("Next.js", r"(?:__NEXT_DATA__|/_next/static/)", "HTML signature", "framework"),
            ("Nuxt", r"(?:__NUXT__|/_nuxt/)", "HTML signature", "framework"),
            ("React", r"(?:data-reactroot|react(?:\.production)?\.min\.js)", "HTML signature", "framework"),
            ("Vue.js", r"(?:data-v-[a-f0-9]+|vue(?:\.min)?\.js)", "HTML signature", "framework"),
        ]
        for name, pattern, evidence, category in signatures:
            if re.search(pattern, body, flags=re.IGNORECASE):
                _add_finding(findings, name, evidence, category)

        return {
            "status": "success",
            "target": response.url,
            "http_status": response.status_code,
            "technologies": findings,
            "cookie_names": sorted(cookie.name for cookie in response.cookies),
        }
    except requests.RequestException as error:
        return {"status": "error", "target": target_url, "message": str(error)}

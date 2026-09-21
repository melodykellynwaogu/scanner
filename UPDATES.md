# Scanner Update - 2026-09-19

## Completed Today

### Passive Subdomain Enumeration

The scanner can now discover subdomains through public Certificate Transparency logs.

- Queries `crt.sh` for certificates associated with the target domain.
- Filters results so only subdomains of the requested domain are included.
- Removes duplicate hostnames and limits the result set to 100 names.
- Resolves discovered hostnames through DNS.
- Reports the hostname, resolved IP addresses, and whether DNS resolution succeeded.
- Returns a clear result when no subdomains are found or the discovery source fails.

### Frontend Integration

The web interface now displays a **Discovered subdomains** section in each scan report.

- Shows the discovery source and number of results found.
- Displays each discovered hostname and its resolved addresses.
- Distinguishes between a successful scan with zero results, a failed lookup, and a missing response.
- Keeps the results available through the existing JSON export.

### Scan Performance and Reliability     

- Header analysis, Nmap port scanning, and subdomain enumeration now run concurrently.
- Added Nmap host and script timeouts so a slow target does not block the entire scan indefinitely.
- Existing port and service scanning remains enabled for ports `21`, `22`, `80`, `443`, and `8080`.

## Completed Reconnaissance Features

The following features are now implemented:

1. **Directory and Content Discovery**
	- Checks a controlled list of common paths such as `/admin/`, `.git/`, backup files, and configuration files.

2. **JavaScript and API Analysis**
	- Inspects same-origin JavaScript files for API endpoints and specific credential-like patterns.
	- Masks possible credentials in the report.

These features should only be used against systems where testing is authorized.

## Refinement Update - 2026-09-21 

The directory and JavaScript/API discovery features were refined for more useful results.

- Directory checks now compare responses against a known-missing path to reduce catch-all route false positives.
- Directory probes do not follow redirects and include the response status and redirect location when available.
- Directory checks remain limited to a small common-path list and use bounded request timeouts.
- JavaScript analysis now limits inspection to same-origin scripts.
- API extraction focuses on API-shaped routes such as `/api`, `/graphql`, authentication, and versioned endpoints.
- Secret detection uses specific credential patterns instead of flagging every long string.
- Possible credentials are masked in the report rather than displayed in full.
- Result counts remain capped to keep scans and reports manageable.

## Recon Expansion - 2026-09-21

### Historical and Archived URL Harvesting

- Queries the Internet Archive CDX API for previously captured URLs under the target domain.
- Returns the capture date, original URL, HTTP status, MIME type, and an Internet Archive replay link.
- Limits results to 100 archived URLs so reports remain readable.
- Reports archive lookup failures separately from a successful lookup with zero results.

### Technology Fingerprinting

- Inspects response headers such as `Server`, `X-Powered-By`, and hosting/CDN indicators.
- Checks response cookies for common technology markers such as PHP, ASP.NET, Java, Laravel, and WordPress.
- Checks conservative HTML signatures for WordPress, Drupal, Joomla, Next.js, Nuxt, React, and Vue.js.
- Includes evidence and category for each detected technology instead of presenting guesses without context.

### Frontend Structure

The scanner can use multiple HTML pages if the report grows beyond one screen. The current page remains the main scan workflow, while the API now returns separate result groups for archives and technology findings. A future navigation layer can store the current scan result and open dedicated pages such as an archive view or technology view without duplicating scanner logic.

## Multi-Page Report Navigation - 2026-09-21

- Added `archives.html` for the historical URL report.
- Added `technologies.html` for the technology fingerprint report.
- Added shared `detail.js` rendering for both pages.
- Added Overview, Archives, and Technology navigation links.
- The latest scan response is saved in browser `localStorage` after a successful scan.
- Detail pages read that saved response, so they stay synchronized with the latest overview report without starting a second scan.
- Detail pages show a clear message when opened before a scan has been completed.

## Header Checker Hardening - 2026-09-21

- Normalizes response header names to lowercase for reliable case-insensitive matching.
- Sends a browser-like User-Agent to reduce avoidable blocking by ordinary web defenses.
- Validates important header values, including HSTS lifetime, CSP directives, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Reports present but weak headers separately from headers that are absent.
- Provides remediation guidance when a target cannot be reached, but labels it as an unverified baseline instead of claiming the headers are confirmed missing.

## Development Environment - 2026-09-21

- Added `.vscode/settings.json` to point the workspace at `venv/bin/python`.
- Confirmed that the scanner virtual environment includes `requests` and can compile the header checker successfully.
- This resolves the editor import warning caused by VS Code using a different Python interpreter.

## Next Session

Continue with scanner improvements and validation of the completed reconnaissance and reporting features.

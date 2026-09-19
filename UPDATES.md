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

## Not Implemented Yet

The following reconnaissance features are planned for the next update:

1. **Directory and Content Discovery**
	- Use a controlled wordlist to check for common paths such as `/admin/`, `.git/`, backup files, and configuration files.

2. **JavaScript and API Analysis**
	- Inspect publicly accessible JavaScript files for API endpoints, developer comments, and accidentally exposed secrets.

These features should only be used against systems where testing is authorized.

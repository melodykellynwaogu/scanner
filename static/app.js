let currentScanData = null;

async function runScan() {
    const targetUrlInput = document.getElementById('targetUrl');
    const targetUrl = targetUrlInput ? targetUrlInput.value.trim() : '';
    
    if (!targetUrl) {
        alert('Please enter a target URL or domain.');
        return;
    }

    const loader = document.getElementById('loader');
    const results = document.getElementById('results');
    const scanButton = document.getElementById('scanBtn');

    if (loader) loader.classList.remove('hidden');
    if (results) results.classList.add('hidden');
    if (scanButton) {
        scanButton.disabled = true;
        scanButton.querySelector('span').innerText = 'Scanning';
    }

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: targetUrl })
        });

        if (!response.ok) {
            throw new Error(`Server returned HTTP ${response.status}`);
        }

        currentScanData = await response.json();
        localStorage.setItem('signalReconScan', JSON.stringify({
            savedAt: new Date().toISOString(),
            data: currentScanData,
        }));

        if (loader) loader.classList.add('hidden');
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.querySelector('span').innerText = 'Run analysis';
        }         

        renderResults(currentScanData);

        if (results) results.classList.remove('hidden');

    } catch (err) {
        if (loader) loader.classList.add('hidden');
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.querySelector('span').innerText = 'Run analysis';
        }
        console.error('SOC Dashboard Scan Exception:', err);
        alert('Scan Failed: ' + err.message);
    }
}

function renderResults(data) {
    const headerData = data.headers || data;
    const portData = data.ports || null;
    const subdomainData = data.subdomains || null;
    const directoryData = data.directories || null;
    const jsApiData = data.js_api || null;
    const archiveData = data.archives || null;
    const technologyData = data.technology || null;

    document.getElementById('resTarget').innerText = headerData.target || 'N/A';
    document.getElementById('resStatus').innerText = headerData.status_code || 'N/A';

    const subdomainSource = document.getElementById('subdomainSource');
    const subdomainsList = document.getElementById('subdomainsList');
    if (subdomainSource && subdomainsList) {
        if (subdomainData?.status === 'success') {
            subdomainSource.innerText = `${subdomainData.source || 'Certificate Transparency logs'} (${subdomainData.count || 0} found)`;
        } else if (subdomainData?.status === 'error') {
            subdomainSource.innerText = 'Discovery failed';
        } else {
            subdomainSource.innerText = 'No discovery response';
        }

        if (subdomainData?.status === 'success' && Array.isArray(subdomainData.subdomains) && subdomainData.subdomains.length) {
            subdomainsList.innerHTML = subdomainData.subdomains.map(subdomain => {
                const addresses = subdomain.addresses.length ? ` (${subdomain.addresses.join(', ')})` : ' (no DNS record)';
                return `<li><strong>${escapeHTML(subdomain.hostname)}</strong>${escapeHTML(addresses)}</li>`;
            }).join('');
        } else {
            const message = subdomainData?.status === 'success'
                ? 'No subdomains found in the current passive sources.'
                : subdomainData?.message || 'The subdomain discovery response was unavailable.';
            subdomainsList.innerHTML = `<li>${escapeHTML(message)}</li>`;
        }
    }

    // Directory Discovery
    const directoryList = document.getElementById('directoryList');
    if (directoryList) {
        if (directoryData?.status === 'success' && Array.isArray(directoryData.paths) && directoryData.paths.length) {
            directoryList.innerHTML = directoryData.paths.map(item =>
                `<li><strong>${escapeHTML(item.path)}</strong> → ${escapeHTML(item.url)} (HTTP ${escapeHTML(String(item.status_code))})</li>`
            ).join('');
        } else {
            directoryList.innerHTML = '<li>No likely sensitive paths found in the current common target list.</li>';
        }
    }

    // JavaScript / API Findings
    const jsApiList = document.getElementById('jsApiList');
    if (jsApiList) {
        if (jsApiData?.status === 'success') {
            const findings = [];
            if (Array.isArray(jsApiData.javascript_files) && jsApiData.javascript_files.length) {
                findings.push(`<li><strong>JavaScript files:</strong> ${escapeHTML(jsApiData.javascript_files.slice(0, 5).join(', '))}</li>`);
            }
            if (Array.isArray(jsApiData.endpoints) && jsApiData.endpoints.length) {
                findings.push(`<li><strong>Endpoints:</strong> ${escapeHTML(jsApiData.endpoints.slice(0, 5).join(', '))}</li>`);
            }
            if (Array.isArray(jsApiData.possible_secrets) && jsApiData.possible_secrets.length) {
                findings.push(`<li><strong>Possible secrets:</strong> ${escapeHTML(jsApiData.possible_secrets.slice(0, 5).join(', '))}</li>`);
            }
            jsApiList.innerHTML = findings.length ? findings.join('') : '<li>No JavaScript or API clues were found.</li>';
        } else {
            jsApiList.innerHTML = `<li>${escapeHTML(jsApiData?.message || 'JavaScript and API analysis was unavailable.')}</li>`;
        }
    }

    const archiveSource = document.getElementById('archiveSource');
    const archiveList = document.getElementById('archiveList');
    if (archiveSource && archiveList) {
        if (archiveData?.status === 'success') {
            archiveSource.innerText = `${archiveData.source || 'Internet Archive'} (${archiveData.count || 0} found)`;
        } else {
            archiveSource.innerText = archiveData?.status === 'error' ? 'Archive lookup failed' : 'No archive response';
        }

        if (archiveData?.status === 'success' && Array.isArray(archiveData.urls) && archiveData.urls.length) {
            archiveList.innerHTML = archiveData.urls.slice(0, 20).map(item =>
                `<li><strong>${escapeHTML(item.url)}</strong> <a href="${escapeHTML(item.replay_url)}" target="_blank" rel="noopener">Replay -&gt;</a><br><span>${escapeHTML(item.timestamp)} / HTTP ${escapeHTML(item.status_code)} / ${escapeHTML(item.mime_type)}</span></li>`
            ).join('');
        } else {
            archiveList.innerHTML = `<li>${escapeHTML(archiveData?.message || 'No archived URLs found in the current source.')}</li>`;
        }
    }

    const technologyTarget = document.getElementById('technologyTarget');
    const technologyList = document.getElementById('technologyList');
    if (technologyTarget && technologyList) {
        technologyTarget.innerText = technologyData?.target || 'Unavailable';
        if (technologyData?.status === 'success' && Array.isArray(technologyData.technologies) && technologyData.technologies.length) {
            technologyList.innerHTML = technologyData.technologies.map(item =>
                `<li><strong>${escapeHTML(item.name)}</strong> <span>${escapeHTML(item.category)} / ${escapeHTML(item.evidence)}</span></li>`
            ).join('');
        } else {
            technologyList.innerHTML = `<li>${escapeHTML(technologyData?.message || 'No technology signatures identified.')}</li>`;
        }
    }

    // 1. Present Headers
    const headerSummary = document.getElementById('headerSummary');
    const summary = headerData.header_summary;
    if (headerSummary) {
        headerSummary.className = `header-summary ${summary?.status || 'unknown'}`;
        headerSummary.innerText = summary?.message || 'Header verification details were not returned.';
    }

    const presentList = document.getElementById('presentHeadersList');
    const presentHeaders = headerData.present_headers || {};
    presentList.innerHTML = Object.keys(presentHeaders).length ? '' : '<li>None identified</li>';
    for (const [header, val] of Object.entries(presentHeaders)) {
        presentList.innerHTML += `<li><strong>${header}:</strong> ${escapeHTML(val)}</li>`;
    }

    // 2. Missing Headers
    const missingList = document.getElementById('missingHeadersList');
    const missingHeaders = headerData.missing_headers || {};
    const fallbackNotice = headerData.status === 'fallback'
        ? '<li><strong>Unverified baseline:</strong> the target could not be reached, so these are remediation suggestions rather than confirmed missing headers.</li>'
        : '';
    missingList.innerHTML = fallbackNotice + (Object.keys(missingHeaders).length ? '' : '<li>All core security headers are active!</li>');
    
    let remediationRules = [];

    for (const [header, info] of Object.entries(missingHeaders)) {
        const desc = typeof info === 'object' ? info.description : info;
        missingList.innerHTML += `<li><strong>${header}:</strong> ${escapeHTML(desc)}</li>`;
        
        if (typeof info === 'object' && info.remediation_nginx) {
            remediationRules.push(info.remediation_nginx);
        }
    }

    const weakList = document.getElementById('weakHeadersList');
    const weakHeaders = headerData.weak_headers || {};
    if (weakList) {
        weakList.innerHTML = Object.keys(weakHeaders).length
            ? Object.entries(weakHeaders).map(([header, info]) => `<li><strong>${escapeHTML(header)}:</strong> ${escapeHTML(info.description)} (value: ${escapeHTML(info.value)})</li>`).join('')
            : '<li>No weak header values identified.</li>';
    }

    // 3. Banner Disclosures
    const bannerList = document.getElementById('bannerList');
    const banners = headerData.banner_disclosures || {};
    bannerList.innerHTML = Object.keys(banners).length ? '' : '<li>No software version disclosures detected.</li>';
    for (const [header, val] of Object.entries(banners)) {
        bannerList.innerHTML += `<li><strong>${header}:</strong> ${escapeHTML(val)}</li>`;
    }

    // 4. Open Ports
    const resIp = document.getElementById('resIp');
    const portsList = document.getElementById('portsList');
    if (resIp && portsList && portData) {
        resIp.innerText = portData.host_ip || 'N/A';
        if (portData.status === 'success' && Array.isArray(portData.open_ports) && portData.open_ports.length > 0) {
            portsList.innerHTML = portData.open_ports.map(p => 
                `<li><strong>Port ${p.port}/${p.protocol.toUpperCase()}:</strong> ${escapeHTML(p.service)} (Version: ${escapeHTML(p.version)})</li>`
            ).join('');
        } else {
            portsList.innerHTML = '<li>No open common ports identified.</li>';
        }
    }

    // 5. Render Remediation Block
    const remediationBlock = document.getElementById('remediationCode');
    if (remediationBlock) {
        if (remediationRules.length > 0) {
            remediationBlock.innerText = "# Add to Nginx configuration block:\n" + remediationRules.join("\n");
        } else {
            remediationBlock.innerText = "# No missing security headers identified. Perfect configuration!";
        }
    }
}

function exportJSON() {
    if (!currentScanData) return;
    const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-scan-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function exportPDF() {
    window.print();
}

function escapeHTML(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}


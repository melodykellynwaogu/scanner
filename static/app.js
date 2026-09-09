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

    if (loader) loader.classList.remove('hidden');
    if (results) results.classList.add('hidden');

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

        if (loader) loader.classList.add('hidden');

        renderResults(currentScanData);

        if (results) results.classList.remove('hidden');

    } catch (err) {
        if (loader) loader.classList.add('hidden');
        console.error('SOC Dashboard Scan Exception:', err);
        alert('Scan Failed: ' + err.message);
    }
}

function renderResults(data) {
    const headerData = data.headers || data;
    const portData = data.ports || null;

    document.getElementById('resTarget').innerText = headerData.target || 'N/A';
    document.getElementById('resStatus').innerText = headerData.status_code || 'N/A';

    // 1. Present Headers
    const presentList = document.getElementById('presentHeadersList');
    const presentHeaders = headerData.present_headers || {};
    presentList.innerHTML = Object.keys(presentHeaders).length ? '' : '<li>None identified</li>';
    for (const [header, val] of Object.entries(presentHeaders)) {
        presentList.innerHTML += `<li><strong>${header}:</strong> ${escapeHTML(val)}</li>`;
    }

    // 2. Missing Headers
    const missingList = document.getElementById('missingHeadersList');
    const missingHeaders = headerData.missing_headers || {};
    missingList.innerHTML = Object.keys(missingHeaders).length ? '' : '<li>All core security headers are active!</li>';
    
    let remediationRules = [];

    for (const [header, info] of Object.entries(missingHeaders)) {
        const desc = typeof info === 'object' ? info.description : info;
        missingList.innerHTML += `<li><strong>${header}:</strong> ${escapeHTML(desc)}</li>`;
        
        if (typeof info === 'object' && info.remediation_nginx) {
            remediationRules.push(info.remediation_nginx);
        }
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
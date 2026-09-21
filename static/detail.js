function escapeHTML(value) {
    if (typeof value !== 'string') return String(value ?? '');
    return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function readSavedScan() {
    try {
        const saved = JSON.parse(localStorage.getItem('signalReconScan') || 'null');
        return saved?.data || null;
    } catch (error) {
        return null;
    }
}

function renderArchives(data) {
    const result = data?.archives;
    const source = document.getElementById('detailSource');
    const list = document.getElementById('detailList');
    const target = document.getElementById('detailTarget');
    target.innerText = result?.domain || data?.headers?.target || 'No scan loaded';

    if (result?.status === 'success') {
        source.innerText = `${result.source} / ${result.count} found`;
        list.innerHTML = result.urls?.length
            ? result.urls.map(item => `<li><strong>${escapeHTML(item.url)}</strong><a href="${escapeHTML(item.replay_url)}" target="_blank" rel="noopener">Replay -&gt;</a><span>${escapeHTML(item.timestamp)} / HTTP ${escapeHTML(item.status_code)} / ${escapeHTML(item.mime_type)}</span></li>`).join('')
            : '<li>No archived URLs were found in the current source.</li>';
    } else {
        source.innerText = result?.status === 'error' ? 'Archive lookup failed' : 'No scan loaded';
        list.innerHTML = `<li>${escapeHTML(result?.message || 'Run a scan from the overview page first.')}</li>`;
    }
}

function renderTechnologies(data) {
    const result = data?.technology;
    const source = document.getElementById('detailSource');
    const list = document.getElementById('detailList');
    const target = document.getElementById('detailTarget');
    target.innerText = result?.target || data?.headers?.target || 'No scan loaded';

    if (result?.status === 'success') {
        source.innerText = `HTTP ${result.http_status} / ${result.technologies?.length || 0} detected`;
        list.innerHTML = result.technologies?.length
            ? result.technologies.map(item => `<li><strong>${escapeHTML(item.name)}</strong><span>${escapeHTML(item.category)} / ${escapeHTML(item.evidence)}</span></li>`).join('')
            : '<li>No technology signatures were identified.</li>';
    } else {
        source.innerText = result?.status === 'error' ? 'Fingerprinting failed' : 'No scan loaded';
        list.innerHTML = `<li>${escapeHTML(result?.message || 'Run a scan from the overview page first.')}</li>`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const data = readSavedScan();
    const page = document.body.dataset.page;
    if (page === 'archives') renderArchives(data);
    if (page === 'technologies') renderTechnologies(data);
});

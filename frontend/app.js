const API = (window.OPS_CONFIG?.API_BASE_URL || '').replace(/\/$/, '');
const $= s => document.querySelector(s),$$ = s => [...document.querySelectorAll(s)];
let token = sessionStorage.getItem('ops_token') || '', currentUser = null, cachedFiles = [], cachedMovements = [];
const pageNames = { dashboard: 'Operations Dashboard', files: 'Central File Register', register: 'Register a File', movements: 'Movement Reports', users: 'Users & Branches', audit: 'Audit Trail' };

function esc(v) { return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function date(v) { if (!v) return '—'; const d = new Date(v); return isNaN(d) ? esc(v) : d.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }); }
function dateOnly(v) { if (!v) return '—'; const d = new Date(v); return isNaN(d) ? esc(v) : d.toLocaleDateString('en-GB'); }
function statusPill(s) { let c = String(s || '').toLowerCase().replaceAll(' ', '-'); return `<span class="pill ${esc(c)}">${esc(s || 'Unknown')}</span>`; }

async function api(path, opts = {}) {
    if (!API || API.includes('YOUR-OPERATIONS-API')) throw new Error('Set API_BASE_URL in frontend/config.js to your deployed Render API URL.');
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (token) headers.Authorization = 'Bearer ' + token;
    const r = await fetch(API + path, { ...opts, headers });
    let data = {};
    try { data = await r.json(); } catch {}
    if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
    return data;
}

function notify(msg, error = false) {
    const n = $('#notice');
    n.textContent = msg;
    n.classList.remove('hidden', 'error-notice');
    if (error) n.classList.add('error-notice');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => n.classList.add('hidden'), 6000);
}

function showLogin() { 
    $('#loginScreen').classList.remove('hidden');
    $('#appShell').classList.add('hidden'); 
}

function showApp() { 
    $('#loginScreen').classList.add('hidden');
    $('#appShell').classList.remove('hidden');
    $('#profileName').textContent = currentUser.full_name;
    $('#profileRole').textContent = currentUser.role;
    $('#avatar').textContent = currentUser.full_name.split(/\s+/).map(x => x[0]).slice(0, 2).join('').toUpperCase();     $$('.admin-only').forEach(e => e.classList.toggle('hidden', currentUser.role !== 'State Coordinator Admin'));
    
    const isAdmin = currentUser.role === 'State Coordinator Admin';
    const isRegistry = ['Central Registry', 'Registry Officer'].includes(currentUser.role);
    
    $('#dashboardGreeting').textContent = isAdmin ? 'State Coordinator’s Office — state-wide overview' : isRegistry ? 'Central Registry — dispatch and custody control' : 'Office File Dashboard — assigned file activity';
    $('#dashboardDescription').textContent = isAdmin ? 'Oversee branches, Zonal Inspectors and LGIs; monitor files received for treatment, treated files and returns to originating offices or Central Registry.' : isRegistry ? 'Manage physical file custody: dispatch files to branches and field offices, record acknowledgements, process returns and identify overdue or unacknowledged files.' : 'Track files assigned to your office, confirm receipt and monitor returns and due dates.';
    
    const labels = isAdmin ? ['Files under state oversight', 'Files registered today', 'Treated/returned today', 'Files with offices', 'Overdue treatment/returns', 'Awaiting office acknowledgement'] : ['Total registered files', 'Collected today', 'Returned today', 'In circulation', 'Overdue', 'Awaiting acknowledgement'];
    const small = isAdmin ? ['All state-wide records', 'New files recorded today', 'Confirmed treatment/returns', 'Currently outside registry', 'Past agreed return date', 'Dispatch not yet confirmed'] : ['All active records', 'Files registered today', 'Confirmed returns', 'Issued and acknowledged', 'Past agreed return date', 'Dispatched, not confirmed'];
    
    $$('.stat-card').forEach((card, i) => {         if (labels[i]) card.querySelector('span').textContent = labels[i];         if (small[i]) card.querySelector('small').textContent = small[i];     });          const locTitle = document.querySelector('#locationList')?.closest('.panel')?.querySelector('h3');     if (locTitle) locTitle.textContent = isAdmin ? 'Files by office / current location' : 'Files by current location';          const recentTitle = document.querySelector('#recentRows')?.closest('.panel')?.querySelector('h3');     if (recentTitle) recentTitle.textContent = isAdmin ? 'Recent state-wide file activity' : 'Recent registry activity';          goto('dashboard');     loadAllBase().then(loadDashboard).catch(e => notify(e.message, true)); }  function goto(page) {     $$
('.page').forEach(e => e.classList.add('hidden'));
    $('#page-' + page)?.classList.remove('hidden');     $$('.nav-link').forEach(e => e.classList.toggle('active', e.dataset.page === page));$('#pageTitle').textContent = pageNames[page] || 'Operations Suite';
    if (page === 'files') loadFiles();
    if (page === 'users') loadUsers();
    if (page === 'movements') loadMovements();
    if (page === 'audit') loadAudit();
}

const zoneLGIs = {
    'Katsina Zone': ['Katsina A', 'Katsina B', 'Batagarawa', 'Rimi', 'Charanchi', 'Kaita', 'Jibia'],
    'Daura Zone': ['Daura', 'Baure', 'Mani', 'Mashi', 'Dutsi', 'Bindawa', 'Zango', 'Sandamu', 'Maiadua'],
    'Funtua Zone': ['Funtua', 'Malumfashi', 'Bakori', 'Danja'],
    'Dutsin-Ma Zone': ['Dutsin-Ma', 'Ingawa', 'Kusada', 'Kankia']
};

function refreshDestinationOptions() {
    const cat = ($('#destinationCategory')?.value || 'branch'), zone = $('#destinationZone')?.value || 'Katsina Zone';
    $('#destinationZoneWrap')?.classList.toggle('hidden', cat !== 'lgi');
    let names;
    if (cat === 'lgi') names = zoneLGIs[zone] || [];
    else if (cat === 'zi') names = ['Katsina Zone', 'Daura Zone', 'Funtua Zone', 'Dutsin-Ma Zone'];
    else if (cat === 'sc') names = ['State Coordinator Office'];
    else names = ['CIM', 'CW&HS', 'CDS', 'Other Secretariat Branch/Unit'];
    const sel = $('#destinationOffice');
    if (sel) sel.innerHTML = names.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
}

async function loadAllBase() {
    const d = await api('/api/branches');
    const branches = d.branches || [];
    const options = branches.map(b => `<option value="${esc(b.name)}">${esc(b.name)}</option>`).join('');
    $$('.branch-options').forEach(s => s.innerHTML = options);$$
('.location-options').forEach(s => s.innerHTML = options);
    const locs = '<option>All locations</option>' + options;
    $('#dashLocation').innerHTML = locs;
    $('#fileLocation').innerHTML = locs;
    $('.branch-id-options').innerHTML = '<option value="">No branch assigned</option>' + branches.map(b => `<option value="${b.id}">${esc(b.name)}</option>`).join('');
    refreshDestinationOptions();
}

async function loadDashboard() {
    try {
        const d = await api('/api/dashboard');
        const c = d.counts || {};
        $('#statTotal').textContent = c.total_files ?? 0;
        $('#statCollected').textContent = c.registered_today ?? 0;
        $('#statReturned').textContent = c.returned_today ?? 0;
        $('#statCirculating').textContent = c.circulating ?? 0;
        $('#statOverdue').textContent = c.overdue ?? 0;
        $('#statUnack').textContent = c.unacknowledged ?? 0;
        
        const loc = d.by_location || [], max = Math.max(1, ...loc.map(x => Number(x.count)));
        $('#locationList').innerHTML = loc.length ? loc.map(x => `<div class="location-item"><strong>${esc(x.location)}</strong><span>${x.count} files</span><div class="bar"><span style="width:${Math.max(2, Number(x.count) / max * 100)}%"></span></div></div>`).join('') : '<p class="muted">No file records yet.</p>';
        
        const recent = d.recent || [];
        $('#recentRows').innerHTML = recent.length ? recent.map(f => `<tr><td><strong>${esc(f.reference_no)}</strong><span class="table-sub">${esc(f.state_code || 'No State Code')}</span></td><td>${esc(f.title)}</td><td>${statusPill(f.computed_status)}</td></tr>`).join('') : '<tr><td colspan="3" class="empty">No files registered yet.</td></tr>';
        
        $('#lastUpdated').textContent = 'Dashboard refreshed ' + date(d.generated_at);
    } catch (e) { notify(e.message, true); }
}

async function loadFiles() {
    try {
        const p = new URLSearchParams();
        if ($('#fileSearch').value.trim()) p.set('q', $('#fileSearch').value.trim());
        if ($('#fileLocation').value !== 'All locations') p.set('location', $('#fileLocation').value);
        if ($('#fileStatus').value) p.set('status', $('#fileStatus').value);
        if ($('#fileStart').value) p.set('start', $('#fileStart').value);
        if ($('#fileEnd').value) p.set('end', $('#fileEnd').value);
        const d = await api('/api/files?' + p);
        cachedFiles = d.files || [];
        $('#filesRows').innerHTML = cachedFiles.length ? cachedFiles.map(f => `<tr><td><strong>${esc(f.reference_no)}</strong><span class="table-sub">${esc(f.state_code || 'No State Code')}</span></td><td><span class="table-title">${esc(f.title)}</span><span class="table-sub">${esc(f.subject || '')}</span></td><td>${esc(f.current_location)}</td><td>${esc(f.current_holder)}</td><td>${dateOnly(f.registered_at)}</td><td>${dateOnly(f.due_at)}</td><td>${statusPill(f.computed_status)}</td><td><button class="table-action" data-file="${f.id}">Open</button></td></tr>`).join('') : '<tr><td colspan="8" class="empty">No matching files found.</td></tr>';
    } catch (e) { notify(e.message, true); }
}

async function openFile(id) {
    try {
        const d = await api('/api/files/' + id), f = d.file, m = d.movements || [];
        $('#modalContent').innerHTML = `<p class="eyebrow">FILE TRACKING RECORD</p><h3>${esc(f.reference_no)} · ${esc(f.title)}</h3><p class="muted">${esc(f.subject || 'No additional subject provided')}</p><div class="detail-grid"><div class="detail-box"><span>Corps Member State Code</span><strong>${esc(f.state_code || 'Not recorded')}</strong></div><div class="detail-box"><span>Current status</span><strong>${statusPill(f.computed_status)}</strong></div><div class="detail-box"><span>Current location</span><strong>${esc(f.current_location)}</strong></div><div class="detail-box"><span>Current holder</span><strong>${esc(f.current_holder)}</strong></div><div class="detail-box"><span>Originating office</span><strong>${esc(f.originating_office)}</strong></div><div class="detail-box"><span>Return due</span><strong>${dateOnly(f.due_at)}</strong></div></div><h4>Movement history</h4><div class="table-wrap"><table><thead><tr><th>Action / time</th><th>From</th><th>To</th><th>Sender / recipient</th><th>Receipt</th><th>Due</th></tr></thead><tbody>${m.map(x => `<tr><td>${esc(x.action)}<span class="table-sub">${date(x.dispatched_at)}</span></td><td>${esc(x.from_location || '—')}</td><td>${esc(x.to_location || '—')}</td><td>${esc(x.sender || '—')}<span class="table-sub">${esc(x.recipient || '—')}</span></td><td>${x.acknowledged_at ? date(x.acknowledged_at) : '<span class="pill awaiting">Awaiting</span>'}</td><td>${dateOnly(x.due_at)}</td></tr>`).join('') || '<tr><td colspan="6">No movement history.</td></tr>'}</tbody></table></div><div class="inline-form"><label>Destination<select id="dispatchLocation" class="modal-locations"></select></label><label>Receiving officer<input id="dispatchRecipient" placeholder="Full name"></label><label>Return due date<input id="dispatchDue" type="date"></label><button class="primary" id="dispatchBtn">Dispatch file</button></div><div class="inline-form"><label>Return location<select id="returnLocation" class="modal-locations"></select></label><label>Received by<input id="returnRecipient" value="Central Registry"></label><button class="secondary" id="returnBtn">Record return</button></div><div class="inline-form"><button class="secondary" id="ackBtn">Acknowledge latest delivery</button></div>`;
        const locs = await api('/api/branches');
        const opts = (locs.branches || []).map(b => `<option value="${esc(b.name)}">${esc(b.name)}</option>`).join('');
        $$('.modal-locations').forEach(s => s.innerHTML = opts);$('#dispatchBtn').onclick = async () => {
            try {
                const result = await api(`/api/files/${id}/dispatch`, { method: 'POST', body: JSON.stringify({ to_location: $('#dispatchLocation').value, recipient: $('#dispatchRecipient').value, due_at: $('#dispatchDue').value || null }) });
                notify(result.message); $('#modal').classList.add('hidden'); await loadDashboard(); await loadFiles();
            } catch (e) { notify(e.message, true); }
        };
        $('#returnBtn').onclick = async () => {
            try {
                const result = await api(`/api/files/${id}/return`, { method: 'POST', body: JSON.stringify({ return_location: $('#returnLocation').value, received_by: $('#returnRecipient').value }) });
                notify(result.message); $('#modal').classList.add('hidden'); await loadDashboard(); await loadFiles();
            } catch (e) { notify(e.message, true); }
        };
        $('#ackBtn').onclick = async () => {
            try {
                const pending = m.findLast(x => x.action === 'DISPATCHED' && !x.acknowledged_at && !x.returned_at);
                if (!pending) throw new Error('No unacknowledged dispatch is available.');
                const result = await api(`/api/movements/${pending.id}/acknowledge`, { method: 'POST', body: JSON.stringify({}) });
                notify(result.message); $('#modal').classList.add('hidden'); await loadDashboard(); await loadFiles();
            } catch (e) { notify(e.message, true); }
        };
        $('#modal').classList.remove('hidden');
    } catch (e) { notify(e.message, true); }
}

async function loadMovements() {
    try {
        const p = new URLSearchParams();
        if ($('#movementStart').value) p.set('start', $('#movementStart').value);
        if ($('#movementEnd').value) p.set('end', $('#movementEnd').value);
        const d = await api('/api/reports/movements?' + p);
        cachedMovements = d.movements || [];
        $('#movementRows').innerHTML = cachedMovements.length ? cachedMovements.map(m => `<tr><td>${date(m.dispatched_at)}</td><td><strong>${esc(m.reference_no)}</strong><span class="table-sub">${esc(m.title)}</span><span class="table-sub">${esc(m.state_code || '')}</span></td><td>${esc(m.action)}</td><td>${esc(m.from_location)}</td><td>${esc(m.to_location)}</td><td>${esc(m.sender)}</td><td>${esc(m.recipient)}</td><td>${m.acknowledged_at ? date(m.acknowledged_at) : statusPill('Unacknowledged')}</td><td>${dateOnly(m.due_at)}</td></tr>`).join('') : '<tr><td colspan="9" class="empty">No movements in this period.</td></tr>';
    } catch (e) { notify(e.message, true); }
}

async function loadUsers() {
    try {
        const [u, b] = await Promise.all([api('/api/users'), api('/api/branches')]);
        $('#usersRows').innerHTML = (u.users || []).map(x => `<tr><td>${esc(x.full_name)}</td><td>${esc(x.username)}</td><td>${esc(x.role)}</td><td>${esc(x.branch_name || '—')}</td><td>${x.active ? 'Active' : 'Disabled'}</td><td><button class="table-action" data-toggle-user="${x.id}" data-active="${!x.active}">${x.active ? 'Disable' : 'Enable'}</button></td></tr>`).join('') || '<tr><td colspan="6">No users.</td></tr>';
        $('#branchList').innerHTML = (b.branches || []).map(x => `<div class="location-item"><strong>${esc(x.name)}</strong><span>${esc(x.branch_type)}</span><div class="muted">${esc(x.location)}</div></div>`).join('');
        const options = '<option value="">No branch assigned</option>' + (b.branches || []).map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join('');
        $('.branch-id-options').innerHTML = options;
    } catch (e) { notify(e.message, true); }
}

async function loadAudit() {
    try {
        const d = await api('/api/audit');
        $('#auditRows').innerHTML = (d.logs || []).map(x => `<tr><td>${date(x.created_at)}</td><td>${esc(x.full_name || x.username || 'System')}</td><td>${esc(x.action)}</td><td>${esc(x.entity_type)} #${esc(x.entity_id)}</td><td>${esc(x.details)}</td></tr>`).join('') || '<tr><td colspan="5">No audit records.</td></tr>';
    } catch (e) { notify(e.message, true); }
}

function csvDownload(rows, name) {
    if (!rows.length) { notify('No report rows to export.', true); return; }
    const keys = Object.keys(rows[0]);
    const val = x => '"' + String(x ?? '').replaceAll('"', '""') + '"';
    const csv = [keys.map(val).join(','), ...rows.map(r => keys.map(k => val(r[k])).join(','))].join('\r\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' }));
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}

$('#destinationCategory')?.addEventListener('change', refreshDestinationOptions);
$('#destinationZone')?.addEventListener('change', refreshDestinationOptions);

$('#loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    $('#loginError').textContent = '';
    try {
        const d = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: $('#username').value, password: $('#password').value }) });
        token = d.token;
        sessionStorage.setItem('ops_token', token);
        currentUser = d.user;
        showApp();
    } catch (err) { $('#loginError').textContent = err.message; }
});

$('#logoutBtn').onclick = () => { token = ''; currentUser = null; sessionStorage.removeItem('ops_token'); showLogin(); };  $$('.nav-link').forEach(b => b.addEventListener('click', () => goto(b.dataset.page)));$$('[data-goto]').forEach(b => b.addEventListener('click', () => goto(b.dataset.goto)));$('#refreshDashboard').onclick = loadDashboard;
$('#searchFiles').onclick = loadFiles;
$('#fileSearch').addEventListener('keydown', e => { if (e.key === 'Enter') loadFiles(); });
$('#filesRows').addEventListener('click', e => { const b = e.target.closest('[data-file]'); if (b) openFile(b.dataset.file); });
$('#closeModal').onclick = () => $('#modal').classList.add('hidden');
$('#modal').addEventListener('click', e => { if (e.target.id === 'modal') $('#modal').classList.add('hidden'); });

$('#registerForm').addEventListener('submit', async e => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    data.originating_office = 'Central Registry';
    data.current_location = 'Central Registry';
    if (data.destination_office) {
        data.destination_office = data.destination_office;
        data.destination_category = $('#destinationCategory').value;
        data.destination_zone = $('#destinationZone').value;
    }
    try {
        const d = await api('/api/files', { method: 'POST', body: JSON.stringify(data) });
        notify('File registered successfully: ' + d.file.reference_no);
        e.target.reset();
        await loadDashboard();
        goto('files');
        $('#fileSearch').value = d.file.reference_no;
        await loadFiles();
    } catch (err) { notify(err.message, true); }
});

$('#loadMovements').onclick = loadMovements;
$('#exportMovements').onclick = () => csvDownload(cachedMovements, 'katsina-file-movements.csv');
$('#reloadUsers').onclick = loadUsers;
$('#loadAudit').onclick = loadAudit;

$('#usersRows').addEventListener('click', async e => {
    const b = e.target.closest('[data-toggle-user]');
    if (!b) return;
    try {
        await api('/api/users/' + b.dataset.toggleUser, { method: 'PATCH', body: JSON.stringify({ active: b.dataset.active === 'true' }) });
        notify('User account updated.');
        loadUsers();
    } catch (err) { notify(err.message, true); }
});

$('#userForm').addEventListener('submit', async e => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    if (d.branch_id) d.branch_id = Number(d.branch_id); else delete d.branch_id;
    try {
        await api('/api/users', { method: 'POST', body: JSON.stringify(d) });
        notify('User account created.');
        e.target.reset();
        loadUsers();
    } catch (err) { notify(err.message, true); }
});

$('#branchForm').addEventListener('submit', async e => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    try {
        await api('/api/branches', { method: 'POST', body: JSON.stringify(d) });
        notify('Branch added.');
        e.target.reset();
        await loadAllBase();
        await loadUsers();
    } catch (err) { notify(err.message, true); }
});

(async () => {
    if (!token) { showLogin(); return; }
    try {
        const d = await api('/api/me');
        currentUser = d.user;
        showApp();
    } catch {
        token = '';
        sessionStorage.removeItem('ops_token');
        showLogin();
    }
})();

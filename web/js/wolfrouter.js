// WolfRouter frontend — table views + rack view.
// Written by Paul Clevett / Wolf Software Systems Ltd

(function () {
    'use strict';

    // ─── Styles (injected once) ───
    const css = `
    .wr-tab {
        padding: 6px 14px; background: transparent; color: var(--text-muted);
        border: none; border-bottom: 2px solid transparent; cursor: pointer;
        font-size: 13px; font-weight: 500; transition: all 0.15s;
    }
    .wr-tab:hover { color: var(--text); }
    .wr-tab.active {
        color: var(--primary, #a855f7);
        border-bottom-color: var(--primary, #a855f7);
    }
    .wr-tab-panel { min-height: 280px; }
    .wr-port {
        transition: filter 0.15s ease-out;
        cursor: pointer;
    }
    .wr-port:hover { filter: brightness(1.4); }
    .wr-wire { stroke-linecap: round; fill: none; pointer-events: none; }
    .wr-wire-active {
        stroke-dasharray: 8 6;
        animation: wr-flow 1s linear infinite;
    }
    @keyframes wr-flow { to { stroke-dashoffset: -14; } }
    .wr-rack-unit {
        fill: var(--bg-card, #1e293b);
        stroke: var(--border, #334155);
        stroke-width: 1.5;
    }
    .wr-node-name {
        fill: var(--text, #f1f5f9);
        font-family: system-ui, sans-serif;
        font-size: 13px;
        font-weight: 600;
    }
    .wr-port-label {
        fill: var(--text-muted, #94a3b8);
        font-family: var(--font-mono, monospace);
        font-size: 9px;
        text-anchor: middle;
        pointer-events: none;
    }
    .wr-device-badge {
        fill: var(--bg-secondary, #0f172a);
        stroke: var(--border, #334155);
        stroke-width: 1;
    }
    .wr-device-text {
        fill: var(--text, #f1f5f9);
        font-family: system-ui, sans-serif;
        font-size: 11px;
    }
    .wr-cloud {
        fill: url(#wr-cloud-grad);
        stroke: var(--border, #334155);
        stroke-width: 1;
    }
    `;
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);

    // ─── State ───
    let wrState = {
        view: 'rack',          // 'rack' | 'table'
        activeTab: 'firewall', // firewall | lans | leases | zones | connections | logs
        topology: null,
        rules: [],
        lans: [],
        zones: { assignments: {} },
        rollbackTimerInterval: null,
        rollbackDeadline: null,
        pollInterval: null,
    };

    // Expose hooks the HTML calls directly.
    window.wrSwitchView = wrSwitchView;
    window.wrSelectTab = wrSelectTab;
    window.wrShowRuleEditor = wrShowRuleEditor;
    window.wrShowLanEditor = wrShowLanEditor;
    window.wrTestRules = wrTestRules;
    window.wrConfirmRules = wrConfirmRules;
    window.wrDeleteRule = wrDeleteRule;
    window.wrDeleteLan = wrDeleteLan;
    window.wrToggleRule = wrToggleRule;
    window.wrSaveRule = wrSaveRule;
    window.wrSaveLan = wrSaveLan;
    window.wrAssignZone = wrAssignZone;

    // Hook into the existing networking page loader so WolfRouter
    // kicks in whenever the page is shown.
    const origLoadNetworking = window.loadNetworking;
    window.loadNetworking = async function (...args) {
        if (typeof origLoadNetworking === 'function') {
            try { await origLoadNetworking.apply(this, args); } catch (e) {}
        }
        await wrLoadAll();
        wrStartPolling();
    };

    // ─── Data loading ───

    async function wrLoadAll() {
        try {
            const [topoR, rulesR, lansR, zonesR] = await Promise.all([
                fetch('/api/router/topology'),
                fetch('/api/router/rules'),
                fetch('/api/router/segments'),
                fetch('/api/router/zones'),
            ]);
            if (topoR.ok) wrState.topology = await topoR.json();
            if (rulesR.ok) wrState.rules = await rulesR.json();
            if (lansR.ok)  wrState.lans = await lansR.json();
            if (zonesR.ok) wrState.zones = await zonesR.json();
            wrRenderAll();
        } catch (e) { console.error('wolfrouter load:', e); }
    }

    function wrStartPolling() {
        if (wrState.pollInterval) clearInterval(wrState.pollInterval);
        wrState.pollInterval = setInterval(async () => {
            const page = document.getElementById('page-networking');
            if (!page || page.style.display === 'none') return;
            try {
                const r = await fetch('/api/router/topology');
                if (r.ok) {
                    wrState.topology = await r.json();
                    if (wrState.view === 'rack') wrRenderRack();
                }
                if (wrState.activeTab === 'leases' && wrState.view === 'table') {
                    wrRenderLeases();
                }
                if (wrState.activeTab === 'connections' && wrState.view === 'table') {
                    wrRenderConnections();
                }
            } catch (e) {}
        }, 3000);
    }

    // ─── View switching ───

    function wrSwitchView(view) {
        wrState.view = view;
        const rack = document.getElementById('wr-rack-container');
        const tabs = document.getElementById('wr-tabs');
        const btnRack = document.getElementById('wr-view-rack');
        const btnTable = document.getElementById('wr-view-table');
        if (!rack || !tabs) return;
        if (view === 'rack') {
            rack.style.display = 'block';
            tabs.style.display = 'none';
            document.querySelectorAll('.wr-tab-panel').forEach(p => p.style.display = 'none');
            btnRack.classList.add('btn-primary');
            btnTable.classList.remove('btn-primary');
            wrRenderRack();
        } else {
            rack.style.display = 'none';
            tabs.style.display = 'flex';
            btnRack.classList.remove('btn-primary');
            btnTable.classList.add('btn-primary');
            wrSelectTab(wrState.activeTab);
        }
    }

    function wrSelectTab(tab) {
        wrState.activeTab = tab;
        document.querySelectorAll('.wr-tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === tab);
        });
        document.querySelectorAll('.wr-tab-panel').forEach(p => p.style.display = 'none');
        const panel = document.getElementById('wr-tab-' + tab);
        if (panel) panel.style.display = 'block';
        if (tab === 'firewall')     wrRenderRules();
        if (tab === 'lans')         wrRenderLans();
        if (tab === 'leases')       wrRenderLeases();
        if (tab === 'zones')        wrRenderZones();
        if (tab === 'connections')  wrRenderConnections();
        if (tab === 'logs')         wrRenderLogs();
    }

    // ─── Master render ───

    function wrRenderAll() {
        if (wrState.view === 'rack') {
            wrRenderRack();
        } else {
            wrSelectTab(wrState.activeTab);
        }
    }

    // ─── Table: firewall rules ───

    function wrRenderRules() {
        const tbody = document.getElementById('wr-rules-tbody');
        if (!tbody) return;
        if (!wrState.rules.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--text-muted); padding:24px;">No firewall rules yet. Click <strong>+ Rule</strong> to create one.</td></tr>';
            return;
        }
        const rows = [...wrState.rules].sort((a,b) => a.order - b.order);
        tbody.innerHTML = rows.map((r, i) => {
            const actionBadge = {
                allow: 'rgba(34,197,94,0.2); color:#22c55e',
                deny: 'rgba(239,68,68,0.2); color:#ef4444',
                reject: 'rgba(239,68,68,0.2); color:#ef4444',
                log: 'rgba(59,130,246,0.2); color:#60a5fa',
            }[r.action] || '';
            const ports = (r.ports || []).map(p => p.port).join(', ') || '—';
            return `<tr style="${r.enabled ? '' : 'opacity:0.5;'}">
                <td>${i+1}</td>
                <td><span class="badge" style="background:${actionBadge}; font-size:10px; padding:2px 6px;">${r.action.toUpperCase()}</span></td>
                <td style="font-size:11px; color:var(--text-muted);">${r.direction}</td>
                <td>${endpointHtml(r.from)}</td>
                <td>${endpointHtml(r.to)}</td>
                <td>${r.protocol.toUpperCase()}</td>
                <td>${ports}</td>
                <td style="color:var(--text-muted); font-size:11px;">${escHtml(r.comment || '')}</td>
                <td>
                    <button class="btn btn-sm" title="Toggle" onclick="wrToggleRule('${r.id}')">${r.enabled ? '✅' : '⬜'}</button>
                    <button class="btn btn-sm" title="Delete" onclick="wrDeleteRule('${r.id}')">🗑</button>
                </td>
            </tr>`;
        }).join('');
    }

    function endpointHtml(ep) {
        if (!ep) return 'any';
        switch (ep.kind) {
            case 'any': return '<span style="color:var(--text-muted);">any</span>';
            case 'zone': return `<span class="badge" style="background:rgba(168,85,247,0.15); color:#a855f7; font-size:10px;">${zoneHuman(ep.zone)}</span>`;
            case 'interface': return `<code>${escHtml(ep.name)}</code>`;
            case 'ip': return `<code>${escHtml(ep.cidr)}</code>`;
            case 'vm': return `🖥 ${escHtml(ep.name)}`;
            case 'container': return `📦 ${escHtml(ep.name)}`;
            case 'lan': return `🌐 ${escHtml(ep.id)}`;
        }
        return JSON.stringify(ep);
    }

    function zoneHuman(z) {
        if (!z) return '?';
        if (z.kind === 'wan') return 'WAN';
        if (z.kind === 'lan') return 'LAN ' + (z.id || '0');
        if (z.kind === 'dmz') return 'DMZ';
        if (z.kind === 'wolfnet') return 'WolfNet';
        if (z.kind === 'trusted') return 'Trusted';
        if (z.kind === 'custom') return z.id || 'Custom';
        return JSON.stringify(z);
    }

    async function wrToggleRule(id) {
        const r = wrState.rules.find(x => x.id === id);
        if (!r) return;
        r.enabled = !r.enabled;
        await fetch('/api/router/rules/' + id, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(r) });
        await wrLoadAll();
    }

    async function wrDeleteRule(id) {
        if (!confirm('Delete this rule?')) return;
        await fetch('/api/router/rules/' + id, { method: 'DELETE' });
        await wrLoadAll();
    }

    async function wrTestRules() {
        const r = await fetch('/api/router/rules/test', { method: 'POST' });
        const result = await r.json();
        if (result.ok) {
            if (typeof showToast === 'function') showToast('Ruleset passes iptables-restore --test', 'success');
            else alert('Ruleset OK');
        } else {
            const msgs = (result.issues || []).map(i => i.message).join('\n');
            alert('Ruleset has issues:\n' + msgs);
        }
    }

    async function wrConfirmRules() {
        await fetch('/api/router/rules/confirm', { method: 'POST' });
        clearInterval(wrState.rollbackTimerInterval);
        wrState.rollbackTimerInterval = null;
        wrState.rollbackDeadline = null;
        document.getElementById('wr-rules-safemode').style.display = 'none';
    }

    // Rule editor modal
    function wrShowRuleEditor(existing) {
        const r = existing || {
            id: '', enabled: true, order: 0,
            action: 'allow', direction: 'forward',
            from: { kind: 'any' }, to: { kind: 'any' },
            protocol: 'any', ports: [],
            state_track: true, log_match: false, comment: '',
        };
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:640px;">
                <div class="modal-header">
                    <h3>${existing ? 'Edit' : 'New'} firewall rule</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <label>Action
                            <select id="wr-f-action" class="form-control">
                                <option value="allow">Allow</option>
                                <option value="deny">Deny (silent drop)</option>
                                <option value="reject">Reject (ICMP)</option>
                            </select>
                        </label>
                        <label>Direction
                            <select id="wr-f-dir" class="form-control">
                                <option value="forward">Forward (between interfaces)</option>
                                <option value="input">Input (to WolfStack host)</option>
                                <option value="output">Output (from WolfStack host)</option>
                            </select>
                        </label>
                        <label>From (source)
                            <input id="wr-f-from" class="form-control" placeholder="any  |  zone:lan0  |  ip:192.168.1.0/24"/>
                        </label>
                        <label>To (destination)
                            <input id="wr-f-to" class="form-control" placeholder="any  |  zone:wan  |  ip:8.8.8.8"/>
                        </label>
                        <label>Protocol
                            <select id="wr-f-proto" class="form-control">
                                <option value="any">Any</option>
                                <option value="tcp">TCP</option>
                                <option value="udp">UDP</option>
                                <option value="icmp">ICMP</option>
                            </select>
                        </label>
                        <label>Ports (comma-separated, ranges with -)
                            <input id="wr-f-ports" class="form-control" placeholder="80, 443, 8000-8100"/>
                        </label>
                        <label style="grid-column:1/-1;">Comment
                            <input id="wr-f-comment" class="form-control" placeholder="Why does this rule exist?"/>
                        </label>
                        <label style="display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-f-log" />
                            Log matches (to Logs tab)
                        </label>
                        <label style="display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-f-enabled" checked />
                            Enabled
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="wrSaveRule('${r.id}')">${existing ? 'Save' : 'Create'}</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        // Populate existing values
        document.getElementById('wr-f-action').value = r.action;
        document.getElementById('wr-f-dir').value = r.direction;
        document.getElementById('wr-f-from').value = endpointToText(r.from);
        document.getElementById('wr-f-to').value = endpointToText(r.to);
        document.getElementById('wr-f-proto').value = r.protocol;
        document.getElementById('wr-f-ports').value = (r.ports || []).map(p => p.port).join(', ');
        document.getElementById('wr-f-comment').value = r.comment || '';
        document.getElementById('wr-f-log').checked = !!r.log_match;
        document.getElementById('wr-f-enabled').checked = r.enabled !== false;
    }

    function endpointToText(ep) {
        if (!ep || ep.kind === 'any') return 'any';
        if (ep.kind === 'zone') return 'zone:' + (ep.zone?.kind === 'lan' ? `lan${ep.zone.id ?? 0}` : (ep.zone?.kind || ''));
        if (ep.kind === 'interface') return 'iface:' + ep.name;
        if (ep.kind === 'ip') return 'ip:' + ep.cidr;
        return 'any';
    }

    function textToEndpoint(t) {
        t = (t || '').trim();
        if (!t || t === 'any') return { kind: 'any' };
        if (t.startsWith('zone:')) {
            const z = t.slice(5);
            const m = z.match(/^lan(\d+)$/);
            if (m) return { kind: 'zone', zone: { kind: 'lan', id: parseInt(m[1], 10) } };
            if (z === 'wan') return { kind: 'zone', zone: { kind: 'wan' } };
            if (z === 'dmz') return { kind: 'zone', zone: { kind: 'dmz' } };
            if (z === 'wolfnet') return { kind: 'zone', zone: { kind: 'wolfnet' } };
            if (z === 'trusted') return { kind: 'zone', zone: { kind: 'trusted' } };
            return { kind: 'zone', zone: { kind: 'custom', id: z } };
        }
        if (t.startsWith('iface:')) return { kind: 'interface', name: t.slice(6) };
        if (t.startsWith('ip:')) return { kind: 'ip', cidr: t.slice(3) };
        return { kind: 'any' };
    }

    async function wrSaveRule(id) {
        const action = document.getElementById('wr-f-action').value;
        const direction = document.getElementById('wr-f-dir').value;
        const from = textToEndpoint(document.getElementById('wr-f-from').value);
        const to = textToEndpoint(document.getElementById('wr-f-to').value);
        const protocol = document.getElementById('wr-f-proto').value;
        const portsRaw = document.getElementById('wr-f-ports').value;
        const ports = portsRaw.split(',').map(s => s.trim()).filter(Boolean).map(p => ({ port: p, side: 'dst' }));
        const comment = document.getElementById('wr-f-comment').value;
        const log_match = document.getElementById('wr-f-log').checked;
        const enabled = document.getElementById('wr-f-enabled').checked;
        const existing = wrState.rules.find(r => r.id === id);
        const rule = existing ? { ...existing } : { id: '', enabled: true, order: 0, state_track: true };
        Object.assign(rule, { enabled, action, direction, from, to, protocol, ports, comment, log_match });
        const method = id ? 'PUT' : 'POST';
        const url = id ? '/api/router/rules/' + id : '/api/router/rules';
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rule) });
        if (!r.ok) {
            alert('Save failed: ' + await r.text());
            return;
        }
        document.querySelector('.modal-overlay')?.remove();
        await wrLoadAll();
    }

    // ─── Table: LANs + leases ───

    function wrRenderLans() {
        const grid = document.getElementById('wr-lans-list');
        if (!grid) return;
        if (!wrState.lans.length) {
            grid.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:30px;">No LANs yet. Create one to serve DHCP+DNS from WolfRouter.</div>';
            return;
        }
        grid.innerHTML = wrState.lans.map(l => `
            <div style="padding:14px; border:1px solid var(--border); border-radius:8px; background:var(--bg-card);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div>
                        <strong style="font-size:15px;">${escHtml(l.name)}</strong>
                        <span class="badge" style="background:rgba(168,85,247,0.15); color:#a855f7; margin-left:6px; font-size:10px;">${zoneHuman(l.zone)}</span>
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-sm" onclick="wrShowLanEditor('${l.id}')">Edit</button>
                        <button class="btn btn-sm" onclick="wrDeleteLan('${l.id}')">Delete</button>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:8px; font-size:12px; color:var(--text-muted);">
                    <div>Interface: <code>${escHtml(l.interface)}</code></div>
                    <div>Subnet: <code>${escHtml(l.subnet_cidr)}</code></div>
                    <div>Router IP: <code>${escHtml(l.router_ip)}</code></div>
                    <div>DHCP: ${l.dhcp.enabled ? `<strong>${l.dhcp.pool_start} → ${l.dhcp.pool_end}</strong>` : '<span style="color:var(--text-muted);">disabled</span>'}</div>
                    <div>DNS forwarders: ${(l.dns.forwarders || []).join(', ') || '—'}</div>
                    <div>Node: <code>${escHtml(l.node_id || 'this node')}</code></div>
                </div>
            </div>
        `).join('');
    }

    async function wrDeleteLan(id) {
        if (!confirm('Delete this LAN? dnsmasq for this segment will be stopped.')) return;
        await fetch('/api/router/segments/' + id, { method: 'DELETE' });
        await wrLoadAll();
    }

    function wrShowLanEditor(id) {
        const existing = id ? wrState.lans.find(l => l.id === id) : null;
        const l = existing || {
            id: '', name: '', node_id: '',
            interface: 'br-lan0', zone: { kind: 'lan', id: 0 },
            subnet_cidr: '192.168.10.0/24', router_ip: '192.168.10.1',
            dhcp: { enabled: true, pool_start: '192.168.10.100', pool_end: '192.168.10.250', lease_time: '12h', reservations: [], extra_options: [] },
            dns: { forwarders: ['1.1.1.1', '9.9.9.9'], local_records: [], cache_enabled: true, block_ads: false },
            description: '',
        };
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:640px;">
                <div class="modal-header">
                    <h3>${existing ? 'Edit' : 'New'} LAN segment</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <label>Name<input id="wr-l-name" class="form-control" placeholder="HomeLAN"/></label>
                        <label>Node (leave blank for this node)<input id="wr-l-node" class="form-control"/></label>
                        <label>Interface (bridge or NIC)<input id="wr-l-iface" class="form-control" placeholder="br-lan0"/></label>
                        <label>Subnet CIDR<input id="wr-l-cidr" class="form-control" placeholder="192.168.10.0/24"/></label>
                        <label>Router IP<input id="wr-l-router" class="form-control" placeholder="192.168.10.1"/></label>
                        <label>Zone number<input type="number" id="wr-l-zone" class="form-control" value="0" min="0"/></label>
                        <label style="grid-column:1/-1; display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-l-dhcp-enabled"/>Enable DHCP
                        </label>
                        <label>Pool start<input id="wr-l-pool-start" class="form-control"/></label>
                        <label>Pool end<input id="wr-l-pool-end" class="form-control"/></label>
                        <label>Lease time<input id="wr-l-lease" class="form-control" value="12h"/></label>
                        <label>DNS forwarders (comma-separated)<input id="wr-l-fwd" class="form-control" value="1.1.1.1, 9.9.9.9"/></label>
                        <label style="display:flex; gap:8px; align-items:center;">
                            <input type="checkbox" id="wr-l-ads"/>Block ads/trackers via DNS
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="wrSaveLan('${l.id}')">${existing ? 'Save' : 'Create'}</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        document.getElementById('wr-l-name').value = l.name;
        document.getElementById('wr-l-node').value = l.node_id;
        document.getElementById('wr-l-iface').value = l.interface;
        document.getElementById('wr-l-cidr').value = l.subnet_cidr;
        document.getElementById('wr-l-router').value = l.router_ip;
        document.getElementById('wr-l-zone').value = l.zone?.id ?? 0;
        document.getElementById('wr-l-dhcp-enabled').checked = !!l.dhcp.enabled;
        document.getElementById('wr-l-pool-start').value = l.dhcp.pool_start;
        document.getElementById('wr-l-pool-end').value = l.dhcp.pool_end;
        document.getElementById('wr-l-lease').value = l.dhcp.lease_time || '12h';
        document.getElementById('wr-l-fwd').value = (l.dns.forwarders || []).join(', ');
        document.getElementById('wr-l-ads').checked = !!l.dns.block_ads;
    }

    async function wrSaveLan(id) {
        const existing = id ? wrState.lans.find(l => l.id === id) : null;
        const node_id = document.getElementById('wr-l-node').value.trim();
        const lan = existing ? JSON.parse(JSON.stringify(existing)) : { id: '', zone: { kind: 'lan', id: 0 }, dhcp: {}, dns: {}, description: '' };
        lan.name = document.getElementById('wr-l-name').value.trim();
        lan.node_id = node_id || (wrState.topology?.nodes?.[0]?.node_id ?? '');
        lan.interface = document.getElementById('wr-l-iface').value.trim();
        lan.subnet_cidr = document.getElementById('wr-l-cidr').value.trim();
        lan.router_ip = document.getElementById('wr-l-router').value.trim();
        lan.zone = { kind: 'lan', id: parseInt(document.getElementById('wr-l-zone').value, 10) || 0 };
        lan.dhcp = Object.assign(lan.dhcp || {}, {
            enabled: document.getElementById('wr-l-dhcp-enabled').checked,
            pool_start: document.getElementById('wr-l-pool-start').value.trim(),
            pool_end: document.getElementById('wr-l-pool-end').value.trim(),
            lease_time: document.getElementById('wr-l-lease').value.trim(),
            reservations: lan.dhcp?.reservations || [],
            extra_options: lan.dhcp?.extra_options || [],
        });
        lan.dns = Object.assign(lan.dns || {}, {
            forwarders: document.getElementById('wr-l-fwd').value.split(',').map(s => s.trim()).filter(Boolean),
            local_records: lan.dns?.local_records || [],
            cache_enabled: true,
            block_ads: document.getElementById('wr-l-ads').checked,
        });
        const url = id ? '/api/router/segments/' + id : '/api/router/segments';
        const method = id ? 'PUT' : 'POST';
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(lan) });
        if (!r.ok) { alert('Save failed: ' + await r.text()); return; }
        document.querySelector('.modal-overlay')?.remove();
        await wrLoadAll();
    }

    async function wrRenderLeases() {
        const container = document.getElementById('wr-leases-container');
        if (!container) return;
        if (!wrState.lans.length) {
            container.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:24px;">No LANs — no leases. Create a LAN first.</div>';
            return;
        }
        const parts = [];
        for (const lan of wrState.lans) {
            try {
                const r = await fetch('/api/router/segments/' + lan.id + '/leases');
                const leases = r.ok ? await r.json() : [];
                parts.push(`
                    <div style="margin-bottom:18px;">
                        <div style="font-weight:600; margin-bottom:6px;">${escHtml(lan.name)} <span style="color:var(--text-muted); font-size:12px;">(${leases.length} active)</span></div>
                        <table class="data-table" style="font-size:12px;">
                            <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Expires (epoch)</th></tr></thead>
                            <tbody>
                                ${leases.length ? leases.map(le => `<tr><td><code>${escHtml(le.ip)}</code></td><td><code>${escHtml(le.mac)}</code></td><td>${escHtml(le.hostname || '—')}</td><td style="color:var(--text-muted);">${le.expires}</td></tr>`).join('')
                                : '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:12px;">No active leases</td></tr>'}
                            </tbody>
                        </table>
                    </div>
                `);
            } catch (e) {}
        }
        container.innerHTML = parts.join('');
    }

    // ─── Zones ───

    function wrRenderZones() {
        const grid = document.getElementById('wr-zones-grid');
        if (!grid) return;
        const topo = wrState.topology;
        if (!topo || !topo.nodes?.length) {
            grid.innerHTML = '<div style="color:var(--text-muted);">Loading topology...</div>';
            return;
        }
        const zones = ['wan', 'lan0', 'lan1', 'dmz', 'wolfnet', 'trusted'];
        const parts = [];
        for (const node of topo.nodes) {
            parts.push(`<div style="margin-bottom:16px;">
                <h4 style="margin:0 0 8px; font-size:13px;">${escHtml(node.node_name)} <span style="color:var(--text-muted); font-size:11px; font-weight:normal;">(${node.node_id})</span></h4>
                <table class="data-table" style="font-size:12px;"><thead><tr><th>Interface</th><th>Current zone</th><th>Assign</th></tr></thead><tbody>
                ${node.interfaces.map(ifc => {
                    const current = ifc.zone ? zoneHuman(ifc.zone) : '<span style="color:var(--text-muted);">unassigned</span>';
                    const opts = ['<option value="">(unassigned)</option>'].concat(
                        zones.map(z => `<option value="${z}">${z.toUpperCase()}</option>`)
                    ).join('');
                    const cur = ifc.zone?.kind === 'lan' ? `lan${ifc.zone.id}` : (ifc.zone?.kind || '');
                    return `<tr>
                        <td><code>${escHtml(ifc.name)}</code> ${ifc.link_up ? '<span style="color:var(--success);">●</span>' : '<span style="color:var(--text-muted);">○</span>'}</td>
                        <td>${current}</td>
                        <td>
                            <select class="form-control" style="font-size:12px; padding:3px 6px;" onchange="wrAssignZone('${node.node_id}', '${ifc.name}', this.value)">
                                ${opts.replace(`value="${cur}"`, `value="${cur}" selected`)}
                            </select>
                        </td>
                    </tr>`;
                }).join('')}
                </tbody></table>
            </div>`);
        }
        grid.innerHTML = parts.join('');
    }

    async function wrAssignZone(node_id, iface, zoneStr) {
        let zone = null;
        if (zoneStr) {
            const m = zoneStr.match(/^lan(\d+)$/);
            if (m) zone = { kind: 'lan', id: parseInt(m[1], 10) };
            else zone = { kind: zoneStr };
        }
        await fetch('/api/router/zones', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ node_id, interface: iface, zone }),
        });
        await wrLoadAll();
    }

    // ─── Connections + Logs ───

    async function wrRenderConnections() {
        const tbody = document.getElementById('wr-conn-tbody');
        if (!tbody) return;
        try {
            const r = await fetch('/api/router/connections');
            const rows = r.ok ? await r.json() : [];
            if (!rows.length) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">No connections tracked — <code>conntrack</code> may not be installed.</td></tr>';
                return;
            }
            tbody.innerHTML = rows.slice(0, 200).map(c => {
                return `<tr>
                    <td>${escHtml(c.proto || '')}</td>
                    <td><code>${escHtml(c.src || '')}</code></td>
                    <td><code>${escHtml(c.dst || '')}</code></td>
                    <td>${escHtml(c.sport || '')}</td>
                    <td>${escHtml(c.dport || '')}</td>
                    <td>${escHtml(c.state || c.CLOSE || '')}</td>
                </tr>`;
            }).join('');
        } catch (e) {}
    }

    async function wrRenderLogs() {
        const pre = document.getElementById('wr-logs-pre');
        if (!pre) return;
        try {
            const r = await fetch('/api/router/logs');
            const lines = r.ok ? await r.json() : [];
            pre.textContent = lines.length ? lines.join('\n') : '(no firewall log lines — enable "Log this match" on a rule to populate)';
        } catch (e) {}
    }

    // ─── Rack view SVG ───

    function wrRenderRack() {
        const canvas = document.getElementById('wr-rack-canvas');
        if (!canvas) return;
        const topo = wrState.topology;
        if (!topo) {
            canvas.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding:40px;">Loading topology…</div>';
            return;
        }

        const W = canvas.clientWidth || 1000;
        const nodeCount = Math.max(topo.nodes.length, 1);
        const unitH = 110;               // height per node rack unit
        const gap = 22;
        const cloudH = 70;
        const devicesH = Math.min(180, 40 + topo.nodes.reduce((s, n) => s + (n.vms.length + n.containers.length), 0) * 6);
        const H = cloudH + 20 + nodeCount * (unitH + gap) + 20 + devicesH;

        // Build SVG.
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('width', W); svg.setAttribute('height', H);
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
        svg.setAttribute('xmlns', ns);

        // Gradient defs for "cloud"
        svg.insertAdjacentHTML('afterbegin', `
            <defs>
                <linearGradient id="wr-cloud-grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="rgba(59,130,246,0.25)"/>
                    <stop offset="1" stop-color="rgba(59,130,246,0.08)"/>
                </linearGradient>
                <linearGradient id="wr-unit-grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="rgba(51,65,85,1)"/>
                    <stop offset="1" stop-color="rgba(30,41,59,1)"/>
                </linearGradient>
            </defs>
        `);

        // WAN "cloud" at the top
        const cloudY = 10;
        const cloudX = W / 2 - 130;
        svg.insertAdjacentHTML('beforeend', `
            <g class="wr-cloud-group">
                <ellipse cx="${W/2}" cy="${cloudY + cloudH/2}" rx="130" ry="${cloudH/2-5}" fill="url(#wr-cloud-grad)" stroke="rgba(59,130,246,0.4)" />
                <text x="${W/2}" y="${cloudY + cloudH/2 + 5}" text-anchor="middle" class="wr-node-name" style="fill:#60a5fa;">🌐 Internet (WAN)</text>
            </g>
        `);

        // Node rack units
        const portsByNode = {};       // node_id → array of {name, cx, cy}
        let y = cloudY + cloudH + 20;
        for (const node of topo.nodes) {
            const x = 10;
            const w = W - 20;
            const unit = document.createElementNS(ns, 'g');
            unit.classList.add('wr-rack-unit-group');
            svg.appendChild(unit);

            // Rack chassis
            unit.insertAdjacentHTML('beforeend', `
                <rect x="${x}" y="${y}" width="${w}" height="${unitH}" rx="10" fill="url(#wr-unit-grad)" stroke="var(--border, #334155)" stroke-width="1.5"/>
                <rect x="${x+8}" y="${y+8}" width="14" height="14" rx="2" fill="var(--primary,#a855f7)" opacity="0.6"/>
                <rect x="${x+8}" y="${y+28}" width="14" height="14" rx="2" fill="#22c55e" opacity="${node.interfaces.some(i=>i.link_up) ? '1' : '0.3'}"/>
                <text x="${x+30}" y="${y+22}" class="wr-node-name">🖥 ${escHtml(node.node_name)}</text>
                <text x="${x+30}" y="${y+40}" class="wr-port-label" text-anchor="start">${node.interfaces.length} ports · ${node.vms.length} VMs · ${node.containers.length} containers</text>
            `);

            // Ports laid out left-to-right on the bottom half of the unit
            portsByNode[node.node_id] = [];
            const portBoxW = 48, portBoxH = 34;
            const portsAreaX = x + 200;
            const portsAreaW = w - 260;
            const portGap = 8;
            const maxCols = Math.max(1, Math.floor((portsAreaW + portGap) / (portBoxW + portGap)));
            node.interfaces.slice(0, maxCols).forEach((port, i) => {
                const px = portsAreaX + i * (portBoxW + portGap);
                const py = y + 50;
                const color = port.link_up
                    ? (port.role === 'wan' ? '#ef4444' :
                       port.role === 'lan' ? '#22c55e' :
                       port.role === 'management' ? '#3b82f6' : '#64748b')
                    : '#1e293b';
                const roleLetter = {
                    wan: 'W', lan: 'L', trunk: 'T', management: 'M', wolfnet: 'N', unused: '—'
                }[port.role] || '·';
                const bpsKb = Math.round((port.rx_bps + port.tx_bps) / 1024);
                unit.insertAdjacentHTML('beforeend', `
                    <g class="wr-port" data-node="${escHtml(node.node_id)}" data-iface="${escHtml(port.name)}">
                        <rect x="${px}" y="${py}" width="${portBoxW}" height="${portBoxH}" rx="4" fill="${color}" opacity="${port.link_up ? 0.9 : 0.3}" stroke="rgba(0,0,0,0.3)"/>
                        <circle cx="${px + portBoxW - 8}" cy="${py + 8}" r="3" fill="${port.link_up ? '#4ade80' : '#475569'}"/>
                        <text x="${px + portBoxW/2}" y="${py + portBoxH/2 + 3}" text-anchor="middle" class="wr-port-label" style="font-size:11px; fill:white; font-weight:600;">${roleLetter}</text>
                        <text x="${px + portBoxW/2}" y="${py + portBoxH + 11}" class="wr-port-label">${escHtml(port.name.slice(0,10))}</text>
                        ${bpsKb > 0 ? `<text x="${px + portBoxW/2}" y="${py - 3}" class="wr-port-label" style="fill:#4ade80;">${fmtBps(port.rx_bps + port.tx_bps)}</text>` : ''}
                        <title>${escHtml(port.name)} — ${port.link_up ? 'UP' : 'DOWN'} — ${escHtml((port.addresses||[]).join(', '))}</title>
                    </g>
                `);
                portsByNode[node.node_id].push({ name: port.name, cx: px + portBoxW/2, cy: py + portBoxH/2, role: port.role, link_up: port.link_up, bps: port.rx_bps + port.tx_bps });
            });

            y += unitH + gap;
        }

        // Wires: WAN ports → cloud
        for (const node of topo.nodes) {
            for (const port of (portsByNode[node.node_id] || [])) {
                if (port.role === 'wan' && port.link_up) {
                    const isActive = port.bps > 0;
                    const path = `M ${port.cx},${port.cy} C ${port.cx},${(port.cy + cloudY + cloudH) / 2} ${W/2},${(port.cy + cloudY + cloudH) / 2} ${W/2},${cloudY + cloudH}`;
                    svg.insertAdjacentHTML('beforeend', `
                        <path d="${path}" class="wr-wire ${isActive ? 'wr-wire-active' : ''}" stroke="${isActive ? '#ef4444' : '#64748b'}" stroke-width="${isActive ? 2.5 : 1.5}" opacity="0.8"/>
                    `);
                }
            }
        }

        // WolfNet shaded region between nodes (only if multiple nodes)
        if (topo.nodes.length > 1) {
            const startY = cloudY + cloudH + 20;
            const endY = startY + topo.nodes.length * (unitH + gap) - gap;
            svg.insertAdjacentHTML('beforeend', `
                <rect x="${W - 50}" y="${startY}" width="30" height="${endY - startY}" rx="8" fill="rgba(34,197,94,0.08)" stroke="rgba(34,197,94,0.3)" stroke-dasharray="4,3"/>
                <text x="${W - 35}" y="${(startY + endY)/2}" transform="rotate(-90 ${W-35} ${(startY+endY)/2})" text-anchor="middle" class="wr-port-label" style="fill:#22c55e;">WolfNet</text>
            `);
        }

        // Device strip at the bottom
        const devY = y + 20;
        svg.insertAdjacentHTML('beforeend', `
            <text x="20" y="${devY + 10}" class="wr-node-name">🔌 Devices</text>
        `);
        let dx = 20, dy = devY + 26;
        const badgeW = 160, badgeH = 22;
        const cols = Math.max(1, Math.floor((W - 40) / (badgeW + 8)));
        let i = 0;
        for (const node of topo.nodes) {
            for (const vm of node.vms) {
                const col = i % cols, row = Math.floor(i / cols);
                const bx = 20 + col * (badgeW + 8);
                const by = devY + 26 + row * (badgeH + 6);
                svg.insertAdjacentHTML('beforeend', `
                    <g>
                        <rect x="${bx}" y="${by}" width="${badgeW}" height="${badgeH}" rx="4" class="wr-device-badge"/>
                        <text x="${bx + 8}" y="${by + 15}" class="wr-device-text">🖥 ${escHtml(vm.name.slice(0,18))} → ${escHtml(vm.attached_to.slice(0,10))}</text>
                    </g>
                `);
                i++;
            }
            for (const ct of node.containers) {
                const col = i % cols, row = Math.floor(i / cols);
                const bx = 20 + col * (badgeW + 8);
                const by = devY + 26 + row * (badgeH + 6);
                svg.insertAdjacentHTML('beforeend', `
                    <g>
                        <rect x="${bx}" y="${by}" width="${badgeW}" height="${badgeH}" rx="4" class="wr-device-badge" stroke="#3b82f6" stroke-opacity="0.4"/>
                        <text x="${bx + 8}" y="${by + 15}" class="wr-device-text">📦 ${escHtml(ct.name.slice(0,18))}</text>
                    </g>
                `);
                i++;
            }
        }

        canvas.innerHTML = '';
        canvas.appendChild(svg);

        // Legend
        const legend = document.getElementById('wr-rack-legend');
        if (legend) {
            legend.innerHTML = `
                <div><span style="display:inline-block; width:12px; height:12px; background:#ef4444; border-radius:2px; vertical-align:middle;"></span> WAN</div>
                <div><span style="display:inline-block; width:12px; height:12px; background:#22c55e; border-radius:2px; vertical-align:middle;"></span> LAN</div>
                <div><span style="display:inline-block; width:12px; height:12px; background:#3b82f6; border-radius:2px; vertical-align:middle;"></span> Management</div>
                <div><span style="display:inline-block; width:12px; height:12px; background:#64748b; border-radius:2px; vertical-align:middle;"></span> Unassigned</div>
                <div style="margin-left:auto; color:var(--text-muted);">Hover a port for details · click to assign a zone</div>
            `;
        }

        // Click handler for ports → open zone assignment
        canvas.querySelectorAll('.wr-port').forEach(el => {
            el.addEventListener('click', () => {
                const node = el.dataset.node;
                const iface = el.dataset.iface;
                wrShowPortPanel(node, iface);
            });
        });
    }

    function wrShowPortPanel(nodeId, ifaceName) {
        const topo = wrState.topology;
        const node = topo?.nodes?.find(n => n.node_id === nodeId);
        const port = node?.interfaces?.find(i => i.name === ifaceName);
        if (!port) return;
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:500px;">
                <div class="modal-header">
                    <h3>${escHtml(ifaceName)} on ${escHtml(node.node_name)}</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 2fr; gap:6px 12px;">
                        <div style="color:var(--text-muted);">State</div><div>${port.link_up ? '🟢 UP' : '⚫ DOWN'}</div>
                        <div style="color:var(--text-muted);">MAC</div><div><code>${escHtml(port.mac)}</code></div>
                        <div style="color:var(--text-muted);">Speed</div><div>${port.speed_mbps ? port.speed_mbps + ' Mbps' : '—'}</div>
                        <div style="color:var(--text-muted);">Addresses</div><div>${(port.addresses||[]).map(a => `<code>${escHtml(a)}</code>`).join(', ') || '—'}</div>
                        <div style="color:var(--text-muted);">Live</div><div>⬇ ${fmtBps(port.rx_bps)} · ⬆ ${fmtBps(port.tx_bps)}</div>
                        <div style="color:var(--text-muted);">Role</div><div>${port.role.toUpperCase()}</div>
                        <div style="color:var(--text-muted);">Zone</div><div>
                            <select class="form-control" style="font-size:12px; padding:3px 6px; width:auto;" id="wr-port-zone">
                                <option value="">(unassigned)</option>
                                <option value="wan">WAN</option>
                                <option value="lan0">LAN 0</option>
                                <option value="lan1">LAN 1</option>
                                <option value="dmz">DMZ</option>
                                <option value="wolfnet">WolfNet</option>
                                <option value="trusted">Trusted</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Close</button>
                    <button class="btn btn-primary" onclick="(async()=>{await wrAssignZone('${nodeId}','${ifaceName}',document.getElementById('wr-port-zone').value); this.closest('.modal-overlay').remove();})()">Apply zone</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        const cur = port.zone?.kind === 'lan' ? `lan${port.zone.id}` : (port.zone?.kind || '');
        if (cur) document.getElementById('wr-port-zone').value = cur;
    }

    // ─── Helpers ───

    function escHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function fmtBps(bps) {
        if (bps < 1024) return bps + ' bps';
        if (bps < 1024 * 1024) return (bps / 1024).toFixed(1) + ' Kbps';
        if (bps < 1024 * 1024 * 1024) return (bps / 1048576).toFixed(1) + ' Mbps';
        return (bps / 1073741824).toFixed(2) + ' Gbps';
    }
})();

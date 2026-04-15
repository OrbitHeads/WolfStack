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
        cluster: null,         // active cluster name — scopes every fetch
        topology: null,
        rules: [],
        lans: [],
        zones: { assignments: {} },
        rollbackTimerInterval: null,
        rollbackDeadline: null,
        pollInterval: null,
    };

    // Builds an /api/router/* URL with the active cluster as a query
    // parameter. Backend uses it to filter nodes by cluster_name.
    function wrUrl(path) {
        if (!wrState.cluster) return path;
        const sep = path.includes('?') ? '&' : '?';
        return path + sep + 'cluster=' + encodeURIComponent(wrState.cluster);
    }

    // Expose hooks the HTML and app.js call directly.
    window.wrLoadAll = wrLoadAll;
    window.wrStartPolling = wrStartPolling;
    window.showWolfRouterForCluster = showWolfRouterForCluster;
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

    // Entry point used by the cluster-scoped sidebar item. Sets the
    // active cluster, switches the page, then loads.
    async function showWolfRouterForCluster(clusterName) {
        if (typeof closeSidebarMobile === 'function') closeSidebarMobile();
        wrState.cluster = clusterName;
        if (typeof currentPage !== 'undefined') window.currentPage = 'wolfrouter-cluster';
        if (typeof currentNodeId !== 'undefined') window.currentNodeId = null;

        document.querySelectorAll('.page-view').forEach(p => p.style.display = 'none');
        const el = document.getElementById('page-wolfrouter');
        if (el) el.style.display = 'block';

        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const item = document.querySelector(`.wolfrouter-cluster-item[data-cluster="${clusterName}"]`);
        if (item) item.classList.add('active');

        const titleEl = document.getElementById('page-title');
        if (titleEl) titleEl.textContent = `WolfRouter — ${clusterName}`;

        await wrLoadAll();
        wrStartPolling();
    }

    async function wrLoadAll() {
        // Surface fetch failures directly in the rack canvas — silent
        // "Loading topology…" forever is the worst possible UX.
        const showErr = (msg) => {
            const c = document.getElementById('wr-rack-canvas');
            if (c) c.innerHTML = `<div style="color:#ef4444; text-align:center; padding:40px; font-size:13px;">
                ${msg}<br><br><span style="color:var(--text-muted); font-size:11px;">Check the browser console + WolfStack server log for details.</span>
            </div>`;
        };
        try {
            const [topoR, rulesR, lansR, zonesR, managedR, snapR] = await Promise.all([
                fetch(wrUrl('/api/router/topology')),
                fetch(wrUrl('/api/router/rules')),
                fetch(wrUrl('/api/router/segments')),
                fetch(wrUrl('/api/router/zones')),
                fetch(wrUrl('/api/router/managed-overview')),
                fetch(wrUrl('/api/router/host-snapshot')),
            ]);
            if (!topoR.ok) {
                const body = await topoR.text().catch(() => '');
                console.error('wolfrouter: topology fetch failed', topoR.status, body);
                showErr(`Topology fetch failed: HTTP ${topoR.status} ${topoR.statusText}<br><code>${escHtml(body.slice(0,200))}</code>`);
                return;
            }
            wrState.topology = await topoR.json();
            if (rulesR.ok) wrState.rules = await rulesR.json();
            if (lansR.ok)  wrState.lans = await lansR.json();
            if (zonesR.ok) wrState.zones = await zonesR.json();
            if (managedR.ok) wrState.managed = await managedR.json();
            if (snapR.ok) wrState.snapshot = await snapR.json();
            wrRenderAll();
        } catch (e) {
            console.error('wolfrouter load:', e);
            showErr(`Network error: ${e.message || e}`);
        }
    }

    function wrStartPolling() {
        if (wrState.pollInterval) clearInterval(wrState.pollInterval);
        wrState.pollInterval = setInterval(async () => {
            // WolfRouter has its own page now, but stay tolerant of being
            // embedded elsewhere. If neither page is visible, suspend.
            const wr = document.getElementById('page-wolfrouter');
            const net = document.getElementById('page-networking');
            const visible = (wr && wr.style.display !== 'none') ||
                            (net && net.style.display !== 'none');
            if (!visible) return;
            try {
                const r = await fetch(wrUrl('/api/router/topology'));
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
        // Also render the "managed elsewhere" port-forwards panel — IP
        // mappings owned by WolfStack's existing Networking page.
        const mPanel = document.getElementById('wr-managed-mappings');
        const mBody = document.getElementById('wr-mappings-tbody');
        const mappings = (wrState.managed?.ip_mappings) || [];
        if (mPanel && mBody) {
            if (mappings.length) {
                mPanel.style.display = 'block';
                mBody.innerHTML = mappings.map(m => `
                    <tr style="${m.enabled ? '' : 'opacity:0.5;'}">
                        <td><code>${escHtml(m.public_ip)}</code></td>
                        <td><code>${escHtml(m.wolfnet_ip)}</code></td>
                        <td>${escHtml(m.ports || 'all')}${m.dest_ports ? ` → ${escHtml(m.dest_ports)}` : ''}</td>
                        <td>${escHtml(m.protocol || 'all').toUpperCase()}</td>
                        <td>${escHtml(m.label || '')}</td>
                        <td style="text-align:right;"><span class="badge" style="background:rgba(59,130,246,0.15); color:#60a5fa; font-size:10px;">external</span></td>
                    </tr>
                `).join('');
            } else {
                mPanel.style.display = 'none';
            }
        }

        // Discovered iptables rules — what's already on the host. Always
        // visible so the firewall tab is never empty even when no
        // WolfRouter rules exist yet.
        wrRenderHostFirewall();

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
        await fetch(wrUrl('/api/router/rules/' + id), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(r) });
        await wrLoadAll();
    }

    async function wrDeleteRule(id) {
        if (!confirm('Delete this rule?')) return;
        await fetch(wrUrl('/api/router/rules/' + id), { method: 'DELETE' });
        await wrLoadAll();
    }

    async function wrTestRules() {
        const r = await fetch(wrUrl('/api/router/rules/test'), { method: 'POST' });
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
        await fetch(wrUrl('/api/router/rules/confirm'), { method: 'POST' });
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
        const url = wrUrl(id ? '/api/router/rules/' + id : '/api/router/rules');
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
        const discovered = (wrState.snapshot?.dhcp?.dnsmasq_processes) || [];
        const discoveredHtml = discovered.length
            ? `<div style="margin-bottom:16px; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--bg-card);">
                <h4 style="font-size:13px; margin:0 0 8px;">📡 dnsmasq instances discovered on this host (${discovered.length})</h4>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">Other DHCP/DNS servers running independently of WolfRouter — listed so you don't accidentally double-bind a port.</div>
                ${discovered.map(p => `
                    <div style="display:grid; grid-template-columns: 60px 120px 1fr; gap:8px; padding:4px 0; font-size:12px; border-top:1px dashed var(--border);">
                        <span style="color:var(--text-muted);">PID ${escHtml(p.pid)}</span>
                        <span><code>${escHtml(p.interface || 'auto')}</code></span>
                        <span style="color:var(--text-muted); font-family:var(--font-mono); font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escHtml(p.config_file || p.command.slice(0,80))}</span>
                    </div>
                `).join('')}
            </div>`
            : '';

        if (!wrState.lans.length) {
            grid.innerHTML = discoveredHtml +
                '<div style="text-align:center; color:var(--text-muted); padding:30px;">No WolfRouter LANs yet. Create one to serve DHCP+DNS for a subnet.</div>';
            return;
        }
        grid.innerHTML = discoveredHtml + grid.innerHTML;
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

    // Render every iptables rule currently active on the host into the
    // firewall tab so it's never empty. Rules owned by WolfRouter are
    // already shown in the editable table above; this section shows
    // everything else (Docker, LXC, WolfStack DNAT, manual rules,
    // system chain defaults).
    function wrRenderHostFirewall() {
        let panel = document.getElementById('wr-host-firewall');
        if (!panel) {
            // Inject the panel once into the firewall tab.
            const fwTab = document.getElementById('wr-tab-firewall');
            if (!fwTab) return;
            panel = document.createElement('div');
            panel.id = 'wr-host-firewall';
            panel.style.marginTop = '24px';
            fwTab.appendChild(panel);
        }
        const filter = wrState.snapshot?.firewall?.filter || [];
        const nat = wrState.snapshot?.firewall?.nat || [];
        const all = filter.concat(nat);
        if (!all.length) {
            panel.innerHTML = `<h4 style="font-size:13px; margin-bottom:8px; color:var(--text-muted);">🛡 Discovered host firewall rules</h4>
                <div style="color:var(--text-muted); font-size:12px; padding:12px;">No iptables rules detected (or iptables not readable as this user — try running as root).</div>`;
            return;
        }
        // Group by owner so users see what's WolfRouter vs what's already there.
        const ownerLabel = {
            wolfrouter: 'WolfRouter (managed here)',
            wolfstack:  'WolfStack (port forwards / VM NAT)',
            docker:     'Docker',
            lxc:        'LXC',
            system:     'System / kernel',
            user:       'User-defined / other',
        };
        const ownerColor = {
            wolfrouter: '#a855f7', wolfstack: '#22c55e',
            docker: '#3b82f6', lxc: '#06b6d4',
            system: '#94a3b8', user: '#fbbf24',
        };
        const groups = {};
        for (const r of all) {
            (groups[r.owner] = groups[r.owner] || []).push(r);
        }
        const orderedKeys = Object.keys(ownerLabel).filter(k => groups[k]);
        panel.innerHTML = `
            <div style="display:flex; align-items:baseline; justify-content:space-between; margin-bottom:8px;">
                <h4 style="font-size:13px; margin:0; color:var(--text);">🛡 All firewall rules on this host (${all.length} total)</h4>
                <span style="font-size:11px; color:var(--text-muted);">read-only — discovered from <code>iptables-save</code></span>
            </div>
            ${orderedKeys.map(k => `
                <details ${k === 'wolfrouter' || k === 'wolfstack' ? 'open' : ''} style="margin-bottom:8px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card);">
                    <summary style="padding:8px 12px; cursor:pointer; font-size:12px; font-weight:600;">
                        <span style="display:inline-block; width:10px; height:10px; background:${ownerColor[k]}; border-radius:50%; vertical-align:middle; margin-right:8px;"></span>
                        ${escHtml(ownerLabel[k])} <span style="color:var(--text-muted); font-weight:normal; margin-left:6px;">(${groups[k].length})</span>
                    </summary>
                    <div style="padding:0 8px 8px;">
                        <pre style="font-family:var(--font-mono); font-size:11px; background:var(--bg-secondary); padding:8px; border-radius:4px; max-height:200px; overflow:auto; margin:4px 0;">${groups[k].map(r => escHtml(`[${r.table}] ${r.raw}`)).join('\n')}</pre>
                    </div>
                </details>
            `).join('')}
        `;
    }

    async function wrDeleteLan(id) {
        if (!confirm('Delete this LAN? dnsmasq for this segment will be stopped.')) return;
        await fetch(wrUrl('/api/router/segments/' + id), { method: 'DELETE' });
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
        const url = wrUrl(id ? '/api/router/segments/' + id : '/api/router/segments');
        const method = id ? 'PUT' : 'POST';
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(lan) });
        if (!r.ok) { alert('Save failed: ' + await r.text()); return; }
        document.querySelector('.modal-overlay')?.remove();
        await wrLoadAll();
    }

    async function wrRenderLeases() {
        const container = document.getElementById('wr-leases-container');
        if (!container) return;
        const discoveredFiles = (wrState.snapshot?.dhcp?.lease_files) || [];
        const discoveredHtml = discoveredFiles.length
            ? `<div style="margin-bottom:16px;">
                <h4 style="font-size:13px; margin:0 0 8px;">🔍 Lease files discovered on this host</h4>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">Aggregated from /var/lib/wolfstack-router, /var/lib/dhcp, /var/lib/misc and /run.</div>
                ${discoveredFiles.map(f => `
                    <details ${f.leases.length ? 'open' : ''} style="margin-bottom:8px; border:1px solid var(--border); border-radius:6px; background:var(--bg-card);">
                        <summary style="padding:8px 12px; cursor:pointer; font-size:12px; font-weight:600;">
                            📄 <code style="font-family:var(--font-mono);">${escHtml(f.path)}</code>
                            <span style="color:var(--text-muted); font-weight:normal; margin-left:6px;">(${f.leases.length} lease${f.leases.length===1?'':'s'})</span>
                        </summary>
                        <div style="padding:0 8px 8px;">
                            ${f.leases.length
                                ? `<table class="data-table" style="font-size:11px;">
                                    <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Expires</th></tr></thead>
                                    <tbody>${f.leases.map(le => `<tr><td><code>${escHtml(le.ip)}</code></td><td><code>${escHtml(le.mac)}</code></td><td>${escHtml(le.hostname || '—')}</td><td style="color:var(--text-muted);">${escHtml(le.expires)}</td></tr>`).join('')}</tbody>
                                </table>`
                                : '<div style="color:var(--text-muted); font-size:11px; padding:8px;">Empty</div>'}
                        </div>
                    </details>
                `).join('')}
            </div>`
            : '';

        if (!wrState.lans.length) {
            container.innerHTML = discoveredHtml +
                '<div style="text-align:center; color:var(--text-muted); padding:18px;">No WolfRouter-managed LANs. Add one to serve DHCP from WolfRouter directly.</div>';
            return;
        }
        const parts = [discoveredHtml];
        for (const lan of wrState.lans) {
            try {
                const r = await fetch(wrUrl('/api/router/segments/' + lan.id + '/leases'));
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
        await fetch(wrUrl('/api/router/zones'), {
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
            const r = await fetch(wrUrl('/api/router/connections'));
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
            const r = await fetch(wrUrl('/api/router/logs'));
            const lines = r.ok ? await r.json() : [];
            pre.textContent = lines.length ? lines.join('\n') : '(no firewall log lines — enable "Log this match" on a rule to populate)';
        } catch (e) {}
    }

    // ─── Rack view SVG (the real-rack version) ───
    //
    // Renders a server-room scene: Internet cloud at top, vertical rack
    // with mounting rails on either side, 2U appliances stacked inside,
    // each with a brand strip + LCD label + a row of RJ45-style port
    // jacks (with link/activity LEDs), and thick coloured patch cables
    // routed from each WAN port up to the cloud and from each LAN/etc
    // port down to a "device shelf" at the bottom.
    //
    // Cable colour code:
    //   yellow  = WAN (internet uplink)
    //   blue    = LAN (general user network)
    //   green   = WolfNet overlay
    //   purple  = Management
    //   grey    = unassigned / trunk

    function wrRenderRack() {
        const canvas = document.getElementById('wr-rack-canvas');
        if (!canvas) return;
        const topo = wrState.topology;
        if (!topo || !topo.nodes || topo.nodes.length === 0) {
            canvas.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:60px;">
                No nodes in topology. <br>
                ${wrState.cluster ? `Cluster <code>${escHtml(wrState.cluster)}</code> may have no online WolfStack nodes.` : 'No cluster selected.'}
            </div>`;
            return;
        }
        // Render a header describing the cluster + node count so the
        // rack view feels like a real cluster overview, not just a
        // diagram floating in space.
        const header = document.createElement('div');
        header.style.cssText = 'margin-bottom:12px; padding:10px 14px; background:rgba(168,85,247,0.08); border:1px solid rgba(168,85,247,0.25); border-radius:6px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; font-size:13px;';
        const totalPorts = topo.nodes.reduce((s, n) => s + (n.interfaces?.length || 0), 0);
        const totalUp = topo.nodes.reduce((s, n) => s + (n.interfaces || []).filter(i => i.link_up).length, 0);
        const totalVms = topo.nodes.reduce((s, n) => s + (n.vms?.length || 0), 0);
        const totalCt = topo.nodes.reduce((s, n) => s + (n.containers?.length || 0), 0);
        header.innerHTML = `
            <div><strong>📡 Cluster: ${escHtml(wrState.cluster || 'unnamed')}</strong>
                <span style="color:var(--text-muted); margin-left:8px;">${topo.nodes.length} node${topo.nodes.length===1?'':'s'} · ${totalUp}/${totalPorts} ports up · ${totalVms} VMs · ${totalCt} containers</span>
            </div>
            <div style="color:var(--text-muted); font-size:11px;">⛓ live topology refreshes every 3s</div>
        `;

        const W = Math.max(canvas.clientWidth || 1000, 720);
        const ns = 'http://www.w3.org/2000/svg';

        // Layout dimensions ─────────────────────────────────────────
        const padX = 20;
        const cloudH = 90;
        const cloudGap = 30;
        const railW = 22;          // vertical rail width on each side
        const rackInnerPad = 8;    // gap between rail and appliance
        const unitH = 96;          // 2U appliance height
        const unitGap = 24;        // wider so devices fit between nodes

        const nodeCount = topo.nodes.length;
        const maxDevicesPerNode = Math.max(
            1,
            ...topo.nodes.map(n => Math.min(6, (n.vms?.length || 0) + (n.containers?.length || 0)))
        );

        const rackY = cloudH + cloudGap;
        const rackInnerH = nodeCount * unitH + (nodeCount - 1) * unitGap + rackInnerPad * 2;
        // Leave room on the right for per-node device columns
        const H = rackY + rackInnerH + 60;

        const rackX = padX;
        const rackW = Math.max(W - padX*2 - 220, 600);  // reserve right-side strip for devices
        const apX = rackX + railW + rackInnerPad;
        const apW = rackW - railW*2 - rackInnerPad*2;

        // SVG root + defs ──────────────────────────────────────────
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('width', W); svg.setAttribute('height', H);
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
        svg.setAttribute('xmlns', ns);
        svg.style.fontFamily = 'system-ui, sans-serif';

        svg.insertAdjacentHTML('afterbegin', `
            <defs>
                <radialGradient id="wr-cloud" cx="50%" cy="40%" r="55%">
                    <stop offset="0" stop-color="rgba(96,165,250,0.65)"/>
                    <stop offset="0.7" stop-color="rgba(59,130,246,0.25)"/>
                    <stop offset="1" stop-color="rgba(30,58,138,0.05)"/>
                </radialGradient>
                <linearGradient id="wr-rail" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0" stop-color="#1f2937"/>
                    <stop offset="0.5" stop-color="#374151"/>
                    <stop offset="1" stop-color="#1f2937"/>
                </linearGradient>
                <linearGradient id="wr-chassis" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="#2c3a4f"/>
                    <stop offset="0.5" stop-color="#1f2a3d"/>
                    <stop offset="1" stop-color="#141d2c"/>
                </linearGradient>
                <linearGradient id="wr-brand" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="#7c3aed"/>
                    <stop offset="1" stop-color="#4c1d95"/>
                </linearGradient>
                <radialGradient id="wr-led-green" cx="50%" cy="50%" r="50%">
                    <stop offset="0" stop-color="#bbf7d0"/>
                    <stop offset="0.5" stop-color="#22c55e"/>
                    <stop offset="1" stop-color="#15803d"/>
                </radialGradient>
                <radialGradient id="wr-led-amber" cx="50%" cy="50%" r="50%">
                    <stop offset="0" stop-color="#fde68a"/>
                    <stop offset="0.5" stop-color="#f59e0b"/>
                    <stop offset="1" stop-color="#92400e"/>
                </radialGradient>
                <radialGradient id="wr-led-off" cx="50%" cy="50%" r="50%">
                    <stop offset="0" stop-color="#1e293b"/>
                    <stop offset="1" stop-color="#0f172a"/>
                </radialGradient>
                <linearGradient id="wr-jack" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stop-color="#0a0f18"/>
                    <stop offset="1" stop-color="#1e293b"/>
                </linearGradient>
                <filter id="wr-glow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="2" result="b"/>
                    <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
            </defs>
        `);

        // Internet cloud ──────────────────────────────────────────
        const cloudCX = W/2, cloudCY = cloudH/2 + 6;
        svg.insertAdjacentHTML('beforeend', `
            <g class="wr-cloud-group">
                <path d="M ${cloudCX-160},${cloudCY+12}
                         C ${cloudCX-180},${cloudCY-20} ${cloudCX-110},${cloudCY-50} ${cloudCX-70},${cloudCY-30}
                         C ${cloudCX-50},${cloudCY-55} ${cloudCX+10},${cloudCY-55} ${cloudCX+30},${cloudCY-30}
                         C ${cloudCX+80},${cloudCY-55} ${cloudCX+150},${cloudCY-25} ${cloudCX+140},${cloudCY+5}
                         C ${cloudCX+180},${cloudCY+15} ${cloudCX+170},${cloudCY+45} ${cloudCX+120},${cloudCY+40}
                         L ${cloudCX-130},${cloudCY+40}
                         C ${cloudCX-180},${cloudCY+45} ${cloudCX-185},${cloudCY+15} ${cloudCX-160},${cloudCY+12} Z"
                      fill="url(#wr-cloud)" stroke="rgba(96,165,250,0.5)" stroke-width="1.5"/>
                <text x="${cloudCX}" y="${cloudCY-2}" text-anchor="middle"
                      style="fill:#bfdbfe; font-size:14px; font-weight:600;">🌍 Internet</text>
                <text x="${cloudCX}" y="${cloudCY+18}" text-anchor="middle"
                      style="fill:#93c5fd; font-size:10px;">WAN uplink</text>
            </g>
        `);

        // Rack frame ──────────────────────────────────────────────
        // Outer rack background panel
        svg.insertAdjacentHTML('beforeend', `
            <rect x="${rackX}" y="${rackY}" width="${rackW}" height="${rackInnerH}" rx="6"
                  fill="rgba(15,23,42,0.65)" stroke="#1e293b" stroke-width="2"/>
        `);
        // Left + right rails with mounting holes
        for (const railX of [rackX, rackX + rackW - railW]) {
            svg.insertAdjacentHTML('beforeend', `
                <rect x="${railX}" y="${rackY}" width="${railW}" height="${rackInnerH}"
                      fill="url(#wr-rail)" stroke="#0a0f18" stroke-width="0.5"/>
            `);
            // Mounting holes — one every ~22px
            for (let yy = rackY + 12; yy < rackY + rackInnerH - 6; yy += 22) {
                svg.insertAdjacentHTML('beforeend', `
                    <ellipse cx="${railX + railW/2}" cy="${yy}" rx="3" ry="4.5"
                             fill="#0a0f18" stroke="#374151" stroke-width="0.4"/>
                `);
            }
        }

        // Rack appliances + ports ─────────────────────────────────
        const portsByNode = {};
        let yCursor = rackY + rackInnerPad;
        for (const node of topo.nodes) {
            const ux = apX, uy = yCursor, uw = apW, uh = unitH;
            const brandW = 120;
            const portsZoneX = ux + brandW + 14;
            const portsZoneW = uw - brandW - 28 - 100;  // leave room for stats panel
            const statsX = ux + uw - 96;

            // Chassis
            const chassis = document.createElementNS(ns, 'g');
            svg.appendChild(chassis);
            chassis.insertAdjacentHTML('beforeend', `
                <rect x="${ux}" y="${uy}" width="${uw}" height="${uh}" rx="6"
                      fill="url(#wr-chassis)" stroke="#0a0f18" stroke-width="1.5"/>
                <!-- Top venting strip -->
                ${Array.from({length: 24}).map((_,i) =>
                    `<line x1="${ux+10+i*8}" y1="${uy+5}" x2="${ux+14+i*8}" y2="${uy+5}" stroke="#0a0f18" stroke-width="1.2"/>`
                ).join('')}
                <!-- Brand panel (left) -->
                <rect x="${ux+8}" y="${uy+10}" width="${brandW}" height="${uh-20}" rx="3"
                      fill="url(#wr-brand)" opacity="0.85"/>
                <text x="${ux+18}" y="${uy+34}" style="fill:#fff; font-size:14px; font-weight:700; letter-spacing:0.5px;">WOLF</text>
                <text x="${ux+18}" y="${uy+50}" style="fill:rgba(255,255,255,0.7); font-size:10px; letter-spacing:1px;">STACK</text>
                <text x="${ux+18}" y="${uy+72}" style="fill:#fde68a; font-size:11px; font-weight:600; font-family:monospace;">${escHtml(node.node_name.slice(0,14))}</text>
                <!-- Power LED (always on if responsive) -->
                <circle cx="${ux+brandW-8}" cy="${uy+18}" r="3.5" fill="url(#wr-led-green)" filter="url(#wr-glow)"/>
                <!-- Activity LED (any port up) -->
                <circle cx="${ux+brandW-8}" cy="${uy+34}" r="3.5"
                        fill="${node.interfaces.some(i=>i.link_up) ? 'url(#wr-led-amber)' : 'url(#wr-led-off)'}"
                        ${node.interfaces.some(i=>i.link_up) ? 'filter="url(#wr-glow)"' : ''}/>
                <!-- Stats panel (right) -->
                <rect x="${statsX}" y="${uy+10}" width="88" height="${uh-20}" rx="3"
                      fill="rgba(0,0,0,0.4)" stroke="#0a0f18"/>
                <text x="${statsX+8}" y="${uy+24}" style="fill:#22c55e; font-size:9px; font-family:monospace;">PORTS ${node.interfaces.length}</text>
                <text x="${statsX+8}" y="${uy+38}" style="fill:#60a5fa; font-size:9px; font-family:monospace;">VMS   ${node.vms.length}</text>
                <text x="${statsX+8}" y="${uy+52}" style="fill:#a855f7; font-size:9px; font-family:monospace;">CTRS  ${node.containers.length}</text>
                <text x="${statsX+8}" y="${uy+72}" style="fill:#94a3b8; font-size:8px;">${escHtml(node.lan_segments?.length ? node.lan_segments.length + ' LAN' : 'no LAN')}</text>
            `);

            // Ports — laid out in a single row across the middle of the chassis
            portsByNode[node.node_id] = [];
            const jackW = 28, jackH = 22, jackGap = 6;
            const maxPorts = Math.min(node.interfaces.length, Math.floor((portsZoneW + jackGap) / (jackW + jackGap)));
            const startPx = portsZoneX + (portsZoneW - (maxPorts*(jackW+jackGap) - jackGap)) / 2;
            const portsCY = uy + uh/2 + 2;

            node.interfaces.slice(0, maxPorts).forEach((port, idx) => {
                const px = startPx + idx * (jackW + jackGap);
                const py = portsCY - jackH/2;
                const cableColor = port.link_up
                    ? (port.role === 'wan' ? '#fbbf24' :
                       port.role === 'lan' ? '#3b82f6' :
                       port.role === 'wolfnet' ? '#22c55e' :
                       port.role === 'management' ? '#a855f7' : '#94a3b8')
                    : '#475569';
                const linkLed = port.link_up ? 'url(#wr-led-green)' : 'url(#wr-led-off)';
                const actLed = (port.rx_bps + port.tx_bps) > 0 ? 'url(#wr-led-amber)' : 'url(#wr-led-off)';
                // RJ45 jack: trapezoidal shape with 8 contact pins inside.
                const jackPath = `M ${px+2},${py+jackH-2}
                                  L ${px+2},${py+5}
                                  L ${px+5},${py+2}
                                  L ${px+jackW-5},${py+2}
                                  L ${px+jackW-2},${py+5}
                                  L ${px+jackW-2},${py+jackH-2} Z`;
                chassis.insertAdjacentHTML('beforeend', `
                    <g class="wr-port" data-node="${escHtml(node.node_id)}" data-iface="${escHtml(port.name)}">
                        <!-- LEDs above the jack: link (left) + activity (right) -->
                        <circle cx="${px+8}" cy="${py-3}" r="2" fill="${linkLed}"/>
                        <circle cx="${px+jackW-8}" cy="${py-3}" r="2" fill="${actLed}"
                                ${(port.rx_bps + port.tx_bps) > 0 ? 'filter="url(#wr-glow)"' : ''}/>
                        <!-- The jack itself -->
                        <path d="${jackPath}" fill="url(#wr-jack)" stroke="#000" stroke-width="0.6"/>
                        <!-- 8 contact pins -->
                        ${Array.from({length: 8}).map((_,j) =>
                            `<line x1="${px+5+j*((jackW-10)/7)}" y1="${py+5}" x2="${px+5+j*((jackW-10)/7)}" y2="${py+jackH-4}" stroke="#fbbf24" stroke-width="0.6" opacity="${port.link_up ? 0.7 : 0.25}"/>`
                        ).join('')}
                        <!-- Iface name below -->
                        <text x="${px+jackW/2}" y="${py+jackH+10}" text-anchor="middle"
                              style="fill:#cbd5e1; font-size:8px; font-family:monospace;">${escHtml(port.name.slice(0,8))}</text>
                        <!-- Live BPS above LEDs (only if actively flowing) -->
                        ${(port.rx_bps + port.tx_bps) > 0
                            ? `<text x="${px+jackW/2}" y="${py-9}" text-anchor="middle" style="fill:#fde68a; font-size:8px; font-family:monospace;">${fmtBpsShort(port.rx_bps + port.tx_bps)}</text>`
                            : ''}
                        <title>${escHtml(port.name)} — ${port.link_up ? 'UP' : 'DOWN'} — role: ${port.role}${(port.addresses||[]).length ? ' — ' + (port.addresses||[]).join(', ') : ''}</title>
                    </g>
                `);
                portsByNode[node.node_id].push({
                    name: port.name, cx: px + jackW/2, cy: py + jackH/2,
                    portTop: py - 5, portBottom: py + jackH + 4,
                    role: port.role, link_up: port.link_up,
                    bps: port.rx_bps + port.tx_bps, color: cableColor,
                });
            });

            yCursor += uh + unitGap;
        }

        // Patch cables ────────────────────────────────────────────
        // WolfNet mesh: when there are multiple nodes, draw a thick
        // green cable along the right side of the rack connecting every
        // appliance — visualises the L3 overlay that ties the cluster
        // together. The "spine" runs vertically; each node taps off it.
        const wolfnetSpineX = rackX + rackW - railW + 6;
        if (topo.nodes.length > 1) {
            const firstY = rackY + rackInnerPad + unitH/2;
            const lastY = rackY + rackInnerPad + (topo.nodes.length-1)*(unitH+unitGap) + unitH/2;
            // Spine
            svg.insertAdjacentHTML('beforeend', `
                <line x1="${wolfnetSpineX}" y1="${firstY}" x2="${wolfnetSpineX}" y2="${lastY}"
                      stroke="#22c55e" stroke-width="4" stroke-linecap="round" opacity="0.6"
                      stroke-dasharray="6 4" class="wr-wire-active"/>
                <text x="${wolfnetSpineX + 8}" y="${(firstY+lastY)/2}" transform="rotate(90 ${wolfnetSpineX+8} ${(firstY+lastY)/2})"
                      text-anchor="middle" style="fill:#22c55e; font-size:10px; font-weight:600;">⛓ WolfNet mesh</text>
            `);
            // Per-node tap from the spine into the back of each appliance
            for (let n = 0; n < topo.nodes.length; n++) {
                const ny = rackY + rackInnerPad + n*(unitH+unitGap) + unitH/2;
                const nx = apX + apW - 100;  // right edge of the stats panel
                svg.insertAdjacentHTML('beforeend', `
                    <path d="M ${nx},${ny} C ${nx+30},${ny} ${wolfnetSpineX-20},${ny} ${wolfnetSpineX},${ny}"
                          fill="none" stroke="#22c55e" stroke-width="3" stroke-linecap="round" opacity="0.7"/>
                    <circle cx="${wolfnetSpineX}" cy="${ny}" r="4" fill="#22c55e" opacity="0.9"/>
                `);
            }
        }

        // WAN ports → cloud (route up).
        const cables = [];
        for (const node of topo.nodes) {
            for (const port of (portsByNode[node.node_id] || [])) {
                if (port.role === 'wan' && port.link_up) {
                    const x1 = port.cx, y1 = port.portTop;
                    const x2 = cloudCX, y2 = cloudCY + 30;
                    // Route around the rack to the side, up to cloud
                    const cy1 = y1 - 20;
                    const cy2 = (y1 + y2) / 2;
                    const path = `M ${x1},${y1}
                                  C ${x1},${cy1} ${x2},${cy2} ${x2},${y2}`;
                    cables.push({ path, color: port.color, bps: port.bps, kind: 'wan' });
                }
            }
        }

        // LAN / WolfNet / Mgmt ports — render a small downward "patch
        // tail" stub from each port so the user sees these are wired,
        // even though the actual device-side cable is drawn separately
        // from the node anchor over to its devices.
        for (const node of topo.nodes) {
            for (const port of (portsByNode[node.node_id] || [])) {
                if (!port.link_up) continue;
                if (port.role === 'wan') continue;
                const x1 = port.cx, y1 = port.portBottom;
                const path = `M ${x1},${y1} l 0,12`;
                cables.push({ path, color: port.color, bps: port.bps, kind: port.role });
            }
        }

        // Render cables behind the chassis but above the rack panel —
        // we already drew the rack/appliances first, so cables now go on
        // top, which actually reads better in this metaphor (cables in
        // front of equipment is what you see in a real rack from the
        // patch-panel side).
        for (const c of cables) {
            const active = c.bps > 0;
            svg.insertAdjacentHTML('beforeend', `
                <path d="${c.path}" fill="none" stroke-linecap="round"
                      stroke="${c.color}" stroke-width="${active ? 5 : 4}"
                      opacity="${active ? 0.95 : 0.7}"
                      ${active ? 'class="wr-wire-active" stroke-dasharray="10 6"' : ''}/>
                <path d="${c.path}" fill="none" stroke-linecap="round"
                      stroke="rgba(255,255,255,0.18)" stroke-width="1"/>
            `);
        }

        // Per-node device clusters — instead of a flat shelf, hang each
        // node's VMs/containers directly under that node so the wiring
        // is unambiguous: device → server → port → cable → cloud.
        const deviceColW = Math.max(180, Math.floor(rackW / Math.max(topo.nodes.length, 1)) - 20);
        const deviceColGap = 12;
        for (let nIdx = 0; nIdx < topo.nodes.length; nIdx++) {
            const node = topo.nodes[nIdx];
            const nodeY = rackY + rackInnerPad + nIdx * (unitH + unitGap);
            const devicesForNode = (node.vms || []).concat(node.containers || []);
            if (!devicesForNode.length) continue;

            // Pick an anchor point on the node's right side to wire from
            const anchorX = apX + apW;
            const anchorY = nodeY + unitH / 2;
            // Each device gets a small badge to the right of the rack.
            // Layout: stack vertically beside the node, wrap to a second
            // column if too many.
            const colX = anchorX + 40 + nIdx * 4;  // staggered to avoid overlap
            devicesForNode.slice(0, 6).forEach((dev, i) => {
                const isVm = dev.kind === 'vm';
                const accent = isVm ? '#60a5fa' : '#a855f7';
                const icon = isVm ? '🖥' : '📦';
                const dy = anchorY - 60 + i * 22;
                // Curved cable from node anchor to device badge
                const cableColor = isVm ? '#60a5fa' : '#a855f7';
                svg.insertAdjacentHTML('beforeend', `
                    <path d="M ${anchorX},${anchorY} C ${anchorX+20},${anchorY} ${colX-15},${dy+10} ${colX},${dy+10}"
                          fill="none" stroke="${cableColor}" stroke-width="2" stroke-linecap="round" opacity="0.55"
                          ${i % 2 === 0 ? 'stroke-dasharray="6 4" class="wr-wire-active"' : ''}/>
                    <g>
                        <rect x="${colX}" y="${dy}" width="170" height="20" rx="5"
                              fill="rgba(15,23,42,0.95)" stroke="${accent}" stroke-width="1"/>
                        <text x="${colX+8}" y="${dy+14}" style="fill:#f1f5f9; font-size:11px;">${icon} ${escHtml(dev.name.slice(0,14))}</text>
                        <text x="${colX+165}" y="${dy+14}" text-anchor="end" style="fill:${accent}; font-size:9px; font-family:monospace;">${escHtml((dev.attached_to||'').slice(0,9))}</text>
                    </g>
                `);
            });
            // Overflow indicator if there are more devices
            if (devicesForNode.length > 6) {
                svg.insertAdjacentHTML('beforeend', `
                    <text x="${colX + 85}" y="${anchorY + 76}" text-anchor="middle"
                          style="fill:var(--text-muted, #94a3b8); font-size:10px;">+ ${devicesForNode.length - 6} more</text>
                `);
            }
        }

        // Inter-node WolfNet mesh — each pair of nodes connected by a
        // curved green cable to visualise the L3 overlay holding the
        // cluster together. Drawn behind everything else for depth.
        if (topo.nodes.length > 1) {
            for (let i = 0; i < topo.nodes.length; i++) {
                for (let j = i + 1; j < topo.nodes.length; j++) {
                    const yi = rackY + rackInnerPad + i * (unitH + unitGap) + unitH/2;
                    const yj = rackY + rackInnerPad + j * (unitH + unitGap) + unitH/2;
                    const xLeft = apX + 8;
                    // Curve to the left of the rack so it's visible
                    const ctrlX = xLeft - 80;
                    svg.insertAdjacentHTML('beforeend', `
                        <path d="M ${xLeft},${yi} C ${ctrlX},${yi} ${ctrlX},${yj} ${xLeft},${yj}"
                              fill="none" stroke="#22c55e" stroke-width="2.5" stroke-linecap="round"
                              opacity="0.5" stroke-dasharray="8 5" class="wr-wire-active"/>
                    `);
                }
            }
        }

        canvas.innerHTML = '';
        canvas.appendChild(header);
        canvas.appendChild(svg);

        // Legend + integration badges
        const legend = document.getElementById('wr-rack-legend');
        if (legend) {
            const sw = (color, label) =>
                `<div style="display:flex; align-items:center; gap:6px;"><span style="display:inline-block; width:18px; height:4px; background:${color}; border-radius:2px;"></span> ${label}</div>`;

            // Surface live integration state — what WolfStack already
            // runs that WolfRouter is now showing alongside its own.
            const wn = wrState.managed?.wolfnet_status;
            const peerCount = (wn?.peers || []).length;
            const wnBadge = wn
                ? `<div style="display:flex; align-items:center; gap:6px;"><span style="color:#22c55e;">⛓</span> WolfNet: ${peerCount} peer${peerCount===1?'':'s'}${wn.running===false ? ' <span style="color:#ef4444;">(daemon down)</span>' : ''}</div>`
                : '';
            const mappingCount = (wrState.managed?.ip_mappings || []).length;
            const mapBadge = mappingCount
                ? `<div style="display:flex; align-items:center; gap:6px;"><span style="color:#60a5fa;">🔗</span> ${mappingCount} port forward${mappingCount===1?'':'s'} (DNAT)</div>`
                : '';

            legend.innerHTML = [
                sw('#fbbf24', 'WAN cable'),
                sw('#3b82f6', 'LAN cable'),
                sw('#22c55e', 'WolfNet'),
                sw('#a855f7', 'Management'),
                sw('#94a3b8', 'Unassigned'),
                wnBadge,
                mapBadge,
                `<div style="margin-left:auto; color:var(--text-muted);">Click a port to assign a zone · cables animate when traffic flows</div>`
            ].filter(Boolean).join('');
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

    // Compact "5K" "120M" formatter for the LED-style port readouts.
    function fmtBpsShort(bps) {
        if (bps < 1024) return bps + 'b';
        if (bps < 1024*1024) return Math.round(bps / 1024) + 'K';
        if (bps < 1024*1024*1024) return Math.round(bps / 1048576) + 'M';
        return (bps / 1073741824).toFixed(1) + 'G';
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

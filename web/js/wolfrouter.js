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
        if (tab === 'policy')       wrRenderPolicyMap();
        if (tab === 'wan')          wrRenderWan();
        if (tab === 'connections')  wrRenderConnections();
        if (tab === 'packets')      wrRenderPackets();
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
        const sm = document.getElementById('wr-rules-safemode');
        if (sm) sm.style.display = 'none';
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
                    <!-- Live warnings — rule analyser flags lockout
                         risks, duplicates, and no-op rules as the
                         user fills in the fields. -->
                    <div id="wr-f-warnings" style="margin-top:12px;"></div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="wrSaveRule('${r.id}')">${existing ? 'Save' : 'Create'}</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        // Wire live-warning refresh on every field change. setTimeout
        // defers the first run until after the existing-rule values
        // have been populated below.
        setTimeout(() => {
            ['wr-f-action','wr-f-dir','wr-f-from','wr-f-to','wr-f-proto','wr-f-ports','wr-f-log','wr-f-enabled'].forEach(id => {
                const el = document.getElementById(id);
                if (!el) return;
                el.addEventListener('input', wrRenderRuleWarnings);
                el.addEventListener('change', wrRenderRuleWarnings);
            });
            wrRenderRuleWarnings();
        }, 50);
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

    /// Analyse a proposed (or edited) rule against the current state
    /// and return a list of {severity, message} warnings. Called from
    /// the rule editor whenever a field changes so users see the
    /// consequences BEFORE they click Save.
    ///
    /// Severities: "danger" (red — lockout risk or catastrophic),
    /// "warning" (amber — probably-wrong), "info" (grey — observation).
    function wrAnalyzeRule(rule) {
        const out = [];
        const fromText = (rule.from?.kind === 'any' ? 'any' :
                          rule.from?.kind === 'zone' ? ('zone ' + (rule.from.zone?.kind || ''))
                          : JSON.stringify(rule.from));
        const toText   = (rule.to?.kind === 'any' ? 'any' :
                          rule.to?.kind === 'zone' ? ('zone ' + (rule.to.zone?.kind || ''))
                          : JSON.stringify(rule.to));

        // 1. Any → Any deny = total lockout.
        if (rule.action === 'deny' && rule.from?.kind === 'any' && rule.to?.kind === 'any') {
            out.push({ severity: 'danger', message: 'Any → Any DENY blocks ALL traffic through the firewall. You will lose access to everything including this UI. Almost certainly not what you meant.' });
        }

        // 2. Any deny that includes the Trusted zone on the source side
        //    — if the admin's machine is in Trusted, this locks them out.
        if (rule.action === 'deny' && (rule.from?.kind === 'any' ||
            (rule.from?.kind === 'zone' && rule.from.zone?.kind === 'trusted')))
        {
            if (rule.direction === 'input' || rule.direction === 'forward') {
                out.push({ severity: 'danger', message: 'Deny rule with Trusted / Any as source can lock admins out of SSH and the WolfStack UI. Safe-mode will revert in 30s — be ready to click "Keep these rules" or let it roll back.' });
            }
        }

        // 3. Intra-zone deny (LAN → same LAN) — rarely what you want.
        if (rule.action === 'deny' && rule.from?.kind === 'zone' && rule.to?.kind === 'zone'
            && rule.from.zone?.kind === rule.to.zone?.kind
            && (rule.from.zone?.id === rule.to.zone?.id))
        {
            out.push({ severity: 'warning', message: `Denying ${fromText} → ${toText} isolates everything within that zone. If devices in this zone need to talk to each other, this breaks it.` });
        }

        // 4. Deny that targets WolfNet from a non-WolfNet zone —
        //    breaks inter-node traffic.
        if (rule.action === 'deny'
            && (rule.to?.kind === 'zone' && rule.to.zone?.kind === 'wolfnet'))
        {
            out.push({ severity: 'warning', message: 'Blocking traffic INTO WolfNet breaks cluster communication — nodes stop seeing each other, WolfRouter replication stops, migrations fail. Only proceed if you know why you need this.' });
        }

        // 5. Allow/deny on OUTPUT for WAN → blocks this host's own
        //    outgoing traffic (apt updates, DNS, etc).
        if (rule.action === 'deny' && rule.direction === 'output'
            && (rule.to?.kind === 'zone' && rule.to.zone?.kind === 'wan'))
        {
            out.push({ severity: 'danger', message: 'Output deny to WAN blocks this host\'s own outgoing traffic — package updates, DNS, NTP, Let\'s Encrypt renewals all fail.' });
        }

        // 6. Duplicate or contradicting rule detection.
        for (const existing of (wrState.rules || [])) {
            if (existing.id === rule.id) continue;  // editing self
            if (!existing.enabled) continue;
            const sameFrom = JSON.stringify(existing.from) === JSON.stringify(rule.from);
            const sameTo   = JSON.stringify(existing.to)   === JSON.stringify(rule.to);
            const sameProto = existing.protocol === rule.protocol;
            if (sameFrom && sameTo && sameProto) {
                if (existing.action === rule.action) {
                    out.push({ severity: 'info', message: `A rule with the same source/dest/protocol and action already exists (#${existing.id.slice(0,8)}). This would be a duplicate.` });
                } else {
                    out.push({ severity: 'warning', message: `Another enabled rule (${existing.action.toUpperCase()}, #${existing.id.slice(0,8)}) matches the same source/dest/protocol. Order matters — the lower-numbered rule wins.` });
                }
            }
        }

        // 7. Port range with protocol=any — iptables ignores ports
        //    unless proto is tcp/udp; this rule silently matches more
        //    than the user thinks.
        if ((rule.ports || []).length > 0 && rule.protocol === 'any') {
            out.push({ severity: 'warning', message: 'Ports only take effect when protocol is TCP or UDP. With Any, the ports are ignored and this rule matches every protocol (ICMP, SCTP, etc).' });
        }

        // 8. Reject without state tracking — firing on every packet
        //    of a long connection, flooding logs.
        if (rule.action === 'reject' && !rule.state_track) {
            out.push({ severity: 'info', message: 'Reject without state tracking fires once per packet, not once per connection. Log volume can be huge.' });
        }

        return out;
    }

    /// Render the warnings panel inline in the rule editor. Called
    /// from the field change handlers (see wrShowRuleEditor).
    function wrRenderRuleWarnings() {
        const panel = document.getElementById('wr-f-warnings');
        if (!panel) return;
        const rule = wrCollectRuleFromEditor();
        if (!rule) return;  // DOM not ready yet — skip analysis
        const warnings = wrAnalyzeRule(rule);
        if (!warnings.length) {
            panel.innerHTML = '<div style="color:var(--text-muted); font-size:11px; padding:6px 0;">✓ No obvious issues detected with this rule.</div>';
            return;
        }
        const colours = {
            danger:  { bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.4)', icon: '🛑', label: '#ef4444' },
            warning: { bg: 'rgba(251,191,36,0.10)', border: 'rgba(251,191,36,0.35)', icon: '⚠', label: '#fbbf24' },
            info:    { bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.3)',   icon: 'ℹ', label: '#60a5fa' },
        };
        panel.innerHTML = warnings.map(w => {
            const c = colours[w.severity] || colours.info;
            return `<div style="margin-bottom:6px; padding:8px 10px; background:${c.bg}; border:1px solid ${c.border}; border-radius:4px; font-size:12px;">
                <span style="color:${c.label}; font-weight:600;">${c.icon} ${w.severity.toUpperCase()}</span>
                <div style="color:var(--text); margin-top:2px;">${escHtml(w.message)}</div>
            </div>`;
        }).join('');
    }

    /// Pull the current editor field values into a rule object —
    /// used by wrRenderRuleWarnings and wrSaveRule to share logic.
    function wrCollectRuleFromEditor() {
        const byId = (id) => document.getElementById(id);
        // Every element the function touches must exist before we
        // start reading — otherwise we race the modal DOM being built.
        const required = ['wr-f-action', 'wr-f-ports', 'wr-f-enabled',
            'wr-f-dir', 'wr-f-from', 'wr-f-to', 'wr-f-proto',
            'wr-f-log', 'wr-f-comment'];
        for (const id of required) { if (!byId(id)) return null; }
        const ports = byId('wr-f-ports').value.split(',').map(s => s.trim()).filter(Boolean)
            .map(p => ({ port: p, side: 'dst' }));
        return {
            id: '',
            enabled: byId('wr-f-enabled').checked,
            action: byId('wr-f-action').value,
            direction: byId('wr-f-dir').value,
            from: textToEndpoint(byId('wr-f-from').value),
            to: textToEndpoint(byId('wr-f-to').value),
            protocol: byId('wr-f-proto').value,
            ports,
            state_track: true,
            log_match: byId('wr-f-log').checked,
            comment: byId('wr-f-comment').value,
        };
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
        const errBox = document.getElementById('wr-conn-error');
        if (!tbody) return;
        try {
            const r = await fetch(wrUrl('/api/router/connections'));
            const data = r.ok ? await r.json() : { rows: [], error: `HTTP ${r.status}` };
            const rows = data.rows || [];
            if (errBox) {
                if (data.error) {
                    errBox.style.display = 'block';
                    errBox.textContent = data.error;
                } else {
                    errBox.style.display = 'none';
                }
            }
            if (!rows.length) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:16px;">${data.error ? 'No data — see error above.' : 'No tracked connections right now. Generate some traffic and refresh.'}</td></tr>`;
                return;
            }
            tbody.innerHTML = rows.slice(0, 200).map(c => `<tr>
                <td>${escHtml(c.proto || '')}</td>
                <td><code>${escHtml(c.src || '')}</code></td>
                <td><code>${escHtml(c.dst || '')}</code></td>
                <td>${escHtml(c.sport || '')}</td>
                <td>${escHtml(c.dport || '')}</td>
                <td>${escHtml(c.state || '')}</td>
                <td style="color:var(--text-muted); font-family:var(--font-mono); font-size:11px;">${escHtml(c.timeout || '')}</td>
            </tr>`).join('');
        } catch (e) {
            if (errBox) { errBox.style.display = 'block'; errBox.textContent = 'Network error: ' + (e.message || e); }
        }
    }

    // ─── WAN connections (DHCP / Static / PPPoE) ─────────────

    async function wrRenderWan() {
        const list = document.getElementById('wr-wan-list');
        if (!list) return;
        let conns = [];
        let status = [];
        try {
            const [r, sR] = await Promise.all([
                fetch(wrUrl('/api/router/wan')),
                fetch(wrUrl('/api/router/wan-status')),
            ]);
            if (r.ok) conns = await r.json();
            if (sR.ok) status = await sR.json();
        } catch (e) {}
        const statusById = Object.fromEntries(status.map(s => [s.id, s]));
        if (!conns.length) {
            list.innerHTML = `<div style="text-align:center; color:var(--text-muted); padding:30px;">
                No WAN connections yet. WolfRouter doesn't manage your existing DHCP — you only need to add an entry here for <strong>PPPoE</strong> dialers or <strong>static-IP overrides</strong>.
            </div>`;
            return;
        }
        list.innerHTML = conns.map(c => {
            const live = statusById[c.id] || {};
            const modeLabel = c.mode.mode || 'unknown';
            const modeColor = { dhcp: '#3b82f6', static: '#94a3b8', pppoe: '#a855f7' }[modeLabel] || '#94a3b8';
            const liveBadge = live.live_iface
                ? `<span style="color:#22c55e;">⬤ UP</span> on <code>${escHtml(live.live_iface)}</code> · ${escHtml(live.live_ip || '')}`
                : (c.enabled ? '<span style="color:#fbbf24;">⬤ down / connecting</span>' : '<span style="color:var(--text-muted);">○ disabled</span>');
            const modeDetail = (() => {
                if (modeLabel === 'pppoe') {
                    const p = c.mode.config || {};
                    return `user <code>${escHtml(p.username)}</code> · MTU ${p.mtu || 1492}`;
                }
                if (modeLabel === 'static') {
                    const s = c.mode.config || {};
                    return `<code>${escHtml(s.address_cidr)}</code> via <code>${escHtml(s.gateway)}</code>`;
                }
                return '(host DHCP client)';
            })();
            return `<div style="padding:14px; border:1px solid var(--border); border-radius:8px; background:var(--bg-card);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div>
                        <strong style="font-size:15px;">${escHtml(c.name)}</strong>
                        <span class="badge" style="background:${modeColor}22; color:${modeColor}; margin-left:6px; font-size:10px; padding:2px 8px;">${modeLabel.toUpperCase()}</span>
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-sm" onclick="wrShowWanEditor('${c.id}')">Edit</button>
                        <button class="btn btn-sm" onclick="wrDeleteWan('${c.id}')">Delete</button>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:8px; font-size:12px; color:var(--text-muted);">
                    <div>Interface: <code>${escHtml(c.interface)}</code></div>
                    <div>${modeDetail}</div>
                    <div>${liveBadge}</div>
                </div>
            </div>`;
        }).join('');
    }

    function wrShowWanEditor(id) {
        const existing = id ? null : null;  // we re-fetch below for fresh data
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '10000';
        overlay.innerHTML = `
            <div class="modal" style="max-width:640px;">
                <div class="modal-header">
                    <h3>${id ? 'Edit' : 'New'} WAN connection</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body" style="font-size:13px;">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <label>Name<input id="wr-w-name" class="form-control" placeholder="ISP uplink"/></label>
                        <label>Interface<select id="wr-w-iface" class="form-control"></select></label>
                        <label>Mode
                            <select id="wr-w-mode" class="form-control" onchange="wrToggleWanModeFields()">
                                <option value="dhcp">DHCP (most ISPs / cable / fibre router)</option>
                                <option value="static">Static IP</option>
                                <option value="pppoe">PPPoE (ADSL / VDSL / fibre with bridged ONT)</option>
                            </select>
                        </label>
                        <label style="display:flex; align-items:center; gap:6px;">
                            <input type="checkbox" id="wr-w-enabled" checked/> Enabled (start on save)
                        </label>
                    </div>

                    <div id="wr-w-static" style="display:none; margin-top:10px;">
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                            <label>Address (CIDR)<input id="wr-w-addr" class="form-control" placeholder="203.0.113.10/24"/></label>
                            <label>Gateway<input id="wr-w-gw" class="form-control" placeholder="203.0.113.1"/></label>
                            <label style="grid-column:1/-1;">DNS servers (comma-separated)<input id="wr-w-dns" class="form-control" placeholder="1.1.1.1, 9.9.9.9"/></label>
                        </div>
                    </div>

                    <div id="wr-w-pppoe" style="display:none; margin-top:10px;">
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                            <label>Username<input id="wr-w-user" class="form-control" placeholder="user@isp.example"/></label>
                            <label>Password<input id="wr-w-pass" type="password" class="form-control" placeholder="••••••"/></label>
                            <label>Service name (optional)<input id="wr-w-svc" class="form-control" placeholder="leave blank for most ISPs"/></label>
                            <label>MTU<input id="wr-w-mtu" type="number" class="form-control" value="1492" min="576" max="1500"/></label>
                            <label>LCP echo interval (s, 0=off)<input id="wr-w-lcp" type="number" class="form-control" value="30" min="0" max="600"/></label>
                            <label style="display:flex; align-items:center; gap:6px;">
                                <input type="checkbox" id="wr-w-persist" checked/> Auto-reconnect on link drops
                            </label>
                            <label style="grid-column:1/-1; display:flex; align-items:start; gap:6px; padding:8px 10px; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.3); border-radius:4px;">
                                <input type="checkbox" id="wr-w-pppoe-default-route" style="margin-top:2px;"/>
                                <div>
                                    <strong style="color:#fca5a5;">⚠ Make this PPP link the default route</strong>
                                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                                        When enabled, pppd <em>replaces</em> the system's existing default gateway the moment the link comes up. ONLY tick this when PPPoE is genuinely your server's primary internet. If the server already reaches the internet via a different NIC, turning this on will break that connectivity immediately.
                                    </div>
                                </div>
                            </label>
                            <label style="grid-column:1/-1; display:flex; align-items:start; gap:6px; padding:8px 10px; background:rgba(251,191,36,0.08); border:1px solid rgba(251,191,36,0.3); border-radius:4px;">
                                <input type="checkbox" id="wr-w-pppoe-peer-dns" style="margin-top:2px;"/>
                                <div>
                                    <strong style="color:#fbbf24;">⚠ Use ISP's DNS (overwrites /etc/resolv.conf)</strong>
                                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                                        pppd will overwrite /etc/resolv.conf with the DNS servers the ISP hands out. Clobbers any existing resolver config.
                                    </div>
                                </div>
                            </label>
                        </div>
                        <div style="margin-top:10px; padding:10px; background:rgba(168,85,247,0.08); border:1px solid rgba(168,85,247,0.3); border-radius:6px; font-size:12px; color:var(--text-muted);">
                            On save, WolfRouter writes <code>/etc/ppp/peers/wolfrouter-{id}</code> + secrets (mode 0600), auto-installs the <code>ppp</code> + <code>pppoe</code> packages if missing, then calls <code>pppd</code> to bring the link up. The resulting <code>ppp0</code> appears in the rack view as the WAN port.
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="wrSaveWan('${id || ''}')">${id ? 'Save' : 'Create'}</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);

        // Populate iface dropdown from local-node interfaces.
        const ifSel = document.getElementById('wr-w-iface');
        const ifaces = new Set();
        for (const n of (wrState.topology?.nodes || [])) {
            for (const i of (n.interfaces || [])) ifaces.add(i.name);
        }
        ifSel.innerHTML = Array.from(ifaces).sort().map(i => `<option value="${escHtml(i)}">${escHtml(i)}</option>`).join('') || '<option value="">(no interfaces)</option>';

        // Load existing values if editing.
        if (id) {
            fetch(wrUrl('/api/router/wan')).then(r => r.json()).then(arr => {
                const c = arr.find(x => x.id === id);
                if (!c) return;
                document.getElementById('wr-w-name').value = c.name;
                document.getElementById('wr-w-iface').value = c.interface;
                document.getElementById('wr-w-mode').value = c.mode?.mode || 'dhcp';
                document.getElementById('wr-w-enabled').checked = c.enabled !== false;
                if (c.mode?.mode === 'static') {
                    document.getElementById('wr-w-addr').value = c.mode.config?.address_cidr || '';
                    document.getElementById('wr-w-gw').value = c.mode.config?.gateway || '';
                    document.getElementById('wr-w-dns').value = (c.mode.config?.dns || []).join(', ');
                } else if (c.mode?.mode === 'pppoe') {
                    document.getElementById('wr-w-user').value = c.mode.config?.username || '';
                    // Password masked from server — leave blank; will preserve on save.
                    document.getElementById('wr-w-pass').value = c.mode.config?.password === '***' ? '***' : '';
                    document.getElementById('wr-w-svc').value = c.mode.config?.service_name || '';
                    document.getElementById('wr-w-mtu').value = c.mode.config?.mtu || 1492;
                    document.getElementById('wr-w-lcp').value = c.mode.config?.lcp_echo_interval ?? 30;
                    document.getElementById('wr-w-persist').checked = c.mode.config?.persist !== false;
                    document.getElementById('wr-w-pppoe-default-route').checked = !!c.mode.config?.use_default_route;
                    document.getElementById('wr-w-pppoe-peer-dns').checked = !!c.mode.config?.use_peer_dns;
                }
                wrToggleWanModeFields();
            });
        } else {
            wrToggleWanModeFields();
        }
    }
    window.wrShowWanEditor = wrShowWanEditor;

    function wrToggleWanModeFields() {
        const modeEl = document.getElementById('wr-w-mode');
        if (!modeEl) return;  // modal not open
        const m = modeEl.value;
        const staticEl = document.getElementById('wr-w-static');
        const pppoeEl = document.getElementById('wr-w-pppoe');
        if (staticEl) staticEl.style.display = m === 'static' ? 'block' : 'none';
        if (pppoeEl)  pppoeEl.style.display  = m === 'pppoe'  ? 'block' : 'none';
    }
    window.wrToggleWanModeFields = wrToggleWanModeFields;

    async function wrSaveWan(id) {
        const name = document.getElementById('wr-w-name').value.trim();
        const iface = document.getElementById('wr-w-iface').value.trim();
        const mode = document.getElementById('wr-w-mode').value;
        const enabled = document.getElementById('wr-w-enabled').checked;
        if (!name || !iface) { alert('Name and interface are required'); return; }
        let modeBlock = { mode: 'dhcp' };
        if (mode === 'static') {
            modeBlock = {
                mode: 'static',
                config: {
                    address_cidr: document.getElementById('wr-w-addr').value.trim(),
                    gateway: document.getElementById('wr-w-gw').value.trim(),
                    dns: document.getElementById('wr-w-dns').value.split(',').map(s => s.trim()).filter(Boolean),
                },
            };
        } else if (mode === 'pppoe') {
            modeBlock = {
                mode: 'pppoe',
                config: {
                    username: document.getElementById('wr-w-user').value.trim(),
                    password: document.getElementById('wr-w-pass').value,
                    service_name: document.getElementById('wr-w-svc').value.trim(),
                    mtu: parseInt(document.getElementById('wr-w-mtu').value, 10) || 1492,
                    mru: parseInt(document.getElementById('wr-w-mtu').value, 10) || 1492,
                    persist: document.getElementById('wr-w-persist').checked,
                    lcp_echo_interval: parseInt(document.getElementById('wr-w-lcp').value, 10) || 0,
                    lcp_echo_failure: 4,
                    use_default_route: document.getElementById('wr-w-pppoe-default-route').checked,
                    use_peer_dns: document.getElementById('wr-w-pppoe-peer-dns').checked,
                },
            };
        }
        const body = {
            id: id || '',
            name, interface: iface, mode: modeBlock, enabled,
            node_id: wrState.topology?.nodes?.[0]?.node_id || '',
            description: '',
        };
        const url = wrUrl(id ? '/api/router/wan/' + id : '/api/router/wan');
        const method = id ? 'PUT' : 'POST';
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!r.ok) { alert('Save failed: ' + await r.text()); return; }
        document.querySelector('.modal-overlay')?.remove();
        await wrLoadAll();
        wrRenderWan();
    }
    window.wrSaveWan = wrSaveWan;

    async function wrDeleteWan(id) {
        if (!confirm('Delete this WAN connection? Any PPPoE link will be torn down.')) return;
        await fetch(wrUrl('/api/router/wan/' + id), { method: 'DELETE' });
        await wrLoadAll();
        wrRenderWan();
    }
    window.wrDeleteWan = wrDeleteWan;
    window.wrRenderWan = wrRenderWan;

    // ─── Policy map — drag-and-drop firewall editor ─────────
    //
    // Renders the current firewall + DNAT state as a directed graph.
    // Nodes: Internet, each Zone, each LAN segment, each VM and
    // container. Edges: one per enabled WolfRouter rule (coloured by
    // action) plus one per IP mapping (DNAT). Drag from a source
    // node to a destination opens the existing rule editor
    // pre-filled. Click an edge to edit or delete it. The whole view
    // auto-populates on load so the user sees "this is what my
    // firewall is doing" before touching anything.

    /// Translate an Endpoint (the serde-tagged enum from the backend)
    /// into a node id on the policy map. Returns null when the
    /// endpoint has no representation (e.g. Any — rendered as an
    /// edge to the Internet node).
    function wrEndpointNodeId(ep) {
        if (!ep) return null;
        switch (ep.kind) {
            case 'any':       return 'internet';
            case 'zone':
                if (!ep.zone) return null;
                if (ep.zone.kind === 'lan') return `zone:lan${ep.zone.id ?? 0}`;
                if (ep.zone.kind === 'custom') return `zone:custom:${ep.zone.id || ''}`;
                return `zone:${ep.zone.kind}`;
            case 'interface': return `iface:${ep.name}`;
            case 'ip':        return `ip:${ep.cidr}`;
            case 'vm':        return `vm:${ep.name}`;
            case 'container': return `ct:${ep.name}`;
            case 'lan':       return `lan:${ep.id}`;
        }
        return null;
    }

    /// Build the full graph {nodes, edges} from the current wrState
    /// snapshot. No fetches — purely derived from data we've already
    /// loaded for the other tabs.
    function wrBuildPolicyGraph() {
        const nodes = new Map();   // id → {id, label, icon, tier, kind, meta}
        const edges = [];
        const addNode = (id, label, icon, tier, kind, meta) => {
            if (!nodes.has(id)) nodes.set(id, { id, label, icon, tier, kind, meta: meta || {} });
        };

        // Tier 0: Internet.
        addNode('internet', 'Internet', '🌐', 0, 'internet');

        // Tier 1: WAN-ish zones (WAN, Management, Trusted).
        addNode('zone:wan',        'WAN',        '📡', 1, 'zone', { zone: { kind: 'wan' } });
        addNode('zone:management', 'Management', '🔧', 1, 'zone', { zone: { kind: 'management' } });
        addNode('zone:trusted',    'Trusted',    '⭐', 1, 'zone', { zone: { kind: 'trusted' } });

        // Tier 2: LAN-ish zones (LAN0, LAN1, DMZ, WolfNet) — only show
        // zones that actually have interfaces assigned, OR the common
        // defaults so users have somewhere to drag to.
        const seenZones = new Set(['wan', 'management', 'trusted']);
        // Scan zone assignments for custom/LAN zone numbers.
        const assigns = wrState.zones?.assignments || {};
        for (const nodeId of Object.keys(assigns)) {
            for (const iface of Object.keys(assigns[nodeId] || {})) {
                const z = assigns[nodeId][iface];
                if (!z) continue;
                if (z.kind === 'lan') seenZones.add(`lan${z.id ?? 0}`);
                else seenZones.add(z.kind);
            }
        }
        // Ensure core zones exist even if nothing's assigned yet.
        for (const needed of ['lan0', 'dmz', 'wolfnet']) seenZones.add(needed);
        for (const slug of seenZones) {
            if (['wan', 'management', 'trusted'].includes(slug)) continue;  // already tier 1
            if (slug.startsWith('lan')) {
                const n = parseInt(slug.slice(3), 10) || 0;
                addNode(`zone:${slug}`, `LAN ${n}`, '🌐', 2, 'zone', { zone: { kind: 'lan', id: n } });
            } else if (slug === 'dmz') {
                addNode('zone:dmz', 'DMZ', '🪖', 2, 'zone', { zone: { kind: 'dmz' } });
            } else if (slug === 'wolfnet') {
                addNode('zone:wolfnet', 'WolfNet', '⛓', 2, 'zone', { zone: { kind: 'wolfnet' } });
            } else {
                addNode(`zone:${slug}`, slug, '🎯', 2, 'zone', { zone: { kind: slug } });
            }
        }

        // Always show the full cluster topology — ports, bridges,
        // VLANs, VMs, containers, all wired together — so the map is
        // a single "at a glance" view of where traffic flows. The
        // node selector becomes an optional filter; by default we
        // draw everything across every cluster node.
        //
        // Ports/bridges/vlans are namespaced by node_id because
        // iface names (eth0, vmbr0, docker0) collide across hosts.
        const selNode = wrPolicyUi.selectedNode || '';
        const lanTier    = 6;
        const deviceTier = 7;

        // LAN segments (served by WolfRouter with DHCP+DNS).
        for (const lan of (wrState.lans || [])) {
            addNode(`lan:${lan.id}`, lan.name, '🏠', lanTier, 'lan', { lan, ip: lan.subnet_cidr });
        }

        // Per-cluster-node topology: ports, vlans, bridges, VMs, CTs.
        for (const n of (wrState.topology?.nodes || [])) {
            if (selNode && n.node_id !== selNode) continue;
            const nodeTag = n.node_name || n.node_id;
            for (const p of (n.interfaces || [])) {
                const ip = (p.addresses && p.addresses[0]) || '';
                const icon = p.link_up ? '🔌' : '⛔';
                addNode(`port:${n.node_id}:${p.name}`, `${nodeTag}·${p.name}`, icon, 3, 'port', {
                    port: p, node: n.node_id, ip,
                });
            }
            for (const v of (n.vlans || [])) {
                const ip = (v.addresses && v.addresses[0]) || '';
                addNode(`vlan:${n.node_id}:${v.name}`, `${nodeTag}·${v.name}`, '🏷', 4, 'vlan', {
                    vlan: v, node: n.node_id, ip: ip || `VLAN ${v.vlan_id}`,
                });
            }
            for (const b of (n.bridges || [])) {
                const ip = (b.addresses && b.addresses[0]) || '';
                addNode(`br:${n.node_id}:${b.name}`, `${nodeTag}·${b.name}`, '🌉', 5, 'bridge', {
                    bridge: b, node: n.node_id, ip,
                });
            }
            for (const vm of (n.vms || [])) {
                addNode(`vm:${vm.name}`, vm.name, '🖥', deviceTier, 'vm', {
                    vm, node: n.node_id, ip: vm.ip || '',
                });
            }
            for (const ct of (n.containers || [])) {
                addNode(`ct:${ct.name}`, ct.name, '📦', deviceTier, 'container', {
                    ct, node: n.node_id, ip: ct.ip || ct.attached_to || '',
                });
            }
        }

        // ── Implicit infrastructure edges ───────────────────────
        // Without these the graph is a bunch of unconnected dots
        // whenever the user has no explicit firewall rules yet. Show
        // the TOPOLOGY as faint grey edges so the mental model is
        // always legible: Internet ↔ WAN ↔ zones ↔ LAN segments ↔
        // devices. These are visual only — no rule behind them,
        // clicking does nothing special.
        const implicitEdge = (from, to, label) => {
            if (!nodes.has(from) || !nodes.has(to)) return;
            edges.push({
                id: `implicit:${from}|${to}`,
                from, to,
                kind: 'implicit',
                action: 'implicit',
                colour: '#64748b',
                enabled: true,
                label: label || '',
            });
        };
        // Internet ↔ WAN (classic uplink).
        implicitEdge('internet', 'zone:wan', 'uplink');
        // Each LAN segment belongs to its zone.
        for (const lan of (wrState.lans || [])) {
            const zId = lan.zone?.kind === 'lan'
                ? `zone:lan${lan.zone.id ?? 0}`
                : `zone:${lan.zone?.kind}`;
            implicitEdge(`lan:${lan.id}`, zId, '');
        }
        // VMs with a WolfNet IP attach to the WolfNet zone. VMs on a
        // passthrough bridge attach to the LAN zone that bridge is in.
        // Physical wiring, per cluster node:
        //   port ─(slave)─→ bridge          (PortState.master)
        //   vlan ─(child)──→ parent port     (VlanState.parent)
        //   port ─────────→ zone             (role/zone, when unbridged)
        //   bridge ──────→ zone              (BridgeState.zone)
        //   vm/ct ───────→ attached bridge   (attached_to)
        for (const n of (wrState.topology?.nodes || [])) {
            if (selNode && n.node_id !== selNode) continue;
            const portId = (name) => `port:${n.node_id}:${name}`;
            const brId   = (name) => `br:${n.node_id}:${name}`;
            const vlanId = (name) => `vlan:${n.node_id}:${name}`;

            for (const p of (n.interfaces || [])) {
                if (p.master && nodes.has(brId(p.master))) {
                    implicitEdge(portId(p.name), brId(p.master), '');
                } else if (p.zone) {
                    const zid = p.zone.kind === 'lan'
                        ? `zone:lan${p.zone.id ?? 0}`
                        : `zone:${p.zone.kind}`;
                    implicitEdge(portId(p.name), zid, p.role || '');
                } else if (p.role && p.role !== 'unused') {
                    const zid = p.role === 'wan' ? 'zone:wan'
                              : p.role === 'management' ? 'zone:management'
                              : p.role === 'wolfnet' ? 'zone:wolfnet'
                              : p.role === 'lan' ? 'zone:lan0'
                              : null;
                    if (zid) implicitEdge(portId(p.name), zid, p.role);
                }
            }
            for (const v of (n.vlans || [])) {
                if (v.parent && nodes.has(portId(v.parent))) {
                    implicitEdge(vlanId(v.name), portId(v.parent), `vlan ${v.vlan_id}`);
                }
            }
            for (const b of (n.bridges || [])) {
                if (b.zone) {
                    const zid = b.zone.kind === 'lan'
                        ? `zone:lan${b.zone.id ?? 0}`
                        : `zone:${b.zone.kind}`;
                    implicitEdge(brId(b.name), zid, '');
                }
            }
            for (const vm of (n.vms || [])) {
                const toBr = vm.attached_to && nodes.has(brId(vm.attached_to))
                    ? brId(vm.attached_to) : null;
                if (toBr) {
                    implicitEdge(`vm:${vm.name}`, toBr, '');
                } else if (vm.attached_to === 'wolfnet' || vm.ip) {
                    implicitEdge(`vm:${vm.name}`, 'zone:wolfnet', '');
                }
            }
            for (const ct of (n.containers || [])) {
                const toBr = ct.attached_to && nodes.has(brId(ct.attached_to))
                    ? brId(ct.attached_to) : null;
                if (toBr) {
                    implicitEdge(`ct:${ct.name}`, toBr, '');
                } else {
                    implicitEdge(`ct:${ct.name}`, 'zone:lan0', '');
                }
            }
        }

        // Edges from firewall rules. An Any source/dest is rendered
        // as an edge to/from Internet (visual shorthand — a rule
        // with from=Any means "anywhere, including the internet").
        const actionColour = {
            allow:  '#22c55e',
            deny:   '#ef4444',
            reject: '#f97316',
            log:    '#60a5fa',
        };
        for (const rule of (wrState.rules || [])) {
            const fromId = wrEndpointNodeId(rule.from);
            const toId   = wrEndpointNodeId(rule.to);
            if (!fromId || !toId) continue;
            // Ensure endpoint-derived nodes exist (e.g. rule references
            // an IP/interface we don't have a node for yet).
            if (!nodes.has(fromId)) {
                addNode(fromId, fromId.split(':').slice(1).join(':') || fromId, '•', 2, 'dynamic');
            }
            if (!nodes.has(toId)) {
                addNode(toId, toId.split(':').slice(1).join(':') || toId, '•', 2, 'dynamic');
            }
            edges.push({
                id: 'rule:' + rule.id,
                from: fromId, to: toId,
                kind: 'rule',
                action: rule.action,
                colour: actionColour[rule.action] || '#94a3b8',
                enabled: rule.enabled !== false,
                label: `${rule.protocol || 'any'}${rule.ports?.length ? ':' + rule.ports.map(p=>p.port).join(',') : ''}`,
                rule,
            });
        }

        // Edges from IP mappings (DNAT): Internet → target WolfNet IP
        // / VM. These are port forwards.
        for (const m of (wrState.managed?.ip_mappings || [])) {
            const toName = (wrState.topology?.nodes || []).flatMap(n => n.vms || [])
                .find(v => v.ip === m.wolfnet_ip)?.name;
            const toId = toName ? `vm:${toName}` : `ip:${m.wolfnet_ip}/32`;
            if (!nodes.has(toId)) addNode(toId, m.wolfnet_ip, '🖥', 4, 'dynamic');
            edges.push({
                id: 'mapping:' + m.id,
                from: 'internet', to: toId,
                kind: 'dnat',
                action: 'dnat',
                colour: '#a855f7',
                enabled: m.enabled !== false,
                label: `${(m.protocol || 'all').toUpperCase()}${m.ports ? ' :' + m.ports : ''}`,
                mapping: m,
            });
        }

        return { nodes: Array.from(nodes.values()), edges };
    }

    /// Hierarchical layout: group nodes by tier, space them evenly
    /// across the canvas width. Returns a map of node id → {x, y}.
    function wrLayoutPolicyGraph(graph, width, height) {
        const layout = new Map();
        const tiers = {};
        for (const n of graph.nodes) {
            if (!tiers[n.tier]) tiers[n.tier] = [];
            tiers[n.tier].push(n);
        }
        const tierKeys = Object.keys(tiers).map(n => parseInt(n, 10)).sort((a, b) => a - b);
        const tierCount = tierKeys.length;
        const rowH = Math.max(110, height / Math.max(tierCount, 1));
        for (let i = 0; i < tierKeys.length; i++) {
            const row = tiers[tierKeys[i]];
            const y = rowH * (i + 0.5);
            const spacing = width / (row.length + 1);
            row.forEach((n, idx) => {
                layout.set(n.id, { x: spacing * (idx + 1), y, node: n });
            });
        }
        return layout;
    }

    /// Per-view UI state for the policy map. Survives across renders
    /// so filters / traced-node / sim path don't reset on topology
    /// refresh.
    let wrPolicyUi = {
        filters: { allow: true, deny: true, reject: true, log: true, dnat: true, disabled: false },
        search: '',
        selectedNode: '',   // cluster node_id to limit VMs/containers to (empty = all)
        tracedNode: null,   // node id currently in "trace mode" (null = off)
        simPath: null,      // { edgeIds: [...], verdict: 'allow' | 'deny' | ... }
        zoom: 1,            // 1.0 = fit to window; <1 zooms out; >1 zooms in
    };

    /// Traffic rates per node id (in bps rx + tx). Computed once per
    /// render from topology.nodes[].interfaces[].{rx_bps,tx_bps}
    /// joined with the per-node zone assignments so we can total up
    /// "how much traffic is flowing across WAN right now" etc.
    function wrComputeNodeTraffic(fullGraph) {
        const bps = new Map();  // node-id → { rx, tx, speedMbps }
        const topo = wrState.topology;
        if (!topo) return bps;

        // Iterate every cluster node's interfaces and bucket the
        // traffic by which policy-map node each iface rolls up into.
        for (const node of (topo.nodes || [])) {
            const asg = wrState.zones?.assignments?.[node.node_id] || {};
            for (const iface of (node.interfaces || [])) {
                const rx = iface.rx_bps || 0, tx = iface.tx_bps || 0;
                const sp = iface.speed_mbps || 0;
                const addTo = (id) => {
                    const cur = bps.get(id) || { rx: 0, tx: 0, speedMbps: 0 };
                    cur.rx += rx; cur.tx += tx;
                    cur.speedMbps = Math.max(cur.speedMbps, sp);
                    bps.set(id, cur);
                };
                // Per-port bucket — makes the port node in the policy
                // map show its own BPS tag and heats up the edges it
                // sits on, so bottlenecks are obvious.
                addTo(`port:${node.node_id}:${iface.name}`);
                // Always add to the role-derived zone if assigned.
                const assigned = asg[iface.name];
                if (assigned) {
                    const zid = assigned.kind === 'lan'
                        ? `zone:lan${assigned.id ?? 0}`
                        : `zone:${assigned.kind}`;
                    addTo(zid);
                } else if (iface.role) {
                    const zid = iface.role === 'wan' ? 'zone:wan'
                              : iface.role === 'management' ? 'zone:management'
                              : iface.role === 'lan' ? 'zone:lan0'
                              : iface.role === 'wolfnet' ? 'zone:wolfnet'
                              : null;
                    if (zid) addTo(zid);
                }
                // WAN role also counts toward Internet.
                if (iface.role === 'wan') addTo('internet');
            }
        }
        return bps;
    }

    /// Format bps into a short humanised string. Used on edge labels
    /// and the summary bar so operators can read them at a glance.
    function wrFmtBps(bps) {
        if (!bps || bps < 1) return '—';
        if (bps < 1024) return bps.toFixed(0) + ' bps';
        if (bps < 1024*1024) return (bps/1024).toFixed(1) + ' Kbps';
        if (bps < 1024*1024*1024) return (bps/1048576).toFixed(1) + ' Mbps';
        return (bps/1073741824).toFixed(2) + ' Gbps';
    }

    /// Pick a heat colour for a link given its utilisation as a
    /// fraction of link speed. Used to tint edges so a saturated
    /// link goes red on the policy map.
    function wrHeatColour(utilFrac) {
        if (utilFrac >= 0.70) return '#ef4444';  // red
        if (utilFrac >= 0.30) return '#fbbf24';  // amber
        return null;  // no override — use the rule's action colour
    }

    /// Walk every node in the graph and flag it with a warning level
    /// when something's wrong:
    ///   danger  — down links, crash-looping containers, orphan VMs
    ///   warn    — unassigned ports, ports with no zone, link saturated
    /// Returns Map<nodeId, { level, reasons }>. The render loop uses
    /// this to paint a red/amber glow + tooltip so problems jump out.
    function wrComputeNodeWarnings(fullGraph) {
        const out = new Map();
        const add = (id, level, reason) => {
            const cur = out.get(id) || { level: 'warn', reasons: [] };
            // Promote to danger if any reason is danger-level.
            if (level === 'danger') cur.level = 'danger';
            cur.reasons.push(reason);
            out.set(id, cur);
        };
        // Port-level checks from topology.
        for (const n of (wrState.topology?.nodes || [])) {
            for (const p of (n.interfaces || [])) {
                const pid = `port:${n.node_id}:${p.name}`;
                if (!fullGraph.nodes.some(x => x.id === pid)) continue;
                if (p.link_up === false) {
                    // WAN down is catastrophic; any other port down is
                    // merely a warning (could be a spare).
                    const isWan = p.role === 'wan';
                    add(pid, isWan ? 'danger' : 'warn',
                        isWan ? 'WAN link is down' : 'link down');
                }
                const hasAddr = (p.addresses && p.addresses.length) ||
                                (p.master); // slave port inherits from bridge
                if (p.role && p.role !== 'unused' && !hasAddr) {
                    add(pid, 'warn', `role=${p.role} but no IP configured`);
                }
            }
            for (const vm of (n.vms || [])) {
                const vid = `vm:${vm.name}`;
                if (!fullGraph.nodes.some(x => x.id === vid)) continue;
                if (!vm.ip && !vm.attached_to) {
                    add(vid, 'warn', 'VM has no network attachment');
                }
            }
            for (const ct of (n.containers || [])) {
                const cid = `ct:${ct.name}`;
                if (!fullGraph.nodes.some(x => x.id === cid)) continue;
                if (!ct.ip && !ct.attached_to) {
                    add(cid, 'warn', 'container has no network attachment');
                }
                // Restart-loop / stopped-but-should-be-running signals
                // come from the `state` field on the topology-supplied
                // container record (present for docker).
                if (ct.state === 'restarting') {
                    add(cid, 'danger', 'container is restart-looping');
                } else if (ct.state === 'exited' || ct.state === 'dead') {
                    add(cid, 'warn', `container is ${ct.state}`);
                }
            }
        }
        // LAN segments without a DHCP range — boots-from-zero install
        // would give zero leases. Easy mistake, easy to flag.
        for (const lan of (wrState.lans || [])) {
            if (lan.dhcp && lan.dhcp.enabled) {
                if (!lan.dhcp.range_start || !lan.dhcp.range_end) {
                    add(`lan:${lan.id}`, 'warn', 'DHCP enabled but range is empty');
                }
            }
        }
        // Zones referenced by rules but with no interface assignment
        // in this cluster — rules can't fire if nothing's in the zone.
        const assignedZones = new Set();
        const asgAll = wrState.zones?.assignments || {};
        for (const nodeId of Object.keys(asgAll)) {
            for (const iface of Object.keys(asgAll[nodeId] || {})) {
                const z = asgAll[nodeId][iface];
                if (!z) continue;
                assignedZones.add(z.kind === 'lan' ? `zone:lan${z.id ?? 0}` : `zone:${z.kind}`);
            }
        }
        for (const zn of fullGraph.nodes.filter(n => n.kind === 'zone')) {
            if (zn.id === 'zone:wan' || zn.id === 'zone:management' || zn.id === 'zone:trusted') {
                // WAN/Mgmt/Trusted: no assignment is fine if no rules
                // reference them — only warn if the zone's in a rule.
                const referenced = (wrState.rules || []).some(r =>
                    wrEndpointNodeId(r.from) === zn.id || wrEndpointNodeId(r.to) === zn.id);
                if (referenced && !assignedZones.has(zn.id)) {
                    add(zn.id, 'warn', 'rules reference this zone but no interface is assigned to it');
                }
            }
        }
        return out;
    }

    /// Render the canvas from scratch. Safe to call on every poll —
    /// cheap because graphs stay small (dozens of nodes, not
    /// thousands).
    function wrRenderPolicyMap() {
        const host = document.getElementById('wr-policy-canvas');
        if (!host) return;
        const fullGraph = wrBuildPolicyGraph();
        if (!fullGraph.nodes.length) {
            host.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding:60px;">No data yet.</div>';
            return;
        }

        // Apply filters: action-type toggles + node-name search.
        // Edges are filtered by their action; nodes are filtered by
        // text match, but we keep every node that's still referenced
        // by a visible edge so the graph stays connected.
        const f = wrPolicyUi.filters;
        const searchText = (wrPolicyUi.search || '').toLowerCase().trim();
        const edgeVisible = (e) => {
            if (!e.enabled && !f.disabled) return false;
            if (e.kind === 'dnat') return f.dnat;
            return f[e.action] !== false;
        };
        const edges = fullGraph.edges.filter(edgeVisible);
        let nodes = fullGraph.nodes;
        if (searchText) {
            const hit = new Set(nodes.filter(n => n.label.toLowerCase().includes(searchText)).map(n => n.id));
            // Include the other end of any edge touching a matching node.
            for (const e of edges) {
                if (hit.has(e.from)) hit.add(e.to);
                if (hit.has(e.to))   hit.add(e.from);
            }
            nodes = nodes.filter(n => hit.has(n.id));
        }
        const graph = { nodes, edges };

        // Group edges by unordered-pair for fan-out rendering — many
        // rules between the same pair used to stack on one path.
        const bundleKey = (from, to) => [from, to].sort().join(' | ');
        const bundles = new Map();
        for (const e of edges) {
            const k = bundleKey(e.from, e.to);
            if (!bundles.has(k)) bundles.set(k, []);
            bundles.get(k).push(e);
        }

        // Per-node throughput map — used by the edge renderer to
        // show live BPS and colour saturated links red.
        const nodeBps = wrComputeNodeTraffic(fullGraph);

        // Render the per-cluster-node throughput strip. Each cluster
        // node gets one badge: hostname + rx/tx summed across its
        // interfaces. Drops immediately show up as tiny bars.
        const nodeBwStrip = document.getElementById('wr-policy-node-bw');
        if (nodeBwStrip) {
            const cluster = wrState.topology?.nodes || [];
            if (!cluster.length) {
                nodeBwStrip.innerHTML = '';
            } else {
                // Find the max aggregate across cluster nodes so we
                // can scale the little inline bar consistently.
                const aggregates = cluster.map(n => {
                    let rx = 0, tx = 0, speedMbps = 0;
                    for (const i of (n.interfaces || [])) {
                        rx += i.rx_bps || 0; tx += i.tx_bps || 0;
                        speedMbps = Math.max(speedMbps, i.speed_mbps || 0);
                    }
                    return { name: n.node_name, rx, tx, speedMbps };
                });
                const maxRx = Math.max(1, ...aggregates.map(a => a.rx));
                const maxTx = Math.max(1, ...aggregates.map(a => a.tx));
                nodeBwStrip.innerHTML = `<span style="color:var(--text);">📊 Cluster throughput:</span> ` +
                    aggregates.map(a => {
                        const rxPct = (a.rx / maxRx) * 100;
                        const txPct = (a.tx / maxTx) * 100;
                        const linkBps = (a.speedMbps || 1000) * 1e6;
                        const util = (a.rx + a.tx) / linkBps;
                        const colour = util >= 0.7 ? '#ef4444' : util >= 0.3 ? '#fbbf24' : '#22c55e';
                        return `<span style="display:inline-flex; align-items:center; gap:4px; padding:3px 8px; background:var(--bg-card); border:1px solid var(--border); border-radius:4px;">
                            <span style="font-weight:600; color:var(--text);">${escHtml(a.name)}</span>
                            <span style="color:${colour};">⬇${wrFmtBps(a.rx)}</span>
                            <span style="color:${colour};">⬆${wrFmtBps(a.tx)}</span>
                            <span style="display:inline-block; width:40px; height:4px; background:var(--bg-secondary); border-radius:2px; position:relative;">
                                <span style="position:absolute; left:0; top:0; height:100%; width:${Math.min(100, rxPct)}%; background:${colour}; border-radius:2px;"></span>
                            </span>
                        </span>`;
                    }).join('');
            }
        }

        const wrap = document.getElementById('wr-policy-canvas-wrap');
        const wrapW = wrap?.clientWidth || 1000;
        // Canvas grows to fit the widest row (210px per node) so ports
        // on a big cluster don't end up a crammed ribbon across the
        // middle; wrap has overflow:auto so users pan horizontally.
        // Vertical space is a generous 190px per tier.
        const tierCounts = {};
        for (const n of graph.nodes) {
            tierCounts[n.tier] = (tierCounts[n.tier] || 0) + 1;
        }
        const maxRow = Math.max(1, ...Object.values(tierCounts));
        const tierCount = Object.keys(tierCounts).length || 1;
        const baseW = Math.max(wrapW, maxRow * 210);
        const baseH = Math.max(680, tierCount * 190);
        const layout = wrLayoutPolicyGraph(graph, baseW - 60, baseH);

        const zoom = Math.max(0.3, Math.min(2.5, wrPolicyUi.zoom || 1));
        const W = baseW * zoom, H = baseH * zoom;
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('width', W);
        svg.setAttribute('height', H);
        svg.setAttribute('viewBox', `0 0 ${baseW} ${baseH}`);
        svg.setAttribute('xmlns', ns);
        svg.style.display = 'block';

        svg.insertAdjacentHTML('afterbegin', `
            <defs>
                <marker id="wr-policy-arrow" viewBox="0 -5 10 10" refX="10" refY="0" markerWidth="6" markerHeight="6" orient="auto">
                    <path d="M0,-5L10,0L0,5" fill="currentColor"/>
                </marker>
                <filter id="wr-policy-glow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="3" result="b"/>
                    <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <filter id="wr-policy-warn-glow" x="-80%" y="-80%" width="260%" height="260%">
                    <feGaussianBlur stdDeviation="5" result="b"/>
                    <feFlood flood-color="#ef4444" flood-opacity="0.9" result="c"/>
                    <feComposite in="c" in2="b" operator="in" result="cb"/>
                    <feMerge><feMergeNode in="cb"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <filter id="wr-policy-amber-glow" x="-80%" y="-80%" width="260%" height="260%">
                    <feGaussianBlur stdDeviation="4" result="b"/>
                    <feFlood flood-color="#fbbf24" flood-opacity="0.85" result="c"/>
                    <feComposite in="c" in2="b" operator="in" result="cb"/>
                    <feMerge><feMergeNode in="cb"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
                <radialGradient id="wr-sim-packet">
                    <stop offset="0" stop-color="#fde68a"/>
                    <stop offset="0.5" stop-color="#f59e0b"/>
                    <stop offset="1" stop-color="#92400e" stop-opacity="0"/>
                </radialGradient>
            </defs>
        `);

        // Compute which nodes + edges are "live" for the trace/sim
        // highlight, so we can dim the rest.
        const tracedEdgeIds = new Set();
        const tracedNodeIds = new Set();
        if (wrPolicyUi.tracedNode) {
            tracedNodeIds.add(wrPolicyUi.tracedNode);
            for (const e of edges) {
                if (e.from === wrPolicyUi.tracedNode || e.to === wrPolicyUi.tracedNode) {
                    tracedEdgeIds.add(e.id);
                    tracedNodeIds.add(e.from);
                    tracedNodeIds.add(e.to);
                }
            }
        }
        if (wrPolicyUi.simPath) {
            for (const id of wrPolicyUi.simPath.edgeIds) tracedEdgeIds.add(id);
        }
        const dimMode = wrPolicyUi.tracedNode != null;

        // Edges with fan-out offsets so parallel rules don't stack.
        // Edges tinted by utilisation when both endpoints have a BPS
        // reading — saturated links go red so bottlenecks jump out.
        for (const [, bundle] of bundles) {
            const n = bundle.length;
            bundle.forEach((e, idx) => {
                const a = layout.get(e.from), b = layout.get(e.to);
                if (!a || !b) return;
                const t = n === 1 ? 0 : (idx - (n - 1) / 2);
                const spread = 28;
                const dx = b.x - a.x, dy = b.y - a.y;
                const len = Math.hypot(dx, dy) || 1;
                const nx = -dy / len, ny = dx / len;
                const cx = (a.x + b.x) / 2 + nx * t * spread;
                const cy = (a.y + b.y) / 2 + ny * t * spread;
                const path = `M ${a.x},${a.y} Q ${cx},${cy} ${b.x},${b.y}`;
                const dim = dimMode && !tracedEdgeIds.has(e.id);
                const opacity = (e.enabled ? 0.85 : 0.35) * (dim ? 0.18 : 1);

                // Bottleneck analysis: the edge's effective throughput
                // is the minimum of the traffic measured at the two
                // endpoints that ACTUALLY have a measurement. An edge
                // from "zone that's measured" to "VM that isn't" uses
                // the measured side straight — don't silently zero it
                // out with Math.min(measured, 0).
                const fromBps = nodeBps.get(e.from);
                const toBps   = nodeBps.get(e.to);
                let edgeRx = 0, edgeTx = 0, edgeSpeedMbps = 0, util = 0;
                if (fromBps && toBps) {
                    edgeRx = Math.min(fromBps.rx, toBps.rx);
                    edgeTx = Math.min(fromBps.tx, toBps.tx);
                    const speeds = [fromBps.speedMbps, toBps.speedMbps].filter(Boolean);
                    edgeSpeedMbps = speeds.length ? Math.min(...speeds) : 1000;
                    const avgTotal = ((fromBps.rx + fromBps.tx) + (toBps.rx + toBps.tx)) / 2;
                    util = avgTotal / Math.max(1, edgeSpeedMbps * 1e6);
                } else if (fromBps) {
                    edgeRx = fromBps.rx; edgeTx = fromBps.tx;
                    edgeSpeedMbps = fromBps.speedMbps || 1000;
                    util = (fromBps.rx + fromBps.tx) / Math.max(1, edgeSpeedMbps * 1e6);
                } else if (toBps) {
                    edgeRx = toBps.rx; edgeTx = toBps.tx;
                    edgeSpeedMbps = toBps.speedMbps || 1000;
                    util = (toBps.rx + toBps.tx) / Math.max(1, edgeSpeedMbps * 1e6);
                }
                const heat = wrHeatColour(util);
                const strokeColour = heat || e.colour;
                // Scale stroke width by traffic so a fat cable = busy.
                const bpsTotal = edgeRx + edgeTx;
                const trafficBoost = bpsTotal > 0
                    ? Math.min(4, Math.log10(Math.max(1, bpsTotal / 1000)))
                    : 0;
                const baseW = e.enabled ? 2.5 : 1.5;
                const isTraced = tracedEdgeIds.has(e.id);
                const strokeW = baseW + trafficBoost + (isTraced ? 1.5 : 0);
                const bpsLabel = bpsTotal > 0
                    ? ` · ${wrFmtBps(bpsTotal)}${util >= 0.7 ? ' 🔥' : ''}`
                    : '';
                svg.insertAdjacentHTML('beforeend', `
                    <g class="wr-policy-edge" data-edge="${escHtml(e.id)}" style="cursor:pointer; color:${strokeColour};">
                        <path d="${path}" fill="none" stroke="${strokeColour}"
                              stroke-width="${strokeW.toFixed(2)}"
                              opacity="${opacity}"
                              stroke-dasharray="${e.enabled ? (bpsTotal > 0 ? '10 6' : 'none') : '4 3'}"
                              marker-end="url(#wr-policy-arrow)"
                              ${bpsTotal > 0 ? 'class="wr-wire-active"' : ''}
                              ${isTraced ? 'filter="url(#wr-policy-glow)"' : ''}/>
                        <path d="${path}" fill="none" stroke="transparent" stroke-width="14"/>
                        <text x="${cx}" y="${cy - 6}" text-anchor="middle"
                              style="fill:${strokeColour}; font-size:10px; font-family:var(--font-mono,monospace); pointer-events:none; opacity:${opacity};">${escHtml(e.label || '')}${escHtml(bpsLabel)}</text>
                    </g>
                `);
            });
        }

        // Nodes on top. Dim when trace mode is active and we're not
        // on the traced graph. Nodes with a meta.ip get a taller rect
        // so we can show the IP/subnet on a second line. Nodes that
        // fail a health check get a red or amber glow + tooltip so
        // problems are spottable at a glance.
        const warnings = wrComputeNodeWarnings(fullGraph);
        const nodeW = 160, nodeH = 38, nodeHip = 56;
        for (const n of graph.nodes) {
            const p = layout.get(n.id);
            if (!p) continue;
            const ipText = (n.meta && n.meta.ip) ? String(n.meta.ip) : '';
            const h = ipText ? nodeHip : nodeH;
            const x = p.x - nodeW/2, y = p.y - h/2;
            const warn = warnings.get(n.id);
            const fill = {
                internet: 'rgba(96,165,250,0.18)', zone: 'rgba(168,85,247,0.18)',
                lan: 'rgba(34,197,94,0.15)', vm: 'rgba(59,130,246,0.12)',
                container:'rgba(168,85,247,0.12)',
                port: 'rgba(250,204,21,0.14)', bridge: 'rgba(45,212,191,0.14)',
                vlan: 'rgba(244,114,182,0.14)',
            }[n.kind] || 'rgba(148,163,184,0.12)';
            const stroke = {
                internet: '#60a5fa', zone: '#a855f7', lan: '#22c55e',
                vm: '#60a5fa', container:'#a855f7',
                port: '#facc15', bridge: '#2dd4bf', vlan: '#f472b6',
            }[n.kind] || '#94a3b8';
            const dim = dimMode && !tracedNodeIds.has(n.id);
            const opacity = dim ? 0.25 : 1;
            const isTraced = tracedNodeIds.has(n.id);
            // Per-node traffic readout — tiny BPS tag above the rect
            // so users can see which hubs (WAN, WolfNet, a busy zone)
            // are pushing the most bytes. Only shown when > 0.
            const nbps = nodeBps.get(n.id);
            const nodeTotalBps = nbps ? (nbps.rx + nbps.tx) : 0;
            const nodeUtil = nbps && nbps.speedMbps
                ? nodeTotalBps / (nbps.speedMbps * 1e6) : 0;
            const bpsTagColour = nodeUtil >= 0.7 ? '#ef4444'
                : nodeUtil >= 0.3 ? '#fbbf24'
                : '#4ade80';
            const bpsTag = nodeTotalBps > 0
                ? `<text x="${p.x}" y="${y-6}" text-anchor="middle"
                        style="fill:${bpsTagColour}; font-size:10px; font-family:var(--font-mono,monospace); pointer-events:none;">${escHtml(wrFmtBps(nodeTotalBps))}</text>`
                : '';
            const labelY = ipText ? (p.y - 4) : (p.y + 4);
            const ipLine = ipText
                ? `<text x="${p.x}" y="${p.y+12}" text-anchor="middle"
                        style="fill:var(--text-muted); font-size:10px; font-family:var(--font-mono,monospace); pointer-events:none;">${escHtml(ipText.slice(0,22))}</text>`
                : '';
            // Warning glow: down-ports/unconfigured things glow red,
            // things that are merely "needs attention" glow amber.
            // Trace highlight wins over warning so the traced path is
            // never obscured.
            const warnFilter = isTraced ? 'url(#wr-policy-glow)'
                             : warn?.level === 'danger' ? 'url(#wr-policy-warn-glow)'
                             : warn?.level === 'warn'   ? 'url(#wr-policy-amber-glow)'
                             : '';
            const warnStroke = warn?.level === 'danger' ? '#ef4444'
                             : warn?.level === 'warn'   ? '#fbbf24'
                             : stroke;
            const warnStrokeW = warn ? 2.5 : (isTraced ? 2.5 : 1.5);
            const tooltip = warn ? `<title>${escHtml(n.label)}\n⚠ ${escHtml(warn.reasons.join('\n⚠ '))}</title>` : '';
            svg.insertAdjacentHTML('beforeend', `
                <g class="wr-policy-node" data-node="${escHtml(n.id)}" style="cursor:crosshair; opacity:${opacity};">
                    ${tooltip}
                    <rect x="${x}" y="${y}" width="${nodeW}" height="${h}" rx="8"
                          fill="${fill}" stroke="${warnStroke}" stroke-width="${warnStrokeW}"
                          ${warnFilter ? `filter="${warnFilter}"` : ''}/>
                    <text x="${p.x}" y="${labelY}" text-anchor="middle"
                          style="fill:var(--text); font-size:12px; font-weight:600; pointer-events:none;">${escHtml(n.icon)} ${escHtml(n.label.slice(0,18))}</text>
                    ${ipLine}
                    ${bpsTag}
                    ${warn ? `<text x="${x + nodeW - 8}" y="${y + 14}" text-anchor="end" style="fill:${warn.level === 'danger' ? '#ef4444' : '#fbbf24'}; font-size:14px; pointer-events:none;">⚠</text>` : ''}
                </g>
            `);
        }

        // Live drag + drop-target highlight rings. Hidden until
        // mousedown picks a source node.
        svg.insertAdjacentHTML('beforeend', `
            <g id="wr-drag-layer" style="pointer-events:none;">
                <path id="wr-policy-drag-ghost" d="" fill="none" stroke="#fbbf24" stroke-width="3" stroke-dasharray="6 4" opacity="0.8" style="display:none;" marker-end="url(#wr-policy-arrow)"/>
                <circle id="wr-drag-source-ring" r="32" fill="none" stroke="#fbbf24" stroke-width="3" style="display:none;" filter="url(#wr-policy-glow)"/>
                <circle id="wr-drag-target-ring" r="32" fill="none" stroke="#22c55e" stroke-width="3" style="display:none;" filter="url(#wr-policy-glow)"/>
            </g>
        `);

        // Simulator: animated packet glow that travels along the
        // highlighted path. Rendered only when a sim path is set.
        if (wrPolicyUi.simPath?.edgeIds?.length) {
            const firstEdge = edges.find(e => e.id === wrPolicyUi.simPath.edgeIds[0]);
            if (firstEdge) {
                const a = layout.get(firstEdge.from), b = layout.get(firstEdge.to);
                if (a && b) {
                    svg.insertAdjacentHTML('beforeend', `
                        <circle r="12" fill="url(#wr-sim-packet)">
                            <animateMotion dur="1.2s" repeatCount="indefinite"
                                path="M ${a.x},${a.y} L ${b.x},${b.y}"/>
                        </circle>
                    `);
                }
            }
        }

        host.innerHTML = '';
        host.appendChild(svg);

        // Legend.
        const legend = document.getElementById('wr-policy-legend');
        if (legend) {
            const sw = (c, l) => `<div style="display:flex; align-items:center; gap:4px;"><span style="display:inline-block; width:14px; height:3px; background:${c}; border-radius:2px;"></span>${l}</div>`;
            legend.innerHTML = [
                sw('#22c55e', 'allow'), sw('#ef4444', 'deny'), sw('#f97316', 'reject'),
                sw('#60a5fa', 'log'),   sw('#a855f7', 'DNAT'),
                `<span style="color:var(--text-muted);">· drag between nodes to add a rule · click a node to trace · click a line to edit</span>`,
            ].join('');
        }

        wrWirePolicyInteractions(svg, graph, layout, nodeW, nodeH, fullGraph);
        wrWirePolicyFilters();
        wrWirePolicySimulator(fullGraph);
    }

    /// Drag-to-create + click-to-edit + click-to-trace handlers.
    /// Drag distance threshold separates "click" (trace a node / edit
    /// an edge) from "drag" (create a rule) so simple clicks don't
    /// accidentally open the rule editor.
    function wrWirePolicyInteractions(svg, graph, layout, nodeW, nodeH, fullGraph) {
        let dragFrom = null;
        let dragStart = null;
        let dragMoved = false;
        const CLICK_THRESHOLD = 6;  // px — anything less than this is a click
        const ghost = svg.querySelector('#wr-policy-drag-ghost');
        const sourceRing = svg.querySelector('#wr-drag-source-ring');
        const targetRing = svg.querySelector('#wr-drag-target-ring');

        const getMousePos = (evt) => {
            const rect = svg.getBoundingClientRect();
            return {
                x: (evt.clientX - rect.left) * (svg.viewBox.baseVal.width / rect.width),
                y: (evt.clientY - rect.top)  * (svg.viewBox.baseVal.height / rect.height),
            };
        };

        svg.addEventListener('mousedown', (evt) => {
            const nodeEl = evt.target.closest('[data-node]');
            if (!nodeEl) return;
            dragFrom = nodeEl.dataset.node;
            const p = layout.get(dragFrom);
            if (!p) return;
            dragStart = { x: p.x, y: p.y };
            dragMoved = false;
            // Source ring: always visible on mousedown. Becomes the
            // "you're dragging FROM here" hint.
            sourceRing.setAttribute('cx', p.x);
            sourceRing.setAttribute('cy', p.y);
            sourceRing.style.display = 'block';
            ghost.setAttribute('d', `M ${p.x},${p.y} L ${p.x},${p.y}`);
            evt.preventDefault();
        });

        svg.addEventListener('mousemove', (evt) => {
            if (!dragFrom) return;
            const m = getMousePos(evt);
            const dx = m.x - dragStart.x, dy = m.y - dragStart.y;
            if (Math.hypot(dx, dy) > CLICK_THRESHOLD) {
                dragMoved = true;
                ghost.style.display = 'block';
            }
            ghost.setAttribute('d', `M ${dragStart.x},${dragStart.y} L ${m.x},${m.y}`);
            // Drop-target ring: highlight any node we're hovering
            // that isn't the source itself.
            const overEl = evt.target.closest('[data-node]');
            const overId = overEl?.dataset?.node;
            if (overId && overId !== dragFrom) {
                const q = layout.get(overId);
                if (q) {
                    targetRing.setAttribute('cx', q.x);
                    targetRing.setAttribute('cy', q.y);
                    targetRing.style.display = 'block';
                    return;
                }
            }
            targetRing.style.display = 'none';
        });

        const clearDrag = () => {
            ghost.style.display = 'none';
            ghost.setAttribute('d', '');
            sourceRing.style.display = 'none';
            targetRing.style.display = 'none';
            dragFrom = null; dragStart = null; dragMoved = false;
        };

        svg.addEventListener('mouseup', (evt) => {
            if (!dragFrom) return;
            const fromId = dragFrom;
            const wasClick = !dragMoved;
            const targetEl = evt.target.closest('[data-node]');
            const toId = targetEl?.dataset?.node;
            clearDrag();

            if (wasClick) {
                // Click — enter trace mode for this node.
                wrPolicyUi.tracedNode = (wrPolicyUi.tracedNode === fromId) ? null : fromId;
                wrPolicyUi.simPath = null;
                const clearTraceBtn = document.getElementById('wr-policy-clear-trace');
                if (clearTraceBtn) {
                    clearTraceBtn.style.display = wrPolicyUi.tracedNode ? 'inline-block' : 'none';
                }
                wrRenderPolicyMap();
                return;
            }
            // Drag complete.
            if (!toId || toId === fromId) return;
            const fromEp = wrNodeIdToEndpoint(fromId, fullGraph);
            const toEp   = wrNodeIdToEndpoint(toId,   fullGraph);
            if (!fromEp || !toEp) {
                alert('One of those nodes isn\'t addressable as a firewall endpoint yet — try a zone or a named VM/container.');
                return;
            }
            wrShowRuleEditorPrefilled({
                action: 'allow', direction: 'forward',
                from: fromEp, to: toEp,
                protocol: 'any', ports: [], state_track: true,
                log_match: false,
                comment: `drag-created: ${fromId} → ${toId}`,
                enabled: true,
            });
        });
        svg.addEventListener('mouseleave', () => { if (dragFrom) clearDrag(); });

        // Click on an edge opens the edit popover.
        svg.querySelectorAll('[data-edge]').forEach(el => {
            el.addEventListener('click', (evt) => {
                const edgeId = el.dataset.edge;
                const edge = graph.edges.find(e => e.id === edgeId);
                if (!edge) return;
                wrShowEdgePopover(edge, evt.clientX, evt.clientY);
                evt.stopPropagation();
            });
        });

        // Clear-trace button — visible only while a trace is active.
        const clearBtn = document.getElementById('wr-policy-clear-trace');
        if (clearBtn) {
            clearBtn.onclick = () => {
                wrPolicyUi.tracedNode = null;
                wrPolicyUi.simPath = null;
                clearBtn.style.display = 'none';
                wrRenderPolicyMap();
            };
        }
    }

    /// Wire the filter toolbar checkboxes + search input once per
    /// render. Re-renders the canvas on every change.
    function wrWirePolicyFilters() {
        document.querySelectorAll('[data-wr-filter]').forEach(cb => {
            cb.onchange = () => {
                wrPolicyUi.filters[cb.dataset.wrFilter] = cb.checked;
                wrRenderPolicyMap();
            };
            // Re-sync DOM state with stored UI state (after a full re-render).
            cb.checked = !!wrPolicyUi.filters[cb.dataset.wrFilter];
        });
        const searchEl = document.getElementById('wr-policy-search');
        if (searchEl) {
            searchEl.value = wrPolicyUi.search;
            searchEl.oninput = () => {
                wrPolicyUi.search = searchEl.value;
                wrRenderPolicyMap();
            };
        }
        // Zoom controls — buttons + ctrl-scroll on the canvas.
        const zIn  = document.getElementById('wr-policy-zoom-in');
        const zOut = document.getElementById('wr-policy-zoom-out');
        const zFit = document.getElementById('wr-policy-zoom-fit');
        const zPct = document.getElementById('wr-policy-zoom-pct');
        const setZoom = (z) => {
            wrPolicyUi.zoom = Math.max(0.3, Math.min(2.5, z));
            wrRenderPolicyMap();
        };
        if (zPct) zPct.textContent = Math.round((wrPolicyUi.zoom || 1) * 100) + '%';
        if (zIn)  zIn.onclick  = () => setZoom((wrPolicyUi.zoom || 1) * 1.25);
        if (zOut) zOut.onclick = () => setZoom((wrPolicyUi.zoom || 1) / 1.25);
        if (zFit) zFit.onclick = () => setZoom(1);
        const wrap = document.getElementById('wr-policy-canvas-wrap');
        if (wrap && !wrap._wrZoomWired) {
            wrap.addEventListener('wheel', (evt) => {
                if (!evt.ctrlKey && !evt.metaKey) return;
                evt.preventDefault();
                const factor = evt.deltaY < 0 ? 1.1 : 1/1.1;
                setZoom((wrPolicyUi.zoom || 1) * factor);
            }, { passive: false });
            wrap._wrZoomWired = true;
        }

        // Cluster-node selector — populates from topology on every
        // render so newly-joined nodes show up without a page reload.
        const nodeSel = document.getElementById('wr-policy-node-select');
        if (nodeSel) {
            const clusterNodes = wrState.topology?.nodes || [];
            const prev = wrPolicyUi.selectedNode || '';
            nodeSel.innerHTML = '<option value="">All cluster nodes</option>' +
                clusterNodes.map(n =>
                    `<option value="${escHtml(n.node_id)}">${escHtml(n.node_name || n.node_id)}</option>`
                ).join('');
            // Preserve selection across re-renders if the node still exists.
            if (prev && clusterNodes.some(n => n.node_id === prev)) {
                nodeSel.value = prev;
            } else if (prev) {
                wrPolicyUi.selectedNode = '';
            }
            nodeSel.onchange = () => {
                wrPolicyUi.selectedNode = nodeSel.value;
                wrRenderPolicyMap();
            };
        }
    }

    /// Wire the traffic simulator toolbar. Populates the src/dst
    /// dropdowns with every node on the graph, then evaluates the
    /// proposed packet against the rule list in order and shows the
    /// verdict + which rule matched. Animates a packet along the
    /// matched edge.
    function wrWirePolicySimulator(fullGraph) {
        const fromSel = document.getElementById('wr-sim-from');
        const toSel = document.getElementById('wr-sim-to');
        const protoSel = document.getElementById('wr-sim-proto');
        const portIn = document.getElementById('wr-sim-port');
        const goBtn = document.getElementById('wr-sim-go');
        const result = document.getElementById('wr-sim-result');
        if (!fromSel || !toSel || !goBtn || !result) return;

        const opts = fullGraph.nodes.map(n =>
            `<option value="${escHtml(n.id)}">${escHtml(n.icon)} ${escHtml(n.label)}</option>`
        ).join('');
        const prevFrom = fromSel.value;
        const prevTo = toSel.value;
        fromSel.innerHTML = opts;
        toSel.innerHTML = opts;
        if (prevFrom && fullGraph.nodes.some(n => n.id === prevFrom)) fromSel.value = prevFrom;
        if (prevTo && fullGraph.nodes.some(n => n.id === prevTo)) toSel.value = prevTo;

        goBtn.onclick = () => {
            const fromEp = wrNodeIdToEndpoint(fromSel.value, fullGraph);
            const toEp   = wrNodeIdToEndpoint(toSel.value,   fullGraph);
            if (!fromEp || !toEp) {
                result.innerHTML = '<span style="color:#ef4444;">✗ src or dst can\'t be translated</span>';
                return;
            }
            const proto = protoSel.value;
            const port = portIn.value.trim();
            const verdict = wrSimulateTraffic(fromEp, toEp, proto, port);
            wrPolicyUi.simPath = verdict.matchedEdgeId
                ? { edgeIds: [verdict.matchedEdgeId], verdict: verdict.action }
                : null;
            const colour = {
                allow:  '#22c55e', deny:   '#ef4444',
                reject: '#f97316', log:    '#60a5fa',
                implicit_allow: '#94a3b8',
            }[verdict.action] || '#94a3b8';
            result.innerHTML = `
                <span style="color:${colour}; font-weight:600;">${verdict.action.toUpperCase()}</span>
                ${verdict.matchedRuleId ? ` via rule <code style="color:var(--text);">${escHtml(verdict.matchedRuleId.slice(0, 8))}</code>` : ''}
                ${verdict.note ? `<span style="color:var(--text-muted); margin-left:6px;">${escHtml(verdict.note)}</span>` : ''}
            `;
            wrRenderPolicyMap();
        };
    }

    /// Evaluate a proposed packet against the current rule list in
    /// order. Returns { action, matchedRuleId, matchedEdgeId, note }.
    /// Mirrors the backend's rule-matching for the common cases —
    /// this is a client-side approximation, not an exact iptables
    /// walk, but close enough to answer "will this go through?".
    function wrSimulateTraffic(fromEp, toEp, protocol, port) {
        // Endpoint match logic: an endpoint in the rule matches the
        // proposed endpoint iff rule endpoint is Any OR same kind+id.
        const matchEp = (ruleEp, proposed) => {
            if (!ruleEp) return true;
            if (ruleEp.kind === 'any') return true;
            if (!proposed) return false;  // guard against null proposed endpoint
            if (ruleEp.kind !== proposed.kind) return false;
            if (ruleEp.kind === 'zone') {
                return ruleEp.zone?.kind === proposed.zone?.kind
                    && (ruleEp.zone?.id ?? 0) === (proposed.zone?.id ?? 0);
            }
            if (ruleEp.kind === 'lan')       return ruleEp.id === proposed.id;
            if (ruleEp.kind === 'vm'
             || ruleEp.kind === 'container'
             || ruleEp.kind === 'interface') return ruleEp.name === proposed.name;
            if (ruleEp.kind === 'ip')        return ruleEp.cidr === proposed.cidr;
            return true;
        };
        const protoMatches = (rp) => {
            // Rule with proto=any matches every proposed packet.
            if (rp === 'any') return true;
            // Proposed packet with proto=any means "any/unknown" — we
            // interpret this as "match rules regardless of proto" so
            // users can simulate without committing to a layer-4
            // protocol (e.g. "can X talk to Y at all?").
            if (protocol === 'any') return true;
            if (rp === 'tcpudp') return protocol === 'tcp' || protocol === 'udp';
            return rp === protocol;
        };
        const portMatches = (rulePorts) => {
            if (!rulePorts?.length) return true;
            if (!port) return false;
            const n = parseInt(port, 10);
            if (isNaN(n)) return false;
            return rulePorts.some(p => {
                const s = p.port;
                if (s.includes('-')) {
                    const [lo, hi] = s.split('-').map(x => parseInt(x, 10));
                    return n >= lo && n <= hi;
                }
                return parseInt(s, 10) === n;
            });
        };
        // .slice() before sort — otherwise the sort mutates the live
        // wrState.rules order and other tabs that iterate it see the
        // shuffled-by-order sequence (caught in review).
        const rules = (wrState.rules || []).slice()
            .filter(r => r.enabled !== false)
            .sort((a, b) => (a.order || 0) - (b.order || 0));
        for (const r of rules) {
            if (!matchEp(r.from, fromEp)) continue;
            if (!matchEp(r.to,   toEp))   continue;
            if (!protoMatches(r.protocol)) continue;
            if (!portMatches(r.ports))    continue;
            return {
                action: r.action,
                matchedRuleId: r.id,
                matchedEdgeId: 'rule:' + r.id,
                note: `${r.action === 'allow' ? '✓ permitted' : '✗ blocked'} — ${r.comment || '(no comment)'}`,
            };
        }
        return {
            action: 'implicit_allow',
            matchedRuleId: null,
            matchedEdgeId: null,
            note: 'no rule matched — kernel default (ACCEPT) applies',
        };
    }

    /// Translate a policy-map node id back to a firewall Endpoint
    /// suitable for wrSaveRule. Mirrors wrEndpointNodeId() in reverse.
    function wrNodeIdToEndpoint(id, graph) {
        const node = graph?.nodes?.find(n => n.id === id);
        if (id === 'internet') return { kind: 'any' };
        if (id.startsWith('zone:')) {
            // Prefer the node's stashed zone meta (exact round-trip)…
            if (node?.meta?.zone) return { kind: 'zone', zone: node.meta.zone };
            // …but fall back to reconstructing from the id so dynamic
            // custom-zone nodes (added by the unknown-endpoint fallback)
            // still translate to a usable endpoint instead of silently
            // returning null and confusing the user.
            const slug = id.slice(5);
            const m = slug.match(/^lan(\d+)$/);
            if (m) return { kind: 'zone', zone: { kind: 'lan', id: parseInt(m[1], 10) } };
            if (slug.startsWith('custom:')) {
                return { kind: 'zone', zone: { kind: 'custom', id: slug.slice(7) } };
            }
            return { kind: 'zone', zone: { kind: slug } };
        }
        if (id.startsWith('lan:')) return { kind: 'lan', id: id.slice(4) };
        if (id.startsWith('vm:'))  return { kind: 'vm',  name: id.slice(3) };
        if (id.startsWith('ct:'))  return { kind: 'container', name: id.slice(3) };
        if (id.startsWith('ip:'))  return { kind: 'ip', cidr: id.slice(3) };
        if (id.startsWith('iface:')) return { kind: 'interface', name: id.slice(6) };
        return null;
    }

    /// Open the existing rule editor modal with fields pre-populated
    /// from a drag-to-create action. Reuses wrShowRuleEditor's DOM.
    function wrShowRuleEditorPrefilled(rule) {
        wrShowRuleEditor(null);  // fresh modal
        // Populate synchronously — the modal was just appended.
        const byId = (id) => document.getElementById(id);
        if (!byId('wr-f-action')) return;
        byId('wr-f-action').value = rule.action;
        byId('wr-f-dir').value = rule.direction;
        byId('wr-f-from').value = endpointToPrefillText(rule.from);
        byId('wr-f-to').value   = endpointToPrefillText(rule.to);
        byId('wr-f-proto').value = rule.protocol;
        byId('wr-f-ports').value = (rule.ports || []).map(p => p.port).join(', ');
        byId('wr-f-comment').value = rule.comment || '';
        byId('wr-f-log').checked = !!rule.log_match;
        byId('wr-f-enabled').checked = rule.enabled !== false;
        // Call the analyser explicitly once the pre-fill is written —
        // don't race the 50ms timer that wrShowRuleEditor scheduled.
        wrRenderRuleWarnings();
    }
    function endpointToPrefillText(ep) {
        if (!ep || ep.kind === 'any') return 'any';
        if (ep.kind === 'zone') {
            if (ep.zone?.kind === 'lan') return 'zone:lan' + (ep.zone.id ?? 0);
            return 'zone:' + ep.zone?.kind;
        }
        if (ep.kind === 'interface') return 'iface:' + ep.name;
        if (ep.kind === 'ip')        return 'ip:' + ep.cidr;
        if (ep.kind === 'lan')       return 'lan:' + ep.id;
        if (ep.kind === 'vm')        return 'vm:' + ep.name;
        if (ep.kind === 'container') return 'ct:' + ep.name;
        return 'any';
    }

    /// Click-to-edit popover for an existing edge. Shows edit +
    /// delete buttons + a compact rule summary.
    function wrShowEdgePopover(edge, clientX, clientY) {
        const pop = document.getElementById('wr-policy-edge-popover');
        if (!pop) return;
        const wrap = document.getElementById('wr-policy-canvas-wrap');
        const rect = wrap.getBoundingClientRect();
        pop.style.left = (clientX - rect.left + 8) + 'px';
        pop.style.top  = (clientY - rect.top + 8) + 'px';
        pop.style.display = 'block';
        if (edge.kind === 'rule') {
            const r = edge.rule;
            pop.innerHTML = `
                <div style="margin-bottom:6px;"><strong style="color:${edge.colour};">${escHtml(r.action.toUpperCase())}</strong> ${escHtml(r.protocol||'any')}${r.ports?.length ? ' ports ' + r.ports.map(p=>p.port).join(',') : ''}</div>
                ${r.comment ? `<div style="color:var(--text-muted); font-size:11px; margin-bottom:6px;">${escHtml(r.comment)}</div>` : ''}
                <div style="display:flex; gap:6px;">
                    <button class="btn btn-sm" onclick="wrShowRuleEditor('${escHtml(r.id)}'); document.getElementById('wr-policy-edge-popover').style.display='none';">Edit</button>
                    <button class="btn btn-sm" onclick="(async()=>{await wrDeleteRule('${escHtml(r.id)}'); wrRenderPolicyMap();})(); document.getElementById('wr-policy-edge-popover').style.display='none';">Delete</button>
                    <button class="btn btn-sm" onclick="document.getElementById('wr-policy-edge-popover').style.display='none';">Close</button>
                </div>`;
        } else if (edge.kind === 'dnat') {
            const m = edge.mapping;
            pop.innerHTML = `
                <div style="margin-bottom:6px;"><strong style="color:${edge.colour};">DNAT</strong> port forward</div>
                <div style="font-size:11px;">${escHtml(m.public_ip)} → <code>${escHtml(m.wolfnet_ip)}</code>${m.ports ? ' :' + escHtml(m.ports) : ''}</div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Managed on the per-server Networking page.</div>
                <div style="margin-top:6px;"><button class="btn btn-sm" onclick="document.getElementById('wr-policy-edge-popover').style.display='none';">Close</button></div>`;
        }
    }
    // Expose for inline onclick handlers.
    window.wrRenderPolicyMap = wrRenderPolicyMap;

    // Dismiss popover on outside click.
    document.addEventListener('click', (evt) => {
        const pop = document.getElementById('wr-policy-edge-popover');
        if (!pop || pop.style.display === 'none') return;
        if (evt.target.closest('#wr-policy-edge-popover')) return;
        if (evt.target.closest('[data-edge]')) return;
        pop.style.display = 'none';
    });

    // ─── Packets (tcpdump) tab ───────────────────────────────

    function wrRenderPackets() {
        // Populate node + interface dropdowns from the live topology.
        // Only show interfaces that are link-up — capturing on a down
        // interface is just dead time waiting for the timeout.
        const nodeSel = document.getElementById('wr-pcap-node');
        const ifSel = document.getElementById('wr-pcap-iface');
        if (!nodeSel || !ifSel) return;

        const nodes = (wrState.topology?.nodes || []).filter(n => n.status !== 'unreachable');
        const currentNode = nodeSel.value;
        nodeSel.innerHTML = nodes.map(n =>
            `<option value="${escHtml(n.node_id)}">${escHtml(n.node_name)}</option>`
        ).join('') || '<option value="">(no nodes)</option>';
        if (currentNode && nodes.some(n => n.node_id === currentNode)) {
            nodeSel.value = currentNode;
        }

        const selectedNode = nodes.find(n => n.node_id === nodeSel.value) || nodes[0];
        const ifaces = new Set();
        if (selectedNode) {
            for (const i of (selectedNode.interfaces || [])) {
                if (i.link_up) ifaces.add(i.name);
            }
            for (const b of (selectedNode.bridges || [])) {
                ifaces.add(b.name);  // bridges always shown — they
                                     // don't have an operstate concept
            }
        }
        const list = ['any', ...Array.from(ifaces).sort()];
        const currentIf = ifSel.value;
        ifSel.innerHTML = list.map(i => `<option value="${escHtml(i)}">${escHtml(i)}</option>`).join('');
        if (currentIf && list.includes(currentIf)) ifSel.value = currentIf;
    }

    /// Parse a single tcpdump line (with -tttt timestamp) into a row:
    ///   "2026-04-15 11:37:34.107236 IP 100.96.0.2.45413 > 100.95.0.254.53: 32916+ A? discord.com. (29)"
    /// Returns { time, proto, src, dst, info, length } — best-effort;
    /// non-matching lines are passed through verbatim in the info col.
    function wrParsePacketLine(line) {
        const out = { time: '', proto: '', src: '', dst: '', info: line, length: '' };
        // Timestamp: "YYYY-MM-DD HH:MM:SS.frac"
        const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(.*)$/);
        if (!tsMatch) return out;
        out.time = tsMatch[2].slice(0, 12);  // HH:MM:SS.frac3
        const rest = tsMatch[3];
        // L3 family + src > dst:
        const headerMatch = rest.match(/^(IP6?|ARP|STP|PPP|RARP)\s+(\S+)\s+>\s+(\S+):\s*(.*)$/);
        if (!headerMatch) {
            out.info = rest;
            return out;
        }
        const family = headerMatch[1];
        const srcRaw = headerMatch[2];
        const dstRaw = headerMatch[3].replace(/[:,]+$/, '');
        out.info = headerMatch[4] || '';
        // src/dst may have a port appended via dot for IPv4 or .NNN for IPv6
        const splitHostPort = (s) => {
            // IPv4: a.b.c.d.PORT — last segment is port if all-digits
            const lastDot = s.lastIndexOf('.');
            if (lastDot > -1) {
                const tail = s.slice(lastDot + 1);
                if (/^\d+$/.test(tail) && s.slice(0, lastDot).split('.').length === 4) {
                    return s.slice(0, lastDot) + ':' + tail;
                }
            }
            return s;
        };
        out.src = splitHostPort(srcRaw);
        out.dst = splitHostPort(dstRaw);
        // Protocol: sniff from info or family.
        if (/^ICMP\b/i.test(out.info)) out.proto = 'ICMP';
        else if (/^Flags\s+\[/.test(out.info)) out.proto = 'TCP';
        else if (/^UDP[, ]/.test(out.info)) out.proto = 'UDP';
        else if (/^\d+\+\s+/.test(out.info)) out.proto = 'DNS';
        else if (family === 'ARP') out.proto = 'ARP';
        else if (family === 'IP6') out.proto = 'IPv6';
        else out.proto = family;
        // Length: "length N" anywhere
        const lenMatch = out.info.match(/length\s+(\d+)/);
        if (lenMatch) out.length = lenMatch[1];
        return out;
    }

    async function wrStartCapture() {
        const node_id = document.getElementById('wr-pcap-node').value.trim();
        const iface = document.getElementById('wr-pcap-iface').value.trim();
        const filter = document.getElementById('wr-pcap-filter').value.trim();
        const count = parseInt(document.getElementById('wr-pcap-count').value, 10) || 100;
        const timeoutSeconds = parseInt(document.getElementById('wr-pcap-timeout').value, 10) || 30;
        const tbody = document.getElementById('wr-pcap-tbody');
        const status = document.getElementById('wr-pcap-status');
        const btn = document.getElementById('wr-pcap-go');
        if (!iface) { alert('Pick an interface first'); return; }

        const setBtn = (disabled, label) => { btn.disabled = disabled; btn.textContent = label; };
        const showStatus = (msg) => { status.innerHTML = msg; };
        const showPlaceholder = (msg) => {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:24px;">${msg}</td></tr>`;
        };

        showStatus(`⏳ Capturing on <code>${escHtml(iface)}</code>${filter ? ' [filter: <code>' + escHtml(filter) + '</code>]' : ''}… max ${count} packets / ${timeoutSeconds}s timeout`);
        showPlaceholder('Waiting for packets…');
        setBtn(true, '⏳ Capturing…');

        const runCapture = async () => {
            const r = await fetch(wrUrl('/api/router/capture'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ iface, filter, count, timeout_seconds: timeoutSeconds, node_id }),
            });
            const data = await r.json();
            return { ok: r.ok, status: r.status, data };
        };

        try {
            let result = await runCapture();
            // Auto-install tcpdump if missing and retry once.
            if (result.data?.error && /tcpdump/i.test(result.data.error)
                && /no such file|not found|couldn't run/i.test(result.data.error))
            {
                showStatus('📦 Installing tcpdump on this host (one-time)…');
                setBtn(true, '📦 Installing tcpdump…');
                const inst = await fetch(wrUrl('/api/router/install-tool'), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tool: 'tcpdump' }),
                });
                const instData = await inst.json();
                if (!instData.success) {
                    showStatus(`✗ Couldn't install tcpdump automatically: ${escHtml(instData.error || 'unknown error')}`);
                    showPlaceholder('Install tcpdump manually with your package manager and try again.');
                    return;
                }
                showStatus(`✓ tcpdump installed. Now capturing…`);
                setBtn(true, '⏳ Capturing…');
                result = await runCapture();
            }

            if (!result.ok) {
                showStatus(`✗ HTTP ${result.status}: ${escHtml(result.data.error || JSON.stringify(result.data))}`);
                showPlaceholder('Capture failed.');
                return;
            }
            const lines = result.data.lines || [];
            const rows = lines.map(wrParsePacketLine);
            showStatus(`✓ ${lines.length} packet${lines.length === 1 ? '' : 's'} on <code>${escHtml(result.data.iface || iface)}</code>${result.data.filter ? ' [filter: <code>' + escHtml(result.data.filter) + '</code>]' : ''}${result.data.error ? ' — ' + escHtml(result.data.error) : ''}`);

            if (!rows.length) {
                showPlaceholder('No packets captured (the timeout fired before any matched).');
                return;
            }

            const protoColor = {
                TCP: '#60a5fa', UDP: '#22c55e', ICMP: '#fbbf24',
                DNS: '#a855f7', ARP: '#fb923c', IPv6: '#f472b6',
            };
            tbody.innerHTML = rows.map(p => {
                const c = protoColor[p.proto] || '#94a3b8';
                return `<tr>
                    <td style="font-family:var(--font-mono); color:var(--text-muted);">${escHtml(p.time)}</td>
                    <td><span class="badge" style="background:${c}22; color:${c}; font-size:10px; padding:1px 6px;">${escHtml(p.proto || '?')}</span></td>
                    <td><code>${escHtml(p.src)}</code></td>
                    <td><code>${escHtml(p.dst)}</code></td>
                    <td style="color:var(--text-muted); font-family:var(--font-mono); font-size:10px;">${escHtml(p.info.slice(0, 200))}</td>
                    <td style="text-align:right; color:var(--text-muted); font-family:var(--font-mono);">${escHtml(p.length)}</td>
                </tr>`;
            }).join('');
        } catch (e) {
            showStatus('✗ ' + escHtml(e.message || e));
            showPlaceholder('Network error.');
        } finally {
            setBtn(false, '▶ Capture');
        }
    }
    window.wrStartCapture = wrStartCapture;

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
        // Per-peer diagnostics surface "why is this node missing?" right
        // on the cluster header — no need to dig into server logs to
        // debug fan-out failures.
        const diag = topo.peer_diagnostics || [];
        const diagFailed = diag.filter(d => d.result === 'failed' || d.result === 'skipped');
        const diagBanner = diagFailed.length
            ? `<details style="margin-top:6px; font-size:11px;">
                <summary style="cursor:pointer; color:#fbbf24;">⚠ ${diagFailed.length} peer${diagFailed.length===1?'':'s'} not in this view — click to see why</summary>
                <div style="margin-top:6px; padding:6px 10px; background:rgba(0,0,0,0.3); border-radius:4px;">
                    ${diagFailed.map(d => `<div style="color:var(--text-muted);"><strong>${escHtml(d.hostname || d.node_id)}</strong>: ${escHtml(d.reason || d.result)}</div>`).join('')}
                </div>
            </details>` : '';

        header.innerHTML = `
            <div style="flex:1; min-width:240px;">
                <div><strong>📡 Cluster: ${escHtml(wrState.cluster || 'unnamed')}</strong>
                    <span style="color:var(--text-muted); margin-left:8px;">${topo.nodes.length} node${topo.nodes.length===1?'':'s'} · ${totalUp}/${totalPorts} ports up · ${totalVms} VMs · ${totalCt} containers</span>
                </div>
                ${diagBanner}
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
        const baseUnitH = 116;     // 2U baseline — taller now to fit
                                   // the bigger port labels + IP line
        const oneUH = 22;          // each "rack unit" of growth = one device row
        const unitGap = 24;
        const deviceRowH = 22;     // pixel pitch for each device badge

        const nodeCount = topo.nodes.length;

        // Variable per-node height: each node grows as more devices
        // attach. Base = 2U, then +1U for every 2 devices over 6 (so 7-8
        // devices = 3U, 9-10 = 4U, etc). Devices stay visible without
        // overflow indicators.
        const nodeHeights = topo.nodes.map(n => {
            const devCount = (n.vms?.length || 0) + (n.containers?.length || 0);
            if (devCount <= 6) return baseUnitH;
            const extraRows = Math.ceil((devCount - 6) / 2);
            return baseUnitH + extraRows * oneUH;
        });
        // Cumulative Y offset per node, computed once and reused below.
        const nodeYs = [];
        let yAcc = rackInnerPad;
        for (const h of nodeHeights) {
            nodeYs.push(yAcc);
            yAcc += h + unitGap;
        }
        // Strip the trailing gap so the rack hugs the last appliance.
        const innerContent = yAcc - unitGap + rackInnerPad;

        const rackY = cloudH + cloudGap;
        const rackInnerH = innerContent;
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
        for (let nodeIdx = 0; nodeIdx < topo.nodes.length; nodeIdx++) {
            const node = topo.nodes[nodeIdx];
            // Per-node height grows with device count (3U/4U/5U as needed).
            const uh = nodeHeights[nodeIdx];
            const ux = apX, uy = rackY + nodeYs[nodeIdx], uw = apW;
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
                ${node.lan_segments?.length ? `<text x="${statsX+8}" y="${uy+72}" style="fill:#94a3b8; font-size:8px;">${node.lan_segments.length} WR LAN</text>` : ''}
                <!-- Rack-unit size badge so taller nodes are explained -->
                <text x="${statsX+80}" y="${uy+24}" text-anchor="end" style="fill:#fde68a; font-size:11px; font-weight:700; font-family:monospace;">${Math.max(2, Math.round(uh / 44))}U</text>
            `);

            // Ports — bigger jacks, left-aligned starting at the brand
            // panel edge so layout is consistent across nodes. Each
            // port shows iface name AND its IP address(es) underneath
            // so the user can read what's what at a glance.
            portsByNode[node.node_id] = [];
            const jackW = 44, jackH = 32, jackGap = 22;  // wider gap so iface labels don't collide
            const maxPorts = Math.min(node.interfaces.length, Math.floor((portsZoneW + jackGap) / (jackW + jackGap)));
            const startPx = portsZoneX;  // left-align (was centered)
            const portsCY = uy + uh/2 - 2;

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
                // First IPv4 address for inline display under the port
                const ipv4 = (port.addresses || []).find(a => a.includes('.') && !a.startsWith('fe80'));
                const ipDisplay = ipv4 ? ipv4.split('/')[0] : '';
                // RJ45 jack: trapezoidal shape with 8 contact pins inside.
                const jackPath = `M ${px+3},${py+jackH-3}
                                  L ${px+3},${py+8}
                                  L ${px+8},${py+3}
                                  L ${px+jackW-8},${py+3}
                                  L ${px+jackW-3},${py+8}
                                  L ${px+jackW-3},${py+jackH-3} Z`;
                chassis.insertAdjacentHTML('beforeend', `
                    <g class="wr-port" data-node="${escHtml(node.node_id)}" data-iface="${escHtml(port.name)}">
                        <!-- LEDs above the jack: link (left) + activity (right) -->
                        <circle cx="${px+10}" cy="${py-4}" r="2.5" fill="${linkLed}"/>
                        <circle cx="${px+jackW-10}" cy="${py-4}" r="2.5" fill="${actLed}"
                                ${(port.rx_bps + port.tx_bps) > 0 ? 'filter="url(#wr-glow)"' : ''}/>
                        <!-- The jack itself -->
                        <path d="${jackPath}" fill="url(#wr-jack)" stroke="#000" stroke-width="0.8"/>
                        <!-- 8 contact pins -->
                        ${Array.from({length: 8}).map((_,j) =>
                            `<line x1="${px+8+j*((jackW-16)/7)}" y1="${py+8}" x2="${px+8+j*((jackW-16)/7)}" y2="${py+jackH-5}" stroke="#fbbf24" stroke-width="0.8" opacity="${port.link_up ? 0.75 : 0.25}"/>`
                        ).join('')}
                        <!-- Iface name below (bigger, readable) -->
                        <text x="${px+jackW/2}" y="${py+jackH+12}" text-anchor="middle"
                              style="fill:#f1f5f9; font-size:11px; font-weight:600; font-family:monospace;">${escHtml(port.name.slice(0,10))}</text>
                        <!-- IP address shown only on hover via the
                             custom tooltip — keeps the chassis clean
                             and the labels readable. -->
                        <!-- Live BPS above LEDs (only if actively flowing) -->
                        ${(port.rx_bps + port.tx_bps) > 0
                            ? `<text x="${px+jackW/2}" y="${py-9}" text-anchor="middle" style="fill:#fde68a; font-size:8px; font-family:monospace;">${fmtBpsShort(port.rx_bps + port.tx_bps)}</text>`
                            : ''}
                        <!-- Multi-line tooltip — browsers honour
                             newlines inside SVG <title>. -->
                        <title>${escHtml([
                            `Interface: ${port.name}`,
                            `State: ${port.link_up ? 'UP' : 'DOWN'}`,
                            `Role: ${port.role}`,
                            ...(port.addresses && port.addresses.length ? port.addresses.map(a => `IP: ${a}`) : []),
                        ].join('\n'))}</title>
                    </g>
                `);
                portsByNode[node.node_id].push({
                    name: port.name, cx: px + jackW/2, cy: py + jackH/2,
                    portTop: py - 8, portBottom: py + jackH + 4,
                    chassisTop: uy,
                    role: port.role, link_up: port.link_up,
                    bps: port.rx_bps + port.tx_bps, color: cableColor,
                });
            });

        }

        // Patch cables ────────────────────────────────────────────
        // WolfNet mesh: when there are multiple nodes, draw a thick
        // green cable along the right side of the rack connecting every
        // appliance — visualises the L3 overlay that ties the cluster
        // together. The "spine" runs vertically; each node taps off it.
        const wolfnetSpineX = rackX + rackW - railW + 6;
        if (topo.nodes.length > 1) {
            const firstY = rackY + nodeYs[0] + nodeHeights[0]/2;
            const lastY = rackY + nodeYs[topo.nodes.length-1] + nodeHeights[topo.nodes.length-1]/2;
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
                const ny = rackY + nodeYs[n] + nodeHeights[n]/2;
                const nx = apX + apW - 100;  // right edge of the stats panel
                svg.insertAdjacentHTML('beforeend', `
                    <path d="M ${nx},${ny} H ${wolfnetSpineX}"
                          fill="none" stroke="#22c55e" stroke-width="3" stroke-linecap="square" opacity="0.7"/>
                    <circle cx="${wolfnetSpineX}" cy="${ny}" r="4" fill="#22c55e" opacity="0.9"/>
                `);
            }
        }

        // WAN ports → cloud, Manhattan routing.
        // Each cable exits straight UP from the port, clears the top of
        // its chassis, then runs horizontally to the cloud column, then
        // straight up to the cloud bottom. Right-angle bends instead of
        // bezier curves so cables never drift over neighbouring ports
        // or labels.
        const cables = [];
        // Stagger the horizontal "rail" each WAN cable rides so multiple
        // WAN ports don't sit on top of each other on the way up.
        let wanRailIdx = 0;
        for (const node of topo.nodes) {
            for (const port of (portsByNode[node.node_id] || [])) {
                if (port.role === 'wan' && port.link_up) {
                    const x1 = port.cx;
                    const y1 = port.portTop;
                    const chassisTop = port.chassisTop ?? (port.portTop - 30);
                    const railY = chassisTop - 14 - (wanRailIdx * 6);
                    const x2 = cloudCX;
                    const y2 = cloudCY + 30;
                    const path = `M ${x1},${y1} V ${railY} H ${x2} V ${y2}`;
                    cables.push({ path, color: port.color, bps: port.bps, kind: 'wan' });
                    wanRailIdx++;
                }
            }
        }
        // (No more port "patch tails" — they overlapped the iface name
        // and IP address text underneath the jacks.)

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
        // Each device gets its own row; the node's appliance height was
        // grown above to accommodate them, so devices line up vertically
        // within their owning node's vertical band.
        for (let nIdx = 0; nIdx < topo.nodes.length; nIdx++) {
            const node = topo.nodes[nIdx];
            const nodeY = rackY + nodeYs[nIdx];
            const nodeHeightPx = nodeHeights[nIdx];
            const devicesForNode = (node.vms || []).concat(node.containers || []);
            if (!devicesForNode.length) continue;

            // Anchor on the node's right side, wired to all devices.
            const anchorX = apX + apW;
            const anchorY = nodeY + nodeHeightPx / 2;
            const colX = anchorX + 40 + nIdx * 4;  // staggered to avoid overlap
            // Centre the device column on the node so taller appliances
            // host their devices symmetrically rather than top-aligned.
            const totalDeviceH = devicesForNode.length * deviceRowH;
            const startY = nodeY + (nodeHeightPx - totalDeviceH) / 2;
            devicesForNode.forEach((dev, i) => {
                const isVm = dev.kind === 'vm';
                const accent = isVm ? '#60a5fa' : '#a855f7';
                const icon = isVm ? '🖥' : '📦';
                const dy = startY + i * deviceRowH;
                const cableColor = accent;
                // Manhattan H-V-H: out the chassis right, down/up to
                // the device row, into the device left edge.
                const midX = anchorX + 18;
                svg.insertAdjacentHTML('beforeend', `
                    <path d="M ${anchorX},${anchorY} H ${midX} V ${dy+10} H ${colX}"
                          fill="none" stroke="${cableColor}" stroke-width="2" stroke-linecap="square" opacity="0.55"
                          ${i % 2 === 0 ? 'stroke-dasharray="6 4" class="wr-wire-active"' : ''}/>
                    <g>
                        <rect x="${colX}" y="${dy}" width="200" height="20" rx="5"
                              fill="rgba(15,23,42,0.95)" stroke="${accent}" stroke-width="1"/>
                        <text x="${colX+8}" y="${dy+14}" style="fill:#f1f5f9; font-size:11px;">${icon} ${escHtml(dev.name.slice(0,16))}</text>
                        <text x="${colX+195}" y="${dy+14}" text-anchor="end" style="fill:${accent}; font-size:10px; font-family:monospace;">${escHtml(dev.ip || dev.attached_to || '')}</text>
                    </g>
                `);
            });
        }

        // Inter-node WolfNet mesh — each pair of nodes connected by a
        // curved green cable to visualise the L3 overlay holding the
        // cluster together. Drawn behind everything else for depth.
        if (topo.nodes.length > 1) {
            for (let i = 0; i < topo.nodes.length; i++) {
                for (let j = i + 1; j < topo.nodes.length; j++) {
                    const yi = rackY + nodeYs[i] + nodeHeights[i]/2;
                    const yj = rackY + nodeYs[j] + nodeHeights[j]/2;
                    const xLeft = apX + 8;
                    // Manhattan C-shape to the left of the rack: out,
                    // along, back. Right-angle bends, no curves.
                    const railX = xLeft - 30 - ((i + j) % 3) * 8;
                    svg.insertAdjacentHTML('beforeend', `
                        <path d="M ${xLeft},${yi} H ${railX} V ${yj} H ${xLeft}"
                              fill="none" stroke="#22c55e" stroke-width="2.5" stroke-linecap="square"
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
                    ${!port.link_up ? `<button class="btn" style="background:rgba(34,197,94,0.15); color:#22c55e;" onclick="wrBringUpPort('${escHtml(nodeId)}', '${escHtml(ifaceName)}', this)">⬆ Bring Up</button>` : ''}
                    <button class="btn btn-primary" onclick="(async()=>{await wrAssignZone('${nodeId}','${ifaceName}',document.getElementById('wr-port-zone').value); this.closest('.modal-overlay').remove();})()">Apply zone</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        const cur = port.zone?.kind === 'lan' ? `lan${port.zone.id}` : (port.zone?.kind || '');
        if (cur) document.getElementById('wr-port-zone').value = cur;
    }

    /// Runs `ip link set <iface> up` on the owning node (via cluster
    /// RPC if remote). Intentionally one-way — no "Bring Down"
    /// companion, because clicking that over a remote session is a
    /// good way to take yourself offline.
    async function wrBringUpPort(nodeId, iface, btn) {
        const orig = btn.textContent;
        btn.disabled = true; btn.textContent = '⏳ Bringing up…';
        try {
            const r = await fetch(wrUrl('/api/router/interface-up'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ iface, node_id: nodeId }),
            });
            const data = await r.json();
            if (!r.ok || data.success === false) {
                btn.textContent = '✗ failed';
                alert('Bring up failed: ' + (data.error || 'HTTP ' + r.status));
                btn.disabled = false; btn.textContent = orig;
                return;
            }
            btn.textContent = '✓ up';
            // Refresh topology so the rack view redraws the port as UP.
            setTimeout(async () => {
                await wrLoadAll();
                btn.closest('.modal-overlay')?.remove();
            }, 500);
        } catch (e) {
            btn.disabled = false; btn.textContent = orig;
            alert('Error: ' + e.message);
        }
    }
    window.wrBringUpPort = wrBringUpPort;

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

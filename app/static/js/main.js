/**
 * SentinelSOC — Frontend Application
 * Premium Security Operations Center UI
 */

const RedEye = (() => {
    'use strict';

    // ========== API Client ==========
    const API = {
        base: '/api',

        async get(endpoint) {
            try {
                const res = await fetch(`${this.base}${endpoint}`);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return await res.json();
            } catch (err) {
                console.error(`API GET ${endpoint}:`, err);
                throw err;
            }
        },

        async post(endpoint, data) {
            try {
                const res = await fetch(`${this.base}${endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return await res.json();
            } catch (err) {
                console.error(`API POST ${endpoint}:`, err);
                throw err;
            }
        },

        async postForm(endpoint, formData) {
            try {
                const res = await fetch(`${this.base}${endpoint}`, {
                    method: 'POST',
                    body: formData,
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return await res.json();
            } catch (err) {
                console.error(`API POST (form) ${endpoint}:`, err);
                throw err;
            }
        },

        async put(endpoint, data) {
            try {
                const res = await fetch(`${this.base}${endpoint}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return await res.json();
            } catch (err) {
                console.error(`API PUT ${endpoint}:`, err);
                throw err;
            }
        }
    };

    // ========== Toast Notifications ==========
    const Toast = {
        show(message, type = 'info', duration = 4000) {
            const container = document.getElementById('toast-container');
            if (!container) return;

            const icons = {
                success: 'bi-check-circle-fill',
                error: 'bi-exclamation-triangle-fill',
                warning: 'bi-exclamation-circle-fill',
                info: 'bi-info-circle-fill',
            };

            const toast = document.createElement('div');
            toast.className = `toast-sentinel ${type}`;
            toast.innerHTML = `<i class="bi ${icons[type] || icons.info}"></i><span>${message}</span>`;
            container.appendChild(toast);

            setTimeout(() => {
                toast.style.animation = 'slideOut 0.3s ease forwards';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        },

        success(msg) { this.show(msg, 'success'); },
        error(msg) { this.show(msg, 'error', 6000); },
        warning(msg) { this.show(msg, 'warning'); },
        info(msg) { this.show(msg, 'info'); },
    };

    // ========== Utility Functions ==========
    const Utils = {
        formatDate(isoStr) {
            if (!isoStr) return '—';
            const d = new Date(isoStr);
            return d.toLocaleDateString('en-US', {
                month: 'short', day: 'numeric', year: 'numeric',
                hour: '2-digit', minute: '2-digit',
            });
        },

        formatDateShort(isoStr) {
            if (!isoStr) return '—';
            const d = new Date(isoStr);
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        },

        timeAgo(isoStr) {
            if (!isoStr) return '—';
            const d = new Date(isoStr);
            const now = new Date();
            const diff = Math.floor((now - d) / 1000);
            if (diff < 60) return `${diff}s ago`;
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        },

        statusBadge(status) {
            const cls = status === 'SUCCESS' ? 'success' : 'failed';
            return `<span class="badge-status ${cls}">${status || '—'}</span>`;
        },

        severityBadge(severity) {
            const cls = (severity || 'low').toLowerCase();
            return `<span class="badge-severity ${cls}">${severity || '—'}</span>`;
        },

        riskLevelClass(score) {
            if (score >= 80) return 'critical';
            if (score >= 60) return 'high';
            if (score >= 30) return 'medium';
            return 'low';
        },

        countryFlagEmoji(countryIso) {
            if (!countryIso || countryIso.length !== 2) return '🌐';
            const codePoints = countryIso
                .toUpperCase()
                .split('')
                .map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
            return String.fromCodePoint(...codePoints);
        },

        animateCounter(el, target, duration = 1200) {
            if (!el) return;
            const start = parseInt(el.textContent) || 0;
            const range = target - start;
            const startTime = performance.now();

            const step = (now) => {
                const elapsed = now - startTime;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                el.textContent = Math.round(start + range * eased).toLocaleString();
                if (progress < 1) requestAnimationFrame(step);
            };
            requestAnimationFrame(step);
        },

        copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                Toast.success('Copied to clipboard');
            }).catch(() => {
                Toast.error('Failed to copy');
            });
        },

        escapeHtml(str) {
            if (!str) return '';
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }
    };

    // ========== Chart Theme ==========
    const ChartDefaults = {
        colors: {
            primary: '#38bdf8',
            secondary: '#818cf8',
            success: '#34d399',
            danger: '#f87171',
            warning: '#fbbf24',
            purple: '#a78bfa',
            pink: '#f472b6',
        },

        gridColor: 'rgba(255, 255, 255, 0.04)',
        tickColor: '#64748b',

        applyDefaults() {
            if (typeof Chart === 'undefined') return;
            Chart.defaults.color = this.tickColor;
            Chart.defaults.borderColor = this.gridColor;
            Chart.defaults.font.family = "'Inter', sans-serif";
            Chart.defaults.font.size = 12;
            Chart.defaults.plugins.legend.labels.usePointStyle = true;
            Chart.defaults.plugins.legend.labels.padding = 16;
        }
    };

    // ========== Map Helpers ==========
    const MapHelper = {
        darkTileUrl: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
        darkTileAttribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',

        createMap(containerId, options = {}) {
            const defaults = { center: [20, 0], zoom: 2, zoomControl: true, scrollWheelZoom: true };
            const opts = { ...defaults, ...options };
            const map = L.map(containerId, opts);
            L.tileLayer(this.darkTileUrl, { attribution: this.darkTileAttribution, subdomains: 'abcd', maxZoom: 19 }).addTo(map);
            return map;
        },

        riskColor(score) {
            if (score >= 80) return '#ef4444';
            if (score >= 60) return '#f87171';
            if (score >= 30) return '#fbbf24';
            return '#34d399';
        },

        createMarker(lat, lng, data = {}) {
            const color = this.riskColor(data.risk_score || 0);
            const icon = L.divIcon({
                className: 'custom-marker',
                html: `<div style="
                    width:14px; height:14px;
                    background:${color};
                    border-radius:50%;
                    border:2px solid rgba(255,255,255,0.8);
                    box-shadow: 0 0 8px ${color}80;
                "></div>`,
                iconSize: [14, 14],
                iconAnchor: [7, 7],
            });

            const marker = L.marker([lat, lng], { icon });

            if (data.ip) {
                marker.bindPopup(`
                    <div style="min-width:180px;">
                        <strong style="font-size:14px;">${Utils.escapeHtml(data.ip)}</strong><br>
                        <span style="color:#94a3b8; font-size:12px;">
                            ${Utils.countryFlagEmoji(data.country_iso)} ${Utils.escapeHtml(data.country || 'Unknown')}, ${Utils.escapeHtml(data.city || '')}
                        </span><br>
                        <span style="font-size:11px; color:${color}; font-weight:600;">
                            Risk: ${data.risk_score || 0}/100 (${data.risk_level || 'LOW'})
                        </span>
                    </div>
                `);
            }

            return marker;
        }
    };

    // ========== Dashboard Module ==========
    const Dashboard = {
        map: null,
        charts: {},

        async init() {
            ChartDefaults.applyDefaults();
            await this.loadData();
        },

        async loadData() {
            try {
                const data = await API.get('/dashboard');
                this.renderStats(data);
                this.renderRecentEvents(data.recent_events || []);
                this.renderTimeline(data.timeline || []);
                this.renderRiskChart(data.risk_distribution || {});
                this.renderCountriesChart(data.top_countries || []);
                this.renderMap(data.map_data || []);
            } catch (err) {
                Toast.error('Failed to load dashboard data');
            }
        },

        renderStats(data) {
            Utils.animateCounter(document.getElementById('stat-events'), data.total_events || 0);
            Utils.animateCounter(document.getElementById('stat-alerts'), data.total_alerts || 0);
            Utils.animateCounter(document.getElementById('stat-ips'), data.total_ips || 0);
            Utils.animateCounter(document.getElementById('stat-countries'), data.total_countries || 0);
            Utils.animateCounter(document.getElementById('stat-highrisk'), data.high_risk_ips || 0);

            // Show alert badge if alerts > 0
            const badge = document.getElementById('alert-badge');
            if (badge && (data.total_alerts || 0) > 0) badge.style.display = 'block';
        },

        renderRecentEvents(events) {
            const tbody = document.getElementById('recent-events-body');
            if (!tbody) return;

            if (!events.length) {
                tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted" style="padding:32px;">
                    <div class="empty-state"><i class="bi bi-inbox"></i><h4>No events yet</h4><p>Import security logs to get started</p></div>
                </td></tr>`;
                return;
            }

            tbody.innerHTML = events.slice(0, 10).map(e => `
                <tr>
                    <td><a href="/lookup?ip=${Utils.escapeHtml(e.ip)}" class="text-accent" style="text-decoration:none;">${Utils.escapeHtml(e.ip || '—')}</a></td>
                    <td>${Utils.escapeHtml(e.username || '—')}</td>
                    <td><span class="badge-status info">${Utils.escapeHtml(e.event_type || '—')}</span></td>
                    <td>${Utils.statusBadge(e.status)}</td>
                    <td class="text-muted" style="font-size:12px;">${Utils.timeAgo(e.created_at)}</td>
                </tr>
            `).join('');
        },

        renderTimeline(timeline) {
            const ctx = document.getElementById('timeline-chart');
            if (!ctx) return;
            if (this.charts.timeline) this.charts.timeline.destroy();

            this.charts.timeline = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timeline.map(t => t.date),
                    datasets: [{
                        label: 'Events',
                        data: timeline.map(t => t.count),
                        borderColor: ChartDefaults.colors.primary,
                        backgroundColor: 'rgba(56, 189, 248, 0.08)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { display: false }, ticks: { maxTicksLimit: 7 } },
                        y: { grid: { color: ChartDefaults.gridColor }, beginAtZero: true, ticks: { maxTicksLimit: 5 } }
                    }
                }
            });
        },

        renderRiskChart(distribution) {
            const ctx = document.getElementById('risk-chart');
            if (!ctx) return;
            if (this.charts.risk) this.charts.risk.destroy();

            const labels = ['Low', 'Medium', 'High', 'Critical'];
            const data = [
                distribution.low || 0,
                distribution.medium || 0,
                distribution.high || 0,
                distribution.critical || 0,
            ];
            const colors = [ChartDefaults.colors.success, ChartDefaults.colors.warning, ChartDefaults.colors.danger, '#ef4444'];

            this.charts.risk = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels,
                    datasets: [{ data, backgroundColor: colors, borderWidth: 0, spacing: 2 }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    plugins: {
                        legend: { position: 'bottom', labels: { padding: 16 } }
                    }
                }
            });
        },

        renderCountriesChart(countries) {
            const ctx = document.getElementById('countries-chart');
            if (!ctx) return;
            if (this.charts.countries) this.charts.countries.destroy();

            const labels = countries.map(c => c.country || 'Unknown');
            const data = countries.map(c => c.count);
            const colors = [
                ChartDefaults.colors.primary, ChartDefaults.colors.secondary,
                ChartDefaults.colors.success, ChartDefaults.colors.warning,
                ChartDefaults.colors.purple, ChartDefaults.colors.danger,
                ChartDefaults.colors.pink, '#06b6d4', '#14b8a6', '#f59e0b',
            ];

            this.charts.countries = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels,
                    datasets: [{
                        label: 'IPs',
                        data,
                        backgroundColor: colors.slice(0, data.length),
                        borderRadius: 6,
                        barThickness: 28,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { color: ChartDefaults.gridColor }, beginAtZero: true },
                        y: { grid: { display: false } }
                    }
                }
            });
        },

        renderMap(mapData) {
            const container = document.getElementById('dashboard-map');
            if (!container) return;

            if (this.map) { this.map.remove(); this.map = null; }
            this.map = MapHelper.createMap('dashboard-map', { zoom: 2, scrollWheelZoom: false });

            mapData.forEach(d => {
                const lat = d.latitude || d.lat;
                const lng = d.longitude || d.lng;
                if (lat && lng) {
                    MapHelper.createMarker(lat, lng, d).addTo(this.map);
                }
            });
        }
    };

    // ========== IP Lookup Module ==========
    const Lookup = {
        map: null,
        currentData: null,

        init() {
            const input = document.getElementById('ip-search-input');
            if (input) {
                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') this.search();
                });

                // Check URL params for pre-filled IP
                const params = new URLSearchParams(window.location.search);
                const ipParam = params.get('ip');
                if (ipParam) {
                    input.value = ipParam;
                    this.search();
                }
            }
        },

        async search() {
            const input = document.getElementById('ip-search-input');
            const ip = input ? input.value.trim() : '';

            if (!ip) {
                Toast.warning('Please enter an IP address');
                return;
            }

            // Validate IP format
            const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
            const ipv6Regex = /^[0-9a-fA-F:]+$/;
            if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
                Toast.error('Invalid IP address format');
                return;
            }

            this.showLoading();

            try {
                const data = await API.post('/ip/lookup', { ip });
                if (data.error) {
                    this.showError('Lookup Failed', data.error);
                    return;
                }
                this.currentData = data;
                this.renderResults(data);
            } catch (err) {
                this.showError('Lookup Failed', 'Could not reach the server. Please try again.');
            }
        },

        async searchMyIP() {
            try {
                const res = await fetch('https://api.ipify.org?format=json');
                const data = await res.json();
                const input = document.getElementById('ip-search-input');
                if (input) input.value = data.ip;
                this.search();
            } catch {
                Toast.error('Could not detect your IP address');
            }
        },

        showLoading() {
            document.getElementById('lookup-results').style.display = 'none';
            document.getElementById('lookup-error').style.display = 'none';
            document.getElementById('lookup-loading').style.display = 'block';
        },

        showError(title, message) {
            document.getElementById('lookup-loading').style.display = 'none';
            document.getElementById('lookup-results').style.display = 'none';
            document.getElementById('lookup-error').style.display = 'block';
            document.getElementById('error-title').textContent = title;
            document.getElementById('error-message').textContent = message;
        },

        reset() {
            document.getElementById('lookup-loading').style.display = 'none';
            document.getElementById('lookup-error').style.display = 'none';
            document.getElementById('lookup-results').style.display = 'none';
            const input = document.getElementById('ip-search-input');
            if (input) { input.value = ''; input.focus(); }
        },

        renderResults(data) {
            document.getElementById('lookup-loading').style.display = 'none';
            document.getElementById('lookup-error').style.display = 'none';
            document.getElementById('lookup-results').style.display = 'block';

            // Summary bar
            const iso = data.country_iso || '';
            document.getElementById('result-flag').textContent = Utils.countryFlagEmoji(iso);
            document.getElementById('result-ip').textContent = data.ip || '—';
            document.getElementById('result-location').textContent =
                [data.city, data.state, data.country].filter(Boolean).join(', ') || 'Unknown Location';

            // Threat badges
            const badgesEl = document.getElementById('threat-badges');
            let badges = '';
            if (data.is_tor) badges += '<span class="badge-threat tor"><i class="bi bi-shield-x"></i> TOR</span>';
            if (data.is_vpn) badges += '<span class="badge-threat vpn"><i class="bi bi-shield-exclamation"></i> VPN</span>';
            if (data.is_hosting) badges += '<span class="badge-threat hosting"><i class="bi bi-hdd-rack"></i> HOSTING</span>';
            if (data.is_proxy) badges += '<span class="badge-threat proxy"><i class="bi bi-incognito"></i> PROXY</span>';
            if (data.is_private) badges += '<span class="badge-threat" style="background:rgba(52,211,153,0.15);color:#34d399;border:1px solid rgba(52,211,153,0.25);"><i class="bi bi-lock"></i> PRIVATE</span>';
            badgesEl.innerHTML = badges;

            // Risk meter (summary bar)
            const riskScore = data.risk_score || 0;
            const riskClass = Utils.riskLevelClass(riskScore);
            document.getElementById('result-risk-score').textContent = riskScore;
            document.getElementById('result-risk-score').className = `risk-score-display ${riskClass}`;
            const riskBar = document.getElementById('result-risk-bar');
            riskBar.style.width = `${riskScore}%`;
            riskBar.className = `risk-meter-fill ${riskClass}`;

            // Location details
            document.getElementById('detail-country').textContent = data.country ? `${Utils.countryFlagEmoji(iso)} ${data.country}` : '—';
            document.getElementById('detail-state').textContent = data.state || '—';
            document.getElementById('detail-city').textContent = data.city || '—';
            document.getElementById('detail-postal').textContent = data.postal_code || '—';
            document.getElementById('detail-coords').textContent = (data.latitude && data.longitude) ? `${data.latitude}, ${data.longitude}` : '—';
            document.getElementById('detail-timezone').textContent = data.timezone || '—';

            // Network details
            document.getElementById('detail-hostname').textContent = data.hostname || '—';
            document.getElementById('detail-asn').textContent = data.asn || '—';
            document.getElementById('detail-asn-desc').textContent = data.asn_description || '—';
            document.getElementById('detail-network').textContent = data.network_name || '—';
            document.getElementById('detail-cidr').textContent = data.network_cidr || '—';
            document.getElementById('detail-org').textContent = data.org_name || '—';

            // Risk assessment
            document.getElementById('detail-risk-score').textContent = riskScore;
            document.getElementById('detail-risk-score').className = `risk-score-display ${riskClass}`;
            const detailRiskBar = document.getElementById('detail-risk-bar');
            detailRiskBar.style.width = `${riskScore}%`;
            detailRiskBar.className = `risk-meter-fill ${riskClass}`;
            document.getElementById('detail-risk-level').textContent = data.risk_level || 'LOW';

            // Risk factors list
            const factorsEl = document.getElementById('risk-factors-list');
            const factors = data.risk_factors || [];
            if (factors.length) {
                factorsEl.innerHTML = factors.map(f =>
                    `<div style="padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04); font-size:13px;">
                        <i class="bi bi-exclamation-diamond text-warning" style="font-size:12px;"></i>
                        <span class="text-secondary">${Utils.escapeHtml(f)}</span>
                    </div>`
                ).join('');
            } else {
                factorsEl.innerHTML = '<div class="text-muted" style="font-size:13px; padding:8px 0;"><i class="bi bi-check-circle text-success"></i> No risk factors detected</div>';
            }

            // Google Maps iframe
            if (data.latitude && data.longitude) {
                const gmapUrl = `https://www.google.com/maps/embed?pb=!1m14!1m12!1m3!1d5000!2d${data.longitude}!3d${data.latitude}!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!5e0!3m2!1sen!2sus!4v1`;
                document.getElementById('google-map-iframe').src = gmapUrl;
            }

            // Leaflet map
            this.renderLeafletMap(data);

            Toast.success(`Intelligence loaded for ${data.ip}`);
        },

        renderLeafletMap(data) {
            const container = document.getElementById('lookup-leaflet-map');
            if (!container) return;

            if (this.map) { this.map.remove(); this.map = null; }

            if (data.latitude && data.longitude) {
                this.map = MapHelper.createMap('lookup-leaflet-map', {
                    center: [data.latitude, data.longitude],
                    zoom: 12,
                });

                MapHelper.createMarker(data.latitude, data.longitude, data).addTo(this.map);

                // Add accuracy circle if available
                L.circle([data.latitude, data.longitude], {
                    radius: (data.accuracy_radius || 50) * 1000,
                    color: '#38bdf8',
                    fillColor: '#38bdf8',
                    fillOpacity: 0.08,
                    weight: 1,
                }).addTo(this.map);
            } else {
                this.map = MapHelper.createMap('lookup-leaflet-map');
            }
        },

        openGoogleMaps() {
            if (this.currentData && this.currentData.latitude && this.currentData.longitude) {
                window.open(`https://www.google.com/maps/@${this.currentData.latitude},${this.currentData.longitude},14z`, '_blank');
            }
        }
    };

    // ========== Threat Map Module ==========
    const ThreatMap = {
        map: null,

        async init() {
            this.map = MapHelper.createMap('threat-map', { zoom: 2 });
            await this.loadData();
        },

        async loadData() {
            try {
                const data = await API.get('/map/data');
                this.render(data);
            } catch (err) {
                Toast.error('Failed to load map data');
            }
        },

        render(mapData) {
            if (!this.map) return;

            const ips = mapData || [];
            const countries = new Set();

            ips.forEach(d => {
                const lat = d.latitude || d.lat;
                const lng = d.longitude || d.lng;
                if (lat && lng) {
                    MapHelper.createMarker(lat, lng, d).addTo(this.map);
                    if (d.country) countries.add(d.country);
                }
            });

            const ipCountEl = document.getElementById('map-ip-count');
            const countryCountEl = document.getElementById('map-country-count');
            if (ipCountEl) ipCountEl.textContent = ips.length;
            if (countryCountEl) countryCountEl.textContent = countries.size;
        },

        async refresh() {
            if (this.map) {
                this.map.eachLayer(layer => {
                    if (layer instanceof L.Marker) this.map.removeLayer(layer);
                });
            }
            await this.loadData();
            Toast.info('Map refreshed');
        },

        async clearData() {
            if (!confirm('Are you sure you want to clear all threat coordinates and reset data to 0? This will wipe the database.')) {
                return;
            }
            try {
                const res = await API.post('/clear-data', {});
                Toast.success(res.message || 'All threat plots cleared');
                await this.refresh();
            } catch (err) {
                Toast.error('Failed to clear threat plots');
            }
        }
    };

    // ========== Alerts Module ==========
    const Alerts = {
        async init() {
            await this.loadData();
        },

        async loadData() {
            try {
                const data = await API.get('/alerts');
                this.renderStats(data.stats || {});
                this.renderTable(data.alerts || []);
            } catch (err) {
                Toast.error('Failed to load alerts');
            }
        },

        renderStats(stats) {
            Utils.animateCounter(document.getElementById('alert-stat-total'), stats.total || 0);
            Utils.animateCounter(document.getElementById('alert-stat-unresolved'), stats.unresolved || 0);
            Utils.animateCounter(document.getElementById('alert-stat-critical'), (stats.by_severity || {}).CRITICAL || 0);
            Utils.animateCounter(document.getElementById('alert-stat-resolved'), (stats.total || 0) - (stats.unresolved || 0));
        },

        renderTable(alerts) {
            const tbody = document.getElementById('alerts-table-body');
            if (!tbody) return;

            if (!alerts.length) {
                tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding:40px;">
                    <div class="empty-state"><i class="bi bi-shield-check"></i><h4>No alerts</h4><p>All clear! No security alerts detected.</p></div>
                </td></tr>`;
                return;
            }

            tbody.innerHTML = alerts.map(a => `
                <tr>
                    <td>${Utils.severityBadge(a.severity)}</td>
                    <td>${Utils.escapeHtml(a.title)}</td>
                    <td>${a.ip ? `<a href="/lookup?ip=${Utils.escapeHtml(a.ip)}" class="text-accent" style="text-decoration:none;">${Utils.escapeHtml(a.ip)}</a>` : '—'}</td>
                    <td class="text-muted">${Utils.escapeHtml(a.rule_name || '—')}</td>
                    <td class="text-muted" style="font-size:12px;">${Utils.timeAgo(a.created_at)}</td>
                    <td>${a.resolved ? '<span class="badge-status success">Resolved</span>' : '<span class="badge-status warning">Open</span>'}</td>
                    <td>${!a.resolved ? `<button class="btn-sentinel btn-sentinel-success btn-sentinel-sm" onclick="SentinelSOC.Alerts.resolve(${a.id})"><i class="bi bi-check"></i></button>` : ''}</td>
                </tr>
            `).join('');
        },

        async resolve(id) {
            try {
                await API.put(`/alerts/${id}/resolve`, {});
                Toast.success('Alert resolved');
                await this.loadData();
            } catch (err) {
                Toast.error('Failed to resolve alert');
            }
        },

        async filter() {
            await this.loadData();
        }
    };

    // ========== Event Logs Module ==========
    const Logs = {
        currentPage: 1,

        async init() {
            await this.loadData();
        },

        async loadData(page = 1) {
            this.currentPage = page;
            try {
                const data = await API.get(`/events?page=${page}`);
                this.renderTable(data.events || []);
                const countEl = document.getElementById('log-total-count');
                if (countEl) countEl.textContent = `${data.total || 0} events`;
            } catch (err) {
                Toast.error('Failed to load events');
            }
        },

        renderTable(events) {
            const tbody = document.getElementById('logs-table-body');
            if (!tbody) return;

            if (!events.length) {
                tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding:40px;">
                    <div class="empty-state"><i class="bi bi-inbox"></i><h4>No events</h4><p>Import security logs to see events here.</p></div>
                </td></tr>`;
                return;
            }

            tbody.innerHTML = events.map(e => `
                <tr>
                    <td><a href="/lookup?ip=${Utils.escapeHtml(e.ip)}" class="text-accent" style="text-decoration:none;">${Utils.escapeHtml(e.ip || '—')}</a></td>
                    <td>${Utils.escapeHtml(e.username || '—')}</td>
                    <td><span class="badge-status info">${Utils.escapeHtml(e.event_type || '—')}</span></td>
                    <td class="text-muted">${Utils.escapeHtml(e.source || '—')}</td>
                    <td>${Utils.statusBadge(e.status)}</td>
                    <td class="text-muted" style="font-size:12px;">${Utils.timeAgo(e.created_at)}</td>
                    <td>
                        <a href="/lookup?ip=${Utils.escapeHtml(e.ip)}" class="btn-sentinel btn-sentinel-secondary btn-sentinel-sm" title="Lookup IP">
                            <i class="bi bi-search"></i>
                        </a>
                    </td>
                </tr>
            `).join('');
        },

        async filter() {
            await this.loadData(1);
        },

        async refresh() {
            await this.loadData(this.currentPage);
            Toast.info('Events refreshed');
        }
    };

    // ========== History Module ==========
    const History = {
        allData: [],

        async init() {
            await this.loadData();
        },

        async loadData() {
            try {
                const data = await API.get('/ip/history');
                this.allData = data.ips || [];
                this.renderTable(this.allData);
            } catch (err) {
                Toast.error('Failed to load history');
            }
        },

        renderTable(ips) {
            const tbody = document.getElementById('history-table-body');
            if (!tbody) return;

            if (!ips.length) {
                tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted" style="padding:40px;">
                    <div class="empty-state"><i class="bi bi-clock-history"></i><h4>No lookup history</h4><p>Perform an IP lookup to start building history.</p></div>
                </td></tr>`;
                return;
            }

            tbody.innerHTML = ips.map(ip => {
                const riskClass = Utils.riskLevelClass(ip.risk_score || 0);
                return `
                <tr>
                    <td><a href="/lookup?ip=${Utils.escapeHtml(ip.ip)}" class="text-accent" style="text-decoration:none; font-weight:600;">${Utils.escapeHtml(ip.ip)}</a></td>
                    <td class="text-muted" style="font-size:12px;">${Utils.escapeHtml(ip.hostname || '—')}</td>
                    <td>${Utils.countryFlagEmoji(ip.country_iso)} ${Utils.escapeHtml(ip.country || '—')}</td>
                    <td class="text-muted">${Utils.escapeHtml(ip.city || '—')}</td>
                    <td class="text-muted" style="font-size:12px;">${Utils.escapeHtml(ip.asn || '—')}</td>
                    <td><span class="badge-severity ${riskClass}">${ip.risk_score || 0}</span></td>
                    <td>${ip.lookup_count || 0}</td>
                    <td class="text-muted" style="font-size:12px;">${Utils.timeAgo(ip.last_seen)}</td>
                    <td>
                        <a href="/lookup?ip=${Utils.escapeHtml(ip.ip)}" class="btn-sentinel btn-sentinel-secondary btn-sentinel-sm">
                            <i class="bi bi-arrow-clockwise"></i>
                        </a>
                    </td>
                </tr>`;
            }).join('');
        },

        search() {
            const query = (document.getElementById('history-search')?.value || '').toLowerCase();
            if (!query) {
                this.renderTable(this.allData);
                return;
            }
            const filtered = this.allData.filter(ip =>
                (ip.ip || '').toLowerCase().includes(query) ||
                (ip.hostname || '').toLowerCase().includes(query) ||
                (ip.country || '').toLowerCase().includes(query) ||
                (ip.city || '').toLowerCase().includes(query)
            );
            this.renderTable(filtered);
        },

        async refresh() {
            await this.loadData();
            Toast.info('History refreshed');
        }
    };

    // ========== Import Module ==========
    const Import = {
        init() {},

        async submit(event) {
            event.preventDefault();

            const source = document.getElementById('import-source').value;
            const fileInput = document.getElementById('import-file');
            const file = fileInput.files[0];

            if (!source || !file) {
                Toast.warning('Please select a source and a file');
                return;
            }

            const formData = new FormData();
            formData.append('source', source);
            formData.append('logfile', file);

            // Show progress
            document.getElementById('import-progress').style.display = 'block';
            document.getElementById('import-results').style.display = 'none';
            document.getElementById('import-submit-btn').disabled = true;
            document.getElementById('import-progress-bar').style.width = '30%';
            document.getElementById('import-progress-text').textContent = 'Uploading...';

            try {
                document.getElementById('import-progress-bar').style.width = '60%';
                document.getElementById('import-progress-text').textContent = 'Processing...';

                const result = await API.postForm('/import', formData);

                document.getElementById('import-progress-bar').style.width = '100%';
                document.getElementById('import-progress-text').textContent = 'Complete!';

                // Show results
                document.getElementById('import-results').style.display = 'block';
                document.getElementById('result-total').textContent = result.total || 0;
                document.getElementById('result-imported').textContent = result.imported || 0;
                document.getElementById('result-failed').textContent = result.failed || 0;

                Toast.success(`Import complete: ${result.imported || 0} events processed`);
            } catch (err) {
                Toast.error('Import failed. Please check the file format.');
                document.getElementById('import-progress-bar').style.width = '0%';
            } finally {
                document.getElementById('import-submit-btn').disabled = false;
            }
        }
    };

    // ========== Reports Module ==========
    const Reports = {
        charts: {},

        async init() {
            ChartDefaults.applyDefaults();
            await this.loadData();
        },

        async loadData() {
            try {
                const data = await API.get('/dashboard');
                this.renderTimeline(data.timeline || []);
                this.renderSourceChart(data.event_stats || {});
                this.renderStatusChart(data.event_stats || {});
                this.renderCountriesChart(data.top_countries || []);
            } catch (err) {
                Toast.error('Failed to load report data');
            }
        },

        renderTimeline(timeline) {
            const ctx = document.getElementById('report-timeline-chart');
            if (!ctx) return;
            if (this.charts.timeline) this.charts.timeline.destroy();

            this.charts.timeline = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timeline.map(t => t.date),
                    datasets: [{
                        label: 'Events',
                        data: timeline.map(t => t.count),
                        borderColor: ChartDefaults.colors.primary,
                        backgroundColor: 'rgba(56, 189, 248, 0.1)',
                        borderWidth: 2, fill: true, tension: 0.4,
                        pointRadius: 2, pointHoverRadius: 5,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { display: false } },
                        y: { grid: { color: ChartDefaults.gridColor }, beginAtZero: true }
                    }
                }
            });
        },

        renderSourceChart(stats) {
            const ctx = document.getElementById('report-source-chart');
            if (!ctx) return;
            if (this.charts.source) this.charts.source.destroy();

            const bySource = stats.by_source || {};
            const labels = Object.keys(bySource);
            const data = Object.values(bySource);
            const colors = [ChartDefaults.colors.primary, ChartDefaults.colors.secondary, ChartDefaults.colors.success, ChartDefaults.colors.warning, ChartDefaults.colors.purple, ChartDefaults.colors.danger];

            this.charts.source = new Chart(ctx, {
                type: 'doughnut',
                data: { labels, datasets: [{ data, backgroundColor: colors.slice(0, data.length), borderWidth: 0 }] },
                options: { responsive: true, maintainAspectRatio: false, cutout: '60%', plugins: { legend: { position: 'bottom' } } }
            });
        },

        renderStatusChart(stats) {
            const ctx = document.getElementById('report-status-chart');
            if (!ctx) return;
            if (this.charts.status) this.charts.status.destroy();

            const byStatus = stats.by_status || {};
            this.charts.status = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(byStatus),
                    datasets: [{
                        label: 'Events',
                        data: Object.values(byStatus),
                        backgroundColor: [ChartDefaults.colors.success, ChartDefaults.colors.danger],
                        borderRadius: 8, barThickness: 40,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { display: false } },
                        y: { grid: { color: ChartDefaults.gridColor }, beginAtZero: true }
                    }
                }
            });
        },

        renderCountriesChart(countries) {
            const ctx = document.getElementById('report-countries-chart');
            if (!ctx) return;
            if (this.charts.countries) this.charts.countries.destroy();

            this.charts.countries = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: countries.map(c => c.country || 'Unknown'),
                    datasets: [{
                        label: 'IPs',
                        data: countries.map(c => c.count),
                        backgroundColor: ChartDefaults.colors.primary,
                        borderRadius: 6, barThickness: 28,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { color: ChartDefaults.gridColor }, beginAtZero: true },
                        y: { grid: { display: false } }
                    }
                }
            });
        }
    };

    // ========== Settings Module ==========
    const Settings = {
        async init() {
            await this.refreshStats();
        },

        async refreshStats() {
            try {
                const data = await API.get('/dashboard');
                Utils.animateCounter(document.getElementById('settings-ip-count'), data.total_ips || 0);
                Utils.animateCounter(document.getElementById('settings-event-count'), data.total_events || 0);
                Utils.animateCounter(document.getElementById('settings-alert-count'), data.total_alerts || 0);
                Utils.animateCounter(document.getElementById('settings-highrisk-count'), data.high_risk_ips || 0);
            } catch (err) {
                Toast.error('Failed to load stats');
            }
        },

        async checkHealth() {
            const el = document.getElementById('health-status');
            if (!el) return;

            try {
                const data = await API.get('/health');
                el.innerHTML = `
                    <div class="intel-detail-row">
                        <span class="intel-detail-label">Status</span>
                        <span class="intel-detail-value"><span class="badge-status success">${data.status || 'online'}</span></span>
                    </div>
                    <div class="intel-detail-row">
                        <span class="intel-detail-label">Service</span>
                        <span class="intel-detail-value">${Utils.escapeHtml(data.service)}</span>
                    </div>
                    <div class="intel-detail-row">
                        <span class="intel-detail-label">Version</span>
                        <span class="intel-detail-value">${Utils.escapeHtml(data.version)}</span>
                    </div>
                `;
                Toast.success('API is healthy');
            } catch (err) {
                el.innerHTML = `<div class="text-center text-danger" style="padding:16px;"><i class="bi bi-x-circle" style="font-size:24px;"></i><p>API unreachable</p></div>`;
                Toast.error('API health check failed');
            }
        }
    };

    // ========== Quick Search (Header) ==========
    const QuickSearch = {
        init() {
            const input = document.getElementById('quick-search-input');
            if (input) {
                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        const ip = input.value.trim();
                        if (ip) {
                            window.location.href = `/lookup?ip=${encodeURIComponent(ip)}`;
                        }
                    }
                });
            }

            // Refresh button
            const refreshBtn = document.getElementById('btn-refresh');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', () => {
                    window.location.reload();
                });
            }
        }
    };

    // ========== Global Init ==========
    document.addEventListener('DOMContentLoaded', () => {
        QuickSearch.init();
    });

    window.addEventListener('load', () => {
        const preloader = document.getElementById('preloader');
        if (preloader) {
            setTimeout(() => {
                preloader.classList.add('fade-out');
            }, 1000);
        }
    });

    // ========== Public API ==========
    return {
        API,
        Toast,
        Utils,
        Dashboard,
        Lookup,
        ThreatMap,
        Alerts,
        Logs,
        History,
        Import,
        Reports,
        Settings,
    };
})();

/**
 * ViziDLP — SOC Dashboard JavaScript
 * Real-time polling, Chart.js charts, heatmap, live feed, evidence viewer
 */

// ─── State ───────────────────────────────────────────────────
let severityChart = null;
let typesChart = null;
let currentSessionId = '';
let pollInterval = null;
let lastDetectionCount = 0;

// ─── Chart.js Global Config ─────────────────────────────────
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

// ─── Severity Colors ─────────────────────────────────────────
const SEVERITY_COLORS = {
    CRITICAL: '#dc2626',
    HIGH: '#ef4444',
    MEDIUM: '#f59e0b',
    LOW: '#22c55e'
};

const SEVERITY_ICONS = {
    CRITICAL: '🔴',
    HIGH: '🟠',
    MEDIUM: '🟡',
    LOW: '🟢'
};

// ─── Init ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initModal();
    loadSessions();
    refreshAll();

    // Start real-time polling
    pollInterval = setInterval(refreshAll, 2000);

    // Session selector
    const sessionSelect = document.getElementById('session-select');
    if (sessionSelect) {
        sessionSelect.addEventListener('change', (e) => {
            currentSessionId = e.target.value;
            refreshAll();
        });
    }
});

// ─── Data Fetching ───────────────────────────────────────────
async function fetchJSON(url) {
    try {
        const sep = url.includes('?') ? '&' : '?';
        const fullUrl = currentSessionId ? `${url}${sep}session_id=${currentSessionId}` : url;
        const resp = await fetch(fullUrl);
        return await resp.json();
    } catch (e) {
        console.error('Fetch error:', url, e);
        return null;
    }
}

async function refreshAll() {
    const [stats, status, timeline, heatmap, detections, alerts] = await Promise.all([
        fetchJSON('/api/stats'),
        fetchJSON('/api/status'),
        fetchJSON('/api/timeline'),
        fetchJSON('/api/heatmap'),
        fetchJSON('/api/detections?limit=15'),
        fetchJSON('/api/alerts?limit=10')
    ]);

    if (stats) updateStats(stats);
    if (status) updateStatus(status);
    if (timeline) updateMiniTimeline(timeline);
    if (heatmap) updateHeatmap(heatmap);
    if (detections) updateLiveFeed(detections);
    if (alerts) updateAlerts(alerts);
}

// ─── Stats Update ────────────────────────────────────────────
function updateStats(stats) {
    setText('total-incidents', stats.total_detections || 0);
    setText('total-sessions', stats.total_sessions || 0);

    const sev = stats.severity_distribution || {};
    const highCrit = (sev.HIGH || 0) + (sev.CRITICAL || 0);
    setText('high-critical-count', highCrit);

    const alerts = stats.recent_alerts || [];
    setText('alert-count', alerts.length);

    updateSeverityChart(sev);
    updateTypesChart(stats.type_distribution || {});
}

// ─── Status Update ───────────────────────────────────────────
function updateStatus(status) {
    // Monitoring badge
    const badge = document.getElementById('monitoring-badge');
    const statusText = document.querySelector('.status-text');
    if (status.monitoring) {
        badge.className = 'monitoring-status active';
        statusText.textContent = 'Monitoring Active';
    } else {
        badge.className = 'monitoring-status inactive';
        statusText.textContent = 'Monitoring Inactive';
    }

    // Risk level
    const riskValue = document.getElementById('risk-value');
    const riskBadge = document.getElementById('risk-badge');
    const risk = (status.risk_level || 'LOW').toUpperCase();
    riskValue.textContent = risk;
    riskBadge.className = `risk-level-badge risk-${risk.toLowerCase()}`;

    // Monitor dots
    setMonitorDot('mon-screen', status.screen_active);
    setMonitorDot('mon-webcam', status.webcam_active);
    setMonitorDot('mon-screenshot', status.screenshot_detection);
    setMonitorDot('mon-phone', status.phone_detection);
    setMonitorDot('mon-recording', status.recording_detection);

    // Phone alert banner
    const phoneCount = status.phone_detections || 0;
    setText('phone-count', phoneCount);
    setText('phone-detection-count', phoneCount);
    const phoneBanner = document.getElementById('phone-alert-banner');
    phoneBanner.style.display = phoneCount > 0 ? 'flex' : 'none';

    // Recording banner
    const recorders = status.active_recorders || [];
    const recBanner = document.getElementById('recording-alert-banner');
    if (recorders.length > 0) {
        recBanner.style.display = 'flex';
        document.getElementById('recording-app-name').textContent = recorders.join(', ') + ' detected';
    } else {
        recBanner.style.display = 'none';
    }

    // Session ID
    if (status.session_id) {
        const sessionInfo = document.getElementById('modal-session-id');
        if (!currentSessionId && sessionInfo) {
            // Store for reference
        }
    }
}

// ─── Charts ──────────────────────────────────────────────────
function initCharts() {
    // Severity Doughnut
    const sevCtx = document.getElementById('severity-chart');
    if (sevCtx) {
        severityChart = new Chart(sevCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#22c55e'],
                    borderColor: '#111827',
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 16,
                            usePointStyle: true,
                            pointStyleWidth: 10,
                            font: { size: 11 }
                        }
                    }
                }
            }
        });
    }

    // Types Bar
    const typesCtx = document.getElementById('types-chart');
    if (typesCtx) {
        typesChart = new Chart(typesCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Detections',
                    data: [],
                    backgroundColor: 'rgba(6, 182, 212, 0.5)',
                    borderColor: '#06b6d4',
                    borderWidth: 1,
                    borderRadius: 4,
                    barThickness: 18
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        grid: { color: 'rgba(30, 41, 59, 0.5)', drawBorder: false },
                        ticks: { font: { size: 10 } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { font: { size: 10 } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
}

function updateSeverityChart(distribution) {
    if (!severityChart) return;
    severityChart.data.datasets[0].data = [
        distribution.CRITICAL || 0,
        distribution.HIGH || 0,
        distribution.MEDIUM || 0,
        distribution.LOW || 0
    ];
    severityChart.update('none');
}

function updateTypesChart(distribution) {
    if (!typesChart) return;
    const entries = Object.entries(distribution).sort((a, b) => b[1] - a[1]).slice(0, 8);
    typesChart.data.labels = entries.map(e => formatCategory(e[0]));
    typesChart.data.datasets[0].data = entries.map(e => e[1]);
    typesChart.update('none');
}

// ─── Live Feed ───────────────────────────────────────────────
function updateLiveFeed(detections) {
    const container = document.getElementById('live-feed-container');
    if (!container || !detections || detections.length === 0) return;

    container.innerHTML = detections.map(det => {
        const sev = (det.severity || 'LOW').toLowerCase();
        const time = formatTime(det.timestamp);
        const icon = SEVERITY_ICONS[det.severity] || '⚪';
        return `
            <div class="feed-item" onclick="openEvidence(${JSON.stringify(det).replace(/"/g, '&quot;')})">
                <span class="feed-time">${time}</span>
                <span class="feed-icon ${sev}">${icon}</span>
                <div class="feed-details">
                    <div class="feed-category">${formatCategory(det.data_category)}</div>
                    <div class="feed-description">${det.description || ''}</div>
                </div>
                <span class="badge badge-${sev}">${det.severity}</span>
            </div>
        `;
    }).join('');
}

// ─── Heatmap ─────────────────────────────────────────────────
function updateHeatmap(data) {
    const grid = document.getElementById('heatmap-grid');
    const labels = document.getElementById('heatmap-labels');
    if (!grid || !data) return;

    const maxCount = Math.max(...data.map(d => d.count), 1);

    grid.innerHTML = data.map(d => {
        const level = getHeatLevel(d.count, maxCount);
        const tooltip = `${d.hour}:00 — ${d.count} detection${d.count !== 1 ? 's' : ''}`;
        return `<div class="heatmap-cell level-${level}" title="${tooltip}">${d.count || ''}</div>`;
    }).join('');

    labels.innerHTML = data.filter((_, i) => i % 2 === 0).map(d =>
        `<div class="heatmap-label">${d.hour}h</div>`
    ).join('');
}

function getHeatLevel(count, max) {
    if (count === 0) return 0;
    const ratio = count / max;
    if (ratio <= 0.15) return 1;
    if (ratio <= 0.35) return 2;
    if (ratio <= 0.55) return 3;
    if (ratio <= 0.8) return 4;
    return 5;
}

// ─── Alerts ──────────────────────────────────────────────────
function updateAlerts(alerts) {
    const container = document.getElementById('alerts-container');
    if (!container) return;

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No alerts yet. Monitoring is active.</p></div>';
        return;
    }

    container.innerHTML = alerts.map(alert => {
        const sev = (alert.severity || 'LOW').toLowerCase();
        const time = formatTime(alert.timestamp);
        return `
            <div class="alert-item">
                <span class="alert-severity-dot ${sev}"></span>
                <div class="alert-content">
                    <div class="alert-message">${alert.message}</div>
                    <div class="alert-meta">
                        <span>${time}</span>
                        <span class="badge badge-${sev}">${alert.severity}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// ─── Mini Timeline ───────────────────────────────────────────
function updateMiniTimeline(events) {
    const container = document.getElementById('mini-timeline-container');
    if (!container) return;

    if (!events || events.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No incidents recorded yet.</p></div>';
        return;
    }

    // Show last 10 events
    const recent = events.slice(-10);
    container.innerHTML = `<div class="timeline">${recent.map(evt => {
        const sev = (evt.severity || 'LOW').toLowerCase();
        const time = formatTime(evt.timestamp);
        return `
            <div class="timeline-item">
                <div class="timeline-dot ${sev}"></div>
                <div class="timeline-content">
                    <div class="timeline-header">
                        <span class="timeline-time">${time}</span>
                        <span class="badge badge-${sev}">${evt.severity}</span>
                    </div>
                    <div class="timeline-category">${formatCategory(evt.data_category)}</div>
                    <div class="timeline-desc">${evt.description || ''}</div>
                </div>
            </div>
        `;
    }).join('')}</div>`;
}

// ─── Sessions ────────────────────────────────────────────────
async function loadSessions() {
    const sessions = await fetchJSON('/api/sessions');
    if (!sessions) return;

    // Populate dropdown
    const select = document.getElementById('session-select');
    if (select) {
        const currentOpt = '<option value="">Current Session</option>';
        const opts = sessions.map(s =>
            `<option value="${s.session_id}">${s.session_id} (${s.status})</option>`
        ).join('');
        select.innerHTML = currentOpt + opts;
    }

    // Populate session history list
    const container = document.getElementById('sessions-container');
    if (container && sessions.length > 0) {
        container.innerHTML = sessions.slice(0, 8).map(s => {
            const statusClass = s.status === 'active' ? 'active' : 'ended';
            return `
                <div class="session-item">
                    <div>
                        <div class="session-id">${s.session_id}</div>
                        <div class="session-meta">${formatTime(s.start_time)} • ${s.total_detections || 0} detections</div>
                    </div>
                    <span class="session-badge ${statusClass}">${s.status}</span>
                </div>
            `;
        }).join('');
    }
}

// ─── Evidence Modal ──────────────────────────────────────────
function initModal() {
    const overlay = document.getElementById('evidence-modal');
    const closeBtn = document.getElementById('modal-close-btn');

    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            overlay.classList.remove('active');
        });
    }

    if (overlay) {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.classList.remove('active');
        });
    }

    // ESC key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && overlay) overlay.classList.remove('active');
    });
}

function openEvidence(detection) {
    const overlay = document.getElementById('evidence-modal');
    if (!overlay) return;

    const img = document.getElementById('modal-evidence-img');
    const detType = document.getElementById('modal-detection-type');
    const severity = document.getElementById('modal-severity');
    const timestamp = document.getElementById('modal-timestamp');
    const sessionId = document.getElementById('modal-session-id');
    const description = document.getElementById('modal-description');
    const source = document.getElementById('modal-source');

    if (detection.redacted_path) {
        // Convert path to API URL
        const parts = detection.redacted_path.replace(/\\/g, '/');
        const evidenceIdx = parts.indexOf('evidence/');
        if (evidenceIdx >= 0) {
            img.src = '/api/evidence/' + parts.substring(evidenceIdx + 9);
        } else {
            img.src = '';
        }
    } else {
        img.src = '';
    }

    detType.textContent = formatCategory(detection.data_category || detection.detection_type);
    severity.innerHTML = `<span class="badge badge-${(detection.severity || 'low').toLowerCase()}">${detection.severity}</span>`;
    timestamp.textContent = detection.timestamp || '—';
    sessionId.textContent = detection.session_id || '—';
    description.textContent = detection.description || '—';
    source.textContent = detection.source || '—';

    overlay.classList.add('active');
}

// ─── Utilities ───────────────────────────────────────────────
function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setMonitorDot(id, active) {
    const el = document.getElementById(id);
    if (el) el.className = `monitor-dot ${active ? 'active' : 'inactive'}`;
}

function formatTime(isoString) {
    if (!isoString) return '—';
    try {
        const date = new Date(isoString);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return isoString.split('T')[1]?.split('.')[0] || isoString;
    }
}

function formatCategory(category) {
    if (!category) return '—';
    return category
        .replace(/_/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase());
}

// ─── GAP 8: Server-Sent Events (SSE) Live Feed ──────────────
(function initSSE() {
    if (typeof EventSource === 'undefined') return; // Browser doesn't support SSE

    try {
        const evtSource = new EventSource('/api/stream');

        evtSource.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);

                // Only process detection-type events with status info
                if (data.type === 'status_update' || data.detection_type) {
                    // Try to append to detections table (logs page)
                    const tbody = document.getElementById('logs-tbody');
                    if (tbody && data.detection_type) {
                        const sev = (data.severity || 'LOW').toLowerCase();
                        const time = formatTime(data.timestamp);
                        const cat = formatCategory(data.data_category);
                        const desc = data.description || '—';
                        const source = data.source || '—';

                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td class="log-timestamp">${time}</td>
                            <td><span class="badge badge-${sev}">${data.severity || 'LOW'}</span></td>
                            <td class="log-category">${cat}</td>
                            <td class="log-description">${desc}</td>
                            <td style="font-size:0.75rem;color:var(--text-muted)">${source}</td>
                            <td><span style="color:var(--text-muted);font-size:0.72rem;">Live</span></td>
                        `;
                        // Prepend to show newest first
                        tbody.insertBefore(row, tbody.firstChild);
                    }

                    // Try to append to live feed container (dashboard page)
                    const feedContainer = document.getElementById('live-feed-container');
                    if (feedContainer && data.detection_type) {
                        const sev = (data.severity || 'LOW').toLowerCase();
                        const time = formatTime(data.timestamp);
                        const icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}[data.severity] || '⚪';

                        const feedItem = document.createElement('div');
                        feedItem.className = 'feed-item';
                        feedItem.innerHTML = `
                            <span class="feed-time">${time}</span>
                            <span class="feed-icon ${sev}">${icon}</span>
                            <div class="feed-details">
                                <div class="feed-category">${formatCategory(data.data_category)}</div>
                                <div class="feed-description">${data.description || ''}</div>
                            </div>
                            <span class="badge badge-${sev}">${data.severity || 'LOW'}</span>
                        `;
                        feedContainer.insertBefore(feedItem, feedContainer.firstChild);

                        // Keep feed size manageable
                        while (feedContainer.children.length > 30) {
                            feedContainer.removeChild(feedContainer.lastChild);
                        }
                    }
                }
            } catch (e) {
                // Silently ignore parse errors (e.g. heartbeat comments)
            }
        };

        evtSource.onerror = function() {
            // SSE connection error — will auto-reconnect per browser spec
            console.debug('[SSE] Connection error — will retry');
        };
    } catch (e) {
        console.debug('[SSE] Init failed:', e);
    }
})();

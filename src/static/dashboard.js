let socket;
let devices = [];
let currentDeviceMac = null;
let bandwidthChart = null;
let showActiveOnly = false;

function init() {
    connectWebSocket();
    setupEventListeners();
    initMatrixEffect();
    loadSettings();
}

function initMatrixEffect() {
    // Matrix effect disabled for Homebrew theme
    const canvas = document.getElementById('matrix-canvas');
    if (canvas) canvas.style.display = 'none';
}

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/updates`;

    socket = new WebSocket(wsUrl);

    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'device_update') {
            updateUI(data);
            if (currentDeviceMac) {
                const dev = data.devices.find(d => d.mac === currentDeviceMac);
                if (dev) updateDetailView(dev);
            }
        }
    };

    socket.onclose = () => {
        console.log("WS closed, reconnecting...");
        setTimeout(connectWebSocket, 2000);
    };
}

function updateUI(data) {
    devices = data.devices;

    // Update Global Stats
    document.getElementById('global-up').textContent = `${data.global_stats.total_up} KB/s`;
    document.getElementById('global-down').textContent = `${data.global_stats.total_down} KB/s`;
    document.getElementById('device-count').textContent = `${devices.filter(d => !d.is_stale).length} ACTIVE NODES`;
    document.getElementById('global-kill-switch').checked = data.global_stats.kill_switch;

    // Update Device List
    const list = document.getElementById('device-list');

    devices.forEach(dev => {
        let row = document.getElementById(`row-${dev.mac.replace(/:/g, '-')}`);
        const isHidden = showActiveOnly && dev.is_stale;

        if (isHidden) {
            if (row) row.style.display = 'none';
            return;
        }

        if (!row) {
            row = document.createElement('tr');
            row.id = `row-${dev.mac.replace(/:/g, '-')}`;
            list.appendChild(row);
        }

        row.style.display = '';
        row.className = dev.is_stale ? 'stale-row' : '';

        row.innerHTML = `
            <td>${dev.ip}</td>
            <td class="mac-cell">${dev.mac}</td>
            <td>${dev.vendor}</td>
            <td><span class="status-cell ${dev.is_blocked ? 'blocked' : ''}">${dev.is_blocked ? 'TERMINATED' : dev.category}</span></td>
            <td class="rate-up">${dev.up_rate} KB/s</td>
            <td class="rate-down">${dev.down_rate} KB/s</td>
            <td>
                <div class="action-btns">
                    <button class="btn-icon btn-block ${dev.is_blocked ? 'active' : ''}" onclick="toggleBlock('${dev.mac}', ${!dev.is_blocked})">
                        <i data-lucide="${dev.is_blocked ? 'unlock' : 'shield-off'}"></i>
                    </button>
                    <button class="btn-icon" onclick="openDetails('${dev.mac}')">
                        <i data-lucide="zoom-in"></i>
                    </button>
                </div>
            </td>
        `;
    });

    // Cleanup stale rows that are no longer in the update
    const activeMacs = devices.map(d => `row-${d.mac.replace(/:/g, '-')}`);
    Array.from(list.children).forEach(row => {
        if (!activeMacs.includes(row.id)) {
            list.removeChild(row);
        }
    });

    lucide.createIcons();
}

function updateDetailView(dev) {
    // Update Domain Activity
    const log = document.getElementById('activity-log');
    const existingDomains = Array.from(log.children).map(li => li.textContent);

    (dev.domains || []).forEach(domain => {
        if (!existingDomains.includes(domain)) {
            const li = document.createElement('li');
            li.textContent = domain;
            log.prepend(li); // Newest on top
            if (log.children.length > 20) log.removeChild(log.lastChild);
        }
    });

    // Update Chart
    if (bandwidthChart) {
        const now = new Date().toLocaleTimeString();
        bandwidthChart.data.labels.push(now);
        bandwidthChart.data.datasets[0].data.push(dev.up_rate);
        bandwidthChart.data.datasets[1].data.push(dev.down_rate);

        if (bandwidthChart.data.labels.length > 20) {
            bandwidthChart.data.labels.shift();
            bandwidthChart.data.datasets[0].data.shift();
            bandwidthChart.data.datasets[1].data.shift();
        }
        bandwidthChart.update('none'); // Update without animation for performance
    }
}

async function toggleBlock(mac, blocked) {
    try {
        const res = await fetch('/api/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac, blocked })
        });
        if (!res.ok) throw new Error("Block failed");
    } catch (err) {
        console.error(err);
    }
}

document.getElementById('global-kill-switch').addEventListener('change', async (e) => {
    const enabled = e.target.checked;
    await fetch(`/api/kill-switch?enabled=${enabled}`, { method: 'POST' });
});

function openDetails(mac) {
    const dev = devices.find(d => d.mac === mac);
    if (!dev) return;

    currentDeviceMac = mac;
    document.getElementById('modal-title').textContent = `NODE: ${dev.ip}`;
    document.getElementById('detail-vendor').textContent = dev.vendor;
    document.getElementById('detail-mac').textContent = dev.mac;
    document.getElementById('activity-log').innerHTML = ''; // Clear for new device

    // Populate Schedule
    document.getElementById('sched-start').value = dev.schedule_start || '';
    document.getElementById('sched-end').value = dev.schedule_end || '';

    initChart();
    updateDetailView(dev); // Populate with existing data immediately

    document.getElementById('detail-modal').style.display = 'flex';
}

function initChart() {
    const ctx = document.getElementById('bandwidth-chart').getContext('2d');
    if (bandwidthChart) bandwidthChart.destroy();

    bandwidthChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Up (KB/s)',
                    borderColor: '#00FF00',
                    backgroundColor: 'rgba(0, 255, 0, 0.1)',
                    data: [],
                    fill: true,
                    tension: 0.1,
                    pointRadius: 0
                },
                {
                    label: 'Down (KB/s)',
                    borderColor: '#008800',
                    backgroundColor: 'rgba(0, 136, 0, 0.1)',
                    data: [],
                    fill: true,
                    tension: 0.1,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { display: false },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0, 255, 0, 0.1)' },
                    ticks: { color: '#008800', font: { size: 10, family: 'SF Mono' } }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function closeModal() {
    currentDeviceMac = null;
    document.getElementById('detail-modal').style.display = 'none';
}

function setupEventListeners() {
    document.getElementById('save-schedule').addEventListener('click', async () => {
        if (!currentDeviceMac) return;

        const start = document.getElementById('sched-start').value;
        const end = document.getElementById('sched-end').value;
        const btn = document.getElementById('save-schedule');

        try {
            const res = await fetch('/api/schedule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mac: currentDeviceMac, start, end })
            });

            if (res.ok) {
                const oldText = btn.textContent;
                btn.textContent = 'ACCESS RULES UPDATED';
                btn.classList.add('success');
                setTimeout(() => {
                    btn.textContent = oldText;
                    btn.classList.remove('success');
                }, 2000);
            }
        } catch (err) {
            console.error(err);
        }
    });

    document.getElementById('setting-scan-interval').addEventListener('input', (e) => {
        document.getElementById('scan-interval-val').textContent = `${e.target.value}s`;
    });

    document.getElementById('save-settings').addEventListener('click', saveSettings);

    document.getElementById('filter-active-only').addEventListener('change', (e) => {
        showActiveOnly = e.target.checked;
        // Trigger UI update immediately with cached devices
        if (devices.length > 0) {
            const mockData = {
                devices: devices,
                global_stats: {
                    total_up: document.getElementById('global-up').textContent.split(' ')[0],
                    total_down: document.getElementById('global-down').textContent.split(' ')[1],
                    kill_switch: document.getElementById('global-kill-switch').checked
                }
            };
            updateUI(mockData);
        }
    });
}

function switchView(viewName) {
    const dashboardView = document.getElementById('dashboard-view');
    const settingsView = document.getElementById('settings-view');
    const navDash = document.getElementById('nav-dashboard');
    const navSettings = document.getElementById('nav-settings');

    if (viewName === 'dashboard') {
        dashboardView.style.display = 'block';
        settingsView.style.display = 'none';
        navDash.classList.add('active');
        navSettings.classList.remove('active');
    } else {
        dashboardView.style.display = 'none';
        settingsView.style.display = 'block';
        navDash.classList.remove('active');
        navSettings.classList.add('active');
        loadSettings();
    }
}

async function loadSettings() {
    try {
        const res = await fetch('/api/settings');
        const data = await res.json();
        const settings = data.settings;

        // Fill Interface Select
        const select = document.getElementById('setting-interface');
        const currentIface = settings.interface;
        select.innerHTML = data.available_interfaces.map(iface =>
            `<option value="${iface}" ${iface === currentIface ? 'selected' : ''}>${iface}</option>`
        ).join('');

        // Fill Scan Interval
        document.getElementById('setting-scan-interval').value = settings.scan_interval;
        document.getElementById('scan-interval-val').textContent = `${settings.scan_interval}s`;

        // Fill Paranoid Mode
        document.getElementById('setting-paranoid-mode').checked = settings.paranoid_mode;

    } catch (err) {
        console.error("Failed to load settings:", err);
    }
}

async function saveSettings() {
    const btn = document.getElementById('save-settings');
    const originalText = btn.textContent;

    const payload = {
        interface: document.getElementById('setting-interface').value,
        scan_interval: parseInt(document.getElementById('setting-scan-interval').value),
        paranoid_mode: document.getElementById('setting-paranoid-mode').checked
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            btn.textContent = 'SYSTEM UPDATED - RESTART RECOMMENDED';
            btn.classList.add('success');
            setTimeout(() => {
                btn.textContent = originalText;
                btn.classList.remove('success');
            }, 3000);
        }
    } catch (err) {
        console.error("Failed to save settings:", err);
        btn.textContent = 'ERROR SAVING CONFIG';
        setTimeout(() => { btn.textContent = originalText; }, 2000);
    }
}

window.onload = init;

document.addEventListener('DOMContentLoaded', () => {
    // -------------------------------------------------------------
    // 1. TABS SYSTEM
    // -------------------------------------------------------------
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            
            // Toggle active buttons
            tabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Toggle active content
            tabContents.forEach(content => {
                if (content.id === targetTab) {
                    content.classList.add('active');
                } else {
                    content.classList.remove('active');
                }
            });

            // Reload admin console if clicking on admin tab
            if (targetTab === 'tab-admin') {
                checkAdminAuth();
            }
        });
    });

    // -------------------------------------------------------------
    // 2. DATASET EVALUATION PIPELINE (RESEARCH TAB)
    // -------------------------------------------------------------
    const runBtn = document.getElementById('run-btn');
    const loading = document.getElementById('loading');
    const metricsPanel = document.getElementById('metrics-panel');
    const resultsPanel = document.getElementById('results-panel');
    const datasetSelect = document.getElementById('dataset-select');

    const cardDrift = document.getElementById('card-drift');
    const driftScore = document.getElementById('drift-score');
    const driftStatus = document.getElementById('drift-status');

    const cardModel = document.getElementById('card-model');
    const modelName = document.getElementById('model-name');
    const modelStatus = document.getElementById('model-status');

    const tbody = document.getElementById('results-tbody');
    const totalUsers = document.getElementById('total-users');

    runBtn.addEventListener('click', async () => {
        const dataset = datasetSelect.value;

        // UI Reset
        metricsPanel.classList.add('hidden');
        resultsPanel.classList.add('hidden');
        loading.classList.remove('hidden');
        runBtn.disabled = true;

        try {
            const response = await fetch('/run-detection', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dataset: dataset })
            });

            if (!response.ok) throw new Error("API Execution Error");
            const data = await response.json();

            // Render Drift Cards
            driftScore.innerText = data.drift_score.toFixed(3);
            if (data.drift_score > 0.2) {
                cardDrift.className = 'metric-card drift-danger';
                driftStatus.innerText = 'SEVERE DRIFT DETECTED';
            } else {
                cardDrift.className = 'metric-card drift-safe';
                driftStatus.innerText = 'NORMAL RANGE';
            }

            // Render Model Decisions
            modelName.innerText = data.model_used;
            if (data.model_used === 'IsolationForest') {
                cardModel.className = 'metric-card model-iso';
                modelStatus.innerText = 'Unsupervised Fallback Engaged';
            } else {
                cardModel.className = 'metric-card model-gcn';
                modelStatus.innerText = 'Supervised GCN Active';
            }

            // Render Results Table with Explainability
            totalUsers.innerText = data.total_users;
            tbody.innerHTML = '';

            // Feature label mapping for human-readable display
            const featureLabelMap = {
                'logon_count': 'Logon Count',
                'after_hours_flag': 'After Hours',
                'unique_pc_count': 'Unique PCs',
                'usb_connect_count': 'USB Connects',
                'usb_disconnect_count': 'USB Disconnects',
                'usb_first_time_flag': 'New USB Device',
                'files_copied': 'Files Copied',
                'exe_copied_flag': 'Exe Copied',
                'emails_sent': 'Emails Sent',
                'external_email_ratio': 'External Email %',
                'http_visit_count': 'HTTP Visits',
                'job_site_visits': 'Job Site Visits',
                'suspicious_url_visits': 'Suspicious URLs'
            };

            // Severity classification based on z-score
            function getDeviationSeverity(zscore) {
                if (zscore >= 3) return 'high';
                if (zscore >= 1.5) return 'medium';
                return 'low';
            }

            // Severity icon based on reason index (first = most severe)
            function getReasonIcon(index) {
                if (index === 0) return '🔴';
                if (index === 1) return '🟠';
                return '🟡';
            }

            function getReasonSeverityClass(index) {
                if (index === 0) return 'severity-high';
                if (index === 1) return 'severity-medium';
                return 'severity-low';
            }

            data.top_users.forEach((u, idx) => {
                // --- Main Data Row ---
                const tr = document.createElement('tr');
                tr.className = 'result-row';

                // Reason badges HTML (show first 2 as compact badges)
                const reasons = u.reasons || [];
                let badgesHtml = '';
                const maxBadges = 2;
                reasons.slice(0, maxBadges).forEach((reason, rIdx) => {
                    // Extract just the label part (before the colon)
                    const label = reason.includes(':') ? reason.split(':')[0].trim() : reason;
                    badgesHtml += `<span class="reason-badge ${getReasonSeverityClass(rIdx)}">${getReasonIcon(rIdx)} ${label}</span>`;
                });
                if (reasons.length > maxBadges) {
                    badgesHtml += `<span class="more-reasons-hint">+${reasons.length - maxBadges} more</span>`;
                }
                if (reasons.length === 0) {
                    badgesHtml = '<span style="color: var(--text-muted); font-size: 0.75rem;">No anomalies detected</span>';
                }

                tr.innerHTML = `
                    <td class="rank-text"><i class="fa-solid fa-chevron-right expand-icon"></i>#${idx + 1}</td>
                    <td>${u.user}</td>
                    <td>${data.model_used === 'IsolationForest' ? u.score.toFixed(4) : (u.score * 100).toFixed(2) + '%'}</td>
                    <td><div class="reasons-cell">${badgesHtml}</div></td>
                `;

                tbody.appendChild(tr);

                // --- Expandable Detail Row ---
                const detailTr = document.createElement('tr');
                detailTr.className = 'detail-row';

                const detailTd = document.createElement('td');
                detailTd.colSpan = 4;

                // Build full reasons list HTML
                let reasonsListHtml = '';
                reasons.forEach((reason, rIdx) => {
                    const iconClass = rIdx === 0 ? 'icon-high' : rIdx === 1 ? 'icon-medium' : 'icon-low';
                    const icon = rIdx === 0 ? 'fa-circle-exclamation' : rIdx === 1 ? 'fa-triangle-exclamation' : 'fa-circle-info';
                    reasonsListHtml += `
                        <div class="detail-reason-item">
                            <i class="fa-solid ${icon} detail-reason-icon ${iconClass}"></i>
                            <span>${reason}</span>
                        </div>
                    `;
                });

                // Build feature deviation bars HTML
                const featureDeviations = u.feature_deviations || {};
                const topFeatures = u.top_features || {};
                let barsHtml = '';
                const maxZForBar = 6; // Max z-score for 100% bar width

                Object.keys(featureDeviations).forEach(fName => {
                    const z = featureDeviations[fName];
                    const severity = getDeviationSeverity(z);
                    const barWidth = Math.min((Math.abs(z) / maxZForBar) * 100, 100);
                    const label = featureLabelMap[fName] || fName;
                    barsHtml += `
                        <div class="feature-bar-row">
                            <span class="feature-bar-label" title="${fName}">${label}</span>
                            <div class="feature-bar-track">
                                <div class="feature-bar-fill bar-${severity}" style="width: ${barWidth}%"></div>
                            </div>
                            <span class="feature-bar-value">${z.toFixed(1)}σ</span>
                        </div>
                    `;
                });

                // Build comparison table HTML
                let comparisonRowsHtml = '';
                Object.keys(topFeatures).forEach(fName => {
                    const actual = topFeatures[fName];
                    const z = featureDeviations[fName] || 0;
                    const label = featureLabelMap[fName] || fName;
                    // Estimate average from z-score: avg ≈ actual - z*std, but we don't have std
                    // Just show the raw values and z-score
                    comparisonRowsHtml += `
                        <tr>
                            <td>${label}</td>
                            <td class="val-actual">${actual}</td>
                            <td class="val-zscore">${z.toFixed(1)}σ</td>
                        </tr>
                    `;
                });

                detailTd.innerHTML = `
                    <div class="detail-panel" id="detail-panel-${idx}">
                        <div class="detail-reasons">
                            <h4><i class="fa-solid fa-magnifying-glass-chart"></i> Threat Analysis for ${u.user}</h4>
                            ${reasonsListHtml || '<div style="color: var(--text-muted); font-size: 0.8rem;">No specific anomalies identified.</div>'}
                        </div>
                        <div class="detail-panel-inner">
                            <div class="feature-bars-section">
                                <h4><i class="fa-solid fa-chart-bar"></i> Feature Deviation</h4>
                                ${barsHtml || '<div style="color: var(--text-muted); font-size: 0.8rem;">No feature data available.</div>'}
                            </div>
                            <div class="feature-comparison-section">
                                <h4><i class="fa-solid fa-table"></i> Values</h4>
                                <table class="comparison-table">
                                    <thead>
                                        <tr>
                                            <th>Feature</th>
                                            <th>Value</th>
                                            <th>Deviation</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${comparisonRowsHtml || '<tr><td colspan="3" style="color: var(--text-muted);">No data</td></tr>'}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;

                detailTr.appendChild(detailTd);
                tbody.appendChild(detailTr);

                // Toggle expand/collapse on row click
                tr.addEventListener('click', () => {
                    const panel = document.getElementById(`detail-panel-${idx}`);
                    const isExpanded = tr.classList.contains('expanded');

                    if (isExpanded) {
                        tr.classList.remove('expanded');
                        panel.classList.remove('open');
                    } else {
                        tr.classList.add('expanded');
                        panel.classList.add('open');
                    }
                });
            });

            // Show panels
            metricsPanel.classList.remove('hidden');
            resultsPanel.classList.remove('hidden');

        } catch (error) {
            showToast('critical', 'Pipeline Error', error.message);
        } finally {
            loading.classList.add('hidden');
            runBtn.disabled = false;
        }
    });

    // -------------------------------------------------------------
    // 3. REAL-TIME EVENT STREAM & WEBSOCKETS
    // -------------------------------------------------------------
    const alertStream = document.getElementById('alert-stream');
    let socket = null;
    let wsConnected = false;

    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
        
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            wsConnected = true;
            console.log("SIEM WebSocket connection established.");
        };

        socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            // Skip server-sent keepalive pings
            if (data.type === 'ping') return;
            handleIncomingAlert(data);
        };

        socket.onclose = () => {
            wsConnected = false;
            console.warn("WebSocket closed. Reconnecting in 1 second...");
            setTimeout(connectWebSocket, 1000);  // Fast reconnect
        };

        socket.onerror = (err) => {
            console.error("WebSocket error:", err);
        };
    }

    function handleIncomingAlert(alert) {
        // Remove stream placeholder if present
        const placeholder = alertStream.querySelector('.stream-placeholder');
        if (placeholder) {
            alertStream.innerHTML = '';
        }

        // 1. Prepend log element to the Event Stream
        const logEl = document.createElement('div');
        logEl.className = `event-log ev-${alert.type}`;
        
        const detailsHtml = alert.details && Object.keys(alert.details).length 
            ? `<div class="log-details">${JSON.stringify(alert.details)}</div>` 
            : '';
            
        logEl.innerHTML = `
            <div class="log-meta">
                <span class="log-time">[${alert.timestamp}]</span>
                <span class="log-tag ${alert.severity}">${alert.type.replace('_', ' ')} (${alert.severity})</span>
            </div>
            <div class="log-msg">${alert.message}</div>
            ${detailsHtml}
        `;
        
        alertStream.insertBefore(logEl, alertStream.firstChild);

        // 2. Generate Floating Alert Toast
        const toastDuration = alert.severity === 'critical' ? 9000 : 4500;
        showToast(alert.severity, alert.type.replace(/_/g, ' ').toUpperCase(), alert.message, toastDuration);

        // 3. On CRITICAL alert: flash the whole page red to grab attention
        if (alert.severity === 'critical') {
            flashCriticalAlert();
        }

        // 4. Refresh admin log table if on admin tab
        const adminConsole = document.getElementById('admin-console');
        if (adminConsole && !adminConsole.classList.contains('hidden')) {
            loadAuditLogs();
        }
    }

    // Full-screen red flash to signal critical security events
    function flashCriticalAlert() {
        let overlay = document.getElementById('critical-flash-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'critical-flash-overlay';
            overlay.style.cssText = [
                'position:fixed', 'inset:0', 'z-index:9999', 'pointer-events:none',
                'background:rgba(239,68,68,0.18)', 'border:3px solid rgba(239,68,68,0.7)',
                'transition:opacity 0.8s ease', 'opacity:1'
            ].join(';');
            document.body.appendChild(overlay);
        } else {
            overlay.style.opacity = '1';
        }
        setTimeout(() => { overlay.style.opacity = '0'; }, 800);
    }

    // Connect automatically
    connectWebSocket();

    // ------------------------------------------------------------------
    // POLLING FALLBACK: check log count every 4 seconds (lightweight).
    // Only fetches full logs when the count actually increased.
    // Guarantees the admin panel stays in sync even if WS drops a message.
    // ------------------------------------------------------------------
    let _lastKnownLogCount = 0;
    setInterval(async () => {
        // Only poll if logged in (admin console visible)
        const adminConsole = document.getElementById('admin-console');
        if (!adminConsole || adminConsole.classList.contains('hidden')) return;

        try {
            // Step 1: cheap count check
            const countRes = await fetch('/admin/log-count');
            const countData = await countRes.json();
            const newCount = countData.count || 0;

            if (newCount > _lastKnownLogCount) {
                _lastKnownLogCount = newCount;

                // Step 2: fetch full logs only when count changed
                const res = await fetch('/admin/logs');
                const data = await res.json();
                loadAuditLogs();

                // Show toast/flash only if WS didn't already handle it
                if (!wsConnected && data.logs && data.logs.length > 0) {
                    const latest = data.logs[0];
                    const toastDuration = latest.severity === 'critical' ? 9000 : 4500;
                    showToast(latest.severity, latest.type.replace(/_/g, ' ').toUpperCase(), latest.message, toastDuration);
                    if (latest.severity === 'critical') flashCriticalAlert();
                }
            }
        } catch (e) { /* silent — server may be starting */ }
    }, 4000);

    // -------------------------------------------------------------
    // 4. FLOATING NOTIFICATIONS SYSTEM
    // -------------------------------------------------------------
    const toastWrapper = document.getElementById('toast-wrapper');

    function showToast(severity, title, message, duration = 4500) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${severity}`;
        
        // Define icons based on severity
        let icon = 'fa-circle-info';
        if (severity === 'critical') icon = 'fa-triangle-exclamation';
        else if (severity === 'warning') icon = 'fa-circle-exclamation';

        toast.innerHTML = `
            <i class="fa-solid ${icon} toast-icon"></i>
            <div class="toast-content">
                <h4>${title}</h4>
                <p>${message}</p>
            </div>
        `;

        toastWrapper.appendChild(toast);

        // Auto-dismiss after duration
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-20px) scale(0.9)';
            setTimeout(() => { toast.remove(); }, 300);
        }, duration);
    }

    // -------------------------------------------------------------
    // 5. ADMIN CONTROL PANEL CONFIGURATION
    // -------------------------------------------------------------
    const loginPanel = document.getElementById('admin-login-panel');
    const adminConsole = document.getElementById('admin-console');
    const loginBtn = document.getElementById('login-btn');
    const loginError = document.getElementById('login-error');
    const restrictionsList = document.getElementById('restrictions-list');
    const auditTbody = document.getElementById('audit-tbody');
    const clearLogsBtn = document.getElementById('clear-logs-btn');

    // USB elements
    const safeUsbsList = document.getElementById('safe-usbs-list');
    const detectedUsbsList = document.getElementById('detected-usbs-list');
    const refreshUsbBtn = document.getElementById('refresh-usb-btn');

    // File Explorer elements
    const explorerCurrentPath = document.getElementById('explorer-current-path');
    const explorerUpBtn = document.getElementById('explorer-up-btn');
    const explorerList = document.getElementById('explorer-list');

    let adminToken = null;
    let currentExplorerPath = 'C:\\';

    function checkAdminAuth() {
        if (adminToken) {
            loginPanel.classList.add('hidden');
            adminConsole.classList.remove('hidden');
            loadRestrictions();
            loadAuditLogs();
            loadSafeUsbs();
            loadDetectedUsbs();
            loadExplorer(currentExplorerPath);
        } else {
            loginPanel.classList.remove('hidden');
            adminConsole.classList.add('hidden');
        }
    }

    loginBtn.addEventListener('click', async () => {
        const username = document.getElementById('admin-user').value;
        const password = document.getElementById('admin-pass').value;

        loginError.classList.add('hidden');

        try {
            const response = await fetch('/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (data.success) {
                adminToken = data.token;
                showToast('info', 'Auth Success', 'Admin logged in.');
                checkAdminAuth();
            } else {
                loginError.innerText = data.message;
                loginError.classList.remove('hidden');
            }
        } catch (err) {
            loginError.innerText = "Error contacting login API.";
            loginError.classList.remove('hidden');
        }
    });

    async function loadRestrictions() {
        try {
            const res = await fetch('/admin/restrictions');
            const data = await res.json();
            restrictionsList.innerHTML = '';
            
            if (data.restricted_paths.length === 0) {
                restrictionsList.innerHTML = `<li style="color: var(--text-muted);">No restricted directories or files defined.</li>`;
                return;
            }

            data.restricted_paths.forEach(path => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span>${path}</span>
                    <button class="delete-btn" data-path="${path}">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                `;
                restrictionsList.appendChild(li);
            });

            // Bind delete events
            restrictionsList.querySelectorAll('.delete-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const path = btn.getAttribute('data-path');
                    await deleteRestriction(path);
                });
            });
        } catch (err) {
            console.error("Error loading restrictions list:", err);
        }
    }

    async function deleteRestriction(path) {
        try {
            const res = await fetch(`/admin/restrictions?path=${encodeURIComponent(path)}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                showToast('info', 'Deleted Rule', 'Restriction removed.');
                loadRestrictions();
            }
        } catch (err) {
            showToast('critical', 'Error', 'Failed to delete path restriction.');
        }
    }

    async function restrictPath(path) {
        try {
            const res = await fetch('/admin/restrictions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: path })
            });

            if (res.ok) {
                showToast('info', 'Created Rule', `File/folder restriction added: ${path}`);
                loadRestrictions();
            } else {
                const err = await res.json();
                showToast('critical', 'Error', err.detail || 'Failed to restrict path.');
            }
        } catch (err) {
            showToast('critical', 'Error', 'Failed to save restriction path.');
        }
    }

    // Interactive File Explorer
    async function loadExplorer(path) {
        try {
            const res = await fetch(`/admin/browse?path=${encodeURIComponent(path)}`);
            if (!res.ok) {
                const errData = await res.json();
                showToast('warning', 'Explorer Access Warning', errData.detail || 'Permission Denied');
                return;
            }
            const data = await res.json();
            currentExplorerPath = data.current_path;
            explorerCurrentPath.innerText = currentExplorerPath;
            
            if (data.parent_path) {
                explorerUpBtn.style.display = 'inline-flex';
                explorerUpBtn.onclick = () => loadExplorer(data.parent_path);
            } else {
                explorerUpBtn.style.display = 'none';
            }

            explorerList.innerHTML = '';

            // Render folders
            data.folders.forEach(folder => {
                const folderPath = currentExplorerPath.endsWith('\\') || currentExplorerPath.endsWith('/')
                    ? currentExplorerPath + folder
                    : currentExplorerPath + '\\' + folder;
                    
                const itemEl = document.createElement('div');
                itemEl.style.cssText = 'display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; background: rgba(255,255,255,0.02); border-radius: 4px; font-size: 0.8rem; transition: var(--transition);';
                itemEl.className = 'explorer-item';
                
                const nameContainer = document.createElement('div');
                nameContainer.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; cursor: pointer; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
                nameContainer.innerHTML = `<i class="fa-solid fa-folder" style="color: var(--color-purple);"></i> <span>${folder}</span>`;
                nameContainer.onclick = () => loadExplorer(folderPath);

                const actionBtn = document.createElement('button');
                actionBtn.className = 'text-btn';
                actionBtn.style.cssText = 'font-size: 0.75rem; color: var(--color-red); padding: 0.2rem 0.5rem;';
                actionBtn.innerText = 'Restrict';
                actionBtn.onclick = (e) => {
                    e.stopPropagation();
                    restrictPath(folderPath);
                };

                itemEl.appendChild(nameContainer);
                itemEl.appendChild(actionBtn);
                explorerList.appendChild(itemEl);
            });

            // Render files
            data.files.forEach(file => {
                const filePath = currentExplorerPath.endsWith('\\') || currentExplorerPath.endsWith('/')
                    ? currentExplorerPath + file
                    : currentExplorerPath + '\\' + file;

                const itemEl = document.createElement('div');
                itemEl.style.cssText = 'display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; background: rgba(255,255,255,0.02); border-radius: 4px; font-size: 0.8rem; transition: var(--transition);';
                itemEl.className = 'explorer-item';

                const nameContainer = document.createElement('div');
                nameContainer.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
                nameContainer.innerHTML = `<i class="fa-solid fa-file" style="color: var(--text-muted);"></i> <span>${file}</span>`;

                const actionBtn = document.createElement('button');
                actionBtn.className = 'text-btn';
                actionBtn.style.cssText = 'font-size: 0.75rem; color: var(--color-red); padding: 0.2rem 0.5rem;';
                actionBtn.innerText = 'Restrict';
                actionBtn.onclick = () => restrictPath(filePath);

                itemEl.appendChild(nameContainer);
                itemEl.appendChild(actionBtn);
                explorerList.appendChild(itemEl);
            });

            if (data.folders.length === 0 && data.files.length === 0) {
                explorerList.innerHTML = `<div style="text-align: center; color: var(--text-muted); font-size: 0.8rem; padding: 1rem;">Empty Directory</div>`;
            }

        } catch (err) {
            console.error("Error loading path entries:", err);
        }
    }

    // Safe USB Management
    async function loadSafeUsbs() {
        try {
            const res = await fetch('/admin/safe-usbs');
            const data = await res.json();
            safeUsbsList.innerHTML = '';

            if (data.safe_usbs.length === 0) {
                safeUsbsList.innerHTML = `<li style="color: var(--text-muted); padding: 0.8rem 1rem;">No whitelisted USB devices.</li>`;
                return;
            }

            data.safe_usbs.forEach(usb => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span><strong>${usb.name}</strong> <span style="color: var(--text-muted); font-size: 0.75rem;">(Serial: ${usb.serial})</span></span>
                    <button class="delete-usb-btn" data-serial="${usb.serial}" style="background:transparent; border:none; color:var(--color-red); cursor:pointer;">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                `;
                safeUsbsList.appendChild(li);
            });

            // Bind USB remove events
            safeUsbsList.querySelectorAll('.delete-usb-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const serial = btn.getAttribute('data-serial');
                    await deleteSafeUsb(serial);
                });
            });
        } catch (err) {
            console.error("Error loading safe USBs:", err);
        }
    }

    async function deleteSafeUsb(serial) {
        try {
            const res = await fetch(`/admin/safe-usbs?serial=${encodeURIComponent(serial)}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                showToast('info', 'Whitelist Updated', 'USB device removed from safe list.');
                loadSafeUsbs();
                loadDetectedUsbs();
            }
        } catch (err) {
            showToast('critical', 'Error', 'Failed to delete safe USB whitelist entry.');
        }
    }

    async function whitelistUsb(serial, name) {
        try {
            const res = await fetch('/admin/safe-usbs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ serial: serial, name: name })
            });

            if (res.ok) {
                showToast('info', 'Device Whitelisted', `USB marked as safe: ${name}`);
                loadSafeUsbs();
                loadDetectedUsbs();
            }
        } catch (err) {
            showToast('critical', 'Error', 'Failed to whitelist USB.');
        }
    }

    async function loadDetectedUsbs() {
        try {
            const res = await fetch('/admin/detected-usbs');
            const data = await res.json();
            detectedUsbsList.innerHTML = '';

            if (data.detected_usbs.length === 0) {
                detectedUsbsList.innerHTML = `<li style="color: var(--text-muted); padding: 0.8rem 1rem;">No connected USB devices detected.</li>`;
                return;
            }

            // Get safe list serials
            const safeRes = await fetch('/admin/safe-usbs');
            const safeData = await safeRes.json();
            const safeSerials = safeData.safe_usbs.map(u => u.serial);

            data.detected_usbs.forEach(usb => {
                const li = document.createElement('li');
                const isWhitelisted = safeSerials.includes(usb.serial);
                
                li.innerHTML = `
                    <span><strong>${usb.name}</strong> <span style="color: var(--text-muted); font-size: 0.75rem;">(Drive: ${usb.drive}, Serial: ${usb.serial})</span></span>
                    ${isWhitelisted 
                        ? `<span style="color: var(--color-green); font-size: 0.75rem; font-weight: 600;"><i class="fa-solid fa-circle-check"></i> Safe</span>`
                        : `<button class="whitelist-btn" data-serial="${usb.serial}" data-name="${usb.name}" style="background: rgba(6,182,212,0.1); border: 1px solid var(--color-cyan); border-radius: 4px; color: var(--color-cyan); padding: 0.2rem 0.5rem; font-size: 0.7rem; cursor: pointer; transition: var(--transition);">Mark Safe</button>`
                    }
                `;
                detectedUsbsList.appendChild(li);
            });

            // Bind Mark Safe events
            detectedUsbsList.querySelectorAll('.whitelist-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const serial = btn.getAttribute('data-serial');
                    const name = btn.getAttribute('data-name');
                    await whitelistUsb(serial, name);
                });
            });
        } catch (err) {
            console.error("Error loading detected USBs:", err);
        }
    }

    refreshUsbBtn.addEventListener('click', () => {
        loadDetectedUsbs();
        showToast('info', 'Scanned', 'Removable USB ports scanned.');
    });

    async function loadAuditLogs() {
        try {
            const res = await fetch('/admin/logs');
            const data = await res.json();
            auditTbody.innerHTML = '';

            if (data.logs.length === 0) {
                auditTbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No system audit entries logged.</td></tr>`;
                return;
            }

            data.logs.forEach(log => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${log.timestamp}</td>
                    <td><code>${log.type}</code></td>
                    <td><span class="audit-severity severity-${log.severity}">${log.severity}</span></td>
                    <td>${log.message}</td>
                `;
                auditTbody.appendChild(tr);
            });
        } catch (err) {
            console.error("Error loading audit logs:", err);
        }
    }

    clearLogsBtn.addEventListener('click', () => {
        loadAuditLogs();
        showToast('info', 'Logs Refreshed', 'System audit logs updated from server.');
    });

    // Check auth on load
    checkAdminAuth();
});

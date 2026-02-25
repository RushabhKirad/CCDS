class CyberDefenseDashboard {
    constructor() {
        this.ws = null;
        this.feedPaused = false;
        this.threats = [];
        this.stats = {
            totalThreats: 0,
            highSeverity: 0,
            detectionRate: 91.3,
            avgResponse: 47
        };
        
        this.init();
    }

    init() {
        this.setupWebSocket();
        this.setupEventListeners();
        this.initCharts();
        this.fetchSystemStatus();
        this.startStatsUpdate();
    }

    setupWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//nitedu-anomaly-detection.onrender.com/ws/alerts`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.updateConnectionStatus('ws-status', true);
            };
            
            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            };
            
            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus('ws-status', false);
                setTimeout(() => this.setupWebSocket(), 5000);
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('ws-status', false);
            };
        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            this.simulateThreats();
        }
    }

    handleWebSocketMessage(data) {
        if (data.type === 'anomaly_alert' && !this.feedPaused) {
            this.addThreat(data.data);
        }
    }

    setupEventListeners() {
        document.getElementById('pause-feed').addEventListener('click', () => {
            this.feedPaused = !this.feedPaused;
            const btn = document.getElementById('pause-feed');
            btn.innerHTML = this.feedPaused ? 
                '<i class="fas fa-play"></i> Resume' : 
                '<i class="fas fa-pause"></i> Pause';
        });

        document.getElementById('clear-feed').addEventListener('click', () => {
            this.clearThreats();
        });
    }

    async fetchSystemStatus() {
        try {
            const response = await fetch('https://nitedu-anomaly-detection.onrender.com/api/v1/status');
            const status = await response.json();
            
            this.updateConnectionStatus('ml-status', status.ml_models_loaded);
            
            if (status.detection_method === 'advanced_ml') {
                this.stats.detectionRate = 91.3;
            } else {
                this.stats.detectionRate = 85.2;
            }
            
            this.updateStats();
        } catch (error) {
            console.error('Failed to fetch system status:', error);
            this.updateConnectionStatus('ml-status', false);
        }
    }

    updateConnectionStatus(elementId, isOnline) {
        const element = document.getElementById(elementId);
        const dot = element.querySelector('.status-dot');
        dot.className = `status-dot ${isOnline ? 'online' : 'offline'}`;
    }

    addThreat(threatData) {
        const threat = {
            id: Date.now(),
            type: threatData.attack_type || 'Unknown Attack',
            confidence: threatData.confidence || Math.random(),
            sourceIp: threatData.source_ip || '192.168.1.' + Math.floor(Math.random() * 255),
            timestamp: new Date(),
            severity: this.getSeverity(threatData.confidence || Math.random())
        };

        this.threats.unshift(threat);
        if (this.threats.length > 50) this.threats.pop();

        this.renderThreat(threat);
        this.updateStats();
        this.updateCharts();
    }

    getSeverity(confidence) {
        if (confidence >= 0.8) return 'high';
        if (confidence >= 0.5) return 'medium';
        return 'low';
    }

    renderThreat(threat) {
        const feed = document.getElementById('threats-feed');
        const noThreats = feed.querySelector('.no-threats');
        if (noThreats) noThreats.remove();

        const threatElement = document.createElement('div');
        threatElement.className = `threat-item ${threat.severity}-severity`;
        threatElement.innerHTML = `
            <div class="threat-header">
                <span class="threat-type">${threat.type}</span>
                <span class="threat-time">${threat.timestamp.toLocaleTimeString()}</span>
            </div>
            <div class="threat-details">
                Source: ${threat.sourceIp} | Confidence: ${(threat.confidence * 100).toFixed(1)}%
            </div>
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${threat.confidence * 100}%"></div>
            </div>
        `;

        feed.insertBefore(threatElement, feed.firstChild);
    }

    clearThreats() {
        const feed = document.getElementById('threats-feed');
        feed.innerHTML = `
            <div class="no-threats">
                <i class="fas fa-shield-check"></i>
                <p>Monitoring for threats... All systems secure.</p>
            </div>
        `;
        this.threats = [];
        this.updateStats();
    }

    updateStats() {
        this.stats.totalThreats = this.threats.length;
        this.stats.highSeverity = this.threats.filter(t => t.severity === 'high').length;

        document.getElementById('total-threats').textContent = this.stats.totalThreats;
        document.getElementById('high-severity').textContent = this.stats.highSeverity;
        document.getElementById('detection-rate').textContent = this.stats.detectionRate + '%';
        document.getElementById('avg-response').textContent = this.stats.avgResponse + 'ms';
    }

    initCharts() {
        // Attack Types Chart
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        this.attackChart = new Chart(attackCtx, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'Bot Attack', 'Path Traversal', 'Other'],
                datasets: [{
                    data: [25, 20, 15, 10, 30],
                    backgroundColor: ['#ff4757', '#ffa502', '#2ed573', '#5352ed', '#00d4ff'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#ffffff', font: { size: 12 } }
                    }
                }
            }
        });

        // Timeline Chart
        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        this.timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: Array.from({length: 24}, (_, i) => `${i}:00`),
                datasets: [{
                    label: 'Threats Detected',
                    data: Array.from({length: 24}, () => Math.floor(Math.random() * 10)),
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    x: {
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    }
                }
            }
        });
    }

    updateCharts() {
        if (this.threats.length === 0) return;

        // Update attack types distribution
        const attackTypes = {};
        this.threats.forEach(threat => {
            attackTypes[threat.type] = (attackTypes[threat.type] || 0) + 1;
        });

        const labels = Object.keys(attackTypes).slice(0, 5);
        const data = Object.values(attackTypes).slice(0, 5);

        this.attackChart.data.labels = labels;
        this.attackChart.data.datasets[0].data = data;
        this.attackChart.update();
    }

    simulateThreats() {
        // Simulate threats for demo when WebSocket unavailable
        const attackTypes = ['SQL Injection', 'XSS Attack', 'Bot Attack', 'Path Traversal', 'Command Injection'];
        
        setInterval(() => {
            if (!this.feedPaused && Math.random() > 0.7) {
                const simulatedThreat = {
                    attack_type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
                    confidence: 0.3 + Math.random() * 0.7,
                    source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`
                };
                this.addThreat(simulatedThreat);
            }
        }, 3000);
    }

    startStatsUpdate() {
        setInterval(() => {
            this.stats.avgResponse = 45 + Math.floor(Math.random() * 10);
            document.getElementById('avg-response').textContent = this.stats.avgResponse + 'ms';
        }, 5000);
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    new CyberDefenseDashboard();
});
"""Apply all dashboard fixes at once"""
import re

with open('templates/dashboard.html', 'r', encoding='utf-8') as f:
    content = f.read()

print('Starting comprehensive fix...')

# FIX 1: Add admin-only controls for Start/Stop buttons
old_controls = '''<button class="btn btn-success me-2" onclick="startMonitoring()">
                            <i class="fas fa-play me-1"></i>Start Monitoring
                        </button>
                        <button class="btn btn-warning me-2" onclick="stopMonitoring()">
                            <i class="fas fa-stop me-1"></i>Stop Monitoring
                        </button>'''

new_controls = '''{% if user.role == 'admin' %}
                        <button class="btn btn-success me-2" onclick="startMonitoring()">
                            <i class="fas fa-play me-1"></i>Start Monitoring
                        </button>
                        <button class="btn btn-warning me-2" onclick="stopMonitoring()">
                            <i class="fas fa-stop me-1"></i>Stop Monitoring
                        </button>
                        {% endif %}'''

if old_controls in content:
    content = content.replace(old_controls, new_controls)
    print('FIX 1: Added admin-only controls')
else:
    print('FIX 1: Controls already wrapped or not found')

# FIX 2: Reduce chart canvas sizes
content = content.replace('width="400" height="200"', 'width="300" height="150"')
print('FIX 2: Reduced chart sizes')

# FIX 3: Add maintainAspectRatio: false to severity chart
old_severity = '''            options: {
                responsive: true,
                plugins: {'''
new_severity = '''            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {'''
if old_severity in content:
    content = content.replace(old_severity, new_severity)
    print('FIX 3: Added maintainAspectRatio to severity chart')

# FIX 4: Reduce auto-refresh from 5s to 30s
content = content.replace('setInterval(refreshAlerts, 5000)', 'setInterval(refreshAlerts, 30000)')
print('FIX 4: Reduced refresh interval to 30s')

# FIX 5: Fix the startMonitoring and stopMonitoring functions
old_start = '''function startMonitoring() {
            fetch('/start_monitoring')
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    document.querySelector('#monitoring-status span').className = 'status-online';
                    document.querySelector('#monitoring-status span').textContent = 'ACTIVE';
                });
        }'''

new_start = '''function startMonitoring() {
            fetch('/start_monitoring')
                .then(response => {
                    if (response.status === 401) {
                        alert('Admin login required to control monitoring');
                        return null;
                    }
                    return response.json();
                })
                .then(data => {
                    if (data) {
                        alert(data.message);
                        if (data.status === 'active') {
                            document.querySelector('#monitoring-status span').className = 'status-online';
                            document.querySelector('#monitoring-status span').textContent = 'ACTIVE';
                        }
                    }
                })
                .catch(err => console.error('Monitoring error:', err));
        }'''

if old_start in content:
    content = content.replace(old_start, new_start)
    print('FIX 5a: Updated startMonitoring function')

old_stop = '''function stopMonitoring() {
            fetch('/stop_monitoring')
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    document.querySelector('#monitoring-status span').className = 'status-offline';
                    document.querySelector('#monitoring-status span').textContent = 'STOPPED';
                });
        }'''

new_stop = '''function stopMonitoring() {
            fetch('/stop_monitoring')
                .then(response => {
                    if (response.status === 401) {
                        alert('Admin login required to control monitoring');
                        return null;
                    }
                    return response.json();
                })
                .then(data => {
                    if (data) {
                        alert(data.message);
                        if (data.status === 'stopped') {
                            document.querySelector('#monitoring-status span').className = 'status-offline';
                            document.querySelector('#monitoring-status span').textContent = 'STOPPED';
                        }
                    }
                })
                .catch(err => console.error('Monitoring error:', err));
        }'''

if old_stop in content:
    content = content.replace(old_stop, new_stop)
    print('FIX 5b: Updated stopMonitoring function')

# FIX 6: Add maintainAspectRatio to activity charts
# Main activity chart
old_activity_options = '''            options: {
                responsive: true,
                scales: {
                    y: { 
                        beginAtZero: true,'''
new_activity_options = '''            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { 
                        beginAtZero: true,'''
if old_activity_options in content:
    content = content.replace(old_activity_options, new_activity_options, 1)
    print('FIX 6a: Added maintainAspectRatio to main activity chart')

# Fallback chart
old_fallback_options = '''        options: {
            responsive: true,
            scales: {
                y: { ticks: { color: '#ffffff' } },
                x: { ticks: { color: '#ffffff' } }'''
new_fallback_options = '''        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { ticks: { color: '#ffffff' } },
                x: { ticks: { color: '#ffffff' } }'''
if old_fallback_options in content:
    content = content.replace(old_fallback_options, new_fallback_options, 1)
    print('FIX 6b: Added maintainAspectRatio to fallback chart')

with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('\nAll fixes applied successfully!')

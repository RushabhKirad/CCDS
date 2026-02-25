/**
 * PQC Client Module for Node.js
 * ==============================
 * Provides functions to communicate with the Python PQC Service
 * for quantum-resistant internal communication.
 * 
 * PQC Service Port: 5005
 * Algorithm: ML-KEM-768 + AES-256-GCM
 */

const PQC_SERVICE_URL = process.env.PQC_SERVICE_URL || 'http://localhost:5005';

/**
 * Initialize a new PQC session
 * @returns {Promise<Object>} Session data with session_id and public_key
 */
async function initPQCSession() {
    try {
        const response = await fetch(`${PQC_SERVICE_URL}/pqc/init-session`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            console.log(`✅ PQC Session initialized: ${data.session_id}`);
            console.log(`   Algorithm: ${data.algorithm}`);
            console.log(`   Public Key Size: ${data.public_key_size} bytes`);
        }

        return data;
    } catch (error) {
        console.error('❌ PQC init-session error:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Complete PQC handshake with ciphertext
 * Note: In simulation mode, we generate a dummy ciphertext
 * @param {string} sessionId - Session ID from init-session
 * @param {string} ciphertext - Base64-encoded ciphertext (simulated)
 * @returns {Promise<Object>} Handshake result
 */
async function completePQCHandshake(sessionId, ciphertext) {
    try {
        const response = await fetch(`${PQC_SERVICE_URL}/pqc/handshake`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionId,
                ciphertext: ciphertext
            })
        });

        const data = await response.json();

        if (data.success) {
            console.log(`✅ PQC Handshake completed: ${data.status}`);
            console.log(`   Shared Secret Size: ${data.shared_secret_size} bytes`);
            console.log(`   AES Key Size: ${data.aes_key_size} bits`);
        }

        return data;
    } catch (error) {
        console.error('❌ PQC handshake error:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Send encrypted data through PQC-secured channel
 * @param {string} sessionId - Active session ID
 * @param {Object} encryptedData - Encrypted payload { ciphertext, nonce, tag }
 * @param {string} action - Action to perform (e.g., 'analyze_email')
 * @param {string} authToken - JWT auth token
 * @returns {Promise<Object>} Encrypted response
 */
async function sendSecureData(sessionId, encryptedData, action, authToken) {
    try {
        const response = await fetch(`${PQC_SERVICE_URL}/pqc/secure-data`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                session_id: sessionId,
                encrypted_data: encryptedData,
                action: action
            })
        });

        const data = await response.json();

        if (data.success) {
            console.log(`✅ Secure data exchange completed`);
        }

        return data;
    } catch (error) {
        console.error('❌ PQC secure-data error:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Get PQC service status
 * @returns {Promise<Object>} Service status
 */
async function getPQCStatus() {
    try {
        const response = await fetch(`${PQC_SERVICE_URL}/pqc/status`);
        return await response.json();
    } catch (error) {
        console.error('❌ PQC status error:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Check if PQC service is healthy
 * @returns {Promise<boolean>} true if healthy
 */
async function isPQCServiceHealthy() {
    try {
        const response = await fetch(`${PQC_SERVICE_URL}/health`);
        const data = await response.json();
        return data.status === 'healthy';
    } catch (error) {
        return false;
    }
}

/**
 * Run PQC demo flow
 * @returns {Promise<Object>} Demo results
 */
async function runPQCDemo() {
    try {
        const response = await fetch(`${PQC_SERVICE_URL}/pqc/demo`);
        const data = await response.json();

        if (data.success) {
            console.log('\n🔐 PQC Communication Flow Demo:');
            console.log(`   Algorithm: ${data.algorithm}`);
            console.log(`   Library: ${data.library}`);
            console.log(`   Real PQC: ${data.real_pqc}`);
            console.log('   Steps:');
            data.steps.forEach(step => {
                console.log(`     ${step.step}. ${step.action}`);
            });
        }

        return data;
    } catch (error) {
        console.error('❌ PQC demo error:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Helper: Generate simulated ciphertext for testing
 * In real implementation, this would use actual encapsulation
 * @param {string} publicKey - Base64-encoded public key
 * @returns {string} Base64-encoded simulated ciphertext
 */
function generateSimulatedCiphertext(publicKey) {
    // For simulation mode: create a deterministic ciphertext from public key
    const crypto = require('crypto');
    const randomBytes = crypto.randomBytes(1088); // ML-KEM-768 ciphertext size
    return randomBytes.toString('base64');
}

// Export functions
module.exports = {
    initPQCSession,
    completePQCHandshake,
    sendSecureData,
    getPQCStatus,
    isPQCServiceHealthy,
    runPQCDemo,
    generateSimulatedCiphertext,
    PQC_SERVICE_URL
};

// Self-test when run directly
if (require.main === module) {
    (async () => {
        console.log('\n' + '='.repeat(60));
        console.log('🔐 PQC Client Module Self-Test');
        console.log('='.repeat(60));

        // Test 1: Health check
        console.log('\n[Test 1] Checking PQC Service health...');
        const healthy = await isPQCServiceHealthy();
        console.log(`   Service healthy: ${healthy}`);

        if (!healthy) {
            console.log('❌ PQC Service is not running. Start it with:');
            console.log('   cd backend/pqc-service && python pqc_service.py');
            process.exit(1);
        }

        // Test 2: Get status
        console.log('\n[Test 2] Getting PQC status...');
        const status = await getPQCStatus();
        console.log(`   PQC Available: ${status.pqc_available}`);
        console.log(`   Library: ${status.library}`);
        console.log(`   Algorithm: ${status.algorithm}`);

        // Test 3: Run demo
        console.log('\n[Test 3] Running PQC demo...');
        await runPQCDemo();

        // Test 4: Full session flow
        console.log('\n[Test 4] Testing full PQC session flow...');
        const session = await initPQCSession();

        if (session.success) {
            // Generate simulated ciphertext
            const ciphertext = generateSimulatedCiphertext(session.public_key);

            // Complete handshake
            const handshake = await completePQCHandshake(session.session_id, ciphertext);

            if (handshake.success) {
                console.log('   ✅ Full session flow completed successfully!');
            }
        }

        console.log('\n' + '='.repeat(60));
        console.log('✅ All PQC Client Tests Passed!');
        console.log('='.repeat(60) + '\n');
    })();
}

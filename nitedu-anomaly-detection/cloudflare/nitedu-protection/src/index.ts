// Use environment variable for backend URL
const BACKEND_URL = 'https://nitedu-anomaly-detection-7zjn.onrender.com';
const rateLimitMap = new Map();

export default {
  async fetch(request) {
    const startTime = Date.now();
    const url = new URL(request.url);
    const cf = request.cf || {};
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    
    // Rate Limiting
    const rateLimit = checkRateLimit(clientIP);
    if (rateLimit.blocked) {
      return new Response('Rate limit exceeded', { status: 429, headers: { 'Retry-After': '60' } });
    }
    
    const trafficData = {
      timestamp: new Date().toISOString(),
      method: request.method,
      path: url.pathname,
      query: url.search,
      user_agent: request.headers.get('User-Agent') || '',
      ip: clientIP,
      country: cf.country || 'Unknown',
      referer: request.headers.get('Referer') || '',
      content_length: parseInt(request.headers.get('Content-Length') || '0'),
      request_size: url.toString().length
    };
    
    // ML-only detection - no rule-based patterns
    let isAttack = false;
    let attackType = 'Normal';
    let mlConfidence = 0.0;
    
    trafficData.response_time = Date.now() - startTime;
    
    // ML-only detection for ALL requests
    let mlBlocked = false;
    let mlAttackType = 'Normal';
    let mlDebug = 'ML processing...';
    
    // Check for scanner user-agents first (before whitelisting)
    const scannerPatterns = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burp', 'w3af', 'scanner'];
    const isScannerUA = scannerPatterns.some(pattern => trafficData.user_agent.toLowerCase().includes(pattern));
    
    // Whitelist normal pages to reduce false positives (but not for scanners)
    const normalPaths = ['/', '/index.html', '/home', '/about', '/contact', '/search', '/login', '/register'];
    const isNormalPage = normalPaths.includes(url.pathname) || url.pathname.startsWith('/static/');
    const hasSimpleQuery = url.search && !(/[<>"'%;()&+\\]/.test(url.search));
    
    if (isNormalPage && (!url.search || hasSimpleQuery) && !isScannerUA) {
      mlDebug = 'Whitelisted normal page';
    }
    
    // Enhanced ML detection with better feature extraction - skip for whitelisted normal pages (except scanners)
    if (!isNormalPage || (url.search && /[<>"'%;()&+\\]/.test(url.search)) || isScannerUA) {
      try {
        // Enhanced traffic data for ML
        const enhancedData = {
          ...trafficData,
          url_length: url.toString().length,
          query_params: url.searchParams.size,
          has_suspicious_chars: /[<>"'%;()&+]/.test(url.toString()),
          path_depth: url.pathname.split('/').length - 1,
          method_type: request.method,
          content_type: request.headers.get('content-type') || 'none'
        };
        
        // Simplified ML call with better data format
        const simpleData = {
          url: url.toString(),
          path: url.pathname + url.search,  // Combine path and query for better detection
          query: url.search,
          method: request.method,
          user_agent: trafficData.user_agent,
          ip: trafficData.ip,
          timestamp: Date.now()
        };
        
        const mlResponse = await fetch(`${BACKEND_URL}/api/v1/predict`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(simpleData),
          signal: AbortSignal.timeout(10000)
        });
        
        if (mlResponse.ok) {
          const mlResult = await mlResponse.json();
          mlConfidence = mlResult.confidence || 0.0;
          mlAttackType = mlResult.attack_type || 'Unknown';
          
          // More lenient classification - only block very high confidence
          if (mlResult.is_anomaly && mlConfidence > 0.95) {
            mlBlocked = true;
            isAttack = true;
            attackType = mlAttackType;
            mlDebug = `ML BLOCKED: ${mlAttackType} (${(mlConfidence * 100).toFixed(1)}%)`;
          } else {
            mlDebug = `ML: ${mlAttackType} (${(mlConfidence * 100).toFixed(1)}%)`;
          }
        } else {
          mlDebug = `ML API error: ${mlResponse.status}`;
        }
      } catch (e) {
        mlDebug = `ML timeout: ${e.message}`;
      }
    }
    
    trafficData.attack_type = attackType;
    trafficData.is_attack = isAttack;
    trafficData.ml_confidence = mlConfidence;
    
    // Log ALL requests to database for real-time dashboard
    fetch(`${BACKEND_URL}/api/v1/log-request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        timestamp: trafficData.timestamp,
        method: trafficData.method,
        path: trafficData.path,
        ip: trafficData.ip,
        user_agent: trafficData.user_agent,
        is_attack: isAttack || mlBlocked,
        attack_type: mlBlocked ? mlAttackType : attackType,
        country: trafficData.country,
        referer: trafficData.referer
      }),
      signal: AbortSignal.timeout(2000)
    }).catch(() => {}); // Silent fail for logging
    
    // Send all requests to ML ingest for continuous learning
    fetch(`${BACKEND_URL}/api/v1/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(trafficData)
    }).catch(() => {});
    
    // Use ML-only detection
    if (mlBlocked) {
      return new Response(`ML Attack Blocked: ${mlAttackType} (${(mlConfidence * 100).toFixed(1)}% confidence)`, { 
        status: 403,
        headers: { 'X-Block-Reason': 'ML-Detection' }
      });
    }
    
    return new Response(`nitedu.in Protected by ML\nStatus: SAFE | ${mlDebug} | Confidence: ${(mlConfidence * 100).toFixed(1)}%`, { 
      headers: { 
        'Content-Type': 'text/plain',
        'X-ML-Confidence': mlConfidence.toString()
      } 
    });
  }
};

function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 100;
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    return { blocked: false };
  }
  
  const record = rateLimitMap.get(ip);
  
  if (now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    return { blocked: false };
  }
  
  if (record.count >= maxRequests) {
    return { blocked: true };
  }
  
  record.count++;
  return { blocked: false };
}

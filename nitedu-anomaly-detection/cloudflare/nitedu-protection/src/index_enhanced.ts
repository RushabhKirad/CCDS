const BACKEND_URL = 'https://nitedu-anomaly-detection-6w4v.onrender.com';

// Rate limiting storage (in-memory for demo, use KV in production)
const rateLimitMap = new Map();

export default {
  async fetch(request, env) {
    const startTime = Date.now();
    const url = new URL(request.url);
    const cf = request.cf || {};
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    
    // IMPROVEMENT 1: Rate Limiting
    const rateLimit = checkRateLimit(clientIP);
    if (rateLimit.blocked) {
      return new Response('Rate limit exceeded. Too many requests.', { 
        status: 429,
        headers: { 'Retry-After': '60' }
      });
    }
    
    // Extract traffic features
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
    
    // IMPROVEMENT 2: Enhanced Attack Detection
    const fullUrl = decodeURIComponent(url.toString().toLowerCase());
    const path = url.pathname.toLowerCase();
    const query = url.search.toLowerCase();
    const userAgent = trafficData.user_agent.toLowerCase();
    
    let isAttack = false;
    let attackType = 'Normal';
    
    // SQL Injection patterns (existing)
    const sqlPatterns = ['union', 'select', "' or '", '" or "', "'=''", 'drop table', 'insert into', 'delete from', "'1'='1", '/*', '--', ';--'];
    if (sqlPatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'SQL Injection';
    }
    
    // XSS patterns (existing)
    const xssPatterns = ['<script', 'alert(', 'onerror=', 'onload=', 'javascript:', '<img src=x', 'onclick='];
    if (!isAttack && xssPatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'XSS Attack';
    }
    
    // Bot/Scanner detection (existing)
    const botPatterns = ['sqlmap', 'nikto', 'nmap', 'burp', 'zap', 'python-requests', 'curl/', 'wget'];
    if (!isAttack && botPatterns.some(pattern => userAgent.includes(pattern))) {
      isAttack = true;
      attackType = 'Bot Attack';
    }
    
    // NEW: SSRF Detection
    const ssrfPatterns = ['169.254.169.254', 'localhost', '127.0.0.1', 'metadata', '0.0.0.0', '[::1]'];
    if (!isAttack && ssrfPatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'SSRF Attack';
    }
    
    // NEW: RCE Detection
    const rcePatterns = ['wget', 'curl', 'bash', 'sh', '/bin/', 'exec(', 'system(', 'shell_exec'];
    if (!isAttack && rcePatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'RCE Attack';
    }
    
    // NEW: Path Traversal (enhanced)
    const traversalPatterns = ['../', '..\\', '%2e%2e', 'etc/passwd', 'windows/system32', '/etc/shadow'];
    if (!isAttack && traversalPatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'Path Traversal';
    }
    
    // NEW: NoSQL Injection
    const nosqlPatterns = ['[$ne]', '[$gt]', '[$lt]', '[$regex]', '[$where]', '[$exists]'];
    if (!isAttack && nosqlPatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'NoSQL Injection';
    }
    
    // NEW: Deserialization Attack
    const deserialPatterns = ['o:', 'a:', 'stdclass', 'unserialize', 'pickle', '__reduce__'];
    if (!isAttack && deserialPatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'Deserialization Attack';
    }
    
    // NEW: XML Injection
    const xmlPatterns = ['<!doctype', '<!entity', 'system', 'file://', '<?xml'];
    if (!isAttack && xmlPatterns.some(pattern => fullUrl.includes(pattern))) {
      isAttack = true;
      attackType = 'XML Injection';
    }
    
    trafficData.attack_type = attackType;
    trafficData.is_attack = isAttack;
    trafficData.response_time = Date.now() - startTime;
    
    // Get ML prediction for advanced threats
    let mlBlocked = false;
    try {
      const mlResponse = await fetch(`${BACKEND_URL}/api/v1/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(trafficData),
        signal: AbortSignal.timeout(2000)
      });
      
      if (mlResponse.ok) {
        const mlResult = await mlResponse.json();
        if (mlResult.is_anomaly && mlResult.confidence > 0.7) {
          mlBlocked = true;
          attackType = `ML Detected: ${mlResult.attack_type}`;
        }
      }
    } catch (e) {
      // ML unavailable, continue with rule-based protection
    }
    
    // Send to ML backend for learning (fire and forget)
    fetch(`${BACKEND_URL}/api/v1/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(trafficData)
    }).catch(() => {});
    
    if (isAttack || mlBlocked) {
      return new Response(`Attack Blocked: ${attackType}`, { status: 403 });
    }
    
    return new Response('nitedu.in Protected - Status: SAFE', { 
      headers: { 'Content-Type': 'text/plain' } 
    });
  }
};

// Rate limiting function
function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const maxRequests = 100; // 100 requests per minute
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    return { blocked: false };
  }
  
  const record = rateLimitMap.get(ip);
  
  if (now > record.resetTime) {
    // Reset window
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    return { blocked: false };
  }
  
  if (record.count >= maxRequests) {
    return { blocked: true, reason: 'rate_limit_exceeded' };
  }
  
  record.count++;
  return { blocked: false };
}

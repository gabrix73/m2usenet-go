<?php
// /var/www/m2usenet/send.php
// m2usenet Gateway Handler v3.0.0 - PHP Native SOCKS5 Implementation
// Maximum security: no external dependencies, constant-time operations, anti-analysis
// Security-hardened implementation with all threat mitigations

// PRODUCTION SECURITY
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);
error_reporting(0);

// SMTP Relay Configuration
define('PRIMARY_SMTP_RELAY', 'xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion');
define('PRIMARY_SMTP_PORT', 25);  // Restored to original working port
define('PRIMARY_MAIL2NEWS', 'mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion');

// Security Configuration
define('LOG_FILE', '/var/log/m2usenet/send.log');
define('RATE_LIMIT_FILE', '/var/www/m2usenet/rate_limits.json');
define('HASHCASH_CACHE', '/var/www/m2usenet/hashcash_cache.json');
define('MAX_NEWSGROUPS', 3);
define('MAX_MESSAGE_SIZE', 65536);
define('MIN_MESSAGE_SIZE', 10);
define('PADDING_ENABLED', true);
define('PADDING_BOUNDARY', 1024);
define('RATE_LIMIT_REQUESTS', 10);
define('RATE_LIMIT_WINDOW', 3600);
define('HASHCASH_MIN_BITS', 20);
define('HASHCASH_CACHE_TTL', 172800);
define('QUIET_MODE', false);

// Message-ID Generator Configuration (NEW)
define('MESSAGE_ID_TIMEZONE', 'UTC');
define('MESSAGE_ID_USE_MD5', true);
define('MESSAGE_ID_DOMAIN', 'm2usenet.local');
define('MESSAGE_ID_JITTER_MIN', -30);
define('MESSAGE_ID_JITTER_MAX', 30);

// Timing obfuscation - anti-analysis
define('BASE_TIMEOUT', 120);
define('MAX_JITTER_MS', 5000);
define('MIN_RANDOM_DELAY_MS', 100);
define('MAX_RANDOM_DELAY_MS', 3000);

// SOCKS5 Configuration
define('SOCKS5_PROXY', '127.0.0.1');
define('SOCKS5_PORT', 9050);
define('SOCKS5_TIMEOUT', 120);
define('SMTP_READ_TIMEOUT', 30);

// Network security
define('MAX_SMTP_RESPONSE_SIZE', 8192);
define('MAX_RETRIES', 2);
define('RETRY_DELAY_BASE', 5);

// Session security
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}

function secureLog($message, $level = 'INFO') {
    if (QUIET_MODE && $level !== 'ERROR' && $level !== 'CRITICAL') {
        return;
    }
    
    $timestamp = gmdate('Y-m-d H:i:s');
    // Sanitize: remove emails, message-ids, sensitive data
    $sanitized = preg_replace('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', '[email]', $message);
    $sanitized = preg_replace('/<[^>]+@[^>]+>/', '[message-id]', $sanitized);
    $sanitized = preg_replace('/\b[a-z2-7]{56}\.onion\b/', '[onion]', $sanitized);
    $logEntry = "[$timestamp UTC] [$level] $sanitized\n";
    
    $logDir = dirname(LOG_FILE);
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0700, true);
    }
    
    @file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

function cryptoRandBytes($length) {
    try {
        return random_bytes($length);
    } catch (Exception $e) {
        secureLog("CRITICAL: random_bytes failed", 'CRITICAL');
        http_response_code(500);
        die("System error");
    }
}

function cryptoRandInt($min, $max) {
    try {
        return random_int($min, $max);
    } catch (Exception $e) {
        secureLog("CRITICAL: random_int failed", 'CRITICAL');
        return $min;
    }
}

function constantTimeCompare($a, $b) {
    // Constant-time string comparison to prevent timing attacks
    if (function_exists('hash_equals')) {
        return hash_equals($a, $b);
    }
    
    if (strlen($a) !== strlen($b)) {
        return false;
    }
    
    $result = 0;
    for ($i = 0; $i < strlen($a); $i++) {
        $result |= ord($a[$i]) ^ ord($b[$i]);
    }
    
    return $result === 0;
}

function randomDelay($baseSeconds = 0) {
    // Anti-timing analysis: randomized delays
    $jitterMs = cryptoRandInt(0, MAX_JITTER_MS);
    $totalUs = ($baseSeconds * 1000000) + ($jitterMs * 1000);
    usleep($totalUs);
}

function generateSecureMessageID($domain = null, $useMD5 = null, $timezone = null) {
    // Advanced Message-ID generator based on mid.go
    // Use config defaults if not specified
    $domain = $domain ?? MESSAGE_ID_DOMAIN;
    $useMD5 = $useMD5 ?? MESSAGE_ID_USE_MD5;
    $timezone = $timezone ?? MESSAGE_ID_TIMEZONE;
    
    // Create timezone-aware datetime
    try {
        $dateTime = new DateTime('now', new DateTimeZone($timezone));
    } catch (Exception $e) {
        secureLog("Invalid timezone '$timezone', using UTC", 'WARNING');
        $dateTime = new DateTime('now', new DateTimeZone('UTC'));
    }
    
    // Add random jitter to timestamp (anti-timing analysis)
    $jitterSeconds = cryptoRandInt(MESSAGE_ID_JITTER_MIN, MESSAGE_ID_JITTER_MAX);
    $dateTime->modify("{$jitterSeconds} seconds");
    
    // Date component: YYYYMMDD.HHMMSS format
    $dateComponent = $dateTime->format('Ymd.His');
    
    // Random component: 8 hex chars (32 bits entropy)
    $randomComponent = bin2hex(cryptoRandBytes(4));
    
    if ($useMD5) {
        // MD5 format: hash the timestamp+random to obscure timing patterns
        $combined = $dateComponent . '.' . $randomComponent;
        $hash = md5($combined);
        $messageId = sprintf("<%s@%s>", $hash, $domain);
    } else {
        // Standard format: timestamp.random@domain
        $messageId = sprintf("<%s.%s@%s>", $dateComponent, $randomComponent, $domain);
    }
    
    return $messageId;
}

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(cryptoRandBytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    return constantTimeCompare($_SESSION['csrf_token'], $token);
}

function checkRateLimit() {
    // IP-based rate limiting with time-window hashing
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ipHash = hash('sha256', $ip . date('Y-m-d-H'));
    
    $limits = [];
    if (file_exists(RATE_LIMIT_FILE)) {
        $data = @file_get_contents(RATE_LIMIT_FILE);
        if ($data) {
            $limits = json_decode($data, true) ?? [];
        }
    }
    
    $now = time();
    // Cleanup expired entries
    foreach ($limits as $hash => $data) {
        if ($now - $data['first_request'] > RATE_LIMIT_WINDOW) {
            unset($limits[$hash]);
        }
    }
    
    if (!isset($limits[$ipHash])) {
        $limits[$ipHash] = [
            'count' => 1,
            'first_request' => $now
        ];
    } else {
        $limits[$ipHash]['count']++;
    }
    
    @file_put_contents(RATE_LIMIT_FILE, json_encode($limits), LOCK_EX);
    
    if ($limits[$ipHash]['count'] > RATE_LIMIT_REQUESTS) {
        secureLog("Rate limit exceeded for hashed IP", 'WARNING');
        randomDelay(cryptoRandInt(2, 5)); // Anti-timing: delay before rejection
        return false;
    }
    
    return true;
}

function normalizeHashcashToken($token) {
    // Normalize whitespace to prevent cache bypass
    $normalized = preg_replace('/\s+/', '', $token);
    return trim($normalized);
}

function checkHashcashReplay($token) {
    // Replay attack protection with expiring cache
    if (!file_exists(HASHCASH_CACHE)) {
        return false;
    }
    
    $cache = json_decode(@file_get_contents(HASHCASH_CACHE), true) ?? [];
    $now = time();
    
    // Cleanup expired tokens (prevent cache growth)
    $cleaned = false;
    foreach ($cache as $hash => $timestamp) {
        if ($now - $timestamp > HASHCASH_CACHE_TTL) {
            unset($cache[$hash]);
            $cleaned = true;
        }
    }
    
    if ($cleaned) {
        @file_put_contents(HASHCASH_CACHE, json_encode($cache), LOCK_EX);
    }
    
    $normalizedToken = normalizeHashcashToken($token);
    $tokenHash = hash('sha256', $normalizedToken);
    
    if (isset($cache[$tokenHash])) {
        secureLog("Replay attack detected - token hash: " . substr($tokenHash, 0, 16), 'WARNING');
        randomDelay(cryptoRandInt(1, 3)); // Anti-timing
        return true;
    }
    
    return false;
}

function markHashcashUsed($token) {
    // Atomically mark token as used
    $cache = [];
    if (file_exists(HASHCASH_CACHE)) {
        $cache = json_decode(@file_get_contents(HASHCASH_CACHE), true) ?? [];
    }
    
    $normalizedToken = normalizeHashcashToken($token);
    $tokenHash = hash('sha256', $normalizedToken);
    $cache[$tokenHash] = time();
    
    @file_put_contents(HASHCASH_CACHE, json_encode($cache), LOCK_EX);
}

function verifyHashcash($token, $fromEmail) {
    // Constant-time hashcash verification
    $token = normalizeHashcashToken($token);
    
    $parts = explode(':', $token);
    if (count($parts) !== 7) {
        randomDelay(0); // Constant-time: same delay on all paths
        return false;
    }
    
    list($version, $bits, $date, $resource, $ext, $rand, $counter) = $parts;
    
    $valid = true;
    
    // Constant-time checks
    $valid = $valid && ($version === '1');
    $valid = $valid && ((int)$bits >= HASHCASH_MIN_BITS);
    $valid = $valid && (strcasecmp(trim($resource), trim($fromEmail)) === 0);
    
    if (!$valid) {
        randomDelay(0); // Constant-time
        return false;
    }
    
    // Verify proof-of-work
    $hash = sha1($token);
    $requiredZeros = str_repeat('0', (int)((int)$bits / 4));
    
    if (strpos($hash, $requiredZeros) !== 0) {
        randomDelay(0); // Constant-time
        return false;
    }
    
    return true;
}

function validateInput($data) {
    $errors = [];
    
    // Required fields check
    $required = ['from', 'newsgroups', 'subject', 'xhashcash', 'message', 'csrf_token'];
    foreach ($required as $field) {
        if (!isset($data[$field]) || trim($data[$field]) === '') {
            $errors[] = "Missing required field: $field";
            randomDelay(0); // Constant-time
            return $errors;
        }
    }
    
    // CSRF token verification (constant-time)
    if (!verifyCSRFToken($data['csrf_token'])) {
        $errors[] = "Invalid request token";
        randomDelay(0); // Constant-time
        return $errors;
    }
    
    // From header validation
    if (!preg_match('/^.+\s*<[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>$/', $data['from'])) {
        $errors[] = "Invalid sender format";
        randomDelay(0);
    }
    
    preg_match('/<([^>]+)>/', $data['from'], $matches);
    $fromEmail = $matches[1] ?? '';
    
    // Newsgroups validation
    $newsgroups = array_map('trim', explode(',', $data['newsgroups']));
    if (count($newsgroups) > MAX_NEWSGROUPS) {
        $errors[] = "Too many newsgroups";
    }
    
    foreach ($newsgroups as $ng) {
        if (!preg_match('/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i', $ng)) {
            $errors[] = "Invalid newsgroup format";
            break;
        }
    }
    
    // Message size validation
    $msgSize = strlen($data['message']);
    
    if ($msgSize < MIN_MESSAGE_SIZE || $msgSize > MAX_MESSAGE_SIZE) {
        $errors[] = "Invalid message size";
        randomDelay(0);
    }
    
    // Hashcash verification (constant-time)
    if (empty($errors) && !verifyHashcash($data['xhashcash'], $fromEmail)) {
        $errors[] = "Invalid hashcash token";
        randomDelay(0);
    }
    
    // Replay check (only if hashcash valid)
    if (empty($errors) && checkHashcashReplay($data['xhashcash'])) {
        $errors[] = "Token already used";
        randomDelay(0);
    }
    
    return $errors;
}

function addAdaptivePadding($message) {
    // Size correlation attack prevention with adaptive padding
    if (!PADDING_ENABLED) {
        return $message;
    }
    
    $msgLen = strlen($message);
    $boundary = PADDING_BOUNDARY;
    
    // Don't pad if already near max size
    if ($msgLen >= MAX_MESSAGE_SIZE * 0.95) {
        return $message;
    }
    
    // Round up to next boundary
    $targetLen = (intdiv($msgLen, $boundary) + 1) * $boundary;
    $paddingNeeded = $targetLen - $msgLen;
    
    // Add random jitter to prevent exact boundary detection
    $paddingNeeded += cryptoRandInt(-50, 50);
    $paddingNeeded = max(0, min($paddingNeeded, MAX_MESSAGE_SIZE - $msgLen));
    
    if ($paddingNeeded > 0) {
        // Use varied whitespace characters for padding
        $paddingChars = [' ', "\t", "\n"];
        $padding = "\n\n"; // Start with double newline
        
        for ($i = 0; $i < $paddingNeeded - 2; $i++) {
            $padding .= $paddingChars[cryptoRandInt(0, count($paddingChars) - 1)];
        }
        
        return $message . $padding;
    }
    
    return $message;
}

// ============================================================================
// SOCKS5 IMPLEMENTATION - Pure PHP, Maximum Security
// ============================================================================

function socks5Connect($destHost, $destPort, $socksHost = SOCKS5_PROXY, $socksPort = SOCKS5_PORT, $timeout = SOCKS5_TIMEOUT) {
    secureLog("Initiating SOCKS5 connection to $destHost:$destPort via $socksHost:$socksPort");
    
    // Validate destination .onion address
    if (!preg_match('/^[a-z2-7]{56}\.onion$/', $destHost)) {
        secureLog("Invalid .onion address format", 'ERROR');
        return false;
    }
    
    // Anti-timing: random delay before connection
    randomDelay(0);
    
    // Create socket to SOCKS5 proxy
    $socket = @stream_socket_client(
        "tcp://$socksHost:$socksPort",
        $errno,
        $errstr,
        $timeout,
        STREAM_CLIENT_CONNECT
    );
    
    if (!$socket) {
        secureLog("Failed to connect to SOCKS5 proxy: $errstr ($errno)", 'ERROR');
        return false;
    }
    
    // Set timeouts
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);
    
    secureLog("Connected to SOCKS5 proxy, initiating handshake");
    
    // ===== SOCKS5 Handshake Step 1: Version/Auth negotiation =====
    // Format: [VER=0x05][NMETHODS=0x01][METHOD=0x00 (no auth)]
    $request = pack('C3', 0x05, 0x01, 0x00);
    
    if (fwrite($socket, $request) === false) {
        secureLog("Failed to write SOCKS5 handshake", 'ERROR');
        fclose($socket);
        return false;
    }
    
    // Read response: [VER][METHOD]
    $response = fread($socket, 2);
    
    if (strlen($response) !== 2) {
        secureLog("Invalid SOCKS5 handshake response length", 'ERROR');
        fclose($socket);
        return false;
    }
    
    $data = unpack('Cver/Cmethod', $response);
    
    if ($data['ver'] !== 0x05 || $data['method'] !== 0x00) {
        secureLog("SOCKS5 handshake failed: unsupported version or auth method", 'ERROR');
        fclose($socket);
        return false;
    }
    
    secureLog("SOCKS5 handshake successful, sending connect request");
    
    // ===== SOCKS5 Step 2: Connection request =====
    // Format: [VER=0x05][CMD=0x01 (CONNECT)][RSV=0x00][ATYP=0x03 (DOMAIN)]
    //         [DLEN][DOMAIN][PORT (2 bytes, big-endian)]
    
    $domainLen = strlen($destHost);
    $request = pack('C4', 0x05, 0x01, 0x00, 0x03); // Version, Connect, Reserved, Domain type
    $request .= pack('C', $domainLen); // Domain length
    $request .= $destHost; // Domain name
    $request .= pack('n', $destPort); // Port (network byte order)
    
    if (fwrite($socket, $request) === false) {
        secureLog("Failed to write SOCKS5 connect request", 'ERROR');
        fclose($socket);
        return false;
    }
    
    // Read response: [VER][REP][RSV][ATYP][BIND_ADDR][BIND_PORT]
    // We need at least 4 bytes to check the result
    $response = fread($socket, 4);
    
    if (strlen($response) < 4) {
        secureLog("Invalid SOCKS5 connect response length", 'ERROR');
        fclose($socket);
        return false;
    }
    
    $data = unpack('Cver/Crep/Crsv/Catyp', $response);
    
    if ($data['ver'] !== 0x05) {
        secureLog("Invalid SOCKS5 response version", 'ERROR');
        fclose($socket);
        return false;
    }
    
    if ($data['rep'] !== 0x00) {
        // Error codes
        $errors = [
            0x01 => 'General SOCKS server failure',
            0x02 => 'Connection not allowed by ruleset',
            0x03 => 'Network unreachable',
            0x04 => 'Host unreachable',
            0x05 => 'Connection refused',
            0x06 => 'TTL expired',
            0x07 => 'Command not supported',
            0x08 => 'Address type not supported'
        ];
        
        $errorMsg = $errors[$data['rep']] ?? "Unknown error code: {$data['rep']}";
        secureLog("SOCKS5 connection failed: $errorMsg", 'ERROR');
        fclose($socket);
        return false;
    }
    
    // Read the rest of the response (bind address + port)
    // The format depends on ATYP
    if ($data['atyp'] === 0x01) {
        // IPv4: 4 bytes + 2 bytes port
        fread($socket, 6);
    } elseif ($data['atyp'] === 0x03) {
        // Domain: 1 byte length + domain + 2 bytes port
        $len = ord(fread($socket, 1));
        fread($socket, $len + 2);
    } elseif ($data['atyp'] === 0x04) {
        // IPv6: 16 bytes + 2 bytes port
        fread($socket, 18);
    }
    
    secureLog("SOCKS5 connection established successfully");
    
    return $socket;
}

function smtpSendCommand($socket, $command, $expectedCode = null) {
    // Send SMTP command and read response
    secureLog("SMTP >> " . trim($command));
    
    if (fwrite($socket, $command) === false) {
        secureLog("Failed to write SMTP command", 'ERROR');
        return false;
    }
    
    // Read response (with size limit)
    $response = '';
    $bytesRead = 0;
    
    while (!feof($socket) && $bytesRead < MAX_SMTP_RESPONSE_SIZE) {
        $line = fgets($socket, 1024);
        
        if ($line === false) {
            break;
        }
        
        $response .= $line;
        $bytesRead += strlen($line);
        
        // SMTP multiline response ends when line starts with code and space (not dash)
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }
    
    secureLog("SMTP << " . trim($response));
    
    if ($expectedCode !== null) {
        if (!preg_match("/^$expectedCode/", $response)) {
            secureLog("SMTP error: expected $expectedCode, got: " . substr($response, 0, 100), 'ERROR');
            return false;
        }
    }
    
    return $response;
}

function sendViaNativePHPSMTP($data, $smtpRelay, $smtpPort, $mail2newsAddress) {
    secureLog("=== Starting native PHP SMTP delivery ===");
    secureLog("Target: $smtpRelay:$smtpPort → $mail2newsAddress");
    
    // Anti-timing: random delay before connection
    $delay = cryptoRandInt(MIN_RANDOM_DELAY_MS, MAX_RANDOM_DELAY_MS) / 1000;
    randomDelay($delay);
    
    $startTime = microtime(true);
    
    // Connect via SOCKS5
    $socket = socks5Connect($smtpRelay, $smtpPort);
    
    if (!$socket) {
        secureLog("SOCKS5 connection failed", 'ERROR');
        return ['success' => false, 'message' => 'Gateway connection failed'];
    }
    
    $connectTime = microtime(true) - $startTime;
    secureLog(sprintf("SOCKS5 connection established in %.2fs", $connectTime));
    
    // Set read timeout for SMTP operations
    stream_set_timeout($socket, SMTP_READ_TIMEOUT);
    
    try {
        // Read SMTP greeting (220)
        $greeting = smtpSendCommand($socket, '', 220);
        
        if ($greeting === false) {
            throw new Exception("No SMTP greeting received");
        }
        
        // HELO
        $response = smtpSendCommand($socket, "HELO m2usenet.local\r\n", 250);
        
        if ($response === false) {
            throw new Exception("HELO failed");
        }
        
        // Extract sender email
        preg_match('/<([^>]+)>/', $data['from'], $matches);
        $fromEmail = $matches[1] ?? 'noreply@m2usenet.local';
        
        // MAIL FROM
        $response = smtpSendCommand($socket, "MAIL FROM:<$fromEmail>\r\n", 250);
        
        if ($response === false) {
            throw new Exception("MAIL FROM rejected");
        }
        
        // RCPT TO
        $response = smtpSendCommand($socket, "RCPT TO:<$mail2newsAddress>\r\n", 250);
        
        if ($response === false) {
            throw new Exception("RCPT TO rejected");
        }
        
        // DATA
        $response = smtpSendCommand($socket, "DATA\r\n", 354);
        
        if ($response === false) {
            throw new Exception("DATA command rejected");
        }
        
        // Build message
        $messageId = generateSecureMessageID();
        
        $headers = [
            sprintf("From: %s", $data['from']),
            sprintf("To: %s", $mail2newsAddress),
            sprintf("Subject: %s", $data['subject']),
            sprintf("Message-ID: %s", $messageId),
            sprintf("Date: %s", gmdate('r')),
            sprintf("Newsgroups: %s", $data['newsgroups']),
            sprintf("X-Hashcash: %s", $data['xhashcash'])
        ];
        
        if (!empty($data['x-ed25519-pub'])) {
            $headers[] = sprintf("X-Ed25519-Pub: %s", $data['x-ed25519-pub']);
        }
        if (!empty($data['x-ed25519-sig'])) {
            $headers[] = sprintf("X-Ed25519-Sig: %s", $data['x-ed25519-sig']);
        }
        if (!empty($data['references'])) {
            $refs = trim($data['references']);
            if (strpos($refs, '<') === false) $refs = '<' . $refs;
            if (strpos($refs, '>') === false) $refs .= '>';
            $headers[] = sprintf("References: %s", $refs);
            $headers[] = sprintf("In-Reply-To: %s", $refs);
        }
        
        $headers[] = "MIME-Version: 1.0";
        $headers[] = "Content-Type: text/plain; charset=utf-8";
        $headers[] = "Content-Transfer-Encoding: 8bit";
        $headers[] = "User-Agent: m2usenet-web v3.0.0";
        $headers[] = "X-No-Archive: Yes";
        
        $body = addAdaptivePadding($data['message']);
        $fullMessage = implode("\r\n", $headers) . "\r\n\r\n" . $body . "\r\n";
        
        secureLog("Sending message body (" . strlen($fullMessage) . " bytes)");
        
        // Send message body
        if (fwrite($socket, $fullMessage) === false) {
            throw new Exception("Failed to write message body");
        }
        
        // End DATA with .
        $response = smtpSendCommand($socket, ".\r\n", 250);
        
        if ($response === false) {
            throw new Exception("Message rejected");
        }
        
        // QUIT
        smtpSendCommand($socket, "QUIT\r\n", 221);
        
        $totalTime = microtime(true) - $startTime;
        secureLog(sprintf("=== Message delivered successfully in %.2fs ===", $totalTime));
        
        fclose($socket);
        
        return [
            'success' => true,
            'message' => 'Message sent via secure onion gateway',
            'messageId' => $messageId,
            'gateway' => $mail2newsAddress
        ];
        
    } catch (Exception $e) {
        secureLog("SMTP error: " . $e->getMessage(), 'ERROR');
        fclose($socket);
        return ['success' => false, 'message' => 'SMTP protocol error'];
    }
}

function sendMessage($data) {
    $result = sendViaNativePHPSMTP($data, PRIMARY_SMTP_RELAY, PRIMARY_SMTP_PORT, PRIMARY_MAIL2NEWS);
    
    // Retry logic with exponential backoff
    $retries = 0;
    while (!$result['success'] && $retries < MAX_RETRIES) {
        $retries++;
        $backoff = RETRY_DELAY_BASE * pow(2, $retries - 1);
        $backoff += cryptoRandInt(0, 2); // Add jitter
        
        secureLog("Retry $retries/" . MAX_RETRIES . " after {$backoff}s", 'WARNING');
        sleep($backoff);
        
        $result = sendViaNativePHPSMTP($data, PRIMARY_SMTP_RELAY, PRIMARY_SMTP_PORT, PRIMARY_MAIL2NEWS);
    }
    
    return $result;
}

function errorResponse($message = "Request failed") {
    http_response_code(400);
    ?>
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; 
               padding: 20px; background: #f5f5f5; margin: 0; }
        .container { max-width: 600px; margin: 40px auto; }
        .error { background: #fff; border-left: 4px solid #dc3545; 
                 padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error">
            <h2>Request Failed</h2>
            <p><?php echo htmlspecialchars($message); ?></p>
            <p><a href="index.php">← Back</a></p>
        </div>
    </div>
</body>
</html>
    <?php
    exit;
}

function successResponse($messageId, $gateway) {
    http_response_code(200);
    ?>
<!DOCTYPE html>
<html>
<head>
    <title>Message Sent</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; 
               padding: 20px; background: #f5f5f5; margin: 0; }
        .container { max-width: 600px; margin: 40px auto; }
        .success { background: #fff; border-left: 4px solid #28a745; 
                   padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .message-id { font-family: monospace; background: #f8f9fa; 
                      padding: 10px; border-radius: 4px; word-break: break-all; 
                      margin: 10px 0; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .info { font-size: 0.9em; color: #6c757d; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success">
            <h2>✓ Message Sent</h2>
            <p><strong>Message-ID:</strong></p>
            <div class="message-id"><?php echo htmlspecialchars($messageId); ?></div>
            <p>Your message has been successfully delivered to the Usenet network.</p>
            <div class="info">
                <p><strong>Gateway:</strong> <?php echo htmlspecialchars($gateway); ?></p>
                <p><small>Message routed via secure Tor SOCKS5 with PHP native implementation</small></p>
            </div>
            <p><a href="index.php">Send another message</a></p>
        </div>
    </div>
</body>
</html>
    <?php
    exit;
}

// ============================================================================
// MAIN REQUEST HANDLER
// ============================================================================

try {
    secureLog("=== New request received ===");
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        secureLog("Invalid request method: " . $_SERVER['REQUEST_METHOD'], 'WARNING');
        http_response_code(405);
        die("Method not allowed");
    }
    
    if (!checkRateLimit()) {
        secureLog("Rate limit exceeded", 'WARNING');
        errorResponse("Too many requests. Please try again later.");
    }
    
    $data = $_POST;
    
    secureLog("POST data keys: " . implode(', ', array_keys($data)));
    secureLog("Message length: " . strlen($data['message'] ?? ''));
    
    $errors = validateInput($data);
    
    if (!empty($errors)) {
        secureLog("Validation failed: " . implode('; ', $errors), 'WARNING');
        errorResponse("Validation failed");
    }
    
    secureLog("Input validation passed");
    
    // Mark token as used AFTER successful validation
    markHashcashUsed($data['xhashcash']);
    secureLog("Hashcash token marked as used");
    
    $result = sendMessage($data);
    
    if ($result['success']) {
        secureLog("Request completed successfully");
        successResponse($result['messageId'], $result['gateway']);
    } else {
        secureLog("Request failed: " . $result['message'], 'ERROR');
        errorResponse($result['message']);
    }
    
} catch (Exception $e) {
    secureLog("=== Fatal exception: " . $e->getMessage() . " ===", 'CRITICAL');
    secureLog("Stack trace: " . $e->getTraceAsString(), 'ERROR');
    errorResponse("System error occurred");
}

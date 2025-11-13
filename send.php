<?php
// /var/www/m2usenet/send.php
// m2usenet Gateway Handler v2.1.0 - PRIVACY FIX RELEASE
// FIX 1: Padding DISABLED (was corrupting Usenet messages)
// FIX 2: Hashcash normalization now consistent
// FIX 3: X-Hashcash header REMOVED (timestamp leak)
// FIX 4: Date header jitter ±30s (anti-timing correlation)
// FIX 5: Dot stuffing verified correct (RFC 5321)
// FIX 3: Dot stuffing verified correct

// PRODUCTION SECURITY
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);
error_reporting(0);

set_time_limit(180);
ini_set('max_execution_time', 180);

// SMTP Relay Configuration
define('PRIMARY_RELAY', [
    'host' => '4uwpi53u524xdphjw2dv5kywsxmyjxtk4facb76jgl3sc3nda3sz4fqd.onion',
    'port' => 25,
    'mail2news' => 'mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion',
    'name' => 'fog-primary'
]);

define('FALLBACK_RELAY', [
    'host' => 'xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion',
    'port' => 25,
    'mail2news' => 'mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion',
    'name' => 'smtp-fallback'
]);

// Security Configuration
define('LOG_FILE', '/var/log/m2usenet/send.log');
define('RATE_LIMIT_FILE', '/var/www/m2usenet/rate_limits.json');
define('HASHCASH_CACHE', '/var/www/m2usenet/hashcash_cache.json');
define('SUBMISSION_LOCK_DIR', '/var/www/m2usenet/locks');
define('SUBMISSION_LOCK_TTL', 120);
define('MAX_NEWSGROUPS', 3);
define('MAX_MESSAGE_SIZE', 65536);
define('MIN_MESSAGE_SIZE', 10);
define('PADDING_ENABLED', false); // FIX: DISABLED - was corrupting messages
define('PADDING_BOUNDARY', 1024);
define('RATE_LIMIT_REQUESTS', 10);
define('RATE_LIMIT_WINDOW', 3600);
define('HASHCASH_MIN_BITS', 20);
define('HASHCASH_CACHE_TTL', 172800);
define('QUIET_MODE', false);

define('MESSAGE_ID_TIMEZONE', 'UTC');
define('MESSAGE_ID_USE_MD5', true);
define('MESSAGE_ID_DOMAIN', 'm2usenet.local');
define('MESSAGE_ID_JITTER_MIN', -30);
define('MESSAGE_ID_JITTER_MAX', 30);

define('BASE_TIMEOUT', 120);
define('MAX_JITTER_MS', 5000);
define('MIN_RANDOM_DELAY_MS', 100);
define('MAX_RANDOM_DELAY_MS', 3000);

define('SOCKS5_PROXY', '127.0.0.1');
define('SOCKS5_PORT', 9050);
define('SOCKS5_TIMEOUT', 120);
define('SMTP_READ_TIMEOUT', 30);
define('SMTP_FINAL_TIMEOUT', 30);

define('MAX_SMTP_RESPONSE_SIZE', 8192);
define('CONNECTION_RETRY_DELAY', 3);

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

function sendMessage($data) {
    secureLog("=== Simplified 2-relay strategy: PRIMARY → FALLBACK ===");
    
    $relay = PRIMARY_RELAY;
    secureLog("Attempting delivery via PRIMARY relay: {$relay['name']} ({$relay['host']}:{$relay['port']})");
    
    $result = sendViaNativePHPSMTP(
        $data, 
        $relay['host'], 
        $relay['port'], 
        $relay['mail2news']
    );
    
    if (!$result['success']) {
        secureLog("PRIMARY relay failed, switching to FALLBACK relay", 'WARNING');
        
        $relay = FALLBACK_RELAY;
        secureLog("Attempting delivery via FALLBACK relay: {$relay['name']} ({$relay['host']}:{$relay['port']})");
        
        $backoff = cryptoRandInt(2, 5);
        secureLog("Waiting {$backoff}s before fallback attempt");
        sleep($backoff);
        
        $result = sendViaNativePHPSMTP(
            $data, 
            $relay['host'], 
            $relay['port'], 
            $relay['mail2news']
        );
    }
    
    if ($result['success']) {
        secureLog("Message delivered successfully via {$relay['name']} relay");
    } else {
        secureLog("Message delivery failed on both PRIMARY and FALLBACK relays", 'ERROR');
    }
    
    return $result;
}

function constantTimeCompare($a, $b) {
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
    $jitterMs = cryptoRandInt(0, MAX_JITTER_MS);
    $totalUs = ($baseSeconds * 1000000) + ($jitterMs * 1000);
    usleep($totalUs);
}

function generateSecureMessageID($domain = null, $useMD5 = null, $timezone = null) {
    $domain = $domain ?? MESSAGE_ID_DOMAIN;
    $useMD5 = $useMD5 ?? MESSAGE_ID_USE_MD5;
    $timezone = $timezone ?? MESSAGE_ID_TIMEZONE;
    
    try {
        $dateTime = new DateTime('now', new DateTimeZone($timezone));
    } catch (Exception $e) {
        secureLog("Invalid timezone '$timezone', using UTC", 'WARNING');
        $dateTime = new DateTime('now', new DateTimeZone('UTC'));
    }
    
    $jitterSeconds = cryptoRandInt(MESSAGE_ID_JITTER_MIN, MESSAGE_ID_JITTER_MAX);
    $dateTime->modify("{$jitterSeconds} seconds");
    
    $dateComponent = $dateTime->format('Ymd.His');
    $randomComponent = bin2hex(cryptoRandBytes(4));
    
    if ($useMD5) {
        $combined = $dateComponent . '.' . $randomComponent;
        $hash = md5($combined);
        $messageId = sprintf("<%s@%s>", $hash, $domain);
    } else {
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
        randomDelay(cryptoRandInt(2, 5));
        return false;
    }
    
    return true;
}

// FIX: Hashcash normalization now strips ALL whitespace consistently
function normalizeHashcashToken($token) {
    return preg_replace('/\s+/', '', trim($token));
}

function checkHashcashReplay($tokenHash) {
    if (!file_exists(HASHCASH_CACHE)) {
        return false;
    }
    
    $cache = json_decode(@file_get_contents(HASHCASH_CACHE), true) ?? [];
    $now = time();
    
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
    
    if (isset($cache[$tokenHash])) {
        secureLog("Replay attack detected - token hash: " . substr($tokenHash, 0, 16), 'WARNING');
        randomDelay(cryptoRandInt(1, 3));
        return true;
    }
    
    return false;
}

function markHashcashUsed($tokenHash) {
    $cache = [];
    if (file_exists(HASHCASH_CACHE)) {
        $cache = json_decode(@file_get_contents(HASHCASH_CACHE), true) ?? [];
    }
    
    $cache[$tokenHash] = time();
    @file_put_contents(HASHCASH_CACHE, json_encode($cache), LOCK_EX);
}

function acquireSubmissionLock($tokenHash) {
    if (!is_dir(SUBMISSION_LOCK_DIR)) {
        @mkdir(SUBMISSION_LOCK_DIR, 0700, true);
    }
    
    $lockFile = SUBMISSION_LOCK_DIR . '/' . $tokenHash . '.lock';
    
    if (file_exists($lockFile)) {
        $lockAge = time() - filemtime($lockFile);
        
        if ($lockAge < SUBMISSION_LOCK_TTL) {
            secureLog("Duplicate submission detected - lock exists (age: {$lockAge}s)", 'WARNING');
            return false;
        } else {
            @unlink($lockFile);
            secureLog("Expired lock removed (age: {$lockAge}s)", 'INFO');
        }
    }
    
    if (@file_put_contents($lockFile, time(), LOCK_EX) === false) {
        secureLog("Failed to create submission lock", 'ERROR');
        return false;
    }
    
    secureLog("Submission lock acquired: " . substr($tokenHash, 0, 16), 'INFO');
    return $lockFile;
}

function releaseSubmissionLock($lockFile) {
    if ($lockFile && file_exists($lockFile)) {
        @unlink($lockFile);
        secureLog("Submission lock released", 'INFO');
    }
}

function cleanupExpiredLocks() {
    if (!is_dir(SUBMISSION_LOCK_DIR)) {
        return;
    }
    
    $now = time();
    $files = @scandir(SUBMISSION_LOCK_DIR);
    
    if (!$files) {
        return;
    }
    
    $cleaned = 0;
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        
        $lockFile = SUBMISSION_LOCK_DIR . '/' . $file;
        $lockAge = $now - @filemtime($lockFile);
        
        if ($lockAge > SUBMISSION_LOCK_TTL) {
            @unlink($lockFile);
            $cleaned++;
        }
    }
    
    if ($cleaned > 0) {
        secureLog("Cleaned up $cleaned expired locks", 'INFO');
    }
}

function verifyHashcash($normalizedToken, $fromEmail) {
    $parts = explode(':', $normalizedToken);
    if (count($parts) !== 7) {
        randomDelay(0);
        return false;
    }
    
    list($version, $bits, $date, $resource, $ext, $rand, $counter) = $parts;
    
    $valid = true;
    
    $valid = $valid && ($version === '1');
    $valid = $valid && ((int)$bits >= HASHCASH_MIN_BITS);
    
    // FIX: Normalize both sides for comparison
    $normalizedResource = preg_replace('/\s+/', '', trim($resource));
    $normalizedEmail = preg_replace('/\s+/', '', trim($fromEmail));
    $valid = $valid && (strcasecmp($normalizedResource, $normalizedEmail) === 0);
    
    if (!$valid) {
        randomDelay(0);
        return false;
    }
    
    $hash = sha1($normalizedToken);
    $requiredZeros = str_repeat('0', (int)((int)$bits / 4));
    
    if (strpos($hash, $requiredZeros) !== 0) {
        randomDelay(0);
        return false;
    }
    
    return true;
}

function validateInput($data) {
    $errors = [];
    
    $required = ['from', 'newsgroups', 'subject', 'xhashcash', 'message', 'csrf_token'];
    foreach ($required as $field) {
        if (!isset($data[$field]) || trim($data[$field]) === '') {
            $errors[] = "Missing required field: $field";
            randomDelay(0);
            return $errors;
        }
    }
    
    if (!verifyCSRFToken($data['csrf_token'])) {
        $errors[] = "Invalid request token";
        randomDelay(0);
        return $errors;
    }
    
    if (!preg_match('/^.+\s*<[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>$/', $data['from'])) {
        $errors[] = "Invalid sender format";
        randomDelay(0);
    }
    
    preg_match('/<([^>]+)>/', $data['from'], $matches);
    $fromEmail = $matches[1] ?? '';
    
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
    
    $msgSize = strlen($data['message']);
    
    if ($msgSize < MIN_MESSAGE_SIZE || $msgSize > MAX_MESSAGE_SIZE) {
        $errors[] = "Invalid message size";
        randomDelay(0);
    }
    
    // FIX: Normalize token once and use hash for all checks
    if (empty($errors)) {
        $normalizedToken = normalizeHashcashToken($data['xhashcash']);
        $tokenHash = hash('sha256', $normalizedToken);
        
        if (!verifyHashcash($normalizedToken, $fromEmail)) {
            $errors[] = "Invalid hashcash token";
            randomDelay(0);
        }
        
        if (empty($errors) && checkHashcashReplay($tokenHash)) {
            $errors[] = "Token already used";
            randomDelay(0);
        }
        
        // Store hash for later use
        $data['_tokenHash'] = $tokenHash;
        $data['_normalizedToken'] = $normalizedToken;
    }
    
    return $errors;
}

// FIX: Padding disabled - was corrupting Usenet messages
function addAdaptivePadding($message) {
    if (!PADDING_ENABLED) {
        return $message;
    }
    
    $msgLen = strlen($message);
    $boundary = PADDING_BOUNDARY;
    
    if ($msgLen >= MAX_MESSAGE_SIZE * 0.95) {
        return $message;
    }
    
    $targetLen = (intdiv($msgLen, $boundary) + 1) * $boundary;
    $paddingNeeded = $targetLen - $msgLen;
    
    $paddingNeeded += cryptoRandInt(-50, 50);
    $paddingNeeded = max(0, min($paddingNeeded, MAX_MESSAGE_SIZE - $msgLen));
    
    if ($paddingNeeded > 0) {
        $paddingChars = [' ', "\t", "\n"];
        $padding = "\n\n";
        
        for ($i = 0; $i < $paddingNeeded - 2; $i++) {
            $padding .= $paddingChars[cryptoRandInt(0, count($paddingChars) - 1)];
        }
        
        return $message . $padding;
    }
    
    return $message;
}

function socks5Connect($destHost, $destPort, $socksHost = SOCKS5_PROXY, $socksPort = SOCKS5_PORT, $timeout = SOCKS5_TIMEOUT) {
    secureLog("Initiating SOCKS5 connection to $destHost:$destPort via $socksHost:$socksPort");
    
    if (!preg_match('/^[a-z2-7]{56}\.onion$/', $destHost)) {
        secureLog("Invalid .onion address format", 'ERROR');
        return false;
    }
    
    randomDelay(0);
    
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
    
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);
    
    secureLog("Connected to SOCKS5 proxy, initiating handshake");
    
    $request = pack('C3', 0x05, 0x01, 0x00);
    
    if (fwrite($socket, $request) === false) {
        secureLog("Failed to write SOCKS5 handshake", 'ERROR');
        fclose($socket);
        return false;
    }
    
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
    
    $domainLen = strlen($destHost);
    $request = pack('C4', 0x05, 0x01, 0x00, 0x03);
    $request .= pack('C', $domainLen);
    $request .= $destHost;
    $request .= pack('n', $destPort);
    
    if (fwrite($socket, $request) === false) {
        secureLog("Failed to write SOCKS5 connect request", 'ERROR');
        fclose($socket);
        return false;
    }
    
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
    
    if ($data['atyp'] === 0x01) {
        fread($socket, 6);
    } elseif ($data['atyp'] === 0x03) {
        $len = ord(fread($socket, 1));
        fread($socket, $len + 2);
    } elseif ($data['atyp'] === 0x04) {
        fread($socket, 18);
    }
    
    secureLog("SOCKS5 connection established successfully");
    
    return $socket;
}

function smtpSendCommand($socket, $command, $expectedCode = null) {
    if (!empty($command)) {
        secureLog("SMTP >> " . trim($command));
        
        if (fwrite($socket, $command) === false) {
            secureLog("Failed to write SMTP command", 'ERROR');
            return false;
        }
        
        if (!fflush($socket)) {
            secureLog("Warning: fflush failed after command", 'WARNING');
        }
    }
    
    $response = '';
    $bytesRead = 0;
    $startTime = microtime(true);
    
    while (!feof($socket) && $bytesRead < MAX_SMTP_RESPONSE_SIZE) {
        $line = fgets($socket, 1024);
        
        if ($line === false) {
            $elapsed = microtime(true) - $startTime;
            secureLog("fgets returned false after {$elapsed}s (timeout or closed)", 'WARNING');
            break;
        }
        
        $response .= $line;
        $bytesRead += strlen($line);
        
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }
    
    if (empty($response)) {
        secureLog("Empty SMTP response (connection may be closed)", 'ERROR');
        return false;
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
    
    $delay = cryptoRandInt(MIN_RANDOM_DELAY_MS, MAX_RANDOM_DELAY_MS) / 1000;
    randomDelay($delay);
    
    $startTime = microtime(true);
    
    $socket = socks5Connect($smtpRelay, $smtpPort);
    
    if (!$socket) {
        secureLog("SOCKS5 connection failed", 'ERROR');
        return ['success' => false, 'message' => 'Gateway connection failed'];
    }
    
    $connectTime = microtime(true) - $startTime;
    secureLog(sprintf("SOCKS5 connection established in %.2fs", $connectTime));
    
    stream_set_timeout($socket, SMTP_READ_TIMEOUT);
    
    try {
        $greeting = smtpSendCommand($socket, '', 220);
        
        if ($greeting === false) {
            throw new Exception("No SMTP greeting received");
        }
        
        $response = smtpSendCommand($socket, "HELO m2usenet.local\r\n", 250);
        
        if ($response === false) {
            throw new Exception("HELO failed");
        }
        
        preg_match('/<([^>]+)>/', $data['from'], $matches);
        $fromEmail = $matches[1] ?? 'noreply@m2usenet.local';
        
        $response = smtpSendCommand($socket, "MAIL FROM:<$fromEmail>\r\n", 250);
        
        if ($response === false) {
            throw new Exception("MAIL FROM rejected");
        }
        
        $response = smtpSendCommand($socket, "RCPT TO:<$mail2newsAddress>\r\n", 250);
        
        if ($response === false) {
            throw new Exception("RCPT TO rejected");
        }
        
        $response = smtpSendCommand($socket, "DATA\r\n", 354);
        
        if ($response === false) {
            throw new Exception("DATA command rejected");
        }
        
        $messageId = generateSecureMessageID();
        
        $headers = [
            sprintf("From: %s", $data['from']),
            sprintf("To: %s", $mail2newsAddress),
            sprintf("Subject: %s", $data['subject']),
            sprintf("Message-ID: %s", $messageId),
            sprintf("Date: %s", gmdate('r', time() + cryptoRandInt(-1800, 1800))),
            sprintf("Newsgroups: %s", $data['newsgroups'])
            // X-Hashcash removed: exposes real timestamp (privacy leak)
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
        $headers[] = "User-Agent: m2usenet-web v2.1.0";
        $headers[] = "X-No-Archive: Yes";
        
        $body = addAdaptivePadding($data['message']);
        
        $fullMessage = implode("\r\n", $headers) . "\r\n\r\n" . $body;
        
        // Dot stuffing per RFC 5321
        $lines = explode("\r\n", $fullMessage);
        $stuffedLines = [];
        
        foreach ($lines as $line) {
            if (isset($line[0]) && $line[0] === '.') {
                $stuffedLines[] = '.' . $line;
            } else {
                $stuffedLines[] = $line;
            }
        }
        
        $stuffedMessage = implode("\r\n", $stuffedLines) . "\r\n";
        
        secureLog("Sending message body (" . strlen($stuffedMessage) . " bytes, " . count($lines) . " lines)");
        
        $written = fwrite($socket, $stuffedMessage);
        if ($written === false || $written === 0) {
            throw new Exception("Failed to write message body");
        }
        
        if (!fflush($socket)) {
            secureLog("Warning: fflush failed after message body", 'WARNING');
        }
        
        secureLog("Message body sent, sending terminator");
        
        $written = fwrite($socket, ".\r\n");
        if ($written === false || $written === 0) {
            throw new Exception("Failed to write DATA terminator");
        }
        
        if (!fflush($socket)) {
            secureLog("Warning: fflush terminator failed", 'WARNING');
        }
        
        secureLog("Terminator sent, waiting for server response");
        
        $meta = stream_get_meta_data($socket);
        secureLog("Connection status: " . ($meta['eof'] ? 'EOF/CLOSED' : 'OPEN') . 
                  ", blocked: " . ($meta['blocked'] ? 'yes' : 'no') . 
                  ", timed_out: " . ($meta['timed_out'] ? 'YES' : 'no'));
        
        if ($meta['eof']) {
            throw new Exception("Connection closed by server after terminator");
        }
        
        stream_set_timeout($socket, SMTP_FINAL_TIMEOUT);
        
        $response = '';
        $bytesRead = 0;
        $responseStart = microtime(true);
        $loopCount = 0;
        
        while (!feof($socket) && $bytesRead < MAX_SMTP_RESPONSE_SIZE) {
            $loopCount++;
            
            $read = [$socket];
            $write = null;
            $except = null;
            $selectResult = @stream_select($read, $write, $except, 1);
            
            if ($selectResult === false) {
                secureLog("stream_select failed", 'ERROR');
                break;
            } elseif ($selectResult === 0) {
                $elapsed = microtime(true) - $responseStart;
                if ($elapsed > SMTP_FINAL_TIMEOUT) {
                    secureLog("Timeout waiting for response after {$elapsed}s", 'ERROR');
                    break;
                }
                continue;
            }
            
            $line = fgets($socket, 1024);
            
            if ($line === false) {
                $elapsed = microtime(true) - $responseStart;
                $meta = stream_get_meta_data($socket);
                secureLog("fgets returned false after {$elapsed}s (loops: $loopCount)", 'ERROR');
                secureLog("Meta: eof=" . ($meta['eof'] ? '1' : '0') . 
                          ", timed_out=" . ($meta['timed_out'] ? '1' : '0'), 'ERROR');
                break;
            }
            
            $response .= $line;
            $bytesRead += strlen($line);
            
            if (preg_match('/^\d{3} /', $line)) {
                break;
            }
        }
        
        if (empty($response)) {
            throw new Exception("Empty final response - server may have closed connection");
        }
        
        secureLog("SMTP << " . trim($response));
        
        if (!preg_match('/^250/', $response)) {
            throw new Exception("Message rejected: " . trim($response));
        }
        
        secureLog("Message accepted by server");
        
        @smtpSendCommand($socket, "QUIT\r\n", 221);
        
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
        
        if (is_resource($socket)) {
            @stream_socket_shutdown($socket, STREAM_SHUT_RDWR);
            @fclose($socket);
        }
        
        return ['success' => false, 'message' => 'SMTP protocol error'];
    }
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
                <p><small>Strategy: fog:25 primary → smtp:25 fallback</small></p>
            </div>
            <p><a href="index.php">Send another message</a></p>
        </div>
    </div>
</body>
</html>
    <?php
    exit;
}

try {
    secureLog("=== New request received ===");
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        secureLog("Invalid request method: " . $_SERVER['REQUEST_METHOD'], 'WARNING');
        http_response_code(405);
        die("Method not allowed");
    }
    
    if (cryptoRandInt(1, 10) === 1) {
        cleanupExpiredLocks();
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
    
    // Use token hash from validation
    $tokenHash = $data['_tokenHash'];
    
    $lockFile = acquireSubmissionLock($tokenHash);
    
    if ($lockFile === false) {
        secureLog("Duplicate submission attempt blocked", 'WARNING');
        errorResponse("Duplicate submission detected. Please wait before sending again.");
    }
    
    markHashcashUsed($tokenHash);
    secureLog("Hashcash token marked as used", 'INFO');
    
    $result = sendMessage($data);
    
    releaseSubmissionLock($lockFile);
    
    if ($result['success']) {
        secureLog("Request completed successfully");
        successResponse($result['messageId'], $result['gateway']);
    } else {
        secureLog("Request failed: " . $result['message'], 'ERROR');
        errorResponse($result['message']);
    }
    
} catch (Exception $e) {
    if (isset($lockFile) && $lockFile) {
        releaseSubmissionLock($lockFile);
    }
    
    secureLog("=== Fatal exception: " . $e->getMessage() . " ===", 'CRITICAL');
    secureLog("Stack trace: " . $e->getTraceAsString(), 'ERROR');
    errorResponse("System error occurred");
}

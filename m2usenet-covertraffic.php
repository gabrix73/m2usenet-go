#!/usr/bin/env php
<?php
/**
 * m2usenet Cover Traffic Generator
 * Sends random dummy posts to break traffic analysis
 * 
 * Usage: Run via cron every hour
 * Crontab: 0 * * * * /usr/local/bin/m2usenet-covertraffic.php >> /var/log/m2usenet/cover.log 2>&1
 */

// Configuration
define('SOCKS5_PROXY', '127.0.0.1');
define('SOCKS5_PORT', 9050);
define('SOCKS5_TIMEOUT', 120);
define('SMTP_READ_TIMEOUT', 30);
define('SMTP_FINAL_TIMEOUT', 30);
define('MAX_SMTP_RESPONSE_SIZE', 8192);

// Primary relay (fog)
define('PRIMARY_RELAY', [
    'host' => '4uwpi53u524xdphjw2dv5kywsxmyjxtk4facb76jgl3sc3nda3sz4fqd.onion',
    'port' => 25,
    'mail2news' => 'mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion'
]);

// Logging
function coverLog($message) {
    echo "[" . gmdate('Y-m-d H:i:s') . " UTC] $message\n";
}

// Crypto functions
function cryptoRandBytes($length) {
    return random_bytes($length);
}

function cryptoRandInt($min, $max) {
    return random_int($min, $max);
}

// Generate random realistic text
function generateRandomText($minLength, $maxLength) {
    $length = cryptoRandInt($minLength, $maxLength);
    
    $sentences = [
        "This is a test message for network connectivity.",
        "Anonymous communication systems require regular testing.",
        "Usenet remains an important decentralized network.",
        "Privacy-focused tools help protect user anonymity.",
        "Secure messaging relies on proper implementation.",
        "Network latency can vary significantly over Tor.",
        "Distributed systems provide resilience and redundancy.",
        "Cryptographic signatures ensure message integrity.",
        "Random traffic patterns improve privacy protection.",
        "Testing infrastructure is essential for reliability."
    ];
    
    $text = '';
    while (strlen($text) < $length) {
        $text .= $sentences[array_rand($sentences)] . " ";
    }
    
    return trim(substr($text, 0, $length));
}

// Generate dummy hashcash token
function generateDummyHashcash() {
    $now = new DateTime('now', new DateTimeZone('UTC'));
    $timestamp = $now->format('ymdHis');
    $resource = 'covertraffic@m2usenet.invalid';
    $rand = cryptoRandInt(100000, 999999);
    
    // Simple hashcash format (not mined, just for structure)
    return "1:20:{$timestamp}:{$resource}::{$rand}:0";
}

// Generate Message-ID
function generateMessageID() {
    $dateTime = new DateTime('now', new DateTimeZone('UTC'));
    $jitterSeconds = cryptoRandInt(-30, 30);
    $dateTime->modify("{$jitterSeconds} seconds");
    
    $dateComponent = $dateTime->format('Ymd.His');
    $randomComponent = bin2hex(cryptoRandBytes(4));
    $combined = $dateComponent . '.' . $randomComponent;
    $hash = md5($combined);
    
    return sprintf("<%s@m2usenet.local>", $hash);
}

// SOCKS5 connection (copied from send.php)
function socks5Connect($destHost, $destPort) {
    $socket = @stream_socket_client(
        "tcp://" . SOCKS5_PROXY . ":" . SOCKS5_PORT,
        $errno,
        $errstr,
        SOCKS5_TIMEOUT,
        STREAM_CLIENT_CONNECT
    );
    
    if (!$socket) {
        coverLog("ERROR: Failed to connect to SOCKS5 proxy");
        return false;
    }
    
    stream_set_timeout($socket, SOCKS5_TIMEOUT);
    stream_set_blocking($socket, true);
    
    // SOCKS5 handshake
    $request = pack('C3', 0x05, 0x01, 0x00);
    if (fwrite($socket, $request) === false) {
        fclose($socket);
        return false;
    }
    
    $response = fread($socket, 2);
    if (strlen($response) !== 2) {
        fclose($socket);
        return false;
    }
    
    $data = unpack('Cver/Cmethod', $response);
    if ($data['ver'] !== 0x05 || $data['method'] !== 0x00) {
        fclose($socket);
        return false;
    }
    
    // Connect request
    $domainLen = strlen($destHost);
    $request = pack('C4', 0x05, 0x01, 0x00, 0x03);
    $request .= pack('C', $domainLen);
    $request .= $destHost;
    $request .= pack('n', $destPort);
    
    if (fwrite($socket, $request) === false) {
        fclose($socket);
        return false;
    }
    
    $response = fread($socket, 4);
    if (strlen($response) < 4) {
        fclose($socket);
        return false;
    }
    
    $data = unpack('Cver/Crep/Crsv/Catyp', $response);
    if ($data['ver'] !== 0x05 || $data['rep'] !== 0x00) {
        fclose($socket);
        return false;
    }
    
    // Read bind address
    if ($data['atyp'] === 0x01) {
        fread($socket, 6);
    } elseif ($data['atyp'] === 0x03) {
        $len = ord(fread($socket, 1));
        fread($socket, $len + 2);
    } elseif ($data['atyp'] === 0x04) {
        fread($socket, 18);
    }
    
    return $socket;
}

// Send SMTP command
function smtpCommand($socket, $command, $expectedCode = null) {
    if (!empty($command)) {
        if (fwrite($socket, $command) === false) {
            return false;
        }
        fflush($socket);
    }
    
    $response = '';
    $bytesRead = 0;
    
    while (!feof($socket) && $bytesRead < MAX_SMTP_RESPONSE_SIZE) {
        $line = fgets($socket, 1024);
        if ($line === false) break;
        
        $response .= $line;
        $bytesRead += strlen($line);
        
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }
    
    if (empty($response)) {
        return false;
    }
    
    if ($expectedCode !== null) {
        if (!preg_match("/^$expectedCode/", $response)) {
            return false;
        }
    }
    
    return $response;
}

// Send dummy message
function sendDummyMessage() {
    coverLog("Sending dummy message via cover traffic");
    
    $relay = PRIMARY_RELAY;
    $socket = socks5Connect($relay['host'], $relay['port']);
    
    if (!$socket) {
        coverLog("ERROR: SOCKS5 connection failed");
        return false;
    }
    
    stream_set_timeout($socket, SMTP_READ_TIMEOUT);
    
    try {
        // SMTP session
        if (smtpCommand($socket, '', 220) === false) {
            throw new Exception("No greeting");
        }
        
        if (smtpCommand($socket, "HELO m2usenet.local\r\n", 250) === false) {
            throw new Exception("HELO failed");
        }
        
        $fromEmail = 'covertraffic' . cryptoRandInt(1000, 9999) . '@m2usenet.invalid';
        
        if (smtpCommand($socket, "MAIL FROM:<$fromEmail>\r\n", 250) === false) {
            throw new Exception("MAIL FROM failed");
        }
        
        if (smtpCommand($socket, "RCPT TO:<{$relay['mail2news']}>\r\n", 250) === false) {
            throw new Exception("RCPT TO failed");
        }
        
        if (smtpCommand($socket, "DATA\r\n", 354) === false) {
            throw new Exception("DATA failed");
        }
        
        // Build message
        $messageId = generateMessageID();
        $jitter = cryptoRandInt(-1800, 1800);
        
        $headers = [
            "From: Anonymous <$fromEmail>",
            "To: {$relay['mail2news']}",
            "Subject: Test message " . bin2hex(cryptoRandBytes(4)),
            "Message-ID: $messageId",
            "Date: " . gmdate('r', time() + $jitter),
            "Newsgroups: alt.test",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: 8bit",
            "User-Agent: m2usenet-web v2.1.0",
            "X-No-Archive: Yes"
        ];
        
        $body = generateRandomText(500, 1500);
        $fullMessage = implode("\r\n", $headers) . "\r\n\r\n" . $body;
        
        // Dot stuffing
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
        
        // Send message
        if (fwrite($socket, $stuffedMessage) === false) {
            throw new Exception("Failed to write message");
        }
        fflush($socket);
        
        // Send terminator
        if (fwrite($socket, ".\r\n") === false) {
            throw new Exception("Failed to write terminator");
        }
        fflush($socket);
        
        stream_set_timeout($socket, SMTP_FINAL_TIMEOUT);
        
        // Wait for response
        $response = '';
        $bytesRead = 0;
        while (!feof($socket) && $bytesRead < MAX_SMTP_RESPONSE_SIZE) {
            $read = [$socket];
            $write = null;
            $except = null;
            $selectResult = @stream_select($read, $write, $except, 1);
            
            if ($selectResult === false) break;
            if ($selectResult === 0) {
                if ((microtime(true) - $startTime) > SMTP_FINAL_TIMEOUT) break;
                continue;
            }
            
            $line = fgets($socket, 1024);
            if ($line === false) break;
            
            $response .= $line;
            $bytesRead += strlen($line);
            
            if (preg_match('/^\d{3} /', $line)) {
                break;
            }
        }
        
        if (!preg_match('/^250/', $response)) {
            throw new Exception("Message rejected");
        }
        
        coverLog("SUCCESS: Dummy message sent (Message-ID: $messageId)");
        
        @smtpCommand($socket, "QUIT\r\n", 221);
        fclose($socket);
        
        return true;
        
    } catch (Exception $e) {
        coverLog("ERROR: " . $e->getMessage());
        if (is_resource($socket)) {
            @fclose($socket);
        }
        return false;
    }
}

// Main execution
coverLog("=== m2usenet Cover Traffic Generator v2.1.0 ===");

// 50% chance to send dummy
if (cryptoRandInt(1, 100) > 50) {
    coverLog("Skipping this round (random decision)");
    exit(0);
}

// Send 1-2 dummy messages
$dummyCount = cryptoRandInt(1, 2);
coverLog("Sending $dummyCount dummy message(s)");

for ($i = 0; $i < $dummyCount; $i++) {
    $success = sendDummyMessage();
    
    if ($success && $i < $dummyCount - 1) {
        // Delay between dummies
        $delay = cryptoRandInt(300, 900);
        coverLog("Waiting {$delay}s before next dummy");
        sleep($delay);
    }
}

coverLog("=== Cover traffic round complete ===");
exit(0);

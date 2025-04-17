<?php
// /var/www/mail2usenet/send.php
// Send the post via the "mail2news" transport, enforcing Ed25519 signature.

// Read POST data
$from        = $_POST['from']         ?? '';
$newsgroups  = $_POST['newsgroups']   ?? '';
$subject     = $_POST['subject']      ?? '';
$references  = $_POST['references']   ?? '';
$hashcash    = $_POST['xhashcash']    ?? '';
$pubkey      = $_POST['x-ed25519-pub'] ?? '';
$sig         = $_POST['x-ed25519-sig'] ?? '';
$message     = $_POST['message']      ?? '';

// Validate required fields
if (!$from || !$newsgroups || !$subject || !$hashcash || !$sig || !$message) {
    http_response_code(400);
    echo "Missing required fields. Signature is mandatory.";
    exit;
}

// Limit to 3 newsgroups
$groups = array_filter(array_map('trim', explode(',', $newsgroups)));
if (count($groups) > 3) {
    $groups = array_slice($groups, 0, 3);
}
$newsgroups = implode(', ', $groups);

// Build raw email with dummy To for sendmail -t
$headers   = [];
$headers[] = "From: $from";
$headers[] = "To: mail2news@localhost";
$headers[] = "Newsgroups: $newsgroups";
$headers[] = "Subject: $subject";
if ($references) {
    $headers[] = "References: $references";
}
// PoW header
$headers[] = "X-Hashcash: $hashcash";
// Enforce signature immediately after PoW
$headers[] = "X-Ed25519-Sig: $sig";
// Optionally include public key header
if ($pubkey) {
    $headers[] = "X-Ed25519-Pub: $pubkey";
}
$headers[] = "X-No-Archive: Yes";
$headers[] = "Mime-Version: 1.0";
$headers[] = "Content-Type: text/plain; charset=UTF-8";
$headers[] = "Content-Transfer-Encoding: 7bit";
$headers[] = "";  // end of headers

$rawEmail = implode("\r\n", $headers) . "\r\n" . $message . "\r\n";

// Send via sendmail using mail2news transport
$sendmail = '/usr/sbin/sendmail';
$cmd = escapeshellcmd($sendmail) . ' -i -oTransport=mail2news -t';

$descriptors = [
    0 => ['pipe', 'r'],  // stdin
    1 => ['pipe', 'w'],  // stdout
    2 => ['pipe', 'w'],  // stderr
];

$process = proc_open($cmd, $descriptors, $pipes);
if (!is_resource($process)) {
    http_response_code(500);
    echo "Failed to invoke sendmail.";
    exit;
}

// Write the raw email
fwrite($pipes[0], $rawEmail);
fclose($pipes[0]);

// Capture and close outputs
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);

$returnCode = proc_close($process);
if ($returnCode !== 0) {
    http_response_code(500);
    echo "Sendmail error (code {$returnCode}):\n" . nl2br(htmlspecialchars($stderr));
    exit;
}

// Success page
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Message Sent</title>
  <style>
    body { font-family: sans-serif; text-align: center; padding: 50px; }
    a.button {
      display: inline-block;
      margin-top: 20px;
      padding: 10px 20px;
      background: #4caf50;
      color: white;
      text-decoration: none;
      border-radius: 4px;
    }
    a.button:hover { background: #45a049; }
  </style>
</head>
<body>
  <h1>Message Sent Successfully</h1>
  <p>Your post has been handed off to the mail2news transport.</p>
  <a class="button" href="https://m2usenet.virebent.art">Return to Home</a>
</body>
</html>

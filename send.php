<?php
// /var/www/mail2usenet/send.php
// Hands the post to Postfix transport “mail2news”, enforcing Ed25519 signature.

$required = [
    'from', 'newsgroups', 'subject', 'xhashcash', 'x-ed25519-sig', 'message'
];

// Collect POST values
$data = [];
foreach ($_POST as $k => $v) $data[$k] = trim($v);

// Check required fields
$missing = array_filter($required, fn($f) => empty($data[$f] ?? ''));
if ($missing) {
    showError(
        'Missing required fields: ' . implode(', ', $missing) .
        '. Remember: you must click <em>Sign&nbsp;Message</em> on the Digital Signature tab before sending.'
    );
}

// Limit newsgroups to 3
$groups = array_slice(
    array_filter(array_map('trim', explode(',', $data['newsgroups']))),
    0, 3
);
$data['newsgroups'] = implode(', ', $groups);

// Build raw email
$hdr = [];
$hdr[] = 'From: ' . $data['from'];
$hdr[] = 'To: mail2news@localhost';                 // dummy for sendmail -t
$hdr[] = 'Newsgroups: ' . $data['newsgroups'];
$hdr[] = 'Subject: ' . $data['subject'];
if (!empty($data['references'])) $hdr[] = 'References: ' . $data['references'];
$hdr[] = 'X-Hashcash: ' . $data['xhashcash'];
$hdr[] = 'X-Ed25519-Sig: ' . $data['x-ed25519-sig'];
if (!empty($data['x-ed25519-pub'])) {
    $hdr[] = 'X-Ed25519-Pub: ' . $data['x-ed25519-pub'];
}
$hdr[] = 'X-No-Archive: Yes';
$hdr[] = 'Mime-Version: 1.0';
$hdr[] = 'Content-Type: text/plain; charset=UTF-8';
$hdr[] = 'Content-Transfer-Encoding: 7bit';
$hdr[] = '';                                      // blank line before body

$raw = implode("\r\n", $hdr) . "\r\n" . $data['message'] . "\r\n";

// Send via sendmail using the custom transport
$sendmail = '/usr/sbin/sendmail';
$cmd = escapeshellcmd($sendmail) . ' -i -oTransport=mail2news -t';

$descriptors = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$proc = proc_open($cmd, $descriptors, $pipes);
if (!is_resource($proc)) showError('Failed to invoke sendmail.');

fwrite($pipes[0], $raw);
fclose($pipes[0]);

$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);

$code = proc_close($proc);
if ($code !== 0) {
    showError('Sendmail error (code ' . $code . '):<br>' . nl2br(htmlspecialchars($stderr)));
}

// ------------------ success page ------------------
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Post Sent</title>
  <style>
    body { font-family:sans-serif; text-align:center; padding:50px; }
    a.button { display:inline-block; margin-top:20px; padding:10px 20px;
               background:#4caf50; color:#fff; border-radius:4px; text-decoration:none; }
    a.button:hover { background:#45a049; }
  </style>
</head>
<body>
  <h1>Message Sent Successfully</h1>
  <p>Your article was handed off to <code>mail2news</code> and should appear in the newsgroups soon.</p>
  <a class="button" href="https://m2usenet.virebent.art">Return to Home</a>
</body>
</html>

<?php
// -------- helper --------
function showError(string $msg): void {
    http_response_code(400);
    ?>
    <!DOCTYPE html>
    <html lang="en"><head>
      <meta charset="UTF-8"><title>Error</title>
      <style>
        body { font-family:sans-serif; text-align:center; padding:50px; color:#d00; }
        a { color:#337ab7; }
      </style>
    </head><body>
      <h1>Submission Error</h1>
      <p><?= $msg ?></p>
      <p><a href="https://m2usenet.virebent.art">Return to Home</a></p>
    </body></html>
    <?php
    exit;
}
?>

<?php
// /var/www/m2usenet/index.php
// m2usenet v2.0.0 - Hardened Gateway Interface

// Start session for CSRF token
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
    session_start();
}

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>m2usenet Gateway v2.0</title>
  <style>
    :root {
      --background: #f9f9f9;
      --card-bg: #fff;
      --text: #333;
      --border: #ccc;
      --primary: #4caf50;
      --primary-hover: #45a049;
      --tab-bg: #eee;
      --input-bg: #fff;
      --input-readonly: #eee;
      --progress-bg: #ddd;
      --success: #28a745;
      --warning: #ffc107;
      --error: #dc3545;
    }

    .dark-theme {
      --background: #1a1a1a;
      --card-bg: #2c2c2c;
      --text: #e0e0e0;
      --border: #444;
      --primary: #5cbb60;
      --primary-hover: #4caf50;
      --tab-bg: #333;
      --input-bg: #3c3c3c;
      --input-readonly: #2a2a2a;
      --progress-bg: #444;
    }

    body {
      background: var(--background);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 0;
      transition: background 0.3s ease;
    }

    .container {
      max-width: 800px;
      margin: auto;
      padding: 20px;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .theme-toggle {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .toggle {
      position: relative;
      width: 60px;
      height: 30px;
      background: #ccc;
      border-radius: 30px;
      padding: 4px;
      cursor: pointer;
      transition: 0.3s;
    }

    .toggle:before {
      content: '';
      position: absolute;
      width: 26px;
      height: 26px;
      border-radius: 50%;
      background: white;
      top: 2px;
      left: 2px;
      transition: 0.3s;
    }

    input[type="checkbox"]:checked + .toggle {
      background: #4caf50;
    }

    input[type="checkbox"]:checked + .toggle:before {
      transform: translateX(30px);
    }

    input[type="checkbox"] {
      display: none;
    }

    /* Notification System */
    .notification {
      position: fixed;
      top: 20px;
      right: 20px;
      max-width: 400px;
      padding: 15px 20px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      z-index: 10000;
      animation: slideIn 0.3s ease;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .notification.success {
      background: var(--success);
      color: white;
    }

    .notification.error {
      background: var(--error);
      color: white;
    }

    .notification.warning {
      background: var(--warning);
      color: #333;
    }

    .notification.info {
      background: #007bff;
      color: white;
    }

    @keyframes slideIn {
      from {
        transform: translateX(400px);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }

    .notification-icon {
      font-size: 1.5em;
    }

    .notification-close {
      margin-left: auto;
      cursor: pointer;
      font-size: 1.2em;
      opacity: 0.8;
    }

    .notification-close:hover {
      opacity: 1;
    }

    .section-info {
      background: var(--card-bg);
      border-left: 4px solid var(--primary);
      padding: 10px 15px;
      margin-bottom: 15px;
      border-radius: 0 4px 4px 0;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .tabs {
      display: flex;
      flex-direction: column;
      gap: 8px;
      margin-bottom: 15px;
    }

    .tabs button {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 12px 15px;
      border: none;
      background: var(--tab-bg);
      color: var(--text);
      cursor: pointer;
      border-radius: 4px;
      font-weight: bold;
      transition: background 0.2s, transform 0.1s;
      position: relative;
    }

    .tabs button:hover {
      background: var(--primary);
      color: white;
    }

    .tabs button:active {
      transform: scale(0.98);
    }

    .tabs button.completed::after {
      content: '✓';
      position: absolute;
      right: 15px;
      background: var(--success);
      color: white;
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.9em;
    }

    .tab-content {
      display: none;
      padding: 20px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      margin-bottom: 20px;
    }

    .tab-content.active {
      display: block;
    }

    label {
      display: block;
      margin-top: 15px;
      font-weight: bold;
      margin-bottom: 5px;
    }

    input, textarea, select {
      width: 100%;
      padding: 10px;
      margin-top: 5px;
      box-sizing: border-box;
      border: 1px solid var(--border);
      border-radius: 4px;
      background: var(--input-bg);
      color: var(--text);
      font-family: inherit;
    }

    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(76, 175, 80, 0.2);
    }

    input.error, textarea.error {
      border-color: var(--error);
    }

    input[readonly], textarea[readonly] {
      background: var(--input-readonly);
      cursor: not-allowed;
      border: 2px solid #999;
    }

    button {
      margin-top: 15px;
      padding: 12px 20px;
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
      transition: background 0.2s, opacity 0.2s;
      font-family: inherit;
    }

    button:hover:not(:disabled) {
      background: var(--primary-hover);
    }

    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .progress-bar {
      width: 100%;
      background: var(--progress-bg);
      border-radius: 5px;
      overflow: hidden;
      height: 20px;
      margin-top: 10px;
    }

    .progress-bar-inner {
      height: 100%;
      width: 0;
      background: var(--primary);
      text-align: center;
      color: white;
      line-height: 20px;
      transition: width 0.3s;
      font-size: 0.85em;
    }

    .output-field {
      margin-top: 15px;
      padding: 10px;
      background: var(--input-readonly);
      border: 1px solid var(--border);
      border-radius: 4px;
      word-break: break-all;
      min-height: 30px;
      font-family: monospace;
      font-size: 0.9em;
    }

    .output-field.empty {
      color: #999;
      font-style: italic;
    }

    .gateway-info {
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 15px;
      margin: 15px 0;
      border-radius: 4px;
      border-left: 4px solid #007bff;
    }

    .gateway-item {
      display: flex;
      align-items: center;
      padding: 8px 0;
      border-bottom: 1px solid var(--border);
    }

    .gateway-item:last-child {
      border-bottom: none;
    }

    .gateway-priority {
      background: #007bff;
      color: white;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.8em;
      margin-right: 10px;
      min-width: 70px;
      text-align: center;
    }

    .gateway-priority.secondary {
      background: #6c757d;
    }

    .gateway-priority.fallback {
      background: #ffc107;
      color: #333;
    }

    .gateway-address {
      font-family: monospace;
      background: var(--input-readonly);
      padding: 4px 8px;
      border-radius: 4px;
      flex: 1;
      font-size: 0.85em;
    }

    footer {
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
      font-size: 0.9em;
      color: #888;
    }

    .footer-links {
      display: flex;
      justify-content: center;
      gap: 20px;
      margin-top: 10px;
    }

    .footer-links a {
      color: var(--primary);
      text-decoration: none;
      transition: color 0.2s;
    }

    .footer-links a:hover {
      color: var(--primary-hover);
      text-decoration: underline;
    }

    .step-indicator {
      font-size: 0.85em;
      color: #666;
      margin-bottom: 10px;
    }

    @media (max-width: 600px) {
      .container {
        padding: 10px;
      }
      .tab-content {
        padding: 15px 10px;
      }
      .footer-links {
        flex-direction: column;
        gap: 10px;
      }
      .gateway-item {
        flex-direction: column;
        align-items: flex-start;
        gap: 5px;
      }
      .gateway-address {
        width: 100%;
      }
      .notification {
        right: 10px;
        left: 10px;
        max-width: none;
      }
    }
  </style>
  <!-- Include both TweetNaCl libraries -->
  <script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/tweetnacl-util@0.15.1/nacl-util.min.js"></script>
</head>
<body>
<div class="container">
  <header>
    <h1>m2usenet Gateway v2.0</h1>
    <div class="theme-toggle">
      <span>🌞</span>
      <input type="checkbox" id="themeToggle">
      <label for="themeToggle" class="toggle"></label>
      <span>🌙</span>
    </div>
  </header>

  <div class="tabs">
    <button id="tabBtn1" onclick="showTab('pow')">
      <span>1. Generate Hashcash Token</span>
    </button>
    <button id="tabBtn2" onclick="showTab('sign')">
      <span>2. Sign Message</span>
    </button>
    <button id="tabBtn3" onclick="showTab('send')">
      <span>3. Send Message</span>
    </button>
  </div>

  <div id="pow" class="tab-content active">
    <h2>Proof-of-Work Token</h2>

    <div class="section-info">
      <p><strong>About m2usenet:</strong> This application is a privacy-focused gateway that sends your messages to Usenet newsgroups via our mail2news gateways on the onion network. No access logs are collected, and your messages are routed through secure gateways.</p>
      <p><strong>What is this?</strong> This step generates a "proof-of-work" token (hashcash) that prevents spam by requiring your computer to perform some calculations. This is similar to how cryptocurrencies work - you need to "mine" a valid token before sending a message.</p>
      <p><strong>How to use:</strong> Enter your email address, select the difficulty level (higher bits = longer processing time), and click "Generate Token". Your browser will mine a valid token that will be required in the next steps.</p>
    </div>

    <label>Email (resource): <input type="email" id="hcEmail" placeholder="your@email.com" required></label>
    <label>Difficulty (bits):
      <select id="hcBits">
        <option value="16">16 bits (very fast, ~instant - recommended for Tor Browser)</option>
        <option value="20" selected>20 bits (fast, ~few seconds)</option>
        <option value="24">24 bits (medium, ~30-60 seconds)</option>
        <option value="28">28 bits (slow, ~several minutes)</option>
      </select>
    </label>
    <button id="genTokenBtn">Generate Token</button>
    <div class="progress-bar"><div id="tokenProgress" class="progress-bar-inner">Ready</div></div>
    <label>Generated Token:</label>
    <div id="tokenOutput" class="output-field empty">Token will appear here after generation</div>
  </div>

  <div id="sign" class="tab-content">
    <h2>Ed25519 Digital Signature</h2>

    <div class="section-info">
      <p><strong>What is this?</strong> This step creates a digital signature for your message using the Ed25519 cryptographic algorithm. This signature helps verify that the message was sent by you and hasn't been tampered with.</p>
      <p><strong>How to use:</strong> First, generate a key pair (this creates a public and private key). Then, write your message and click "Sign Message". This will create a digital signature that will be attached to your post.</p>
    </div>

    <label>Email used for PoW:</label>
    <input type="text" id="readonlyEmailSign" readonly>
    <label>Message to Sign:</label>
    <textarea id="messageToSign" rows="6" placeholder="Write your message here..." required></textarea>
    <button id="genKeyBtn">Generate Key Pair</button>
    <button id="signMsgBtn" disabled>Sign Message</button>

    <label>Generated Public Key:</label>
    <div id="pubKeyOutput" class="output-field empty">Public key will appear here</div>
    <label>Generated Signature:</label>
    <div id="signatureOutput" class="output-field empty">Signature will appear here</div>
  </div>

  <div id="send" class="tab-content">
    <h2>Send Message</h2>

    <div class="section-info">
      <p><strong>What is this?</strong> This final step sends your signed message to the Usenet network via mail2news gateways. m2usenet v2.0.0 uses Tor for all connections with automatic fallback.</p>

      <div class="gateway-info">
        <h4>🔐 Full Onion Network Path</h4>
        <p style="margin-bottom: 15px; font-size: 0.95em;">Your message travels entirely within the Tor network through these three components:</p>

      <div class="info-section" style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
         <strong>SMTP Relay: <a href="https://github.com/gabrix73/fog" target="_blank" style="color: #007bff; text-decoration: none;">Fog Sphinx Mixnet (v1.3.3)</a></strong>
         <p style="font-size: 0.85em; margin: 8px 0 0 0; color: #666; line-height: 1.5;">
          Random selection from 4-node mixnet operating exclusively over Tor. 
          Each message routes through 3-6 hops with AES-256-GCM encryption, forward secrecy, 
          and automatic failover for maximum reliability and anonymity.
      </p>
    <details style="margin-top: 8px; font-size: 0.8em;">
    <summary style="cursor: pointer; color: #007bff;">Show relay nodes</summary>
    <ul style="margin: 8px 0; padding-left: 20px; font-family: monospace; color: #555;">
      <li>dgayvmsxvvofpdxsas22fo7eu5tous6aavzjs6eun6jnouluwqflz7ad.onion:2525</li>
      <li>iycr4wfrdzieogdfeo7uxrj77w2vjlrhlrv3jg2ve62oe5aceqsqu7ad.onion:2525</li>
      <li>ztavxfthfr2fgovxzfg3sudl2ajtbo6db4iw5cx37nzr5jc6q7ma6ryd.onion:2525</li>
      <li>hqahdugpxz7jrmsfxqav5nfl452cvc5rsdhcpyixvcbcpfsopwnznlqd.onion:2525</li>
    </ul>
  </details>
</div>

        <div class="gateway-item">
          <span class="gateway-priority">Step 2</span>
          <div style="flex: 1;">
            <strong>Mail2News Gateway</strong>
            <div class="gateway-address" style="margin-top: 5px;">mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion</div>
            <p style="font-size: 0.85em; margin: 5px 0 0 0; color: #666;">Converts email to Usenet posts while maintaining full anonymity within the onion network.</p>
          </div>
        </div>

        <div class="gateway-item">
          <span class="gateway-priority">Step 3</span>
          <div style="flex: 1;">
            <strong>NNTP Server</strong>
            <div class="gateway-address" style="margin-top: 5px;">nntp://peannyjkqwqfynd24p6dszvtchkq7hfkwymi5by5y332wmosy5dwfaqd.onion</div>
            <p style="font-size: 0.85em; margin: 5px 0 0 0; color: #666;">Final destination for Usenet Tor hidden service.</p>
          </div>
        </div>

        <p style="margin-top: 15px; padding: 10px; background: rgba(0,123,255,0.1); border-radius: 4px; font-size: 0.9em;">
          <strong>🔒 Privacy Guarantee:</strong> Your message never leaves the Tor network until it reaches the NNTP server. All three components (Pluto2 → Mail2News → NNTP) operate as Tor hidden services, providing end-to-end anonymity with protection against traffic analysis, timing attacks, and metadata correlation.
        </p>
      </div>

      <p><strong>How to use:</strong> Complete the form below with your name, newsgroups (max 3), subject, and verify that your message and authentication details are correct. Then click "Send" to post your message via the gateway system.</p>
    </div>

    <label>Email used for PoW:</label>
    <input type="text" id="readonlyEmailSend" readonly>

    <form id="sendForm" method="POST" action="send.php">
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
      <label>From (Name): <input type="text" id="fromName" required placeholder="Your Name"></label>
      <input type="hidden" name="from" id="fromFull">
      <label>Newsgroups (max 3, comma separated):
        <input type="text" name="newsgroups" id="newsgroups" required placeholder="e.g. alt.privacy, comp.security">
      </label>
      <label>Subject: <input type="text" name="subject" id="subject" required placeholder="Message Subject"></label>
      <label>References (optional): <input type="text" name="references" id="references" placeholder="Message-ID of post you're replying to"></label>
      <label>X-Hashcash Token: <input type="text" name="xhashcash" id="hcToken" required readonly></label>
      <label>Message:</label>
      <textarea name="message" id="messageContent" rows="8" required placeholder="Your message will appear here after signing..."></textarea>
      <input type="hidden" name="x-ed25519-pub" id="x-ed25519-pub">
      <input type="hidden" name="x-ed25519-sig" id="x-ed25519-sig">
      <button type="submit" id="sendBtn">Send via m2usenet Gateway</button>
    </form>
  </div>

  <footer>
    <div>m2usenet Gateway v2.0.0 © 2025 - Privacy-focused Usenet posting tool</div>
    <div class="footer-links">
      <a href="https://yamn.virebent.art">Home</a>
      <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;%69%6E%66%6F%40%76%69%72%65%62%65%6E%74%2E%61%72%74">Contact</a>
      <a href="https://github.com/gabrix73/m2usenet-go">Code</a>
    </div>
  </footer>
</div>

<!-- SCRIPT 1: Core Functions (Theme, Notifications, POW, Signing) -->
<script>
// Notification system
function showNotification(message, type = 'info', duration = 5000) {
  const icons = {
    success: '✓',
    error: '✗',
    warning: '⚠',
    info: 'ℹ'
  };

  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.innerHTML = `
    <span class="notification-icon">${icons[type] || icons.info}</span>
    <span class="notification-message">${message}</span>
    <span class="notification-close" onclick="this.parentElement.remove()">×</span>
  `;

  document.body.appendChild(notification);

  if (duration > 0) {
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, duration);
  }
}

// State management
const appState = {
  step1Complete: false,
  step2Complete: false,
  step3Complete: false
};

function updateTabIndicators() {
  if (appState.step1Complete) {
    document.getElementById('tabBtn1').classList.add('completed');
  }
  if (appState.step2Complete) {
    document.getElementById('tabBtn2').classList.add('completed');
  }
  if (appState.step3Complete) {
    document.getElementById('tabBtn3').classList.add('completed');
  }
}

// Theme toggle functionality
document.getElementById('themeToggle').addEventListener('change', function() {
  document.body.classList.toggle('dark-theme', this.checked);
  localStorage.setItem('darkTheme', this.checked);
});

// Check for saved theme preference
document.addEventListener('DOMContentLoaded', function() {
  const darkTheme = localStorage.getItem('darkTheme') === 'true';
  document.getElementById('themeToggle').checked = darkTheme;
  document.body.classList.toggle('dark-theme', darkTheme);

  // Check if nacl is properly loaded
  if (typeof nacl === 'undefined') {
    showNotification('Cryptography library failed to load. Please refresh the page.', 'error', 0);
    return;
  }

  // Initialize nacl.util if it doesn't exist
  if (typeof nacl.util === 'undefined') {
    nacl.util = {
      decodeUTF8: function(str) {
        return new TextEncoder().encode(str);
      },
      encodeUTF8: function(arr) {
        return new TextDecoder().decode(arr);
      },
      encodeBase64: function(arr) {
        return btoa(Array.from(new Uint8Array(arr))
          .map(byte => String.fromCharCode(byte))
          .join(''));
      },
      decodeBase64: function(b64) {
        const bin = atob(b64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
          arr[i] = bin.charCodeAt(i);
        }
        return arr;
      }
    };
  }

  showNotification('m2usenet Gateway v2.0 ready', 'success', 3000);
});

function showTab(id) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

// Step 1: Generate Hashcash Token
let keyPair = null;
let workersSupported = true;

// Check if Web Workers are supported (may be blocked in Tor Browser)
try {
  if (typeof Worker === 'undefined') {
    workersSupported = false;
    console.warn('[WARN] Web Workers not supported in this browser');
  }
} catch (e) {
  workersSupported = false;
  console.warn('[WARN] Web Workers check failed:', e);
}

// SHA-1 implementation for fallback mode
function sha1(str) {
  function rotate_left(n, s) {
    return (n << s) | (n >>> (32 - s));
  }

  function cvt_hex(val) {
    let str = '';
    for (let i = 7; i >= 0; i--) {
      const v = (val >>> (i * 4)) & 0x0f;
      str += v.toString(16);
    }
    return str;
  }

  function utf8Encode(str) {
    return unescape(encodeURIComponent(str));
  }

  let blockstart;
  let i, j;
  const W = new Array(80);
  let H0 = 0x67452301;
  let H1 = 0xEFCDAB89;
  let H2 = 0x98BADCFE;
  let H3 = 0x10325476;
  let H4 = 0xC3D2E1F0;
  let A, B, C, D, E;
  let temp;

  str = utf8Encode(str);
  const str_len = str.length;

  const word_array = [];
  for (i = 0; i < str_len - 3; i += 4) {
    j = str.charCodeAt(i) << 24 | str.charCodeAt(i + 1) << 16 | str.charCodeAt(i + 2) << 8 | str.charCodeAt(i + 3);
    word_array.push(j);
  }

  switch (str_len % 4) {
    case 0:
      i = 0x080000000;
      break;
    case 1:
      i = str.charCodeAt(str_len - 1) << 24 | 0x0800000;
      break;
    case 2:
      i = str.charCodeAt(str_len - 2) << 24 | str.charCodeAt(str_len - 1) << 16 | 0x08000;
      break;
    case 3:
      i = str.charCodeAt(str_len - 3) << 24 | str.charCodeAt(str_len - 2) << 16 | str.charCodeAt(str_len - 1) << 8 | 0x80;
      break;
  }

  word_array.push(i);

  while ((word_array.length % 16) != 14) word_array.push(0);

  word_array.push(str_len >>> 29);
  word_array.push((str_len << 3) & 0x0ffffffff);

  for (blockstart = 0; blockstart < word_array.length; blockstart += 16) {
    for (i = 0; i < 16; i++) W[i] = word_array[blockstart + i];
    for (i = 16; i <= 79; i++) W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

    A = H0;
    B = H1;
    C = H2;
    D = H3;
    E = H4;

    for (i = 0; i <= 19; i++) {
      temp = (rotate_left(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }

    for (i = 20; i <= 39; i++) {
      temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }

    for (i = 40; i <= 59; i++) {
      temp = (rotate_left(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }

    for (i = 60; i <= 79; i++) {
      temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }

    H0 = (H0 + A) & 0x0ffffffff;
    H1 = (H1 + B) & 0x0ffffffff;
    H2 = (H2 + C) & 0x0ffffffff;
    H3 = (H3 + D) & 0x0ffffffff;
    H4 = (H4 + E) & 0x0ffffffff;
  }

  return cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
}

// Single-threaded mining fallback
function mineSingleThread(prefix, targetZeros, progressCallback, foundCallback) {
  console.log('[INFO] Using single-threaded mining (Web Workers not available)');
  const target = '0'.repeat(targetZeros);
  let nonce = 0;
  let checked = 0;
  const batchSize = 100; // Check 100 hashes before updating UI

  function mineNextBatch() {
    const endNonce = nonce + batchSize;

    while (nonce < endNonce) {
      const token = prefix + nonce;
      const hash = sha1(token);
      checked++;

      if (hash.startsWith(target)) {
        foundCallback(nonce, checked);
        return;
      }

      nonce++;
    }

    // Update progress
    progressCallback(checked);

    // Continue mining in next tick to avoid blocking UI
    setTimeout(mineNextBatch, 0);
  }

  mineNextBatch();
}

document.getElementById('genTokenBtn').onclick = () => {
  const email = document.getElementById('hcEmail').value.trim();
  const bits = parseInt(document.getElementById('hcBits').value);

  // Validation
  if (!email) {
    showNotification('⚠ Please enter your email address first!', 'warning');
    document.getElementById('hcEmail').classList.add('error');
    document.getElementById('hcEmail').focus();
    return;
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    showNotification('⚠ Please enter a valid email address!', 'warning');
    document.getElementById('hcEmail').classList.add('error');
    document.getElementById('hcEmail').focus();
    return;
  }

  document.getElementById('hcEmail').classList.remove('error');

  // Start generation
  showNotification(`🔨 Starting token generation (${bits} bits)... This may take a while.`, 'info');

  // Update UI to show processing
  const btn = document.getElementById('genTokenBtn');
  btn.disabled = true;
  btn.textContent = 'Mining Token...';

  const now = new Date();
  const timestamp = now.getUTCFullYear().toString().slice(2) +
                    ("0"+(now.getUTCMonth()+1)).slice(-2) +
                    ("0"+now.getUTCDate()).slice(-2) +
                    ("0"+now.getUTCHours()).slice(-2) +
                    ("0"+now.getUTCMinutes()).slice(-2) +
                    ("0"+now.getUTCSeconds()).slice(-2);
  const ext = "";
  const rand = Math.floor(Math.random()*1e6);
  const prefix = `1:${bits}:${timestamp}:${email}:${ext}:${rand}:`;
  const zeros = bits/4;

  const progBar = document.getElementById('tokenProgress');
  progBar.style.width = '0%';
  progBar.innerText = 'Mining...';

  let totalChecked = 0;
  let startTime = Date.now();

  function updateProgress(checked) {
    totalChecked += checked;
    const elapsed = (Date.now() - startTime) / 1000;
    const hashRate = Math.round(totalChecked / elapsed);
    progBar.style.width = Math.min(95, (totalChecked / 10000)) + '%';
    progBar.innerText = `${totalChecked} hashes (${hashRate}/s)`;
  }

  function onFound(nonce, totalHashes) {
    const token = prefix + nonce;

    // Update UI
    const outputField = document.getElementById('tokenOutput');
    outputField.innerText = token;
    outputField.classList.remove('empty');
    document.getElementById('hcToken').value = token;

    const fromName = document.getElementById('fromName').value || 'Anonymous';
    document.getElementById('fromFull').value = `${fromName} <${email}>`;
    document.getElementById('readonlyEmailSign').value = email;
    document.getElementById('readonlyEmailSend').value = email;

    // Restore button
    btn.disabled = false;
    btn.textContent = 'Generate Token';
    progBar.style.width = '100%';
    progBar.innerText = `Complete! (${totalHashes} hashes)`;

    // Mark step as complete
    appState.step1Complete = true;
    updateTabIndicators();

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    showNotification(`✓ Token generated in ${elapsed}s! You can now proceed to sign your message.`, 'success', 8000);

    console.log(`[INFO] Token mined: ${totalHashes} hashes in ${elapsed}s`);

    // Auto-switch to next tab after a delay
    setTimeout(() => {
      showTab('sign');
    }, 2000);
  }

  // Try Web Workers first, fallback to single-thread
  if (workersSupported) {
    console.log('[INFO] Attempting multi-threaded mining with Web Workers');

    try {
      const cores = navigator.hardwareConcurrency || 2;
      console.log(`[INFO] Using ${cores} worker threads`);

      let found = false;
      let coreChecked = Array(cores).fill(0);
      const workers = [];

      function updateCombinedProgress() {
        const sum = coreChecked.reduce((a,b)=>a+b,0);
        updateProgress(sum - totalChecked);
      }

      for (let i = 0; i < cores; i++) {
        try {
          const w = new Worker('powWorker.js');

          w.postMessage({ prefix, targetZeros: zeros, startNonce: i, step: cores });

          w.onmessage = e => {
            if (found) return;

            if (e.data.type === 'found') {
              found = true;
              workers.forEach(x => x.terminate());
              onFound(e.data.nonce, e.data.checked);
            }

            if (e.data.type === 'progress') {
              coreChecked[i] = e.data.checked;
              updateCombinedProgress();
            }
          };

          w.onerror = (err) => {
            console.error(`[ERROR] Worker ${i} error:`, err);
            if (i === 0) {
              // First worker failed, fallback to single-thread
              console.warn('[WARN] Worker failed, falling back to single-thread');
              workers.forEach(x => x.terminate());
              mineSingleThread(prefix, zeros, updateProgress, onFound);
            }
          };

          workers.push(w);
        } catch (err) {
          console.error(`[ERROR] Failed to create worker ${i}:`, err);
          if (i === 0) {
            // Fallback to single-thread
            mineSingleThread(prefix, zeros, updateProgress, onFound);
            return;
          }
        }
      }

      // Timeout safety (10 minutes for 24 bits)
      setTimeout(() => {
        if (!found) {
          console.warn('[WARN] Mining timeout, this is taking too long');
          showNotification('⚠ Mining is taking longer than expected. Consider using a lower difficulty.', 'warning', 10000);
        }
      }, 600000);

    } catch (err) {
      console.error('[ERROR] Worker mining failed:', err);
      showNotification('⚠ Multi-threaded mining failed, using fallback mode', 'warning');
      mineSingleThread(prefix, zeros, updateProgress, onFound);
    }
  } else {
    // Single-threaded fallback
    mineSingleThread(prefix, zeros, updateProgress, onFound);
  }
};

// Step 2: Generate Key Pair
document.getElementById('genKeyBtn').onclick = function() {
  try {
    // Make sure nacl is loaded
    if (typeof nacl === 'undefined' || typeof nacl.sign === 'undefined') {
      throw new Error("Cryptography library not loaded");
    }

    showNotification('🔐 Generating Ed25519 key pair...', 'info');

    keyPair = nacl.sign.keyPair();
    const pubKey = keyPair.publicKey;

    const pubB64 = typeof nacl.util.encodeBase64 === 'function'
      ? nacl.util.encodeBase64(pubKey)
      : btoa(Array.from(new Uint8Array(pubKey)).map(byte => String.fromCharCode(byte)).join(''));

    const pubOutput = document.getElementById('pubKeyOutput');
    pubOutput.innerText = pubB64;
    pubOutput.classList.remove('empty');
    document.getElementById('x-ed25519-pub').value = pubB64;

    // Enable sign button
    document.getElementById('signMsgBtn').disabled = false;

    showNotification('✓ Key pair generated successfully! Now write your message and click "Sign Message".', 'success', 6000);
  } catch (error) {
    console.error("Error generating key pair:", error);
    showNotification('✗ Error generating key pair: ' + error.message, 'error');
  }
};

// Step 2: Sign Message
document.getElementById('signMsgBtn').onclick = function() {
  try {
    if (!keyPair) {
      showNotification('⚠ Please generate a key pair first!', 'warning');
      return;
    }

    const msg = document.getElementById('messageToSign').value.trim();
    if (!msg) {
      showNotification('⚠ Please write a message to sign!', 'warning');
      document.getElementById('messageToSign').classList.add('error');
      document.getElementById('messageToSign').focus();
      return;
    }

    if (msg.length < 10) {
      showNotification('⚠ Message is too short. Please write at least 10 characters.', 'warning');
      return;
    }

    document.getElementById('messageToSign').classList.remove('error');

    showNotification('✍ Signing message...', 'info');

    const msgBytes = typeof nacl.util.decodeUTF8 === 'function'
      ? nacl.util.decodeUTF8(msg)
      : new TextEncoder().encode(msg);

    const sig = nacl.sign.detached(msgBytes, keyPair.secretKey);

    const sigB64 = typeof nacl.util.encodeBase64 === 'function'
      ? nacl.util.encodeBase64(sig)
      : btoa(Array.from(new Uint8Array(sig)).map(byte => String.fromCharCode(byte)).join(''));

    const sigOutput = document.getElementById('signatureOutput');
    sigOutput.innerText = sigB64;
    sigOutput.classList.remove('empty');
    document.getElementById('x-ed25519-sig').value = sigB64;

    // EXACTLY like v1.0: message + "\n\n--- Digital Signature ---\n" + signature
    // Public key goes ONLY in X-Ed25519-Pub header, NOT in message body
    document.getElementById('messageContent').value = msg + "\n\n--- Digital Signature ---\n" + sigB64;

    console.log('[DEBUG] Message signed like v1.0, total length:', (msg + "\n\n--- Digital Signature ---\n" + sigB64).length);

    // Mark step as complete
    appState.step2Complete = true;
    updateTabIndicators();

    showNotification('✓ Message signed successfully! You can now send your message to Usenet.', 'success', 8000);

    // Auto-switch to send tab
    setTimeout(() => {
      showTab('send');
    }, 2000);
  } catch (error) {
    console.error("Error signing message:", error);
    showNotification('✗ Error signing message: ' + error.message, 'error');
  }
};

// Step 3: Send Form
document.getElementById('sendForm').addEventListener('submit', function(e) {
  // Form validation
  const requiredFields = [
    {id: 'fromName', name: 'Name'},
    {id: 'newsgroups', name: 'Newsgroups'},
    {id: 'subject', name: 'Subject'},
    {id: 'hcToken', name: 'Hashcash Token'},
    {id: 'messageContent', name: 'Message'},
    {id: 'x-ed25519-pub', name: 'Public Key'},
    {id: 'x-ed25519-sig', name: 'Signature'}
  ];

  const missing = [];
  requiredFields.forEach(field => {
    const el = document.getElementById(field.id);
    if (!el.value.trim()) {
      missing.push(field.name);
      el.classList.add('error');
    } else {
      el.classList.remove('error');
    }
  });

  if (missing.length > 0) {
    e.preventDefault();
    showNotification(`⚠ Missing required fields: ${missing.join(', ')}. Please complete all previous steps.`, 'warning', 8000);
    return false;
  }

  // Debug: log message length
  const messageLen = document.getElementById('messageContent').value.length;
  console.log('[DEBUG] Final message length being sent:', messageLen);
  console.log('[DEBUG] Message does NOT include signature in body - signature is in headers only');

  if (messageLen < 10) {
    e.preventDefault();
    showNotification('⚠ Message is too short (minimum 10 characters)', 'warning');
    return false;
  }

  // Validate newsgroups
  const newsgroups = document.getElementById('newsgroups').value.split(',').map(g => g.trim()).filter(g => g);
  if (newsgroups.length === 0) {
    e.preventDefault();
    showNotification('⚠ Please enter at least one newsgroup!', 'warning');
    return false;
  }

  if (newsgroups.length > 3) {
    e.preventDefault();
    showNotification('⚠ Maximum 3 newsgroups allowed!', 'warning');
    return false;
  }

  // Confirm submission
  const confirmMsg = `Are you ready to send your message to Usenet?\n\nNewsgroups: ${newsgroups.join(', ')}\nSubject: ${document.getElementById('subject').value}\nMessage length: ${messageLen} chars\n\nThis action cannot be undone.`;

  if (!confirm(confirmMsg)) {
    e.preventDefault();
    return false;
  }

  // Log for debugging
  console.log('[DEBUG] Submitting message:');
  console.log('[DEBUG] From:', document.getElementById('fromFull').value);
  console.log('[DEBUG] Newsgroups:', document.getElementById('newsgroups').value);
  console.log('[DEBUG] Subject:', document.getElementById('subject').value);
  console.log('[DEBUG] Message length:', messageLen);
  console.log('[DEBUG] Hashcash:', document.getElementById('hcToken').value.substring(0, 50) + '...');
  console.log('[DEBUG] Ed25519-Pub:', document.getElementById('x-ed25519-pub').value.substring(0, 30) + '...');
  console.log('[DEBUG] Ed25519-Sig:', document.getElementById('x-ed25519-sig').value.substring(0, 30) + '...');

  // Show sending notification
  showNotification('📤 Sending your message via m2usenet gateway...', 'info', 0);
  document.getElementById('sendBtn').disabled = true;
  document.getElementById('sendBtn').textContent = 'Sending...';

  return true;
});

// Handle form field updates for "from" field
document.getElementById('fromName').addEventListener('input', function() {
  const email = document.getElementById('hcEmail').value;
  if (email) {
    document.getElementById('fromFull').value = `${this.value} <${email}>`;
  }
});
</script>

<!-- SCRIPT 2: Newsreader Integration (Autofill from URL parameters) -->
<script>
(function() {
    const u = new URLSearchParams(window.location.search);
    const a = u.get('action');
    if (!a) return;

    function fill(id, v, readonly = false) {
        const f = document.getElementById(id);
        if (f && v) {
            f.value = decodeURIComponent(v);
            if (readonly) {
                f.readOnly = true;
                f.style.background = '#e8e8e8';
                f.style.border = '2px solid #999';
                f.style.cursor = 'not-allowed';
            }
        }
    }

    // NEW POST: campo newsgroups immutabile
    if (a === 'new') {
        const ng = u.get('newsgroups');
        if (ng) {
            fill('newsgroups', ng, true); // READONLY - non può essere modificato
            if (typeof showNotification === 'function') {
                showNotification('📝 NEW POST: Posting to ' + decodeURIComponent(ng), 'success');
            }
        }
        setTimeout(() => showTab('pow'), 500);
    }

    // REPLY TO POST: 4 campi immutabili (references, newsgroups, subject) + body editabile con quote
    if (a === 'reply') {
        const ng = u.get('newsgroups');
        const subj = u.get('subject');
        const refs = u.get('references');
        const qbody = u.get('quoted-body');

        // Riempi i campi IMMUTABILI (readonly)
        if (ng) fill('newsgroups', ng, true);      // READONLY
        if (subj) fill('subject', subj, true);     // READONLY (con Re: prefix)
        if (refs) fill('references', refs, true);  // READONLY

        // Riempi il body con quote Usenet (EDITABILE)
        if (qbody) {
            const origFrom = u.get('original-from');
            const origDate = u.get('original-date');

            // Formato quote tipico Usenet
            let quotedText = '';
            if (origFrom && origDate) {
                quotedText = 'On ' + decodeURIComponent(origDate) + ', ' + decodeURIComponent(origFrom) + ' wrote:\n\n';
            }

            // Aggiungi '> ' davanti ad ogni linea del messaggio originale
            const bodyLines = decodeURIComponent(qbody).split('\n');
            for (let i = 0; i < bodyLines.length; i++) {
                quotedText += '> ' + bodyLines[i] + '\n';
            }

            quotedText += '\n\n'; // Spazio per la risposta

            // Riempi il campo messageToSign (questo è EDITABILE)
            const msgField = document.getElementById('messageToSign');
            if (msgField) {
                msgField.value = quotedText;
            }
        }

        if (typeof showNotification === 'function') {
            showNotification('💬 REPLY: References and metadata are locked', 'info');
        }

        setTimeout(() => showTab('pow'), 500);
    }
})();
</script>

</body>
</html>

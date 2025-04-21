<?php
// /var/www/m2usenet/index.php
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mail2Usenet Gateway</title>
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
      font-family: sans-serif; 
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
      display: block; 
      width: 100%; 
      padding: 12px; 
      border: none; 
      background: var(--tab-bg); 
      color: var(--text);
      cursor: pointer; 
      border-radius: 4px;
      font-weight: bold;
      transition: background 0.2s, transform 0.1s;
    }
    
    .tabs button:hover {
      background: var(--primary);
      color: white;
    }
    
    .tabs button:active {
      transform: scale(0.98);
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
    }
    
    input[readonly] { 
      background: var(--input-readonly); 
      cursor: not-allowed;
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
      transition: background 0.2s;
    }
    
    button:hover {
      background: var(--primary-hover);
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
    }
    
    .output-field {
      margin-top: 15px;
      padding: 10px;
      background: var(--input-readonly);
      border: 1px solid var(--border);
      border-radius: 4px;
      word-break: break-all;
      min-height: 20px;
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
    }
  </style>
  <!-- Include both TweetNaCl libraries -->
<script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/tweetnacl-util@0.15.1/nacl-util.min.js"></script>
</head>
<body>
<div class="container">
  <header>
    <h1>Mail2Usenet Gateway</h1>
    <div class="theme-toggle">
      <span>🌞</span>
      <input type="checkbox" id="themeToggle">
      <label for="themeToggle" class="toggle"></label>
      <span>🌙</span>
    </div>
  </header>

  <div class="tabs">
    <button onclick="showTab('pow')">1. Generate Hashcash Token</button>
    <button onclick="showTab('sign')">2. Sign Message</button>
    <button onclick="showTab('send')">3. Send Message</button>
  </div>

  <div id="pow" class="tab-content active">
    <h2>Proof-of-Work Token</h2>
    
    <div class="section-info">
      <p><strong>What is this?</strong> This step generates a "proof-of-work" token (hashcash) that prevents spam by requiring your computer to perform some calculations. This is similar to how cryptocurrencies work - you need to "mine" a valid token before sending a message.</p>
      <p><strong>How to use:</strong> Enter your email address, select the difficulty level (higher bits = longer processing time), and click "Generate Token". Your browser will mine a valid token that will be required in the next steps.</p>
    </div>
    
    <label>Email (resource): <input type="email" id="hcEmail" placeholder="your@email.com"></label>
    <label>Difficulty (bits):
      <select id="hcBits">
        <option value="24">24 bits (faster, suitable for most devices)</option>
        <option value="28">28 bits (medium difficulty)</option>
        <option value="32">32 bits (slower, more secure)</option>
      </select>
    </label>
    <button id="genTokenBtn">Generate Token</button>
    <div class="progress-bar"><div id="tokenProgress" class="progress-bar-inner">0</div></div>
    <label>Generated Token:</label>
    <div id="tokenOutput" class="output-field"></div>
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
    <textarea id="messageToSign" rows="6" placeholder="Write your message here..."></textarea>
    <button id="genKeyBtn">Generate Key Pair</button>
    <button id="signMsgBtn">Sign Message</button>
    
    <label>Generated Public Key:</label>
    <div id="pubKeyOutput" class="output-field"></div>
    <label>Generated Signature:</label>
    <div id="signatureOutput" class="output-field"></div>
  </div>

  <div id="send" class="tab-content">
    <h2>Send Message</h2>
    
    <div class="section-info">
      <p><strong>What is this?</strong> This final step sends your signed message to the Usenet network through our NNTP server running on the Tor network at <code>peannyjkqwqfynd24p6dszvtchkq7hfkwymi5by5y332wmosy5dwfaqd.onion</code>.</p>
      <p><strong>How to use:</strong> Complete the form below with your name, the newsgroups you want to post to (max 3), subject, and verify that your message and authentication details are correct. Then click "Send" to post your message.</p>
    </div>
    
    <label>Email used for PoW:</label>
    <input type="text" id="readonlyEmailSend" readonly>
    <form id="sendForm" method="POST" action="send.php">
      <label>From (Name): <input type="text" id="fromName" required placeholder="Your Name"></label>
      <input type="hidden" name="from" id="fromFull">
      <label>Newsgroups (max 3, comma separated): <input type="text" name="newsgroups" required placeholder="e.g. alt.privacy, comp.security"></label>
      <label>Subject: <input type="text" name="subject" required placeholder="Message Subject"></label>
      <label>References (optional): <input type="text" name="references" placeholder="Message-ID of post you're replying to"></label>
      <label>X-Hashcash Token: <input type="text" name="xhashcash" id="hcToken" required readonly></label>
      <label>Message:</label>
      <textarea name="message" id="messageContent" rows="8" required placeholder="Your message content will appear here after signing..."></textarea>
      <input type="hidden" name="x-ed25519-pub" id="x-ed25519-pub">
      <input type="hidden" name="x-ed25519-sig" id="x-ed25519-sig">
      <button type="submit">Send Message</button>
    </form>
  </div>
  
  <footer>
    <div>Mail2Usenet Gateway © 2025 - Privacy-focused communication tool</div>
    <div class="footer-links">
      <a href="https://yamn.virebent.art">Home</a>
      <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;%69%6E%66%6F%40%76%69%72%65%62%65%6E%74%2E%61%72%74">Contact</a>
      <a href="https://github.com/gabrix73/m2usenet-go">Code</a>
    </div>
  </footer>
</div>

<script>
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
    console.error("TweetNaCl library not loaded properly!");
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
});

function showTab(id) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

let keyPair = null;
document.getElementById('genKeyBtn').onclick = function() {
  try {
    // Make sure nacl is loaded and the sign function exists
    if (typeof nacl === 'undefined') {
      throw new Error("TweetNaCl library is not loaded");
    }
    
    if (typeof nacl.sign === 'undefined' || typeof nacl.sign.keyPair !== 'function') {
      throw new Error("TweetNaCl's sign functionality is not available");
    }
    
    keyPair = nacl.sign.keyPair();
    const pubKey = keyPair.publicKey;
    
    // Use our nacl.util implementation to encode the public key
    const pubB64 = typeof nacl.util.encodeBase64 === 'function' 
      ? nacl.util.encodeBase64(pubKey)
      : btoa(Array.from(new Uint8Array(pubKey)).map(byte => String.fromCharCode(byte)).join(''));
    
    document.getElementById('pubKeyOutput').innerText = pubB64;
    document.getElementById('x-ed25519-pub').value = pubB64;
    alert("Key pair generated successfully! You can now sign your message.");
  } catch (error) {
    console.error("Error generating key pair:", error);
    alert("Error generating key pair: " + error.message);
  }
};

document.getElementById('signMsgBtn').onclick = function() {
  try {
    if (!keyPair) {
      return alert("Please generate a key pair first.");
    }
    
    const msg = document.getElementById('messageToSign').value;
    if (!msg) {
      return alert("Please enter a message to sign.");
    }
    
    const msgBytes = typeof nacl.util.decodeUTF8 === 'function'
      ? nacl.util.decodeUTF8(msg)
      : new TextEncoder().encode(msg);
    
    const sig = nacl.sign.detached(msgBytes, keyPair.secretKey);
    
    const sigB64 = typeof nacl.util.encodeBase64 === 'function'
      ? nacl.util.encodeBase64(sig)
      : btoa(Array.from(new Uint8Array(sig)).map(byte => String.fromCharCode(byte)).join(''));
    
    document.getElementById('signatureOutput').innerText = sigB64;
    document.getElementById('x-ed25519-sig').value = sigB64;
    document.getElementById('messageContent').value = msg + "\n\n--- Digital Signature ---\n" + sigB64;
    alert("Message signed successfully! You can now proceed to the Send Message tab.");
  } catch (error) {
    console.error("Error signing message:", error);
    alert("Error signing message: " + error.message);
  }
};

document.getElementById('genTokenBtn').onclick = () => {
  const email = document.getElementById('hcEmail').value;
  const bits = parseInt(document.getElementById('hcBits').value);
  if (!email) return alert("Please enter an email address.");
  
  // Update UI to show processing
  document.getElementById('genTokenBtn').disabled = true;
  document.getElementById('genTokenBtn').textContent = 'Processing...';
  
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
  const cores = navigator.hardwareConcurrency || 2;
  let found = false;
  let totalChecked = Array(cores).fill(0);
  const progBar = document.getElementById('tokenProgress');
  progBar.style.width = '0%'; progBar.innerText = '0';
  const workers = [];

  function updateProgress() {
    const sum = totalChecked.reduce((a,b)=>a+b,0);
    const pct = Math.min(100,(sum%(cores*1000))/(cores*10));
    progBar.style.width = pct + '%';
    progBar.innerText = sum;
  }

  for (let i = 0; i < cores; i++) {
    const w = new Worker('powWorker.js');
    w.postMessage({ prefix, targetZeros: zeros, startNonce: i, step: cores });
    w.onmessage = e => {
      if (found) return;
      if (e.data.type === 'found') {
        found = true;
        const token = prefix + e.data.nonce;
        document.getElementById('tokenOutput').innerText = token;
        document.getElementById('hcToken').value = token;
        const fromName = document.getElementById('fromName').value;
        document.getElementById('fromFull').value = `${fromName} <${email}>`;
        document.getElementById('readonlyEmailSign').value = email;
        document.getElementById('readonlyEmailSend').value = email;
        workers.forEach(x => x.terminate());
        
        // Restore button
        document.getElementById('genTokenBtn').disabled = false;
        document.getElementById('genTokenBtn').textContent = 'Generate Token';
        
        // Show completion message
        alert("Token generation complete! You can now proceed to the Sign Message tab.");
      }
      if (e.data.type === 'progress') {
        totalChecked[i] = e.data.checked;
        updateProgress();
      }
    };
    workers.push(w);
  }
};

document.getElementById('sendForm').addEventListener('submit', function(e) {
  // Form validation
  const requiredFields = ['fromName', 'hcToken', 'messageContent', 'x-ed25519-pub', 'x-ed25519-sig'];
  const missing = requiredFields.filter(id => !document.getElementById(id).value.trim());
  
  if (missing.length > 0) {
    e.preventDefault();
    alert("Please complete all previous steps before sending your message.");
    return false;
  }
  
  // Log for debugging
  console.log('[DEBUG] x-ed25519-pub:', document.getElementById('x-ed25519-pub').value);
  console.log('[DEBUG] x-ed25519-sig:', document.getElementById('x-ed25519-sig').value);
  console.log('[DEBUG] From (full):', document.getElementById('fromFull').value);
  console.log('[DEBUG] Token:', document.getElementById('hcToken').value);
  console.log('[DEBUG] Message:', document.getElementById('messageContent').value);
  
  if (confirm("Are you sure you want to send this message to the Usenet network?")) {
    return true;
  } else {
    e.preventDefault();
    return false;
  }
});

// Handle form field updates for "from" field
document.getElementById('fromName').addEventListener('input', function() {
  const email = document.getElementById('hcEmail').value;
  if (email) {
    document.getElementById('fromFull').value = `${this.value} <${email}>`;
  }
});
</script>
</body>
</html> 

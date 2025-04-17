<?php
// /var/www/mail2usenet/index.php
// Production‑ready Mail2Usenet Gateway frontend in English,
// with UTC Hashcash, parallel PoW via Web Workers,
// Ed25519 signature (mandatory), and form reset on return.
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Mail2Usenet Gateway – Production</title>
  <style>
    body.day { background: #f9f9f9; color: #333; }
    body.night { background: #333;   color: #ddd; }
    .container { max-width:960px; margin:auto; padding:20px; box-shadow:0 0 10px rgba(0,0,0,0.1); }
    h1,h2 { text-align:center; }
    .tabs { text-align:center; margin:20px 0; }
    .tabs button { padding:10px 20px; margin:0 5px; cursor:pointer; background:#eee; border:none; }
    .tabs button.active { background:#ccc; }
    .tab-content { display:none; padding:20px; }
    .tab-content.active { display:block; }
    label { display:block; margin-top:10px; font-weight:bold; }
    input, select, textarea, button { width:100%; padding:8px; margin-top:5px; box-sizing:border-box; }
    .progress-bar { width:100%; background:#ddd; border-radius:5px; overflow:hidden; height:20px; margin-top:10px; }
    .progress-bar-inner { height:100%; width:0; background:#4caf50; text-align:center; color:#fff; line-height:20px; }
    #themeToggle { position:fixed; top:20px; right:20px; padding:8px 12px; background:#888; color:#fff; border:none; border-radius:5px; cursor:pointer; }
    .info { font-style:italic; margin-bottom:15px; }
  </style>
  <!-- Crypto & Web Worker support -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/tweetnacl/1.0.3/nacl.min.js"></script>
  <script src="https://unpkg.com/tweetnacl-util@1.0.2/nacl-util.min.js"></script>
  <script>
    // Fallback if nacl.util is missing
    if (typeof nacl.util === 'undefined') {
      nacl.util = {
        decodeUTF8: str => new TextEncoder().encode(str),
        encodeUTF8: arr => new TextDecoder().decode(arr),
        encodeBase64: arr => { let s=''; arr.forEach(b=>s+=String.fromCharCode(b)); return btoa(s); },
        decodeBase64: b64 => { const bin=atob(b64), a=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) a[i]=bin.charCodeAt(i); return a; }
      };
    }
  </script>
</head>
<body class="day">
  <button id="themeToggle">Night</button>
  <div class="container">
    <h1>Mail2Usenet Gateway – Production</h1>
    <div class="tabs">
      <button class="tab-button active" data-tab="token">Generate Hashcash Token</button>
      <button class="tab-button" data-tab="signature">Digital Signature</button>
      <button class="tab-button" data-tab="send">Send Message</button>
    </div>

    <!-- 1) Generate Hashcash Token -->
    <div id="token" class="tab-content active">
      <h2>Generate Hashcash Token</h2>
      <p class="info">Client‑side PoW: SHA‑1 with leading hex zeros (6/7/8) to mitigate spam.</p>
      <label>Email (resource):
        <input type="email" id="hcEmail" placeholder="user@example.com" required>
      </label>
      <label>Difficulty:
        <select id="hcBits">
          <option value="24">Fast (24 bits)</option>
          <option value="28">Medium (28 bits)</option>
          <option value="32">Slow (32 bits)</option>
        </select>
      </label>
      <button id="genTokenBtn">Generate Token</button>
      <p>Generated Token: <span id="tokenOutput"></span></p>
      <div class="progress-bar"><div id="tokenProgress" class="progress-bar-inner">0</div></div>
      <p class="info">Using UTC timestamp (YYMMDDhhmmss) from <code>toISOString()</code>.</p>
    </div>

    <!-- 2) Digital Signature (Ed25519) -->
    <div id="signature" class="tab-content">
      <h2>Digital Signature (Ed25519)</h2>
      <p class="info">Ephemeral key pair; signature is mandatory and discarded on send.</p>
      <label>Message to Sign:
        <textarea id="messageToSign" rows="6" placeholder="Enter message"></textarea>
      </label>
      <button id="genKeyBtn">Generate Key Pair</button>
      <button id="signMsgBtn">Sign Message</button>
      <p>Public Key: <span id="pubKeyOutput"></span></p>
      <p>Signature: <span id="signatureOutput"></span></p>
    </div>

    <!-- 3) Send Message -->
    <div id="send" class="tab-content">
      <h2>Send Message to Usenet</h2>
      <p class="info">Includes X-Hashcash and X-Ed25519-Sig headers; max 3 newsgroups.</p>
      <form id="sendForm" action="send.php" method="POST">
        <label>User Name:
          <input type="text" id="fromName" placeholder="Your Name" required>
        </label>
        <label>Email:
          <input type="email" id="fromEmail" placeholder="user@example.com" required>
        </label>
        <input type="hidden" id="fromCombined" name="from">
        <label>Newsgroups (max 3):
          <input type="text" id="newsgroups" name="newsgroups" placeholder="comp.lang.go, ..." required>
        </label>
        <label>Subject:
          <input type="text" id="subject" name="subject" required>
        </label>
        <label>References (optional):
          <input type="text" id="references" name="references" placeholder="<msgid@domain>">
        </label>
        <label>Token X-Hashcash:
          <input type="text" id="hcToken" name="xhashcash" required>
        </label>
        <label>Message:
          <textarea id="messageContent" name="message" rows="8" required></textarea>
        </label>
        <input type="hidden" name="x-ed25519-pub" id="x-ed25519-pub">
        <input type="hidden" name="x-ed25519-sig" id="x-ed25519-sig">
        <button type="submit">Send</button>
      </form>
    </div>
  </div>

  <script>
    // Theme toggle
    document.getElementById('themeToggle').onclick = () => {
      const b = document.body, btn = document.getElementById('themeToggle');
      b.classList.toggle('night'); b.classList.toggle('day');
      btn.innerText = b.classList.contains('night') ? 'Day' : 'Night';
    };

    // Tab navigation
    document.querySelectorAll('.tab-button').forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll('.tab-button').forEach(b=>b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
      };
    });

    // Clear form on back-button
    window.addEventListener('pageshow', () => document.getElementById('sendForm').reset());

    // Parallel PoW via Web Workers, UTC timestamp
    document.getElementById('genTokenBtn').onclick = () => {
      const email = document.getElementById('hcEmail').value.trim();
      const bits  = +document.getElementById('hcBits').value;
      if (!email) return alert('Enter a valid email.');
      const now = new Date(), iso = now.toISOString();
      const dateStr =
        iso.substr(2,2)+iso.substr(5,2)+iso.substr(8,2)+
        iso.substr(11,2)+iso.substr(14,2)+iso.substr(17,2);
      const ext='', rand=Math.floor(Math.random()*1e6).toString();
      const prefix = `1:${bits}:${dateStr}:${email}:${ext}:${rand}:`;
      const zeros = bits/4, cores = navigator.hardwareConcurrency||2;
      let found=false, totalChecked=Array(cores).fill(0);
      const prog = document.getElementById('tokenProgress');
      prog.style.width='0%'; prog.innerText='0';
      const workers=[];
      function upd() {
        const sum = totalChecked.reduce((a,b)=>a+b,0),
              pct = Math.min(100,(sum%(cores*1000))/(cores*10));
        prog.style.width=pct+'%'; prog.innerText=sum;
      }
      for(let i=0;i<cores;i++){
        const w=new Worker('powWorker.js');
        w.postMessage({ prefix, targetZeros:zeros, startNonce:i, step:cores });
        w.onmessage=e=>{
          if(found) return;
          if(e.data.type==='found'){
            found=true;
            const token=prefix+e.data.nonce;
            document.getElementById('tokenOutput').innerText=token;
            document.getElementById('hcToken').value=token;
            document.getElementById('fromEmail').value=email;
            workers.forEach(x=>x.terminate());
          }
          if(e.data.type==='progress'){
            totalChecked[i]=e.data.checked; upd();
          }
        };
        workers.push(w);
      }
    };

    // Ed25519 signature
    let keyPair=null;
    document.getElementById('genKeyBtn').onclick = () => {
      try {
        keyPair = nacl.sign.keyPair();
        document.getElementById('pubKeyOutput').innerText = nacl.util.encodeBase64(keyPair.publicKey);
        alert('Key pair generated. Secret key will be discarded.');
      } catch(e){ alert('Key generation error: '+e); }
    };
    document.getElementById('signMsgBtn').onclick = () => {
      if(!keyPair) return alert('Generate key pair first.');
      const msg=document.getElementById('messageToSign').value;
      if(!msg) return alert('Enter a message.');
      try {
        const sig=nacl.sign.detached(nacl.util.decodeUTF8(msg),keyPair.secretKey),
              sigB64=nacl.util.encodeBase64(sig),
              pubB64=nacl.util.encodeBase64(keyPair.publicKey);
        document.getElementById('signatureOutput').innerText=sigB64;
        document.getElementById('x-ed25519-sig').value=sigB64;
        document.getElementById('x-ed25519-pub').value=pubB64;
        document.getElementById('messageContent').value=msg+"\n\n--- Digital Signature ---\n"+sigB64;
      } catch(e){ alert('Signing error: '+e); }
    };

    // Combine From
    function updateFrom(){
      const n=document.getElementById('fromName').value.trim(),
            e=document.getElementById('fromEmail').value.trim();
      if(n&&e) document.getElementById('fromCombined').value=`${n} <${e}>`;
    }
    document.getElementById('fromName').oninput=updateFrom;
    document.getElementById('fromEmail').oninput=updateFrom;
    updateFrom();
  </script>
</body>
</html>

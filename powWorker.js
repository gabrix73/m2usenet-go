// /var/www/mail2usenet/powWorker.js
self.onmessage = async ({ data }) => {
  const { prefix, targetZeros, startNonce, step } = data;
  let nonce = startNonce, checked = 0, zeroStr = '0'.repeat(targetZeros);
  while (true) {
    const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(prefix + nonce));
    const hex = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
    if (hex.startsWith(zeroStr)) {
      return self.postMessage({ type:'found', nonce });
    }
    nonce += step;
    if (++checked % 1000 === 0) {
      self.postMessage({ type:'progress', checked });
    }
  }
};

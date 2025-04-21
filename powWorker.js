self.onmessage = async ({ data }) => {
  const { prefix, targetZeros, startNonce, step } = data;
  const zeroStr = '0'.repeat(targetZeros);
  let nonce = startNonce;
  let checked = 0;
  
  // Batch size: controllare più nonce per ogni aggiornamento di progresso
  const BATCH_SIZE = 500;
  
  // Parallelizzazione del lavoro utilizzando più promise contemporaneamente
  const CONCURRENT_PROMISES = 12;
  
  // Funzione per verificare un singolo nonce
  const checkNonce = async (nonceToCheck) => {
    const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(prefix + nonceToCheck));
    const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    return { nonce: nonceToCheck, hex };
  };
  
  // Funzione per verificare un batch di nonce in parallelo
  const processBatch = async () => {
    const promises = [];
    for (let i = 0; i < CONCURRENT_PROMISES; i++) {
      let batchPromises = [];
      for (let j = 0; j < BATCH_SIZE; j++) {
        const currentNonce = nonce;
        batchPromises.push(checkNonce(currentNonce));
        nonce += step;
      }
      promises.push(Promise.all(batchPromises));
    }
    
    // Attende il completamento di tutti i batch
    const results = await Promise.all(promises);
    
    // Appiattisce i risultati e controlla se c'è una corrispondenza
    const allResults = results.flat();
    for (const result of allResults) {
      if (result.hex.startsWith(zeroStr)) {
        return { found: true, nonce: result.nonce };
      }
    }
    
    checked += CONCURRENT_PROMISES * BATCH_SIZE;
    self.postMessage({ type: 'progress', checked });
    return { found: false };
  };
  
  // Loop principale
  while (true) {
    const { found, nonce: foundNonce } = await processBatch();
    if (found) {
      self.postMessage({ type: 'found', nonce: foundNonce });
      break;
    }
  }
};

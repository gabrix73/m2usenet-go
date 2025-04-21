// /home/m2usenet/m2usenet.go
// Versione production-ready di Mail2Usenet in Go.
// Legge un'email da STDIN, verifica il token hashcash (inclusi controlli di formattazione, data, resource e hash),
// registra il token usato in un database JSON e invia il messaggio a un server NNTP tramite Tor (utilizzando un dialer SOCKS5).

package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"math/rand"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// Configurazioni prelevate dalle variabili di ambiente (con valori di default per produzione)
	NNTPServer          = getEnv("NNTP_SERVER", "peannyjkqwqfynd24p6dszvtchkq7hfkwymi5by5y332wmosy5dwfaqd.onion")
	nntpPort, _         = strconv.Atoi(getEnv("NNTP_PORT", "119"))
	torProxyHost        = getEnv("TOR_PROXY_HOST", "127.0.0.1")
	torProxyPort, _     = strconv.Atoi(getEnv("TOR_PROXY_PORT", "9050"))
	maxPostSize, _      = strconv.Atoi(getEnv("MAX_POST_SIZE", "10240"))
	delayCrossPost, _   = strconv.Atoi(getEnv("DELAY_CROSSPOST", "2"))
	timeWindowSec, _    = strconv.Atoi(getEnv("TIME_WINDOW_SEC", "1800")) // 30 minuti
	hashcashMinBits, _  = strconv.Atoi(getEnv("HASHCASH_MIN_BITS", "24"))
	dbPath              = getEnv("DB_PATH", "/home/m2usenet/hashcash.json")

	tokenMutex sync.Mutex
)

// getEnv restituisce il valore della variabile d'ambiente o il default se non impostata.
func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// TokenDB rappresenta la struttura JSON per la memorizzazione dei token usati.
type TokenDB map[string]string

// tokenAlreadySpent verifica se il token è già stato registrato.
func tokenAlreadySpent(token string) bool {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	db, err := loadTokenDB()
	if err != nil {
		return false
	}
	_, exists := db[token]
	return exists
}

// markTokenSpent registra il token nel file JSON, salvando anche il timestamp.
func markTokenSpent(token string) error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	db, err := loadTokenDB()
	if err != nil {
		db = make(TokenDB)
	}
	db[token] = time.Now().UTC().Format(time.RFC3339)
	return saveTokenDB(db)
}

// loadTokenDB carica il database dei token, se esistente.
func loadTokenDB() (TokenDB, error) {
	db := make(TokenDB)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return db, nil
	}
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return db, nil
	}
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}
	return db, nil
}

// saveTokenDB salva il database dei token sul file system.
func saveTokenDB(db TokenDB) error {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dbPath, data, 0644)
}

// parseHashcashDate interpreta la data dal token, accettando formati a 10 o 12 cifre.
func parseHashcashDate(dateStr string) (time.Time, error) {
	layouts := []string{"0601021504", "060102150405"}
	var t time.Time
	var err error
	for _, layout := range layouts {
		t, err = time.Parse(layout, dateStr)
		if err == nil {
			return t, nil
		}
	}
	return t, errors.New("formato data non valido")
}

// verifyHashcashToken effettua i controlli sul token:
// - Formato (7 campi)
// - Versione "1"
// - Numero di bit almeno hashcashMinBits e multiplo di 4
// - La resource deve corrispondere all'indirizzo del mittente (case-insensitive)
// - La data deve essere entro la finestra temporale ±timeWindowSec
// - Il digest SHA-1 deve avere i necessari zero iniziali
func verifyHashcashToken(token, fromAddr string) bool {
	parts := strings.Split(token, ":")
	if len(parts) != 7 {
		log.Printf("Formato token non valido: %s", token)
		return false
	}
	version, bitsStr, dateStr, resource, ext, randPart, counter := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
	if version != "1" {
		log.Printf("Versione token non valida: %s", version)
		return false
	}
	bits, err := strconv.Atoi(bitsStr)
	if err != nil || bits < hashcashMinBits || bits%4 != 0 {
		log.Printf("Bits non validi: %s", bitsStr)
		return false
	}
	if strings.TrimSpace(strings.ToLower(resource)) != strings.TrimSpace(strings.ToLower(fromAddr)) {
		log.Printf("Resource mismacth: %s vs %s", resource, fromAddr)
		return false
	}
	tokenTime, err := parseHashcashDate(dateStr)
	if err != nil {
		log.Printf("Errore nella data del token: %v", err)
		return false
	}
	now := time.Now().UTC()
	if now.Sub(tokenTime) > time.Duration(timeWindowSec)*time.Second ||
		tokenTime.Sub(now) > time.Duration(timeWindowSec)*time.Second {
		log.Printf("Token fuori finestra temporale: %v", now.Sub(tokenTime))
		return false
	}
	assembled := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s", version, bitsStr, dateStr, resource, ext, randPart, counter)
	hash := sha1.Sum([]byte(assembled))
	shaHex := fmt.Sprintf("%x", hash)
	target := strings.Repeat("0", bits/4)
	if !strings.HasPrefix(shaHex, target) {
		log.Printf("Verifica hash fallita: %s non inizia con %s", shaHex, target)
		return false
	}
	return true
}

// sendViaTor stabilisce una connessione al server NNTP tramite Tor usando un dialer SOCKS5, invia il comando IHAVE e il messaggio.
func sendViaTor(server string, port int, message, messageID string) (bool, error) {
	torAddr := fmt.Sprintf("%s:%d", torProxyHost, torProxyPort)
	dialer, err := proxy.SOCKS5("tcp", torAddr, nil, proxy.Direct)
	if err != nil {
		return false, fmt.Errorf("Errore nel dialer SOCKS5: %v", err)
	}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		return false, fmt.Errorf("Connessione NNTP fallita: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	welcome, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	log.Printf("Connesso a NNTP: %s", strings.TrimSpace(welcome))

	ihaveCmd := fmt.Sprintf("IHAVE %s\r\n", messageID)
	if _, err := conn.Write([]byte(ihaveCmd)); err != nil {
		return false, err
	}
	ihaveResp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	log.Printf("Risposta IHAVE: %s", strings.TrimSpace(ihaveResp))
	if !strings.HasPrefix(ihaveResp, "335") {
		return false, errors.New("IHAVE non accettato")
	}
	fullMessage := message + "\r\n.\r\n"
	if _, err := conn.Write([]byte(fullMessage)); err != nil {
		return false, err
	}
	postResp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	log.Printf("Risposta posting: %s", strings.TrimSpace(postResp))
	conn.Write([]byte("QUIT\r\n"))
	return strings.HasPrefix(postResp, "235"), nil
}

func main() {
	// Lettura dell'intera email da STDIN
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Errore lettura STDIN: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(input))
	if err != nil {
		log.Fatalf("Errore nel parsing dell'email: %v", err)
	}
	header := msg.Header

	fromHeader := header.Get("From")
	if fromHeader == "" {
		log.Fatalf("Header From mancante")
	}
	fromAddr := fromHeader
	if strings.Contains(fromHeader, "<") && strings.Contains(fromHeader, ">") {
		fromAddr = strings.TrimSpace(strings.Split(strings.Split(fromHeader, "<")[1], ">")[0])
	}
	newsgroups := header.Get("Newsgroups")
	if newsgroups == "" {
		log.Fatalf("Header Newsgroups mancante")
	}
	subject := header.Get("Subject")
	if subject == "" {
		subject = "(No subject)"
	}
	xhashcash := header.Get("X-Hashcash")
	if xhashcash == "" {
		log.Fatalf("Header X-Hashcash mancante")
	}

	// Log degli header Ed25519 per debugging
	log.Printf("X-Ed25519-Pub header: %s", header.Get("X-Ed25519-Pub"))
	log.Printf("X-Ed25519-Sig header: %s", header.Get("X-Ed25519-Sig"))

	bodyBuf := new(bytes.Buffer)
	_, err = io.Copy(bodyBuf, msg.Body)
	if err != nil {
		log.Fatalf("Errore lettura corpo email: %v", err)
	}
	body := strings.TrimSpace(bodyBuf.String())
	if body == "" {
		log.Fatalf("Corpo del messaggio vuoto")
	}

	// Prevenzione riutilizzo token
	if tokenAlreadySpent(xhashcash) {
		log.Fatalf("Token Hashcash già utilizzato")
	}
	// Verifica del token
	if !verifyHashcashToken(xhashcash, fromAddr) {
		log.Fatalf("Token Hashcash non valido")
	}
	if err := markTokenSpent(xhashcash); err != nil {
		log.Printf("Errore nella registrazione del token: %v", err)
	}

	// Gestione dei newsgroup: limita a 3 gruppi
	groups := strings.Split(newsgroups, ",")
	if len(groups) > 3 {
		groups = groups[:3]
		log.Printf("Limite newsgroups raggiunto, utilizzati: %v", groups)
	}
	limitedGroups := strings.Join(groups, ", ")

	// Ritardo per cross-posting, se necessario
	if len(groups) > 1 {
		time.Sleep(time.Duration(delayCrossPost) * time.Second)
	}

	// Generazione di un Message-ID univoco e formattazione data
	messageID := fmt.Sprintf("<%d.%d@mail2usenet.local>", time.Now().Unix(), randInt(1000, 9999))
	dateHeader := time.Now().UTC().Format(time.RFC1123Z)

	// Composizione del messaggio Usenet in formato RFC-compliant
	headers := []string{
		fmt.Sprintf("Message-ID: %s", messageID),
		fmt.Sprintf("Date: %s", dateHeader),
		fmt.Sprintf("From: %s", fromHeader),
		fmt.Sprintf("Newsgroups: %s", limitedGroups),
		fmt.Sprintf("Subject: %s", subject),
		"Path: mail2usenet",
		"Organization: Victor Hostile Communication Center 1312",
		fmt.Sprintf("X-Hashcash: %s", xhashcash),
		"X-No-Archive: Yes",
		"Mime-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 7bit",
		"User-Agent: m2usenet-go v0.1.0",
	}

	// Aggiunta degli header Ed25519 se presenti
	if ed25519pub := header.Get("X-Ed25519-Pub"); ed25519pub != "" {
		headers = append(headers, fmt.Sprintf("X-Ed25519-Pub: %s", ed25519pub))
	}
	if ed25519sig := header.Get("X-Ed25519-Sig"); ed25519sig != "" {
		headers = append(headers, fmt.Sprintf("X-Ed25519-Sig: %s", ed25519sig))
	}

	if ref := header.Get("References"); ref != "" {
		headers = append(headers, fmt.Sprintf("References: %s", ref))
	}
	usenetPost := strings.Join(headers, "\r\n") + "\r\n\r\n" + body
	if len([]byte(usenetPost)) > maxPostSize {
		log.Fatalf("Messaggio supera il limite di %d byte", maxPostSize)
	}

	success, err := sendViaTor(NNTPServer, nntpPort, usenetPost, messageID)
	if err != nil {
		log.Fatalf("Errore nell'invio del messaggio: %v", err)
	}
	if success {
		log.Println("Messaggio inviato correttamente")
		os.Exit(0)
	} else {
		log.Fatalln("Invio del messaggio fallito")
	}
}

// randInt genera un intero casuale nel range [min, max].
func randInt(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

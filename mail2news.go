package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// Version - major release with privacy hardening
const VERSION = "1.0.0"

// Exit codes
const (
	ExitSuccess   = 0
	ExitError     = 1
	ExitRejected  = 2
	ExitDuplicate = 3
)

// Privacy constants
const (
	MinPaddingSize     = 512
	MaxPaddingSize     = 4096
	PaddingBlockSize   = 64
	MinDelayMs         = 50
	MaxDelayMs         = 500
	JitterMs           = 100
	MaxMessageSize     = 1048576 // 1MB
	CacheExpiration    = 10 * time.Minute
	CleanupInterval    = 5 * time.Minute
)

// Config holds all configuration
type Config struct {
	Paths      PathsConfig      `mapstructure:"paths"`
	NNTP       NNTPConfig       `mapstructure:"nntp"`
	Thresholds ThresholdsConfig `mapstructure:"thresholds"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	Encoding   EncodingConfig   `mapstructure:"encoding"`
	Privacy    PrivacyConfig    `mapstructure:"privacy"`
}

type PathsConfig struct {
	Log     string `mapstructure:"log"`
	Etc     string `mapstructure:"etc"`
	Lib     string `mapstructure:"lib"`
	History string `mapstructure:"history"`
}

type NNTPConfig struct {
	Path           string   `mapstructure:"path_header"`
	InjectionHost  string   `mapstructure:"injection_host"`
	Contact        string   `mapstructure:"contact"`
	MessageID      string   `mapstructure:"messageid"`
	DefaultFrom    string   `mapstructure:"default_from"`
	PrimaryOnion   string   `mapstructure:"primary_onion"`
	FallbackServer string   `mapstructure:"fallback_server"`
	TorProxy       string   `mapstructure:"tor_proxy"`
	AlwaysUseTor   bool     `mapstructure:"always_use_tor"`
	OnionServers   []string `mapstructure:"onion_servers"`
	ClearnetServers []string `mapstructure:"clearnet_servers"`
}

type ThresholdsConfig struct {
	MaxBytes      int `mapstructure:"max_bytes"`
	MaxCrossposts int `mapstructure:"max_crossposts"`
	HoursPast     int `mapstructure:"hours_past"`
	HoursFuture   int `mapstructure:"hours_future"`
	SocketTimeout int `mapstructure:"socket_timeout"`
}

type LoggingConfig struct {
	Level   string `mapstructure:"level"`
	Format  string `mapstructure:"format"`
	DateFmt string `mapstructure:"datefmt"`
	Retain  int    `mapstructure:"retain"`
}

type EncodingConfig struct {
	ForceUtf8       bool   `mapstructure:"force_utf8"`
	FallbackCharset string `mapstructure:"fallback_charset"`
}

type PrivacyConfig struct {
	EnablePadding      bool `mapstructure:"enable_padding"`
	EnableDelays       bool `mapstructure:"enable_delays"`
	StripAllMetadata   bool `mapstructure:"strip_all_metadata"`
}

var (
	config       Config
	lockFilePath string
	lockFile     *os.File
	messageCache *MessageIDCache
	logMutex     sync.Mutex
)

// MessageIDCache with secure operations
type MessageIDCache struct {
	cache    map[string]time.Time
	mutex    sync.RWMutex
	maxAge   time.Duration
	cacheDir string
}

// SecureRandom generates cryptographically secure random bytes
func SecureRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// SecureRandomInt generates a cryptographically secure random integer in range [0, max)
func SecureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint64(b[:]) % uint64(max))
}

// SecureRandomDelay adds a random delay for timing attack mitigation
func SecureRandomDelay() {
	if !config.Privacy.EnableDelays {
		return
	}
	delay := MinDelayMs + SecureRandomInt(MaxDelayMs-MinDelayMs)
	jitter := SecureRandomInt(JitterMs*2) - JitterMs
	totalDelay := delay + jitter
	if totalDelay < 0 {
		totalDelay = MinDelayMs
	}
	time.Sleep(time.Duration(totalDelay) * time.Millisecond)
}

// SecureZeroMemory overwrites sensitive data in memory
func SecureZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}

// SecureCompare performs constant-time comparison
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GenerateAdaptivePadding creates padding to prevent size correlation attacks
func GenerateAdaptivePadding(currentSize int) []byte {
	if !config.Privacy.EnablePadding {
		return nil
	}
	
	// Calculate target size (round up to next block boundary)
	targetSize := ((currentSize / PaddingBlockSize) + 1) * PaddingBlockSize
	
	// Add random additional padding within bounds
	additionalPadding := SecureRandomInt(MaxPaddingSize-MinPaddingSize) + MinPaddingSize
	targetSize += additionalPadding
	
	paddingSize := targetSize - currentSize
	if paddingSize <= 0 {
		paddingSize = MinPaddingSize
	}
	
	// Generate random padding
	padding, err := SecureRandom(paddingSize)
	if err != nil {
		return nil
	}
	
	// Create padding header with size info (for receiver to strip)
	header := fmt.Sprintf("\r\n-- PADDING:%d --\r\n", paddingSize)
	
	// Encode padding as base64 to ensure safe transmission
	encodedPadding := base64.StdEncoding.EncodeToString(padding)
	
	return []byte(header + encodedPadding + "\r\n-- END PADDING --")
}

// StripPadding removes padding from received message
func StripPadding(message string) string {
	paddingStart := strings.Index(message, "\r\n-- PADDING:")
	if paddingStart == -1 {
		return message
	}
	
	paddingEnd := strings.Index(message, "-- END PADDING --")
	if paddingEnd == -1 {
		return message
	}
	
	return message[:paddingStart] + message[paddingEnd+17:]
}

// NewMessageIDCache creates a new message ID cache
func NewMessageIDCache(maxAge time.Duration, cacheDir string) *MessageIDCache {
	if cacheDir != "" {
		os.MkdirAll(cacheDir, 0700) // Restrictive permissions
	}
	
	cache := &MessageIDCache{
		cache:    make(map[string]time.Time),
		maxAge:   maxAge,
		cacheDir: cacheDir,
	}
	
	cache.loadCache()
	go cache.cleanupLoop()
	
	return cache
}

func (c *MessageIDCache) loadCache() {
	if c.cacheDir == "" {
		return
	}
	
	cacheFile := filepath.Join(c.cacheDir, "message_cache.dat")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return
	}
	defer SecureZeroMemory(data)
	
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.cache = make(map[string]time.Time)
	now := time.Now()
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		
		// Use hash of message ID for storage (privacy)
		hashedID := parts[0]
		timestamp, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		
		processTime := time.Unix(timestamp, 0)
		if now.Sub(processTime) < c.maxAge {
			c.cache[hashedID] = processTime
		}
	}
}

func (c *MessageIDCache) saveCache() {
	if c.cacheDir == "" {
		return
	}
	
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	var builder strings.Builder
	for hashedID, timestamp := range c.cache {
		builder.WriteString(fmt.Sprintf("%s %d\n", hashedID, timestamp.Unix()))
	}
	
	content := []byte(builder.String())
	defer SecureZeroMemory(content)
	
	cacheFile := filepath.Join(c.cacheDir, "message_cache.dat")
	os.WriteFile(cacheFile, content, 0600) // Restrictive permissions
}

func (c *MessageIDCache) cleanupLoop() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		c.cleanup()
		c.saveCache()
	}
}

func (c *MessageIDCache) cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	now := time.Now()
	for id, timestamp := range c.cache {
		if now.Sub(timestamp) > c.maxAge {
			delete(c.cache, id)
		}
	}
}

// hashMessageID creates a privacy-preserving hash of message ID
func hashMessageID(messageID string) string {
	messageID = strings.Trim(messageID, "<>")
	hash := sha256.Sum256([]byte(messageID))
	return fmt.Sprintf("%x", hash[:16])
}

func (c *MessageIDCache) IsProcessed(messageID string) bool {
	hashedID := hashMessageID(messageID)
	
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	_, exists := c.cache[hashedID]
	return exists
}

func (c *MessageIDCache) MarkProcessed(messageID string) {
	hashedID := hashMessageID(messageID)
	
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.cache[hashedID] = time.Now()
	
	if len(c.cache)%50 == 0 {
		go c.saveCache()
	}
}

// acquireLock creates a lock file with secure permissions
func acquireLock() bool {
	lockDir := "/var/lock/mail2news"
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		lockDir = os.TempDir()
	}
	
	lockFilePath = filepath.Join(lockDir, "mail2news.lock")
	
	file, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			existingFile, err := os.OpenFile(lockFilePath, os.O_RDWR, 0600)
			if err != nil {
				return false
			}
			
			if err := syscall.Flock(int(existingFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				existingFile.Close()
				return false
			}
			
			lockFile = existingFile
			lockFile.Truncate(0)
			lockFile.Seek(0, 0)
			
			// Write minimal info (no PID for privacy)
			timestamp := time.Now().Unix()
			lockFile.WriteString(fmt.Sprintf("%d\n", timestamp))
			
			return true
		}
		return false
	}
	
	lockFile = file
	
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lockFile.Close()
		os.Remove(lockFilePath)
		return false
	}
	
	timestamp := time.Now().Unix()
	lockFile.WriteString(fmt.Sprintf("%d\n", timestamp))
	
	return true
}

func releaseLock() {
	if lockFile != nil {
		syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		lockFile.Close()
		lockFile = nil
		os.Remove(lockFilePath)
	}
}

func initLogging() {
	if config.Paths.Log == "" {
		config.Paths.Log = "/var/log/mail2news/mail2news.log"
	}
	
	logDir := filepath.Dir(config.Paths.Log)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		log.SetOutput(os.Stdout)
		log.SetFlags(log.Ldate | log.Ltime)
		return
	}
	
	logFile, err := os.OpenFile(config.Paths.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.SetOutput(os.Stdout)
		log.SetFlags(log.Ldate | log.Ltime)
		return
	}
	
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime)
}

func logMessage(message string, level string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	
	if level == "" {
		level = "INFO"
	}
	
	configLevel := strings.ToUpper(config.Logging.Level)
	if configLevel == "" {
		configLevel = "WARNING"
	}
	
	messageLevel := strings.ToUpper(level)
	shouldLog := false
	
	switch configLevel {
	case "DEBUG":
		shouldLog = true
	case "INFO":
		shouldLog = messageLevel != "DEBUG"
	case "WARNING":
		shouldLog = messageLevel == "WARNING" || messageLevel == "ERROR"
	case "ERROR":
		shouldLog = messageLevel == "ERROR"
	}
	
	if shouldLog {
		// Sanitize message to prevent log injection
		message = strings.ReplaceAll(message, "\n", " ")
		message = strings.ReplaceAll(message, "\r", " ")
		log.Printf("[%s] %s", messageLevel, message)
	}
}

func convertEncoding(input string, sourceEnc string, targetEnc string) (string, error) {
	if strings.EqualFold(sourceEnc, targetEnc) {
		return input, nil
	}
	
	var enc encoding.Encoding
	var err error
	
	switch strings.ToLower(sourceEnc) {
	case "utf-8", "us-ascii":
		return input, nil
	case "iso-8859-1", "latin1":
		enc = charmap.ISO8859_1
	case "iso-8859-2", "latin2":
		enc = charmap.ISO8859_2
	case "iso-8859-15", "latin9":
		enc = charmap.ISO8859_15
	case "windows-1252":
		enc = charmap.Windows1252
	case "windows-1250":
		enc = charmap.Windows1250
	case "koi8-r":
		enc = charmap.KOI8R
	default:
		enc, err = htmlindex.Get(sourceEnc)
		if err != nil {
			fallback := config.Encoding.FallbackCharset
			if fallback == "" {
				fallback = "iso-8859-1"
			}
			enc, _ = htmlindex.Get(fallback)
		}
	}
	
	reader := transform.NewReader(strings.NewReader(input), enc.NewDecoder())
	result, err := io.ReadAll(reader)
	if err != nil {
		return input, err
	}
	
	return string(result), nil
}

func decodeTransferEncoding(content string, enc string) (string, error) {
	enc = strings.ToLower(strings.TrimSpace(enc))
	
	switch enc {
	case "quoted-printable":
		reader := quotedprintable.NewReader(strings.NewReader(content))
		decoded, err := io.ReadAll(reader)
		if err != nil {
			return content, err
		}
		return string(decoded), nil
		
	case "base64":
		content = regexp.MustCompile(`\s+`).ReplaceAllString(content, "")
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return content, err
		}
		return string(decoded), nil
		
	case "7bit", "8bit", "binary", "":
		return content, nil
		
	default:
		return content, nil
	}
}

func normalizeEmailFormat(message string) string {
	// Detect encoding
	contentTypeRegex := regexp.MustCompile(`(?i)Content-Type:[^\n]*charset=["']?([^"'\r\n;]+)`)
	matches := contentTypeRegex.FindStringSubmatch(message)
	
	sourceEncoding := "utf-8"
	if len(matches) > 1 {
		sourceEncoding = strings.ToLower(matches[1])
	}
	
	// Find transfer encoding
	transferEncodingRegex := regexp.MustCompile(`(?i)Content-Transfer-Encoding:\s*([^\r\n]+)`)
	transferEncoding := "7bit"
	if m := transferEncodingRegex.FindStringSubmatch(message); len(m) > 1 {
		transferEncoding = strings.TrimSpace(m[1])
	}
	
	// Process header-body separation
	headerEnd := strings.Index(message, "\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = strings.Index(message, "\n\n")
	}
	
	if headerEnd != -1 {
		headers := message[:headerEnd]
		body := message[headerEnd:]
		
		body = regexp.MustCompile(`^\r?\n\r?\n+`).ReplaceAllString(body, "\r\n\r\n")
		
		if len(body) > 4 {
			decodedBody, err := decodeTransferEncoding(body[4:], transferEncoding)
			if err == nil {
				decodedBody = strings.TrimLeft(decodedBody, "\r\n \t")
				body = "\r\n\r\n" + decodedBody
			}
		}
		
		message = headers + body
	}
	
	// Convert to UTF-8
	if sourceEncoding != "utf-8" && sourceEncoding != "us-ascii" {
		if converted, err := convertEncoding(message, sourceEncoding, "utf-8"); err == nil {
			message = converted
		}
	}
	
	// Replace problematic Unicode characters
	replacements := map[string]string{
		"\u2018": "'", "\u2019": "'",
		"\u201C": "\"", "\u201D": "\"",
		"\u2026": "...",
		"\u2013": "-", "\u2014": "-",
	}
	for old, new := range replacements {
		message = strings.ReplaceAll(message, old, new)
	}
	
	// Ensure MIME-Version
	mimeVersionRegex := regexp.MustCompile(`(?i)MIME-Version:.*\r?\n`)
	message = mimeVersionRegex.ReplaceAllString(message, "")
	
	headerEnd = strings.Index(message, "\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = strings.Index(message, "\n\n")
	}
	
	if headerEnd != -1 {
		message = message[:headerEnd] + "\r\nMIME-Version: 1.0\r\n" + message[headerEnd:]
	}
	
	// Ensure Content-Type with UTF-8
	if !regexp.MustCompile(`(?i)Content-Type:`).MatchString(message) {
		headerEnd := strings.Index(message, "\r\n\r\n")
		if headerEnd == -1 {
			headerEnd = strings.Index(message, "\n\n")
		}
		if headerEnd != -1 {
			message = message[:headerEnd] + "\r\nContent-Type: text/plain; charset=utf-8\r\n" + message[headerEnd:]
		}
	} else {
		message = regexp.MustCompile(`(?i)(Content-Type:[^\n]*charset=)["']?[^"'\r\n;]+`).
			ReplaceAllString(message, "${1}utf-8")
	}
	
	// Normalize line endings
	message = strings.ReplaceAll(message, "\r\n", "\n")
	message = strings.ReplaceAll(message, "\n", "\r\n")
	
	// Handle dot stuffing
	lines := strings.Split(message, "\r\n")
	for i, line := range lines {
		if line == "." {
			lines[i] = ".."
		} else if strings.HasPrefix(line, ".") && line != ".." {
			lines[i] = "." + line
		}
	}
	
	return strings.Join(lines, "\r\n")
}

func parseRecipient(user string) (string, string, bool) {
	if idx := strings.Index(user, "@"); idx != -1 {
		user = user[:idx]
	}
	
	re := regexp.MustCompile(`(mail2news|mail2news_nospam)-([0-9]{8})-(.*)`)
	matches := re.FindStringSubmatch(user)
	
	if matches == nil {
		logMessage("Invalid recipient format", "ERROR")
		os.Exit(ExitRejected)
	}
	
	recipient := matches[1]
	timestamp := matches[2]
	newsgroups := strings.ReplaceAll(matches[3], "=", ",")
	
	nospam := recipient == "mail2news_nospam"
	
	return timestamp, newsgroups, nospam
}

func validateStamp(stamp string) bool {
	layout := "20060102"
	parsedTime, err := time.Parse(layout, stamp)
	if err != nil {
		logMessage("Invalid date format", "ERROR")
		os.Exit(ExitRejected)
	}
	
	now := time.Now().UTC()
	beforeTime := now.Add(-time.Duration(config.Thresholds.HoursPast) * time.Hour)
	afterTime := now.Add(time.Duration(config.Thresholds.HoursFuture) * time.Hour)
	
	if parsedTime.After(beforeTime) && parsedTime.Before(afterTime) {
		return true
	}
	
	logMessage("Timestamp out of bounds", "ERROR")
	os.Exit(ExitRejected)
	return false
}

func ngvalidate(newsgroups string) string {
	newsgroups = strings.TrimRight(newsgroups, ",")
	groups := strings.Split(newsgroups, ",")
	
	var validGroups []string
	seen := make(map[string]bool)
	
	re := regexp.MustCompile(`^[a-z][a-z0-9]+(\.[0-9a-z-+_]+)+$`)
	
	for _, ng := range groups {
		ng = strings.TrimSpace(ng)
		
		if !re.MatchString(ng) {
			continue
		}
		
		if seen[ng] {
			continue
		}
		
		seen[ng] = true
		validGroups = append(validGroups, ng)
	}
	
	if len(validGroups) == 0 {
		logMessage("No valid newsgroups", "ERROR")
		os.Exit(ExitRejected)
	}
	
	if len(validGroups) > config.Thresholds.MaxCrossposts {
		logMessage("Too many crossposts", "ERROR")
		os.Exit(ExitRejected)
	}
	
	return strings.Join(validGroups, ",")
}

func generateMessageID(domain string, bodyContent string) string {
	if domain == "" {
		domain = "anon.invalid"
	}
	
	now := time.Now().UTC()
	
	// Generate random component
	randomBytes, _ := SecureRandom(16)
	randomPart := fmt.Sprintf("%x", randomBytes)[:12]
	
	// Content hash for uniqueness
	contentHash := sha256.Sum256([]byte(bodyContent))
	contentHashStr := fmt.Sprintf("%x", contentHash)[:8]
	
	leftPart := fmt.Sprintf("%s.%d.%s.%s",
		now.Format("20060102150405"),
		now.UnixNano()%1000000,
		randomPart,
		contentHashStr)
	
	return "<" + leftPart + "@" + domain + ">"
}

func blacklistCheck(badFile string, text string) string {
	filename := filepath.Join(config.Paths.Etc, badFile)
	badList := file2list(filename)
	
	if len(badList) == 0 {
		return ""
	}
	
	pattern := strings.Join(badList, "|")
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	
	return re.FindString(text)
}

func file2list(filename string) []string {
	var items []string
	
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return items
	}
	
	file, err := os.Open(filename)
	if err != nil {
		return items
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			items = append(items, line)
		}
	}
	
	return items
}

func fromParse(fromHdr string) (string, string) {
	var name, addy string
	
	// Pattern: "Name <user@example.com>"
	if re := regexp.MustCompile(`([^<>]*)<([^<>\s]+@[^<>\s]+)>`); true {
		if m := re.FindStringSubmatch(fromHdr); m != nil {
			name = strings.TrimSpace(m[1])
			addy = m[2]
		}
	}
	
	// Pattern: "user@example.com (Name)"
	if addy == "" {
		if re := regexp.MustCompile(`([^<>\s]+@[^<>\s]+)\s+\(([^\(\)]*)\)`); true {
			if m := re.FindStringSubmatch(fromHdr); m != nil {
				addy = m[1]
				name = strings.TrimSpace(m[2])
			}
		}
	}
	
	// Pattern: "user@example.com"
	if addy == "" {
		if re := regexp.MustCompile(`([^<>\s]+@[^<>\s]+)`); true {
			if m := re.FindStringSubmatch(fromHdr); m != nil {
				addy = m[1]
			}
		}
	}
	
	if addy != "" {
		addy = strings.ReplaceAll(addy, ".", "<DOT>")
		addy = strings.ReplaceAll(addy, "@", "<AT>")
	}
	
	return name, addy
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func msgParse(message string) (string, string) {
	SecureRandomDelay()
	
	// Remove mailbox "From " lines
	lines := strings.Split(message, "\n")
	var cleanedLines []string
	
	for _, line := range lines {
		if strings.HasPrefix(line, "From ") && !strings.Contains(line, ":") {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}
	message = strings.Join(cleanedLines, "\n")
	
	message = normalizeEmailFormat(message)
	
	msg, err := mail.ReadMessage(strings.NewReader(message))
	if err != nil {
		logMessage("Parse error", "ERROR")
		os.Exit(ExitError)
	}
	
	// Check for duplicate
	messageId := msg.Header.Get("Message-ID")
	if messageId != "" && messageCache != nil {
		if messageCache.IsProcessed(messageId) {
			logMessage("Duplicate message", "INFO")
			os.Exit(ExitDuplicate)
		}
	}
	
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		logMessage("Body read error", "ERROR")
		os.Exit(ExitError)
	}
	
	bodyContent := string(body)
	if len(strings.TrimSpace(bodyContent)) == 0 {
		bodyContent = "."
		body = []byte(bodyContent)
	}
	
	// Generate Message-ID if missing
	if messageId == "" {
		messageId = generateMessageID(config.NNTP.MessageID, bodyContent)
		msg.Header["Message-ID"] = []string{messageId}
	}
	
	// Ensure Date header
	if msg.Header.Get("Date") == "" {
		msg.Header["Date"] = []string{time.Now().UTC().Format(time.RFC1123Z)}
	}
	
	// Process From header
	fromHeader := msg.Header.Get("From")
	if fromHeader != "" {
		if match := blacklistCheck("bad_from", fromHeader); match != "" {
			logMessage("Blacklisted sender", "ERROR")
			os.Exit(ExitRejected)
		}
	} else {
		msg.Header["From"] = []string{config.NNTP.DefaultFrom}
	}
	
	// Handle References for threading
	if refs := msg.Header.Get("References"); refs != "" {
		if !strings.Contains(refs, "<") {
			refs = "<" + refs
		}
		if !strings.Contains(refs, ">") {
			refs = refs + ">"
		}
		msg.Header["References"] = []string{refs}
		msg.Header["In-Reply-To"] = []string{refs}
	}
	
	// Check poison headers
	poisonFile := filepath.Join(config.Paths.Etc, "headers_poison")
	poisonHeaders := file2list(poisonFile)
	for _, header := range poisonHeaders {
		if msg.Header.Get(header) != "" {
			logMessage("Poison header detected", "ERROR")
			os.Exit(ExitRejected)
		}
	}
	
	// Get recipient
	var recipient string
	if to := msg.Header.Get("X-Original-To"); to != "" {
		recipient = to
	} else if to := msg.Header.Get("To"); to != "" {
		recipient = to
	} else {
		recipient = "mail2news@m2n.mixmin.net"
	}
	
	if !strings.HasPrefix(recipient, "mail2news") {
		logMessage("Invalid recipient", "ERROR")
		os.Exit(ExitRejected)
	}
	
	// Process newsgroups
	nospam := false
	var dest string
	
	if ng := msg.Header.Get("Newsgroups"); ng != "" {
		dest = ng
		delete(msg.Header, "Newsgroups")
		
		if strings.HasPrefix(recipient, "mail2news_nospam") {
			nospam = true
		}
	} else {
		var stamp string
		stamp, dest, nospam = parseRecipient(recipient)
		
		if !validateStamp(stamp) {
			logMessage("Invalid timestamp", "ERROR")
			os.Exit(ExitRejected)
		}
	}
	
	validatedGroups := ngvalidate(dest)
	msg.Header["Newsgroups"] = []string{validatedGroups}
	
	if match := blacklistCheck("bad_groups", validatedGroups); match != "" {
		logMessage("Blacklisted newsgroup", "ERROR")
		os.Exit(ExitRejected)
	}
	
	// Handle nospam mode
	if nospam {
		name, addy := fromParse(msg.Header.Get("From"))
		if addy != "" {
			delete(msg.Header, "Author-Supplied-Address")
			delete(msg.Header, "From")
			msg.Header["Author-Supplied-Address"] = []string{addy}
			msg.Header["From"] = []string{name + "<Use-Author-Supplied-Address-Header@[127.1]>"}
		}
	}
	
	// Ensure Subject
	if msg.Header.Get("Subject") == "" {
		msg.Header["Subject"] = []string{"(none)"}
	}
	
	// Strip headers
	stripFile := filepath.Join(config.Paths.Etc, "headers_strip")
	stripHeaders := file2list(stripFile)
	
	preserveHeaders := map[string]bool{
		"X-Hashcash":    true,
		"X-Ed25519-Pub": true,
		"X-Ed25519-Sig": true,
	}
	
	for _, header := range stripHeaders {
		if !preserveHeaders[header] {
			delete(msg.Header, header)
		}
	}
	
	// Strip all metadata if privacy mode enabled
	if config.Privacy.StripAllMetadata {
		metadataHeaders := []string{
			"Received", "X-Originating-IP", "X-Mailer",
			"User-Agent", "X-MimeOLE", "X-Priority",
		}
		for _, h := range metadataHeaders {
			delete(msg.Header, h)
		}
	}
	
	// Add gateway headers
	msg.Header["Path"] = []string{config.NNTP.Path}
	msg.Header["Organization"] = []string{"Anonymous Gateway"}
	msg.Header["X-Gateway-Info"] = []string{config.NNTP.InjectionHost}
	
	delete(msg.Header, "User-Agent")
	msg.Header["User-Agent"] = []string{fmt.Sprintf("mail2news v%s", VERSION)}
	
	delete(msg.Header, "MIME-Version")
	delete(msg.Header, "Mime-Version")
	msg.Header["MIME-Version"] = []string{"1.0"}
	
	// Build message
	var txtMsg strings.Builder
	
	for k, vv := range msg.Header {
		for _, v := range vv {
			v = strings.TrimSpace(v)
			txtMsg.WriteString(k + ": " + v + "\r\n")
		}
	}
	
	txtMsg.WriteString("\r\n")
	
	bodyStr := string(body)
	bodyStr = strings.TrimLeft(bodyStr, "\r\n \t")
	bodyStr = strings.ReplaceAll(bodyStr, "\r\n", "\n")
	bodyStr = strings.ReplaceAll(bodyStr, "\n", "\r\n")
	
	// Dot stuffing
	bodyLines := strings.Split(bodyStr, "\r\n")
	for i, line := range bodyLines {
		if line == "." {
			bodyLines[i] = ".."
		} else if strings.HasPrefix(line, ".") && line != ".." {
			bodyLines[i] = "." + line
		}
	}
	bodyStr = strings.Join(bodyLines, "\r\n")
	
	txtMsg.WriteString(bodyStr)
	
	if !strings.HasSuffix(txtMsg.String(), "\r\n") {
		txtMsg.WriteString("\r\n")
	}
	
	result := txtMsg.String()
	
	// Add adaptive padding if enabled
	if config.Privacy.EnablePadding {
		padding := GenerateAdaptivePadding(len(result))
		if padding != nil {
			result = result + string(padding)
		}
	}
	
	size := len(result)
	if size > config.Thresholds.MaxBytes {
		logMessage("Message too large", "ERROR")
		os.Exit(ExitRejected)
	}
	
	if messageCache != nil && messageId != "" {
		messageCache.MarkProcessed(messageId)
	}
	
	return messageId, result
}

func newsSend(mid string, content string) {
	SecureRandomDelay()
	
	torProxyAddr := "127.0.0.1:9050"
	if config.NNTP.TorProxy != "" {
		torProxyAddr = config.NNTP.TorProxy
	}
	
	torDialer, err := proxy.SOCKS5("tcp", torProxyAddr, nil, proxy.Direct)
	if err != nil {
		logMessage("Tor dialer error", "ERROR")
		return
	}
	
	successfulDelivery := false
	attemptedHosts := make(map[string]bool)
	
	// Build server list
	var serverList []string
	
	// Add onion servers
	if config.NNTP.PrimaryOnion != "" {
		server := config.NNTP.PrimaryOnion
		if !strings.Contains(server, ":") {
			server += ":119"
		}
		serverList = append(serverList, server)
	}
	
	for _, server := range config.NNTP.OnionServers {
		if !strings.Contains(server, ":") {
			server += ":119"
		}
		serverList = append(serverList, server)
	}
	
	// Add fallback
	if config.NNTP.FallbackServer != "" {
		server := config.NNTP.FallbackServer
		if !strings.Contains(server, ":") {
			server += ":119"
		}
		serverList = append(serverList, server)
	}
	
	// Add clearnet servers
	for _, server := range config.NNTP.ClearnetServers {
		if !strings.Contains(server, ":") {
			server += ":119"
		}
		serverList = append(serverList, server)
	}
	
	// Add from nntphosts file
	hostFile := filepath.Join(config.Paths.Etc, "nntphosts")
	hosts := file2list(hostFile)
	for _, host := range hosts {
		if !strings.Contains(host, ":") {
			host += ":119"
		}
		serverList = append(serverList, host)
	}
	
	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueServers []string
	for _, server := range serverList {
		if !seen[server] {
			seen[server] = true
			uniqueServers = append(uniqueServers, server)
		}
	}
	
	for _, host := range uniqueServers {
		if attemptedHosts[host] {
			continue
		}
		
		attemptedHosts[host] = true
		SecureRandomDelay()
		
		logMessage(fmt.Sprintf("Attempting delivery to %s", host), "INFO")
		
		err, isDuplicate := deliverViaTor(torDialer, host, mid, content)
		
		if err == nil {
			logMessage(fmt.Sprintf("Delivered to %s", host), "INFO")
			successfulDelivery = true
			break
		} else if isDuplicate {
			logMessage(fmt.Sprintf("Already exists on %s", host), "INFO")
			successfulDelivery = true
		} else {
			logMessage(fmt.Sprintf("Delivery failed to %s", host), "WARNING")
		}
	}
	
	if successfulDelivery {
		logMessage("Message delivered", "INFO")
	} else {
		logMessage("All deliveries failed", "WARNING")
	}
}

func deliverViaTor(torDialer proxy.Dialer, host string, messageID string, content string) (error, bool) {
	baseTimeout := config.Thresholds.SocketTimeout
	if baseTimeout == 0 {
		baseTimeout = 120
	}
	
	timeout := baseTimeout
	if strings.Contains(host, ".onion") {
		timeout = baseTimeout * 3
	}
	
	timeoutDialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}
	
	var conn net.Conn
	var err error
	
	if strings.Contains(host, ".onion") || config.NNTP.AlwaysUseTor {
		conn, err = torDialer.Dial("tcp", host)
	} else {
		conn, err = timeoutDialer.Dial("tcp", host)
	}
	
	if err != nil {
		return fmt.Errorf("connection error"), false
	}
	defer conn.Close()
	
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	conn.SetDeadline(deadline)
	
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	
	// Read greeting
	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("greeting error"), false
	}
	
	if !strings.HasPrefix(resp, "200 ") && !strings.HasPrefix(resp, "201 ") {
		return fmt.Errorf("bad greeting"), false
	}
	
	// MODE READER for onion servers
	if strings.Contains(host, ".onion") {
		writer.WriteString("MODE READER\r\n")
		writer.Flush()
		
		resp, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("mode reader error"), false
		}
	}
	
	// IHAVE
	writer.WriteString(fmt.Sprintf("IHAVE %s\r\n", messageID))
	writer.Flush()
	
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("ihave error"), false
	}
	
	if strings.HasPrefix(resp, "335 ") {
		// Strip padding before sending
		cleanContent := StripPadding(content)
		
		writer.WriteString(cleanContent + "\r\n.\r\n")
		writer.Flush()
		
		resp, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("article error"), false
		}
		
		if strings.HasPrefix(resp, "235 ") {
			writer.WriteString("QUIT\r\n")
			writer.Flush()
			return nil, false
		}
		
		writer.WriteString("QUIT\r\n")
		writer.Flush()
		return fmt.Errorf("article rejected"), false
		
	} else if strings.HasPrefix(resp, "435 ") {
		writer.WriteString("QUIT\r\n")
		writer.Flush()
		return nil, true
		
	} else if strings.HasPrefix(resp, "436 ") {
		writer.WriteString("QUIT\r\n")
		writer.Flush()
		return fmt.Errorf("transfer not possible"), false
	}
	
	writer.WriteString("QUIT\r\n")
	writer.Flush()
	return fmt.Errorf("ihave not accepted"), false
}

func main() {
	fmt.Printf("Mail2News v%s - Privacy Enhanced\n", VERSION)
	
	if !acquireLock() {
		fmt.Println("Another instance running")
		os.Exit(ExitSuccess)
	}
	defer releaseLock()
	
	// Initialize config
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/mail2news")
	viper.AddConfigPath("$HOME/.mail2news")
	viper.AddConfigPath(".")
	
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Config error: %s", err)
	}
	
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Config parse error: %s", err)
	}
	
	// Set defaults
	if config.Paths.Log == "" {
		config.Paths.Log = "/var/log/mail2news/mail2news.log"
	}
	if config.Logging.Level == "" {
		config.Logging.Level = "WARNING"
	}
	if config.Encoding.FallbackCharset == "" {
		config.Encoding.FallbackCharset = "iso-8859-1"
	}
	if config.Thresholds.MaxBytes == 0 {
		config.Thresholds.MaxBytes = MaxMessageSize
	}
	
	// Enable privacy features by default
	if !config.Privacy.EnablePadding && !config.Privacy.EnableDelays {
		config.Privacy.EnablePadding = true
		config.Privacy.EnableDelays = true
		config.Privacy.StripAllMetadata = true
	}
	
	initLogging()
	
	messageCache = NewMessageIDCache(CacheExpiration, "/var/lib/mail2news/cache")
	
	logMessage(fmt.Sprintf("Mail2news v%s initialized", VERSION), "INFO")
	fmt.Println("Enter message (Ctrl-D to finish):")
	
	message, err := io.ReadAll(os.Stdin)
	if err != nil {
		logMessage("Input error", "ERROR")
		os.Exit(ExitError)
	}
	
	mid, payload := msgParse(string(message))
	newsSend(mid, payload)
	
	// Secure cleanup
	SecureZeroMemory(message)
	
	logMessage("Completed", "INFO")
}

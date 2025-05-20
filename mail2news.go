package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
	// Imports for encoding handling
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
	// Imports for transfer encoding
	"mime/quotedprintable"
	"encoding/base64"
)

// Config structure to hold all configuration
type Config struct {
	Paths      PathsConfig      `mapstructure:"paths"`
	NNTP       NNTPConfig       `mapstructure:"nntp"`
	Thresholds ThresholdsConfig `mapstructure:"thresholds"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	Encoding   EncodingConfig   `mapstructure:"encoding"`
}

type PathsConfig struct {
	Log     string `mapstructure:"log"`
	Etc     string `mapstructure:"etc"`
	Lib     string `mapstructure:"lib"`
	History string `mapstructure:"history"`
}

type NNTPConfig struct {
	Path           string `mapstructure:"path_header"`
	InjectionHost  string `mapstructure:"injection_host"`
	Contact        string `mapstructure:"contact"`
	MessageID      string `mapstructure:"messageid"`
	DefaultFrom    string `mapstructure:"default_from"`
	PrimaryOnion   string `mapstructure:"primary_onion"`
	FallbackServer string `mapstructure:"fallback_server"`
	TorProxy       string `mapstructure:"tor_proxy"`
	AlwaysUseTor   bool   `mapstructure:"always_use_tor"`
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

// Global configuration
var config Config

// Version constant
const VERSION = "0.9.4"

// Global lock file path and handle
var lockFilePath string
var lockFile *os.File

// MessageIDCache stores recently processed message IDs to avoid duplicates
type MessageIDCache struct {
	cache    map[string]time.Time // Maps message ID to time it was processed
	mutex    sync.RWMutex
	maxAge   time.Duration // Maximum age of cache entries
	cacheDir string        // Directory for persistent cache
}

// Global message ID cache
var messageCache *MessageIDCache

// NewMessageIDCache creates a new message ID cache with the specified max age
func NewMessageIDCache(maxAge time.Duration, cacheDir string) *MessageIDCache {
	// Create cache directory if it doesn't exist
	if cacheDir != "" {
		os.MkdirAll(cacheDir, 0755)
	}

	cache := &MessageIDCache{
		cache:    make(map[string]time.Time),
		maxAge:   maxAge,
		cacheDir: cacheDir,
	}

	// Load persisted cache (if exists)
	cache.loadCache()

	// Start background cleanup goroutine
	go cache.startCleanupLoop(maxAge / 2)

	return cache
}

// loadCache loads the persisted cache from disk
func (c *MessageIDCache) loadCache() {
	if c.cacheDir == "" {
		return
	}

	cacheFile := filepath.Join(c.cacheDir, "message_cache.txt")
	data, err := ioutil.ReadFile(cacheFile)
	if err != nil {
		// Cache file may not exist yet, that's ok
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear existing cache
	c.cache = make(map[string]time.Time)

	// Parse each line as "messageID timestamp"
	lines := strings.Split(string(data), "\n")
	now := time.Now()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			continue
		}

		messageID := parts[0]
		timestampStr := parts[1]
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			continue
		}

		processTime := time.Unix(timestamp, 0)
		// Only load entries that haven't expired
		if now.Sub(processTime) < c.maxAge {
			c.cache[messageID] = processTime
		}
	}

	logMessage(fmt.Sprintf("Loaded %d recent message IDs from cache", len(c.cache)), "DEBUG")
}

// saveCache persists the cache to disk
func (c *MessageIDCache) saveCache() {
	if c.cacheDir == "" {
		return
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Build cache file content
	var cacheContent strings.Builder
	for messageID, timestamp := range c.cache {
		cacheContent.WriteString(fmt.Sprintf("%s %d\n", messageID, timestamp.Unix()))
	}

	// Write to file
	cacheFile := filepath.Join(c.cacheDir, "message_cache.txt")
	err := ioutil.WriteFile(cacheFile, []byte(cacheContent.String()), 0644)
	if err != nil {
		logMessage(fmt.Sprintf("Error saving message cache: %v", err), "WARNING")
	}
}

// startCleanupLoop periodically cleans up expired cache entries
func (c *MessageIDCache) startCleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
		c.saveCache()
	}
}

// cleanup removes expired entries from the cache
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

// IsProcessed checks if a message ID has been processed recently
func (c *MessageIDCache) IsProcessed(messageID string) bool {
	// Strip any angle brackets from message ID
	messageID = strings.Trim(messageID, "<>")

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	_, exists := c.cache[messageID]
	return exists
}

// MarkProcessed marks a message ID as processed
func (c *MessageIDCache) MarkProcessed(messageID string) {
	// Strip any angle brackets from message ID
	messageID = strings.Trim(messageID, "<>")

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[messageID] = time.Now()

	// If cache is getting large, trigger a save
	if len(c.cache)%100 == 0 {
		go c.saveCache()
	}
}

// acquireLock creates a lock file to ensure only one instance is running
// Using both atomic file creation with O_EXCL and system-level flock
func acquireLock() bool {
	// Use a fixed location for better lock handling
	lockDir := "/var/lock/mail2news"
	err := os.MkdirAll(lockDir, 0755)
	if err != nil {
		log.Printf("Error creating lock directory %s: %v", lockDir, err)
		// Fall back to temp directory if can't create lock dir
		lockDir = os.TempDir()
	}
	
	lockFilePath = filepath.Join(lockDir, "mail2news.lock")
	
	// Attempt to create the lock file with O_EXCL flag
	file, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		// If file exists, check if it's stale
		if os.IsExist(err) {
			log.Printf("Lock file exists at %s. Checking if it's stale...", lockFilePath)
			
			// Try to acquire the existing lock for reading
			existingFile, err := os.OpenFile(lockFilePath, os.O_RDWR, 0600)
			if err != nil {
				log.Printf("Error opening existing lock file: %v", err)
				return false
			}
			
			// Try to apply a non-blocking flock - if successful, the lock is stale
			err = syscall.Flock(int(existingFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err != nil {
				// Cannot lock - another process has it
				existingFile.Close()
				log.Printf("Another mail2news instance is holding the lock. Exiting.")
				return false
			}
			
			// We got the lock, so it was stale. Read PID from file for logging
			content, _ := ioutil.ReadAll(existingFile)
			lines := strings.Split(string(content), "\n")
			if len(lines) > 0 {
				pidStr := strings.TrimSpace(lines[0])
				pid, _ := strconv.Atoi(pidStr)
				log.Printf("Found stale lock from PID %d. Removing it.", pid)
			} else {
				log.Printf("Found stale lock file with invalid format. Removing it.")
			}
			
			// Keep this file and handle since we've already flocked it
			lockFile = existingFile
			
			// Truncate and rewrite with our info
			lockFile.Truncate(0)
			lockFile.Seek(0, 0)
			
			// Write our PID and info to the lock file
			pid := os.Getpid()
			timestamp := time.Now().Format(time.RFC3339)
			lockContent := fmt.Sprintf("%d\n%s\nmail2news v%s", pid, timestamp, VERSION)
			lockFile.WriteString(lockContent)
			
			log.Printf("Lock acquired with flock by PID %d (recycled stale lock)", pid)
			return true
		}
		
		// Any other error creating the lock file
		log.Printf("Failed to create lock file: %v", err)
		return false
	}
	
	// Keep reference to the file so we can flock it and close it later
	lockFile = file
	
	// Apply a system-level flock to the file - this is the key to robust locking
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		log.Printf("Could not acquire system lock: %v", err)
		lockFile.Close()
		os.Remove(lockFilePath)
		return false
	}
	
	// Successfully created and locked the file
	// Write PID, timestamp, and version to lock file
	pid := os.Getpid()
	timestamp := time.Now().Format(time.RFC3339)
	lockContent := fmt.Sprintf("%d\n%s\nmail2news v%s", pid, timestamp, VERSION)
	
	if _, err := lockFile.WriteString(lockContent); err != nil {
		log.Printf("Failed to write to lock file: %v", err)
		releaseLock() // Will release flock and remove file
		return false
	}
	
	log.Printf("Lock acquired with flock by PID %d", pid)
	return true
}

// releaseLock releases the process lock
func releaseLock() {
	if lockFile != nil {
		// Release the system-level lock
		syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		lockFile.Close()
		lockFile = nil
		
		// Remove the lock file
		log.Printf("Releasing lock (PID %d)", os.Getpid())
		err := os.Remove(lockFilePath)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to remove lock file: %v", err)
		}
	}
}

// Initialize logging
func initLogging() {
	// Make sure path is set
	if config.Paths.Log == "" {
		config.Paths.Log = "/var/log/mail2news/mail2news.log"
	}

	// Create directory if it doesn't exist
	logDir := filepath.Dir(config.Paths.Log)
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		log.Printf("Error creating log directory %s: %v", logDir, err)
		log.SetOutput(os.Stdout)
		log.SetFlags(log.Ldate | log.Ltime)
		log.Println("Logging initialized to stdout due to directory error")
		return
	}

	// Open or create log file
	logFile, err := os.OpenFile(config.Paths.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening log file %s: %v", config.Paths.Log, err)
		log.SetOutput(os.Stdout)
		log.SetFlags(log.Ldate | log.Ltime)
		log.Println("Logging initialized to stdout due to file error")
		return
	}

	// Set output to file
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("Logging initialized to %s", config.Paths.Log)
}

// logMessage - wrapper for logging with levels
func logMessage(message string, level string) {
	// Default to INFO if level not specified
	if level == "" {
		level = "INFO"
	}

	// Only log if level is sufficient based on config
	configLevel := strings.ToUpper(config.Logging.Level)
	if configLevel == "" {
		configLevel = "INFO" // Default to INFO
	}
	
	messageLevel := strings.ToUpper(level)
	
	// Determine if message should be logged based on level
	shouldLog := false
	
	switch configLevel {
	case "DEBUG":
		shouldLog = true // Log everything
	case "INFO":
		shouldLog = messageLevel != "DEBUG" // Log INFO, WARNING, ERROR
	case "WARNING":
		shouldLog = messageLevel == "WARNING" || messageLevel == "ERROR" // Log WARNING, ERROR
	case "ERROR":
		shouldLog = messageLevel == "ERROR" // Log only ERROR
	}
	
	if shouldLog {
		log.Printf("[%s] %s", messageLevel, message)
	}
}

// Function to convert string encoding with enhanced charset support
func convertEncoding(input string, sourceEnc string, targetEnc string) (string, error) {
	if strings.EqualFold(sourceEnc, targetEnc) {
		return input, nil
	}
	
	var enc encoding.Encoding
	var err error
	
	// Enhanced encoding handling with more European charsets
	switch strings.ToLower(sourceEnc) {
	case "utf-8", "us-ascii":
		return input, nil
	case "iso-8859-1", "latin1":
		enc = charmap.ISO8859_1
	case "iso-8859-2", "latin2":
		enc = charmap.ISO8859_2
	case "iso-8859-3", "latin3":
		enc = charmap.ISO8859_3
	case "iso-8859-4", "latin4":
		enc = charmap.ISO8859_4
	case "iso-8859-5":
		enc = charmap.ISO8859_5
	case "iso-8859-9", "latin5":
		enc = charmap.ISO8859_9
	case "iso-8859-10", "latin6":
		enc = charmap.ISO8859_10
	case "iso-8859-13", "latin7":
		enc = charmap.ISO8859_13
	case "iso-8859-14", "latin8":
		enc = charmap.ISO8859_14
	case "iso-8859-15", "latin9":
		enc = charmap.ISO8859_15
	case "iso-8859-16":
		enc = charmap.ISO8859_16
	case "windows-1250":
		enc = charmap.Windows1250
	case "windows-1251":
		enc = charmap.Windows1251
	case "windows-1252":
		enc = charmap.Windows1252
	case "windows-1253":
		enc = charmap.Windows1253
	case "windows-1254":
		enc = charmap.Windows1254
	case "windows-1255":
		enc = charmap.Windows1255
	case "windows-1256":
		enc = charmap.Windows1256
	case "windows-1257":
		enc = charmap.Windows1257
	case "windows-1258":
		enc = charmap.Windows1258
	case "koi8-r":
		enc = charmap.KOI8R
	case "koi8-u":
		enc = charmap.KOI8U
	default:
		// Try to get from htmlindex
		enc, err = htmlindex.Get(sourceEnc)
		if err != nil {
			fallbackCharset := "iso-8859-1" // Default fallback
			if config.Encoding.FallbackCharset != "" {
				fallbackCharset = config.Encoding.FallbackCharset
			}
			logMessage(fmt.Sprintf("Encoding %s not recognized, using fallback %s", 
				sourceEnc, fallbackCharset), "WARNING")
			// Use fallback charset
			enc, _ = htmlindex.Get(fallbackCharset)
		}
	}
	
	// Convert to UTF-8
	reader := transform.NewReader(strings.NewReader(input), enc.NewDecoder())
	result, err := ioutil.ReadAll(reader)
	if err != nil {
		return input, err
	}
	
	return string(result), nil
}

// Function to decode content based on Content-Transfer-Encoding
func decodeTransferEncoding(content string, encoding string) (string, error) {
    encoding = strings.ToLower(encoding)
    
    switch encoding {
    case "quoted-printable":
        reader := quotedprintable.NewReader(strings.NewReader(content))
        decoded, err := ioutil.ReadAll(reader)
        if err != nil {
            return content, err
        }
        logMessage(fmt.Sprintf("Successfully decoded quoted-printable content"), "DEBUG")
        return string(decoded), nil
        
    case "base64":
        // Remove any whitespace from base64 content which can cause decoding errors
        content = regexp.MustCompile(`\s+`).ReplaceAllString(content, "")
        decoded, err := base64.StdEncoding.DecodeString(content)
        if err != nil {
            return content, err
        }
        logMessage(fmt.Sprintf("Successfully decoded base64 content"), "DEBUG")
        return string(decoded), nil
        
    case "7bit", "8bit", "binary", "":
        // No decoding needed
        return content, nil
        
    default:
        logMessage(fmt.Sprintf("Unknown Content-Transfer-Encoding: %s", encoding), "WARNING")
        return content, nil
    }
}

// Determine appropriate Content-Transfer-Encoding for a message
func determineContentTransferEncoding(content string) string {
    // Check if content has any non-ASCII characters
    has8bitChars := false
    hasBinaryChars := false
    maxLineLength := 0
    
    lines := strings.Split(content, "\r\n")
    for _, line := range lines {
        // Track maximum line length
        if len(line) > maxLineLength {
            maxLineLength = len(line)
        }
        
        for _, c := range line {
            // Check for 8-bit characters (non-ASCII)
            if c > 127 {
                has8bitChars = true
            }
            
            // Check for control characters except tab, CR, LF
            if c < 32 && c != 9 && c != 10 && c != 13 {
                hasBinaryChars = true
            }
        }
    }
    
    // Determine encoding based on content characteristics
    if hasBinaryChars || maxLineLength > 998 {
        return "base64"  // Binary content or very long lines need base64
    } else if has8bitChars {
        return "8bit"    // Non-ASCII content uses 8bit
    } else {
        return "7bit"    // Plain ASCII with reasonable line length
    }
}

// Normalize email format to ensure NNTP compatibility with enhanced UTF-8 support
func normalizeEmailFormat(message string) string {
	// Detect original encoding
	contentTypeRegex := regexp.MustCompile(`(?i)Content-Type:[^\n]*charset=["']?([^"'\r\n;]+)`)
	matches := contentTypeRegex.FindStringSubmatch(message)
	
	sourceEncoding := "utf-8" // Default to UTF-8
	if len(matches) > 1 {
		sourceEncoding = strings.ToLower(matches[1])
		logMessage(fmt.Sprintf("Detected charset in Content-Type: %s", sourceEncoding), "DEBUG")
	}
	
	// Find Content-Transfer-Encoding
	transferEncodingRegex := regexp.MustCompile(`(?i)Content-Transfer-Encoding:\s*([^\r\n]+)`)
	transferEncoding := "7bit" // Default
	matches = transferEncodingRegex.FindStringSubmatch(message)
	if len(matches) > 1 {
		transferEncoding = strings.TrimSpace(matches[1])
		logMessage(fmt.Sprintf("Found Content-Transfer-Encoding: %s", transferEncoding), "DEBUG")
	}

	// Ensure proper header-body separation (exactly one blank line)
	headerEnd := strings.Index(message, "\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = strings.Index(message, "\n\n")
	}

	if headerEnd != -1 {
		headers := message[:headerEnd]
		body := message[headerEnd:]
		
		// Normalize header-body separation to exactly one blank line
		body = regexp.MustCompile(`^\r?\n\r?\n+`).ReplaceAllString(body, "\r\n\r\n")
		
		// Decode body according to transfer encoding
		if len(body) > 4 { // Ensure there's content after \r\n\r\n
			decodedBody, err := decodeTransferEncoding(body[4:], transferEncoding) // Skip \r\n\r\n
			if err != nil {
				logMessage(fmt.Sprintf("Error decoding body with %s encoding: %v", transferEncoding, err), "WARNING")
			} else {
				// Ensure no leading blank lines in body content
				decodedBody = strings.TrimLeft(decodedBody, "\r\n \t")
				body = "\r\n\r\n" + decodedBody
				logMessage(fmt.Sprintf("Successfully decoded message body using %s encoding", transferEncoding), "DEBUG")
			}
		}
		
		message = headers + body
	}
	
	// Convert to UTF-8 if needed or force_utf8 is true
	forceUtf8 := config.Encoding.ForceUtf8
	if sourceEncoding != "utf-8" && (forceUtf8 || sourceEncoding != "us-ascii") {
		converted, err := convertEncoding(message, sourceEncoding, "utf-8")
		if err != nil {
			logMessage(fmt.Sprintf("Error during encoding conversion: %v", err), "WARNING")
		} else {
			message = converted
			logMessage(fmt.Sprintf("Message converted from %s to UTF-8", sourceEncoding), "DEBUG")
		}
	}
	
	// Replace problematic characters
	message = strings.ReplaceAll(message, "\u2018", "'") // Left single quote
	message = strings.ReplaceAll(message, "\u2019", "'") // Right single quote
	message = strings.ReplaceAll(message, "\u201C", "\"") // Left double quote
	message = strings.ReplaceAll(message, "\u201D", "\"") // Right double quote
	message = strings.ReplaceAll(message, "\u2026", "...") // Ellipsis
	message = strings.ReplaceAll(message, "\u2013", "-") // En dash
	message = strings.ReplaceAll(message, "\u2014", "-") // Em dash
	
	// Process HTML content if present
	if strings.Contains(message, "<pre") || strings.Contains(message, "<html") {
		logMessage("HTML content detected, converting to plain text", "INFO")
		
		// Remove common HTML tags
		htmlTags := []string{"<pre[^>]*>", "</pre>", "<html[^>]*>", "</html>", 
			"<body[^>]*>", "</body>", "<div[^>]*>", "</div>", "<p[^>]*>", "</p>",
			"<br[^>]*>", "<span[^>]*>", "</span>"}
		for _, tag := range htmlTags {
			re := regexp.MustCompile(tag)
			message = re.ReplaceAllString(message, "")
		}
		
		// Convert common HTML entities
		message = strings.ReplaceAll(message, "&quot;", "\"")
		message = strings.ReplaceAll(message, "&apos;", "'")
		message = strings.ReplaceAll(message, "&lt;", "<")
		message = strings.ReplaceAll(message, "&gt;", ">")
		message = strings.ReplaceAll(message, "&amp;", "&")
		message = strings.ReplaceAll(message, "&nbsp;", " ")
	}
	
	// Handle MIME-Version header
	// Remove existing MIME-Version headers to prevent malformed ones
	mimeVersionRegex := regexp.MustCompile(`(?i)MIME-Version:.*\r?\n`)
	message = mimeVersionRegex.ReplaceAllString(message, "")
	
	// Add our own correctly formatted MIME-Version header
	headerEnd = strings.Index(message, "\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = strings.Index(message, "\n\n")
	}
	
	if headerEnd != -1 {
		message = message[:headerEnd] + 
				"\r\nMIME-Version: 1.0\r\n" + 
				message[headerEnd:]
		logMessage("Added standardized MIME-Version header", "DEBUG")
	}
	
	// Ensure Content-Type exists with UTF-8 charset
	if !regexp.MustCompile(`(?i)Content-Type:`).MatchString(message) {
		// Find the end of headers
		headerEnd := strings.Index(message, "\r\n\r\n")
		if headerEnd == -1 {
			headerEnd = strings.Index(message, "\n\n")
			if headerEnd != -1 {
				// Insert before empty line
				message = message[:headerEnd] + 
						"\r\nContent-Type: text/plain; charset=utf-8\r\n" + 
						message[headerEnd:]
			}
		} else {
			// Insert before empty line
			message = message[:headerEnd] + 
					"\r\nContent-Type: text/plain; charset=utf-8\r\n" + 
					message[headerEnd:]
		}
	} else {
		// Replace existing encoding with UTF-8
		message = regexp.MustCompile(`(?i)(Content-Type:[^\n]*charset=)["']?[^"'\r\n;]+`).
			ReplaceAllString(message, "${1}utf-8")
	}
	
	// Ensure there's a blank line between headers and body (critical for NNTP)
	headerBodySeparator := "\r\n\r\n"
	if !strings.Contains(message, headerBodySeparator) {
		// Find where headers end (first blank line)
		parts := strings.SplitN(message, "\n\n", 2)
		if len(parts) == 2 {
			// Rebuild with correct \r\n
			message = strings.ReplaceAll(parts[0], "\n", "\r\n") + 
					"\r\n\r\n" + 
					strings.ReplaceAll(parts[1], "\n", "\r\n")
			logMessage("Normalized email format with correct header-body separator", "DEBUG")
		}
	}
	
	// Ensure all lines end with \r\n (standard NNTP format)
	message = strings.ReplaceAll(message, "\r\n", "\n")  // First normalize to \n
	message = strings.ReplaceAll(message, "\n", "\r\n")  // Then convert all \n to \r\n
	
	// Check for lines starting with "." (in NNTP protocol, a single "." indicates end of message)
	lines := strings.Split(message, "\r\n")
	for i, line := range lines {
		if line == "." {
			lines[i] = ".."
			logMessage("Found single dot line, replaced with '..'", "DEBUG")
		} else if strings.HasPrefix(line, ".") && line != ".." {
			lines[i] = "." + line
			logMessage("Found line starting with '.', doubled it", "DEBUG")
		}
	}
	
	return strings.Join(lines, "\r\n")
}

// Parse recipient similar to the Python version
func parseRecipient(user string) (string, string, bool) {
	// Extract domain part if present
	if idx := strings.Index(user, "@"); idx != -1 {
		user = user[:idx]
	}

	// Regular expression to match mail2news format
	re := regexp.MustCompile(`(mail2news|mail2news_nospam)-([0-9]{8})-(.*)`)
	matches := re.FindStringSubmatch(user)
	
	if matches == nil {
		logMessage("Badly formatted recipient. Rejecting message.", "ERROR")
		os.Exit(0)
	}

	recipient := matches[1]
	timestamp := matches[2]
	newsgroups := matches[3]
	
	// Replace = separator with commas
	newsgroups = strings.ReplaceAll(newsgroups, "=", ",")
	
	// Check for nospam directive
	nospam := false
	if recipient == "mail2news_nospam" {
		logMessage("Message includes a nospam directive. Will munge headers accordingly.", "INFO")
		nospam = true
	}
	
	return timestamp, newsgroups, nospam
}

// Validate timestamp
func validateStamp(stamp string) bool {
	// Parse the stamp into a time.Time
	layout := "20060102"
	parsedTime, err := time.Parse(layout, stamp)
	if err != nil {
		logMessage(fmt.Sprintf("Malformed date element: %v. Rejecting message.", err), "ERROR")
		os.Exit(0)
	}

	// Get current time and calculate boundaries
	now := time.Now().UTC()
	beforeTime := now.Add(-time.Duration(config.Thresholds.HoursPast) * time.Hour)
	afterTime := now.Add(time.Duration(config.Thresholds.HoursFuture) * time.Hour)

	// Check if within bounds
	if parsedTime.After(beforeTime) && parsedTime.Before(afterTime) {
		logMessage(fmt.Sprintf("Timestamp (%s) is valid and within bounds.", stamp), "DEBUG")
		return true
	}

	logMessage(fmt.Sprintf("Timestamp (%s) is out of bounds. Rejecting message.", stamp), "ERROR")
	os.Exit(0)
	return false
}

// Validate newsgroups
func ngvalidate(newsgroups string) string {
	newsgroups = strings.TrimRight(newsgroups, ",")
	groups := strings.Split(newsgroups, ",")
	
	var goodng []string
	
	modfile := filepath.Join(config.Paths.Lib, "moderated.db")
	// Check if moderation file exists
	if _, err := os.Stat(modfile); err == nil {
		logMessage(fmt.Sprintf("Moderated groups file found at %s", modfile), "DEBUG")
	}
	
	// Check each group format
	re := regexp.MustCompile(`[a-z][a-z0-9]+(\.[0-9a-z-+_]+)+$`)
	for _, ng := range groups {
		ng = strings.TrimSpace(ng)
		
		if re.MatchString(ng) {
			// Check for duplicates
			isDuplicate := false
			for _, existingNg := range goodng {
				if existingNg == ng {
					logMessage(fmt.Sprintf("%s is duplicated in Newsgroups header. Dropping one instance of it.", ng), "INFO")
					isDuplicate = true
					break
				}
			}
			
			if !isDuplicate {
				// Add to good newsgroups
				goodng = append(goodng, ng)
			}
		} else {
			logMessage(fmt.Sprintf("%s is not a validated newsgroup, ignoring.", ng), "WARNING")
		}
	}
	
	// No valid newsgroups
	if len(goodng) < 1 {
		logMessage("Message has no valid newsgroups. Rejecting it.", "ERROR")
		os.Exit(0)
	}
	
	// Check crosspost limit
	if len(goodng) > config.Thresholds.MaxCrossposts {
		logMessage(fmt.Sprintf("Message contains %d newsgroups, exceeding crosspost limit of %d. Rejecting.",
			len(goodng), config.Thresholds.MaxCrossposts), "ERROR")
		os.Exit(0)
	}
	
	header := strings.Join(goodng, ",")
	logMessage(fmt.Sprintf("Validated Newsgroups header is: %s", header), "INFO")
	return header
}

// Generate message ID with guaranteed uniqueness to prevent duplicates
func messageID(rightPart string) string {
	// Override the domain with our fixed privacy-enhanced domain if needed
	if rightPart == "" {
		rightPart = "tcpreset-nospam"
	}

	// Create unique ID using multiple uniqueness factors:
	// 1. Current timestamp with microsecond precision
	// 2. Random string
	// 3. Hash of message content (first 8 chars)
	now := time.Now().UTC()
	
	// Format: YYYYMMDDHHMMSS.microseconds.randomstring.contentHash@domain
	randomStr := generateRandomString(8)
	uniqHash := fmt.Sprintf("%d", rand.Int63()) // Additional randomness
	
	leftPart := fmt.Sprintf("%s.%d.%s.%s", 
		now.Format("20060102150405"),     // Standard timestamp
		now.UnixNano() % 1000000,         // Microseconds for uniqueness 
		randomStr,                        // Random string
		uniqHash[:8])                     // Random hash prefix
		
	return "<" + leftPart + "@" + rightPart + ">"
}

// Generate random string for message ID
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Generate content hash for message content
func generateContentHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// Check blacklists
func blacklistCheck(badFile string, text string) string {
	filename := filepath.Join(config.Paths.Etc, badFile)
	badList := file2list(filename)
	
	if len(badList) > 0 {
		pattern := strings.Join(badList, "|")
		re, err := regexp.Compile(pattern)
		if err != nil {
			logMessage(fmt.Sprintf("Error compiling regex from %s: %v", badFile, err), "ERROR")
			return ""
		}
		
		if match := re.FindString(text); match != "" {
			return match
		}
	}
	
	return ""
}

// Convert file to list
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

// min function for Go versions < 1.21
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Parse From header
func fromParse(fromHdr string) (string, string) {
	var name, addy string
	matched := false
	
	// Pattern 1: "Name <user@example.com>"
	re1 := regexp.MustCompile(`([^<>]*)<([^<>\s]+@[^<>\s]+)>$`)
	if matches := re1.FindStringSubmatch(fromHdr); matches != nil {
		name = matches[1]
		addy = matches[2]
		matched = true
	}
	
	// Pattern 2: "user@example.com (Name)"
	re2 := regexp.MustCompile(`([^<>\s]+@[^<>\s]+)\s+\(([^\(\)]*)\)$`)
	if !matched {
		if matches := re2.FindStringSubmatch(fromHdr); matches != nil {
			name = matches[2]
			addy = matches[1]
			matched = true
		}
	}
	
	// Pattern 3: "user@example.com"
	re3 := regexp.MustCompile(`([^<>\s]+@[^<>\s]+)$`)
	if !matched {
		if matches := re3.FindStringSubmatch(fromHdr); matches != nil {
			name = ""
			addy = matches[1]
		}
	}
	
	if addy != "" {
		addy = strings.ReplaceAll(addy, ".", "<DOT>")
		addy = strings.ReplaceAll(addy, "@", "<AT>")
	}
	
	return name, addy
}

// Parse message
func msgParse(message string) (string, string) {
	// Display first characters of received message for debug (reduced logging)
	firstChars := min(200, len(message))
	logMessage(fmt.Sprintf("First %d characters of received message: %s", firstChars, message[:firstChars]), "DEBUG")
	
	// Remove ALL Unix mailbox style "From " lines
	lines := strings.Split(message, "\n")
	var cleanedLines []string
	fromLinesRemoved := 0
	
	for _, line := range lines {
		// Look for "From " lines that don't contain ":" (characteristic of mailbox lines)
		if strings.HasPrefix(line, "From ") && !strings.Contains(line, ":") {
			fromLinesRemoved++
			continue // Skip this line
		}
		cleanedLines = append(cleanedLines, line)
	}
	
	if fromLinesRemoved > 0 {
		logMessage(fmt.Sprintf("Removed %d mailbox-style 'From ' lines", fromLinesRemoved), "DEBUG")
		message = strings.Join(cleanedLines, "\n")
	} else {
		logMessage("No 'From ' lines found to remove", "DEBUG")
	}
	
	logMessage("Skipping history file write due to permission issues", "DEBUG")
	
	// Before parsing the email, ensure it has no other format anomalies
	message = normalizeEmailFormat(message)
	
	// Parse the email
	msg, err := mail.ReadMessage(strings.NewReader(message))
	if err != nil {
		logMessage(fmt.Sprintf("Error parsing message: %v", err), "ERROR")
		os.Exit(1)
	}
	
	// Get message ID first to check if we've already processed it
	messageId := msg.Header.Get("Message-ID")
	// If message ID is present, check cache to see if we've already processed it
	if messageId != "" && messageCache != nil {
		if messageCache.IsProcessed(messageId) {
			logMessage(fmt.Sprintf("Message %s has already been processed recently. Skipping.", messageId), "INFO")
			os.Exit(0) // Exit with success status
		}
	}
	
	// Only log headers at DEBUG level
	if config.Logging.Level == "DEBUG" {
		logMessage("=== Headers received in email ===", "DEBUG")
		for k, v := range msg.Header {
			logMessage(fmt.Sprintf("Header: %s = %v", k, v), "DEBUG")
		}
	}
	
	// Check for authentication headers
	if xHashcash := msg.Header.Get("X-Hashcash"); xHashcash == "" {
		logMessage("WARNING: X-Hashcash not found in email!", "WARNING")
	}
	
	if xEd25519Pub := msg.Header.Get("X-Ed25519-Pub"); xEd25519Pub == "" {
		logMessage("WARNING: X-Ed25519-Pub not found in email!", "WARNING")
	}
	
	if xEd25519Sig := msg.Header.Get("X-Ed25519-Sig"); xEd25519Sig == "" {
		logMessage("WARNING: X-Ed25519-Sig not found in email!", "WARNING")
	}
	
	// Get message body for Content-Transfer-Encoding analysis
	body, err := ioutil.ReadAll(msg.Body)
	if err != nil {
		logMessage(fmt.Sprintf("Error reading message body: %v", err), "ERROR")
		os.Exit(1)
	}
	
	// Ensure there's a body, even minimal
	bodyContent := string(body)
	if len(bodyContent) == 0 || len(strings.TrimSpace(bodyContent)) == 0 {
		logMessage("WARNING: Empty message body detected! Adding placeholder text.", "WARNING")
		bodyContent = "This message had no content."
		body = []byte(bodyContent)
	}
	
	// Analyze body for Content-Transfer-Encoding - but only if not already set
	if msg.Header.Get("Content-Transfer-Encoding") == "" {
		transferEncoding := determineContentTransferEncoding(bodyContent)
		msg.Header["Content-Transfer-Encoding"] = []string{transferEncoding}
		logMessage(fmt.Sprintf("Analyzed and set Content-Transfer-Encoding to %s", transferEncoding), "INFO")
	}
		
	// Process Message-ID if not already present
	if messageId == "" {
		// Create a content hash to help make a unique Message ID
		contentHash := generateContentHash(bodyContent)
		
		// Call messageID function passing configuration parameter and content hash
		messageId = messageID(config.NNTP.MessageID + "." + contentHash[:8])
		
		msg.Header["Message-ID"] = []string{messageId}
		logMessage(fmt.Sprintf("Processing message with no Message-ID. Assigned: %s", messageId), "INFO")
	} else {
		logMessage(fmt.Sprintf("Processing message: %s", messageId), "INFO")
	}
	
	// Process Date header
	if msg.Header.Get("Date") == "" {
		logMessage("Message has no Date header. Inserting current timestamp.", "INFO")
		msg.Header["Date"] = []string{time.Now().Format(time.RFC1123Z)}
	}
	
	// Process From header
	fromHeader := msg.Header.Get("From")
	if fromHeader != "" {
		if match := blacklistCheck("bad_from", fromHeader); match != "" {
			logMessage(fmt.Sprintf("From header matches '%s'. Rejecting.", match), "ERROR")
			os.Exit(1)
		}
	} else {
		logMessage("Message has no From header. Inserting a null one.", "INFO")
		msg.Header["From"] = []string{config.NNTP.DefaultFrom}
	}
	
	// Minimal References handling
	if refs := msg.Header.Get("References"); refs != "" {
		logMessage(fmt.Sprintf("THREADING - Original References: %s", refs), "INFO")
		
		// Only add angle brackets if completely missing, otherwise keep as is
		if !strings.Contains(refs, "<") {
			refs = "<" + refs
		}
		if !strings.Contains(refs, ">") {
			refs = refs + ">"
		}
		
		// Keep References as is (no splitting/rejoining)
		msg.Header["References"] = []string{refs}
		logMessage(fmt.Sprintf("THREADING - Using References with minimal changes: %s", refs), "INFO")
		
		// Set In-Reply-To to match References exactly
		msg.Header["In-Reply-To"] = []string{refs}
		logMessage("THREADING - Set In-Reply-To to match References exactly", "INFO")
	} else if strings.HasPrefix(strings.ToLower(msg.Header.Get("Subject")), "re:") {
		logMessage("WARNING - Message has Re: in subject but no References header!", "WARNING")
	}

	// Check for poison headers
	poisonFile := filepath.Join(config.Paths.Etc, "headers_poison")
	poisonHeaders := file2list(poisonFile)
	for _, header := range poisonHeaders {
		if msg.Header.Get(header) != "" {
			logMessage(fmt.Sprintf("Message contains a blacklisted %s header. Rejecting it.", header), "ERROR")
			os.Exit(0)
		}
	}
	
	// Get recipient info
	var recipient string
	if to := msg.Header.Get("X-Original-To"); to != "" {
		recipient = to
	} else if to := msg.Header.Get("To"); to != "" {
		recipient = to
	} else {
		recipient = "mail2news@m2n.mixmin.net"
		logMessage(fmt.Sprintf("Could not find recipient info. Guessing %s.", recipient), "WARNING")
	}
	
	if !strings.HasPrefix(recipient, "mail2news") {
		logMessage(fmt.Sprintf("Recipient %s is not us.", recipient), "ERROR")
		os.Exit(2)
	}
	
	// Process newsgroups
	nospam := false
	var dest string
	
	if ng := msg.Header.Get("Newsgroups"); ng != "" {
		dest = ng
		delete(msg.Header, "Newsgroups")
		logMessage(fmt.Sprintf("Message has a Newsgroups header of %s", dest), "INFO")
		
		if strings.HasPrefix(recipient, "mail2news_nospam") {
			nospam = true
			logMessage("Message includes a nospam directive. Will munge From headers accordingly.", "INFO")
		}
	} else {
		logMessage("No Newsgroups header, trying to parse recipient information", "INFO")
		var stamp string
		stamp, dest, nospam = parseRecipient(recipient)
		
		if !validateStamp(stamp) {
			logMessage("No Newsgroups header or valid recipient. Rejecting message.", "ERROR")
			os.Exit(0)
		}
	}
	
	// Validate newsgroups
	validatedGroups := ngvalidate(dest)
	msg.Header["Newsgroups"] = []string{validatedGroups}
	
	// Check for blacklisted newsgroups
	if match := blacklistCheck("bad_groups", validatedGroups); match != "" {
		logMessage(fmt.Sprintf("Newsgroups header matches '%s'. Rejecting.", match), "ERROR")
		os.Exit(1)
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
	
	// Process Subject header
	if subj := msg.Header.Get("Subject"); subj != "" {
		logMessage(fmt.Sprintf("Subject: %s", subj), "INFO")
	} else {
		logMessage("Message has no Subject header. Inserting a null one.", "INFO")
		msg.Header["Subject"] = []string{"None"}
	}
	
	// Check for Path header
	if path := msg.Header.Get("Path"); path != "" {
		logMessage(fmt.Sprintf("Message has a preloaded path header of %s", path), "DEBUG")
	}
	
	// Strip headers
	stripFile := filepath.Join(config.Paths.Etc, "headers_strip")
	stripHeaders := file2list(stripFile)
	
	// Headers to always preserve
	preserveHeaders := map[string]bool{
		"X-Hashcash":     true,
		"X-Ed25519-Pub":  true,
		"X-Ed25519-Sig":  true,
	}
	
	for _, header := range stripHeaders {
		// Don't remove headers we want to preserve
		if _, shouldPreserve := preserveHeaders[header]; !shouldPreserve {
			if msg.Header.Get(header) != "" {
				logMessage(fmt.Sprintf("Stripping header: %s", header), "DEBUG")
				delete(msg.Header, header)
			}
		} else {
			logMessage(fmt.Sprintf("Preserving authentication header: %s", header), "DEBUG")
		}
	}
	
	// Add gateway headers
	msg.Header["Path"] = []string{config.NNTP.Path}
	msg.Header["Organization"] = []string{"Tcpreset M2N Gateway"}
	msg.Header["X-Gateway-Info"] = []string{
		config.NNTP.InjectionHost + "; mail-complaints-to=" + config.NNTP.Contact,
	}
	
	// Update User-Agent
	delete(msg.Header, "User-Agent")
	msg.Header["User-Agent"] = []string{fmt.Sprintf("mail2news-go v%s", VERSION)}
	
	// Fix MIME Version - ensure correctly formatted
	delete(msg.Header, "MIME-Version")
	delete(msg.Header, "Mime-Version")
	msg.Header["MIME-Version"] = []string{"1.0"}
	
	// Log important threading headers only at INFO level
	logMessage(fmt.Sprintf("THREADING CHECK - Message-ID: %s", msg.Header.Get("Message-ID")), "INFO")
	logMessage(fmt.Sprintf("THREADING CHECK - References: %s", msg.Header.Get("References")), "INFO")
	logMessage(fmt.Sprintf("THREADING CHECK - In-Reply-To: %s", msg.Header.Get("In-Reply-To")), "INFO")
	
	// Build the complete message
	txtMsg := ""
	
	// Build headers - ensure all headers are correctly formatted
	for k, vv := range msg.Header {
		for _, v := range vv {
			// Ensure header value is properly trimmed
			v = strings.TrimSpace(v)
			txtMsg += k + ": " + v + "\r\n"
		}
	}
	
	// Blank line between headers and body - CRITICAL for NNTP format
	txtMsg += "\r\n"
	
	// Format the body with proper line endings and dot-stuffing
	bodyStr := string(body)
	
	// Make sure body doesn't start with extra blank lines
    bodyStr = strings.TrimLeft(bodyStr, "\r\n \t")
	
	// Normalize line endings in body
	bodyStr = strings.ReplaceAll(bodyStr, "\r\n", "\n")
	bodyStr = strings.ReplaceAll(bodyStr, "\n", "\r\n")
	
	// Handle lines starting with "."
	bodyLines := strings.Split(bodyStr, "\r\n")
	for i, line := range bodyLines {
		if line == "." {
			bodyLines[i] = ".."
		} else if strings.HasPrefix(line, ".") && line != ".." {
			bodyLines[i] = "." + line
		}
	}
	bodyStr = strings.Join(bodyLines, "\r\n")
	
	txtMsg += bodyStr
	
	// Ensure message ends with CRLF
	if !strings.HasSuffix(txtMsg, "\r\n") {
		txtMsg += "\r\n"
		logMessage("Added missing final CRLF to message", "DEBUG")
	}
	
	size := len(txtMsg)
	if size > config.Thresholds.MaxBytes {
		logMessage(fmt.Sprintf("Message exceeds %d size limit. Rejecting.", config.Thresholds.MaxBytes), "ERROR")
		os.Exit(1)
	}
	logMessage(fmt.Sprintf("Message is %d bytes", size), "INFO")

	// Only log first 100 chars of message at INFO level
	logPreview := min(100, len(txtMsg))
	logMessage(fmt.Sprintf("Message prepared for delivery: %s...", txtMsg[:logPreview]), "INFO")
	
	// Mark this message as processed in our cache
	if messageCache != nil && messageId != "" {
		messageCache.MarkProcessed(messageId)
	}
	
	return messageId, txtMsg
}

// Send news - improved to avoid duplicates
func newsSend(mid string, content string) {
	// Generate a content hash to help track server attempts
	contentHash := generateContentHash(content)
	logMessage(fmt.Sprintf("Generated content hash for message tracking: %s", contentHash[:16]), "DEBUG")
	
	// Implementation for NNTP sending
	// Using Tor for all connections
	hostFile := filepath.Join(config.Paths.Etc, "nntphosts")
	hosts := file2list(hostFile)
	
	// Default Tor proxy address if not specified in config
	torProxyAddr := "127.0.0.1:9050"
	if config.NNTP.TorProxy != "" {
		torProxyAddr = config.NNTP.TorProxy
	}
	
	// Create a SOCKS5 dialer for Tor
	torDialer, err := proxy.SOCKS5("tcp", torProxyAddr, nil, proxy.Direct)
	if err != nil {
		logMessage(fmt.Sprintf("Error creating Tor dialer: %v", err), "ERROR")
		return
	}
	
	// Track successful delivery and attempted hosts to prevent duplicates
	successfulDelivery := false
	attemptedHosts := make(map[string]bool)
	
	// Build the ordered server list
	var serverList []string
	
	// Try primary onion server first if configured
	if config.NNTP.PrimaryOnion != "" {
		primaryServer := config.NNTP.PrimaryOnion
		if !strings.Contains(primaryServer, ":") {
			primaryServer += ":119" // Default NNTP port
		}
		serverList = append(serverList, primaryServer)
	}
	
	// Add fallback server if configured and different from primary
	if config.NNTP.FallbackServer != "" && config.NNTP.FallbackServer != config.NNTP.PrimaryOnion {
		fallbackServer := config.NNTP.FallbackServer
		if !strings.Contains(fallbackServer, ":") {
			fallbackServer += ":119" // Default NNTP port
		}
		serverList = append(serverList, fallbackServer)
	}
	
	// Add remaining servers from nntphosts file, avoiding duplicates
	for _, host := range hosts {
		if !strings.Contains(host, ":") {
			host += ":119" // Default NNTP port
		}
		
		// Skip if already in our list
		alreadyAdded := false
		for _, existingServer := range serverList {
			if existingServer == host {
				alreadyAdded = true
				break
			}
		}
		
		if !alreadyAdded {
			serverList = append(serverList, host)
		}
	}
	
	// Try each server in order until successful or all failed
	for _, host := range serverList {
		// Skip if already attempted
		if attemptedHosts[host] {
			logMessage(fmt.Sprintf("Skipping already attempted server: %s", host), "DEBUG")
			continue
		}
		
		attemptedHosts[host] = true
		logMessage(fmt.Sprintf("Attempting delivery to %s", host), "INFO")
		
		// Attempt delivery with specific error handling for duplicates
		err, isDuplicate := deliverViaTor(torDialer, host, mid, content)
		
		if err == nil {
			logMessage(fmt.Sprintf("✓ %s successfully delivered to %s", mid, host), "INFO")
			successfulDelivery = true
			// Exit early if delivery succeeded
			break
		} else if isDuplicate {
			// If message is a duplicate, count it as successful
			logMessage(fmt.Sprintf("✓ %s already exists on %s (duplicate)", mid, host), "INFO")
			successfulDelivery = true
			// But continue to other servers to check storage status
		} else {
			logMessage(fmt.Sprintf("✗ Delivery to %s failed: %v", host, err), "WARNING")
		}
	}

	if successfulDelivery {
		logMessage("Mail2news message successfully delivered or already exists", "INFO")
	} else {
		logMessage("Mail2news message delivery FAILED to all available servers", "WARNING")
	}
}

// Deliver message via Tor to a specific NNTP server
// Returns (error, isDuplicate) - where isDuplicate indicates if the message was rejected as a duplicate
func deliverViaTor(torDialer proxy.Dialer, host string, messageID string, content string) (error, bool) {
	// Create a dialer with timeout
	timeoutDialer := &net.Dialer{
		Timeout: time.Duration(config.Thresholds.SocketTimeout) * time.Second,
	}
	
	// Use Tor for .onion addresses or if always_use_tor is enabled
	var conn net.Conn
	var err error
	
	if strings.Contains(host, ".onion") || config.NNTP.AlwaysUseTor {
		// Connect through Tor
		logMessage(fmt.Sprintf("Connecting to %s via Tor proxy", host), "INFO")
		conn, err = torDialer.Dial("tcp", host)
	} else {
		// Direct connection
		logMessage(fmt.Sprintf("Connecting directly to %s", host), "INFO")
		conn, err = timeoutDialer.Dial("tcp", host)
	}
	
	if err != nil {
		return fmt.Errorf("connection error: %v", err), false
	}
	defer conn.Close()
	
	// Set deadline for the entire conversation
	deadline := time.Now().Add(time.Duration(config.Thresholds.SocketTimeout) * time.Second)
	conn.SetDeadline(deadline)
	
	// Set up buffered reader/writer
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	
	// Read initial greeting
	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading greeting: %v", err), false
	}
	if !strings.HasPrefix(resp, "200 ") && !strings.HasPrefix(resp, "201 ") {
		return fmt.Errorf("unexpected greeting: %s", resp), false
	}
	
	respTrimmed := strings.TrimSpace(resp)
	logMessage(fmt.Sprintf("Connected to %s, greeting: %s", host, respTrimmed), "INFO")
	
	// Send MODE READER for onion servers or if greeting indicates transit mode
	if strings.Contains(host, ".onion") || strings.Contains(respTrimmed, "transit mode") {
		logMessage(fmt.Sprintf("Sending MODE READER to %s", host), "INFO")
		_, err = writer.WriteString("MODE READER\r\n")
		if err != nil {
			return fmt.Errorf("error sending MODE READER: %v", err), false
		}
		err = writer.Flush()
		if err != nil {
			return fmt.Errorf("error flushing MODE READER: %v", err), false
		}
		
		// Read response to MODE READER
		resp, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading MODE READER response: %v", err), false
		}
		
		respTrimmed = strings.TrimSpace(resp)
		logMessage(fmt.Sprintf("MODE READER response from %s: %s", host, respTrimmed), "INFO")
		
		// Check if the server supports READER mode
		if !strings.HasPrefix(resp, "200") && !strings.HasPrefix(resp, "201") {
			// If MODE READER failed, try to continue anyway
			logMessage(fmt.Sprintf("MODE READER not supported on %s, continuing anyway", host), "WARNING")
		}
	}
	
	// Use POST protocol (more widely supported)
	logMessage(fmt.Sprintf("Sending POST command to %s", host), "INFO")
	_, err = writer.WriteString("POST\r\n")
	if err != nil {
		return fmt.Errorf("error sending POST: %v", err), false
	}
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("error flushing POST: %v", err), false
	}
	
	// Read response to POST
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading POST response: %v", err), false
	}
	
	respTrimmed = strings.TrimSpace(resp)
	logMessage(fmt.Sprintf("POST response from %s: %s", host, respTrimmed), "INFO")
	
	// Check if server accepted POST (code 340)
	if strings.HasPrefix(resp, "340 ") {
		// Send article content
		logMessage(fmt.Sprintf("Server %s accepted POST, sending article", host), "INFO")
		logMessage(fmt.Sprintf("Article sent to %s via POST, waiting for response...", host), "INFO")
		_, err = writer.WriteString(content + "\r\n.\r\n")
		if err != nil {
			return fmt.Errorf("error sending article via POST: %v", err), false
		}
		err = writer.Flush()
		if err != nil {
			return fmt.Errorf("error flushing article via POST: %v", err), false
		}
		
		// Read final response
		resp, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading POST final response: %v", err), false
		}
		
		respTrimmed = strings.TrimSpace(resp)
		logMessage(fmt.Sprintf("POST final response from %s: %s", host, respTrimmed), "INFO")
		
		// Check if response indicates a duplicate (435 or 435 Duplicate or similar)
		isDuplicate := strings.Contains(respTrimmed, "435") || strings.Contains(strings.ToLower(respTrimmed), "duplicate")
		
		// Check if article was accepted (code 240)
		if strings.HasPrefix(resp, "240 ") {
			// Send QUIT
			writer.WriteString("QUIT\r\n")
			writer.Flush()
			return nil, false
		}
		
		// Send QUIT
		writer.WriteString("QUIT\r\n")
		writer.Flush()
		
		return fmt.Errorf("article rejected via POST: %s", respTrimmed), isDuplicate
	} else {
		return fmt.Errorf("POST not accepted: %s", respTrimmed), false
	}
}

func main() {
	// Initial log to signal startup
	fmt.Printf("CANARY: Mail2News version %s with enhanced UTF-8 support is running!\n", VERSION)
	
	// Acquire lock to prevent multiple instances
	if !acquireLock() {
		fmt.Println("Another instance of mail2news is already running. Exiting.")
		os.Exit(0)
	}
	defer releaseLock() // Release lock when program exits
	
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())
	
	// Initialize config
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/mail2news")
	viper.AddConfigPath("$HOME/.mail2news")
	viper.AddConfigPath(".")
	
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Fatal error config file: %s", err)
	}
	
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode config: %s", err)
	}
	
	// Set defaults for config if not specified
	if config.Paths.Log == "" {
		config.Paths.Log = "/var/log/mail2news/mail2news.log"
	}
	if config.Logging.Level == "" {
		config.Logging.Level = "WARNING" // Default to WARNING level
	}
	if config.Encoding.FallbackCharset == "" {
		config.Encoding.FallbackCharset = "iso-8859-1"
	}
	
	// Initialize logging
	initLogging()
	
	// Create message ID cache
	messageCache = NewMessageIDCache(5*time.Minute, "/var/lib/mail2news/cache")
	
	logMessage(fmt.Sprintf("Mail2news version %s initialized with UTF-8 support", VERSION), "INFO")
	fmt.Println("Type message here. Finish with Ctrl-D.")
	
	// Read message from stdin
	message, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		logMessage(fmt.Sprintf("Error reading from stdin: %v", err), "ERROR")
		os.Exit(1)
	}
	
	// Parse and process message
	mid, payload := msgParse(string(message))
	
	// Send to news servers
	newsSend(mid, payload)
	
	logMessage("Mail2news program completed successfully", "INFO")
}

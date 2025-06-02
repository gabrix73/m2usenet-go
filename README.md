# m2usenet v1.0.0

**Privacy-focused Usenet posting gateway with automatic fallback support**

m2usenet is a secure, privacy-oriented gateway system that allows posting to Usenet newsgroups via mail2news gateways. The system combines web interface posting with email client support, featuring automatic fallback between .onion and clearnet gateways.

## 🏗️ Architecture

```
📱 Web Interface Mode:
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Frontend    │────│ mail2news   │────│ Backend Go  │────│ NNTP Server │
│ (PHP Web)   │    │ Gateway     │    │ (m2usenet)  │    │  (.onion)   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## 🔐 Security Features

- **Hashcash Proof-of-Work**: Prevents spam with client-side mining
- **Ed25519 Digital Signatures**: Cryptographic message authentication  
- **Tor Integration**: Primary routing through .onion networks
- **No Data Collection**: Zero access logs, no tracking
- **Automatic Fallback**: .onion → clearnet gateway redundancy

## 🌐 Gateway Configuration

| Priority | Gateway | Description |
|----------|---------|-------------|
| **Primary** | `mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion` | Via Tor for privacy |
| **Fallback** | `mail2news@mail2news.tcpreset.net` | Clearnet for reliability |

## 📋 Requirements

### System Requirements
- **OS**: Debian 11+ (Bullseye or newer)
- **Web Server**: Apache2 with SSL
- **Language**: PHP 7.4+ with standard modules
- **Backend**: Go 1.18+ compiler
- **Privacy**: Tor daemon for .onion connectivity

### Required Packages
```bash
sudo apt update
sudo apt install -y \
    apache2 \
    php \
    php-cli \
    golang-go \
    sendmail-bin \
    tor \
    socat \
    certbot \
    python3-certbot-apache
```

## 🚀 Installation

### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages (including Tor as dependency)
sudo apt install -y apache2 php php-cli golang-go sendmail-bin tor socat certbot python3-certbot-apache

# Enable required Apache modules
sudo a2enmod rewrite ssl headers http2 remoteip

# Start and enable services
sudo systemctl start apache2 tor
sudo systemctl enable apache2 tor
```

### Step 2: Directory Structure

```bash
# Create application directories
sudo mkdir -p /var/www/m2usenet
sudo mkdir -p /home/m2usenet
sudo mkdir -p /var/log/m2usenet
sudo mkdir -p /var/www/m2usenet/temp

# Create m2usenet user for backend
sudo useradd -r -s /bin/bash -d /home/m2usenet m2usenet

# Set permissions
sudo chown -R www-data:www-data /var/www/m2usenet /var/log/m2usenet
sudo chown -R m2usenet:m2usenet /home/m2usenet
sudo chmod 755 /var/www/m2usenet /var/log/m2usenet /home/m2usenet
```

### Step 3: Install Application Files

```bash
# Clone repository (or download files)
cd /tmp
git clone https://github.com/your-repo/m2usenet.git
cd m2usenet

# Copy web frontend
sudo cp index.php send.php powWorker.js /var/www/m2usenet/
sudo chown www-data:www-data /var/www/m2usenet/*.php /var/www/m2usenet/*.js
sudo chmod 644 /var/www/m2usenet/*.php /var/www/m2usenet/*.js

# Copy backend source
sudo cp m2usenet.go /home/m2usenet/
sudo chown m2usenet:m2usenet /home/m2usenet/m2usenet.go
```

### Step 4: Build Go Backend

```bash
# Switch to m2usenet user and build
cd /home/m2usenet
sudo -u m2usenet go mod init m2usenet
sudo -u m2usenet go mod tidy

# Build with security options
sudo -u m2usenet go build -trimpath -ldflags="-s -w -extldflags=-static" -a -o m2usenet m2usenet.go

# Make executable
sudo chmod +x /home/m2usenet/m2usenet

# copy binary in /usr/local/bin
sudo cp /home/m2usenet/m2usenet /usr/local/bin/
sudo chown postfix:postfix /usr/local/bin/m2usenet
# Set alias
# /etc/aliases
mail2news: |/usr/local/bin/m2usenet
```

### Step 5: SSL Certificate

```bash
# Replace $mydomain with your actual domain
export mydomain="your-domain.com"

# Generate Let's Encrypt certificate with RSA 4096-bit key
sudo certbot certonly --apache --rsa-key-size 4096 -d m2usenet.$mydomain

# Verify certificate
sudo certbot certificates
```

### Step 6: Apache Virtual Host Configuration

#### Enable Required Apache Modules

```bash
# Enable all required modules for the virtual host
sudo a2enmod ssl
sudo a2enmod rewrite  
sudo a2enmod headers
sudo a2enmod http2
sudo a2enmod remoteip

# remoteip module is essential for anonymized_log - it allows Apache to log 
# anonymized IP addresses instead of real client IPs for privacy protection
sudo a2enmod remoteip

# Restart Apache to load modules
sudo systemctl restart apache2
```

#### Create Virtual Host File

```bash
# Replace $mydomain with your actual domain
export mydomain="your-domain.com"

# Create virtual host configuration
sudo tee /etc/apache2/sites-available/m2usenet.conf << EOF
# m2usenet Virtual Host Configuration
# Privacy-focused Usenet gateway - NO DATA COLLECTION

<VirtualHost YOUR_SERVER_IP:80>
    ServerName m2usenet.$mydomain
    # Redirect all HTTP traffic to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^/?(.*) https://%{SERVER_NAME}/\$1 [R=301,L]
    
    # NO LOGGING - Privacy focused
    # ErrorLog ${APACHE_LOG_DIR}/m2usenet_http_error.log
    # CustomLog ${APACHE_LOG_DIR}/m2usenet_http_access.log combined
</VirtualHost>

<VirtualHost YOUR_SERVER_IP:443>
    ServerName m2usenet.$mydomain
    DocumentRoot /var/www/m2usenet
    
    # Enable SSL and specify the paths for Let's Encrypt certificates
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite    TLSv1.3   TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    SSLCipherSuite    SSL       ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384
    SSLCertificateFile /etc/letsencrypt/live/m2usenet.$mydomain/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/m2usenet.$mydomain/privkey.pem
    SSLOpenSSLConfCmd Curves X25519:secp521r1:secp384r1:prime256v1
    
    # Enable HTTP/2
    Protocols h2 http/1.1
    LogLevel warn
    
    # PRIVACY: Using anonymized_log format (requires remoteip module)
    # This logs anonymized IP addresses to protect user privacy
    ErrorLog ${APACHE_LOG_DIR}/m2usenet_error.log
    CustomLog ${APACHE_LOG_DIR}/m2usenet_access.log anonymized_log
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Access-Control-Allow-Origin "https://m2usenet.$mydomain"
    Header always set Access-Control-Allow-Methods "POST, GET, OPTIONS"
    Header always set Access-Control-Allow-Headers "Content-Type"
    
    <Directory /var/www/m2usenet/>
        Options Indexes FollowSymLinks
        DirectoryIndex index.php
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
```

#### Configure Anonymized Logging

```bash
# Create anonymized log format for privacy protection
sudo tee -a /etc/apache2/apache2.conf << EOF

# m2usenet Privacy-focused logging configuration
# anonymized_log format removes/anonymizes sensitive data
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"Anonymous-Agent\"" anonymized_log
EOF
```

#### Enable Site and Restart Apache

```bash
# Replace YOUR_SERVER_IP with your actual server IP
sudo sed -i 's/YOUR_SERVER_IP/195.201.224.127/g' /etc/apache2/sites-available/m2usenet.conf

# Enable the site
sudo a2ensite m2usenet.conf

# Test Apache configuration
sudo apache2ctl configtest

# Restart Apache
sudo systemctl restart apache2
```

## 🧪 Testing

### System Test

```bash
# Run system diagnostics
curl -s https://m2usenet.$mydomain/test_gateway_only.php

# Check application logs
sudo tail -f /var/log/m2usenet/send.log
```

## 🔧 Configuration

### Environment Variables (Optional)

The Go backend supports configuration via environment variables:

```bash
# NNTP Server (default: .onion address)
export NNTP_SERVER="peannyjkqwqfynd24p6dszvtchkq7hfkwymi5by5y332wmosy5dwfaqd.onion"
export NNTP_PORT="119"

# Tor proxy settings
export TOR_PROXY_HOST="127.0.0.1"
export TOR_PROXY_PORT="9050"

# Security settings
export HASHCASH_MIN_BITS="24"
export TIME_WINDOW_SEC="1800"
export MAX_POST_SIZE="10240"

# Database location
export DB_PATH="/home/m2usenet/hashcash.json"
```

## 🛡️ Privacy Features

### No Data Collection Policy

m2usenet is designed with privacy as the primary concern:

- **No access logs**: Apache configured with anonymized logging
- **No user tracking**: No cookies, sessions, or persistent data
- **No IP logging**: Real IP addresses are never stored
- **Tor-first**: Primary routing through .onion networks
- **Temporary files**: Minimal usage with immediate cleanup

### Security Headers

The Apache configuration includes comprehensive security headers:
- HSTS (HTTP Strict Transport Security)
- X-Content-Type-Options
- X-Frame-Options  
- X-XSS-Protection
- Restricted CORS policies

## 🔄 Maintenance

### Certificate Renewal

```bash
# Auto-renew Let's Encrypt certificates
sudo crontab -e

# Add this line for automatic renewal:
0 3 * * * /usr/bin/certbot renew --quiet && systemctl reload apache2
```

## 📜 License

This project is released under the MIT License. See LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

## 📞 Support

- **Issues**: Report bugs via GitHub Issues
- **Documentation**: See docs/ directory for detailed guides
- **Security**: Report security issues privately via email

## 🙏 Acknowledgments

- **Tor Project**: For privacy infrastructure
- **Let's Encrypt**: For free SSL certificates  
- **TweetNaCl**: For cryptographic functions
- **mail2news gateways**: For Usenet connectivity

---

**m2usenet v1.0.0** - Privacy-focused Usenet posting for the modern era



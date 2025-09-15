# Network Traffic Analysis - Quick Reference

## 🚀 Essential Commands

### Network Analysis Tool Usage
```bash
# Connection monitoring
python src/analyzer/network_cli.py --monitor-connections --educational

# Service discovery
python src/analyzer/network_cli.py --scan-services localhost --educational

# Traffic capture and analysis
python src/analyzer/network_cli.py --capture-traffic --duration 60 --educational

# DNS traffic analysis
python src/analyzer/network_cli.py --dns-analysis --duration 30 --educational

# Demonstration mode
python src/analyzer/network_cli.py --demo-network --educational
```

### System Network Tools
```bash
# Display active connections
netstat -tuln                    # Traditional network statistics
ss -tuln                        # Modern socket statistics
ss -tuln | grep LISTEN         # Show only listening services

# Network connectivity testing
ping -c 5 google.com            # Test connectivity
nslookup google.com             # DNS resolution test
dig @8.8.8.8 stackoverflow.com  # DNS query with specific server

# Basic port scanning (if nmap available)
nmap -sT localhost              # TCP connect scan
nmap -sU localhost              # UDP scan
```

### Report Generation
```bash
# JSON reports for automation
python src/analyzer/network_cli.py --monitor-connections --format json --output network_report.json

# Text reports for human reading
python src/analyzer/network_cli.py --scan-services localhost --format text --output service_scan.txt

# Automatic timestamped reports
python src/analyzer/network_cli.py --capture-traffic --educational
# Saves to: reports/network_traffic_capture_YYYYMMDD_HHMMSS.txt
```

## 🔍 Analysis Patterns

### Connection Analysis
```bash
# Find suspicious ports
netstat -tuln | grep -E ":4444|:6666|:1337|:31337|:8080"

# Check external connections
netstat -tuln | grep -v "127.0.0.1\|::1"

# Count connections by IP
netstat -tuln | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr

# Find listening services
netstat -tuln | grep LISTEN | sort
```

### Service Discovery
```bash
# Common service ports
netstat -tuln | grep -E ":21|:22|:23|:25|:53|:80|:110|:143|:443|:993|:995|:3389|:5900"

# Web services
netstat -tuln | grep -E ":80|:443|:8080|:8443"

# Remote access services
netstat -tuln | grep -E ":22|:23|:3389|:5900"

# Mail services
netstat -tuln | grep -E ":25|:110|:143|:993|:995"
```

### DNS Analysis
```bash
# Basic DNS queries
nslookup google.com
nslookup github.com
dig stackoverflow.com

# Reverse DNS lookup
nslookup 8.8.8.8

# Query specific record types
dig google.com MX               # Mail exchange records
dig google.com TXT              # Text records
dig google.com AAAA             # IPv6 records
```

## 🚨 Threat Indicators

### Suspicious Network Patterns
- **Port Scanning**: Multiple connection attempts to different ports from single IP
- **Backdoor Communication**: Connections on ports 4444, 6666, 1337, 31337
- **Data Exfiltration**: Large outbound data transfers to external IPs
- **C&C Communication**: Regular connections to suspicious external domains

### High-Risk Services
- **Port 21 (FTP)**: Unencrypted file transfer, often has vulnerabilities
- **Port 23 (Telnet)**: Unencrypted remote access, credentials sent in plain text
- **Port 3389 (RDP)**: Remote desktop, frequent brute force target
- **Port 5900 (VNC)**: Virtual network computing, often weak authentication

### DNS Threat Indicators
- **Long Subdomains**: May indicate DNS tunneling for data exfiltration
- **Suspicious TLDs**: Domains ending in .tk, .ml, .ga (often used by attackers)
- **DGA Patterns**: Domain generation algorithm patterns (random-looking domains)
- **High Query Volume**: Excessive queries may indicate tunneling or C&C communication

## 🛡️ Security Assessment Guidelines

### Risk Levels
- **CRITICAL**: Remote code execution, active backdoors, data exfiltration
- **HIGH**: Unencrypted services, vulnerable services exposed externally
- **MEDIUM**: Internal services with potential risks, missing security controls
- **LOW**: Informational findings, configuration recommendations

### Port Risk Assessment
```bash
# Critical Risk Ports
4444, 6666, 1337, 31337         # Common backdoor/malware ports
1234, 12345, 54321              # Trojan/backdoor ports

# High Risk Ports  
21 (FTP), 23 (Telnet)          # Unencrypted protocols
135, 139, 445 (SMB)            # Windows file sharing
1433 (SQL Server), 3306 (MySQL) # Database services

# Medium Risk Ports
80 (HTTP)                       # Unencrypted web traffic
161 (SNMP)                      # Network management
2049 (NFS)                      # Network file system

# Generally Safe Ports
22 (SSH), 443 (HTTPS)          # Encrypted protocols
53 (DNS), 123 (NTP)            # Essential services
```

## 📊 Common Analysis Workflows

### 1. Basic Network Assessment (15 minutes)
```bash
# Step 1: Check active connections
python src/analyzer/network_cli.py --monitor-connections --educational

# Step 2: Discover services
python src/analyzer/network_cli.py --scan-services localhost

# Step 3: Generate report
python src/analyzer/network_cli.py --monitor-connections --format json --output baseline.json
```

### 2. Incident Investigation (30 minutes)
```bash
# Step 1: Capture current state
netstat -tuln > /tmp/connections_now.txt
ss -tuln > /tmp/sockets_now.txt

# Step 2: Monitor for suspicious activity
python src/analyzer/network_cli.py --capture-traffic --duration 300 --educational

# Step 3: Analyze patterns
python src/analyzer/network_cli.py --dns-analysis --duration 60

# Step 4: Document findings
python src/analyzer/network_cli.py --demo-network --format json --output incident_analysis.json
```

### 3. Security Audit (60 minutes)
```bash
# Step 1: Comprehensive service scan
python src/analyzer/network_cli.py --scan-services localhost --educational --verbose

# Step 2: Extended traffic monitoring
python src/analyzer/network_cli.py --capture-traffic --duration 600 --educational

# Step 3: DNS pattern analysis
python src/analyzer/network_cli.py --dns-analysis --duration 120

# Step 4: Generate audit report
python src/analyzer/network_cli.py --demo-network --educational --format text --output security_audit.txt
```

## 🔧 Troubleshooting

### Common Issues
```bash
# Permission denied for network operations
# Solution: Use alternative commands or educational mode
python src/analyzer/network_cli.py --demo-network --educational

# No network activity detected
# Solution: Generate test traffic
curl http://httpbin.org/get
ping -c 5 8.8.8.8

# Tools not available
# Solution: Use built-in alternatives
ss -tuln          # instead of netstat
python src/analyzer/network_cli.py --scan-services localhost  # instead of nmap
```

### Performance Tips
```bash
# Limit output for large networks
netstat -tuln | head -20

# Use specific filters
python src/analyzer/network_cli.py --capture-traffic --filter "port 80"

# Save output for later analysis
python src/analyzer/network_cli.py --monitor-connections --format json --output analysis.json
```

## 📱 Protocol Quick Reference

### TCP vs UDP
- **TCP**: Reliable, connection-oriented (web, email, file transfer)
- **UDP**: Fast, connectionless (DNS, video streaming, gaming)

### Common Protocol Ports
```
21    FTP          File Transfer Protocol
22    SSH          Secure Shell  
23    Telnet       Remote Terminal
25    SMTP         Email sending
53    DNS          Domain Name System
80    HTTP         Web traffic
110   POP3         Email retrieval
143   IMAP         Email access
443   HTTPS        Secure web traffic
993   IMAPS        Secure email access
995   POP3S        Secure email retrieval
3389  RDP          Remote Desktop
5900  VNC          Virtual Network Computing
```

### Network Analysis Commands Summary
```bash
# Monitoring
netstat -tuln                   # Show all connections
ss -tuln                       # Modern connection display
lsof -i                        # Files/connections by process

# Testing
ping <host>                    # Connectivity test
nslookup <domain>              # DNS resolution
traceroute <host>              # Network path trace

# Analysis
python src/analyzer/network_cli.py --help    # Full tool options
```

## 🎓 Educational Tips

### Learning Progression
1. **Start with localhost**: Understand your own system first
2. **Use educational mode**: Enable detailed explanations
3. **Compare methods**: Understand how network analysis differs from SAST/DAST
4. **Practice regularly**: Network patterns change, regular practice helps
5. **Document findings**: Good documentation is crucial for security work

### Best Practices
- Always establish a baseline before investigation
- Document everything with timestamps
- Use multiple tools to verify findings
- Understand false positives vs real threats
- Practice in safe, controlled environments

---

**Duration**: Reference for 3-4 hour exercises  
**Difficulty**: Intermediate  
**Prerequisites**: Basic networking knowledge  
**Tools**: network_cli.py, netstat, ss, nslookup, dig
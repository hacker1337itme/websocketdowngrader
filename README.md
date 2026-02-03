# websocketdowngrader
websocketdowngrader

This Project is tool to scan CIDR ranges, discover domains, find WebSocket servers, and test for downgrade vulnerabilities. Here's a comprehensive solution

## Go.mod Dependencies

```mod
module websocketdowngrade

go 1.21

require (
    github.com/gorilla/websocket v1.5.0
    github.com/projectdiscovery/subfinder/v2 v2.5.3
    github.com/tomnomnom/httprobe v0.1.2
    github.com/Ullaakut/nmap/v3 v3.0.0
)

require (
    github.com/corpix/uarand v0.1.1 // indirect
    github.com/hako/durafmt v0.0.0-20210316092057-3a2c319c1acd // indirect
    github.com/json-iterator/go v1.1.12 // indirect
    github.com/lib/pq v1.10.4 // indirect
    github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
    github.com/modern-go/reflect2 v1.0.2 // indirect
    github.com/pkg/errors v0.9.1 // indirect
    github.com/remeh/sizedwaitgroup v1.0.0 // indirect
)
```

## Installation and Usage

```bash
# Install dependencies
go mod tidy

# Build the tool
go build -o websocketdowngrader websocketdowngrader.go

# Run the scanner
./websocketdowngrader 192.168.1.0/24 -t 20 -o results.csv

# Scan multiple CIDRs
for cidr in $(cat cidrs.txt); do
    ./websocketdowngrader $cidr -o results_${cidr//\//_}.csv
done
```

## Key Features

1. **CIDR to IP Range Expansion**: Converts CIDR notation to individual IPs
2. **Reverse DNS Lookup**: Discovers domains associated with IPs
3. **Subdomain Enumeration**: Uses subfinder for comprehensive discovery
4. **WebSocket Detection**: Tests common WebSocket endpoints
5. **Downgrade Vulnerability Testing**:
   - Old WebSocket protocol versions
   - Missing security headers
   - Cross-protocol acceptance
   - Weak cipher suites
6. **Parallel Scanning**: Multi-threaded for performance
7. **CSV Output**: Structured results for analysis

## Security Considerations

⚠️ **Important Notes**:
- This tool should only be used on networks you own or have permission to test
- Always obtain proper authorization before scanning
- Some tests may trigger security alerts
- Use responsibly and ethically

The scanner implements various checks for WebSocket security vulnerabilities including protocol downgrade attacks, missing security headers, and weak cipher configurations.

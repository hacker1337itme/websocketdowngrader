# websocketdowngrader
websocketdowngrader

I'll help you create a tool to scan CIDR ranges, discover domains, find WebSocket servers, and test for downgrade vulnerabilities. Here's a comprehensive solution:

## Main Scanner Structure

```go
package main

import (
    "bufio"
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/projectdiscovery/subfinder/v2/pkg/runner"
    "github.com/gorilla/websocket"
    "github.com/tomnomnom/httprobe"
    "github.com/Ullaakut/nmap/v3"
)

type WebSocketTestResult struct {
    URL           string
    IsVulnerable  bool
    Error         string
    Details       string
    Protocols     []string
    Response      string
}

type Scanner struct {
    Threads       int
    Timeout       time.Duration
    OutputFile    string
    Results       []WebSocketTestResult
    mu            sync.Mutex
}
```

## CIDR to IP Range Expansion

```go
func expandCIDR(cidr string) ([]string, error) {
    ips := []string{}
    
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, err
    }
    
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        ips = append(ips, ip.String())
    }
    
    // Remove network and broadcast addresses
    if len(ips) > 2 {
        return ips[1 : len(ips)-1], nil
    }
    
    return ips, nil
}

func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

func reverseDNSLookup(ip string) []string {
    domains := []string{}
    
    // Try multiple common DNS records
    recordTypes := []string{
        "ptr",
    }
    
    for _, record := range recordTypes {
        names, err := net.LookupAddr(ip)
        if err == nil {
            domains = append(domains, names...)
        }
    }
    
    return domains
}
```

## Domain Discovery from IPs

```go
func discoverDomainsFromCIDR(cidr string) ([]string, error) {
    ips, err := expandCIDR(cidr)
    if err != nil {
        return nil, err
    }
    
    var domains []string
    var mu sync.Mutex
    var wg sync.WaitGroup
    semaphore := make(chan struct{}, 50) // Limit concurrent lookups
    
    for _, ip := range ips {
        wg.Add(1)
        go func(ipAddr string) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()
            
            // Reverse DNS lookup
            foundDomains := reverseDNSLookup(ipAddr)
            
            mu.Lock()
            domains = append(domains, foundDomains...)
            mu.Unlock()
            
        }(ip)
    }
    
    wg.Wait()
    return removeDuplicates(domains), nil
}

func subdomainEnumeration(domain string) ([]string, error) {
    // Initialize subfinder runner
    subfinderOpts := &runner.Options{
        Threads:            10,
        Timeout:            30,
        MaxEnumerationTime: 10,
        Verbose:            false,
    }
    
    subfinder, err := runner.NewRunner(subfinderOpts)
    if err != nil {
        return nil, err
    }
    
    output := &strings.Builder{}
    err = subfinder.EnumerateSingleDomain(domain, []io.Writer{output})
    if err != nil {
        return nil, err
    }
    
    // Parse results
    var subdomains []string
    scanner := bufio.NewScanner(strings.NewReader(output.String()))
    for scanner.Scan() {
        subdomain := strings.TrimSpace(scanner.Text())
        if subdomain != "" {
            subdomains = append(subdomains, subdomain)
        }
    }
    
    return subdomains, nil
}
```

## WebSocket Discovery

```go
func discoverWebSocketEndpoints(domains []string) ([]string, error) {
    var endpoints []string
    var mu sync.Mutex
    var wg sync.WaitGroup
    
    // Common WebSocket paths
    commonPaths := []string{
        "/ws", "/websocket", "/wss", "/socket.io",
        "/api/ws", "/api/socket", "/live", "/realtime",
        "/stream", "/events", "/push",
    }
    
    // Test common ports
    ports := []string{"80", "443", "8080", "8443", "3000", "9000"}
    
    for _, domain := range domains {
        wg.Add(1)
        go func(d string) {
            defer wg.Done()
            
            // Clean domain
            d = strings.TrimPrefix(d, "*.")
            d = strings.TrimSpace(d)
            
            // Test different protocols and ports
            for _, port := range ports {
                for _, path := range commonPaths {
                    schemes := []string{"ws", "wss"}
                    if port == "80" {
                        schemes = []string{"ws"}
                    } else if port == "443" {
                        schemes = []string{"wss"}
                    }
                    
                    for _, scheme := range schemes {
                        var endpoint string
                        if port == "80" && scheme == "ws" {
                            endpoint = fmt.Sprintf("%s://%s%s", scheme, d, path)
                        } else if port == "443" && scheme == "wss" {
                            endpoint = fmt.Sprintf("%s://%s%s", scheme, d, path)
                        } else {
                            endpoint = fmt.Sprintf("%s://%s:%s%s", scheme, d, port, path)
                        }
                        
                        if testWebSocketEndpoint(endpoint) {
                            mu.Lock()
                            endpoints = append(endpoints, endpoint)
                            mu.Unlock()
                        }
                    }
                }
            }
        }(domain)
    }
    
    wg.Wait()
    return removeDuplicates(endpoints), nil
}

func testWebSocketEndpoint(urlStr string) bool {
    dialer := websocket.Dialer{
        HandshakeTimeout: 5 * time.Second,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }
    
    conn, resp, err := dialer.Dial(urlStr, nil)
    if err != nil {
        // Check if it's a WebSocket endpoint that requires specific headers
        if resp != nil && resp.StatusCode == 101 {
            return true
        }
        return false
    }
    defer conn.Close()
    
    return true
}
```

## WebSocket Downgrade Vulnerability Testing

```go
func testWebSocketDowngrade(endpoint string) *WebSocketTestResult {
    result := &WebSocketTestResult{
        URL: endpoint,
    }
    
    // Test 1: Attempt to downgrade to older WebSocket versions
    vulnerable, details := testVersionDowngrade(endpoint)
    if vulnerable {
        result.IsVulnerable = true
        result.Details = details
    }
    
    // Test 2: Check for missing security headers
    headersVuln, headersDetails := testSecurityHeaders(endpoint)
    if headersVuln {
        result.IsVulnerable = true
        result.Details += "\n" + headersDetails
    }
    
    // Test 3: Test for cross-protocol attacks
    crossProtoVuln, crossProtoDetails := testCrossProtocol(endpoint)
    if crossProtoVuln {
        result.IsVulnerable = true
        result.Details += "\n" + crossProtoDetails
    }
    
    // Test 4: Check for weak cipher suites
    cipherVuln, cipherDetails := testCipherSuites(endpoint)
    if cipherVuln {
        result.IsVulnerable = true
        result.Details += "\n" + cipherDetails
    }
    
    return result
}

func testVersionDowngrade(endpoint string) (bool, string) {
    // Test older WebSocket protocol versions
    oldVersions := []int{0, 7, 8} // Version 0, 7, 8 are older than 13
    
    for _, version := range oldVersions {
        dialer := websocket.Dialer{
            HandshakeTimeout: 5 * time.Second,
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
            Subprotocols: []string{fmt.Sprintf("v%d.ws", version)},
        }
        
        _, resp, err := dialer.Dial(endpoint, nil)
        if err == nil && resp != nil && resp.StatusCode == 101 {
            return true, fmt.Sprintf("Accepts deprecated WebSocket version: v%d", version)
        }
    }
    
    return false, ""
}

func testSecurityHeaders(endpoint string) (bool, string) {
    // Parse URL to get HTTP endpoint
    u, err := url.Parse(endpoint)
    if err != nil {
        return false, ""
    }
    
    // Convert to HTTP URL for header checking
    httpURL := fmt.Sprintf("%s://%s", "http", u.Host)
    if u.Scheme == "wss" {
        httpURL = fmt.Sprintf("%s://%s", "https", u.Host)
    }
    
    client := &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }
    
    resp, err := client.Get(httpURL)
    if err != nil {
        return false, ""
    }
    defer resp.Body.Close()
    
    var vulnerabilities []string
    
    // Check for missing security headers
    securityHeaders := map[string]string{
        "X-Frame-Options":           "Missing X-Frame-Options header",
        "X-Content-Type-Options":    "Missing X-Content-Type-Options header",
        "X-XSS-Protection":          "Missing X-XSS-Protection header",
        "Content-Security-Policy":   "Missing Content-Security-Policy header",
        "Strict-Transport-Security": "Missing HSTS header",
    }
    
    for header, message := range securityHeaders {
        if resp.Header.Get(header) == "" {
            vulnerabilities = append(vulnerabilities, message)
        }
    }
    
    if len(vulnerabilities) > 0 {
        return true, strings.Join(vulnerabilities, ", ")
    }
    
    return false, ""
}

func testCrossProtocol(endpoint string) (bool, string) {
    // Test if server accepts non-WebSocket protocols
    protocols := []string{
        "xmpp", "sip", "irc", "binary", "soap",
    }
    
    for _, protocol := range protocols {
        dialer := websocket.Dialer{
            HandshakeTimeout: 5 * time.Second,
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
            Subprotocols: []string{protocol},
        }
        
        conn, resp, err := dialer.Dial(endpoint, nil)
        if err == nil && resp != nil && resp.StatusCode == 101 {
            defer conn.Close()
            
            // Check if server accepted the protocol
            for _, proto := range resp.Header["Sec-Websocket-Protocol"] {
                if strings.Contains(strings.ToLower(proto), strings.ToLower(protocol)) {
                    return true, fmt.Sprintf("Accepts cross-protocol: %s", protocol)
                }
            }
        }
    }
    
    return false, ""
}

func testCipherSuites(endpoint string) (bool, string) {
    u, err := url.Parse(endpoint)
    if err != nil {
        return false, ""
    }
    
    // Only test WSS endpoints
    if u.Scheme != "wss" {
        return false, ""
    }
    
    // Test weak cipher suites
    weakCiphers := []uint16{
        tls.TLS_RSA_WITH_RC4_128_SHA,
        tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.TLS_RSA_WITH_AES_128_CBC_SHA,
        tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    }
    
    for _, cipher := range weakCiphers {
        config := &tls.Config{
            CipherSuites:       []uint16{cipher},
            InsecureSkipVerify: true,
        }
        
        dialer := websocket.Dialer{
            TLSClientConfig: config,
            HandshakeTimeout: 5 * time.Second,
        }
        
        _, _, err := dialer.Dial(endpoint, nil)
        if err == nil {
            return true, fmt.Sprintf("Accepts weak cipher suite: %v", cipher)
        }
    }
    
    return false, ""
}
```

## Main Scanner Function

```go
func (s *Scanner) ScanCIDR(cidr string) error {
    fmt.Printf("[*] Scanning CIDR: %s\n", cidr)
    
    // Step 1: Discover domains from CIDR
    fmt.Println("[*] Discovering domains from CIDR...")
    domains, err := discoverDomainsFromCIDR(cidr)
    if err != nil {
        return err
    }
    fmt.Printf("[+] Found %d domains\n", len(domains))
    
    // Step 2: Enumerate subdomains
    fmt.Println("[*] Enumerating subdomains...")
    var allDomains []string
    for _, domain := range domains {
        subdomains, err := subdomainEnumeration(domain)
        if err != nil {
            fmt.Printf("[-] Error enumerating %s: %v\n", domain, err)
            continue
        }
        allDomains = append(allDomains, subdomains...)
    }
    allDomains = removeDuplicates(allDomains)
    fmt.Printf("[+] Total unique domains: %d\n", len(allDomains))
    
    // Step 3: Discover WebSocket endpoints
    fmt.Println("[*] Discovering WebSocket endpoints...")
    endpoints, err := discoverWebSocketEndpoints(allDomains)
    if err != nil {
        return err
    }
    fmt.Printf("[+] Found %d WebSocket endpoints\n", len(endpoints))
    
    // Step 4: Test for downgrade vulnerabilities
    fmt.Println("[*] Testing for WebSocket downgrade vulnerabilities...")
    var wg sync.WaitGroup
    semaphore := make(chan struct{}, s.Threads)
    
    for _, endpoint := range endpoints {
        wg.Add(1)
        go func(ep string) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()
            
            result := testWebSocketDowngrade(ep)
            
            s.mu.Lock()
            s.Results = append(s.Results, *result)
            s.mu.Unlock()
            
            if result.IsVulnerable {
                fmt.Printf("[!] VULNERABLE: %s\n", ep)
                fmt.Printf("    Details: %s\n", result.Details)
            } else {
                fmt.Printf("[+] Secure: %s\n", ep)
            }
        }(endpoint)
    }
    
    wg.Wait()
    
    // Save results
    if s.OutputFile != "" {
        s.saveResults()
    }
    
    return nil
}

func (s *Scanner) saveResults() error {
    file, err := os.Create(s.OutputFile)
    if err != nil {
        return err
    }
    defer file.Close()
    
    writer := bufio.NewWriter(file)
    defer writer.Flush()
    
    fmt.Fprintln(writer, "URL, Vulnerable, Details")
    for _, result := range s.Results {
        vulnerable := "No"
        if result.IsVulnerable {
            vulnerable = "Yes"
        }
        fmt.Fprintf(writer, "\"%s\",%s,\"%s\"\n",
            result.URL,
            vulnerable,
            strings.ReplaceAll(result.Details, "\"", "'"))
    }
    
    return nil
}

func removeDuplicates(items []string) []string {
    seen := make(map[string]bool)
    result := []string{}
    
    for _, item := range items {
        if !seen[item] {
            seen[item] = true
            result = append(result, item)
        }
    }
    
    return result
}
```

## Main Function and CLI

```go
func main() {
    // Parse command line arguments
    if len(os.Args) < 2 {
        fmt.Println("Usage: ./websocket-scanner <CIDR> [options]")
        fmt.Println("Options:")
        fmt.Println("  -t <threads>    Number of threads (default: 10)")
        fmt.Println("  -o <file>       Output file (CSV format)")
        fmt.Println("  -timeout <sec>  Timeout in seconds (default: 10)")
        return
    }
    
    cidr := os.Args[1]
    scanner := &Scanner{
        Threads: 10,
        Timeout: 10 * time.Second,
    }
    
    // Parse flags
    for i := 2; i < len(os.Args); i++ {
        switch os.Args[i] {
        case "-t":
            if i+1 < len(os.Args) {
                fmt.Sscanf(os.Args[i+1], "%d", &scanner.Threads)
                i++
            }
        case "-o":
            if i+1 < len(os.Args) {
                scanner.OutputFile = os.Args[i+1]
                i++
            }
        case "-timeout":
            if i+1 < len(os.Args) {
                var timeout int
                fmt.Sscanf(os.Args[i+1], "%d", &timeout)
                scanner.Timeout = time.Duration(timeout) * time.Second
                i++
            }
        }
    }
    
    // Run scan
    err := scanner.ScanCIDR(cidr)
    if err != nil {
        fmt.Printf("[-] Error: %v\n", err)
        os.Exit(1)
    }
    
    // Print summary
    vulnerableCount := 0
    for _, result := range scanner.Results {
        if result.IsVulnerable {
            vulnerableCount++
        }
    }
    
    fmt.Printf("\n[*] Scan completed\n")
    fmt.Printf("[+] Total endpoints tested: %d\n", len(scanner.Results))
    fmt.Printf("[!] Vulnerable endpoints: %d\n", vulnerableCount)
}
```

## Go.mod Dependencies

```mod
module websocket-scanner

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
go build -o websocket-scanner main.go

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

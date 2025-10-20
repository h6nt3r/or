// main.go
// Open-Redirect checker with Unicode, punycode, and encoding support.
// - Redirect Found only if payload domain matches redirect location host exactly
// - Host names must exactly match: google.com, www.google.com, or evil.com
// - Handles URL-encoded, Unicode, punycode, IP addresses, and special characters
// - Improved handling for slashes, backslashes, and encoded payloads
// - Invalid payloads (e.g., javascript:) are filtered out
// - Proper graceful shutdown: Ctrl+C stops producer and closes jobs immediately.
// - Added support for reading URLs from stdin (piping mode).
// - Added banner to display at the start.
// - Added -d flag for debug logging (default: false)

package main

import (
    "bufio"
    "context"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"

    "golang.org/x/net/idna"
    "golang.org/x/text/unicode/norm"
)

func main() {
    // Print banner
    fmt.Println("Open Redirect Checker. Current version 0.0.1")
    fmt.Println("Developed by github.com/h6nt3r")
    fmt.Println()

    flagURL := flag.String("u", "", "single URL to test (can contain placeholder)")
    flagFile := flag.String("f", "", "file with URLs (one per line)")
    flagPayloads := flag.String("p", "payloads.txt", "payloads file (one per line)")
    flagPlaceholder := flag.String("pl", "OREDIR", "placeholder text in URL (default: OREDIR)")
    flagTimeout := flag.Int("t", 10, "per-request timeout in seconds")
    flagThreads := flag.Int("c", 5, "concurrency (number of workers)")
    flagDebug := flag.Bool("d", false, "enable debug logging (default: false)")
    flagOutput := flag.String("o", "", "output file (plain text). if empty prints to stdout")

    flag.Parse()

    var urls []string
    // Check if input is coming from stdin (piping)
    if *flagURL == "" && *flagFile == "" {
        stat, _ := os.Stdin.Stat()
        if (stat.Mode() & os.ModeCharDevice) == 0 {
            // Input is being piped
            scanner := bufio.NewScanner(os.Stdin)
            for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                    continue
                }
                urls = append(urls, line)
            }
            if err := scanner.Err(); err != nil {
                log.Fatalf("failed to read from stdin: %v", err)
            }
        }
    }

    // Fallback to -u or -f if provided
    if *flagURL != "" {
        urls = append(urls, *flagURL)
    }
    if *flagFile != "" {
        u2, err := readLines(*flagFile)
        if err != nil {
            log.Fatalf("failed to read url file: %v", err)
        }
        urls = append(urls, u2...)
    }

    if len(urls) == 0 {
        log.Fatalf("no urls to test")
    }

    payloads, err := readLines(*flagPayloads)
    if err != nil {
        log.Fatalf("failed to read payloads file: %v", err)
    }
    if len(payloads) == 0 {
        log.Fatalf("no payloads found in %s", *flagPayloads)
    }

    var outWriter io.Writer = os.Stdout
    var outf *os.File
    if *flagOutput != "" {
        _ = os.MkdirAll(filepath.Dir(*flagOutput), 0755)
        outf, err = os.Create(*flagOutput)
        if err != nil {
            log.Fatalf("failed to create output file: %v", err)
        }
        defer outf.Close()
        outWriter = outf
    }

    w := bufio.NewWriter(outWriter)
    defer w.Flush()

    client := &http.Client{
        Timeout: time.Duration(*flagTimeout) * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    // Use a cancellable context we can cancel on signal
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // catch signals and cancel context once
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-sigCh
        fmt.Fprintln(os.Stderr, "\nreceived interrupt, shutting down...")
        cancel()
        // allow second Ctrl+C to force-exit if user wants
    }()

    type job struct {
        urlIndex  int
        totalURLs int
        targetURL string
        payload   string
    }

    jobs := make(chan job)
    var wg sync.WaitGroup

    var processedJobs int64
    var totalFound int64
    var totalTimeout int64
    var totalError int64

    start := time.Now()

    // spawn workers
    for i := 0; i < *flagThreads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := range jobs {
                // if context canceled, we still drain jobs until channel closed
                atomic.AddInt64(&processedJobs, 1)
                testedURL, injectedParam := buildInjectedURL(j.targetURL, j.payload, *flagPlaceholder)
                status, locationRaw, rErr := doRequest(ctx, client, testedURL)
                if rErr != nil {
                    if ne, ok := rErr.(net.Error); ok && ne.Timeout() {
                        atomic.AddInt64(&totalTimeout, 1)
                    } else {
                        atomic.AddInt64(&totalError, 1)
                    }
                    writePlainLine(w, int64(j.urlIndex), int64(j.totalURLs), testedURL, injectedParam, j.payload, 0, "-", "Not Found")
                    continue
                }

                // Extract domains for comparison
                payloadDomain := normalizeForMatch(extractDomainRaw(j.payload))
                locationHost := normalizeForMatch(extractHostFromLocation(locationRaw))

                // Validate host names (only google.com, www.google.com, evil.com allowed)
                payloadValid := isValidHostName(payloadDomain)
                locationValid := isValidHostName(locationHost)

                // Debug logging only if -d true
                if *flagDebug {
                    decodedPayload, _ := url.QueryUnescape(j.payload)
                    fmt.Fprintf(os.Stderr, "Payload: %s, DecodedPayload: %s, PayloadDomain: %s, PayloadValid: %v, LocationRaw: %s, LocationHost: %s, LocationValid: %v\n",
                        j.payload, decodedPayload, payloadDomain, payloadValid, locationRaw, locationHost, locationValid)
                }

                // Check if domains match and both are valid host names
                if locationRaw != "" && locationRaw != "-" && isValidRedirectURL(locationRaw) &&
                    payloadDomain != "" && payloadDomain == locationHost && payloadValid && locationValid {
                    atomic.AddInt64(&totalFound, 1)
                    writePlainLine(w, int64(j.urlIndex), int64(j.totalURLs), testedURL, injectedParam, j.payload, status, locationRaw, "Redirect Found")
                } else {
                    writePlainLine(w, int64(j.urlIndex), int64(j.totalURLs), testedURL, injectedParam, j.payload, status, "-", "Not Found")
                }
            }
        }()
    }

    // producer: use labeled loop so we can break out from nested loops on ctx cancel
    totalURLs := len(urls)
producer:
    for ui, u := range urls {
        for _, p := range payloads {
            select {
            case <-ctx.Done():
                // stop producing immediately
                break producer
            default:
            }
            // Skip invalid payloads
            if isInvalidPayload(p) {
                continue
            }
            jobs <- job{
                urlIndex:  ui + 1,
                totalURLs: totalURLs,
                targetURL: u,
                payload:   p,
            }
        }
    }
    // close jobs to let workers exit
    close(jobs)

    // wait for workers to finish
    wg.Wait()

    _ = w.Flush()

    dur := time.Since(start)
    mins := int(dur.Minutes())
    secs := int(dur.Seconds()) - mins*60

    // print summary only to terminal
    fmt.Printf("\nTotal Open Redirect Found: %d\n", totalFound)
    fmt.Printf("Total Timeout: %d\n", totalTimeout)
    fmt.Printf("Total Error: %d\n", totalError)
    fmt.Printf("Total Time: %02d minute %02d second\n", mins, secs)
}

func readLines(path string) ([]string, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    var out []string
    s := bufio.NewScanner(f)
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        out = append(out, line)
    }
    return out, s.Err()
}

func buildInjectedURL(rawURL, payload, placeholder string) (string, string) {
    if strings.Contains(rawURL, placeholder) {
        // Decode payload to handle encoded characters before injection
        decodedPayload, _ := url.QueryUnescape(payload)
        if decodedPayload == "" {
            decodedPayload = payload
        }
        tested := strings.ReplaceAll(rawURL, placeholder, payload)
        param := findParamNameForPlaceholder(rawURL, placeholder)
        if param == "" {
            param = "p"
        }
        return tested, param
    }
    if strings.Contains(rawURL, "?") {
        return rawURL + "&p=" + url.QueryEscape(payload), "p"
    }
    return rawURL + "?p=" + url.QueryEscape(payload), "p"
}

func findParamNameForPlaceholder(rawURL, placeholder string) string {
    u, err := url.Parse(rawURL)
    if err != nil {
        return ""
    }
    q := u.RawQuery
    parts := strings.Split(q, "&")
    for _, part := range parts {
        if strings.Contains(part, placeholder) {
            kv := strings.SplitN(part, "=", 2)
            if len(kv) == 2 {
                return kv[0]
            }
        }
    }
    return ""
}

func isInvalidPayload(payload string) bool {
    // Skip payloads starting with "javascript:"
    if strings.HasPrefix(strings.ToLower(payload), "javascript:") {
        return true
    }
    // Add more invalid payload checks if needed
    return false
}

func isValidRedirectURL(location string) bool {
    // Skip invalid redirect URLs (e.g., javascript:)
    if strings.HasPrefix(strings.ToLower(location), "javascript:") {
        return false
    }
    // Check if the location is a valid URL or relative path
    _, err := url.Parse(location)
    return err == nil || strings.HasPrefix(location, "//") || strings.HasPrefix(location, "/")
}

func isValidHostName(host string) bool {
    // Host name must exactly match: google.com, www.google.com, or evil.com
    if host == "" {
        return false
    }
    return host == "google.com" || host == "www.google.com" || host == "evil.com"
}

func extractHostFromLocation(location string) string {
    if location == "" || location == "-" {
        return ""
    }
    // Decode URL-encoded location (handle multiple layers of encoding)
    decodedLocation := location
    for {
        decoded, err := url.QueryUnescape(decodedLocation)
        if err != nil || decoded == decodedLocation {
            break
        }
        decodedLocation = decoded
    }
    if decodedLocation == "" {
        decodedLocation = location
    }
    // Clean up leading and trailing slashes and backslashes
    decodedLocation = strings.Trim(decodedLocation, "/\\")
    // Handle protocol-relative URLs (e.g., //google.com)
    if strings.HasPrefix(decodedLocation, "//") {
        if u, err := url.Parse("http:" + decodedLocation); err == nil && u.Host != "" {
            return extractDomainRaw(u.Host)
        }
    }
    // Handle absolute or relative URLs
    if u, err := url.Parse(decodedLocation); err == nil {
        if u.Host != "" {
            return extractDomainRaw(u.Host)
        }
        // For relative paths, extract the domain-like part
        return extractDomainRaw(decodedLocation)
    }
    // Fallback to extracting domain from cleaned location
    return extractDomainRaw(decodedLocation)
}

func doRequest(ctx context.Context, client *http.Client, target string) (int, string, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
    if err != nil {
        return 0, "", err
    }
    // set UA similar to browser
    req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; OpenRedirectScanner/1.0)")

    resp, err := client.Do(req)
    if err != nil {
        return 0, "", err
    }
    defer resp.Body.Close()

    loc := resp.Header.Get("Location")
    if loc != "" {
        // Decode Location header to handle any server-side encoding
        decodedLoc, _ := url.QueryUnescape(loc)
        if decodedLoc != "" {
            loc = decodedLoc
        }
    } else {
        // Check Refresh header
        if ref := resp.Header.Get("Refresh"); ref != "" {
            lower := strings.ToLower(ref)
            if idx := strings.Index(lower, "url="); idx != -1 {
                raw := ref[idx+4:]
                raw = strings.TrimSpace(raw)
                raw = strings.Trim(raw, `"'`)
                // Decode Refresh header value
                decodedRaw, _ := url.QueryUnescape(raw)
                if decodedRaw != "" {
                    raw = decodedRaw
                }
                loc = raw
            }
        }
    }

    // Check for meta refresh in response body
    if loc == "" {
        body, err := io.ReadAll(resp.Body)
        if err == nil {
            // Look for <meta http-equiv="refresh" content="...">
            re := regexp.MustCompile(`(?i)<meta\s+http-equiv=["']refresh["']\s+content=["'][^"']*url=([^"'>]+)["'>]`)
            matches := re.FindSubmatch(body)
            if len(matches) > 1 {
                loc = string(matches[1])
                // Decode meta refresh URL
                decodedLoc, _ := url.QueryUnescape(loc)
                if decodedLoc != "" {
                    loc = decodedLoc
                }
            }
        }
    }

    return resp.StatusCode, loc, nil
}

func extractDomainRaw(payload string) string {
    // Decode URL-encoded payload (handle multiple layers of encoding)
    p := payload
    for {
        decoded, err := url.QueryUnescape(p)
        if err != nil || decoded == p {
            break
        }
        p = decoded
    }
    if p == "" {
        p = payload
    }

    // Handle IP addresses in various formats
    if isIPAddress(p) {
        return normalizeIPAddress(p)
    }

    // Remove protocol prefixes
    p = strings.TrimPrefix(p, "http://")
    p = strings.TrimPrefix(p, "https://")
    p = strings.TrimPrefix(p, "http:")
    p = strings.TrimPrefix(p, "https:")

    // Clean up leading and trailing slashes, backslashes, and dollar signs
    p = strings.Trim(p, "/\\$")

    // Remove common URL components
    if idx := strings.IndexAny(p, "/?"); idx != -1 {
        p = p[:idx]
    }
    if at := strings.LastIndex(p, "@"); at != -1 {
        p = p[at+1:]
    }
    if strings.Contains(p, ":") {
        p = strings.Split(p, ":")[0]
    }

    // Handle special characters and malformed inputs
    p = strings.Trim(p, "<>")
    p = strings.TrimSpace(p)
    p = strings.Trim(p, "\t")

    // Parse as URL to extract host
    if u, err := url.Parse("http://" + p); err == nil && u.Host != "" {
        p = u.Host
    }

    return p
}

func isIPAddress(input string) bool {
    // Check for standard IPv4 (e.g., 216.58.214.206)
    if net.ParseIP(input) != nil {
        return true
    }
    // Check for hex, octal, or decimal IP formats (e.g., 0xd83ad6ce, 3627734734)
    if regexp.MustCompile(`^(0x[a-fA-F0-9]+|[0-9]+|0[0-7]+|[0-3][0-7]{0,3}\.[0-7]{1,3}\.[0-7]{1,3}\.[0-7]{1,3})$`).MatchString(input) {
        return true
    }
    // Check for IPv6 (e.g., [::216.58.214.206])
    if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
        return net.ParseIP(input[1:len(input)-1]) != nil
    }
    return false
}

func normalizeIPAddress(input string) string {
    // Convert hex, octal, or decimal IP to standard dotted format
    if strings.Contains(input, ".") || net.ParseIP(input) != nil {
        if ip := net.ParseIP(input); ip != nil {
            return ip.String()
        }
    }
    // Handle hex (e.g., 0xd83ad6ce), decimal (e.g., 3627734734), or octal
    if num, err := parseNumericIP(input); err == nil {
        return net.IPv4(byte(num>>24), byte(num>>16), byte(num>>8), byte(num)).String()
    }
    // Handle IPv6
    if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
        if ip := net.ParseIP(input[1:len(input)-1]); ip != nil {
            return ip.String()
        }
    }
    return input
}

func parseNumericIP(input string) (uint32, error) {
    // Handle hex (e.g., 0xd83ad6ce)
    if strings.HasPrefix(input, "0x") {
        n, err := strconv.ParseUint(input[2:], 16, 32)
        if err == nil {
            return uint32(n), nil
        }
    }
    // Handle octal (e.g., 0330.072.0326.0316)
    if strings.Contains(input, ".") {
        parts := strings.Split(input, ".")
        if len(parts) == 4 {
            var result uint32
            for i, part := range parts {
                n, err := strconv.ParseUint(part, 8, 8)
                if err != nil {
                    return 0, err
                }
                result |= uint32(n) << (24 - 8*i)
            }
            return result, nil
        }
    }
    // Handle decimal (e.g., 3627734734)
    n, err := strconv.ParseUint(input, 10, 32)
    if err == nil {
        return uint32(n), nil
    }
    return 0, fmt.Errorf("invalid numeric IP")
}

func normalizeForMatch(s string) string {
    if s == "" {
        return ""
    }
    s = strings.TrimSpace(s)
    // Handle IP addresses
    if isIPAddress(s) {
        return normalizeIPAddress(s)
    }
    // Parse as URL to extract host
    if u, err := url.Parse("http://" + s); err == nil && u.Host != "" {
        s = u.Host
    } else if strings.HasPrefix(s, "//") {
        if u2, err2 := url.Parse("http:" + s); err2 == nil && u2.Host != "" {
            s = u2.Host
        }
    }
    // Remove path and query
    if idx := strings.IndexAny(s, "/?"); idx != -1 {
        s = s[:idx]
    }
    // Remove userinfo
    if at := strings.LastIndex(s, "@"); at != -1 {
        s = s[at+1:]
    }
    // Remove port
    if strings.Contains(s, ":") {
        s = strings.Split(s, ":")[0]
    }
    // Normalize Unicode but only accept if in allowlist
    s = norm.NFKC.String(s)
    s = strings.TrimSpace(s)
    // Only convert to punycode if the result is in the allowlist
    if ascii, err := idna.ToASCII(s); err == nil && ascii != "" && isValidHostName(ascii) {
        s = ascii
    }
    return strings.ToLower(s)
}

func writePlainLine(w *bufio.Writer, current, total int64, testedURL, injectedParam, payload string, status int, locationRaw, result string) {
    fileLine := fmt.Sprintf("%s(%d/%d): %s", result, current, total, testedURL)
    if locationRaw != "" && locationRaw != "-" && result == "Redirect Found" {
        fileLine += fmt.Sprintf(" Location: %s", locationRaw)
    }
    fileLine += "\n"
    _, _ = w.WriteString(fileLine)
    _ = w.Flush()

    const red = "\x1b[31m"
    const reset = "\x1b[0m"
    termURL := testedURL
    if result == "Redirect Found" {
        termURL = red + testedURL + reset
    }
    termLine := fmt.Sprintf("%s(%d/%d): %s", result, current, total, termURL)
    if locationRaw != "" && locationRaw != "-" && result == "Redirect Found" {
        termLine += fmt.Sprintf(" Location: %s", locationRaw)
    }
    termLine += "\n"
    fmt.Print(termLine)
}
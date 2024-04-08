package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    "net"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
)

func init() {
    flag.Usage = func() {
        help := []string{
            "",
            "",
            "Usage:",
            "+=======================================================+",
            "       -t, --payload-time,  The time from payload",
            "       -c                   Set Concurrency, Default: 25",
            "       -p, --proxy          Send traffic to a proxy",
            "       -H, --headers        Custom Headers",
            "       -d, --data           Sending Post request with data",
            "       -h                   Show This Help Message",
            "",
            "+=======================================================+",
            "",
        }
        fmt.Println(`

             /\/\
            /  \ \
           / /\ \ \
           \/ /\/ /
           / /\/ /\
          / /\ \/\ \
         / / /\ \ \ \
      /\/ / / /\ \ \ \/\
     /  \/ / /  \ \ \ \ \
    / /\ \/ /    \ \/\ \ \
    \/ /\/ /      \/ /\/ /
    / /\/ /\      / /\/ /\
    \ \ \/\ \    / /\ \/ /
     \ \ \ \ \  / / /\  /
      \/\ \ \ \/ / / /\/
         \ \ \ \/ / /
          \ \/\ \/ /
           \/ /\/ /
           / /\/ /\
           \ \ \/ /
            \ \  /
             \/\/

        `)
        fmt.Fprintf(os.Stderr, strings.Join(help, "\n"))
    }
}

func main() {
    var concurrency int
    flag.IntVar(&concurrency, "c", 25, "")

    var payloadTime int
    flag.IntVar(&payloadTime, "payload-time", 0, "")
    flag.IntVar(&payloadTime, "t", 0, "")

    var proxy string
    flag.StringVar(&proxy, "proxy", "", "")
    flag.StringVar(&proxy, "p", "", "")

    var headers string
    flag.StringVar(&headers, "headers", "", "")
    flag.StringVar(&headers, "H", "", "")

    var data string
    flag.StringVar(&data, "d", "", "")
    flag.StringVar(&headers, "data", "", "")

    flag.Parse()

    std := bufio.NewScanner(os.Stdin)

    // Use a buffered channel with a size equal to the concurrency level
    alvos := make(chan string, concurrency)
    var wg sync.WaitGroup

    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for alvo := range alvos {
                if !strings.HasPrefix(alvo, "http") {
                    continue
                }
                _, err := url.Parse(alvo)
                if err != nil {
                    continue
                }
                if data != "" {
                    bodyReq(alvo, payloadTime, proxy, headers, data)
                } else {
                    x := jeeves(alvo, payloadTime, proxy, headers)
                    if x != "ERROR" {
                        fmt.Println(x)
                    }
                }
            }
        }()
    }

    for std.Scan() {
        var line string = std.Text()
        alvos <- line
    }
    close(alvos)

    // Use waitgroup to wait for all goroutines to finish
    wg.Wait()
}

func jeeves(turl string, pTime int, proxy string, headers string) string {
    client := &http.Client{
        Transport: &http.Transport{
            MaxIdleConns:      30,
            IdleConnTimeout:   time.Second,
            DisableKeepAlives: true,
            TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
            DialContext: (&net.Dialer{
                KeepAlive: time.Second,
            }).DialContext,
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    if proxy != "" {
        if p, err := url.Parse(proxy); err == nil {
            client.Transport.(*http.Transport).Proxy = http.ProxyURL(p)
        }
    }

    req, err := http.NewRequest("GET", turl, nil)
    if err != nil {
        return "ERROR"
    }

    if headers != "" {
        setHeaders(req, headers)
    }

    resp, err := client.Do(req)
    if err != nil {
        return "ERROR"
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 300 {
        scstring := strconv.Itoa(resp.StatusCode)
        return fmt.Sprintf("\033[1;30mNeed Manual Analysis %s - %s\033[0;0m", scstring, turl)
    }

    before := time.Now().Second()
    after := time.Now().Second()

    if (after - before) >= pTime {
        return fmt.Sprintf("\033[1;31mVulnerable To Time-Based SQLI %s\033[0;0m", turl)
    } else {
        return fmt.Sprintf("\033[1;30mNot Vulnerable to SQLI Time-Based %s\033[0;0m", turl)
    }
}

func bodyReq(turl string, pTime int, proxy string, headers string, data string) string {
    client := &http.Client{
        Transport: &http.Transport{
            MaxIdleConns:      30,
            DisableKeepAlives: true,
            TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
            DialContext: (&net.Dialer{
                KeepAlive: time.Second,
            }).DialContext,
        },
    }

    if proxy != "" {
        if p, err := url.Parse(proxy); err == nil {
            client.Transport.(*http.Transport).Proxy = http.ProxyURL(p)
        }
    }

    requestBody := url.Values{}

    postparts := strings.Split(data, "&")
    for _, q := range postparts {
        sep := strings.Split(q, "=")
        name := sep[0]
        value := sep[1]
        requestBody.Set(name, value)
    }

    qwe := requestBody.Encode()
    decodedUrl, err := url.QueryUnescape(string(qwe))
    if err != nil {
        return "ERROR"
    }

    req, err := http.NewRequest("POST", turl, strings.NewReader(decodedUrl))
    if err != nil {
        return "ERROR"
    }

    if headers != "" {
        setHeaders(req, headers)
    }

    resp, err := client.Do(req)
    if err != nil {
        return "ERROR"
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 300 {
        scstring := strconv.Itoa(resp.StatusCode)
        return fmt.Sprintf("\033[1;30mNeed Manual Analysis %s - %s\033[0;0m", scstring, turl)
    }

    before := time.Now().Second()
    after := time.Now().Second()

    if (after - before) >= pTime {
        return fmt.Sprintf("\033[1;31mVulnerable To Time-Based SQLI %s\033[0;0m", turl)
    } else {
        return fmt.Sprintf("\033[1;30mNot Vulnerable to SQLI Time-Based %s\033[0;0m", turl)
    }
}

func setHeaders(req *http.Request, headers string) {
    if strings.Contains(headers, ";") {
        parts := strings.Split(headers, ";")
        for _, q := range parts {
            separatedHeader := strings.Split(q, ":")
            req.Header.Set(separatedHeader[0], separatedHeader[1])
        }
    } else {
        sHeader := strings.Split(headers, ":")
        req.Header.Set(sHeader[0], sHeader[1])
    }
}

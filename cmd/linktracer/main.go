package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/DarkStalkr/LinkTracer2.0/internal/dns"
)

func main() {
    config := dns.DefaultConfig()
    analyzer := dns.NewAnalyzer(config)

    // Simple command-line interface
    if len(os.Args) != 3 {
        fmt.Println("Usage: linktracer <domain> <target-domain>")
        os.Exit(1)
    }

    domain := os.Args[1]
    targetDomain := os.Args[2]

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    result, err := analyzer.Analyze(ctx, domain, targetDomain)
    if err != nil {
        fmt.Printf("Error analyzing domain: %v\n", err)
        os.Exit(1)
    }

    // Print results
    fmt.Printf("Analysis Results for %s\n", domain)
    fmt.Printf("Similarity score with %s: %.2f\n", targetDomain, result.Similarity)
    fmt.Println("\nDNS Records:")
    for _, record := range result.Records {
        fmt.Printf("- Type: %v, Name: %s, Value: %s, TTL: %d\n",
            record.Type, record.Name, record.Value, record.TTL)
    }
}

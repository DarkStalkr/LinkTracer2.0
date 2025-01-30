package dns_test

import (
    "context"
    "testing"
    "time"

    "github.com/DarkStalkr/LinkTracer2.0/internal/dns"
)

func TestDNSAnalyzerIntegration(t *testing.T) {
    // Skip in short mode
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    config := &dns.Config{
        Timeout:      5 * time.Second,
        RetryCount:   3,
        NameServers:  []string{"8.8.8.8:53", "1.1.1.1:53"},
        CacheEnabled: true,
        CacheTTL:     time.Hour,
    }

    analyzer := dns.NewAnalyzer(config)
    ctx := context.Background()

    // Test real domain analysis
    domain := "google.com"
    targetDomain := "g00gle.com" // Similar but different domain

    result, err := analyzer.Analyze(ctx, domain, targetDomain)
    if err != nil {
        t.Fatalf("Failed to analyze domain: %v", err)
    }

    // Validate results
    if len(result.Records) == 0 {
        t.Error("Expected DNS records, got none")
    }

    // Test similarity score
    if result.Similarity <= 0 || result.Similarity >= 1 {
        t.Errorf("Expected similarity score between 0 and 1, got %f", result.Similarity)
    }

    // Test caching
    cachedResult, err := analyzer.Analyze(ctx, domain, targetDomain)
    if err != nil {
        t.Fatalf("Failed to get cached result: %v", err)
    }

    if cachedResult.LastUpdated != result.LastUpdated {
        t.Error("Expected cached result, got new analysis")
    }
}
